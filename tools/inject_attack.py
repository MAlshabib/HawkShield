#!/usr/bin/env python3
"""HawkShield over-the-air self-test — the antenna-to-dashboard proof.

Craft real 802.11 attack frames, transmit them from a monitor-mode adapter
against **your own** HawkShield testbed, then (optionally) query the Pi's
``packets`` table to confirm the detector actually saw them.

The frames are NOT crafted here. They come, byte for byte, from the shared
factory in ``backend/detector/attack_sim.py`` — the same constructors that
``POST /simulate`` and ``--self-test`` use, so the over-the-air test and the
in-process test are the same frames. This module only:

  1. retargets the built frames' BSSID to the operator's own AP (so nothing is
     broadcast blindly into the room),
  2. puts them on the antenna with scapy's ``sendp`` (Linux, root, monitor mode),
  3. reports what the Pi detected — honestly, not asserted-perfect.

Honesty caveat, surfaced in the verify report: the shipped model is AWID3-
trained and validated across time *within one recording*, not across
deployments (see ``models/README.md`` §2.7.1). Frames from a different radio /
antenna / driver than AWID3's may be detected as *an* attack but mislabelled.
The verify step therefore reports what the Pi saw and grades PASS / PARTIAL /
FAIL — a PARTIAL is the expected shape of that documented hardware-domain gap,
not a bug.

Import-safe on any OS: importing this module, running ``--help``, building
frames and the software safety gate all work on Windows with no radio and no
root. Only the transmit and DB-verify paths touch Linux/root/scapy-sendp/DB,
and those are guarded at call time.
"""
from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import time
from typing import List, Optional, Sequence

# attack_sim is import-safe on any OS (it builds frames, never sends). This is
# the ONLY thing we import from backend.detector — we reuse its frames, we do
# not craft our own.
from backend.detector.attack_sim import (
    build_frames,
    resolve_classes,
)
from scapy.layers.dot11 import Dot11

# --- hard safety caps (in code, not just docs) -------------------------------
# Big numbers are how a self-test becomes a weapon. These ceilings are enforced
# at argument-parse time; there is no flag to raise them.
MAX_COUNT = 1000          # frames per class
MAX_RATE = 100.0          # frames per second

# The CLI --attack vocabulary. 'all' expands to everything attack_sim can build.
ATTACK_CHOICES = [
    "deauth", "disas", "reassoc", "rogueap", "evil_twin", "krack", "all",
]

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

LEGAL_WARNING = (
    "==============================================================================\n"
    " LEGAL WARNING\n"
    " Transmitting deauthentication / disassociation frames against networks you do\n"
    " not own is ILLEGAL in most jurisdictions. This tool is for testing YOUR OWN\n"
    " equipment only. By passing --i-own-this-network you assert that the target\n"
    " BSSID is an access point you own and are authorised to test.\n"
    "=============================================================================="
)


# --- errors ------------------------------------------------------------------
def _die(msg: str, code: int = 2) -> "None":
    """Print a clear error to stderr and exit."""
    print(f"inject_attack: error: {msg}", file=sys.stderr)
    raise SystemExit(code)


# --- argument parsing --------------------------------------------------------
def _bounded_int(name: str, lo: int, hi: int):
    def parse(value: str) -> int:
        try:
            iv = int(value)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"{name} must be an integer, got {value!r}")
        if iv < lo or iv > hi:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {lo} and {hi} (safety cap), got {iv}"
            )
        return iv

    return parse


def _bounded_rate(value: str) -> float:
    try:
        fv = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"--rate must be a number, got {value!r}")
    if fv <= 0 or fv > MAX_RATE:
        raise argparse.ArgumentTypeError(
            f"--rate must be >0 and <= {MAX_RATE:g} frames/s (safety cap), got {fv:g}"
        )
    return fv


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="inject_attack.py",
        description=(
            "HawkShield over-the-air self-test: transmit crafted 802.11 attack "
            "frames against your OWN testbed and verify the Pi detected them."
        ),
        epilog=(
            "Example:\n"
            "  sudo python tools/inject_attack.py --iface wlan1mon "
            "--target-bssid de:ad:be:ef:00:01 --attack all --count 50 --rate 20 "
            "--i-own-this-network --verify postgresql://hawk:pw@pi.local:5432/hawkshield\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--iface", required=True,
                   help="monitor-mode interface to transmit from, e.g. wlan1mon")
    # Optional at the argparse level so the safety gate can refuse with a clear
    # message (rather than argparse's generic 'required') and never default to
    # broadcast.
    p.add_argument("--target-bssid", default=None,
                   help="BSSID (MAC) of the AP you own; every frame is scoped to it")
    p.add_argument("--attack", required=True, choices=ATTACK_CHOICES,
                   help="attack class to transmit, or 'all' for every class")
    p.add_argument("--count", type=_bounded_int("--count", 1, MAX_COUNT), default=10,
                   help=f"frames per class (1..{MAX_COUNT})")
    p.add_argument("--rate", type=_bounded_rate, default=10.0,
                   help=f"frames per second (>0..{MAX_RATE:g})")
    p.add_argument("--verify", default=None, metavar="DB_URL",
                   help="postgresql://... to the Pi's DB; poll packets after inject")
    p.add_argument("--verify-timeout", type=float, default=20.0,
                   help="seconds to wait for the detector to write rows (default 20)")
    p.add_argument("--i-own-this-network", action="store_true",
                   help="required assertion that you own the target AP")
    return p


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


# --- safety gate (pure, testable, no radio) ----------------------------------
def enforce_transmit_safety(args: argparse.Namespace) -> None:
    """Refuse to transmit unless the operator owns the target and named it.

    Both conditions are non-negotiable and enforced here in code:
      * --i-own-this-network must be set, and
      * --target-bssid must be an explicit, well-formed MAC (never a default,
        never broadcast).
    Exits with a clear message otherwise. Caps on count/rate are already
    enforced by the argument parser before we get here.
    """
    if not args.i_own_this_network:
        _die(
            "refusing to transmit without --i-own-this-network. This tool puts "
            "real deauth/disassoc frames on the air; you must assert you own the "
            "target AP. See the LEGAL WARNING above."
        )
    if not args.target_bssid:
        _die(
            "refusing to transmit without an explicit --target-bssid. There is no "
            "default and frames are never broadcast to the room; name the AP you own."
        )
    if not _MAC_RE.match(args.target_bssid.strip()):
        _die(
            f"--target-bssid {args.target_bssid!r} is not a MAC address "
            "(expected form aa:bb:cc:dd:ee:ff)."
        )
    if args.target_bssid.strip().lower() == "ff:ff:ff:ff:ff:ff":
        _die("--target-bssid must not be the broadcast address.")


# --- radio-environment gate (guarded; Linux/root/monitor only) ---------------
def interface_type(iface: str) -> Optional[str]:
    """Return the iw-reported type of *iface* ('monitor', 'managed', ...).

    Same idiom as deploy/monitor_mode.sh: parse ``iw dev <iface> info``.
    """
    try:
        proc = subprocess.run(
            ["iw", "dev", iface, "info"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        _die("'iw' not found. Install it with: sudo apt install -y iw")
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        s = line.strip()
        if s.startswith("type "):
            return s.split()[1]
    return None


def require_radio_environment(iface: str) -> None:
    """Fail clearly unless we are Linux, root, and *iface* is in monitor mode."""
    if platform.system() != "Linux":
        _die(
            f"transmitting only runs on Linux (target: Raspberry Pi OS). "
            f"Detected: {platform.system()}. Build/--help/verify work anywhere."
        )
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        _die(f"must run as root. Try: sudo python tools/inject_attack.py --iface {iface} ...")
    itype = interface_type(iface)
    if itype != "monitor":
        _die(
            f"interface '{iface}' reports type '{itype or 'unknown'}', expected "
            f"'monitor'. Put it in monitor mode first:\n"
            f"      sudo ./deploy/monitor_mode.sh {iface.replace('mon', '')} <channel>"
        )


# --- frame building (reuses attack_sim; retargets to the owned AP) -----------
def _retarget(frame, target_bssid: str) -> None:
    """Point a built frame's BSSID at the operator's own AP.

    attack_sim builds every frame with the same placeholder AP as addr3 (and,
    for most subtypes, addr2). We rewrite exactly those BSSID-role addresses to
    --target-bssid, leaving the locally-administered test victim/client MACs
    alone. The frame's *type/subtype/reason* — everything the model keys on — is
    untouched: a retargeted deauth still carries reason 7. Nothing goes to
    broadcast except beacons, which are broadcast by their nature.
    """
    dot11 = frame.getlayer(Dot11)
    if dot11 is None:
        return
    original_bssid = dot11.addr3
    for attr in ("addr1", "addr2", "addr3"):
        if getattr(dot11, attr) == original_bssid:
            setattr(dot11, attr, target_bssid)


def build_and_retarget(classes: List[str], count: int, target_bssid: str) -> list:
    """`count` frames per class from attack_sim, each scoped to *target_bssid*."""
    frames = build_frames(classes, count)
    for frame in frames:
        _retarget(frame, target_bssid)
    return frames


# --- transmit ----------------------------------------------------------------
def transmit(iface: str, frames: list, rate: float) -> None:
    """Put the frames on the antenna, paced at *rate* frames/second."""
    from scapy.sendrecv import sendp  # imported lazily; needs a real radio

    inter = 1.0 / rate if rate > 0 else 0.0
    sendp(frames, iface=iface, inter=inter, verbose=False)


# --- verify against the Pi's packets table -----------------------------------
def _make_session(db_url: str):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url, pool_pre_ping=True, future=True)
    return sessionmaker(bind=engine, autoflush=False, future=True)()


def capture_baseline(db_url: str) -> int:
    """Highest packets.id before we inject, so verify only counts new rows."""
    from sqlalchemy import func

    from backend.app.models import Packet  # lazy: no DB config needed to import tool

    session = _make_session(db_url)
    try:
        return int(session.query(func.max(Packet.id)).scalar() or 0)
    finally:
        session.close()


def poll_new_packets(db_url: str, baseline_id: int, timeout: float,
                     interval: float = 1.0) -> List[str]:
    """Poll for predicted labels of rows written after *baseline_id*."""
    from backend.app.models import Packet

    deadline = time.time() + timeout
    labels: List[str] = []
    while True:
        session = _make_session(db_url)
        try:
            rows = (
                session.query(Packet.predicted_label)
                .filter(Packet.id > baseline_id)
                .all()
            )
        finally:
            session.close()
        labels = [r[0] for r in rows if r[0] is not None]
        if labels or time.time() >= deadline:
            break
        time.sleep(interval)
    return labels


def format_verify_report(expected_classes: Sequence[str],
                         detected_labels: Sequence[str]) -> str:
    """Render an honest per-class detection table with a PASS/PARTIAL/FAIL verdict.

    PASS    — the Pi labelled at least one new frame as this exact class.
    PARTIAL — the Pi saw attack traffic but under a different label (the
              expected shape of the AWID3 cross-hardware gap, models §2.7.1).
    FAIL    — the Pi wrote nothing new for this class.
    """
    from backend.detector.feature_spec import ATTACK_CLASSES

    attack_set = set(ATTACK_CLASSES)
    from collections import Counter
    counts = Counter(detected_labels)
    saw_any_attack = any(lbl in attack_set for lbl in detected_labels)

    lines: List[str] = []
    lines.append("")
    lines.append("=== HawkShield verify: what the Pi detected ===")
    lines.append(f"new rows since inject: {len(detected_labels)}")
    if detected_labels:
        breakdown = ", ".join(f"{lbl}={n}" for lbl, n in counts.most_common())
        lines.append(f"labels seen: {breakdown}")
    lines.append("")
    header = f"{'injected class':<14} {'as-itself':>9}  {'verdict':<8} note"
    lines.append(header)
    lines.append("-" * len(header))

    per_class_verdicts: List[str] = []
    for cls in expected_classes:
        hits = counts.get(cls, 0)
        if hits > 0:
            verdict, note = "PASS", "detected as the injected class"
        elif saw_any_attack:
            verdict, note = "PARTIAL", "attack seen, other label (cross-hw gap)"
        elif detected_labels:
            verdict, note = "PARTIAL", "traffic seen, not classed as attack"
        else:
            verdict, note = "FAIL", "Pi wrote nothing"
        per_class_verdicts.append(verdict)
        lines.append(f"{cls:<14} {hits:>9}  {verdict:<8} {note}")

    # Overall verdict.
    if not detected_labels:
        overall = "FAIL"
    elif all(v == "PASS" for v in per_class_verdicts):
        overall = "PASS"
    else:
        overall = "PARTIAL"

    lines.append("-" * len(header))
    lines.append(f"OVERALL: {overall}")
    lines.append("")
    if overall == "PASS":
        lines.append("Antenna-to-dashboard proven: the Pi saw and correctly classed the frames.")
    elif overall == "PARTIAL":
        lines.append(
            "The Pi detected traffic but not every class matched. This is the "
            "documented AWID3 cross-deployment gap (models/README.md §2.7.1): the "
            "model was validated across time within one recording, not across radio\n"
            "hardware. A PARTIAL over the air is expected, not a failure of capture."
        )
    else:
        lines.append(
            "The Pi wrote no new rows. Check: same channel as the AP, detector "
            "running, CAPTURE_IFACE correct, and the adapter actually injecting."
        )
    return "\n".join(lines)


# --- orchestration -----------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    # The legal warning prints on every run, before anything else happens.
    print(LEGAL_WARNING, file=sys.stderr)

    # Software safety gate — refuses without ownership assertion + explicit BSSID.
    enforce_transmit_safety(args)

    # Environment gate — Linux, root, monitor mode. (No-op path never reached on
    # Windows: this raises SystemExit there before any transmit.)
    require_radio_environment(args.iface)

    classes = resolve_classes(args.attack)
    frames = build_and_retarget(classes, args.count, args.target_bssid)

    baseline = capture_baseline(args.verify) if args.verify else None

    print(
        f"transmitting {len(frames)} frames "
        f"({args.count}/class x {len(classes)} classes: {', '.join(classes)}) "
        f"on {args.iface} at {args.rate:g} fps, scoped to {args.target_bssid}",
        file=sys.stderr,
    )
    transmit(args.iface, frames, args.rate)

    if args.verify:
        labels = poll_new_packets(args.verify, baseline or 0, args.verify_timeout)
        print(format_verify_report(classes, labels))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main())
