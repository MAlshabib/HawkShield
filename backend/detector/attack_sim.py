"""
Attack sources for simulation -- crafted 802.11 frames, and held-out AWID3 rows.

Two different things live here because two different questions need answering,
and one source cannot answer both.

Crafted frames -- ``build_frames``
----------------------------------
Real scapy 802.11 constructs, for callers that need actual frames:

  - ``--self-test``      proves a model loads and yields a full 46-feature
                         vector and a verdict on this machine
  - tools/inject_attack  transmits them over the air against your own testbed

So the constructors live here, once.  They are the same scapy constructs proven
in ``backend/tests/test_features_v2.py`` -- a crafted deauth carries reason code 7
(class-3 frame from a nonassociated station), which is what the feature contract
keys on and what a real deauth flood looks like on the air.

Nothing here transmits.  Building a frame and putting it on an antenna are
deliberately separate: this module is import-safe on any OS, and only
``tools/inject_attack.py`` (root, Linux) ever calls ``sendp()``.

Crafted frames are honest for a *self-test* but not for a demo.  Measured: a
burst of crafted deauths scores ``p1 = 0.959`` (the model is sure it is an
attack) but stage-2 confidence sits at ~0.36 and mislabels, because the booster's
single most important feature is ``roll64.frame.dt_log.mean`` -- inter-frame
timing -- and frames built in a ``for`` loop carry no timing.  So crafted frames
prove the plumbing; they do not drive ``/simulate``.

Held-out AWID3 rows -- ``load_sim_corpus``
------------------------------------------
The corpus at ``data/sim/awid3_sim_corpus.parquet`` is what ``POST /simulate``
replays: contiguous segments of real AWID3 frames the model never trained on, one
per attack class, each 46-feature row plus its integer ``label``.  These classify
correctly (Deauth->Deauth, Krack->Krack, ...) because they are the model's own
domain -- see ``data/sim/README.md`` and ``data/sim/build_sim_corpus.py`` for how
the segments were chosen and why the contiguous benign frames between attacks are
kept.  Loading needs pandas only; it does not touch scapy.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ReassoReq,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet as ScapyPacket

# Optional: EAPOL_KEY moved across scapy versions; degrade gracefully.
try:
    from scapy.layers.dot11 import EAPOL_KEY  # type: ignore
except Exception:  # pragma: no cover - version dependent
    EAPOL_KEY = None  # Krack falls back to a bare EAPOL frame

logger = logging.getLogger(__name__)

__all__ = [
    "SIM_CLASSES",
    "AttackSpec",
    "ATTACK_SPECS",
    "build_frames",
    "resolve_classes",
    "SIM_CORPUS_PATH",
    "SimCorpus",
    "CorpusUnavailable",
    "load_sim_corpus",
    "sim_mac",
]

# The classes we can craft a representative frame for. A subset of the model's
# nine: Normal is never an attack, and SSDP is a volumetric data-frame pattern
# with no single crafted frame that means "SSDP" on its own (it is better shown
# by replaying the corpus, which /simulate does).
SIM_CLASSES: List[str] = [
    "Deauth", "Disas", "(Re)Assoc", "RogueAP", "Krack", "Evil_Twin",
]

# Frontend key -> model class name, for the *craftable* classes only, so the API
# can accept either spelling.  Deliberately does NOT list SSDP or Kr00k: those
# have no crafted frame, and resolve_classes must never return a class that
# build_frames cannot build.  The corpus resolver (SimCorpus.resolve) has its own,
# wider key normalisation covering all eight attack classes.
_ALIASES: Dict[str, str] = {
    "deauth": "Deauth",
    "disas": "Disas",
    "disassoc": "Disas",
    "reassoc": "(Re)Assoc",
    "(re)assoc": "(Re)Assoc",
    "rogueap": "RogueAP",
    "rogue_ap": "RogueAP",
    "krack": "Krack",
    "evil_twin": "Evil_Twin",
    "eviltwin": "Evil_Twin",
}

# Test-net MACs (locally-administered bit set, so they can never collide with a
# real vendor OUI on the air).
_ATTACKER = "02:11:22:33:44:55"
_VICTIM = "02:aa:bb:cc:dd:01"
_AP = "02:de:ad:be:ef:01"
_BROADCAST = "ff:ff:ff:ff:ff:ff"


def _mgmt(subtype: int, addr1: str, addr2: str, addr3: str) -> Dot11:
    return Dot11(type=0, subtype=subtype, addr1=addr1, addr2=addr2, addr3=addr3)


def _deauth(bssid: str, victim: str) -> ScapyPacket:
    # subtype 12 = deauthentication; reason 7 = class-3 frame from nonassoc STA
    return RadioTap() / _mgmt(12, victim, bssid, bssid) / Dot11Deauth(reason=7)


def _disas(bssid: str, victim: str) -> ScapyPacket:
    # subtype 10 = disassociation; reason 1 = unspecified
    return RadioTap() / _mgmt(10, victim, bssid, bssid) / Dot11Disas(reason=1)


def _reassoc(bssid: str, client: str) -> ScapyPacket:
    # subtype 2 = reassociation request, from the client toward the AP
    return (
        RadioTap() / _mgmt(2, bssid, client, bssid)
        / Dot11ReassoReq(cap="ESS", current_AP=bssid, listen_interval=10)
        / Dot11Elt(ID=0, info=b"HawkShield-Test")
    )


def _rogue_ap(ssid: bytes, bssid: str) -> ScapyPacket:
    # a beacon claiming an SSID from an unexpected BSSID
    return (
        RadioTap() / _mgmt(8, _BROADCAST, bssid, bssid)
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=ssid)
        / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")   # supported rates
        / Dot11Elt(ID=3, info=b"\x06")               # DS param: channel 6
    )


def _evil_twin(ssid: bytes, bssid: str) -> ScapyPacket:
    # beacon impersonating a legitimate SSID from a spoofed, locally-admin BSSID
    return (
        RadioTap() / _mgmt(8, _BROADCAST, bssid, bssid)
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID=0, info=ssid)
        / Dot11Elt(ID=3, info=b"\x0b")               # different channel: 11
    )


def _krack(bssid: str, victim: str) -> ScapyPacket:
    # replayed EAPOL message 3 of the 4-way handshake (the KRACK signature)
    base = (
        RadioTap()
        / Dot11(type=2, subtype=0, FCfield="from-DS",
                addr1=victim, addr2=bssid, addr3=bssid)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(code=0x888E)
    )
    if EAPOL_KEY is not None:
        return base / EAPOL(version=2, type=3) / EAPOL_KEY(
            key_descriptor_type=2, key_length=16,
            has_key_mic=1, key_ack=1, install=1, secure=1, key_data_length=0,
        )
    return base / EAPOL(version=2, type=3)


@dataclass(frozen=True)
class AttackSpec:
    """How to build one attack class, and which pcap replays it end to end."""

    cls: str
    build: Callable[[], ScapyPacket]
    sample_pcap: Optional[str] = None   # a data/samples file that also shows it


ATTACK_SPECS: Dict[str, AttackSpec] = {
    "Deauth": AttackSpec("Deauth", lambda: _deauth(_AP, _VICTIM),
                         "deauth_raw_decrypted.pcapng"),
    "Disas": AttackSpec("Disas", lambda: _disas(_AP, _VICTIM),
                        "disassoc_raw_decrypted.pcapng"),
    "(Re)Assoc": AttackSpec("(Re)Assoc", lambda: _reassoc(_AP, _VICTIM),
                            "assoc_flood_raw_decrypted.pcapng"),
    "RogueAP": AttackSpec("RogueAP", lambda: _rogue_ap(b"HawkShield-Guest", _AP),
                          "beacon_raw_decrypted.pcapng"),
    "Krack": AttackSpec("Krack", lambda: _krack(_AP, _VICTIM), None),
    "Evil_Twin": AttackSpec("Evil_Twin", lambda: _evil_twin(b"HawkShield", _AP),
                            "beacon_raw_decrypted.pcapng"),
}


def resolve_classes(requested: Any) -> List[str]:
    """Map a request ('all', a list of keys or class names) to model class names.

    Accepts frontend keys ('deauth'), model names ('Deauth'), and 'all'. Unknown
    entries raise ValueError so the API can 400 rather than silently craft nothing.

    'all' expands to the crafted-frame classes (``SIM_CLASSES``); that is what the
    over-the-air injector and the self-test can build.  The corpus loader has its
    own, wider 'all' (every attack class the parquet holds) -- see
    ``load_sim_corpus``.
    """
    if requested is None:
        raise ValueError("no attacks requested")
    if isinstance(requested, str):
        requested = [requested]
    out: List[str] = []
    for item in requested:
        s = str(item).strip()
        if s.lower() == "all":
            return list(SIM_CLASSES)
        if s in ATTACK_SPECS:
            cls = s
        elif s.lower() in _ALIASES:
            cls = _ALIASES[s.lower()]
        else:
            raise ValueError(f"unknown attack: {item!r}")
        if cls not in out:
            out.append(cls)
    return out


def build_frames(classes: List[str], count: int) -> List[ScapyPacket]:
    """`count` crafted frames for each class, interleaved as a burst would arrive.

    Interleaving matters: the model's rolling features are causal over the frame
    stream, so a realistic mix beats one class fully drained before the next.
    """
    per = [ATTACK_SPECS[c] for c in classes]
    frames: List[ScapyPacket] = []
    for _ in range(count):
        for spec in per:
            frames.append(spec.build())
    return frames


# ---------------------------------------------------------------------------
# Held-out AWID3 corpus -- the /simulate source
# ---------------------------------------------------------------------------
#: The committed parquet.  ``data/`` is a sibling of ``backend/`` at the repo root
#: (backend/detector/attack_sim.py -> backend/detector -> backend -> repo root).
SIM_CORPUS_PATH: Path = Path(__file__).resolve().parents[2] / "data" / "sim" / "awid3_sim_corpus.parquet"


def _norm_key(name: str) -> str:
    """Punctuation-insensitive key: ``"(Re)Assoc" -> "reassoc"``, ``"Kr00k" -> "kr00k"``."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


#: Extra spellings the corpus resolver accepts, beyond each class's own norm key.
_EXTRA_CORPUS_KEYS: Dict[str, str] = {
    "disassoc": "Disas",
    "rogue_ap": "RogueAP",
    "evil_twin": "Evil_Twin",
    "reassoc": "(Re)Assoc",
}


class CorpusUnavailable(RuntimeError):
    """The simulation corpus cannot be loaded (missing file, or pandas absent).

    ``POST /simulate`` maps this to 503, exactly as ``/ask`` does when its RAG
    backend is missing: the feature declines rather than the process dying.
    """


# Locally-administered per-class MACs, so a simulated row is visibly synthetic on
# the map and in the tail and can never collide with a real vendor OUI.  The rows
# themselves are feature vectors with no addresses, so the demo needs *some* MAC
# to show; these are honest stand-ins, not spoofs of anything real.
_SIM_OUI = "02:5a:11"  # 0x02 = locally administered; "5a11" ~ "sim"


def sim_mac(cls: str, kind: str) -> str:
    """A deterministic locally-administered MAC for one class and role.

    ``kind`` is 'sa' (source), 'da' (destination) or 'bssid'.  Same class + kind
    always yields the same MAC, so top-offenders and the map group simulated
    traffic sensibly.
    """
    h = (abs(hash((cls, kind))) & 0xFFFF)
    role = {"sa": 0x10, "da": 0x20, "bssid": 0x30}.get(kind, 0x40)
    return f"{_SIM_OUI}:{role:02x}:{(h >> 8) & 0xFF:02x}:{h & 0xFF:02x}"


@dataclass(frozen=True)
class SimCorpus:
    """The parquet, grouped by class, ready to stream into a pipeline.

    ``rows[cls]`` is an ``(n, 46)`` float32 array in ``FEATURE_ORDER`` order --
    the contiguous segment for that class, benign frames included, in capture
    order.  ``labels[cls]`` is the matching ``(n,)`` int array of class ids, so a
    caller can tell which rows are the attack (they self-classify) and which are
    the interleaved Normal frames (they do not persist).
    """

    path: Path
    spec_version: Optional[str]
    feature_order: List[str]
    rows: Dict[str, Any]           # cls -> np.ndarray (n, 46) float32
    labels: Dict[str, Any]         # cls -> np.ndarray (n,)   int
    class_to_id: Dict[str, int]

    @property
    def classes(self) -> List[str]:
        """Attack classes present in the corpus, in feature_spec order."""
        return list(self.rows.keys())

    def resolve(self, requested: Any) -> List[str]:
        """Map a request to corpus class names.  'all' = every class present.

        Wider than :func:`resolve_classes`: the corpus covers all eight attack
        classes (Kr00k and SSDP included), not just the six with a crafted frame.
        Keys are matched by a punctuation-insensitive normalisation, so
        ``"evil_twin"``, ``"Evil_Twin"`` and ``"eviltwin"`` all resolve, as do
        ``"(re)assoc"``, ``"reassoc"`` and ``"disassoc"``.
        """
        if requested is None:
            raise ValueError("no attacks requested")
        if isinstance(requested, str):
            requested = [requested]

        # normalised key -> class name, for every class actually present.
        norm = {_norm_key(c): c for c in self.rows}
        norm.update({_norm_key(k): v for k, v in _EXTRA_CORPUS_KEYS.items() if v in self.rows})

        out: List[str] = []
        for item in requested:
            s = str(item).strip()
            if s.lower() == "all":
                return list(self.rows.keys())
            cls = s if s in self.rows else norm.get(_norm_key(s))
            if not cls:
                raise ValueError(f"unknown or absent attack class: {item!r}")
            if cls not in out:
                out.append(cls)
        return out


_CORPUS_CACHE: Dict[str, SimCorpus] = {}


def load_sim_corpus(path: Optional[Path] = None, use_cache: bool = True) -> SimCorpus:
    """Load and group the corpus parquet, or raise :class:`CorpusUnavailable`.

    Cached by path: the file is small and immutable at runtime, so one read
    serves every request.  Needs pandas + a parquet engine (pyarrow); both ship
    with the model stack, and their absence is reported as unavailability rather
    than crashing the import.
    """
    p = Path(path) if path is not None else SIM_CORPUS_PATH
    key = str(p.resolve())
    if use_cache and key in _CORPUS_CACHE:
        return _CORPUS_CACHE[key]

    if not p.is_file():
        raise CorpusUnavailable(f"simulation corpus not found: {p}")

    try:
        import numpy as np
        import pandas as pd
    except Exception as exc:  # pragma: no cover - only on a partial install
        raise CorpusUnavailable(f"pandas/numpy unavailable: {exc}") from exc

    # feature_spec is a stdlib-only leaf; safe to import without dragging the model.
    from backend.detector.feature_spec import CLASSES, FEATURE_ORDER

    try:
        df = pd.read_parquet(p)
    except Exception as exc:
        raise CorpusUnavailable(f"{p} is not a readable parquet: {exc}") from exc

    missing = [c for c in ("cls", "seq", "label", *FEATURE_ORDER) if c not in df.columns]
    if missing:
        raise CorpusUnavailable(
            f"{p} is missing expected columns {missing[:6]}"
            + ("..." if len(missing) > 6 else "")
        )

    class_to_id = {c: i for i, c in enumerate(CLASSES)}
    rows: Dict[str, Any] = {}
    labels: Dict[str, Any] = {}
    # Preserve feature_spec class order, not the parquet's row order.
    for cls in CLASSES:
        g = df[df["cls"] == cls]
        if g.empty:
            continue
        g = g.sort_values("seq")
        rows[cls] = g[FEATURE_ORDER].to_numpy(dtype=np.float32)
        labels[cls] = g["label"].to_numpy(dtype=np.int64)

    if not rows:
        raise CorpusUnavailable(f"{p} holds no rows for any known class")

    corpus = SimCorpus(
        path=p,
        spec_version=None,
        feature_order=list(FEATURE_ORDER),
        rows=rows,
        labels=labels,
        class_to_id=class_to_id,
    )
    if use_cache:
        _CORPUS_CACHE[key] = corpus
    logger.info(
        "sim corpus loaded: %s classes=%s total_rows=%d",
        p, list(rows), int(sum(len(v) for v in rows.values())),
    )
    return corpus
