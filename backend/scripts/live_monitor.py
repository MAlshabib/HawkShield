#!/usr/bin/env python3
"""Console real-time tail of the ``packets`` table -- the terminal twin of GET /stream.

Polls the database for new detections and prints each as one coloured line, so you
can watch the detector (or ``POST /simulate``) work without a browser:

    python -m backend.scripts.live_monitor --follow
    python -m backend.scripts.live_monitor --follow --sim-only
    python -m backend.scripts.live_monitor --since-id 0            # replay history, then exit

It reuses ``backend.app.db`` and the ``Packet`` model -- the same engine, session
factory and schema the API and detector use -- so it reads exactly what they
wrote, against whatever ``DATABASE_URL`` points at.

Columns: timestamp, predicted class, ``p1``/``p2``, source MAC -> BSSID, and a
``SIM`` tag when ``raw.sim`` is set (a row written by /simulate).  Colour is by
class and is dropped automatically when stdout is not a TTY (or ``--no-color``),
so piping to a file stays clean.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

logger = logging.getLogger("live_monitor")

# ANSI colours by attack class; anything unknown falls back to default.
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CLASS_COLOR: Dict[str, str] = {
    "Deauth": "\033[91m",       # red
    "Disas": "\033[95m",        # magenta
    "(Re)Assoc": "\033[93m",    # yellow
    "RogueAP": "\033[96m",      # cyan
    "Krack": "\033[92m",        # green
    "Kr00k": "\033[94m",        # blue
    "Evil_Twin": "\033[33m",    # orange-ish
    "SSDP": "\033[90m",         # grey
}


def _sim_flag(raw: Any) -> bool:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return False
    return bool(raw.get("sim")) if isinstance(raw, dict) else False


def _fmt(row: Dict[str, Any], color: bool) -> str:
    ts = row.get("ts")
    ts_s = ts.strftime("%H:%M:%S") if hasattr(ts, "strftime") else str(ts)
    label = row.get("predicted_label") or "?"
    p1 = row.get("proba_anomaly")
    p2 = row.get("proba_attack")
    p1_s = f"{p1:.3f}" if isinstance(p1, (int, float)) else " -- "
    p2_s = f"{p2:.3f}" if isinstance(p2, (int, float)) else " -- "
    sa = row.get("src_mac") or "??:??:??:??:??:??"
    bssid = row.get("bssid") or "??:??:??:??:??:??"
    sim = _sim_flag(row.get("raw"))
    tag = "SIM " if sim else "    "

    line = (
        f"{ts_s}  {tag}{label:<11}  p1={p1_s} p2={p2_s}  "
        f"{sa} -> {bssid}  #{row.get('id')}"
    )
    if not color:
        return line
    col = _CLASS_COLOR.get(label, "")
    tag_c = f"{_DIM}SIM {_RESET}" if sim else "    "
    return (
        f"{_DIM}{ts_s}{_RESET}  {tag_c}{col}{_BOLD}{label:<11}{_RESET}  "
        f"p1={p1_s} p2={p2_s}  {sa} -> {bssid}  {_DIM}#{row.get('id')}{_RESET}"
    )


def _max_id(SessionLocal: Any) -> int:
    from sqlalchemy import func

    from backend.app.models import Packet

    s = SessionLocal()
    try:
        return int(s.query(func.max(Packet.id)).scalar() or 0)
    finally:
        s.close()


def _poll_once(SessionLocal: Any, last_id: int, sim_only: bool, limit: int):
    """Return ``(rows, new_last_id)`` for ids greater than ``last_id``."""
    from backend.app.models import Packet

    s = SessionLocal()
    try:
        q = (
            s.query(Packet)
            .filter(Packet.id > last_id)
            .order_by(Packet.id.asc())
            .limit(limit)
        )
        rows: List[Dict[str, Any]] = []
        new_last = last_id
        for p in q:
            new_last = p.id
            if sim_only and not _sim_flag(p.raw):
                continue
            rows.append({
                "id": p.id, "ts": p.ts, "predicted_label": p.predicted_label,
                "proba_anomaly": p.proba_anomaly, "proba_attack": p.proba_attack,
                "src_mac": p.src_mac, "bssid": p.bssid, "raw": p.raw,
            })
        return rows, new_last
    finally:
        s.close()


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Live console tail of the packets table")
    ap.add_argument("--follow", "-f", action="store_true",
                    help="keep polling for new rows (Ctrl-C to stop); "
                         "without it, print what is there and exit")
    ap.add_argument("--since-id", type=int, default=None,
                    help="start after this packet id; default is the current tail in "
                         "--follow mode, or 0 (all history) for a one-shot dump")
    ap.add_argument("--sim-only", action="store_true",
                    help="show only rows written by /simulate (raw.sim = true)")
    ap.add_argument("--interval", type=float, default=1.0, help="poll seconds (default: %(default)s)")
    ap.add_argument("--limit", type=int, default=1000, help="rows drained per poll")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    color = (not args.no_color) and sys.stdout.isatty()

    from backend.app.db import SessionLocal

    if args.since_id is not None:
        last_id = args.since_id
    elif args.follow:
        last_id = _max_id(SessionLocal)  # only genuinely new rows
        print(f"{_DIM if color else ''}watching for detections after id={last_id} "
              f"(Ctrl-C to stop){_RESET if color else ''}")
    else:
        last_id = 0

    printed = 0
    try:
        while True:
            rows, last_id = _poll_once(SessionLocal, last_id, args.sim_only, args.limit)
            for row in rows:
                print(_fmt(row, color))
                printed += 1
            if not args.follow:
                break
            time.sleep(max(0.1, args.interval))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        print(f"\n{_DIM if color else ''}stopped after {printed} row(s){_RESET if color else ''}")
        return 0

    if not args.follow and printed == 0:
        print("(no rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
