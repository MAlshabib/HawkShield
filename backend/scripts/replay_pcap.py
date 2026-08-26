#!/usr/bin/env python3
"""Replay a capture file through the live detector path - no radio required.

Uses the *same* ``backend.detector.features.packet_to_row`` and
``backend.detector.pipeline.TwoStagePipeline`` the detector uses, so whatever this
prints is what the Pi would have done with the same frames.

    python -m backend.scripts.replay_pcap data/samples/deauth_raw_decrypted.pcapng
    python -m backend.scripts.replay_pcap data/samples/*.pcapng --limit 5000 --json
    python -m backend.scripts.replay_pcap capture.pcapng --to-db

Default mode is ``--dry-run``: nothing touches the database.
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

import numpy as np  # noqa: E402

from backend.detector._config import get_settings  # noqa: E402
from backend.detector.features import (  # noqa: E402
    FEATURE_ORDER,
    ExtractState,
    packet_to_row,
)
from backend.detector.pipeline import TwoStagePipeline, Verdict  # noqa: E402

logger = logging.getLogger("replay_pcap")

CHUNK = 2048


# ---------------------------------------------------------------------------
def _iter_packets(path: Path, limit: Optional[int]):
    from scapy.utils import PcapReader

    n = 0
    with PcapReader(str(path)) as rd:
        for pkt in rd:
            yield pkt
            n += 1
            if limit and n >= limit:
                return


def _score_chunk(
    pipe: TwoStagePipeline, rows: List[Dict[str, Any]], per_packet: bool
) -> List[Verdict]:
    """Score a chunk of rows. Batched by default; identical maths to ``pipe.predict``."""
    if per_packet:
        return [pipe.predict(r) for r in rows]

    out: List[Verdict] = [Verdict(is_attack=False, stage=0)] * len(rows)
    p1 = pipe.stage1.predict_proba_batch(rows)
    if p1 is None:
        return out

    hot_idx = [i for i, p in enumerate(p1) if p >= pipe.thr1]
    for i, p in enumerate(p1):
        out[i] = Verdict(is_attack=False, p1=float(p), stage=1)
    if not hot_idx:
        return out

    probs = pipe.stage2.predict_batch([rows[i] for i in hot_idx])
    if probs is None:
        return out
    id_to_class = pipe.stage2.id_to_class
    for k, i in enumerate(hot_idx):
        vec = np.asarray(probs[k], dtype=float)
        cid = int(np.argmax(vec))
        label = id_to_class.get(cid, str(cid))
        p2 = float(vec[cid])
        out[i] = Verdict(
            is_attack=p2 >= pipe.thr2, label=label, p1=float(p1[i]), p2=p2, stage=2
        )
    return out


# ---------------------------------------------------------------------------
def replay_file(
    path: Path,
    pipe: TwoStagePipeline,
    iface: str,
    limit: Optional[int],
    sink: Any = None,
    per_packet: bool = False,
    null_features: Optional[List[str]] = None,
) -> Dict[str, Any]:
    state = ExtractState()
    non_null = {k: 0 for k in FEATURE_ORDER}
    labels: Dict[str, int] = {}
    considered_labels: Dict[str, int] = {}
    n = 0
    n_stage1_hot = 0
    n_attacks = 0
    t0 = time.time()

    buf_rows: List[Dict[str, Any]] = []
    buf_raw: List[Dict[str, Any]] = []

    def _drain() -> None:
        nonlocal n_stage1_hot, n_attacks
        if not buf_rows:
            return
        verdicts = _score_chunk(pipe, buf_rows, per_packet)
        for raw, row, v in zip(buf_raw, buf_rows, verdicts):
            if v.p1 is not None and v.p1 >= pipe.thr1:
                n_stage1_hot += 1
            if v.stage == 2 and v.label:
                considered_labels[v.label] = considered_labels.get(v.label, 0) + 1
            if v.is_attack and v.label:
                n_attacks += 1
                labels[v.label] = labels.get(v.label, 0) + 1
                if sink is not None:
                    sink.write(raw, row, v, iface)
        buf_rows.clear()
        buf_raw.clear()

    for pkt in _iter_packets(path, limit):
        row, raw = packet_to_row(pkt, iface, state)
        if null_features:
            for f in null_features:
                row[f] = None
        n += 1
        for k, val in row.items():
            if val is not None:
                non_null[k] += 1
        buf_rows.append(row)
        buf_raw.append(raw)
        if len(buf_rows) >= CHUNK:
            _drain()
    _drain()

    elapsed = time.time() - t0
    coverage = {k: (100.0 * non_null[k] / n if n else 0.0) for k in FEATURE_ORDER}
    return {
        "file": str(path),
        "packets": n,
        "seconds": round(elapsed, 2),
        "pps": round(n / elapsed, 1) if elapsed > 0 else None,
        "stage1_hot": n_stage1_hot,
        "stage1_attack_rate_pct": round(100.0 * n_stage1_hot / n, 2) if n else 0.0,
        "attacks_persisted": n_attacks,
        "persist_rate_pct": round(100.0 * n_attacks / n, 2) if n else 0.0,
        "labels_persisted": dict(sorted(labels.items(), key=lambda kv: -kv[1])),
        "labels_stage2_argmax": dict(sorted(considered_labels.items(), key=lambda kv: -kv[1])),
        "feature_coverage_pct": coverage,
        "capture_span_s": round((state.prev_ts - state.start_ts), 3)
        if (state.prev_ts is not None and state.start_ts is not None)
        else None,
    }


# ---------------------------------------------------------------------------
def _print_report(res: Dict[str, Any], thr1: float, thr2: float) -> None:
    print("=" * 78)
    print(f"FILE  {res['file']}")
    print(
        f"  packets read      : {res['packets']}   "
        f"({res['seconds']}s, {res['pps']} pkt/s, capture span {res['capture_span_s']}s)"
    )
    print(
        f"  stage-1 >= {thr1:.2f}   : {res['stage1_hot']} "
        f"({res['stage1_attack_rate_pct']}%)"
    )
    print(
        f"  persisted (p2>={thr2:.2f}): {res['attacks_persisted']} "
        f"({res['persist_rate_pct']}%)"
    )

    print("  stage-2 label distribution (argmax over stage-1 hits):")
    tot = sum(res["labels_stage2_argmax"].values()) or 1
    if not res["labels_stage2_argmax"]:
        print("    (none)")
    for lbl, c in res["labels_stage2_argmax"].items():
        kept = res["labels_persisted"].get(lbl, 0)
        print(f"    {lbl:<12} {c:>7}  ({100.0*c/tot:5.1f}%)   persisted {kept}")

    print("  feature coverage (% packets with a non-null value):")
    cov = res["feature_coverage_pct"]
    for k in FEATURE_ORDER:
        bar = "#" * int(round(cov[k] / 5.0))
        print(f"    {k:<30} {cov[k]:6.1f}%  {bar}")


def main(argv: Optional[List[str]] = None) -> int:
    s = get_settings()
    ap = argparse.ArgumentParser(description="Replay a pcap/pcapng through the HawkShield detector")
    ap.add_argument("pcap", nargs="+", help="capture file(s)")
    ap.add_argument("--model-dir", default=None, help="directory holding the two bundles")
    ap.add_argument("--threshold1", type=float, default=None)
    ap.add_argument("--threshold2", type=float, default=None)
    ap.add_argument("--iface", default=getattr(s, "CAPTURE_IFACE", "wlan1"),
                    help="interface name recorded on the rows")
    ap.add_argument("--limit", type=int, default=None, help="stop after N packets per file")
    mx = ap.add_mutually_exclusive_group()
    mx.add_argument("--dry-run", action="store_true", default=True,
                    help="do not touch the database (default)")
    mx.add_argument("--to-db", action="store_true",
                    help="write detected attacks to the database via PacketSink")
    ap.add_argument("--null-feature", action="append", default=None, metavar="NAME",
                    help="force a feature to null before scoring (repeatable) - use it to "
                         "reproduce the leakage ablation in models/README.md")
    ap.add_argument("--per-packet", action="store_true",
                    help="score one row at a time (slower; identical result to the default batching)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--log-level", default=getattr(s, "LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    bad = [f for f in (args.null_feature or []) if f not in FEATURE_ORDER]
    if bad:
        print(f"ERROR: --null-feature {bad} not in the 31-feature space", file=sys.stderr)
        return 2

    paths = [Path(p) for p in args.pcap]
    missing = [p for p in paths if not p.is_file()]
    if missing:
        for p in missing:
            print(f"ERROR: no such capture file: {p}", file=sys.stderr)
        return 2

    try:
        pipe = TwoStagePipeline(
            model_dir=Path(args.model_dir) if args.model_dir else None,
            thr1=args.threshold1,
            thr2=args.threshold2,
        )
    except Exception as e:
        print(f"ERROR: could not load model bundles: {e}", file=sys.stderr)
        return 2

    sink = None
    if args.to_db:
        from backend.detector.sink import PacketSink

        try:
            sink = PacketSink()
        except Exception as e:
            print(f"ERROR: could not open the database sink: {e}", file=sys.stderr)
            return 2

    results = []
    try:
        for p in paths:
            results.append(
                replay_file(p, pipe, args.iface, args.limit, sink=sink,
                            per_packet=args.per_packet,
                            null_features=args.null_feature)
            )
    finally:
        if sink is not None:
            sink.close()

    if args.json:
        print(json.dumps(
            {"thr1": pipe.thr1, "thr2": pipe.thr2, "to_db": bool(args.to_db),
             "results": results},
            indent=2,
        ))
    else:
        for res in results:
            _print_report(res, pipe.thr1, pipe.thr2)
        if len(results) > 1:
            print("=" * 78)
            print("SUMMARY")
            print(f"  {'file':<44} {'pkts':>7} {'stage1%':>8} {'saved':>7} {'top label':>12}")
            for r in results:
                top = next(iter(r["labels_persisted"]), "-")
                print(f"  {Path(r['file']).name:<44} {r['packets']:>7} "
                      f"{r['stage1_attack_rate_pct']:>8} {r['attacks_persisted']:>7} {top:>12}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
