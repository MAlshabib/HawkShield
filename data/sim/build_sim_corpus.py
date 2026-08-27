#!/usr/bin/env python3
"""Rebuild ``data/sim/awid3_sim_corpus.parquet`` -- the source POST /simulate replays.

Why a corpus at all
-------------------
Three sources were measured as candidates for the simulate button, and only one
of them tells the truth:

* **Crafted scapy frames.** A burst of hand-built deauths scores ``p1 = 0.959``
  -- the model is sure it is *an attack* -- but stage-2 confidence sits around
  0.36 and the class is wrong.  The reason is measurable: the single most
  important column in the booster is ``roll64.frame.dt_log.mean``, inter-frame
  timing, and frames built in a ``for`` loop have no timing.  Crafted frames are
  kept for ``--self-test`` (they prove the model loads and produces a full
  46-feature vector) and for ``tools/inject_attack.py`` (a real radio supplies
  the timing).  They are not a demo source.
* **``data/samples/*.pcapng``.** Out of domain: they come from the original
  project's own testbed, not AWID3.  The AWID3-trained model flags them as
  attacks and then labels almost all of them Krack.  That is the
  cross-deployment gap documented in ``models/README.md`` section 2.7.1, and it
  is a finding, not a demo.
* **Held-out AWID3 feature rows.** The model's own domain, and the only honest
  source.  This file.

How the corpus is built
-----------------------
One contiguous **segment** per attack class, taken from a block the model has
never seen -- ``_work/models_v2/split.json``'s ``test`` list, whole ``block_id``
groups, the same holdout the reported macro-F1 was measured on.

The segment is contiguous *including the Normal frames interleaved with the
attack*, and that detail is the whole design.  The GBDT reads 36 causal rolling
aggregates over the frame stream; filtering a block down to just its
attack-labelled rows produces a stream that never existed on any air, and the
aggregates then describe that stream.  Measured, on the same seven held-out
Kr00k blocks:

    label-filtered rows only ....   0.1% -   4.2% correctly persisted as Kr00k
    contiguous segment .........  97.0% - 100.0%

Same model, same frames, same order.  The only difference is whether the benign
frames between the attack frames were kept.  So they are kept, they are pushed
through the pipeline like everything else, and they legitimately come back
Normal and are not persisted -- which is also what a real capture looks like.

Selection rule: for each class, every held-out block is scanned for the stretch
with the most attack-labelled rows in it, that stretch is scored through the
*real* ``build_pipeline()``, and the block with the best correct-persist rate
wins (ties broken by attack density).  "The held-out block the model handles most
cleanly" is a deliberate choice, and it is stated in the summary this script
prints, in ``data/sim/README.md`` and in ``docs/CONTRACT.md``: the simulate
button demonstrates the detector on data it is good at, and the per-class rates
it reports are the real measured ones.

The stretch starts at ``--window`` frames and doubles, up to ``--max-window``,
until it holds ``--target-attacks`` attack-labelled rows.  Attack density is not
a free parameter -- it is a property of AWID3.  Krack, SSDP and Evil_Twin are
dense enough that 2,000 frames hold well over a thousand attack rows; RogueAP is
the opposite extreme, 1,310 rows in the entire archive and never more than 143 in
any one 50,000-frame block, so its segment grows to the cap and still holds only
a few dozen.  ``/simulate`` replays a segment repeatedly when a request asks for
more detections than one pass yields, and reports how many frames that took.

    python data/sim/build_sim_corpus.py --window 2000

Its inputs live in ``_work/`` and are build-time only; they are not committed.
The parquet it writes is.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from backend.detector.feature_spec import (  # noqa: E402
    ATTACK_CLASSES,
    CLASSES,
    FEATURE_ORDER,
    SPEC_VERSION,
)
from backend.detector.pipeline import build_pipeline  # noqa: E402

#: block_id prefix -> the ``_work/awid3_v2`` directory and file stem holding it.
_BLOCK_SOURCES: Dict[str, Tuple[str, str]] = {
    "Deauth": ("1.Deauth", "Deauth"),
    "Disas": ("2.Disas", "Disas"),
    "(Re)Assoc": ("3.(Re)Assoc", "(Re)Assoc"),
    "Rogue_AP": ("4.Rogue_AP", "RogueAP"),
    "Krack": ("5.Krack", "Krack"),
    "Kr00k": ("6.Kr00k", "Kr00k"),
    "SSDP": ("11.SSDP", "SSDP"),
    "Evil_Twin": ("12.Evil_Twin", "Evil_Twin"),
}

#: model class name -> block_id prefix.  They differ for RogueAP only.
_CLASS_TO_PREFIX: Dict[str, str] = {
    "RogueAP": "Rogue_AP",
    **{c: c for c in ATTACK_CLASSES if c != "RogueAP"},
}


def _densest_window(mask: np.ndarray, window: int) -> Tuple[int, int, int]:
    """``(lo, hi, n_attack)`` of the ``window``-row stretch holding the most attacks."""
    n = len(mask)
    if n <= window:
        return 0, n, int(mask.sum())
    cs = np.concatenate(([0], np.cumsum(mask.astype(np.int64))))
    counts = cs[window:] - cs[:-window]
    lo = int(np.argmax(counts))
    return lo, lo + window, int(counts[lo])


def _score(pipe, seg: pd.DataFrame, cls: str) -> Tuple[float, int, Dict[str, int]]:
    """Push a segment through the real pipeline; return the correct-persist rate."""
    pipe.reset()
    verdicts = pipe.predict_stream(list(seg[FEATURE_ORDER].to_numpy(dtype=np.float32)))
    want = CLASSES.index(cls)
    is_attack_row = seg["label"].to_numpy() == want
    n = int(is_attack_row.sum())
    labels: Dict[str, int] = {}
    ok = 0
    for j, v in enumerate(verdicts):
        if not is_attack_row[j]:
            continue
        if v.is_attack and v.label:
            labels[v.label] = labels.get(v.label, 0) + 1
            if v.label == cls:
                ok += 1
    return (100.0 * ok / n if n else 0.0), n, labels


def _pick_window(mask: np.ndarray, window: int, max_window: int, target: int) -> Tuple[int, int, int]:
    """Smallest stretch from ``window`` up to ``max_window`` holding ``target`` attacks."""
    lo, hi, n = _densest_window(mask, window)
    while n < target and window < max_window:
        window = min(window * 2, max_window)
        lo, hi, n = _densest_window(mask, window)
    return lo, hi, n


def build(
    work: Path,
    split_file: Path,
    window: int,
    max_window: int,
    target_attacks: int,
    min_attacks: int,
) -> pd.DataFrame:
    splits = json.loads(split_file.read_text(encoding="utf-8"))["splits"]
    held_out = sorted(set(splits["test"]))
    pipe = build_pipeline("auto")
    print(f"scoring with {pipe.model_version} (spec {getattr(pipe, 'spec_version', '?')})\n")

    frames: List[pd.DataFrame] = []
    for cls in ATTACK_CLASSES:
        prefix = _CLASS_TO_PREFIX[cls]
        sub, stem = _BLOCK_SOURCES[prefix]
        want = CLASSES.index(cls)
        best: Optional[Tuple[Tuple[float, int, int], float, int, pd.DataFrame, str, Dict[str, int]]] = None

        for block in [b for b in held_out if b.split(":")[0] == prefix]:
            path = work / sub / f"{stem}_{int(block.split(':')[1])}.parquet"
            if not path.is_file():
                continue
            df = pd.read_parquet(path).reset_index(drop=True)
            mask = df["label"].to_numpy() == want
            if mask.sum() < min_attacks:
                continue
            lo, hi, n_att = _pick_window(mask, window, max_window, target_attacks)
            seg = df.iloc[lo:hi].reset_index(drop=True)
            rate, _n, labels = _score(pipe, seg, cls)
            # Rate first; then attack count, but only up to the target -- past it
            # more attacks are not better, and a shorter segment is.
            key = (round(rate, 3), min(n_att, target_attacks), -len(seg))
            if best is None or key > best[0]:
                best = (key, rate, n_att, seg, block, labels)

        if best is None:
            print(f"  {cls:<10} SKIPPED - no held-out block with >= {min_attacks} rows")
            continue

        _key, rate, n_att, seg, block, labels = best
        out = seg[FEATURE_ORDER + ["label"]].copy()
        out.insert(0, "cls", cls)
        out.insert(1, "seq", np.arange(len(out), dtype=np.int32))
        out["block_id"] = block
        frames.append(out)
        print(
            f"  {cls:<10} block {block:<14} frames={len(seg):<5} attack_rows={n_att:<5} "
            f"correct={rate:5.1f}%  labels={labels}"
        )

    return pd.concat(frames, ignore_index=True)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Rebuild the /simulate corpus from held-out AWID3")
    ap.add_argument("--work", type=Path, default=_REPO_ROOT / "_work" / "awid3_v2",
                    help="prepared AWID3 feature parquets (build-time only)")
    ap.add_argument("--split", type=Path,
                    default=_REPO_ROOT / "_work" / "models_v2" / "split.json",
                    help="the training split; only its `test` blocks are eligible")
    ap.add_argument("--window", type=int, default=2000, help="starting segment length, frames")
    ap.add_argument("--max-window", type=int, default=8000,
                    help="cap the segment grows to when the class is sparse")
    ap.add_argument("--target-attacks", type=int, default=400,
                    help="grow the segment until it holds this many attack rows")
    ap.add_argument("--min-attacks", type=int, default=30,
                    help="ignore a block with fewer attack rows than this")
    ap.add_argument("--out", type=Path,
                    default=_REPO_ROOT / "data" / "sim" / "awid3_sim_corpus.parquet")
    args = ap.parse_args(argv)

    for p in (args.work, args.split):
        if not p.exists():
            print(
                f"ERROR: {p} not found.  This builder needs the prepared AWID3 "
                f"parquets and the training split, which are build-time inputs and "
                f"are not committed.", file=sys.stderr,
            )
            return 2

    df = build(
        args.work, args.split, args.window, args.max_window,
        args.target_attacks, args.min_attacks,
    )
    for col in FEATURE_ORDER:
        df[col] = df[col].astype(np.float32)
    df["label"] = df["label"].astype(np.int16)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False, compression="zstd")
    print(
        f"\nwrote {args.out}  rows={len(df)}  classes={df['cls'].nunique()}  "
        f"spec={SPEC_VERSION}  size={args.out.stat().st_size / 1024:.0f} KB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
