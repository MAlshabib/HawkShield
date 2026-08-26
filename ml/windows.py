#!/usr/bin/env python3
"""
Block-aware data loading, grouped splitting and window construction.

This module is the single definition of *how frames are grouped into model
inputs*, shared by training, evaluation, and the live detector. Two invariants
are enforced here and nowhere else:

1. **A window never spans a block boundary.** One ``block_id`` is one 50,000-frame
   contiguous source file. Frames from two different files are not temporally
   adjacent even when ``frame.number`` says they are, and a window that straddles
   the seam teaches the model a discontinuity that does not exist in the field.

2. **Splits are made over whole blocks, never over rows.** ``frame.number`` is
   continuous across an attack's chunk files, so each attack folder is ONE
   capture; leave-one-capture-out would delete the class. Holding out whole
   blocks is the strongest split AWID3 permits. See ``ml/README.md``.

The live detector mirrors :func:`inference_chunks` with a ring buffer: keep the
last ``context`` frames of the current stream, append the new frame, run the
model, take the prediction at the final position. Identical arithmetic, so a
frame scored offline and the same frame scored online see the same context.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

import numpy as np
import pyarrow.parquet as pq

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.detector.feature_spec import (  # noqa: E402
    CLASSES,
    FEATURE_ORDER,
    SPEC_VERSION,
)

__all__ = [
    "CLASSES",
    "FEATURE_ORDER",
    "SPEC_VERSION",
    "BlockDataset",
    "load_blocks",
    "block_label_counts",
    "grouped_split",
    "training_windows",
    "inference_chunks",
    "gather_windows",
]

N_CLASSES = len(CLASSES)
N_FEATURES = len(FEATURE_ORDER)


# --------------------------------------------------------------------------- #
# Dataset container                                                            #
# --------------------------------------------------------------------------- #
@dataclass
class BlockDataset:
    """Rows in capture order, plus the block boundaries that partition them."""

    X: np.ndarray                    # (N, 47) float32, NaN preserved
    y: np.ndarray                    # (N,)    int64, index into CLASSES
    block_ids: List[str]             # (B,)    e.g. "Deauth:0022"
    bounds: np.ndarray               # (B, 2)  [start, stop) row indices, contiguous
    sessions: List[str] = field(default_factory=list)   # (B,) e.g. "Deauth"

    @property
    def n_blocks(self) -> int:
        return len(self.block_ids)

    def block_len(self, b: int) -> int:
        return int(self.bounds[b, 1] - self.bounds[b, 0])

    def rows_of(self, blocks: Sequence[int]) -> np.ndarray:
        """Row indices belonging to the given blocks, in capture order."""
        if len(blocks) == 0:
            return np.zeros(0, dtype=np.int64)
        return np.concatenate(
            [np.arange(self.bounds[b, 0], self.bounds[b, 1], dtype=np.int64) for b in blocks]
        )

    def subset_bounds(self, blocks: Sequence[int]) -> np.ndarray:
        return self.bounds[np.asarray(blocks, dtype=np.int64)]


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #
def _shards(data_dir: Path) -> List[Path]:
    return sorted(p for p in data_dir.glob("*/*.parquet"))


def block_label_counts(data_dir: Path) -> Tuple[List[Path], List[str], np.ndarray]:
    """Cheap first pass: read only the ``label`` column of every shard.

    Returns (shard paths, block ids, counts of shape (n_blocks, n_classes)).
    Used to pick blocks for ``--max-rows`` without paying for the features.
    """
    paths = _shards(data_dir)
    if not paths:
        raise FileNotFoundError(f"no parquet shards under {data_dir}")
    ids: List[str] = []
    counts = np.zeros((len(paths), N_CLASSES), dtype=np.int64)
    for i, p in enumerate(paths):
        t = pq.read_table(p, columns=["label", "block_id"])
        lab = t.column("label").to_numpy(zero_copy_only=False).astype(np.int64)
        bid = t.column("block_id").to_numpy(zero_copy_only=False)
        uniq = set(bid.tolist())
        if len(uniq) != 1:
            raise ValueError(f"{p} holds {len(uniq)} block_ids; one shard must be one block")
        ids.append(str(next(iter(uniq))))
        counts[i] = np.bincount(lab, minlength=N_CLASSES)
    return paths, ids, counts


def select_blocks(counts: np.ndarray, max_rows: Optional[int], seed: int) -> np.ndarray:
    """Choose whole blocks under a row budget, rarest-class-first.

    Never subsamples *rows* -- that would break contiguity, which is the whole
    point of block grouping. Blocks holding rare attacks are taken first so a
    small ``--max-rows`` run still sees every class it can.
    """
    n = counts.shape[0]
    order = np.arange(n)
    if max_rows is None or counts.sum() <= max_rows:
        return order

    totals = counts.sum(axis=0)
    rng = np.random.default_rng(seed)
    # rarity of a block = smallest global count among the attack classes it holds
    rarity = np.full(n, np.inf)
    for b in range(n):
        present = [c for c in range(1, N_CLASSES) if counts[b, c] > 0]
        if present:
            rarity[b] = min(totals[c] for c in present)
    jitter = rng.random(n)
    order = np.lexsort((jitter, -counts[:, 1:].sum(axis=1), rarity))

    keep, used = [], 0
    for b in order:
        rows = int(counts[b].sum())
        if used + rows > max_rows and keep:
            continue
        keep.append(int(b))
        used += rows
        if used >= max_rows:
            break
    return np.array(sorted(keep), dtype=np.int64)


def load_blocks(
    data_dir: Path,
    max_rows: Optional[int] = None,
    seed: int = 0,
    verbose: bool = True,
) -> BlockDataset:
    """Load shards into one contiguous array, preserving per-block capture order."""
    data_dir = Path(data_dir)
    paths, ids, counts = block_label_counts(data_dir)
    keep = select_blocks(counts, max_rows, seed)
    if verbose:
        print(f"  blocks     : {len(keep)} of {len(paths)} "
              f"({counts[keep].sum():,} of {counts.sum():,} rows)")

    xs: List[np.ndarray] = []
    ys: List[np.ndarray] = []
    bounds: List[Tuple[int, int]] = []
    block_ids: List[str] = []
    sessions: List[str] = []
    cursor = 0
    for b in keep:
        p = paths[b]
        t = pq.read_table(p, columns=FEATURE_ORDER + ["label", "session_id"])
        n = t.num_rows
        arr = np.empty((n, N_FEATURES), dtype=np.float32)
        for j, name in enumerate(FEATURE_ORDER):
            arr[:, j] = t.column(name).to_numpy(zero_copy_only=False)
        xs.append(arr)
        ys.append(t.column("label").to_numpy(zero_copy_only=False).astype(np.int64))
        sess = t.column("session_id").to_numpy(zero_copy_only=False)
        sessions.append(str(sess[0]) if n else "")
        block_ids.append(ids[b])
        bounds.append((cursor, cursor + n))
        cursor += n

    return BlockDataset(
        X=np.concatenate(xs, axis=0) if xs else np.zeros((0, N_FEATURES), np.float32),
        y=np.concatenate(ys, axis=0) if ys else np.zeros(0, np.int64),
        block_ids=block_ids,
        bounds=np.asarray(bounds, dtype=np.int64).reshape(-1, 2),
        sessions=sessions,
    )


# --------------------------------------------------------------------------- #
# Grouped split                                                                #
# --------------------------------------------------------------------------- #
def grouped_split(
    counts: np.ndarray,
    fracs: Tuple[float, float, float] = (0.60, 0.15, 0.25),
    seed: int = 0,
) -> Dict[str, List[int]]:
    """Assign whole blocks to train/val/test, balancing per-class row counts.

    ``GroupShuffleSplit`` on 48 groups routinely lands every block of a 147-row
    class in one split. This is a deterministic greedy alternative: blocks are
    offered in rarest-class-first order and each goes to whichever split is
    furthest below its per-class target, weighted by class rarity.

    It is still a *grouped* split -- no row of a block ever appears in two
    splits -- it just doesn't gamble the rare classes on a coin flip.
    """
    n_blocks = counts.shape[0]
    names = ["train", "val", "test"]
    totals = counts.sum(axis=0).astype(np.float64)
    target = {s: totals * f for s, f in zip(names, fracs)}
    cur = {s: np.zeros(N_CLASSES, dtype=np.float64) for s in names}
    rows_cur = {s: 0.0 for s in names}
    rows_total = float(counts.sum())

    rng = np.random.default_rng(seed)
    rarity = np.full(n_blocks, np.inf)
    for b in range(n_blocks):
        present = [c for c in range(1, N_CLASSES) if counts[b, c] > 0]
        if present:
            rarity[b] = min(totals[c] for c in present)
    order = np.lexsort((rng.random(n_blocks), -counts[:, 1:].sum(axis=1), rarity))

    w = 1.0 / np.maximum(totals, 1.0)          # rare classes dominate the score
    # A class held in only two blocks can cover at most two of the three splits.
    # That choice is made here, deliberately, rather than falling out of the
    # arithmetic: **train first** (a class absent from train cannot be learned at
    # all), then **test** (a class absent from test cannot be reported), and val
    # last -- val only drives checkpoint selection, and a val split that is heavy
    # on Normal still selects a usable epoch. ``split_report`` says out loud when
    # this bites.
    coverage_priority = {"train": 3.0, "test": 2.0, "val": 1.0}
    assign: Dict[str, List[int]] = {s: [] for s in names}
    for b in order:
        blk = counts[b].astype(np.float64)
        best, best_score = None, -np.inf
        for s, f in zip(names, fracs):
            deficit = np.maximum(target[s] - cur[s], 0.0)
            score = float(np.sum(w * np.minimum(blk, deficit)))
            uncovered = (blk > 0) & (cur[s] <= 0)
            score += 10.0 * coverage_priority[s] * float(np.sum(w[uncovered] * blk[uncovered]))
            # tiebreak on overall row balance so pure-Normal blocks spread out
            score += 1e-6 * ((f * rows_total) - rows_cur[s]) / max(rows_total, 1.0)
            if score > best_score:
                best, best_score = s, score
        assign[best].append(int(b))
        cur[best] += blk
        rows_cur[best] += float(blk.sum())
    return {s: sorted(v) for s, v in assign.items()}


def split_report(counts: np.ndarray, assign: Dict[str, List[int]]) -> str:
    """Markdown table of per-class rows per split, plus absence warnings."""
    lines = ["| class | blocks | train | val | test |", "|---|---:|---:|---:|---:|"]
    gaps: Dict[str, List[str]] = {"train": [], "val": [], "test": []}
    for c, name in enumerate(CLASSES):
        if counts[:, c].sum() == 0:
            lines.append(f"| {name} | 0 | - | - | - |")
            continue
        nb = int((counts[:, c] > 0).sum())
        vals = [int(counts[assign[s]].sum(axis=0)[c]) if assign[s] else 0
                for s in ("train", "val", "test")]
        lines.append(f"| {name} | {nb} | {vals[0]:,} | {vals[1]:,} | {vals[2]:,} |")
        for s, v in zip(("train", "val", "test"), vals):
            if v == 0:
                gaps[s].append(name)
    lines.append(f"| **blocks** | {counts.shape[0]} | {len(assign['train'])} "
                 f"| {len(assign['val'])} | {len(assign['test'])} |")
    if any(gaps.values()):
        lines.append("")
        lines.append("> **Warning -- too few blocks to cover every split.** A class "
                     "present in only *k* blocks can appear in at most *k* splits; "
                     "assignment priority is train > test > val, for the reasons in "
                     "`grouped_split`. Empty cells above are **undefined, not zero**.")
        if gaps["train"]:
            lines.append("> - **absent from train: " + ", ".join(gaps["train"])
                         + "** -- cannot be learned; any test score for it is 0 by "
                           "construction and means nothing.")
        if gaps["test"]:
            lines.append("> - **absent from test: " + ", ".join(gaps["test"])
                         + "** -- cannot be measured; no claim about it is supported.")
        if gaps["val"]:
            lines.append("> - absent from val: " + ", ".join(gaps["val"])
                         + " -- val macro-F1 does not see these classes, so "
                           "checkpoint selection is partly blind to them.")
        lines.append("> "
                     "Run the **full** `prepare_awid3.py` pass (tens of blocks per "
                     "class instead of two) before believing any number here.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Windows                                                                      #
# --------------------------------------------------------------------------- #
def training_windows(
    bounds: np.ndarray,
    blocks: Sequence[int],
    window: int,
    stride: int,
) -> np.ndarray:
    """Start row index of every training window. Shape (M,), int64.

    Each window covers ``[start, start + window)`` and lies entirely inside one
    block. Blocks shorter than ``window`` are skipped (a 50k-frame block never
    is; this only bites on truncated shards).
    """
    starts: List[int] = []
    for b in blocks:
        s, e = int(bounds[b, 0]), int(bounds[b, 1])
        if e - s < window:
            continue
        last = e - window
        t = s
        while t < last:
            starts.append(t)
            t += stride
        starts.append(last)                    # always cover the block tail
    return np.asarray(sorted(set(starts)), dtype=np.int64)


def inference_chunks(
    bounds: np.ndarray,
    blocks: Sequence[int],
    chunk: int,
    context: int,
) -> List[Tuple[int, int, int]]:
    """Exactly-one-prediction-per-frame tiling: (ctx_start, pred_start, pred_end).

    Rows ``[ctx_start, pred_start)`` are causal context that is fed to the model
    but whose predictions are discarded; rows ``[pred_start, pred_end)`` are
    scored. ``context`` should be at least the model's receptive field minus one,
    so every scored frame sees the same history it would see streaming.

    At the head of a block there is no history -- the model is left-padded, which
    is exactly what happens when the live detector starts on a fresh stream.
    """
    out: List[Tuple[int, int, int]] = []
    for b in blocks:
        s, e = int(bounds[b, 0]), int(bounds[b, 1])
        pos = s
        while pos < e:
            pred_end = min(pos + chunk, e)
            out.append((max(s, pos - context), pos, pred_end))
            pos = pred_end
    return out


def gather_windows(X: np.ndarray, starts: np.ndarray, window: int) -> np.ndarray:
    """(B, F, W) float32 batch from row-major (N, F) storage."""
    idx = starts[:, None] + np.arange(window, dtype=np.int64)[None, :]
    return np.ascontiguousarray(X[idx].transpose(0, 2, 1))


def assert_no_cross_block(starts: np.ndarray, bounds: np.ndarray, window: int) -> None:
    """Fail loudly if any window straddles a seam. Cheap; run it in training."""
    lo = bounds[:, 0]
    for s in np.asarray(starts).tolist():
        b = int(np.searchsorted(lo, s, side="right") - 1)
        if not (bounds[b, 0] <= s and s + window <= bounds[b, 1]):
            raise AssertionError(
                f"window [{s}, {s + window}) escapes block {b} "
                f"[{bounds[b, 0]}, {bounds[b, 1]})"
            )


# --------------------------------------------------------------------------- #
# Causal rolling aggregates (the GBDT's substitute for a temporal receptive field)
# --------------------------------------------------------------------------- #
# A tree model sees one row at a time, so on its own it cannot represent "sixty
# deauths in the last second". These aggregates hand it a bounded past. They are
# strictly causal -- window N ends at the current frame -- and computed per block,
# so no aggregate ever mixes two source files.
ROLLUP_MEAN_STD: List[str] = [
    "frame.len", "frame.dt_log", "radio.signal_dbm",
    "wlan.duration", "wlan.seq_delta", "radio.datarate",
]
ROLLUP_RATE: List[str] = [
    "mgmt.has_reason", "fc.retry", "addr.da_broadcast",
    "eapol.present", "fc.protected", "addr.da_multicast",
]
ROLLUP_WINDOWS: List[int] = [16, 64]


def rollup_names(windows: Sequence[int] = tuple(ROLLUP_WINDOWS)) -> List[str]:
    names: List[str] = []
    for n in windows:
        names += [f"roll{n}.{c}.mean" for c in ROLLUP_MEAN_STD]
        names += [f"roll{n}.{c}.std" for c in ROLLUP_MEAN_STD]
        names += [f"roll{n}.{c}.rate" for c in ROLLUP_RATE]
    return names


def causal_rollups(
    X: np.ndarray,
    bounds: np.ndarray,
    blocks: Sequence[int],
    windows: Sequence[int] = tuple(ROLLUP_WINDOWS),
) -> np.ndarray:
    """Per-row causal rolling mean/std/rate, shape (sum block_len, len(rollup_names)).

    Rows are returned in ``rows_of(blocks)`` order. NaN inputs are excluded from
    the aggregate (they do not count toward the denominator) rather than being
    treated as zero, matching the spec's "absent is not zero" rule.
    """
    cols = [FEATURE_ORDER.index(c) for c in ROLLUP_MEAN_STD]
    rcols = [FEATURE_ORDER.index(c) for c in ROLLUP_RATE]
    out_blocks: List[np.ndarray] = []
    for b in blocks:
        s, e = int(bounds[b, 0]), int(bounds[b, 1])
        blk = X[s:e]
        n = e - s
        parts: List[np.ndarray] = []
        for w in windows:
            for group, want_std in ((cols, True), (rcols, False)):
                v = blk[:, group].astype(np.float64)
                valid = ~np.isnan(v)
                v0 = np.where(valid, v, 0.0)
                cs = np.concatenate([np.zeros((1, v.shape[1])), np.cumsum(v0, axis=0)])
                cn = np.concatenate([np.zeros((1, v.shape[1])), np.cumsum(valid, axis=0)])
                lo = np.maximum(np.arange(n + 1) - w, 0)
                cnt = cn[1:] - cn[lo[:-1]]
                tot = cs[1:] - cs[lo[:-1]]
                denom = np.maximum(cnt, 1.0)
                mean = np.where(cnt > 0, tot / denom, np.nan)
                parts.append(mean.astype(np.float32))
                if want_std:
                    cs2 = np.concatenate(
                        [np.zeros((1, v.shape[1])), np.cumsum(v0 * v0, axis=0)]
                    )
                    tot2 = cs2[1:] - cs2[lo[:-1]]
                    var = np.maximum(tot2 / denom - (tot / denom) ** 2, 0.0)
                    parts.append(np.where(cnt > 1, np.sqrt(var), np.nan).astype(np.float32))
        out_blocks.append(np.concatenate(parts, axis=1))
    if not out_blocks:
        return np.zeros((0, len(rollup_names(windows))), np.float32)
    return np.concatenate(out_blocks, axis=0)


def save_split(path: Path, dataset: BlockDataset, assign: Dict[str, List[int]]) -> None:
    payload = {
        "spec_version": SPEC_VERSION,
        "block_ids": dataset.block_ids,
        "splits": {s: [dataset.block_ids[b] for b in v] for s, v in assign.items()},
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_split(path: Path, dataset: BlockDataset) -> Dict[str, List[int]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    index = {bid: i for i, bid in enumerate(dataset.block_ids)}
    out: Dict[str, List[int]] = {}
    for s, ids in payload["splits"].items():
        missing = [b for b in ids if b not in index]
        if missing:
            raise ValueError(
                f"split '{s}' references blocks absent from the loaded dataset: "
                f"{missing[:5]}{'...' if len(missing) > 5 else ''}. "
                f"Evaluate with the same --data and --max-rows used for training."
            )
        out[s] = sorted(index[b] for b in ids)
    return out
