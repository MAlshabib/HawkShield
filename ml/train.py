#!/usr/bin/env python3
"""
Train the HawkShield v2 detectors on a *grouped* split of AWID3.

    python ml/train.py --model both --epochs 12
    python ml/train.py --model tcn --max-rows 600000 --epochs 2 --device cpu

Two candidates are trained on identical data and identical splits:

* **tcn**  -- causal dilated temporal CNN, per-frame classification (``ml/model.py``)
* **gbdt** -- LightGBM over per-frame features plus causal rolling aggregates

They are reported side by side and neither is assumed to win. A 90 KB tree model
that beats the network on macro-F1 is the better answer for a Raspberry Pi, and
saying so is the point of running both.

The split is over whole ``block_id`` groups, never over rows. See ml/README.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml import windows as W  # noqa: E402
from ml.windows import CLASSES, FEATURE_ORDER, SPEC_VERSION  # noqa: E402

N_CLASSES = len(CLASSES)
DEFAULT_DATA = REPO_ROOT / "_work" / "awid3_v2"
DEFAULT_OUT = REPO_ROOT / "_work" / "models_v2"
REPORT_DIR = REPO_ROOT / "ml" / "reports"


# --------------------------------------------------------------------------- #
# Metrics                                                                      #
# --------------------------------------------------------------------------- #
def macro_f1(y_true: np.ndarray, y_pred: np.ndarray, present_only: bool = True) -> float:
    """Macro-F1 over the classes actually present in ``y_true``.

    Averaging over absent classes silently scores them 0 and buries the fact
    that the split could not test them at all; ``present_only`` keeps that
    visible in the support column instead of hiding it in the mean.
    """
    labels = np.unique(y_true) if present_only else np.arange(N_CLASSES)
    f1s = []
    for c in labels:
        tp = int(np.sum((y_pred == c) & (y_true == c)))
        fp = int(np.sum((y_pred == c) & (y_true != c)))
        fn = int(np.sum((y_pred != c) & (y_true == c)))
        denom = 2 * tp + fp + fn
        f1s.append(0.0 if denom == 0 else 2 * tp / denom)
    return float(np.mean(f1s)) if f1s else 0.0


def per_class_table(y_true: np.ndarray, y_pred: np.ndarray) -> str:
    rows = ["| class | precision | recall | f1 | support |", "|---|---:|---:|---:|---:|"]
    for c, name in enumerate(CLASSES):
        tp = int(np.sum((y_pred == c) & (y_true == c)))
        fp = int(np.sum((y_pred == c) & (y_true != c)))
        fn = int(np.sum((y_pred != c) & (y_true == c)))
        sup = tp + fn
        if sup == 0:
            # No ground truth for this class here. Precision/recall/F1 are
            # undefined -- printing 0.0000 would read as "the model failed",
            # when in fact the split could not test it at all. False positives
            # are still worth showing: they are pure noise on this data.
            note = "absent from split" if fp == 0 else f"absent; {fp:,} false positives"
            rows.append(f"| {name} | - | - | - | 0 *({note})* |")
            continue
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / sup
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        rows.append(f"| {name} | {p:.4f} | {r:.4f} | {f:.4f} | {sup:,} |")
    rows.append(f"| **macro-F1 (present classes)** | | | **{macro_f1(y_true, y_pred):.4f}** | "
                f"{len(y_true):,} |")
    return "\n".join(rows)


def confusion_md(y_true: np.ndarray, y_pred: np.ndarray) -> str:
    cm = np.zeros((N_CLASSES, N_CLASSES), dtype=np.int64)
    np.add.at(cm, (y_true, y_pred), 1)
    head = "| true \\ pred | " + " | ".join(CLASSES) + " |"
    sep = "|---|" + "---:|" * N_CLASSES
    lines = [head, sep]
    for i, name in enumerate(CLASSES):
        lines.append(f"| **{name}** | " + " | ".join(f"{v:,}" if v else "." for v in cm[i]) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Shared setup                                                                 #
# --------------------------------------------------------------------------- #
def block_counts_of(ds: W.BlockDataset) -> np.ndarray:
    counts = np.zeros((ds.n_blocks, N_CLASSES), dtype=np.int64)
    for b in range(ds.n_blocks):
        s, e = ds.bounds[b]
        counts[b] = np.bincount(ds.y[s:e], minlength=N_CLASSES)
    return counts


def norm_stats(X: np.ndarray, rows: np.ndarray) -> Tuple[np.ndarray, np.ndarray, List[int]]:
    """Train-only per-feature mean/std and the set of NaN-capable features.

    Constants are saved with the model. Inference must not recompute them --
    that was one half of the v1 train/serve skew.
    """
    sub = X[rows]
    with np.errstate(invalid="ignore", all="ignore"):
        mean = np.nanmean(sub, axis=0)
        std = np.nanstd(sub, axis=0)
    nan_any = np.isnan(sub).any(axis=0)
    all_nan = np.isnan(sub).all(axis=0)
    mean = np.where(np.isnan(mean), 0.0, mean).astype(np.float32)
    std = np.where(np.isnan(std) | (std < 1e-6), 1.0, std).astype(np.float32)
    mask_idx = [int(i) for i in np.where(nan_any)[0]]
    if all_nan.any():
        names = [FEATURE_ORDER[i] for i in np.where(all_nan)[0]]
        print(f"  [warn] features NaN in every training row: {names}")
    return mean, std, mask_idx


def class_weights(counts: np.ndarray, alpha: float = 0.5, cap: float = 100.0) -> np.ndarray:
    """Capped inverse-frequency weights. Uncapped weights on a 68-row class make
    the loss surface a cliff; the cap trades a little rare-class recall for a
    model that actually converges."""
    n = counts.sum()
    k = max(int((counts > 0).sum()), 1)
    w = np.ones(N_CLASSES, dtype=np.float32)
    for c in range(N_CLASSES):
        if counts[c] > 0:
            w[c] = min(float((n / (k * counts[c])) ** alpha), cap)
    return np.maximum(w, 1e-3)


# --------------------------------------------------------------------------- #
# TCN                                                                          #
# --------------------------------------------------------------------------- #
def select_training_windows(ds: W.BlockDataset, blocks: Sequence[int], window: int,
                            stride: int, normal_ratio: float, seed: int) -> np.ndarray:
    """All attack-bearing windows + ``normal_ratio`` x as many Normal-only ones.

    90% of frames are Normal. Training on the raw mix spends almost all compute
    on the majority class; subsampling the Normal-only windows is cheaper and
    better than cranking loss weights alone. Class weights are then computed on
    the *sampled* distribution so the two corrections do not double up.
    """
    starts = W.training_windows(ds.bounds, blocks, window, stride)
    if starts.size == 0:
        return starts
    W.assert_no_cross_block(starts, ds.bounds, window)
    attack_cs = np.concatenate([[0], np.cumsum(ds.y > 0)])
    has_attack = (attack_cs[starts + window] - attack_cs[starts]) > 0
    rng = np.random.default_rng(seed)
    atk = starts[has_attack]
    nrm = starts[~has_attack]
    budget = int(round(normal_ratio * max(len(atk), 1)))
    if len(nrm) > budget:
        nrm = rng.choice(nrm, size=budget, replace=False)
    sel = np.concatenate([atk, nrm])
    rng.shuffle(sel)
    return np.sort(sel)


def predict_frames_tcn(model, X: np.ndarray, chunks: List[Tuple[int, int, int]],
                       device, batch: int = 8) -> Tuple[np.ndarray, np.ndarray]:
    """Score every frame covered by ``chunks`` exactly once, causally.

    Chunks are bucketed by shape so equal-length ones batch together; the head of
    each block is its own shape (no history) and is handled in its own bucket.
    """
    import torch

    rows_out: List[np.ndarray] = []
    preds_out: List[np.ndarray] = []
    buckets: Dict[Tuple[int, int], List[Tuple[int, int, int]]] = {}
    for c in chunks:
        buckets.setdefault((c[1] - c[0], c[2] - c[0]), []).append(c)

    model.eval()
    with torch.no_grad():
        for (off, total), group in buckets.items():
            for i in range(0, len(group), batch):
                part = group[i:i + batch]
                arr = np.stack([X[c[0]:c[0] + total] for c in part]).transpose(0, 2, 1)
                t = torch.from_numpy(np.ascontiguousarray(arr)).to(device)
                logits = model(t)[:, :, off:]
                p = logits.argmax(dim=1).cpu().numpy()
                for j, c in enumerate(part):
                    rows_out.append(np.arange(c[1], c[2], dtype=np.int64))
                    preds_out.append(p[j])
    rows = np.concatenate(rows_out) if rows_out else np.zeros(0, np.int64)
    preds = np.concatenate(preds_out) if preds_out else np.zeros(0, np.int64)
    order = np.argsort(rows, kind="stable")
    return rows[order], preds[order].astype(np.int64)


def train_tcn(ds: W.BlockDataset, assign: Dict[str, List[int]], args, out_dir: Path,
              log: List[str]) -> Dict[str, object]:
    import torch
    import torch.nn as nn
    from ml.model import HawkShieldTCN, assert_causal

    device = torch.device(args.device)
    train_rows = ds.rows_of(assign["train"])
    mean, std, mask_idx = norm_stats(ds.X, train_rows)

    model = HawkShieldTCN(mean, std, mask_idx, n_classes=N_CLASSES,
                          channels=args.channels, dropout=args.dropout).to(device)
    causality = assert_causal(model, n_features=len(FEATURE_ORDER),
                              window=args.window, t=args.window // 2)
    print(f"  TCN params      : {model.n_parameters():,}")
    print(f"  receptive field : {model.receptive_field} frames")
    print(f"  causality probe : past delta {causality['max_delta_past']:.3e} "
          f"(must be 0) / future delta {causality['max_delta_future']:.3e} (must be > 0)")

    starts = select_training_windows(ds, assign["train"], args.window, args.stride,
                                     args.normal_ratio, args.seed)
    if starts.size == 0:
        raise SystemExit("[FAIL] no training windows: blocks shorter than --window?")
    sampled_counts = np.zeros(N_CLASSES, dtype=np.int64)
    for i in range(0, len(starts), 4096):          # chunked: M x W int64 gets large
        chunk = starts[i:i + 4096][:, None] + np.arange(args.window)[None, :]
        sampled_counts += np.bincount(ds.y[chunk].ravel(), minlength=N_CLASSES)
    wts = class_weights(sampled_counts, args.weight_alpha, args.weight_cap)
    print(f"  train windows   : {len(starts):,} "
          f"({int(sampled_counts.sum()):,} frames after subsampling)")
    print(f"  class weights   : " + ", ".join(
        f"{CLASSES[c]}={wts[c]:.1f}" for c in range(N_CLASSES) if sampled_counts[c] > 0))

    ctx = model.receptive_field - 1
    val_chunks = W.inference_chunks(ds.bounds, assign["val"], args.eval_chunk, ctx)

    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    steps = max(1, (len(starts) + args.batch_size - 1) // args.batch_size) * args.epochs
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=args.lr, total_steps=steps,
                                                pct_start=0.25)
    wt = torch.as_tensor(wts, device=device)
    lossfn = nn.CrossEntropyLoss(weight=wt, ignore_index=-100,
                                 label_smoothing=args.label_smoothing)
    rng = np.random.default_rng(args.seed)

    best = -1.0
    history: List[Dict[str, float]] = []
    ckpt_path = out_dir / "tcn.pt"
    for ep in range(1, args.epochs + 1):
        model.train()
        perm = rng.permutation(len(starts))
        tot_loss, nb = 0.0, 0
        tr_true: List[np.ndarray] = []
        tr_pred: List[np.ndarray] = []
        t0 = time.time()
        for i in range(0, len(perm), args.batch_size):
            sel = starts[perm[i:i + args.batch_size]]
            xb = torch.from_numpy(W.gather_windows(ds.X, sel, args.window)).to(device)
            ridx = sel[:, None] + np.arange(args.window)[None, :]
            yb = torch.from_numpy(ds.y[ridx]).to(device)
            logits = model(xb)
            loss = lossfn(logits, yb)
            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            tot_loss += float(loss.item())
            nb += 1
            if nb % max(1, args.log_every) == 0 or i == 0:
                tr_true.append(yb.detach().cpu().numpy().ravel())
                tr_pred.append(logits.detach().argmax(1).cpu().numpy().ravel())
            if args.max_steps and nb >= args.max_steps:
                break
        tr_f1 = macro_f1(np.concatenate(tr_true), np.concatenate(tr_pred)) if tr_true else 0.0
        rows, preds = predict_frames_tcn(model, ds.X, val_chunks, device, args.eval_batch)
        val_f1 = macro_f1(ds.y[rows], preds) if rows.size else 0.0
        dt = time.time() - t0
        print(f"  epoch {ep:>3}/{args.epochs}  loss {tot_loss / max(nb, 1):.4f}  "
              f"train_macroF1 {tr_f1:.4f}  val_macroF1 {val_f1:.4f}  {dt:.1f}s", flush=True)
        history.append({"epoch": ep, "loss": tot_loss / max(nb, 1),
                        "train_macro_f1": tr_f1, "val_macro_f1": val_f1, "seconds": dt})
        if val_f1 > best:
            best = val_f1
            torch.save({
                "state_dict": model.state_dict(),
                "config": model.config,
                "norm": {"mean": mean.tolist(), "std": std.tolist()},
                "classes": CLASSES,
                "features": FEATURE_ORDER,
                "spec_version": SPEC_VERSION,
                "window": args.window,
                "context": ctx,
                "class_weights": wts.tolist(),
                "val_macro_f1": val_f1,
                "epoch": ep,
                "causality": causality,
            }, ckpt_path)

    log.append(f"### TCN\n")
    log.append(f"- parameters: **{model.n_parameters():,}**, receptive field "
               f"**{model.receptive_field}** past frames, window {args.window}, "
               f"stride {args.stride}")
    log.append(f"- NaN handling: learned per-feature sentinel + "
               f"{len(mask_idx)} companion mask channels "
               f"({len(mask_idx)} of {len(FEATURE_ORDER)} features are NaN-capable in train)")
    log.append(f"- causality probe: max output delta at t from perturbing t+1.. = "
               f"`{causality['max_delta_past']:.3e}` (must be 0.0); "
               f"future-side delta `{causality['max_delta_future']:.3e}` (proves the probe bites)")
    log.append(f"- best val macro-F1: **{best:.4f}** (epoch "
               f"{max(history, key=lambda h: h['val_macro_f1'])['epoch'] if history else 0})\n")
    log.append("| epoch | loss | train macro-F1 | val macro-F1 | sec |")
    log.append("|---:|---:|---:|---:|---:|")
    for h in history:
        log.append(f"| {h['epoch']} | {h['loss']:.4f} | {h['train_macro_f1']:.4f} "
                   f"| {h['val_macro_f1']:.4f} | {h['seconds']:.1f} |")
    log.append("")
    return {"best_val_macro_f1": best, "history": history, "checkpoint": str(ckpt_path),
            "params": model.n_parameters(), "causality": causality}


# --------------------------------------------------------------------------- #
# GBDT                                                                         #
# --------------------------------------------------------------------------- #
def gbdt_matrix(ds: W.BlockDataset, blocks: Sequence[int], max_rows: Optional[int] = None,
                seed: int = 0, keep_all_attacks: bool = True) -> Tuple[np.ndarray, np.ndarray]:
    """Per-frame features + causal rolling aggregates, block by block.

    Rollups need the block's full row sequence, so they are computed first and
    rows are subsampled afterwards. Subsampling rows is safe here (a tree sees
    one row at a time); subsampling before the rollups would corrupt them.
    """
    rng = np.random.default_rng(seed)
    total = sum(int(ds.bounds[b, 1] - ds.bounds[b, 0]) for b in blocks)
    keep_p = 1.0 if (max_rows is None or total <= max_rows) else max_rows / total
    xs, ys = [], []
    for b in blocks:
        s, e = int(ds.bounds[b, 0]), int(ds.bounds[b, 1])
        roll = W.causal_rollups(ds.X, ds.bounds, [b])
        feats = np.concatenate([ds.X[s:e], roll], axis=1)
        lab = ds.y[s:e]
        if keep_p < 1.0:
            take = rng.random(e - s) < keep_p
            if keep_all_attacks:
                take |= lab > 0
            feats, lab = feats[take], lab[take]
        xs.append(feats)
        ys.append(lab)
    if not xs:
        return (np.zeros((0, len(FEATURE_ORDER) + len(W.rollup_names())), np.float32),
                np.zeros(0, np.int64))
    return np.concatenate(xs), np.concatenate(ys)


def gbdt_feature_names() -> List[str]:
    return list(FEATURE_ORDER) + W.rollup_names()


def train_gbdt(ds: W.BlockDataset, assign: Dict[str, List[int]], args, out_dir: Path,
               log: List[str], drop_feature: Optional[str] = None,
               quiet: bool = False) -> Dict[str, object]:
    import lightgbm as lgb

    names = gbdt_feature_names()
    keep = [i for i, n in enumerate(names) if n != drop_feature]
    kept_names = [names[i] for i in keep]

    Xtr, ytr = gbdt_matrix(ds, assign["train"], args.gbdt_max_rows, args.seed)
    Xva, yva = gbdt_matrix(ds, assign["val"], args.gbdt_max_rows, args.seed + 1)
    if drop_feature is not None:
        Xtr, Xva = Xtr[:, keep], Xva[:, keep]
    counts = np.bincount(ytr, minlength=N_CLASSES)
    wts = class_weights(counts, args.weight_alpha, args.weight_cap)
    sw = wts[ytr]

    if not quiet:
        print(f"  GBDT train rows : {len(ytr):,}  val rows: {len(yva):,}  "
              f"features: {len(kept_names)}")

    params = dict(objective="multiclass", num_class=N_CLASSES, learning_rate=args.gbdt_lr,
                  num_leaves=args.gbdt_leaves, min_data_in_leaf=50, feature_fraction=0.8,
                  bagging_fraction=0.8, bagging_freq=1, max_bin=127,
                  num_threads=args.threads, verbosity=-1, seed=args.seed)
    dtrain = lgb.Dataset(Xtr, label=ytr, weight=sw, feature_name=kept_names,
                         free_raw_data=True)
    dval = lgb.Dataset(Xva, label=yva, weight=wts[yva], reference=dtrain,
                       feature_name=kept_names, free_raw_data=True)
    cb = [lgb.early_stopping(args.gbdt_early_stop, verbose=False)]
    if not quiet:
        cb.append(lgb.log_evaluation(period=max(1, args.gbdt_rounds // 5)))
    booster = lgb.train(params, dtrain, num_boost_round=args.gbdt_rounds,
                        valid_sets=[dval], valid_names=["val"], callbacks=cb)
    del Xtr, dtrain

    val_pred = booster.predict(Xva, num_iteration=booster.best_iteration).argmax(1)
    val_f1 = macro_f1(yva, val_pred)
    del Xva

    imp = booster.feature_importance(importance_type="gain")
    order = np.argsort(-imp)
    top = [(kept_names[i], float(imp[i])) for i in order[:15]]

    if drop_feature is None:
        booster.save_model(str(out_dir / "gbdt.txt"),
                           num_iteration=booster.best_iteration)
        (out_dir / "gbdt_meta.json").write_text(json.dumps({
            "spec_version": SPEC_VERSION, "classes": CLASSES,
            "features": kept_names, "rollup_windows": W.ROLLUP_WINDOWS,
            "best_iteration": booster.best_iteration,
            "val_macro_f1": val_f1, "class_weights": wts.tolist(),
        }, indent=2), encoding="utf-8")

        log.append("### LightGBM baseline\n")
        log.append(f"- features: {len(FEATURE_ORDER)} per-frame + {len(W.rollup_names())} "
                   f"causal rolling aggregates (windows {W.ROLLUP_WINDOWS}) = {len(kept_names)}")
        log.append(f"- trees: {booster.best_iteration} x {N_CLASSES} classes, "
                   f"{args.gbdt_leaves} leaves")
        log.append(f"- val macro-F1: **{val_f1:.4f}**\n")
        log.append("| rank | feature | gain |")
        log.append("|---:|---|---:|")
        for r, (n, g) in enumerate(top, 1):
            log.append(f"| {r} | `{n}` | {g:,.0f} |")
        log.append("")
        print(f"  GBDT val macroF1: {val_f1:.4f}  (best_iteration={booster.best_iteration})")

    return {"booster": booster, "val_macro_f1": val_f1, "top_features": top,
            "kept_names": kept_names, "best_iteration": booster.best_iteration}


# --------------------------------------------------------------------------- #
# main                                                                         #
# --------------------------------------------------------------------------- #
def resolve_device(name: str) -> str:
    if name != "auto":
        return name
    try:
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"


def build_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Train HawkShield v2 detectors.")
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--model", choices=["tcn", "gbdt", "both"], default="both")
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--batch-size", type=int, default=64)
    ap.add_argument("--window", type=int, default=128)
    ap.add_argument("--stride", type=int, default=64)
    ap.add_argument("--device", default="auto", choices=["auto", "cuda", "cpu"])
    ap.add_argument("--max-rows", type=int, default=None,
                    help="row budget; whole blocks are dropped to meet it, rarest kept first")
    ap.add_argument("--seed", type=int, default=1337)
    # TCN
    ap.add_argument("--channels", type=int, default=56)
    ap.add_argument("--dropout", type=float, default=0.05)
    ap.add_argument("--lr", type=float, default=3e-3)
    ap.add_argument("--label-smoothing", type=float, default=0.0)
    ap.add_argument("--normal-ratio", type=float, default=3.0,
                    help="Normal-only windows kept per attack-bearing window")
    ap.add_argument("--weight-alpha", type=float, default=0.5)
    ap.add_argument("--weight-cap", type=float, default=100.0)
    ap.add_argument("--eval-chunk", type=int, default=2048)
    ap.add_argument("--eval-batch", type=int, default=8)
    ap.add_argument("--log-every", type=int, default=20)
    ap.add_argument("--max-steps", type=int, default=0, help="cap batches per epoch (debug)")
    # GBDT
    ap.add_argument("--gbdt-rounds", type=int, default=400)
    ap.add_argument("--gbdt-leaves", type=int, default=63)
    ap.add_argument("--gbdt-lr", type=float, default=0.08)
    ap.add_argument("--gbdt-early-stop", type=int, default=40)
    ap.add_argument("--gbdt-max-rows", type=int, default=3_000_000)
    ap.add_argument("--threads", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    # split
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--test-frac", type=float, default=0.25)
    args = ap.parse_args(argv)
    args.device = resolve_device(args.device)
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_args(argv)
    np.random.seed(args.seed)
    try:
        import torch
        torch.manual_seed(args.seed)
    except Exception:
        pass

    args.out.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    t_start = time.time()

    print(f"HawkShield v2 training | spec {SPEC_VERSION}")
    print(f"  data       : {args.data}")
    print(f"  out        : {args.out}")
    print(f"  model      : {args.model}   device: {args.device}")
    ds = W.load_blocks(args.data, args.max_rows, args.seed)
    counts = block_counts_of(ds)
    print(f"  rows       : {len(ds.y):,}")

    assign = W.grouped_split(counts, (1 - args.val_frac - args.test_frac,
                                      args.val_frac, args.test_frac), args.seed)
    W.save_split(args.out / "split.json", ds, assign)
    print("  split (whole blocks, never rows):")
    for s in ("train", "val", "test"):
        rows = sum(int(counts[b].sum()) for b in assign[s])
        print(f"    {s:<5} {len(assign[s]):>3} blocks  {rows:>12,} rows")

    log: List[str] = []
    log.append(f"# HawkShield v2 -- training report\n")
    log.append(f"- spec version: `{SPEC_VERSION}` | features: {len(FEATURE_ORDER)} "
               f"| classes: {len(CLASSES)}")
    log.append(f"- data: `{args.data}` -- {len(ds.y):,} rows in {ds.n_blocks} blocks")
    log.append(f"- device: `{args.device}` | seed: {args.seed} | "
               f"generated {time.strftime('%Y-%m-%d %H:%M')}")
    log.append(f"- command: `python ml/train.py " + " ".join(sys.argv[1:]) + "`\n")
    log.append("## Split protocol\n")
    log.append(
        "Whole **`block_id`** groups are assigned to train/val/test; a block is one "
        "contiguous 50,000-frame AWID3 source file and no row of a block ever appears "
        "in two splits. Windows never cross a block boundary.\n\n"
        "This is **weaker than leave-one-capture-out**, and deliberately so: AWID3 "
        "records each attack exactly once, `frame.number` runs continuously across an "
        "attack's chunk files, so holding out a capture deletes the class outright. "
        "Held-out blocks are therefore from the same session, same testbed, same "
        "hardware as the training blocks -- what these numbers measure is "
        "generalisation across time within one recording, not across deployments. "
        "Read them as an upper bound on field performance.\n")
    log.append("### Rows per class per split\n")
    log.append(W.split_report(counts, assign))
    log.append("")
    log.append("## Models\n")

    results: Dict[str, object] = {}
    if args.model in ("tcn", "both"):
        print("\n-- TCN " + "-" * 60)
        results["tcn"] = train_tcn(ds, assign, args, args.out, log)
    if args.model in ("gbdt", "both"):
        print("\n-- LightGBM " + "-" * 55)
        g = train_gbdt(ds, assign, args, args.out, log)
        results["gbdt"] = {k: v for k, v in g.items() if k != "booster"}

    if args.model == "both":
        t = float(results["tcn"]["best_val_macro_f1"])          # type: ignore[index]
        b = float(results["gbdt"]["val_macro_f1"])              # type: ignore[index]
        winner = "TCN" if t > b else "LightGBM"
        log.append("## Head to head (validation macro-F1)\n")
        log.append(f"| model | val macro-F1 |\n|---|---:|\n| TCN | {t:.4f} |"
                   f"\n| LightGBM | {b:.4f} |\n")
        log.append(f"**{winner} leads on validation by {abs(t - b):.4f} macro-F1.** "
                   f"Test-set numbers and the leakage probe are in `eval_report.md`; "
                   f"decide on those, not on this.\n")
        print(f"\n  head-to-head val macro-F1: TCN {t:.4f} | LightGBM {b:.4f} -> {winner}")

    log.append(f"\n---\nWall clock: {(time.time() - t_start) / 60:.1f} min\n")
    (REPORT_DIR / "train_report.md").write_text("\n".join(log), encoding="utf-8")
    (args.out / "train_summary.json").write_text(
        json.dumps({"args": {k: (str(v) if isinstance(v, Path) else v)
                             for k, v in vars(args).items()},
                    "results": results}, indent=2, default=str), encoding="utf-8")
    print(f"\n  wrote {REPORT_DIR / 'train_report.md'}")
    print(f"  wall clock {(time.time() - t_start) / 60:.1f} min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
