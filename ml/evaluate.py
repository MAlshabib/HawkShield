#!/usr/bin/env python3
"""
Score the held-out **test blocks** and write ``ml/reports/eval_report.md``.

    python ml/evaluate.py --models _work/models_v2

Reads the split written by ``train.py`` so the test blocks are byte-identical to
the ones the model never saw. Produces, for each trained model:

* per-class precision / recall / F1 / support and macro-F1
* a full 9x9 confusion matrix
* a **leakage probe**: the top-importance feature is removed and the model
  re-scored. v1 collapsed when ``frame.time_relative`` was ablated -- 42% of its
  split gain came from a column that encoded which capture session a row was
  from. A detector whose macro-F1 falls off a cliff when one feature disappears
  is keyed on that feature, and if that feature is an artefact of the capture,
  the detector is an artefact of the capture.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml import train as T  # noqa: E402
from ml import windows as W  # noqa: E402
from ml.windows import CLASSES, FEATURE_ORDER, SPEC_VERSION  # noqa: E402

N_CLASSES = len(CLASSES)
REPORT_DIR = REPO_ROOT / "ml" / "reports"


# --------------------------------------------------------------------------- #
def eval_tcn(ckpt_path: Path, ds: W.BlockDataset, blocks: Sequence[int], device: str,
             chunk: int, batch: int, ablate: Optional[int] = None
             ) -> Tuple[np.ndarray, np.ndarray, dict]:
    import torch
    from ml.model import build_from_checkpoint

    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    model = build_from_checkpoint(ckpt).to(device)
    ctx = int(ckpt.get("context", model.receptive_field - 1))
    chunks = W.inference_chunks(ds.bounds, blocks, chunk, ctx)

    X = ds.X
    if ablate is not None:
        # NaN, not zero: NaN is a state the contract defines and the model has a
        # mask channel for. Zeroing would post-normalise to "the training mean",
        # which is precisely the silent imputation that killed v1.
        X = ds.X.copy()
        X[:, ablate] = np.nan
    rows, preds = T.predict_frames_tcn(model, X, chunks, device, batch)
    return rows, preds, ckpt


def eval_gbdt(model_dir: Path, ds: W.BlockDataset, blocks: Sequence[int],
              ablate_name: Optional[str] = None) -> Tuple[np.ndarray, np.ndarray]:
    import lightgbm as lgb

    booster = lgb.Booster(model_file=str(model_dir / "gbdt.txt"))
    names = T.gbdt_feature_names()
    rows_out, preds_out = [], []
    for b in blocks:
        s, e = int(ds.bounds[b, 0]), int(ds.bounds[b, 1])
        feats = np.concatenate([ds.X[s:e], W.causal_rollups(ds.X, ds.bounds, [b])], axis=1)
        if ablate_name is not None and ablate_name in names:
            feats[:, names.index(ablate_name)] = np.nan
        preds_out.append(booster.predict(feats).argmax(1))
        rows_out.append(np.arange(s, e, dtype=np.int64))
    if not rows_out:
        return np.zeros(0, np.int64), np.zeros(0, np.int64)
    return np.concatenate(rows_out), np.concatenate(preds_out).astype(np.int64)


# --------------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate HawkShield v2 on held-out blocks.")
    ap.add_argument("--models", type=Path, default=T.DEFAULT_OUT)
    ap.add_argument("--data", type=Path, default=None)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--device", default="auto", choices=["auto", "cuda", "cpu"])
    ap.add_argument("--split", default="test", choices=["test", "val", "train"])
    ap.add_argument("--eval-chunk", type=int, default=2048)
    ap.add_argument("--eval-batch", type=int, default=8)
    ap.add_argument("--probe-top", type=int, default=1,
                    help="how many top-importance features to ablate in the leakage probe")
    ap.add_argument("--no-probe-retrain", action="store_true",
                    help="skip the GBDT ablation retrain (score-only probe)")
    args = ap.parse_args(argv)
    args.device = T.resolve_device(args.device)

    summary_path = args.models / "train_summary.json"
    train_args: Dict = {}
    if summary_path.exists():
        train_args = json.loads(summary_path.read_text(encoding="utf-8")).get("args", {})
    if args.data is None:
        args.data = Path(train_args.get("data", T.DEFAULT_DATA))
    if args.max_rows is None:
        args.max_rows = train_args.get("max_rows")
    seed = int(train_args.get("seed", 1337))

    print(f"HawkShield v2 evaluation | spec {SPEC_VERSION}")
    print(f"  models : {args.models}")
    print(f"  data   : {args.data}   split: {args.split}   device: {args.device}")
    ds = W.load_blocks(args.data, args.max_rows, seed)
    counts = T.block_counts_of(ds)
    assign = W.load_split(args.models / "split.json", ds)
    blocks = assign[args.split]
    print(f"  {args.split} blocks: {len(blocks)} "
          f"({sum(int(counts[b].sum()) for b in blocks):,} rows)")

    md: List[str] = [f"# HawkShield v2 -- evaluation on held-out {args.split} blocks\n"]
    md.append(f"- spec `{SPEC_VERSION}` | models `{args.models}` | data `{args.data}`")
    md.append(f"- generated {time.strftime('%Y-%m-%d %H:%M')} | device `{args.device}`")
    md.append(f"- held-out blocks: `" + "`, `".join(ds.block_ids[b] for b in blocks) + "`\n")
    md.append(
        "> **Protocol.** Whole `block_id` groups are held out -- one block is one "
        "contiguous 50,000-frame AWID3 source file, and no row of a held-out block "
        "was seen in training. This is weaker than leave-one-capture-out: AWID3 "
        "recorded each attack exactly once and `frame.number` runs continuously "
        "across an attack's chunk files, so removing a capture removes the class. "
        "The held-out blocks share the session, testbed and radio hardware of the "
        "training blocks, so these numbers bound field performance from above.\n")

    results: Dict[str, float] = {}
    ckpt_path = args.models / "tcn.pt"
    gbdt_path = args.models / "gbdt.txt"

    # ---------------- TCN ----------------
    if ckpt_path.exists():
        print("\n-- TCN " + "-" * 60)
        t0 = time.time()
        rows, preds, ckpt = eval_tcn(ckpt_path, ds, blocks, args.device,
                                     args.eval_chunk, args.eval_batch)
        y = ds.y[rows]
        f1 = T.macro_f1(y, preds)
        results["tcn"] = f1
        print(f"  test macro-F1 : {f1:.4f}   ({len(rows):,} frames, {time.time() - t0:.1f}s)")
        md.append("## TCN (causal dilated temporal CNN)\n")
        md.append(f"- checkpoint `{ckpt_path.name}` from epoch {ckpt.get('epoch')} "
                  f"(val macro-F1 {ckpt.get('val_macro_f1', float('nan')):.4f})")
        md.append(f"- causality probe at train time: past-side delta "
                  f"`{ckpt.get('causality', {}).get('max_delta_past', 'n/a')}` "
                  f"(0.0 required), future-side delta "
                  f"`{ckpt.get('causality', {}).get('max_delta_future', 'n/a')}`")
        md.append(f"- **test macro-F1: {f1:.4f}** over {len(rows):,} frames\n")
        md.append(T.per_class_table(y, preds))
        md.append("\n### Confusion matrix\n")
        md.append(T.confusion_md(y, preds))
        md.append("")
    else:
        md.append("## TCN\n\n_No `tcn.pt` in the model directory; not evaluated._\n")

    # ---------------- GBDT ----------------
    top_features: List[Tuple[str, float]] = []
    if gbdt_path.exists():
        print("\n-- LightGBM " + "-" * 55)
        import lightgbm as lgb
        t0 = time.time()
        rows_g, preds_g = eval_gbdt(args.models, ds, blocks)
        yg = ds.y[rows_g]
        f1g = T.macro_f1(yg, preds_g)
        results["gbdt"] = f1g
        booster = lgb.Booster(model_file=str(gbdt_path))
        names = booster.feature_name()
        imp = booster.feature_importance(importance_type="gain")
        order = np.argsort(-imp)
        top_features = [(names[i], float(imp[i])) for i in order[:10]]
        size_kb = gbdt_path.stat().st_size / 1024
        print(f"  test macro-F1 : {f1g:.4f}   ({len(rows_g):,} frames, "
              f"{time.time() - t0:.1f}s, model {size_kb:.0f} KB)")
        md.append("## LightGBM baseline\n")
        md.append(f"- {booster.num_trees()} trees, model file {size_kb:.0f} KB on disk")
        md.append(f"- **test macro-F1: {f1g:.4f}** over {len(rows_g):,} frames\n")
        md.append(T.per_class_table(yg, preds_g))
        md.append("\n### Confusion matrix\n")
        md.append(T.confusion_md(yg, preds_g))
        md.append("\n### Top gain features\n")
        md.append("| rank | feature | gain |\n|---:|---|---:|")
        for r, (n, g) in enumerate(top_features, 1):
            md.append(f"| {r} | `{n}` | {g:,.0f} |")
        md.append("")
    else:
        md.append("## LightGBM\n\n_No `gbdt.txt` in the model directory; not evaluated._\n")

    # ---------------- Head to head ----------------
    if len(results) == 2:
        t, b = results["tcn"], results["gbdt"]
        winner = "TCN" if t > b else "LightGBM"
        md.append("## Head to head (held-out test macro-F1)\n")
        md.append(f"| model | test macro-F1 |\n|---|---:|\n| TCN | {t:.4f} |"
                  f"\n| LightGBM | {b:.4f} |\n")
        md.append(f"**{winner} wins by {abs(t - b):.4f}.**"
                  + ("" if winner == "TCN" else
                     " A tree ensemble beating the network is a legitimate result, "
                     "not a bug to tune away -- it is smaller, faster and easier to "
                     "reason about on a Pi.") + "\n")
        print(f"\n  head-to-head test macro-F1: TCN {t:.4f} | LightGBM {b:.4f} -> {winner}")

    # ---------------- Leakage probe ----------------
    md.append("## Leakage probe -- ablate the top-importance feature\n")
    md.append(
        "v1 scored ~99% under a random shuffle and was worthless in the field. The "
        "test that exposed it: delete its single most important feature and re-measure. "
        "`frame.time_relative` carried 42% of stage-1 split gain while encoding nothing "
        "but *which capture the row came from* -- removing it collapsed the model. A "
        "healthy detector degrades gracefully; a leaky one falls off a cliff or, worse, "
        "does not move at all because ten other columns encode the same artefact.\n")
    if not top_features:
        md.append("_No GBDT importances available, so no feature to ablate._\n")
    else:
        probe_rows = ["| ablated feature | model | macro-F1 | delta |",
                      "|---|---|---:|---:|"]
        for name, _ in top_features[:max(1, args.probe_top)]:
            print(f"\n-- probe: ablate '{name}' " + "-" * 30)
            # GBDT, score-only (feature -> NaN at inference)
            _, p = eval_gbdt(args.models, ds, blocks, ablate_name=name)
            f = T.macro_f1(ds.y[rows_g], p)
            probe_rows.append(f"| `{name}` | LightGBM (score-only) | {f:.4f} "
                              f"| {f - results['gbdt']:+.4f} |")
            print(f"  gbdt score-only : {f:.4f} ({f - results['gbdt']:+.4f})")

            # GBDT, retrained without the column -- the honest version
            if not args.no_probe_retrain:
                targs = T.build_args([])
                for k, v in train_args.items():
                    if hasattr(targs, k) and k not in {"data", "out", "device", "model"}:
                        setattr(targs, k, v)
                targs.data, targs.out, targs.device = args.data, args.models, "cpu"
                g2 = T.train_gbdt(ds, assign, targs, args.models, [],
                                  drop_feature=name, quiet=True)
                keep = [i for i, n in enumerate(T.gbdt_feature_names()) if n != name]
                rr, pp = [], []
                for b_ in blocks:
                    s, e = int(ds.bounds[b_, 0]), int(ds.bounds[b_, 1])
                    fe = np.concatenate(
                        [ds.X[s:e], W.causal_rollups(ds.X, ds.bounds, [b_])], axis=1)[:, keep]
                    pp.append(g2["booster"].predict(fe).argmax(1))
                    rr.append(np.arange(s, e, dtype=np.int64))
                f2 = T.macro_f1(ds.y[np.concatenate(rr)], np.concatenate(pp).astype(np.int64))
                probe_rows.append(f"| `{name}` | LightGBM (**retrained** without it) "
                                  f"| {f2:.4f} | {f2 - results['gbdt']:+.4f} |")
                print(f"  gbdt retrained  : {f2:.4f} ({f2 - results['gbdt']:+.4f})")

        # The TCN has no rolling-aggregate inputs, so if the GBDT's top feature is
        # a `roll*` column there is nothing to ablate on the network. Fall back to
        # the highest-gain feature that *is* in the 47-feature contract, and say so.
        tcn_note = ""
        if ckpt_path.exists():
            frame_top = [(n, g) for n, g in top_features if n in FEATURE_ORDER]
            for name, _ in frame_top[:max(1, args.probe_top)]:
                print(f"\n-- probe: ablate '{name}' on the TCN " + "-" * 22)
                _, pt, _ = eval_tcn(ckpt_path, ds, blocks, args.device, args.eval_chunk,
                                    args.eval_batch, ablate=FEATURE_ORDER.index(name))
                ft = T.macro_f1(ds.y[rows], pt)
                probe_rows.append(f"| `{name}` | TCN (score-only) | {ft:.4f} "
                                  f"| {ft - results['tcn']:+.4f} |")
                print(f"  tcn score-only  : {ft:.4f} ({ft - results['tcn']:+.4f})")
            if frame_top and frame_top[0][0] != top_features[0][0]:
                tcn_note = (f"\n_The GBDT's top feature is `{top_features[0][0]}`, a causal "
                            f"rolling aggregate the TCN does not take as input -- the network "
                            f"builds its own temporal context through dilated convolutions. "
                            f"The TCN row therefore ablates `{frame_top[0][0]}`, the "
                            f"highest-gain feature that is actually in the 47-feature "
                            f"contract._\n")
        md.append("\n".join(probe_rows))
        if tcn_note:
            md.append(tcn_note)
        md.append(
            "\n_Score-only ablation sets the feature to **NaN**, not zero: NaN is a "
            "state the feature contract defines and the model has a mask channel for, "
            "whereas zeroing post-normalises to the training mean -- the exact silent "
            "imputation that broke v1. The retrained row is the stronger evidence; the "
            "score-only rows show how brittle the *deployed* weights are to that field "
            "going missing on a real capture._\n")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "eval_report.md").write_text("\n".join(md), encoding="utf-8")
    (args.models / "eval_summary.json").write_text(
        json.dumps({"split": args.split, "macro_f1": results}, indent=2), encoding="utf-8")
    print(f"\n  wrote {REPORT_DIR / 'eval_report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
