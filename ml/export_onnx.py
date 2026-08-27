#!/usr/bin/env python3
"""
Export the trained TCN to ONNX, quantise it to int8, and prove the exported graph
still agrees with PyTorch.

    python ml/export_onnx.py --models _work/models_v2

Writes:
    models/hawkshield_v2.onnx           float32 graph
    models/hawkshield_v2.int8.onnx      dynamically quantised (weights -> int8)
    models/hawkshield_v2_meta.json      spec version, classes, feature order,
                                        window, and the normalisation constants
    models/hawkshield_v2_gbdt.txt       the LightGBM baseline, if one was trained

The normalisation constants live *inside* the graph as initialisers and *also* in
the meta file. The graph is the authority -- the meta copy exists so the runtime
can assert they match and refuse to start if they do not. Training and inference
disagreeing about the constants is half of what killed v1.

Both graphs take ``(batch, 47, T)`` with NaN allowed for genuinely-absent fields
and return ``(batch, 9, T)`` logits, one per frame. ``T`` is dynamic: the live
detector feeds ``context + 1`` frames and reads the last position.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import warnings
import tempfile
import time
from pathlib import Path
from typing import Optional, Sequence

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ml.windows as W  # noqa: E402
from ml.windows import CLASSES, FEATURE_ORDER, SPEC_VERSION  # noqa: E402

DEFAULT_MODELS = REPO_ROOT / "_work" / "models_v2"
DEFAULT_OUT = REPO_ROOT / "models"


def sample_batch(n: int, t: int, seed: int = 0) -> np.ndarray:
    """Random input with realistic NaN density so the missing-value path is tested."""
    rng = np.random.default_rng(seed)
    x = rng.normal(0, 3, size=(n, len(FEATURE_ORDER), t)).astype(np.float32)
    x[rng.random(x.shape) < 0.15] = np.nan
    return x


def real_batch(data: Path, n: int, t: int, seed: int = 0) -> Optional[np.ndarray]:
    """Prefer real frames: they carry the real NaN *pattern*, which random noise
    does not (``eapol.*`` is NaN on every non-EAPOL frame, not 15% of the time)."""
    try:
        from ml import windows as W
        ds = W.load_blocks(data, max_rows=n * t * 4, seed=seed, verbose=False)
        if len(ds.y) < t:
            return None
        starts = W.training_windows(ds.bounds, range(ds.n_blocks), t, t)[:n]
        if starts.size == 0:
            return None
        return W.gather_windows(ds.X, starts, t)
    except Exception as exc:  # data not prepared yet -- fall back to synthetic
        print(f"  [warn] no real frames for verification ({exc}); using synthetic")
        return None


def _bench_main(model: str, npy: str, iters: int, threads: int) -> int:
    """Latency benchmark, run in a **clean subprocess**.

    In-process timing is unreliable here: torch's allocator and the 16-thread
    pools of the verification sessions both perturb it, and the same graph
    measured 0.4 ms standalone and 5 ms in the export process. A subprocess that
    imports nothing but numpy and onnxruntime gives a number that means something
    and reproduces.
    """
    import numpy as _np
    import onnxruntime as _ort

    x = _np.ascontiguousarray(_np.load(npy))
    so = _ort.SessionOptions()
    so.intra_op_num_threads = max(1, threads)
    so.inter_op_num_threads = 1
    sess = _ort.InferenceSession(model, so, providers=["CPUExecutionProvider"])
    for _ in range(30):
        sess.run(None, {"frames": x})
    best = float("inf")                       # min of 5 rounds: robust to jitter
    per_round = max(1, iters // 5)
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(per_round):
            sess.run(None, {"frames": x})
        best = min(best, (time.perf_counter() - t0) / per_round * 1000.0)
    print(f"{best:.6f}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None and len(sys.argv) > 1 and sys.argv[1] == "--bench-only":
        return _bench_main(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    ap = argparse.ArgumentParser(description="Export HawkShield v2 to ONNX + int8.")
    ap.add_argument("--models", type=Path, default=DEFAULT_MODELS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--data", type=Path, default=REPO_ROOT / "_work" / "awid3_v2")
    ap.add_argument("--name", default="hawkshield_v2")
    ap.add_argument("--opset", type=int, default=17)
    ap.add_argument("--latency-iters", type=int, default=400)
    ap.add_argument("--latency-threads", type=int, default=4,
                    help="onnxruntime intra-op threads for the latency measurement; "
                         "4 mirrors a Pi 4/5, not this 16-core dev box")
    ap.add_argument("--tolerance", type=float, default=2e-4)
    args = ap.parse_args(argv)
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    warnings.filterwarnings("ignore", category=UserWarning)

    import torch
    from ml.model import build_from_checkpoint, assert_causal

    ckpt_path = args.models / "tcn.pt"
    if not ckpt_path.exists():
        print(f"[FAIL] no checkpoint at {ckpt_path}. Run ml/train.py --model tcn first.",
              file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)
    model = build_from_checkpoint(ckpt)
    window = int(ckpt.get("window", 128))
    context = int(ckpt.get("context", model.receptive_field - 1))
    n_params = sum(p.numel() for p in model.parameters())

    print(f"HawkShield v2 ONNX export | spec {SPEC_VERSION}")
    print(f"  checkpoint : {ckpt_path} (epoch {ckpt.get('epoch')}, "
          f"val macro-F1 {ckpt.get('val_macro_f1', float('nan')):.4f})")
    print(f"  parameters : {n_params:,}   receptive field {model.receptive_field}")

    causality = assert_causal(model, n_features=len(FEATURE_ORDER), window=window,
                              t=window // 2)
    print(f"  causality  : past {causality['max_delta_past']:.3e} / "
          f"future {causality['max_delta_future']:.3e}  OK")

    fp32 = args.out / f"{args.name}.onnx"
    int8 = args.out / f"{args.name}.int8.onnx"
    dummy = torch.from_numpy(sample_batch(2, window, seed=7))

    exported = False
    for use_dynamo in (False, True):
        try:
            torch.onnx.export(
                model, (dummy,), str(fp32),
                input_names=["frames"], output_names=["logits"],
                dynamic_axes={"frames": {0: "batch", 2: "time"},
                              "logits": {0: "batch", 2: "time"}},
                opset_version=args.opset, dynamo=use_dynamo,
            )
            exported = True
            print(f"  exported   : {fp32.name} (opset {args.opset}, "
                  f"{'dynamo' if use_dynamo else 'legacy'} exporter)")
            break
        except Exception as exc:
            print(f"  [warn] {'dynamo' if use_dynamo else 'legacy'} export failed: {exc}")
    if not exported:
        print("[FAIL] ONNX export failed with both exporters.", file=sys.stderr)
        return 3

    # ---- verify exported == torch on real frames -----------------------------
    import onnxruntime as ort

    verify = real_batch(args.data, 8, window)
    if verify is None:
        verify = sample_batch(8, window, seed=11)
        source = "synthetic (NaN sprinkled)"
    else:
        source = f"real AWID3 frames ({np.isnan(verify).mean() * 100:.1f}% NaN)"

    with torch.no_grad():
        ref = model(torch.from_numpy(verify)).numpy()
    sess = ort.InferenceSession(str(fp32), providers=["CPUExecutionProvider"])
    got = sess.run(None, {"frames": verify})[0]
    max_abs = float(np.max(np.abs(ref - got)))
    agree = float(np.mean(ref.argmax(1) == got.argmax(1)))
    print(f"  verify     : {source}")
    print(f"               max |torch - onnx| = {max_abs:.3e}  "
          f"argmax agreement = {agree * 100:.4f}%")
    if max_abs > args.tolerance or agree < 1.0:
        print(f"[FAIL] exported graph disagrees with PyTorch "
              f"(tolerance {args.tolerance}).", file=sys.stderr)
        return 4

    # ---- int8 dynamic quantisation ------------------------------------------
    from onnxruntime.quantization import quantize_dynamic, QuantType
    from onnxruntime.quantization.shape_inference import quant_pre_process

    pre = args.out / f"{args.name}.pre.onnx"
    try:
        quant_pre_process(str(fp32), str(pre), skip_symbolic_shape=False)
        src = pre
    except Exception as exc:
        print(f"  [warn] quant pre-process skipped: {exc}")
        src = fp32
    quantize_dynamic(str(src), str(int8), weight_type=QuantType.QInt8)
    if pre.exists():
        pre.unlink()

    sess8 = ort.InferenceSession(str(int8), providers=["CPUExecutionProvider"])
    got8 = sess8.run(None, {"frames": verify})[0]
    agree8 = float(np.mean(ref.argmax(1) == got8.argmax(1)))
    max_abs8 = float(np.max(np.abs(ref - got8)))
    print(f"  int8       : max |torch - int8| = {max_abs8:.3e}  "
          f"argmax agreement = {agree8 * 100:.4f}%")

    # ---- latency -------------------------------------------------------------
    # Torch keeps a 16-thread intra-op pool alive in this process; left alone it
    # contends with onnxruntime's and inflates the measurement ~10x. Park it, and
    # pin ORT to a fixed thread count so the number means something and does not
    # drift with whatever else the box is doing.
    tmpdir = Path(tempfile.mkdtemp(prefix="hawkshield_bench_"))

    def latency(model_path: Path, n_frames: int, iters: int) -> float:
        npy = tmpdir / f"in_{n_frames}.npy"
        if not npy.exists():
            np.save(npy, np.ascontiguousarray(verify[:1, :, :n_frames]))
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--bench-only",
             str(model_path), str(npy), str(iters), str(args.latency_threads)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print(f"  [warn] latency subprocess failed: {proc.stderr.strip()[:200]}")
            return float("nan")
        return float(proc.stdout.strip().splitlines()[-1])

    stream_len = context + 1
    lat = {
        "fp32_window_ms": latency(fp32, window, args.latency_iters),
        "int8_window_ms": latency(int8, window, args.latency_iters),
        "fp32_stream_ms": latency(fp32, stream_len, args.latency_iters),
        "int8_stream_ms": latency(int8, stream_len, args.latency_iters),
    }
    size32 = fp32.stat().st_size / 1024
    size8 = int8.stat().st_size / 1024
    print(f"  size       : fp32 {size32:.1f} KB | int8 {size8:.1f} KB")
    print(f"  latency    : window({window}) fp32 {lat['fp32_window_ms']:.2f} ms / "
          f"int8 {lat['int8_window_ms']:.2f} ms  "
          f"(= {lat['int8_window_ms'] / window * 1000:.1f} us per frame)")
    print(f"               stream({stream_len}) fp32 {lat['fp32_stream_ms']:.2f} ms / "
          f"int8 {lat['int8_stream_ms']:.2f} ms per decision")
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)
    print(f"  [note] {args.latency_threads} onnxruntime threads on this dev box's CPU; "
          f"a Pi 4/5 at the same thread count is roughly 4-8x slower.")
    if lat["int8_stream_ms"] > lat["fp32_stream_ms"] * 1.1:
        print(f"  [note] int8 is {lat['int8_stream_ms'] / lat['fp32_stream_ms']:.1f}x "
              f"SLOWER than fp32 here: onnxruntime has no fast int8 Conv1d kernel for "
              f"these shapes, so it dequantises per call. Ship the fp32 graph unless "
              f"you are flash-bound; the int8 file is {size32 / size8:.1f}x smaller.")

    # ---- companion GBDT ------------------------------------------------------
    # The GBDT is a first-class serving target (``--model-version v2-gbdt``), not a
    # curiosity: it consumes the 46 spec features PLUS the causal rolling
    # aggregates from ``ml/windows.py``, 82 columns in all.  The block recorded in
    # the meta below is *informational* -- the authority on those columns is the
    # ``feature_names=`` header LightGBM writes into the model file itself, which
    # is what ``GBDTPipeline`` validates against.  Recording it here anyway means a
    # reader of the meta can see that the ONNX graph is not the only thing shipped.
    gbdt_src = args.models / "gbdt.txt"
    gbdt_out = None
    gbdt_block = None
    if gbdt_src.exists():
        gbdt_out = args.out / f"{args.name}_gbdt.txt"
        gbdt_out.write_bytes(gbdt_src.read_bytes())
        rollups = W.rollup_names()
        gbdt_block = {
            "file": gbdt_out.name,
            "n_features": len(FEATURE_ORDER) + len(rollups),
            "rollup_windows": list(W.ROLLUP_WINDOWS),
            "rollup_names": rollups,
            "feature_order": list(FEATURE_ORDER) + rollups,
            "note": "informational. The booster's own feature_names header is the "
                    "authority, and backend/detector/pipeline.py validates against "
                    "that, element for element, at load time.",
        }
        print(f"  gbdt       : copied {gbdt_out.name} "
              f"({gbdt_out.stat().st_size / 1024:.0f} KB, "
              f"{gbdt_block['n_features']} columns)")

    # ---- metadata ------------------------------------------------------------
    meta = {
        "spec_version": SPEC_VERSION,
        "model": args.name,
        "architecture": "causal dilated TCN",
        "classes": CLASSES,
        "feature_order": FEATURE_ORDER,
        "n_features": len(FEATURE_ORDER),
        "window": window,
        "context": context,
        "receptive_field": model.receptive_field,
        "parameters": int(n_params),
        "input": {"name": "frames", "shape": ["batch", len(FEATURE_ORDER), "time"],
                  "dtype": "float32",
                  "nan_policy": "NaN means the field is absent; do NOT impute. The "
                                "graph replaces NaN with a learned per-feature "
                                "sentinel and raises a companion mask channel."},
        "output": {"name": "logits", "shape": ["batch", len(CLASSES), "time"],
                   "note": "one prediction per frame; streaming reads the last position"},
        "normalisation": {
            "note": "train-split only; already baked into the graph as initialisers. "
                    "Assert these match the graph before serving.",
            "mean": [float(v) for v in ckpt["norm"]["mean"]],
            "std": [float(v) for v in ckpt["norm"]["std"]],
            "clamp": 8.0,
            "mask_feature_indices": list(ckpt["config"]["mask_idx"]),
        },
        "training": {
            "epoch": ckpt.get("epoch"),
            "val_macro_f1": ckpt.get("val_macro_f1"),
            "class_weights": ckpt.get("class_weights"),
            "causality_probe": ckpt.get("causality"),
        },
        "export": {
            "opset": args.opset,
            "verify_source": source,
            "max_abs_diff_fp32": max_abs,
            "argmax_agreement_fp32": agree,
            "max_abs_diff_int8": max_abs8,
            "argmax_agreement_int8": agree8,
            "size_kb": {"fp32": round(size32, 1), "int8": round(size8, 1)},
            "latency_ms": {k: round(v, 3) for k, v in lat.items()},
            "latency_threads": args.latency_threads,
            "latency_host": f"dev CPU, {args.latency_threads} ORT intra-op threads; "
                            f"expect 4-8x on a Raspberry Pi",
        },
        "companion_gbdt": gbdt_out.name if gbdt_out else None,
        "gbdt": gbdt_block,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    meta_path = args.out / f"{args.name}_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"  wrote      : {meta_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
