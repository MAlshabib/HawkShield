#!/usr/bin/env python3
"""Detector entrypoint.

    sudo -E python -m backend.detector.cli --iface wlan1 --channel 6 --ssid HawkShield \
        --threshold1 0.4 --threshold2 0.8 --log-level INFO

Every option defaults to the corresponding setting in ``backend.app.config``
(i.e. to the environment / repo-root ``.env``).  ``--dry-run`` classifies without
opening a database connection, which is what you want when checking a new radio.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:  # allow `python backend/detector/cli.py` too
    sys.path.insert(0, str(_REPO_ROOT))

from backend.detector._config import get_settings  # noqa: E402
from backend.detector.capture import Detector  # noqa: E402
from backend.detector.pipeline import (  # noqa: E402
    MODEL_VERSION_ALIASES,
    MODEL_VERSIONS,
    build_pipeline,
)

logger = logging.getLogger("hawkshield.detector")


def build_parser() -> argparse.ArgumentParser:
    s = get_settings()
    ap = argparse.ArgumentParser(
        prog="python -m backend.detector.cli",
        description="HawkShield two-stage Wi-Fi attack detector (scapy monitor mode)",
    )
    ap.add_argument("--iface", default=getattr(s, "CAPTURE_IFACE", "wlan1"),
                    help="monitor-mode interface (default: %(default)s)")
    ap.add_argument("--channel", type=int, default=getattr(s, "CAPTURE_CHANNEL", 6),
                    help="channel to pin (default: %(default)s)")
    ap.add_argument("--ssid", default=getattr(s, "TARGET_SSID", "") or None,
                    help="optional SSID soft filter (default: no filter)")
    ap.add_argument("--threshold1", type=float, default=getattr(s, "STAGE1_THRESHOLD", 0.40),
                    help="stage-1 P(attack) cutoff (default: %(default)s)")
    ap.add_argument("--threshold2", type=float, default=getattr(s, "STAGE2_THRESHOLD", 0.80),
                    help="stage-2 confidence cutoff (default: %(default)s)")
    ap.add_argument("--model-dir", default=None,
                    help="override MODEL_DIR for this run")
    ap.add_argument("--model-version", default=getattr(s, "MODEL_VERSION", "auto"),
                    choices=list(MODEL_VERSIONS) + sorted(MODEL_VERSION_ALIASES),
                    metavar="{" + ",".join(MODEL_VERSIONS) + "}",
                    help="auto = v2-gbdt (LightGBM + causal rolling aggregates, the "
                         "best measured model: test macro-F1 0.9907), else v2-tcn "
                         "(causal TCN, ONNX, 0.9856), else the v1 bundles - taking the "
                         "first whose artefact matches feature_spec. An explicit choice "
                         "refuses to start on a mismatch rather than downgrading. "
                         "'v2' is accepted and means v2-tcn (default: %(default)s)")
    ap.add_argument("--batch-frames", type=int, default=None,
                    help="v2 only: frames scored per inference call "
                         "(default: V2_BATCH_FRAMES, 32)")
    ap.add_argument("--dry-run", action="store_true",
                    help="classify and log, but never write to the database")
    ap.add_argument("--self-test", action="store_true",
                    help="load the model, push crafted frames through the full "
                         "feature + inference path, and assert every frame yields a "
                         "complete feature vector and a verdict. Exits 0 if the model "
                         "is live and predicting on this machine, non-zero otherwise. "
                         "Never touches a radio or the database.")
    ap.add_argument("--self-test-count", type=int, default=8,
                    help="crafted frames per class for --self-test (default: %(default)s)")
    ap.add_argument("--log-level", default=getattr(s, "LOG_LEVEL", "INFO"),
                    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    return ap


def self_test(args: argparse.Namespace) -> int:
    """Prove the model loads and predicts on this machine.

    Builds the selected pipeline, then pushes crafted frames through the SAME
    feature extractor and inference path the detector uses, and asserts the
    plumbing: the model loaded, every frame produced a complete feature vector,
    and every frame produced a verdict carrying a finite ``p1``.

    It deliberately does NOT assert class labels.  Crafted frames carry no
    inter-frame timing, and the booster's most important feature is exactly that
    timing, so their *labels* are unreliable by construction (a documented
    finding) -- but their feature vectors and probabilities are fully formed,
    which is what "is the model live?" actually asks.
    """
    from backend.detector.attack_sim import SIM_CLASSES, build_frames
    from backend.detector.feature_spec import FEATURE_ORDER
    from backend.detector.features import (
        FEATURE_ORDER_V2,
        ExtractState,
        FrameState,
        packet_to_features_v2,
        packet_to_row,
    )

    try:
        pipe = build_pipeline(
            model_version=args.model_version,
            model_dir=Path(args.model_dir) if args.model_dir else None,
            thr1=args.threshold1,
            thr2=args.threshold2,
            batch_frames=args.batch_frames,
        )
    except Exception as e:
        logger.error("SELF-TEST FAILED: no model could be loaded "
                     "(--model-version %s): %s", args.model_version, e)
        return 2

    is_v2 = getattr(pipe, "feature_space", "v1") == "v2"
    expected = FEATURE_ORDER_V2 if is_v2 else FEATURE_ORDER
    logger.info("SELF-TEST: model=%s feature_space=%s spec=%s classes=%d",
                getattr(pipe, "model_version", "?"),
                getattr(pipe, "feature_space", "?"),
                getattr(pipe, "spec_version", None), len(pipe.classes))

    frames = build_frames(list(SIM_CLASSES), max(1, int(args.self_test_count)))
    state = FrameState() if is_v2 else ExtractState()
    pipe.reset() if hasattr(pipe, "reset") else None

    rows: List[dict] = []
    problems: List[str] = []
    for i, pkt in enumerate(frames):
        if is_v2:
            row, _raw = packet_to_features_v2(pkt, "selftest0", state)
        else:
            row, _raw = packet_to_row(pkt, "selftest0", state)
        missing = [k for k in expected if k not in row]
        if missing:
            problems.append(f"frame {i}: {len(missing)} feature(s) absent from the "
                            f"vector, e.g. {missing[:4]}")
        rows.append(row)

    # Score the whole batch through the real path, then check every verdict.
    if hasattr(pipe, "predict_stream"):
        verdicts = pipe.predict_stream(rows)
    else:  # v1 has no streaming API
        verdicts = [pipe.predict(r) for r in rows]

    if len(verdicts) != len(frames):
        problems.append(f"got {len(verdicts)} verdicts for {len(frames)} frames")

    import math
    n_p1 = 0
    for i, v in enumerate(verdicts):
        if v.p1 is None or not math.isfinite(float(v.p1)):
            problems.append(f"frame {i}: no finite p1 (stage={v.stage})")
        else:
            n_p1 += 1

    if problems:
        logger.error("SELF-TEST FAILED (%d issue(s)):", len(problems))
        for p in problems[:12]:
            logger.error("  - %s", p)
        return 1

    logger.info(
        "SELF-TEST PASSED: %d crafted frames -> %d complete %d-feature vectors, "
        "%d verdicts, all with a finite p1. The model is live and predicting.",
        len(frames), len(rows), len(expected), n_p1,
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    if args.self_test:
        return self_test(args)

    try:
        pipeline = build_pipeline(
            model_version=args.model_version,
            model_dir=Path(args.model_dir) if args.model_dir else None,
            thr1=args.threshold1,
            thr2=args.threshold2,
            batch_frames=args.batch_frames,
        )
    except Exception as e:
        logger.error("could not load a model (--model-version %s): %s", args.model_version, e)
        return 2

    try:
        det = Detector(
            iface=args.iface,
            channel=args.channel,
            ssid=args.ssid,
            pipeline=pipeline,
            dry_run=args.dry_run,
        )
    except Exception as e:
        logger.error("could not start the detector: %s", e)
        return 2

    det.install_signal_handlers()
    try:
        det.run()
    except KeyboardInterrupt:  # pragma: no cover - interactive
        det.stop()
        det.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
