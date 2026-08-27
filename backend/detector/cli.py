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
    ap.add_argument("--log-level", default=getattr(s, "LOG_LEVEL", "INFO"),
                    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

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
