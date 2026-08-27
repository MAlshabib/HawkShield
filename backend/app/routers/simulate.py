"""``POST /simulate`` -- replay held-out AWID3 frames through the real pipeline.

This is the testing / demo control.  It does **not** fabricate detections: it
loads ``data/sim/awid3_sim_corpus.parquet`` (real, held-out AWID3 feature rows),
pushes them through the *same* ``build_pipeline`` the live detector runs, and
persists whatever the model actually flags -- via the *same* ``PacketSink`` the
detector writes with, so the ``packets`` schema is untouched.

Two honesty properties hold by construction:

* every simulated row carries ``raw.sim = true`` and ``raw.sim_batch = <uuid>``,
  so simulated traffic is invisible in the normal UI shape yet trivially
  filterable and purgeable (``DELETE FROM packets WHERE json_extract(raw,'$.sim')``);
* the per-class summary reports what the model *did*, not what was asked -- so if
  a class under-detects (Kr00k, in isolation, leans toward Disas), the caller
  sees it in the numbers rather than being told a comfortable lie.

Gated by ``ALLOW_SIMULATION`` (default on) and capped at ``SIM_MAX_COUNT`` per
class.  Consistent with ``/ask``: 503 when no model or no corpus can load.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from typing import Any, Deque, Dict, List, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import settings
from backend.app.db import get_db
from backend.app.schemas import (
    SimulateClassResult,
    SimulatePayload,
    SimulateResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["simulate"])

# The heavy machinery (scapy via attack_sim, lightgbm via the pipeline) is
# imported lazily inside the handler so registering this router never drags the
# model stack into a bare web process, and a missing dependency becomes a clean
# 503 rather than an import-time crash -- the same shape as ask.py.

# One pipeline, built once and reused.  It is stateful (the GBDT's rolling
# aggregates), so a lock serialises scoring and every run resets between classes.
_PIPELINE: Any = None
_PIPELINE_LOCK = threading.Lock()

# Light rate limit: a rolling window of recent call times.  Not a security
# control -- just a guard so a stuck client cannot spin the DB.
_RATE_WINDOW_S = 60.0
_RATE_MAX = 30
_CALLS: Deque[float] = deque()
_RATE_LOCK = threading.Lock()

#: Stop a class once a full replay pass persists nothing new -- otherwise a
#: request for more detections than the corpus can yield would loop forever.
_MAX_PASSES = 200


def _rate_check() -> None:
    now = time.monotonic()
    with _RATE_LOCK:
        while _CALLS and now - _CALLS[0] > _RATE_WINDOW_S:
            _CALLS.popleft()
        if len(_CALLS) >= _RATE_MAX:
            raise HTTPException(
                status_code=429,
                detail=f"simulation rate limit: {_RATE_MAX} calls per "
                       f"{int(_RATE_WINDOW_S)}s. Try again shortly.",
            )
        _CALLS.append(now)


def _get_pipeline() -> Any:
    """Build (once) and return the same pipeline the detector uses, or raise."""
    global _PIPELINE
    with _PIPELINE_LOCK:
        if _PIPELINE is None:
            from backend.detector.pipeline import build_pipeline

            # Pass MODEL_DIR from this router's settings object explicitly, so the
            # gate here and the artefact lookup inside build_pipeline agree on one
            # configuration rather than the pipeline re-reading a (possibly
            # reloaded) settings singleton via get_settings().
            _PIPELINE = build_pipeline(
                model_version=settings.MODEL_VERSION,
                model_dir=settings.MODEL_DIR,
            )
        return _PIPELINE


def _simulate_one_class(
    pipe: Any,
    sink: Any,
    cls: str,
    seg: Any,
    want_count: int,
    batch: str,
    intensity: str,
) -> SimulateClassResult:
    """Replay one class's segment until ``want_count`` detections persist."""
    import numpy as np  # noqa: F401 - kept local; pipeline already needs it

    from backend.detector.attack_sim import sim_mac
    from backend.detector.feature_spec import FEATURE_ORDER
    from backend.detector.pipeline import Verdict  # noqa: F401 - type only

    raw_template: Dict[str, Any] = {
        "iface": "sim0",
        "sa": sim_mac(cls, "sa"),
        "da": sim_mac(cls, "da"),
        "bssid": sim_mac(cls, "bssid"),
        "sim": True,
        "sim_batch": batch,
        "sim_class": cls,
    }

    frames_pushed = 0
    detected = 0
    persisted = 0
    labels: Dict[str, int] = {}
    seg_list = list(seg)

    for _pass in range(_MAX_PASSES):
        if persisted >= want_count:
            break
        pipe.reset()
        verdicts = pipe.predict_stream(seg_list)
        gained = 0
        for idx, v in enumerate(verdicts):
            frames_pushed += 1
            # p1 cleared thr1 => the model considers it an attack at all.
            if v.stage == 2 and v.label is not None:
                detected += 1
            if v.is_attack and v.label is not None:
                labels[v.label] = labels.get(v.label, 0) + 1
                row = {k: float(seg_list[idx][j]) for j, k in enumerate(FEATURE_ORDER)}
                raw = dict(raw_template)
                sink.write(raw, row, v, "sim0")
                persisted += 1
                gained += 1
                if persisted >= want_count:
                    break
        if gained == 0:
            # A whole pass added nothing; the corpus cannot reach want_count.
            break
        if intensity == "trickle":
            # A visible cadence for the live tail without materially slowing a run.
            time.sleep(0.02)

    top_label = max(labels, key=labels.get) if labels else None
    return SimulateClassResult(
        requested=want_count,
        frames_pushed=frames_pushed,
        detected=detected,
        persisted=persisted,
        top_label=top_label,
        labels=labels,
    )


@router.post("/simulate", response_model=SimulateResponse)
def simulate(payload: SimulatePayload, db: Session = Depends(get_db)) -> SimulateResponse:
    """Replay corpus frames through the live model and persist real detections."""
    if not settings.ALLOW_SIMULATION:
        raise HTTPException(status_code=403, detail="simulation is disabled (ALLOW_SIMULATION=0)")

    _rate_check()

    count = min(int(payload.count), int(settings.SIM_MAX_COUNT))

    # Corpus first: a clear 503 if the demo data is missing, before loading a model.
    from backend.detector.attack_sim import CorpusUnavailable, load_sim_corpus

    corpus_path = settings.SIM_CORPUS.strip() or None
    try:
        corpus = load_sim_corpus(corpus_path)
    except CorpusUnavailable as exc:
        logger.info("/simulate rejected: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        classes = corpus.resolve(payload.attacks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        pipe = _get_pipeline()
    except FileNotFoundError as exc:
        logger.info("/simulate rejected: no model (%s)", exc)
        raise HTTPException(status_code=503, detail=f"no model available: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - any load failure is a 503, like /ask
        logger.warning("/simulate rejected: model load failed (%s)", exc)
        raise HTTPException(status_code=503, detail=f"model load failed: {exc}") from exc

    batch = uuid.uuid4().hex

    # Write through the same sink the detector uses, but bound to *this request's*
    # engine so the endpoint honours a get_db dependency-override (tests) and the
    # configured database (production) alike.
    from backend.detector.sink import PacketSink

    maker = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)
    sink = PacketSink(session_factory=maker)

    per_class: Dict[str, SimulateClassResult] = {}
    with _PIPELINE_LOCK:
        try:
            for cls in classes:
                per_class[cls] = _simulate_one_class(
                    pipe, sink, cls, corpus.rows[cls], count, batch, payload.intensity
                )
        finally:
            sink.close()

    total_persisted = sum(r.persisted for r in per_class.values())
    logger.info(
        "/simulate batch=%s classes=%s count=%d persisted=%d",
        batch, classes, count, total_persisted,
    )
    return SimulateResponse(
        sim_batch=batch,
        model_version=getattr(pipe, "model_version", "unknown"),
        intensity=payload.intensity,
        classes=classes,
        count_per_class=count,
        total_persisted=total_persisted,
        per_class=per_class,
    )
