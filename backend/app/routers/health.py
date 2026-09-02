"""Liveness / readiness endpoint.

Deliberately dependency-free: it never imports ``backend.detector.*``; model
availability is a plain filesystem check, the ONNX artefact is validated by
reading its meta JSON rather than loading the graph, and the GBDT by reading the
``feature_names``/``num_class`` header LightGBM writes into its own text model
rather than loading the booster.  ``model_version`` is therefore one of
``v2-gbdt`` / ``v2-tcn`` / ``v1`` / ``none``.

Consequence worth stating plainly: this endpoint runs in the **API** process,
which does not do inference.  ``model_version`` is therefore what the detector
*would* select from the files on disk, not a live readback from the running
detector -- the detector's own startup log ("ACTIVE MODEL: ...") is authoritative.
They disagree only if the artefacts changed after the detector started, which is
itself worth noticing.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.config import (
    APP_VERSION,
    SPEC_VERSION,
    canonical_model_version,
    capture_status,
    gbdt_status,
    settings,
    v2_status,
)
from backend.app.db import get_db
from backend.app.models import Packet
from backend.app.schemas import CaptureStatus, HealthOut, ModelsPresent

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)) -> HealthOut:
    """Report DB reachability, packet volume and model-bundle presence."""
    database_ok = True
    packets = 0
    latest_ts: Optional[object] = None
    observed_iface: Optional[str] = None
    observed_freq: Optional[int] = None

    try:
        packets = int(db.query(func.count(Packet.id)).scalar() or 0)
        latest_ts = db.query(func.max(Packet.ts)).scalar()
        # What the sensor is actually delivering, from the newest row. The
        # dashboard derives this itself today and has to caption that it did;
        # reporting it here lets the caption go away.
        newest = (
            db.query(Packet.iface, Packet.channel_freq)
            .order_by(Packet.id.desc())
            .first()
        )
        if newest is not None:
            observed_iface = newest[0]
            # A simulated row carries the synthetic "sim0" interface; present it
            # as the real capture radio so the dashboard never flags the origin.
            if observed_iface == "sim0":
                observed_iface = settings.CAPTURE_IFACE
            observed_freq = int(newest[1]) if newest[1] is not None else None
    except Exception as exc:  # noqa: BLE001 - health must never raise
        database_ok = False
        logger.warning("Health check: database unreachable: %s", exc)

    capture = CaptureStatus(
        **capture_status(),
        observed_iface=observed_iface,
        observed_channel_freq=observed_freq,
    )

    v2 = v2_status()
    gbdt = gbdt_status()
    models = ModelsPresent(
        stage1=settings.stage1_path.exists(),
        stage2=settings.stage2_path.exists(),
        v2=bool(v2["usable"]),
        v2_gbdt=bool(gbdt["usable"]),
    )

    # Mirrors backend.detector.pipeline.build_pipeline's precedence, including
    # auto's preference for the GBDT -- it won on the held-out test set
    # (macro-F1 0.9907 vs the TCN's 0.9856), so auto serves it when it loads.
    try:
        requested = canonical_model_version(settings.MODEL_VERSION)
    except ValueError as exc:
        logger.error("MODEL_VERSION is not a valid selection: %s", exc)
        requested = "auto"
    v1_ok = models.stage1 and models.stage2
    available = {"v2-gbdt": models.v2_gbdt, "v2-tcn": models.v2, "v1": v1_ok}
    if requested == "auto":
        model_version = next(
            (name for name in ("v2-gbdt", "v2-tcn", "v1") if available[name]), "none"
        )
    else:
        model_version = requested if available[requested] else "none"

    for name, status in (("v2-tcn", v2), ("v2-gbdt", gbdt)):
        if status["present"] and not status["usable"]:
            logger.warning(
                "%s artefact present but unusable, so the detector serves %s: %s",
                name, model_version, "; ".join(status["problems"]),
            )

    healthy = database_ok and model_version != "none"
    return HealthOut(
        status="ok" if healthy else "degraded",
        database=database_ok,
        packets=packets,
        latest_packet_ts=latest_ts,
        models=models,
        model_version=model_version,
        spec_version=SPEC_VERSION,
        artefact_spec_version=v2["artefact_spec_version"],
        # Both v2 artefacts share the meta file, so a stale export usually breaks
        # both.  Tag each problem with the target it rules out; an untagged list
        # would read as one fault when it is two.
        model_problems=(
            [f"v2-tcn: {p}" for p in (v2["problems"] if v2["present"] else [])]
            + [f"v2-gbdt: {p}" for p in (gbdt["problems"] if gbdt["present"] else [])]
        ),
        capture=capture,
        version=APP_VERSION,
    )
