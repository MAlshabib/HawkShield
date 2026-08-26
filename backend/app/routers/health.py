"""Liveness / readiness endpoint.

Deliberately dependency-free: it never imports ``backend.detector.*``; model
availability is a plain filesystem check, and the v2 artefact is validated by
reading its meta JSON, not by loading the graph.

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

from backend.app.config import APP_VERSION, SPEC_VERSION, settings, v2_status
from backend.app.db import get_db
from backend.app.models import Packet
from backend.app.schemas import HealthOut, ModelsPresent

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)) -> HealthOut:
    """Report DB reachability, packet volume and model-bundle presence."""
    database_ok = True
    packets = 0
    latest_ts: Optional[object] = None

    try:
        packets = int(db.query(func.count(Packet.id)).scalar() or 0)
        latest_ts = db.query(func.max(Packet.ts)).scalar()
    except Exception as exc:  # noqa: BLE001 - health must never raise
        database_ok = False
        logger.warning("Health check: database unreachable: %s", exc)

    v2 = v2_status()
    models = ModelsPresent(
        stage1=settings.stage1_path.exists(),
        stage2=settings.stage2_path.exists(),
        v2=bool(v2["usable"]),
    )

    # Mirrors backend.detector.pipeline.build_pipeline's precedence.
    requested = str(settings.MODEL_VERSION or "auto").lower()
    v1_ok = models.stage1 and models.stage2
    if requested == "v1":
        model_version = "v1" if v1_ok else "none"
    elif requested == "v2":
        model_version = "v2" if models.v2 else "none"
    else:
        model_version = "v2" if models.v2 else ("v1" if v1_ok else "none")

    if v2["present"] and not v2["usable"]:
        logger.warning(
            "v2 artefact present but unusable, so the detector serves %s: %s",
            model_version, "; ".join(v2["problems"]),
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
        model_problems=list(v2["problems"]) if v2["present"] else [],
        version=APP_VERSION,
    )
