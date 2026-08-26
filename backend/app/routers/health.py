"""Liveness / readiness endpoint.

Deliberately dependency-free: it never imports ``backend.detector.*``; model
availability is a plain filesystem check.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.config import APP_VERSION, settings
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

    models = ModelsPresent(
        stage1=settings.stage1_path.exists(),
        stage2=settings.stage2_path.exists(),
    )

    healthy = database_ok and models.stage1 and models.stage2
    return HealthOut(
        status="ok" if healthy else "degraded",
        database=database_ok,
        packets=packets,
        latest_packet_ts=latest_ts,
        models=models,
        version=APP_VERSION,
    )
