"""Map endpoints: AP inventory, per-source RSSI and origin estimation."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models import Packet
from backend.app.schemas import (
    APLocation,
    EstimateOriginPayload,
    RSSIPoint,
    SourceRSSIResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["map"])


def _load_ap_locations() -> List[Dict[str, Any]]:
    """Read the AP inventory from ``AP_LOCATIONS_FILE``.

    Returns an empty list (with a warning) when the file is missing or malformed
    so the map page degrades instead of 500-ing.
    """
    path = settings.AP_LOCATIONS_FILE
    if not path.exists():
        logger.warning("AP locations file not found at %s - returning []", path)
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read AP locations from %s: %s - returning []", path, exc)
        return []

    if isinstance(data, dict):
        data = data.get("aps", [])
    if not isinstance(data, list):
        logger.warning("AP locations file %s is not a list - returning []", path)
        return []

    out: List[Dict[str, Any]] = []
    for entry in data:
        try:
            out.append(APLocation(**entry).model_dump())
        except Exception as exc:  # noqa: BLE001 - one bad row must not kill the list
            logger.warning("Skipping malformed AP entry %r: %s", entry, exc)
    return out


def _avg_rssi_rows(db: Session, sa: str, minutes: int):
    """Average signal per BSSID for frames from ``sa`` in the last ``minutes``."""
    lower_bound_dt = datetime.fromtimestamp(time.time() - minutes * 60, tz=timezone.utc)
    return (
        db.query(
            Packet.bssid.label("bssid"),
            func.avg(Packet.signal_dbm).label("avg_rssi"),
            func.count(Packet.id).label("n"),
        )
        .filter(Packet.src_mac == sa)
        .filter(Packet.ts >= lower_bound_dt)
        .group_by(Packet.bssid)
        .all()
    )


@router.get("/map/ap-locations", response_model=List[APLocation])
def ap_locations() -> List[Dict[str, Any]]:
    """The configured access-point inventory."""
    return _load_ap_locations()


@router.get("/map/source-rssi", response_model=SourceRSSIResponse)
def source_rssi(sa: str, minutes: int = 10, db: Session = Depends(get_db)) -> SourceRSSIResponse:
    """Average RSSI per BSSID for a given source MAC over a time window."""
    rows = _avg_rssi_rows(db, sa, minutes)
    points = [
        RSSIPoint(bssid=str(r.bssid or ""), avg_rssi=float(r.avg_rssi or -90.0), n=int(r.n or 0))
        for r in rows
        if r.bssid
    ]
    return SourceRSSIResponse(sa=sa, points=points)


@router.post("/map/estimate-origin")
def estimate_origin(
    payload: EstimateOriginPayload,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Rough origin estimate: centroid of AP locations weighted by signal strength."""
    sa = str(payload.sa or "")
    minutes = int(payload.minutes or 10)
    ap_locations_in = payload.ap_locations or []
    if not sa or not ap_locations_in:
        return {"detail": "Missing sa or ap_locations"}

    rows = _avg_rssi_rows(db, sa, minutes)
    rssi_by_bssid = {str(r.bssid): float(r.avg_rssi or -90.0) for r in rows if r.bssid}

    used: List[tuple] = []
    for ap in ap_locations_in:
        bssid = str(ap.get("bssid") or "")
        if not bssid or bssid not in rssi_by_bssid:
            continue
        try:
            lat = float(ap.get("lat"))
            lng = float(ap.get("lng"))
        except (TypeError, ValueError):
            logger.warning("Skipping AP with unusable coordinates: %r", ap)
            continue
        rssi = rssi_by_bssid[bssid]
        w = 1.0 / max(1.0, abs(rssi) + 1.0)  # simple weighting by signal strength
        used.append((lat, lng, w))

    if not used:
        return {
            "sa": sa,
            "method": "weighted-centroid",
            "used": 0,
            "center": None,
            "note": "No matching RSSI/AP pairs in the selected window.",
        }

    sw = sum(w for _, _, w in used)
    lat = sum(lat * w for lat, _, w in used) / sw
    lng = sum(lng * w for _, lng, w in used) / sw
    return {"sa": sa, "method": "weighted-centroid", "used": len(used), "center": {"lat": lat, "lng": lng}}
