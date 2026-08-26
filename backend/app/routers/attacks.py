"""Packet / attack analytics endpoints."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from backend.app.config import ATTACK_CLASSES
from backend.app.db import get_db
from backend.app.models import Packet

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attacks"])

# DB labels the analysis endpoint always reports, zero-filled.  Derived from
# ``feature_spec.ATTACK_CLASSES`` (via config) rather than re-listed: v1 hardcoded
# six here, the spec now defines eight, and a second hand-maintained list is how
# ``Disas`` and ``Kr00k`` would have silently gone missing from the dashboard.
KNOWN_LABELS: List[str] = list(ATTACK_CLASSES)

# Accumulation order is Mon-first (``datetime.weekday()``); the response is
# re-ordered Sun-first because that is what the frontend heatmap expects.
DAY_NAMES_MON_FIRST: List[str] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
DAY_ORDER_SUN_FIRST: List[str] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def _normalise_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Undo the driver differences a raw ``SELECT *`` exposes.

    The listing uses raw SQL (so extra columns show up without a code change),
    which bypasses SQLAlchemy's result processors.  On PostgreSQL psycopg2
    already returns a ``dict`` for ``raw`` and a ``datetime`` for ``ts``; on
    SQLite both arrive as TEXT.  Normalise so the JSON shape is identical
    whichever backend is in use.
    """
    value = row.get("raw")
    if isinstance(value, str):
        try:
            row["raw"] = json.loads(value)
        except json.JSONDecodeError:
            logger.debug("Packet %s has a non-JSON raw payload", row.get("id"))

    ts = row.get("ts")
    if isinstance(ts, str):
        try:
            row["ts"] = datetime.fromisoformat(ts)
        except ValueError:
            logger.debug("Packet %s has an unparseable ts %r", row.get("id"), ts)

    return row


@router.get("/attacks")
def get_all_packets(
    db: Session = Depends(get_db),
    limit: int = Query(5000, ge=1, le=100000),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, Any]]:
    """Raw dump of the ``packets`` table, newest first, with pagination."""
    sql = text("SELECT * FROM packets ORDER BY id DESC LIMIT :limit OFFSET :offset")
    rows = db.execute(sql, {"limit": limit, "offset": offset}).mappings().all()
    return [_normalise_row(dict(r)) for r in rows]


@router.get("/packets/count")
def packets_count(db: Session = Depends(get_db)) -> Dict[str, int]:
    """Total number of persisted attack packets."""
    n = db.execute(text("SELECT COUNT(*) AS c FROM packets")).mappings().first()["c"]
    return {"count": int(n)}


@router.get("/attacks/analysis")
def read_attack_analysis(db: Session = Depends(get_db)) -> Dict[str, int]:
    """Count by ``predicted_label``; every attack class in the spec is present.

    Eight keys as of spec 2.1.0, zero-filled.  A label the DB holds but the spec
    no longer defines (a v1 row after a v2 upgrade, say) is not invented into the
    response -- the key set is the spec's, not the table's.
    """
    rows = (
        db.query(Packet.predicted_label, func.count(Packet.id))
        .filter(Packet.predicted_label.isnot(None))
        .group_by(Packet.predicted_label)
        .all()
    )
    result: Dict[str, int] = {k: 0 for k in KNOWN_LABELS}
    for db_label, cnt in rows:
        if db_label in result:
            result[db_label] = int(cnt)
    return result


@router.get("/top-offenders")
def top_offenders(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Top source MACs by packet count, descending.

    The output key is ``wlan_sa`` (not ``src_mac``): the frontend depends on the
    legacy name.
    """
    rows = (
        db.query(Packet.src_mac, func.count(Packet.id))
        .group_by(Packet.src_mac)
        .order_by(func.count(Packet.id).desc())
        .all()
    )
    return [{"wlan_sa": mac, "count": int(n)} for mac, n in rows if mac]


@router.get("/channel-usage")
def channel_usage(db: Session = Depends(get_db)) -> List[Dict[str, int]]:
    """Packet counts per RadioTap channel frequency, descending."""
    rows = (
        db.query(Packet.channel_freq, func.count(Packet.id))
        .group_by(Packet.channel_freq)
        .order_by(func.count(Packet.id).desc())
        .all()
    )
    return [{"channel_freq": int(freq), "count": int(c)} for (freq, c) in rows if freq is not None]


@router.get("/heatmap-attack")
def heatmap_attack(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Week x hour heatmap of packet timestamps, 7 days of 24 hours, Sun first."""
    buckets: Dict[str, List[Dict[str, int]]] = {
        d: [{"hour": h, "intensity": 0} for h in range(24)] for d in DAY_NAMES_MON_FIRST
    }

    for (ts,) in db.query(Packet.ts).all():
        if not ts:
            continue
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        day = DAY_NAMES_MON_FIRST[dt.weekday()]  # Mon = 0
        buckets[day][dt.hour]["intensity"] += 1

    return [
        {"day": d, "hours": buckets[d]}
        if d in buckets
        else {"day": d, "hours": [{"hour": h, "intensity": 0} for h in range(24)]}
        for d in DAY_ORDER_SUN_FIRST
    ]
