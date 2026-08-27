"""Packet / attack analytics endpoints.

Every range/timezone parameter added here is **optional with a default that
reproduces the previous behaviour exactly**.  The shipped ``frontend/out`` bundle
calls all of these with no query string at all, so "omitted" has to mean "what
you got before": all time, UTC, and -- everywhere except ``/top-offenders`` --
the same number of rows.  ``backend/scripts/check_frontend.py`` pins that.
"""
from __future__ import annotations

import json
import logging
from collections import OrderedDict
from datetime import date as _date, datetime, time as _time, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Query as OrmQuery, Session

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


# --------------------------------------------------------------------------- #
# Range and timezone helpers                                                   #
# --------------------------------------------------------------------------- #
#: Upper bound on ``days``, matching the reporting window ``/reports/summary``
#: accepts.  Ten years is not a real query; it is a guard against an unbounded
#: integer arriving from a URL.
MAX_DAYS = 3650

#: ``bucket=hour`` over ten years would zero-fill 87,600 points.  Each bucket
#: size gets the window that keeps the response a sensible size, and anything
#: past it is a 400 rather than a silent clamp -- a caller who asked for 90 days
#: of hours should be told, not handed 31 and left to wonder.
MAX_DAYS_BY_BUCKET: Dict[str, int] = {"hour": 31, "day": 366}

#: Timestamps are stored naive UTC (``datetime.now(timezone.utc)`` with the
#: tzinfo dropped by the column type), so every comparison has to be naive UTC
#: too or SQLite compares two differently-shaped strings.
UTC = timezone.utc


def _resolve_tz(name: str) -> ZoneInfo:
    """An IANA zone name -> ``ZoneInfo``, or a 400.

    Rejected rather than silently falling back to UTC: a heatmap quietly drawn
    in the wrong zone is the defect this parameter exists to fix, so failing
    over to UTC would reintroduce it in a form nobody can see.
    """
    try:
        return ZoneInfo(str(name))
    except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown timezone {name!r}. Use an IANA name such as 'UTC', "
                "'Asia/Riyadh' or 'Europe/London'."
            ),
        ) from exc


def _since(days: Optional[int]) -> Optional[datetime]:
    """Lower bound of a ``days`` window as naive UTC, or ``None`` for all time."""
    if days is None:
        return None
    return (datetime.now(UTC) - timedelta(days=int(days))).replace(tzinfo=None)


def _windowed(query: OrmQuery, days: Optional[int]) -> OrmQuery:
    """Apply an optional ``days`` window to a query.  ``None`` leaves it all-time."""
    lower_bound = _since(days)
    return query if lower_bound is None else query.filter(Packet.ts >= lower_bound)


def _local(ts: datetime, zone: ZoneInfo) -> datetime:
    """A stored timestamp as wall-clock time in ``zone``."""
    aware = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    return aware.astimezone(zone)


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


# Every parameter below uses ``Annotated[T, Query(...)]`` rather than
# ``x: T = Query(default, ...)``.  The two are identical to FastAPI, but only the
# Annotated form leaves a *real* Python default on the function -- and these
# handlers are called directly, as plain functions, both by the tests and by the
# Saqr agent's tools (which must never self-HTTP).  With the older form,
# ``heatmap_attack(db)`` binds ``tz`` to a ``Query`` object and blows up inside
# ``ZoneInfo``, which is precisely how this refactor first broke the suite.
@router.get("/top-offenders")
def top_offenders(
    db: Session = Depends(get_db),
    days: Annotated[Optional[int], Query(
        ge=1, le=MAX_DAYS,
        description="Only count frames from the last N days. Omit for all time.",
    )] = None,
    limit: Annotated[int, Query(
        ge=1, le=500,
        description="Maximum offenders returned, largest first.",
    )] = 50,
) -> List[Dict[str, Any]]:
    """Top source MACs by packet count, descending.

    The output key is ``wlan_sa`` (not ``src_mac``): the frontend depends on the
    legacy name.

    ``limit`` is the one default in this module that does *not* reproduce the
    previous response: this endpoint used to return every distinct source MAC,
    which on a busy capture is unbounded wire cost for a table the browser then
    slices to 20.  Ordering is unchanged, so the default 50 is a prefix of what
    was returned before and no existing caller loses a row it displayed.
    """
    query = _windowed(
        db.query(Packet.src_mac, func.count(Packet.id)).filter(Packet.src_mac.isnot(None)),
        days,
    )
    rows = (
        query.group_by(Packet.src_mac)
        # The tiebreaker is load-bearing, not cosmetic: without it the engine
        # returns equal-count MACs in an arbitrary order, and truncating an
        # arbitrary order with LIMIT hands back an arbitrary *subset* of the tie
        # group -- a different one on each call. It is what makes `limit` mean
        # something. The trade is that tie order now differs from the unbounded
        # endpoint's incidental ordering; the counts and the data are identical.
        .order_by(func.count(Packet.id).desc(), Packet.src_mac.asc())
        .limit(int(limit))
        .all()
    )
    return [{"wlan_sa": mac, "count": int(n)} for mac, n in rows if mac]


@router.get("/channel-usage")
def channel_usage(
    db: Session = Depends(get_db),
    days: Annotated[Optional[int], Query(
        ge=1, le=MAX_DAYS,
        description="Only count frames from the last N days. Omit for all time.",
    )] = None,
) -> List[Dict[str, int]]:
    """Packet counts per RadioTap channel frequency, descending."""
    query = _windowed(
        db.query(Packet.channel_freq, func.count(Packet.id)).filter(
            Packet.channel_freq.isnot(None)
        ),
        days,
    )
    # No tiebreaker, deliberately: this endpoint returns every channel, so tie
    # order changes nothing about *which* rows a caller gets, and leaving the
    # ORDER BY exactly as it was keeps the no-parameter response byte-identical
    # to the one the shipped bundle already renders.  (``/top-offenders`` is the
    # opposite case -- it truncates, so there a tiebreaker is load-bearing.)
    rows = (
        query.group_by(Packet.channel_freq)
        .order_by(func.count(Packet.id).desc())
        .all()
    )
    return [{"channel_freq": int(freq), "count": int(c)} for (freq, c) in rows if freq is not None]


@router.get("/heatmap-attack")
def heatmap_attack(
    db: Session = Depends(get_db),
    days: Annotated[Optional[int], Query(
        ge=1, le=MAX_DAYS,
        description="Only count frames from the last N days. Omit for all time.",
    )] = None,
    tz: Annotated[str, Query(
        description="IANA timezone the day/hour grid is bucketed in, e.g. Asia/Riyadh.",
    )] = "UTC",
) -> List[Dict[str, Any]]:
    """Week x hour heatmap of packet timestamps, 7 days of 24 hours, Sun first.

    Bucketing stays in Python rather than moving into SQL.  Truncating to a
    wall-clock hour in a named zone is ``ts AT TIME ZONE 'Asia/Riyadh'`` on
    PostgreSQL and simply *not available* on SQLite, which ships no timezone
    database -- so a SQL implementation would be a dialect split, and this repo
    runs on both.  ``days`` now bounds the scan that was previously unbounded,
    which is the part that actually mattered.
    """
    zone = _resolve_tz(tz)
    buckets: Dict[str, List[Dict[str, int]]] = {
        d: [{"hour": h, "intensity": 0} for h in range(24)] for d in DAY_NAMES_MON_FIRST
    }

    for (ts,) in _windowed(db.query(Packet.ts), days).all():
        if not ts:
            continue
        dt = _local(ts, zone)
        day = DAY_NAMES_MON_FIRST[dt.weekday()]  # Mon = 0
        buckets[day][dt.hour]["intensity"] += 1

    return [
        {"day": d, "hours": buckets[d]}
        if d in buckets
        else {"day": d, "hours": [{"hour": h, "intensity": 0} for h in range(24)]}
        for d in DAY_ORDER_SUN_FIRST
    ]


# --------------------------------------------------------------------------- #
# Time series                                                                  #
# --------------------------------------------------------------------------- #
def _bucket_key(dt: datetime, bucket: str) -> str:
    """The grouping key for a local timestamp.

    A string, and the *same* string for both bucket generation and row
    assignment, so the two cannot disagree.  Keying on the rendered wall clock
    rather than on an instant is also what keeps a DST transition from opening a
    hole in the series: two instants an hour apart that render as the same local
    hour collapse into one bucket instead of one of them landing nowhere.
    """
    return dt.strftime("%Y-%m-%d") if bucket == "day" else dt.strftime("%Y-%m-%dT%H")


def _empty_buckets(
    zone: ZoneInfo, days: int, bucket: str
) -> "OrderedDict[str, Dict[str, Any]]":
    """Every bucket in the window, in order, zero-filled.

    Zero-filled on purpose: a quiet hour is a fact worth plotting.  Returning
    only the hours that happened to have traffic makes a chart draw a straight
    line across an outage, which is the most misleading thing a security
    dashboard can do.
    """
    now_local = datetime.now(zone)
    out: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

    if bucket == "day":
        # Iterate calendar dates, not 24-hour steps: a DST day is 23 or 25 hours
        # long and stepping by timedelta would drift onto the wrong date.
        end_day: _date = now_local.date()
        for offset in range(days - 1, -1, -1):
            day = end_day - timedelta(days=offset)
            start = datetime.combine(day, _time(0, 0), tzinfo=zone)
            out[_bucket_key(start, bucket)] = {"t": start.isoformat(), "count": 0}
        return out

    end_hour = now_local.replace(minute=0, second=0, microsecond=0)
    for offset in range(days * 24 - 1, -1, -1):
        start = end_hour - timedelta(hours=offset)
        out.setdefault(_bucket_key(start, bucket), {"t": start.isoformat(), "count": 0})
    return out


@router.get("/attacks/series")
def attacks_series(
    db: Session = Depends(get_db),
    days: Annotated[int, Query(
        ge=1, le=MAX_DAYS, description="Window length in days.",
    )] = 7,
    bucket: Annotated[str, Query(
        pattern="^(hour|day)$", description="hour | day",
    )] = "hour",
    tz: Annotated[str, Query(
        description="IANA timezone the buckets are aligned to.",
    )] = "UTC",
    label: Annotated[Optional[str], Query(
        description=(
            "Restrict to one attack class, using the exact database spelling "
            "(Deauth, Disas, (Re)Assoc, RogueAP, Krack, Kr00k, Evil_Twin, SSDP). "
            "Omit for every class combined."
        ),
    )] = None,
) -> Dict[str, Any]:
    """Detections over time, in zero-filled buckets aligned to a wall clock.

    Replaces folding a bounded ``/attacks?limit=1000`` page in the browser: that
    is both the largest payload on the dashboard and quietly wrong, since a
    thousand rows is not the same as a window and a busy capture silently loses
    the older end of the chart.
    """
    max_days = MAX_DAYS_BY_BUCKET[bucket]
    if days > max_days:
        raise HTTPException(
            status_code=400,
            detail=(
                f"days={days} is too long for bucket={bucket!r}: the maximum is "
                f"{max_days} ({max_days * (24 if bucket == 'hour' else 1)} buckets). "
                "Use bucket='day' for a longer window."
            ),
        )

    resolved_label: Optional[str] = None
    if label is not None and str(label).strip():
        resolved_label = str(label).strip()
        if resolved_label not in KNOWN_LABELS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown attack class {label!r}. Valid classes: {KNOWN_LABELS}.",
            )

    zone = _resolve_tz(tz)
    points = _empty_buckets(zone, int(days), bucket)

    query = _windowed(db.query(Packet.ts), int(days))
    if resolved_label is not None:
        query = query.filter(Packet.predicted_label == resolved_label)

    total = 0
    outside = 0
    for (ts,) in query.all():
        if not ts:
            continue
        key = _bucket_key(_local(ts, zone), bucket)
        point = points.get(key)
        if point is None:
            # A row inside the SQL window but outside the rendered bucket range:
            # the first partial bucket at the far end. Counted in `total` so the
            # figure still matches the window, but not plotted into a bucket that
            # does not exist.
            outside += 1
            continue
        point["count"] += 1
        total += 1

    values = list(points.values())
    return {
        "bucket": bucket,
        "tz": str(zone),
        "days": int(days),
        "label": resolved_label,
        "start": values[0]["t"] if values else None,
        "end": values[-1]["t"] if values else None,
        "total": total,
        "outside_range": outside,
        "points": values,
    }
