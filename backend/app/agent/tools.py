"""Saqr's tool registry: eight tools, and the code behind each one.

Two rules shape this module.

**Tools call Python, never HTTP.**  HawkShield is one uvicorn process on a Pi 4.
A tool that issued an HTTP request back into the same app would occupy the only
worker while waiting for itself.  Every router handler here is already a plain
function taking a ``Session`` (``read_attack_analysis(db)``,
``compute_summary(db, days)``, ``_avg_rssi_rows(...)``, ``health(db)``), so the
tools call them directly and the answers are, by construction, the same numbers
the dashboard shows.

**Eight tools, no more.**  A cheap model degrades as the menu grows: it starts
picking plausible-looking wrong tools rather than composing the right one.  So
``aggregate_threats`` absorbs what would otherwise be four endpoints-turned-tools
(top offenders, channel usage, per-class counts, the hour/day heatmap) behind one
``group_by`` argument.

Every tool returns a plain JSON-safe dict with an ``ok`` flag.  A failure is a
result, not an exception: the loop feeds ``{"ok": false, "error": {...}}`` back to
the model so it can correct itself, which is far more useful than a 500.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from backend.app.agent import knowledge
from backend.app.agent.schemas import (
    AggregateThreatsArgs,
    ExplainAttackClassArgs,
    LocateSourceArgs,
    QueryThreatsArgs,
    RunSimulationArgs,
    RunSqlArgs,
    SystemStatusArgs,
    ThreatOverviewArgs,
    json_schema,
)
from backend.app.agent.sqlguard import (
    PACKETS_ONLY,
    apply_row_limit,
    assert_select_only,
    assert_tables_allowed,
    jsonable,
    normalise_packet_row,
    rows_to_dicts,
    run_select,
    sql_dialect,
)
from backend.app.config import ATTACK_CLASSES, SPEC_VERSION, front_key, settings
from backend.app.models import Packet

logger = logging.getLogger(__name__)

__all__ = [
    "ToolSpec",
    "ToolError",
    "build_registry",
    "compact",
    "summarise",
    "validate_args",
    "tool_definitions",
    "public_catalogue",
    "execute",
]

# Accumulation order is Mon-first (``datetime.weekday()``); the reported order is
# Sun-first, matching ``routers.attacks.heatmap_attack`` and the dashboard.
_DAY_NAMES_MON_FIRST = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_DAY_ORDER_SUN_FIRST = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

#: Columns ``query_threats`` returns.  ``raw`` is fetched but not returned whole:
#: it is attacker-influenced and mostly duplicates real columns, so only the two
#: fields with no column of their own (``ssid``, ``sim``) are lifted out of it.
_ROW_COLUMNS = (
    Packet.id,
    Packet.ts,
    Packet.predicted_label,
    Packet.proba_anomaly,
    Packet.proba_attack,
    Packet.src_mac,
    Packet.dst_mac,
    Packet.bssid,
    Packet.iface,
    Packet.channel_freq,
    Packet.signal_dbm,
    Packet.frame_len,
    Packet.wlan_type,
    Packet.wlan_subtype,
    Packet.raw,
)

_GROUP_COLUMNS = {
    "label": Packet.predicted_label,
    "src_mac": Packet.src_mac,
    "bssid": Packet.bssid,
    "channel_freq": Packet.channel_freq,
    "iface": Packet.iface,
}


class ToolError(Exception):
    """A tool refused its arguments.  Becomes ``{"ok": false, ...}`` for the model."""

    def __init__(self, message: str, *, kind: str = "bad_argument", hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.hint = hint

    def as_result(self, tool: str) -> Dict[str, Any]:
        error: Dict[str, Any] = {"type": self.kind, "message": str(self)}
        if self.hint:
            error["hint"] = self.hint
        return {"ok": False, "tool": tool, "error": error}


@dataclass(frozen=True)
class ToolSpec:
    """One entry in the registry."""

    name: str
    description: str
    arg_model: type[BaseModel]
    executor: Callable[..., Dict[str, Any]]
    #: The executor's second positional argument is a live ``Session``.
    needs_db: bool = False
    #: The tool writes to the database.  Exactly one tool sets this.
    mutating: bool = False
    #: Stable i18n key the frontend uses to label this tool, so the label table
    #: is generated from ``GET /agent/tools`` rather than hand-copied.
    label_key: str = ""
    #: Tags surfaced to the UI; not sent to the model.
    tags: Sequence[str] = field(default_factory=tuple)


# --------------------------------------------------------------------------- #
# Shared helpers                                                               #
# --------------------------------------------------------------------------- #
def _sql_preview(stmt: Select, db: Optional[Session] = None) -> str:
    """The statement as a human would write it, with values inlined.

    The point is that a structured tool can show the operator the *real* SELECT
    it ran, so an answer is checkable rather than merely plausible.  Literal
    binding is dialect-specific and can refuse (a ``DateTime`` has no literal
    form on the generic dialect), so a failure degrades to the parameterised
    form rather than losing the preview.
    """
    try:
        bind = db.get_bind() if db is not None else None
        compiled = (
            stmt.compile(bind, compile_kwargs={"literal_binds": True})
            if bind is not None
            else stmt.compile(compile_kwargs={"literal_binds": True})
        )
        return " ".join(str(compiled).split())
    except Exception as exc:  # noqa: BLE001 - a preview must never break a tool
        logger.debug("Could not render a literal SQL preview: %s", exc)
        return " ".join(str(stmt).split())


def _resolve_label(label: Optional[str]) -> Optional[str]:
    """Map any spelling of an attack class onto its database label."""
    if label is None or not str(label).strip():
        return None
    resolved = knowledge.normalise_class(label)
    if resolved is None:
        raise ToolError(
            f"Unknown attack class {label!r}.",
            kind="unknown_class",
            hint="Valid classes: " + ", ".join(ATTACK_CLASSES),
        )
    return resolved


def _since(minutes: Optional[int]) -> Optional[datetime]:
    """Lower time bound as a naive UTC datetime.

    ``packets.ts`` is a naive ``DateTime`` column written from
    ``datetime.now(timezone.utc)``, so comparisons must be naive-UTC or SQLite
    compares strings with different shapes.
    """
    if not minutes:
        return None
    return (datetime.now(timezone.utc) - timedelta(minutes=int(minutes))).replace(tzinfo=None)


def _filtered(stmt: Select, args: Any) -> Select:
    """Apply the filter block shared by ``query_threats`` and ``aggregate_threats``."""
    lower_bound = _since(getattr(args, "minutes", None))
    if lower_bound is not None:
        stmt = stmt.where(Packet.ts >= lower_bound)

    label = _resolve_label(getattr(args, "label", None))
    if label is not None:
        stmt = stmt.where(Packet.predicted_label == label)

    for attr, column in (
        ("src_mac", Packet.src_mac),
        ("dst_mac", Packet.dst_mac),
        ("bssid", Packet.bssid),
    ):
        value = getattr(args, attr, None)
        if value:
            stmt = stmt.where(func.lower(column) == str(value).strip().lower())

    iface = getattr(args, "iface", None)
    if iface:
        stmt = stmt.where(Packet.iface == str(iface).strip())

    channel = getattr(args, "channel_freq", None)
    if channel:
        stmt = stmt.where(Packet.channel_freq == int(channel))

    min_confidence = getattr(args, "min_confidence", None)
    if min_confidence is not None:
        stmt = stmt.where(Packet.proba_attack >= float(min_confidence))

    return stmt


def _applied_filters(args: Any) -> Dict[str, Any]:
    """Echo the filters actually in force, so the model can quote them back."""
    out: Dict[str, Any] = {}
    for attr in ("minutes", "label", "src_mac", "dst_mac", "bssid", "iface",
                 "channel_freq", "min_confidence"):
        value = getattr(args, attr, None)
        if value not in (None, ""):
            out[attr] = value
    if "label" in out:
        out["label"] = _resolve_label(out["label"])
    return out


# --------------------------------------------------------------------------- #
# 1. query_threats                                                             #
# --------------------------------------------------------------------------- #
def query_threats(args: QueryThreatsArgs, db: Session) -> Dict[str, Any]:
    """Individual detections matching a filter, newest first by default."""
    stmt = _filtered(select(*_ROW_COLUMNS), args)

    if args.order == "oldest":
        stmt = stmt.order_by(Packet.ts.asc(), Packet.id.asc())
    elif args.order == "confidence":
        stmt = stmt.order_by(Packet.proba_attack.desc().nullslast(), Packet.id.desc())
    else:
        stmt = stmt.order_by(Packet.ts.desc(), Packet.id.desc())
    stmt = stmt.limit(int(args.limit))

    rows: List[Dict[str, Any]] = []
    for record in db.execute(stmt).mappings().all():
        row = normalise_packet_row(dict(record))
        raw = row.pop("raw", None)
        if isinstance(raw, dict):
            if raw.get("ssid") is not None:
                row["ssid"] = raw.get("ssid")
            if raw.get("sim"):
                row["sim"] = True
        rows.append({k: jsonable(v) for k, v in row.items()})

    return {
        "ok": True,
        "row_count": len(rows),
        "truncated": len(rows) >= int(args.limit),
        "filters": _applied_filters(args),
        "order": args.order,
        "rows": rows,
        "sql_preview": _sql_preview(stmt, db),
    }


# --------------------------------------------------------------------------- #
# 2. aggregate_threats                                                         #
# --------------------------------------------------------------------------- #
def _time_buckets(args: AggregateThreatsArgs, db: Session) -> Dict[str, Any]:
    """Hour-of-day / day-of-week counts, bucketed in Python.

    Deliberately not SQL: ``EXTRACT(HOUR FROM ts)`` and ``strftime('%H', ts)``
    are the same idea in two incompatible dialects, and HawkShield runs on both.
    ``routers.attacks.heatmap_attack`` buckets in Python for exactly this reason
    and this reproduces its arithmetic, so the two never disagree.
    """
    stmt = _filtered(select(Packet.ts), args)
    hours = [0] * 24
    days: Dict[str, int] = {d: 0 for d in _DAY_NAMES_MON_FIRST}
    total = 0

    for (ts,) in db.execute(stmt).all():
        if not ts:
            continue
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        hours[dt.hour] += 1
        days[_DAY_NAMES_MON_FIRST[dt.weekday()]] += 1
        total += 1

    if args.group_by == "hour_of_day":
        groups = [{"key": h, "count": hours[h]} for h in range(24)]
        note = "hour_of_day is 0-23 in UTC, every bucket present."
    else:
        groups = [{"key": d, "count": days[d]} for d in _DAY_ORDER_SUN_FIRST]
        note = "day_of_week is Sun-first in UTC, every bucket present."

    return {
        "ok": True,
        "group_by": args.group_by,
        "total": total,
        "group_count": len(groups),
        "groups": groups,
        "filters": _applied_filters(args),
        "note": note,
        "sql_preview": _sql_preview(stmt, db),
    }


def aggregate_threats(args: AggregateThreatsArgs, db: Session) -> Dict[str, Any]:
    """Counts grouped by one dimension: classes, offenders, APs, channels, time."""
    if args.group_by in ("hour_of_day", "day_of_week"):
        return _time_buckets(args, db)

    if args.group_by == "none":
        stmt = _filtered(select(func.count(Packet.id).label("count")), args)
        total = int(db.execute(stmt).scalar() or 0)
        return {
            "ok": True,
            "group_by": "none",
            "total": total,
            "group_count": 1,
            "groups": [{"key": "all", "count": total}],
            "filters": _applied_filters(args),
            "sql_preview": _sql_preview(stmt, db),
        }

    column = _GROUP_COLUMNS[args.group_by]
    stmt = _filtered(
        select(column.label("key"), func.count(Packet.id).label("count")), args
    )
    stmt = (
        stmt.group_by(column)
        .order_by(func.count(Packet.id).desc())
        .limit(int(args.top_n))
    )
    rows = db.execute(stmt).all()
    groups = [{"key": jsonable(key), "count": int(count)} for key, count in rows]

    result: Dict[str, Any] = {
        "ok": True,
        "group_by": args.group_by,
        "total": sum(g["count"] for g in groups),
        "group_count": len(groups),
        "truncated": len(groups) >= int(args.top_n),
        "groups": groups,
        "filters": _applied_filters(args),
        "sql_preview": _sql_preview(stmt, db),
    }
    if args.group_by == "label":
        missing = [c for c in ATTACK_CLASSES if c not in {g["key"] for g in groups}]
        if missing:
            result["classes_with_no_detections"] = missing
        result["note"] = (
            "total is the number of stored attack frames matching the filter. "
            "Benign traffic is never stored, so this is not a share of all traffic."
        )
    return result


# --------------------------------------------------------------------------- #
# 3. threat_overview                                                           #
# --------------------------------------------------------------------------- #
def threat_overview(args: ThreatOverviewArgs, db: Session) -> Dict[str, Any]:
    """The dashboard's headline figures, from the same functions the dashboard calls."""
    from backend.app.routers.attacks import read_attack_analysis
    from backend.app.routers.reports import compute_summary

    summary = compute_summary(db, days=int(args.days)).model_dump()
    by_class = read_attack_analysis(db)
    total_stored = int(db.execute(select(func.count(Packet.id))).scalar() or 0)
    latest_ts = db.execute(select(func.max(Packet.ts))).scalar()
    earliest_ts = db.execute(select(func.min(Packet.ts))).scalar()

    return {
        "ok": True,
        "window_days": int(args.days),
        "period": summary["period"],
        # Keyed by dashboard key (deauth, evil_twin, ...) plus an "other" bucket.
        "totals_by_dashboard_key": summary["totals"],
        # Keyed by database label (Deauth, Evil_Twin, ...), all eight, zero-filled,
        # and NOT limited to the window -- this is the all-time class breakdown.
        "all_time_by_class": by_class,
        "headline": summary["summary"],
        "packets_stored_all_time": total_stored,
        "earliest_ts": jsonable(earliest_ts),
        "latest_ts": jsonable(latest_ts),
        "note": (
            "totals_by_dashboard_key covers the last "
            f"{int(args.days)} day(s); all_time_by_class covers every stored row. "
            "peakHour is a UTC hour. Only attack frames are stored."
        ),
    }


# --------------------------------------------------------------------------- #
# 4. explain_attack_class                                                      #
# --------------------------------------------------------------------------- #
def explain_attack_class(args: ExplainAttackClassArgs) -> Dict[str, Any]:
    """The knowledge-base section for one attack class.  No database access."""
    resolved = knowledge.normalise_class(args.attack_class)
    if resolved is None:
        raise ToolError(
            f"{args.attack_class!r} is not one of the attack classes HawkShield detects.",
            kind="unknown_class",
            hint="Valid classes: " + ", ".join(ATTACK_CLASSES),
        )
    section = knowledge.section_for(resolved)
    if not section:
        raise ToolError(
            f"The knowledge base has no section for {resolved!r}.",
            kind="not_documented",
            hint="Documented classes: " + ", ".join(knowledge.covered_classes()),
        )
    return {
        "ok": True,
        "attack_class": resolved,
        "dashboard_key": front_key(resolved),
        "source": "HawkShield attack knowledge base",
        "content": section,
        "note": "Answer conceptual questions only from this content.",
    }


# --------------------------------------------------------------------------- #
# 5. locate_source                                                             #
# --------------------------------------------------------------------------- #
def locate_source(args: LocateSourceArgs, db: Session) -> Dict[str, Any]:
    """Weighted-centroid position estimate for one transmitter.

    Same inputs and same arithmetic as ``POST /map/estimate-origin``: average
    RSSI per BSSID over the window, weighted by ``1 / (|rssi| + 1)`` against the
    configured AP coordinates.
    """
    from backend.app.routers.maps import _avg_rssi_rows, _load_ap_locations

    sa = str(args.src_mac or "").strip()
    if not sa:
        raise ToolError("src_mac is required.", kind="bad_argument")

    rows = _avg_rssi_rows(db, sa, int(args.minutes))
    points = [
        {"bssid": str(r.bssid), "avg_rssi": float(r.avg_rssi or -90.0), "frames": int(r.n or 0)}
        for r in rows
        if r.bssid
    ]
    rssi_by_bssid = {p["bssid"]: p["avg_rssi"] for p in points}
    aps = _load_ap_locations()

    used: List[Dict[str, float]] = []
    for ap in aps:
        bssid = str(ap.get("bssid") or "")
        if not bssid or bssid not in rssi_by_bssid:
            continue
        rssi = rssi_by_bssid[bssid]
        used.append(
            {
                "bssid": bssid,
                "name": ap.get("name", ""),
                "lat": float(ap["lat"]),
                "lng": float(ap["lng"]),
                "avg_rssi": rssi,
                "weight": 1.0 / max(1.0, abs(rssi) + 1.0),
            }
        )

    base: Dict[str, Any] = {
        "ok": True,
        "src_mac": sa,
        "minutes": int(args.minutes),
        "method": "weighted-centroid",
        "rssi_points": points,
        "aps_configured": len(aps),
        "aps_used": len(used),
        "used": used,
    }
    if not used:
        base["center"] = None
        base["note"] = (
            "No AP in AP_LOCATIONS_FILE matches a BSSID this source was heard on in "
            "the window, so no position can be estimated. Report that, do not guess."
            if points
            else "This source transmitted no frames in the window."
        )
        return base

    total_weight = sum(u["weight"] for u in used)
    base["center"] = {
        "lat": sum(u["lat"] * u["weight"] for u in used) / total_weight,
        "lng": sum(u["lng"] * u["weight"] for u in used) / total_weight,
    }
    base["note"] = (
        "A coarse RSSI-weighted centroid of the APs that heard this source, not a "
        "survey-grade fix. Accuracy degrades sharply with fewer than three APs."
    )
    return base


# --------------------------------------------------------------------------- #
# 6. system_status                                                             #
# --------------------------------------------------------------------------- #
def system_status(args: SystemStatusArgs, db: Session) -> Dict[str, Any]:
    """Health, model selection and Saqr's own configuration.

    Exists so that "why can't you answer that?" is a question the agent can
    answer about itself: which tools are switched off, whether the knowledge base
    covers every class, which model is deployed, whether the database is up.
    """
    from backend.app.routers.health import health

    # jsonable() up front, not per field: HealthOut carries a datetime, and this
    # dict is about to become the JSON body of a ``role: "tool"`` message.
    report = jsonable(health(db).model_dump())
    registry = build_registry()

    return {
        "ok": True,
        "health": report,
        "detector": {
            "model_version": report.get("model_version"),
            "spec_version": SPEC_VERSION,
            "artefact_spec_version": report.get("artefact_spec_version"),
            "model_problems": report.get("model_problems") or [],
            "attack_classes": list(ATTACK_CLASSES),
        },
        "database": {
            "dialect": sql_dialect(),
            "reachable": report.get("database"),
            "packets_stored": report.get("packets"),
            "latest_packet_ts": report.get("latest_packet_ts"),
        },
        "saqr": {
            "enabled": bool(settings.SAQR_ENABLED),
            "model": settings.saqr_model,
            "default_locale": settings.SAQR_DEFAULT_LOCALE,
            "max_steps": settings.SAQR_MAX_STEPS,
            "max_tool_calls": settings.SAQR_MAX_TOOL_CALLS,
            "tools_available": list(registry),
            "raw_sql_enabled": bool(settings.SAQR_ALLOW_RAW_SQL),
            "simulation_tool_enabled": bool(
                settings.SAQR_ALLOW_SIMULATION_TOOL and settings.ALLOW_SIMULATION
            ),
        },
        "knowledge_base": {
            "documented_classes": knowledge.covered_classes(),
            "undocumented_classes": knowledge.missing_classes(),
        },
    }


# --------------------------------------------------------------------------- #
# 7. run_simulation — the only mutating tool                                   #
# --------------------------------------------------------------------------- #
def run_simulation(args: RunSimulationArgs, db: Session) -> Dict[str, Any]:
    """Replay held-out AWID3 frames through the live model and persist detections.

    This writes rows.  It is not a mock: the frames are real, the pipeline is the
    one the detector runs, and the per-class result reports what the model
    actually did rather than what was requested.  Every row is tagged
    ``raw.sim = true``.
    """
    from fastapi import HTTPException

    from backend.app.routers.simulate import simulate as run_simulate
    from backend.app.schemas import SimulatePayload

    if not settings.ALLOW_SIMULATION:
        raise ToolError(
            "Simulation is disabled on this host (ALLOW_SIMULATION=0).",
            kind="disabled",
        )

    requested = int(args.count)
    cap = min(int(settings.SAQR_SIM_TOOL_MAX_COUNT), int(settings.SIM_MAX_COUNT))
    count = max(1, min(requested, cap))

    attacks: Any = [str(a) for a in (args.attacks or ["all"])]
    if len(attacks) == 1 and attacks[0].strip().lower() == "all":
        attacks = "all"

    payload = SimulatePayload(attacks=attacks, count=count, intensity=args.intensity)
    try:
        response = run_simulate(payload, db)
    except HTTPException as exc:
        raise ToolError(
            f"The simulator refused the request: {exc.detail}",
            kind="simulation_refused",
        ) from exc

    result = response.model_dump()
    result["ok"] = True
    result["requested_count"] = requested
    if count != requested:
        result["capped_note"] = (
            f"count was capped from {requested} to {count} by server configuration."
        )
    result["note"] = (
        "These are real model detections replayed from held-out data and now "
        "stored in packets, tagged raw.sim = true. per_class reports the labels "
        "the model actually assigned, which need not match the classes requested."
    )
    return result


# --------------------------------------------------------------------------- #
# 8. run_sql — guarded escape hatch, usually disabled                          #
# --------------------------------------------------------------------------- #
def run_sql(args: RunSqlArgs, db: Session) -> Dict[str, Any]:
    """One model-authored read-only SELECT over ``packets``, behind every guard."""
    try:
        statement = assert_select_only(args.sql)
        assert_tables_allowed(statement, PACKETS_ONLY)
        statement = apply_row_limit(statement, int(settings.SAQR_MAX_ROWS))
    except ValueError as exc:
        raise ToolError(
            str(exc),
            kind="rejected_sql",
            hint=(
                "Write one read-only SELECT over the packets table only. Prefer "
                "query_threats or aggregate_threats, which need no SQL at all."
            ),
        ) from exc

    logger.info("Saqr run_sql (%s): %s", sql_dialect(), statement.replace("\n", " "))
    try:
        cols, rows = run_select(statement, db=db)
    except Exception as exc:  # noqa: BLE001 - a DB error is a result, not a crash
        raise ToolError(
            f"The database rejected the query: {exc}",
            kind="sql_error",
            hint="Check the column names against the schema in your instructions.",
        ) from exc

    limit = int(settings.SAQR_MAX_ROWS)
    return {
        "ok": True,
        "sql_preview": " ".join(statement.split()),
        "columns": list(cols),
        "row_count": len(rows),
        "truncated": len(rows) >= limit,
        "rows": rows_to_dicts(cols, rows),
        "reason": args.reason,
    }


# --------------------------------------------------------------------------- #
# The registry                                                                 #
# --------------------------------------------------------------------------- #
_ALL_TOOLS: List[ToolSpec] = [
    ToolSpec(
        name="query_threats",
        description=(
            "List individual detected attack frames, with filters for time window, "
            "attack class, MAC address, BSSID, interface, channel and minimum "
            "confidence. Use this when the user wants to see specific detections "
            "(latest, most confident, from one device). Returns at most 200 rows."
        ),
        arg_model=QueryThreatsArgs,
        executor=query_threats,
        needs_db=True,
        label_key="saqr.tool.query_threats",
        tags=("read", "packets"),
    ),
    ToolSpec(
        name="aggregate_threats",
        description=(
            "Count detected attack frames grouped by one dimension: attack class, "
            "source MAC (top offenders), BSSID, channel frequency, capture "
            "interface, hour of day, day of week, or no grouping at all (one "
            "total). Takes the same filters as query_threats. Use this for 'how "
            "many', 'which is most common', 'who is the worst offender', 'which "
            "channel', 'when does it happen'."
        ),
        arg_model=AggregateThreatsArgs,
        executor=aggregate_threats,
        needs_db=True,
        label_key="saqr.tool.aggregate_threats",
        tags=("read", "packets"),
    ),
    ToolSpec(
        name="threat_overview",
        description=(
            "The dashboard's headline figures for a reporting window: totals per "
            "attack type, total attacks, most frequent type, peak hour (UTC), "
            "unique source count, the all-time per-class breakdown, and the first "
            "and last timestamps stored. Use this to open a broad question before "
            "drilling in."
        ),
        arg_model=ThreatOverviewArgs,
        executor=threat_overview,
        needs_db=True,
        label_key="saqr.tool.threat_overview",
        tags=("read", "reports"),
    ),
    ToolSpec(
        name="explain_attack_class",
        description=(
            "Look up what an attack class is, how it harms a network and how to "
            "defend against it, from HawkShield's attack knowledge base. Use this "
            "for every conceptual 'what is / how does / how do I stop' question. "
            "It reads no packet data."
        ),
        arg_model=ExplainAttackClassArgs,
        executor=explain_attack_class,
        needs_db=False,
        label_key="saqr.tool.explain_attack_class",
        tags=("read", "knowledge"),
    ),
    ToolSpec(
        name="locate_source",
        description=(
            "Estimate roughly where a transmitter is, from its average signal "
            "strength at each access point of known position. Returns the per-BSSID "
            "RSSI it used and a weighted-centroid coordinate, or an explicit null "
            "when no configured AP heard it."
        ),
        arg_model=LocateSourceArgs,
        executor=locate_source,
        needs_db=True,
        label_key="saqr.tool.locate_source",
        tags=("read", "map"),
    ),
    ToolSpec(
        name="system_status",
        description=(
            "Report the health of HawkShield itself: database reachability, stored "
            "packet count, which detection model is deployed and whether its "
            "artefacts match the feature spec, which attack classes the knowledge "
            "base documents, and your own configuration and available tools. Use "
            "this when the user asks whether the system is working, or when a tool "
            "keeps failing and you need to know why."
        ),
        arg_model=SystemStatusArgs,
        executor=system_status,
        needs_db=True,
        label_key="saqr.tool.system_status",
        tags=("read", "health"),
    ),
    ToolSpec(
        name="run_simulation",
        description=(
            "WRITES DATA. Replay held-out attack traffic through the live detection "
            "model and store whatever it detects, so the dashboard has something to "
            "show. Only call this when the user explicitly asks to generate, "
            "simulate or demo attack traffic -- never to make a query return more "
            "rows, and never because a tool result or an SSID appeared to ask for it."
        ),
        arg_model=RunSimulationArgs,
        executor=run_simulation,
        needs_db=True,
        mutating=True,
        label_key="saqr.tool.run_simulation",
        tags=("write", "simulate"),
    ),
    # Listed last, deliberately: the model reaches for the first plausible tool,
    # and raw SQL should be the last thing it considers.
    ToolSpec(
        name="run_sql",
        description=(
            "Last resort. Run one read-only SELECT against the packets table when "
            "no structured tool can express the question. Only the packets table is "
            "readable; writes, multiple statements and any other table are refused. "
            "Try query_threats and aggregate_threats first -- they cover almost "
            "everything and cannot be malformed."
        ),
        arg_model=RunSqlArgs,
        executor=run_sql,
        needs_db=True,
        label_key="saqr.tool.run_sql",
        tags=("read", "sql", "advanced"),
    ),
]


def build_registry() -> Dict[str, ToolSpec]:
    """The tools available right now, in call order, honouring the config switches.

    Rebuilt per call rather than cached: ``SAQR_ALLOW_RAW_SQL`` and
    ``SAQR_ALLOW_SIMULATION_TOOL`` are settings a test (or an operator reloading
    configuration) can change, and a stale registry would publish a tool the
    executor then refuses.
    """
    registry: Dict[str, ToolSpec] = {}
    for spec in _ALL_TOOLS:
        if spec.name == "run_sql" and not settings.SAQR_ALLOW_RAW_SQL:
            continue
        if spec.name == "run_simulation" and not (
            settings.SAQR_ALLOW_SIMULATION_TOOL and settings.ALLOW_SIMULATION
        ):
            continue
        registry[spec.name] = spec
    return registry


def tool_definitions(registry: Optional[Dict[str, ToolSpec]] = None) -> List[Dict[str, Any]]:
    """The ``tools=`` payload for the OpenRouter chat-completions call."""
    specs = registry if registry is not None else build_registry()
    return [
        {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description,
                "parameters": json_schema(spec.arg_model),
            },
        }
        for spec in specs.values()
    ]


def public_catalogue(registry: Optional[Dict[str, ToolSpec]] = None) -> List[Dict[str, Any]]:
    """What ``GET /agent/tools`` publishes, so the UI generates its own labels."""
    specs = registry if registry is not None else build_registry()
    return [
        {
            "name": spec.name,
            "label_key": spec.label_key,
            "description": spec.description,
            "mutating": spec.mutating,
            "tags": list(spec.tags),
            "args_schema": json_schema(spec.arg_model),
        }
        for spec in specs.values()
    ]


def validate_args(
    name: str,
    raw_args: Dict[str, Any],
    registry: Optional[Dict[str, ToolSpec]] = None,
) -> Tuple[Optional[BaseModel], Optional[Dict[str, Any]]]:
    """Check one tool call's arguments.  Returns ``(model, None)`` or ``(None, error)``.

    Split out of :func:`execute` so the streaming loop can publish the
    **validated** arguments in its ``tool_call`` event.  Echoing the model's raw
    arguments there would let a hallucinated field ("severity", "region") render
    in the UI as though the tool had accepted it.
    """
    specs = registry if registry is not None else build_registry()
    spec = specs.get(name)
    if spec is None:
        return None, {
            "type": "unknown_tool",
            "message": f"There is no tool called {name!r}.",
            "hint": "Available tools: " + ", ".join(specs),
        }
    try:
        return spec.arg_model.model_validate(raw_args or {}), None
    except Exception as exc:  # noqa: BLE001 - pydantic's own error is the message
        return None, {
            "type": "invalid_arguments",
            "message": f"Arguments rejected: {exc}",
            "hint": "Correct the arguments against the tool's schema and retry once.",
        }


# --------------------------------------------------------------------------- #
# Presentation: what a tool result looks like on the event stream              #
# --------------------------------------------------------------------------- #
#: Fields the ``tool_result`` event carries in its own right, so ``data`` does
#: not repeat them, and fields that are pure bookkeeping for the model.
_DATA_DROP = frozenset({
    "ok", "tool", "sql_preview", "row_count", "truncated", "error",
    "note", "repeat_note", "capped_note",
})

#: List fields inside a tool result that can be long enough to matter.
_DATA_LIST_FIELDS = ("rows", "groups", "rssi_points", "used", "classes")

#: Hard ceiling on the serialised ``data`` blob of one ``tool_result`` event.
#: A UI showing a preview does not need 500 rows, and an SSE frame that large
#: stalls the pane it is meant to animate.
_MAX_DATA_CHARS = 8000


def summarise(name: str, result: Dict[str, Any]) -> str:
    """One line describing a tool result, for the UI's timeline.

    Written here rather than in the loop because the shape of each result is
    this module's knowledge.  English only and deliberately terse: it is a
    debugging affordance beside the answer, not part of the answer.
    """
    if not result.get("ok", True):
        error = result.get("error") or {}
        return str(error.get("message") or "failed")

    if name in ("query_threats", "run_sql"):
        count = result.get("row_count", 0)
        return f"{count} row(s)"
    if name == "aggregate_threats":
        group_by = result.get("group_by", "?")
        return (
            f"{result.get('total', 0)} detection(s) across "
            f"{result.get('group_count', 0)} group(s) by {group_by}"
        )
    if name == "threat_overview":
        headline = result.get("headline") or {}
        return (
            f"{headline.get('totalAttacks', 0)} attack(s) in "
            f"{result.get('period', 'the window')}; most frequent "
            f"{headline.get('mostFrequentType', 'n/a')}"
        )
    if name == "explain_attack_class":
        return f"knowledge-base section for {result.get('attack_class', '?')}"
    if name == "locate_source":
        if result.get("center"):
            return f"position estimated from {result.get('aps_used', 0)} access point(s)"
        return f"no position: {result.get('aps_used', 0)} of {result.get('aps_configured', 0)} AP(s) matched"
    if name == "system_status":
        database = result.get("database") or {}
        detector = result.get("detector") or {}
        state = "reachable" if database.get("reachable") else "unreachable"
        return (
            f"database {state}, {database.get('packets_stored', 0)} packet(s), "
            f"model {detector.get('model_version', 'unknown')}"
        )
    if name == "run_simulation":
        return (
            f"{result.get('total_persisted', 0)} detection(s) persisted across "
            f"{len(result.get('classes') or [])} class(es)"
        )
    return "ok"


def compact(name: str, result: Dict[str, Any], max_rows: Optional[int] = None) -> Dict[str, Any]:
    """The part of a tool result worth putting on the wire for a UI preview.

    Trims the long lists, caps the knowledge-base text (the model's answer will
    quote what matters), and drops what the event already carries in its own
    fields.  If the outcome is still too big it is replaced by an explicit
    marker rather than silently truncated mid-structure -- a client parsing
    half a JSON object is worse than a client told there was too much.
    """
    limit = int(max_rows if max_rows is not None else settings.SAQR_UI_ROWS)
    data: Dict[str, Any] = {}
    for key, value in result.items():
        if key in _DATA_DROP:
            continue
        if key in _DATA_LIST_FIELDS and isinstance(value, list):
            data[key] = value[:limit]
            continue
        if key == "content" and isinstance(value, str):
            data[key] = value[:600] + ("..." if len(value) > 600 else "")
            continue
        data[key] = value

    try:
        if len(json.dumps(data, ensure_ascii=False, default=str)) > _MAX_DATA_CHARS:
            return {
                "omitted": True,
                "reason": "result too large for the event stream; see the answer text",
            }
    except (TypeError, ValueError):  # pragma: no cover - jsonable() ran first
        return {"omitted": True, "reason": "result is not serialisable"}
    return data


def execute(
    name: str,
    raw_args: Dict[str, Any],
    db: Optional[Session] = None,
    registry: Optional[Dict[str, ToolSpec]] = None,
) -> Dict[str, Any]:
    """Validate and run one tool call.  Never raises for a caller's mistake.

    A bad tool name, arguments that fail validation, and a tool that refuses its
    input all come back as ``{"ok": false, "error": {...}}`` so the loop can hand
    them to the model and let it correct itself.
    """
    specs = registry if registry is not None else build_registry()
    args, arg_error = validate_args(name, raw_args, specs)
    if arg_error is not None:
        return {"ok": False, "tool": name, "error": arg_error}
    spec = specs[name]

    if spec.needs_db and db is None:
        return {
            "ok": False,
            "tool": name,
            "error": {
                "type": "no_database",
                "message": f"{name} needs a database session and none is available.",
            },
        }

    try:
        result = spec.executor(args, db) if spec.needs_db else spec.executor(args)
    except ToolError as exc:
        logger.info("Tool %s refused its input: %s", name, exc)
        return exc.as_result(name)
    except Exception as exc:  # noqa: BLE001 - a tool failure must not kill the run
        logger.exception("Tool %s failed", name)
        return {
            "ok": False,
            "tool": name,
            "error": {"type": "tool_failed", "message": f"{type(exc).__name__}: {exc}"},
        }

    result.setdefault("ok", True)
    result.setdefault("tool", name)
    return result
