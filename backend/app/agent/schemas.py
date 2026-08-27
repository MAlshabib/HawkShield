"""Argument models for Saqr's tools -- one pydantic model per tool.

There is exactly one schema per tool and it lives here.  ``tools.py`` feeds
``Model.model_json_schema()`` straight to the OpenRouter ``tools=`` payload and
validates the model's arguments with the same class, so the schema the model is
shown and the schema its call is checked against cannot drift apart.

Field descriptions are load-bearing: they are the only documentation the model
gets, so they say what a value means and what it is bounded by rather than
restating the field name.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AggregateThreatsArgs",
    "ExplainAttackClassArgs",
    "GroupBy",
    "LocateSourceArgs",
    "QueryThreatsArgs",
    "RunSimulationArgs",
    "RunSqlArgs",
    "SystemStatusArgs",
    "ThreatOverviewArgs",
]

#: ``aggregate_threats`` dimensions.  ``hour_of_day`` / ``day_of_week`` are
#: bucketed in Python, so there is no ``date_trunc`` / ``strftime`` split.
GroupBy = Literal[
    "label", "src_mac", "bssid", "channel_freq", "iface", "hour_of_day", "day_of_week", "none"
]


class _ToolArgs(BaseModel):
    """Base for every tool argument model.

    ``extra="forbid"`` matters: it becomes ``additionalProperties: false`` in the
    published JSON Schema, so a model that invents an argument is told about it
    instead of having it silently dropped.
    """

    model_config = ConfigDict(extra="forbid")


class _ThreatFilters(_ToolArgs):
    """Filters shared by ``query_threats`` and ``aggregate_threats``."""

    minutes: Optional[int] = Field(
        default=None,
        ge=1,
        le=525_600,
        description=(
            "Look back this many minutes from now. 60 = the last hour, 1440 = the "
            "last 24 hours, 10080 = the last week. Omit to search all stored data."
        ),
    )
    label: Optional[str] = Field(
        default=None,
        description=(
            "Restrict to one attack class. Use the exact database spelling: "
            "Deauth, Disas, (Re)Assoc, RogueAP, Krack, Kr00k, Evil_Twin, SSDP."
        ),
    )
    src_mac: Optional[str] = Field(
        default=None,
        description="Restrict to frames transmitted by this MAC (802.11 addr2), case-insensitive.",
    )
    bssid: Optional[str] = Field(
        default=None,
        description="Restrict to this BSS / access point (802.11 addr3), case-insensitive.",
    )
    dst_mac: Optional[str] = Field(
        default=None,
        description="Restrict to frames addressed to this MAC (802.11 addr1), case-insensitive.",
    )
    iface: Optional[str] = Field(
        default=None, description="Restrict to one capture interface, e.g. wlan1."
    )
    channel_freq: Optional[int] = Field(
        default=None,
        ge=1,
        le=100_000,
        description="Restrict to one RadioTap channel frequency in MHz (2412, 2437, 5180, ...).",
    )
    min_confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Keep only rows whose stage-2 confidence in the predicted class "
            "(proba_attack) is at least this. 0.9 = high confidence only."
        ),
    )


class QueryThreatsArgs(_ThreatFilters):
    """Arguments for ``query_threats``: individual detections."""

    order: Literal["newest", "oldest", "confidence"] = Field(
        default="newest",
        description=(
            "Row order. 'newest'/'oldest' sort by ts; 'confidence' sorts by "
            "proba_attack descending (most certain detections first)."
        ),
    )
    limit: int = Field(
        default=25, ge=1, le=200, description="Maximum rows to return. Hard ceiling 200."
    )


class AggregateThreatsArgs(_ThreatFilters):
    """Arguments for ``aggregate_threats``: counts grouped by one dimension."""

    group_by: GroupBy = Field(
        default="label",
        description=(
            "The dimension to count by. 'label' = per attack class; 'src_mac' = top "
            "offenders; 'bssid' = per access point; 'channel_freq' = channel usage; "
            "'iface' = per capture interface; 'hour_of_day' = 0-23 UTC; "
            "'day_of_week' = Sun..Sat; 'none' = one overall total."
        ),
    )
    top_n: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "Keep only the this-many largest groups, by count. Ignored for "
            "hour_of_day and day_of_week, which always return every bucket."
        ),
    )


class ThreatOverviewArgs(_ToolArgs):
    """Arguments for ``threat_overview``: the dashboard's headline figures."""

    days: int = Field(
        default=30,
        ge=1,
        le=3650,
        description="Reporting window in days, matching the dashboard's report period.",
    )


class ExplainAttackClassArgs(_ToolArgs):
    """Arguments for ``explain_attack_class``: the knowledge base, not the data."""

    attack_class: str = Field(
        description=(
            "The attack to explain. Accepts the database label (Deauth, Disas, "
            "(Re)Assoc, RogueAP, Krack, Kr00k, Evil_Twin, SSDP) or a plain-language "
            "name such as 'evil twin', 'key reinstallation', 'disassociation flood'."
        )
    )


class LocateSourceArgs(_ToolArgs):
    """Arguments for ``locate_source``: where a transmitter probably is."""

    src_mac: str = Field(
        description="The transmitter MAC (802.11 addr2) to locate, as it appears in src_mac."
    )
    minutes: int = Field(
        default=10,
        ge=1,
        le=10_080,
        description="Average signal strength over this many minutes back from now.",
    )


class SystemStatusArgs(_ToolArgs):
    """``system_status`` takes no arguments; the empty model keeps the schema honest."""


class RunSimulationArgs(_ToolArgs):
    """Arguments for ``run_simulation`` -- the one tool that writes to the database."""

    attacks: List[str] = Field(
        default_factory=lambda: ["all"],
        description=(
            "Attack classes to replay, by database label or dashboard key. Use "
            "['all'] for every class. Each name must be a real class."
        ),
    )
    count: int = Field(
        default=10,
        ge=1,
        le=50,
        description=(
            "Target number of persisted detections per class. Capped further by "
            "server configuration; the response reports what was actually written."
        ),
    )
    intensity: Literal["burst", "trickle"] = Field(
        default="burst",
        description="'burst' replays as fast as possible; 'trickle' paces it for a live demo.",
    )


class RunSqlArgs(_ToolArgs):
    """Arguments for ``run_sql`` -- the guarded escape hatch, usually disabled."""

    sql: str = Field(
        description=(
            "One read-only SELECT against the packets table. No semicolons, no "
            "second statement, no write keyword, no table other than packets. A "
            "LIMIT is appended automatically if you leave the query unbounded."
        )
    )
    reason: Optional[str] = Field(
        default=None,
        description="Why no structured tool could answer this. Shown to the operator.",
    )


def json_schema(model: type[BaseModel]) -> Dict[str, Any]:
    """The JSON Schema an OpenRouter ``tools=`` entry needs for ``model``.

    ``model_json_schema()`` emits ``$defs`` / ``$ref`` for nested models and
    ``anyOf`` with ``null`` for optionals; both are valid JSON Schema and are
    accepted as-is.  ``title`` keys are stripped because they add tokens to every
    request and tell the model nothing it does not already read in the name.
    """
    schema = model.model_json_schema()

    def strip_titles(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: strip_titles(v) for k, v in node.items() if k != "title"}
        if isinstance(node, list):
            return [strip_titles(v) for v in node]
        return node

    cleaned = strip_titles(schema)
    cleaned.setdefault("type", "object")
    cleaned.setdefault("properties", {})
    return cleaned
