"""Tests for backend.app.agent.tools.

They run entirely against a temporary SQLite database, so no PostgreSQL, no
network and no OPENROUTER_API_KEY are needed.  Nothing here calls a model: the
tools are plain functions over a ``Session``, which is the whole point of the
"tools call Python, never HTTP" decision.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.agent import knowledge, tools  # noqa: E402
from backend.app.agent.schemas import (  # noqa: E402
    AggregateThreatsArgs,
    ExplainAttackClassArgs,
    LocateSourceArgs,
    QueryThreatsArgs,
    SystemStatusArgs,
    ThreatOverviewArgs,
)
from backend.app.config import ATTACK_CLASSES, settings  # noqa: E402
from backend.app.db import Base  # noqa: E402
from backend.app.models import Packet  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    db_path: Path = tmp_path_factory.mktemp("saqr") / "tools.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def seeded(engine) -> None:
    """A small, deterministic set of attack rows across classes and sources."""
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows: List[Packet] = []

    # Four Deauth frames from one loud offender, all inside the last hour.
    for i in range(4):
        rows.append(
            Packet(
                ts=now - timedelta(minutes=5 * (i + 1)),
                iface="wlan1",
                src_mac="AA:BB:CC:DD:EE:01",
                dst_mac="FF:FF:FF:FF:FF:FF",
                bssid="AA:AA:AA:AA:AA:01",
                frame_len=128,
                channel_freq=2437,
                signal_dbm=-42.0 - i,
                wlan_type=0,
                wlan_subtype=12,
                proba_anomaly=0.95,
                proba_attack=0.91,
                predicted_label="Deauth",
                raw={"iface": "wlan1", "ssid": "HawkNet", "sa": "AA:BB:CC:DD:EE:01"},
            )
        )
    # Two Kr00k frames from a second source, older than the last hour.
    for i in range(2):
        rows.append(
            Packet(
                ts=now - timedelta(hours=5 + i),
                iface="wlan1",
                src_mac="AA:BB:CC:DD:EE:02",
                bssid="AA:AA:AA:AA:AA:02",
                frame_len=90,
                channel_freq=5180,
                signal_dbm=-70.0,
                wlan_type=2,
                proba_anomaly=0.8,
                proba_attack=0.55,
                predicted_label="Kr00k",
                raw={"iface": "wlan1"},
            )
        )
    # One simulated Disas row, so raw.sim surfaces the way the stream does it.
    rows.append(
        Packet(
            ts=now - timedelta(minutes=1),
            iface="sim0",
            src_mac="AA:BB:CC:DD:EE:03",
            bssid="AA:AA:AA:AA:AA:01",
            channel_freq=2437,
            signal_dbm=-55.0,
            proba_anomaly=0.99,
            proba_attack=0.97,
            predicted_label="Disas",
            raw={"iface": "sim0", "sim": True, "sim_batch": "abc", "ssid": "HawkNet"},
        )
    )

    session = maker()
    try:
        session.add_all(rows)
        session.commit()
    finally:
        session.close()


@pytest.fixture()
def db(engine, seeded):
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = maker()
    try:
        yield session
    finally:
        session.close()


def _json_safe(result) -> None:
    """Every tool result has to survive json.dumps -- it becomes a tool message."""
    json.dumps(result, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# query_threats                                                                #
# --------------------------------------------------------------------------- #
def test_query_threats_returns_rows_newest_first(db):
    out = tools.query_threats(QueryThreatsArgs(limit=10), db)
    assert out["ok"] is True
    assert out["row_count"] == 7
    timestamps = [r["ts"] for r in out["rows"]]
    assert timestamps == sorted(timestamps, reverse=True)
    _json_safe(out)


def test_query_threats_filters_by_label_and_window(db):
    out = tools.query_threats(QueryThreatsArgs(label="Deauth", minutes=60), db)
    assert out["row_count"] == 4
    assert {r["predicted_label"] for r in out["rows"]} == {"Deauth"}
    assert out["filters"] == {"minutes": 60, "label": "Deauth"}


def test_query_threats_accepts_a_plain_language_label(db):
    out = tools.query_threats(QueryThreatsArgs(label="deauthentication"), db)
    assert out["row_count"] == 4
    assert out["filters"]["label"] == "Deauth"


def test_query_threats_rejects_an_unknown_label(db):
    with pytest.raises(tools.ToolError) as excinfo:
        tools.query_threats(QueryThreatsArgs(label="Nonsense"), db)
    assert excinfo.value.kind == "unknown_class"


def test_query_threats_mac_filter_is_case_insensitive(db):
    out = tools.query_threats(QueryThreatsArgs(src_mac="aa:bb:cc:dd:ee:02"), db)
    assert out["row_count"] == 2
    assert {r["predicted_label"] for r in out["rows"]} == {"Kr00k"}


def test_query_threats_confidence_filter_and_order(db):
    out = tools.query_threats(QueryThreatsArgs(min_confidence=0.9, order="confidence"), db)
    assert out["row_count"] == 5  # 4 Deauth at 0.91 + 1 Disas at 0.97
    scores = [r["proba_attack"] for r in out["rows"]]
    assert scores == sorted(scores, reverse=True)


def test_query_threats_lifts_ssid_and_sim_out_of_raw(db):
    out = tools.query_threats(QueryThreatsArgs(label="Disas"), db)
    row = out["rows"][0]
    assert row["ssid"] == "HawkNet"
    assert row["sim"] is True
    assert "raw" not in row  # the whole attacker-influenced blob is not returned


def test_query_threats_limit_is_respected_and_flagged(db):
    out = tools.query_threats(QueryThreatsArgs(limit=2), db)
    assert out["row_count"] == 2
    assert out["truncated"] is True


def test_query_threats_publishes_a_real_select(db):
    out = tools.query_threats(QueryThreatsArgs(label="Deauth", limit=3), db)
    preview = out["sql_preview"]
    assert preview.upper().startswith("SELECT")
    assert "packets" in preview
    assert "Deauth" in preview  # literal binds, not a :param placeholder


# --------------------------------------------------------------------------- #
# aggregate_threats                                                            #
# --------------------------------------------------------------------------- #
def test_aggregate_by_label(db):
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="label"), db)
    counts = {g["key"]: g["count"] for g in out["groups"]}
    assert counts == {"Deauth": 4, "Kr00k": 2, "Disas": 1}
    assert out["total"] == 7
    # Classes with nothing detected are named rather than silently absent.
    assert set(out["classes_with_no_detections"]) == set(ATTACK_CLASSES) - set(counts)
    _json_safe(out)


def test_aggregate_by_src_mac_is_top_offenders(db):
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="src_mac", top_n=1), db)
    assert out["groups"] == [{"key": "AA:BB:CC:DD:EE:01", "count": 4}]
    assert out["truncated"] is True


def test_aggregate_by_channel_freq_is_channel_usage(db):
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="channel_freq"), db)
    counts = {g["key"]: g["count"] for g in out["groups"]}
    assert counts == {2437: 5, 5180: 2}


def test_aggregate_by_bssid_and_iface(db):
    by_bssid = tools.aggregate_threats(AggregateThreatsArgs(group_by="bssid"), db)
    assert {g["key"]: g["count"] for g in by_bssid["groups"]} == {
        "AA:AA:AA:AA:AA:01": 5, "AA:AA:AA:AA:AA:02": 2
    }
    by_iface = tools.aggregate_threats(AggregateThreatsArgs(group_by="iface"), db)
    assert {g["key"]: g["count"] for g in by_iface["groups"]} == {"wlan1": 6, "sim0": 1}


def test_aggregate_group_by_none_is_a_plain_total(db):
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="none"), db)
    assert out["groups"] == [{"key": "all", "count": 7}]
    assert out["total"] == 7


def test_aggregate_hour_of_day_returns_every_bucket(db):
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="hour_of_day"), db)
    assert [g["key"] for g in out["groups"]] == list(range(24))
    assert sum(g["count"] for g in out["groups"]) == 7
    assert out["total"] == 7


def test_aggregate_day_of_week_is_sunday_first(db):
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="day_of_week"), db)
    assert [g["key"] for g in out["groups"]] == ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    assert sum(g["count"] for g in out["groups"]) == 7


def test_aggregate_time_buckets_match_the_dashboard_heatmap(db):
    """The Python bucketing here must equal routers.attacks.heatmap_attack's."""
    from backend.app.routers.attacks import heatmap_attack

    heatmap = heatmap_attack(db)
    expected = {row["day"]: sum(h["intensity"] for h in row["hours"]) for row in heatmap}
    out = tools.aggregate_threats(AggregateThreatsArgs(group_by="day_of_week"), db)
    assert {g["key"]: g["count"] for g in out["groups"]} == expected


def test_aggregate_honours_the_shared_filters(db):
    out = tools.aggregate_threats(
        AggregateThreatsArgs(group_by="label", minutes=60), db
    )
    assert {g["key"]: g["count"] for g in out["groups"]} == {"Deauth": 4, "Disas": 1}


# --------------------------------------------------------------------------- #
# threat_overview                                                              #
# --------------------------------------------------------------------------- #
def test_threat_overview_matches_the_dashboard_functions(db):
    from backend.app.routers.attacks import read_attack_analysis
    from backend.app.routers.reports import compute_summary

    out = tools.threat_overview(ThreatOverviewArgs(days=30), db)
    assert out["ok"] is True
    assert out["all_time_by_class"] == read_attack_analysis(db)
    assert out["totals_by_dashboard_key"] == compute_summary(db, days=30).totals
    assert out["packets_stored_all_time"] == 7
    assert out["headline"]["totalAttacks"] == 7
    assert out["latest_ts"] and out["earliest_ts"]
    _json_safe(out)


# --------------------------------------------------------------------------- #
# explain_attack_class                                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_explain_covers_every_class_in_the_spec(attack_class):
    """Iterates config.ATTACK_CLASSES on purpose.

    A second hand-written list here is exactly how ``Disas`` and ``Kr00k`` went
    missing from the knowledge base in the first place: the list would have been
    written from the file, so it would have agreed with the file, and the gap
    would have stayed invisible.
    """
    out = tools.explain_attack_class(ExplainAttackClassArgs(attack_class=attack_class))
    assert out["ok"] is True
    assert out["attack_class"] == attack_class
    assert len(out["content"]) > 200, f"{attack_class} section is suspiciously short"
    assert "Definition" in out["content"]
    assert "Defenses" in out["content"]


def test_knowledge_base_documents_every_class():
    assert knowledge.missing_classes() == []
    assert knowledge.covered_classes() == list(ATTACK_CLASSES)


@pytest.mark.parametrize(
    "spelling, expected",
    [
        ("evil twin", "Evil_Twin"),
        ("fake access point", "Evil_Twin"),
        ("deauthentication flood", "Deauth"),
        ("disassociation flood", "Disas"),
        ("key reinstallation", "Krack"),
        ("CVE-2019-15126", "Kr00k"),
        ("rogue ap", "RogueAP"),
        ("association flood", "(Re)Assoc"),
        ("amplification", "SSDP"),
        ("KRACK", "Krack"),
        ("(re)assoc", "(Re)Assoc"),
    ],
)
def test_explain_accepts_plain_language_names(spelling, expected):
    out = tools.explain_attack_class(ExplainAttackClassArgs(attack_class=spelling))
    assert out["attack_class"] == expected


def test_explain_rejects_something_that_is_not_an_attack_class():
    with pytest.raises(tools.ToolError) as excinfo:
        tools.explain_attack_class(ExplainAttackClassArgs(attack_class="ransomware"))
    assert excinfo.value.kind == "unknown_class"


def test_krack_heading_matches_the_database_label():
    """The markdown heading was ``## KRACK``; the DB label is ``Krack``."""
    section = knowledge.section_for("Krack")
    assert section is not None
    assert section.splitlines()[0].startswith("## Krack")


def test_disas_section_distinguishes_the_two_management_subtypes():
    section = knowledge.section_for("Disas") or ""
    assert "10" in section and "12" in section
    assert "isassociation" in section


def test_kr00k_section_names_the_cve_and_the_mechanism():
    section = knowledge.section_for("Kr00k") or ""
    assert "CVE-2019-15126" in section
    assert "all-zero" in section.lower()
    assert "Broadcom" in section


# --------------------------------------------------------------------------- #
# locate_source                                                                #
# --------------------------------------------------------------------------- #
def test_locate_source_without_matching_aps_returns_no_centre(db, monkeypatch):
    monkeypatch.setattr("backend.app.routers.maps._load_ap_locations", lambda: [])
    out = tools.locate_source(
        LocateSourceArgs(src_mac="AA:BB:CC:DD:EE:01", minutes=600), db
    )
    assert out["ok"] is True
    assert out["center"] is None
    assert out["rssi_points"], "the RSSI it did have should still be reported"
    assert "no position" in out["note"].lower()
    _json_safe(out)


def test_locate_source_weighted_centroid(db, monkeypatch):
    aps = [
        {"bssid": "AA:AA:AA:AA:AA:01", "name": "AP-1", "lat": 10.0, "lng": 20.0},
        {"bssid": "AA:AA:AA:AA:AA:02", "name": "AP-2", "lat": 12.0, "lng": 22.0},
    ]
    monkeypatch.setattr("backend.app.routers.maps._load_ap_locations", lambda: aps)
    out = tools.locate_source(
        LocateSourceArgs(src_mac="AA:BB:CC:DD:EE:01", minutes=600), db
    )
    assert out["aps_used"] == 1
    assert out["center"] == {"lat": 10.0, "lng": 20.0}


def test_locate_source_matches_the_map_endpoint(db, monkeypatch):
    """Same maths as POST /map/estimate-origin, or the map and the agent disagree."""
    from backend.app.routers.maps import estimate_origin
    from backend.app.schemas import EstimateOriginPayload

    aps = [
        {"bssid": "AA:AA:AA:AA:AA:01", "name": "AP-1", "lat": 10.0, "lng": 20.0},
        {"bssid": "AA:AA:AA:AA:AA:02", "name": "AP-2", "lat": 12.0, "lng": 22.0},
    ]
    monkeypatch.setattr("backend.app.routers.maps._load_ap_locations", lambda: aps)
    endpoint = estimate_origin(
        EstimateOriginPayload(sa="AA:BB:CC:DD:EE:02", minutes=600, ap_locations=aps), db
    )
    tool = tools.locate_source(
        LocateSourceArgs(src_mac="AA:BB:CC:DD:EE:02", minutes=600), db
    )
    assert tool["center"] == endpoint["center"]


def test_locate_source_rejects_a_blank_mac(db):
    with pytest.raises(tools.ToolError):
        tools.locate_source(LocateSourceArgs(src_mac="   "), db)


# --------------------------------------------------------------------------- #
# system_status                                                                #
# --------------------------------------------------------------------------- #
def test_system_status_reports_config_health_and_knowledge_coverage(db):
    out = tools.system_status(SystemStatusArgs(), db)
    assert out["ok"] is True
    assert out["database"]["reachable"] is True
    assert out["database"]["packets_stored"] == 7
    assert out["detector"]["attack_classes"] == list(ATTACK_CLASSES)
    assert "query_threats" in out["saqr"]["tools_available"]
    assert out["knowledge_base"]["undocumented_classes"] == []
    _json_safe(out)


def test_system_status_never_reports_the_model_identifier(db):
    """Which model answers is a server detail; it belongs in the log, not here."""
    out = tools.system_status(SystemStatusArgs(), db)
    assert "model" not in out["saqr"]
    assert settings.saqr_model not in json.dumps(out, default=str)


def test_system_status_says_which_tools_are_switched_off(db, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", False)
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", False)
    out = tools.system_status(SystemStatusArgs(), db)
    assert "run_sql" not in out["saqr"]["tools_available"]
    assert "run_simulation" not in out["saqr"]["tools_available"]
    assert out["saqr"]["raw_sql_enabled"] is False


def test_system_status_hides_the_gated_surface_from_a_read_only_caller(db, monkeypatch):
    """A visitor must not learn that a simulation tool exists.

    The owner's reason is operational: the simulator is the fallback for demoing
    when the router cannot be attacked live. Someone who knows a replay tool
    exists can infer the attacks on the dashboard may not have been captured.
    """
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", True)
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)

    out = tools.system_status(SystemStatusArgs(), db, ctx=tools.ToolContext(is_admin=False))
    blob = json.dumps(out, default=str)

    assert "simulation_tool_enabled" not in out["saqr"]
    assert out["authorisation"]["this_request_is_admin"] is False
    assert out["authorisation"]["session"] == "read-only"
    # Not a name, not a count, not a hint that any of it exists.
    for hidden in tools.ADMIN_TOOLS:
        assert hidden not in blob
    assert "admin_tools_available_now" not in out["authorisation"]


def test_system_status_shows_the_operator_surface_to_an_operator(db, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", True)
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)

    out = tools.system_status(SystemStatusArgs(), db, ctx=tools.ToolContext(is_admin=True))
    assert out["authorisation"]["session"] == "operator"
    assert "run_simulation" in out["authorisation"]["admin_tools_available_now"]
    assert set(out["authorisation"]["destructive_tools"]) == {
        "purge_simulated_detections", "delete_detections",
    }


# --------------------------------------------------------------------------- #
# run_sql — the guarded escape hatch                                           #
# --------------------------------------------------------------------------- #
def test_run_sql_executes_a_guarded_select(db, monkeypatch):
    from backend.app.agent.schemas import RunSqlArgs

    monkeypatch.setattr(settings, "SAQR_MAX_ROWS", 500)
    out = tools.run_sql(
        RunSqlArgs(sql="SELECT predicted_label, COUNT(*) AS n FROM packets GROUP BY 1"), db
    )
    assert out["ok"] is True
    assert {r["predicted_label"]: r["n"] for r in out["rows"]} == {
        "Deauth": 4, "Kr00k": 2, "Disas": 1
    }
    _json_safe(out)


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM packets",
        "SELECT 1; DROP TABLE packets",
        "SELECT * FROM documents",
        "SELECT name FROM sqlite_master",
        "SELECT * FROM packets JOIN documents ON 1=1",
    ],
)
def test_run_sql_refuses_writes_and_other_tables(db, sql):
    from backend.app.agent.schemas import RunSqlArgs

    with pytest.raises(tools.ToolError) as excinfo:
        tools.run_sql(RunSqlArgs(sql=sql), db)
    assert excinfo.value.kind == "rejected_sql"


def test_run_sql_turns_a_database_error_into_a_tool_error(db):
    from backend.app.agent.schemas import RunSqlArgs

    with pytest.raises(tools.ToolError) as excinfo:
        tools.run_sql(RunSqlArgs(sql="SELECT no_such_column FROM packets"), db)
    assert excinfo.value.kind == "sql_error"


# --------------------------------------------------------------------------- #
# The registry and the dispatcher                                              #
# --------------------------------------------------------------------------- #
def test_the_read_only_registry_is_seven_tools_with_raw_sql_last(monkeypatch):
    """What an unauthenticated visitor's model is offered. No operator tools."""
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", True)
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")
    assert list(tools.build_registry()) == [
        "query_threats",
        "aggregate_threats",
        "threat_overview",
        "explain_attack_class",
        "locate_source",
        "system_status",
        "run_sql",
    ]


def test_the_operator_registry_adds_the_admin_tools_with_raw_sql_last(monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", True)
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")
    assert list(tools.build_registry(is_admin=True)) == [
        "query_threats",
        "aggregate_threats",
        "threat_overview",
        "explain_attack_class",
        "locate_source",
        "system_status",
        "run_simulation",
        "purge_simulated_detections",
        "delete_detections",
        "export_report",
        "get_runtime_config",
        "run_sql",
    ]


def test_admin_tools_stay_hidden_when_no_token_is_configured(monkeypatch):
    """No token on this host means no admin surface at all, for anyone.

    Not "published but unreachable": a tool the model was never shown is a tool
    it cannot be argued into calling.
    """
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "")
    registry = tools.build_registry(is_admin=True)
    for name in tools.ADMIN_TOOLS:
        assert name not in registry


def test_every_writing_tool_is_admin_gated(monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", True)
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")

    assert not [n for n, s in tools.build_registry().items() if s.mutating]
    operator = tools.build_registry(is_admin=True)
    assert sorted(n for n, s in operator.items() if s.mutating) == [
        "delete_detections", "purge_simulated_detections", "run_simulation",
    ]
    # Destroying data implies writing it; a destructive tool that was not also
    # mutating would slip past any check that keys on `mutating`.
    for name, spec in operator.items():
        if spec.destructive:
            assert spec.mutating, f"{name} destroys data but is not marked mutating"


def test_raw_sql_is_hidden_unless_explicitly_enabled(monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", False)
    assert "run_sql" not in tools.build_registry()
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    assert "run_sql" in tools.build_registry()


def test_simulation_tool_hidden_when_simulation_is_off(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", False)
    assert "run_simulation" not in tools.build_registry()


def test_tool_definitions_are_well_formed_json_schema(monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")
    definitions = tools.tool_definitions(tools.build_registry(is_admin=True))
    assert len(definitions) == 12
    for definition in definitions:
        assert definition["type"] == "function"
        function = definition["function"]
        assert function["name"] and function["description"]
        params = function["parameters"]
        assert params["type"] == "object"
        assert params["additionalProperties"] is False
        json.dumps(definition)  # must be serialisable for the wire


def test_public_catalogue_publishes_label_keys_and_the_mutating_flag(monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")
    catalogue = tools.public_catalogue(is_admin=True)
    assert {entry["name"] for entry in catalogue} == set(
        tools.build_registry(is_admin=True)
    )
    for entry in catalogue:
        assert entry["label_key"] == f"saqr.tool.{entry['name']}"
        assert isinstance(entry["mutating"], bool)
        assert isinstance(entry["admin"], bool)
        assert isinstance(entry["destructive"], bool)
        assert entry["args_schema"]["type"] == "object"
    assert sorted(e["name"] for e in catalogue if e["mutating"]) == [
        "delete_detections", "purge_simulated_detections", "run_simulation",
    ]


def test_the_public_catalogue_omits_the_admin_tools_entirely(monkeypatch):
    """Not listed-and-disabled. Absent.

    The frontend builds its controls from this list, so gating it correctly is
    what makes the visitor-facing UI correct without special-casing.
    """
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", True)
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)
    monkeypatch.setattr(settings, "SAQR_ADMIN_TOKEN", "operator-token-abcdef")

    catalogue = tools.public_catalogue()
    blob = json.dumps(catalogue)
    for name in tools.ADMIN_TOOLS:
        assert name not in blob, f"{name} leaked into the read-only catalogue"
    assert not [e for e in catalogue if e["mutating"] or e["admin"]]


def test_execute_reports_an_unknown_tool_instead_of_raising(db):
    out = tools.execute("no_such_tool", {}, db)
    assert out["ok"] is False
    assert out["error"]["type"] == "unknown_tool"
    assert "query_threats" in out["error"]["hint"]


def test_execute_reports_invalid_arguments_instead_of_raising(db):
    out = tools.execute("query_threats", {"limit": 5000}, db)
    assert out["ok"] is False
    assert out["error"]["type"] == "invalid_arguments"
    _json_safe(out)


def test_execute_rejects_an_argument_the_schema_does_not_define(db):
    out = tools.execute("query_threats", {"nonsense": 1}, db)
    assert out["ok"] is False
    assert out["error"]["type"] == "invalid_arguments"


def test_execute_turns_a_tool_error_into_a_result(db):
    out = tools.execute("explain_attack_class", {"attack_class": "phishing"}, db)
    assert out["ok"] is False
    assert out["error"]["type"] == "unknown_class"
    assert "Deauth" in out["error"]["hint"]


def test_execute_runs_a_db_free_tool_without_a_session():
    out = tools.execute("explain_attack_class", {"attack_class": "Deauth"}, None)
    assert out["ok"] is True


def test_execute_refuses_a_db_tool_with_no_session():
    out = tools.execute("query_threats", {}, None)
    assert out["ok"] is False
    assert out["error"]["type"] == "no_database"


def test_execute_never_raises_when_the_tool_itself_explodes(db):
    import dataclasses

    def boom(args, session):
        raise RuntimeError("the disk caught fire")

    spec = dataclasses.replace(tools.build_registry()["threat_overview"], executor=boom)
    out = tools.execute("threat_overview", {}, db, {"threat_overview": spec})
    assert out["ok"] is False
    assert out["error"]["type"] == "tool_failed"
    assert "disk caught fire" in out["error"]["message"]
