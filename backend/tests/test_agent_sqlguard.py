"""Tests for backend.app.agent.sqlguard.

No network, no OPENROUTER_API_KEY, no PostgreSQL.

The SELECT-only and LIMIT cases are ported verbatim from ``test_rag.py``: the
guards moved module, so the cases that pinned them have to follow, otherwise the
extraction silently loses its safety net the day ``test_rag.py`` is deleted.
The table allow-list cases below are new -- that guard did not exist before.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.agent import sqlguard  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_config(monkeypatch):
    """Neutralise ambient configuration so every test is deterministic."""
    for var in ("DATABASE_URL", "SAQR_MAX_ROWS", "RAG_MAX_ROWS"):
        monkeypatch.delenv(var, raising=False)
    yield


# --------------------------------------------------------------------------- #
# DATABASE_URL normalisation (ported from test_rag.py)                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            "postgresql+psycopg2://hawkshield:pw@localhost:5432/hawkshield",
            "postgresql://hawkshield:pw@localhost:5432/hawkshield",
        ),
        (
            "postgresql+psycopg://hawkshield:pw@10.0.0.5:5432/hawkshield",
            "postgresql://hawkshield:pw@10.0.0.5:5432/hawkshield",
        ),
        (
            "postgresql://hawkshield:pw@localhost:5432/hawkshield",
            "postgresql://hawkshield:pw@localhost:5432/hawkshield",
        ),
        (
            "postgres+psycopg2://u:p@host/db",
            "postgres://u:p@host/db",
        ),
        ("", ""),
    ],
)
def test_normalize_db_url(raw, expected):
    assert sqlguard.normalize_db_url(raw) == expected


def test_normalize_db_url_preserves_query_and_password_specials():
    url = "postgresql+psycopg2://user:p%40ss@db.internal:5432/hawkshield?sslmode=require"
    assert sqlguard.normalize_db_url(url) == (
        "postgresql://user:p%40ss@db.internal:5432/hawkshield?sslmode=require"
    )


@pytest.mark.parametrize(
    "url, expected",
    [
        ("sqlite:///./hawkshield.db", "sqlite"),
        ("SQLite:///:memory:", "sqlite"),
        ("postgresql+psycopg2://u:p@h/db", "postgresql"),
        ("", "postgresql"),
    ],
)
def test_sql_dialect_follows_the_url(url, expected):
    assert sqlguard.sql_dialect(url) == expected


def test_sql_dialect_reads_the_environment_when_not_told(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./demo.db")
    assert sqlguard.sql_dialect() == "sqlite"


def test_dialect_notes_match_the_dialect():
    assert "SQLite" in sqlguard.dialect_notes("sqlite")
    assert "PostgreSQL" in sqlguard.dialect_notes("postgresql")


# --------------------------------------------------------------------------- #
# SELECT-only guard (ported verbatim from test_rag.py)                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT COUNT(*) AS count FROM packets",
        "select src_mac, count(*) as count from packets group by 1 order by 2 desc limit 10",
        "SELECT * FROM packets WHERE predicted_label = '(Re)Assoc' LIMIT 5",
        "SELECT COUNT(*) AS count FROM packets;",  # single trailing semicolon tolerated
        "WITH recent AS (SELECT * FROM packets WHERE ts >= NOW() - INTERVAL '1 hour')"
        " SELECT COUNT(*) AS count FROM recent",
    ],
)
def test_select_guard_accepts_read_only_queries(sql):
    cleaned = sqlguard.assert_select_only(sql)
    assert not cleaned.endswith(";")


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO packets (id) VALUES (1)",
        "UPDATE packets SET predicted_label = 'Deauth'",
        "DELETE FROM packets",
        "DROP TABLE packets",
        "TRUNCATE packets",
        "ALTER TABLE packets ADD COLUMN x int",
        "SELECT 1; DROP TABLE packets",
        "SELECT 1;DELETE FROM packets;",
        "SELECT * INTO evil FROM packets",
        "WITH x AS (DELETE FROM packets RETURNING *) SELECT * FROM x",
        "WITH x AS (INSERT INTO packets DEFAULT VALUES RETURNING *) SELECT * FROM x",
        "",
        "   ",
    ],
)
def test_select_guard_rejects_writes_and_multi_statements(sql):
    with pytest.raises(ValueError):
        sqlguard.assert_select_only(sql)


def test_select_guard_rejects_non_select_start():
    with pytest.raises(ValueError, match="non-SELECT"):
        sqlguard.assert_select_only("EXPLAIN SELECT * FROM packets")


# --------------------------------------------------------------------------- #
# LIMIT safety net (ported verbatim from test_rag.py)                          #
# --------------------------------------------------------------------------- #
def test_limit_appended_to_bare_select():
    out = sqlguard.apply_row_limit("SELECT * FROM packets", max_rows=500)
    assert out.endswith("LIMIT 500")
    assert out.startswith("SELECT * FROM packets")


def test_limit_appended_to_grouped_query_which_can_return_many_rows():
    out = sqlguard.apply_row_limit(
        "SELECT src_mac, COUNT(*) AS count FROM packets GROUP BY src_mac", max_rows=250
    )
    assert out.endswith("LIMIT 250")


def test_limit_not_added_to_bare_aggregate():
    sql = "SELECT COUNT(*) AS count FROM packets WHERE predicted_label = 'Deauth'"
    assert sqlguard.apply_row_limit(sql, max_rows=500) == sql


def test_limit_not_added_when_already_present():
    sql = "SELECT src_mac FROM packets ORDER BY ts DESC LIMIT 25"
    assert sqlguard.apply_row_limit(sql, max_rows=500) == sql


def test_limit_not_added_for_fetch_first():
    sql = "SELECT src_mac FROM packets ORDER BY ts DESC FETCH FIRST 10 ROWS ONLY"
    assert sqlguard.apply_row_limit(sql, max_rows=500) == sql


def test_limit_default_comes_from_env(monkeypatch):
    monkeypatch.setenv("SAQR_MAX_ROWS", "42")
    assert sqlguard.apply_row_limit("SELECT * FROM packets").endswith("LIMIT 42")


def test_limit_default_honours_the_deprecated_rag_variable(monkeypatch):
    """RAG_MAX_ROWS stays a working fallback so an existing .env keeps tuning it."""
    monkeypatch.setenv("RAG_MAX_ROWS", "17")
    assert sqlguard.apply_row_limit("SELECT * FROM packets").endswith("LIMIT 17")


def test_limit_strips_trailing_semicolon():
    out = sqlguard.apply_row_limit("SELECT * FROM packets;", max_rows=10)
    assert out == "SELECT * FROM packets\nLIMIT 10"


# --------------------------------------------------------------------------- #
# Table allow-list — new in the agent                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT COUNT(*) AS count FROM packets",
        "SELECT * FROM packets p WHERE p.predicted_label = 'Deauth' LIMIT 5",
        "SELECT * FROM packets AS p LIMIT 5",
        "SELECT * FROM public.packets LIMIT 5",
        'SELECT * FROM "packets" LIMIT 5',
        "SELECT a.src_mac FROM packets a JOIN packets b ON a.bssid = b.bssid LIMIT 5",
        "SELECT src_mac FROM (SELECT src_mac FROM packets) AS inner_q LIMIT 5",
        # A CTE name defined in the same statement is a legitimate FROM target.
        "WITH recent AS (SELECT * FROM packets WHERE ts >= NOW() - INTERVAL '1 hour')"
        " SELECT COUNT(*) AS count FROM recent",
        "WITH recent AS (SELECT src_mac FROM packets), busy AS (SELECT src_mac FROM recent)"
        " SELECT * FROM busy LIMIT 5",
        # 'from' inside a string literal is not a table reference.
        "SELECT COUNT(*) AS count FROM packets WHERE raw::text LIKE '%from documents%'",
    ],
)
def test_table_guard_accepts_packets_and_local_ctes(sql):
    assert sqlguard.assert_tables_allowed(sql) is sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM documents",
        "SELECT text FROM documents LIMIT 5",
        "SELECT name FROM sqlite_master",
        "SELECT * FROM pg_catalog.pg_tables",
        "SELECT usename, passwd FROM pg_shadow",
        "SELECT table_name FROM information_schema.tables",
        "SELECT * FROM packets JOIN documents ON 1 = 1",
        "SELECT * FROM packets, documents",
        "SELECT * FROM packets p, sqlite_master m",
        "SELECT * FROM packets WHERE id IN (SELECT id FROM documents)",
        "WITH x AS (SELECT * FROM documents) SELECT * FROM x",
        # A comment must not be able to hide the real FROM target.
        "SELECT * /* packets */ FROM documents",
    ],
)
def test_table_guard_rejects_everything_else(sql):
    with pytest.raises(ValueError):
        sqlguard.assert_tables_allowed(sql)


def test_table_guard_names_the_offending_table():
    with pytest.raises(ValueError, match="documents"):
        sqlguard.assert_tables_allowed("SELECT * FROM documents")


def test_table_guard_allow_list_is_configurable():
    sqlguard.assert_tables_allowed("SELECT * FROM documents", {"documents"})
    with pytest.raises(ValueError):
        sqlguard.assert_tables_allowed("SELECT * FROM packets", {"documents"})


def test_table_references_are_lower_cased_and_unqualified_names_kept():
    refs = sqlguard.table_references("SELECT * FROM Packets P JOIN PG_CATALOG.pg_tables t ON 1=1")
    assert refs == ["packets", "pg_catalog.pg_tables"]


def test_cte_names_only_collected_for_a_with_statement():
    sql = "WITH recent AS (SELECT 1), busy AS (SELECT 2) SELECT * FROM recent"
    assert sqlguard.cte_names(sql) == {"recent", "busy"}
    assert sqlguard.cte_names("SELECT * FROM packets") == set()


# --------------------------------------------------------------------------- #
# JSON serialisation of rows (ported from test_rag.py)                         #
# --------------------------------------------------------------------------- #
def test_rows_with_datetime_and_decimal_are_json_serialisable():
    cols = ["ts", "count", "signal_dbm", "raw"]
    rows = [(datetime(2026, 8, 26, 12, 30, 45), Decimal("17"), None, {"ssid": "HawkNet"})]
    dicts = sqlguard.rows_to_dicts(cols, rows)

    assert dicts[0]["ts"] == "2026-08-26T12:30:45"
    assert dicts[0]["count"] == 17.0
    assert dicts[0]["signal_dbm"] is None
    assert dicts[0]["raw"] == {"ssid": "HawkNet"}
    json.dumps(dicts)  # must not raise


def test_jsonable_handles_bytes_and_unknown_objects():
    assert sqlguard.jsonable(b"\x01\x02") == "0102"
    assert sqlguard.jsonable(object()).startswith("<object")


# --------------------------------------------------------------------------- #
# raw / ts normalisation — one implementation, not a third copy                #
# --------------------------------------------------------------------------- #
def test_normalise_packet_row_parses_sqlite_text_columns():
    row = {"id": 1, "raw": '{"sim": true, "ssid": "HawkNet"}', "ts": "2026-08-26T12:30:45"}
    out = sqlguard.normalise_packet_row(row)
    assert out["raw"] == {"sim": True, "ssid": "HawkNet"}
    assert out["ts"] == datetime(2026, 8, 26, 12, 30, 45)


def test_normalise_packet_row_leaves_postgres_values_alone():
    ts = datetime(2026, 8, 26, 12, 30, 45)
    row = {"id": 1, "raw": {"sim": False}, "ts": ts}
    out = sqlguard.normalise_packet_row(row)
    assert out["raw"] == {"sim": False}
    assert out["ts"] is ts


def test_normalise_packet_row_survives_junk():
    row = {"id": 1, "raw": "not json", "ts": "not a timestamp"}
    out = sqlguard.normalise_packet_row(row)
    assert out["raw"] == "not json"
    assert out["ts"] == "not a timestamp"
