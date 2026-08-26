"""Tests for backend.app.rag.packet_qa.

No network, no OPENAI_API_KEY, no PostgreSQL: the OpenAI client and the database
layer are always faked.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.rag import packet_qa  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures / helpers                                                           #
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _isolated_config(monkeypatch):
    """Neutralise ambient configuration so every test is deterministic."""
    monkeypatch.setattr(packet_qa, "_settings", None, raising=False)
    monkeypatch.setattr(packet_qa, "_client", None, raising=False)
    for var in (
        "OPENAI_API_KEY",
        "DATABASE_URL",
        "GEN_MODEL",
        "HUMANIZE_SQL",
        "ATTACKS_FILE",
        "RAG_KNOWLEDGE_FILE",
        "RAG_MAX_ROWS",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


class _FakeCompletions:
    """Records calls and replays canned assistant messages."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        content = self._replies.pop(0) if self._replies else ""
        message = SimpleNamespace(content=content)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _fake_client(replies):
    completions = _FakeCompletions(replies)
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return client, completions


# --------------------------------------------------------------------------- #
# Fix #3 — import safety + RagUnavailable                                      #
# --------------------------------------------------------------------------- #
def test_import_without_api_key_succeeds(monkeypatch):
    """Re-importing the module with no credentials must not raise."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    module = importlib.reload(packet_qa)
    assert module.SYSTEM_PROMPT
    assert issubclass(module.RagUnavailable, RuntimeError)
    # restore a clean module state for the remaining tests
    module._client = None


def test_packet_ask_raises_rag_unavailable_without_api_key():
    with pytest.raises(packet_qa.RagUnavailable):
        packet_qa.packet_ask("how many attacks today?")


def test_rag_unavailable_is_not_swallowed_into_error_dict():
    """RagUnavailable must propagate so the router can answer 503."""
    try:
        packet_qa.packet_ask("what is an evil twin?")
    except packet_qa.RagUnavailable as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:  # pragma: no cover
        pytest.fail("packet_ask should have raised RagUnavailable")


def test_missing_database_url_raises_rag_unavailable(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    with pytest.raises(packet_qa.RagUnavailable):
        packet_qa._db_url()


# --------------------------------------------------------------------------- #
# Fix #2 — DATABASE_URL normalisation                                          #
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
    assert packet_qa._normalize_db_url(raw) == expected


def test_normalize_db_url_preserves_query_and_password_specials():
    url = "postgresql+psycopg2://user:p%40ss@db.internal:5432/hawkshield?sslmode=require"
    assert packet_qa._normalize_db_url(url) == (
        "postgresql://user:p%40ss@db.internal:5432/hawkshield?sslmode=require"
    )


def test_db_url_uses_normalised_value(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@h:5432/d")
    assert packet_qa._db_url() == "postgresql://u:p@h:5432/d"


# --------------------------------------------------------------------------- #
# SELECT-only guard                                                            #
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
    cleaned = packet_qa._assert_select_only(sql)
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
        packet_qa._assert_select_only(sql)


def test_select_guard_rejects_non_select_start():
    with pytest.raises(ValueError, match="non-SELECT"):
        packet_qa._assert_select_only("EXPLAIN SELECT * FROM packets")


# --------------------------------------------------------------------------- #
# LIMIT safety net                                                             #
# --------------------------------------------------------------------------- #
def test_limit_appended_to_bare_select():
    out = packet_qa._apply_row_limit("SELECT * FROM packets", max_rows=500)
    assert out.endswith("LIMIT 500")
    assert out.startswith("SELECT * FROM packets")


def test_limit_appended_to_grouped_query_which_can_return_many_rows():
    out = packet_qa._apply_row_limit(
        "SELECT src_mac, COUNT(*) AS count FROM packets GROUP BY src_mac", max_rows=250
    )
    assert out.endswith("LIMIT 250")


def test_limit_not_added_to_bare_aggregate():
    sql = "SELECT COUNT(*) AS count FROM packets WHERE predicted_label = 'Deauth'"
    assert packet_qa._apply_row_limit(sql, max_rows=500) == sql


def test_limit_not_added_when_already_present():
    sql = "SELECT src_mac FROM packets ORDER BY ts DESC LIMIT 25"
    assert packet_qa._apply_row_limit(sql, max_rows=500) == sql


def test_limit_not_added_for_fetch_first():
    sql = "SELECT src_mac FROM packets ORDER BY ts DESC FETCH FIRST 10 ROWS ONLY"
    assert packet_qa._apply_row_limit(sql, max_rows=500) == sql


def test_limit_default_comes_from_env(monkeypatch):
    monkeypatch.setenv("RAG_MAX_ROWS", "42")
    assert packet_qa._apply_row_limit("SELECT * FROM packets").endswith("LIMIT 42")


def test_limit_strips_trailing_semicolon():
    out = packet_qa._apply_row_limit("SELECT * FROM packets;", max_rows=10)
    assert out == "SELECT * FROM packets\nLIMIT 10"


# --------------------------------------------------------------------------- #
# Fix #4 — knowledge base path                                                 #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def scratch_dir():
    """A throwaway directory (pytest's tmp_path GC is racy on Windows)."""
    with tempfile.TemporaryDirectory() as name:
        yield Path(name)


def test_knowledge_file_loads_from_arbitrary_cwd(scratch_dir):
    """Fix #4: the knowledge base is resolved relative to the package, not the CWD."""
    packet_qa._attacks_cache.clear()
    original_cwd = Path.cwd()
    os.chdir(scratch_dir)  # a directory containing nothing named attacks.*
    try:
        text = packet_qa._load_attacks_context()
        path = packet_qa._knowledge_path()
    finally:
        os.chdir(original_cwd)  # restore before the temp dir is removed

    assert "Evil_Twin" in text
    assert "Deauth" in text
    assert path.is_absolute()


def test_knowledge_file_is_cached_after_first_read(scratch_dir, monkeypatch):
    packet_qa._attacks_cache.clear()
    kb = scratch_dir / "kb.md"
    kb.write_text("# only in the file", encoding="utf-8")
    monkeypatch.setenv("ATTACKS_FILE", str(kb))

    assert packet_qa._load_attacks_context() == "# only in the file"
    kb.unlink()  # cache must survive the file disappearing
    assert packet_qa._load_attacks_context() == "# only in the file"


def test_missing_knowledge_file_returns_empty_string(scratch_dir, monkeypatch):
    packet_qa._attacks_cache.clear()
    monkeypatch.setenv("ATTACKS_FILE", str(scratch_dir / "nope.md"))
    assert packet_qa._load_attacks_context() == ""


# --------------------------------------------------------------------------- #
# JSON serialisation of rows                                                   #
# --------------------------------------------------------------------------- #
def test_rows_with_datetime_and_decimal_are_json_serialisable():
    cols = ["ts", "count", "signal_dbm", "raw"]
    rows = [(datetime(2026, 8, 26, 12, 30, 45), Decimal("17"), None, {"ssid": "HawkNet"})]
    dicts = packet_qa._rows_to_dicts(cols, rows)

    assert dicts[0]["ts"] == "2026-08-26T12:30:45"
    assert dicts[0]["count"] == 17.0
    assert dicts[0]["signal_dbm"] is None
    assert dicts[0]["raw"] == {"ssid": "HawkNet"}
    json.dumps(dicts)  # must not raise


def test_jsonable_handles_bytes_and_unknown_objects():
    assert packet_qa._jsonable(b"\x01\x02") == "0102"
    assert packet_qa._jsonable(object()).startswith("<object")


# --------------------------------------------------------------------------- #
# End-to-end with fakes: routing, SQL execution, humanisation                  #
# --------------------------------------------------------------------------- #
def test_sql_mode_end_to_end_with_fakes(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://u:p@h/db")

    client, completions = _fake_client(
        [
            json.dumps({"mode": "SQL", "sql": "SELECT COUNT(*) AS count FROM packets", "answer": ""}),
            "There were 7 attack packets in total.",
        ]
    )
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)

    executed = {}

    def fake_run_sql(sql):
        executed["sql"] = sql
        return ["count"], [(7,)]

    monkeypatch.setattr(packet_qa, "_run_sql", fake_run_sql)

    out = packet_qa.packet_ask("how many attacks today?")
    assert out["mode"] == "SQL"
    assert out["cols"] == ["count"]
    assert out["rows"] == [{"count": 7}]
    assert out["answer"] == "There were 7 attack packets in total."
    assert "error" not in out
    assert executed["sql"] == "SELECT COUNT(*) AS count FROM packets"  # aggregate: no LIMIT
    assert len(completions.calls) == 2


def test_sql_mode_appends_limit_to_reported_sql(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("HUMANIZE_SQL", "0")
    monkeypatch.setenv("RAG_MAX_ROWS", "100")

    client, completions = _fake_client(
        [json.dumps({"mode": "SQL", "sql": "SELECT * FROM packets", "answer": ""})]
    )
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)
    monkeypatch.setattr(
        packet_qa,
        "_run_sql",
        lambda sql: (["ts", "src_mac"], [(datetime(2026, 8, 26, 1, 2, 3), "aa:bb:cc:dd:ee:ff")]),
    )

    out = packet_qa.packet_ask("show me the packets")
    assert out["sql"].endswith("LIMIT 100")
    assert out["rows"] == [{"ts": "2026-08-26T01:02:03", "src_mac": "aa:bb:cc:dd:ee:ff"}]
    # HUMANIZE_SQL=0 → deterministic fallback, so only the routing call happened
    assert len(completions.calls) == 1
    assert "returned 1 row" in out["answer"]


def test_humanisation_failure_falls_back_to_deterministic(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class _Flaky(_FakeCompletions):
        def create(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                message = SimpleNamespace(
                    content=json.dumps(
                        {"mode": "SQL", "sql": "SELECT COUNT(*) AS count FROM packets", "answer": ""}
                    )
                )
                return SimpleNamespace(choices=[SimpleNamespace(message=message)])
            raise RuntimeError("openai is down")

    completions = _Flaky([])
    monkeypatch.setattr(
        packet_qa,
        "_get_client",
        lambda: SimpleNamespace(chat=SimpleNamespace(completions=completions)),
    )
    monkeypatch.setattr(packet_qa, "_run_sql", lambda sql: (["count"], [(3,)]))

    out = packet_qa.packet_ask("how many attacks?")
    assert out["mode"] == "SQL"
    assert "count = 3" in out["answer"]


def test_docs_mode_returns_answer_without_sql(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client, _ = _fake_client(
        [json.dumps({"mode": "DOCS", "sql": "", "answer": "An evil twin is a rogue AP..."})]
    )
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)

    out = packet_qa.packet_ask("what is an evil twin?")
    assert out == {
        "mode": "DOCS",
        "sql": "",
        "answer": "An evil twin is a rogue AP...",
        "cols": [],
        "rows": [],
    }


def test_oos_mode_gets_default_scope_message(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client, _ = _fake_client([json.dumps({"mode": "OOS", "sql": "", "answer": ""})])
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)

    out = packet_qa.packet_ask("what is the weather?")
    assert out["mode"] == "OOS"
    assert "Wi-Fi packet analytics" in out["answer"]


def test_model_emitting_a_write_becomes_an_error_result(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client, _ = _fake_client(
        [json.dumps({"mode": "SQL", "sql": "DROP TABLE packets", "answer": ""})]
    )
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)

    out = packet_qa.packet_ask("delete everything")
    assert out["mode"] == "ERROR"
    assert out["error"]
    assert out["rows"] == [] and out["cols"] == []


def test_malformed_model_json_becomes_an_error_result(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client, _ = _fake_client(["not json at all"])
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)

    out = packet_qa.packet_ask("how many attacks?")
    assert out["mode"] == "ERROR"
    assert "valid JSON" in out["error"]


def test_code_fenced_json_is_accepted(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    fenced = "```json\n" + json.dumps({"mode": "OOS", "sql": "", "answer": "Out of scope."}) + "\n```"
    client, _ = _fake_client([fenced])
    monkeypatch.setattr(packet_qa, "_get_client", lambda: client)

    out = packet_qa.packet_ask("tell me a joke")
    assert out["mode"] == "OOS"
    assert out["answer"] == "Out of scope."


# --------------------------------------------------------------------------- #
# Prompt sanity: the schema block must describe the real table                 #
# --------------------------------------------------------------------------- #
def test_system_prompt_describes_the_real_schema():
    prompt = packet_qa.SYSTEM_PROMPT
    for column in (
        "ts", "iface", "src_mac", "dst_mac", "bssid", "frame_len", "channel_freq",
        "datarate", "signal_dbm", "wlan_ds", "wlan_retry", "wlan_type",
        "wlan_subtype", "wlan_duration", "proba_anomaly", "proba_attack",
        "predicted_label", "raw",
    ):
        assert column in prompt, f"missing column {column} in SYSTEM_PROMPT"
    for label in ("SSDP", "Evil_Twin", "Krack", "Deauth", "(Re)Assoc", "RogueAP"):
        assert f"'{label}'" in prompt, f"missing quoted label {label}"
    assert "Table: packets" in prompt
    assert "ONLY ATTACK PACKETS ARE STORED" in prompt
    assert "raw->>" in prompt
    # the stale legacy columns must be gone (except where explicitly forbidden)
    assert "ip_src" not in prompt and "tcp_srcport" not in prompt
    assert "wlan_sa" not in prompt and "attack_type = ..." in prompt
