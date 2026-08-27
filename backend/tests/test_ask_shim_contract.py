"""The contract ``frontend/out`` has with ``POST /ask``.

This file is the CI half of ``backend/scripts/check_frontend.py``: the script is
the human-readable go/no-go gate you run before a demo, these are the assertions
that fail a build.

**Why it exists.** ``/ask`` is going to be reimplemented as a shim over the Saqr
agent while the already-built ``frontend/out`` bundle stays in production. The
bundle cannot be re-checked by reading ``docs/CONTRACT.md``, because the contract
can be right while the shipped build still breaks. So every assertion here was
taken from what the built RAG page *does* --
``frontend/out/_next/static/chunks/app/(app)/rag/page-*.js`` -- not from what the
contract says it should do.

The page's handler, in full:

    const e = await apiFetchJson("/ask", {question, session_id})
    if (e.error) { render error bubble; return }          // (1)
    if ("SQL" === e.mode) {                               // (2)
        r = e.answer || "(no summary)"                    // (3)
        if (Array.isArray(e.rows) && e.rows.length) {     // (4)
            const t = e.rows.slice(0, 5)
            const a = e.cols || Object.keys(t[0] || {})   // (5)
            ... t.map(row => a.map(col => String(row[col] ?? ""))) ...   // (6)
        }
    } else r = e.answer || "(no answer)"                  // (7)

Every numbered line below is pinned by a test with the same number in its name.

No network, no OPENROUTER_API_KEY, no PostgreSQL: the model is faked at both the
current and the future boundary, while the SQL runs for real against a seeded
SQLite database, so ``cols``/``rows`` are genuine query output.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app import db as db_module  # noqa: E402
from backend.app.config import ATTACK_CLASSES, FRONT_TYPES, settings  # noqa: E402
from backend.app.db import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Packet  # noqa: E402
from backend.app.routers import ask as ask_router  # noqa: E402

#: The keys the built page destructures. Not a superset of the contract -- the
#: exact set the bundle reads, which is what a shim must keep.
ASK_KEYS = ("mode", "sql", "answer", "cols", "rows", "error")

#: The tool the faked model calls. Real query, real rows out of the seeded DB.
GATE_TOOL = "aggregate_threats"
GATE_ARGS = {"group_by": "label"}


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    db_path: Path = tmp_path_factory.mktemp("ask_shim") / "gate.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=eng)

    maker = sessionmaker(bind=eng, autocommit=False, autoflush=False)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    session = maker()
    try:
        session.add_all(
            [
                Packet(
                    ts=now - timedelta(minutes=7 * (i + 1)),
                    iface="wlan1",
                    src_mac=f"AA:BB:CC:DD:EE:{i % 3:02d}",
                    dst_mac="FF:FF:FF:FF:FF:FF",
                    bssid="AA:AA:AA:AA:AA:01",
                    frame_len=120 + i,
                    channel_freq=2437 if i % 2 else 5180,
                    signal_dbm=-42.0 - i,
                    wlan_type=0,
                    wlan_subtype=12,
                    proba_anomaly=0.95,
                    proba_attack=0.91,
                    predicted_label=("Deauth", "Kr00k", "Disas")[i % 3],
                    raw={"iface": "wlan1", "ssid": "HawkNet"},
                )
                for i in range(6)
            ]
        )
        session.commit()
    finally:
        session.close()

    yield eng
    eng.dispose()


@pytest.fixture()
def client(engine, monkeypatch) -> Iterator[TestClient]:
    """The real app, over the seeded database, with `/ask`'s engine repointed.

    ``DATABASE_URL`` and ``backend.app.db.engine`` are patched as well as the
    ``get_db`` dependency, because the current ``/ask`` reaches the database
    through the module engine rather than the request's session. A shim over the
    agent *will* honour the request bind -- patching both means this file gives
    the same verdict before and after the flip.
    """
    monkeypatch.setattr(db_module, "engine", engine)
    monkeypatch.setattr(settings, "DATABASE_URL", str(engine.url))
    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "test-key")

    def override_get_db() -> Iterator[Session]:
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        session: Session = maker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    ask_router.cache.store.clear()
    ask_router.SESSION_MEMORY.clear()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def faked_model(monkeypatch):
    """Fake the model at the ``/ask`` boundary.

    ``/ask`` is now a shim over the agent, so ``agent.llm.chat`` is the only
    boundary there is.  Until S5 this fixture also patched
    ``packet_qa._get_client``, which is how the same file gave the same verdict
    before and after the flip.
    """
    from backend.app.agent import llm as agent_llm

    prose = "Deauth is the most frequent detected class in this window."

    def fake_chat(messages: Any, **kwargs: Any) -> Any:
        if kwargs.get("tool_choice") == "none" or not kwargs.get("tools"):
            return SimpleNamespace(content=prose, tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="shim_call_1",
                    type="function",
                    function=SimpleNamespace(
                        name=GATE_TOOL, arguments=json.dumps(GATE_ARGS),
                    ),
                )
            ],
        )

    monkeypatch.setattr(agent_llm, "chat", fake_chat)
    monkeypatch.setattr(agent_llm, "chat_stream", lambda messages, **kw: iter([prose]))
    yield


@pytest.fixture()
def ask(client, faked_model) -> Dict[str, Any]:
    """One ``POST /ask`` for a database question, as the bundle sends it."""
    response = client.post(
        "/ask",
        json={"question": "how many attacks by class?", "session_id": "shim-contract"},
    )
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# The envelope                                                                 #
# --------------------------------------------------------------------------- #
def test_ask_returns_every_key_the_bundle_reads(ask):
    missing = [key for key in ASK_KEYS if key not in ask]
    assert not missing, f"the built bundle reads these and they are absent: {missing}"


def test_1_error_is_falsy_on_success(ask):
    """`if (e.error) { render error; return }` runs FIRST and short-circuits.

    A non-null `error` beside a perfectly good answer discards the answer and
    the rows entirely, and the user sees only an error bubble.
    """
    assert not ask.get("error"), (
        f"error={ask.get('error')!r} on a successful answer; the bundle checks "
        "`if (e.error)` before anything else and returns early"
    )


def test_2_mode_is_the_literal_string_SQL(ask):
    """The crux. `"SQL" === e.mode` is the ONLY branch that renders the table.

    Any other value -- "sql", "AGENT", "TOOLS", None -- falls through to
    `r = e.answer || "(no answer)"`. The answer still renders, fluently and
    plausibly, and the rows table silently disappears. Nothing errors, nothing
    turns red, and a human watching a demo has no way to notice.
    """
    assert ask.get("mode") == "SQL", (
        f"mode={ask.get('mode')!r}. The bundle branches on the exact string "
        '"SQL"; every other value degrades to prose and drops the rows table '
        "without any visible error."
    )


def test_3_answer_is_a_non_empty_string(ask):
    """`r = e.answer || "(no summary)"` -- an empty answer renders that literal."""
    assert isinstance(ask.get("answer"), str)
    assert ask["answer"].strip(), 'the bundle would render the literal "(no summary)"'


def test_4_rows_is_a_non_empty_array(ask):
    """`Array.isArray(e.rows) && e.rows.length` gates the whole table."""
    assert isinstance(ask.get("rows"), list), (
        f"rows is {type(ask.get('rows')).__name__}; a non-array fails "
        "`Array.isArray` and the table never renders"
    )
    assert ask["rows"], "no rows for a grouping query; the table would not render"


def test_5_cols_is_a_list_of_names_present_in_the_rows(ask):
    """`const a = e.cols || Object.keys(t[0])` -- names absent from a row render blank."""
    cols = ask.get("cols")
    assert isinstance(cols, list) and cols, f"cols is {cols!r}"
    unknown = [c for c in cols if c not in ask["rows"][0]]
    assert not unknown, f"cols names columns the rows do not have: {unknown}"


def test_6_rows_are_objects_keyed_by_column_name(ask):
    """Values are read as `row[col]`; an array row renders as a row of blanks."""
    for index, row in enumerate(ask["rows"][:5]):
        assert isinstance(row, dict), (
            f"rows[{index}] is {type(row).__name__}; the bundle indexes rows by "
            "column name, so a list renders as empty cells"
        )
    for col in ask["cols"]:
        assert col in ask["rows"][0]


def test_6_row_values_survive_string_coercion(ask):
    """`String(row[col] ?? "")` must not produce "[object Object]" or "undefined"."""
    for row in ask["rows"][:5]:
        for col in ask["cols"]:
            value = row.get(col)
            assert not isinstance(value, (dict, list)), (
                f"{col}={value!r} would render as [object Object]"
            )


def test_7_a_non_sql_mode_still_carries_an_answer(client, monkeypatch):
    """The fall-through branch: `else r = e.answer || "(no answer)"`.

    A conceptual question uses only the knowledge-base tool, which is DOCS mode
    and legitimately has no rows -- and that must keep working.  The point of
    test 2 is that a *database* question must not land here, not that this
    branch is wrong.
    """
    from backend.app.agent import llm as agent_llm

    answer = "An evil twin is a rogue access point impersonating a real SSID."

    def fake_chat(messages: Any, **kwargs: Any) -> Any:
        if kwargs.get("tool_choice") == "none" or not kwargs.get("tools"):
            return SimpleNamespace(content=answer, tool_calls=None)
        if any(m.get("role") == "tool" for m in messages):
            return SimpleNamespace(content=answer, tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="docs_1", type="function",
                    function=SimpleNamespace(
                        name="explain_attack_class",
                        arguments=json.dumps({"attack_class": "Evil_Twin"}),
                    ),
                )
            ],
        )

    monkeypatch.setattr(agent_llm, "chat", fake_chat)
    ask_router.cache.store.clear()
    response = client.post("/ask", json={"question": "what is an evil twin?"})
    assert response.status_code == 200
    body = response.json()
    assert not body.get("error")
    assert body["mode"] == "DOCS", "only the knowledge tool ran"
    assert body["answer"].strip(), 'would render the literal "(no answer)"'


# --------------------------------------------------------------------------- #
# Request shape and failure modes                                              #
# --------------------------------------------------------------------------- #
def test_session_id_is_accepted(client, faked_model):
    """The bundle always sends `session_id`; rejecting it would 4xx every question."""
    response = client.post(
        "/ask", json={"question": "how many attacks?", "session_id": "abc-123"}
    )
    assert response.status_code == 200


def test_a_question_without_a_session_id_is_accepted(client, faked_model):
    assert client.post("/ask", json={"question": "how many attacks?"}).status_code == 200


def test_no_api_key_is_a_503(client, monkeypatch):
    """The bundle renders any non-2xx as a 'Network error' bubble -- the intended
    degradation. A 200 with an empty answer would look like a broken assistant."""
    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "")
    ask_router.cache.store.clear()
    response = client.post("/ask", json={"question": "anything at all"})
    assert response.status_code == 503
    assert response.json()["detail"]


def test_a_failed_run_reports_through_error_not_a_500(client, monkeypatch):
    """The bundle has an `e.error` branch; it has no handler for a 500 body."""
    from backend.app.agent import llm as agent_llm

    def exploding_chat(messages: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the upstream fell over")

    monkeypatch.setattr(agent_llm, "chat", exploding_chat)
    ask_router.cache.store.clear()
    response = client.post("/ask", json={"question": "break it"})
    assert response.status_code == 200, "an upstream failure must not become a 500"
    body = response.json()
    assert body["mode"] == "ERROR"
    assert body["error"], "the failure must arrive in `error`"


# --------------------------------------------------------------------------- #
# The rest of the surface the bundle calls                                     #
# --------------------------------------------------------------------------- #
def test_the_api_process_serves_the_built_pages(client):
    """A page 404ing means the static mount is missing or an API route shadowed it."""
    if not (settings.FRONTEND_DIST / "index.html").is_file():
        pytest.skip("no built frontend at FRONTEND_DIST; run `npm run build` in frontend/")
    for page in ("/", "/dashboard/", "/attacks/", "/rag/", "/admin/"):
        response = client.get(page)
        assert response.status_code == 200, f"{page} -> {response.status_code}"
        assert "text/html" in response.headers.get("content-type", "")


@pytest.mark.parametrize(
    "path",
    [
        "/health",
        "/attacks?limit=5&offset=0",
        "/attacks/analysis",
        "/packets/count",
        "/top-offenders",
        "/channel-usage",
        "/heatmap-attack",
        "/reports/summary?days=30",
    ],
)
def test_every_endpoint_the_bundle_calls_answers_200(client, path):
    assert client.get(path).status_code == 200


def test_attacks_analysis_carries_all_eight_classes(client):
    body = client.get("/attacks/analysis").json()
    for label in ATTACK_CLASSES:
        assert label in body, f"the dashboard zero-fills on {label!r}"
    assert all(isinstance(v, int) for v in body.values())


def test_top_offenders_uses_the_legacy_key(client):
    """`wlan_sa`, not `src_mac`: the built bundle depends on the historical name."""
    body = client.get("/top-offenders").json()
    assert isinstance(body, list)
    if body:
        assert "wlan_sa" in body[0] and "count" in body[0]


def test_report_summary_totals_cover_every_dashboard_key(client):
    totals = client.get("/reports/summary?days=30").json()["totals"]
    for key in list(FRONT_TYPES) + ["other"]:
        assert key in totals, f"the report page reads totals[{key!r}]"


def test_heatmap_is_seven_sunday_first_days_of_24_hours(client):
    body = client.get("/heatmap-attack").json()
    assert [entry["day"] for entry in body] == ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    for entry in body:
        assert len(entry["hours"]) == 24


def test_reports_export_is_a_pdf(client):
    response = client.post("/reports/export", json={"days": 30})
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")


def test_the_routes_the_bundle_needs_are_registered(client):
    """`/stream` and `/simulate` are not exercised here -- see check_frontend.py.

    ``/stream`` is an endless generator that no in-process transport can close
    cleanly, and ``/simulate`` loads the model and writes rows. Both are proven
    by the gate script; what matters in CI is that the static mount at ``/`` has
    not swallowed them, which is a routing fact.
    """
    paths = {route.path for route in app.routes}
    for path in ("/ask", "/stream", "/simulate", "/attacks", "/health"):
        assert path in paths, f"{path} is not registered"


# --------------------------------------------------------------------------- #
# Shim mode mapping                                                            #
# --------------------------------------------------------------------------- #
# `mode` is derived from which tools actually executed, never from anything the
# model says about itself -- the bundle renders its rows table on the literal
# "SQL" alone, so this field must not depend on a model's self-report.
def _chat_calling(tool: str, args: Dict[str, Any], answer: str):
    """A fake `llm.chat` that calls `tool` once, then answers."""

    def fake_chat(messages: Any, **kwargs: Any) -> Any:
        if kwargs.get("tool_choice") == "none" or not kwargs.get("tools"):
            return SimpleNamespace(content=answer, tool_calls=None)
        if any(m.get("role") == "tool" for m in messages):
            return SimpleNamespace(content=answer, tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="m1", type="function",
                    function=SimpleNamespace(name=tool, arguments=json.dumps(args)),
                )
            ],
        )

    return fake_chat


@pytest.mark.parametrize(
    "tool, args",
    [
        ("aggregate_threats", {"group_by": "label"}),
        ("query_threats", {"limit": 5}),
        ("threat_overview", {"days": 30}),
        ("system_status", {}),
    ],
)
def test_any_data_tool_yields_sql_mode(client, monkeypatch, tool, args):
    from backend.app.agent import llm as agent_llm

    monkeypatch.setattr(agent_llm, "chat", _chat_calling(tool, args, "Here you go."))
    ask_router.cache.store.clear()
    body = client.post("/ask", json={"question": f"use {tool}"}).json()
    assert body["mode"] == "SQL", f"{tool} reads packet data, so the table must render"


def test_only_the_knowledge_tool_yields_docs_mode(client, monkeypatch):
    from backend.app.agent import llm as agent_llm

    monkeypatch.setattr(
        agent_llm, "chat",
        _chat_calling("explain_attack_class", {"attack_class": "Deauth"}, "A deauth flood is..."),
    )
    ask_router.cache.store.clear()
    body = client.post("/ask", json={"question": "what is deauth?"}).json()
    assert body["mode"] == "DOCS"
    assert body["rows"] == []


def test_no_tool_at_all_yields_oos_mode(client, monkeypatch):
    from backend.app.agent import llm as agent_llm

    monkeypatch.setattr(
        agent_llm, "chat",
        lambda messages, **kw: SimpleNamespace(
            content="HawkShield answers questions about Wi-Fi attacks only.",
            tool_calls=None,
        ),
    )
    ask_router.cache.store.clear()
    body = client.post("/ask", json={"question": "what is the weather?"}).json()
    assert body["mode"] == "OOS"
    assert not body["error"]
    assert body["answer"]


def test_a_failed_tool_does_not_count_towards_the_mode(client, monkeypatch):
    """Only tools that actually succeeded may promote a run to SQL mode."""
    from backend.app.agent import llm as agent_llm

    monkeypatch.setattr(
        agent_llm, "chat",
        _chat_calling("explain_attack_class", {"attack_class": "ransomware"}, "Not a class."),
    )
    ask_router.cache.store.clear()
    body = client.post("/ask", json={"question": "what is ransomware?"}).json()
    assert body["mode"] == "OOS", "the only tool call failed, so no tool ran"


def test_sql_field_carries_the_real_select(client, faked_model):
    ask_router.cache.store.clear()
    body = client.post("/ask", json={"question": "how many by class?"}).json()
    assert body["mode"] == "SQL"
    assert body["sql"].upper().startswith("SELECT")
    assert "packets" in body["sql"]


# --------------------------------------------------------------------------- #
# The table allow-list now covers /ask too                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM documents",
        "SELECT name FROM sqlite_master",
        "SELECT * FROM pg_catalog.pg_tables",
        "SELECT table_name FROM information_schema.tables",
        "DELETE FROM packets",
    ],
)
def test_ask_can_no_longer_reach_anything_but_packets(client, monkeypatch, sql):
    """Closed at S5. The RAG path enforced SELECT-only but never a table allow-list.

    The model is made to ask for the forbidden query directly; the guard has to
    refuse it, and the refusal has to arrive as a tool error the model can read
    rather than as a 500.
    """
    from backend.app.agent import llm as agent_llm
    from backend.app.config import settings as app_settings

    monkeypatch.setattr(app_settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(
        agent_llm, "chat", _chat_calling("run_sql", {"sql": sql}, "That query was refused.")
    )
    ask_router.cache.store.clear()
    response = client.post("/ask", json={"question": f"run: {sql}"})
    assert response.status_code == 200
    body = response.json()
    # The tool failed, so no data tool succeeded and there are no rows.
    assert body["rows"] == []
    assert body["mode"] in ("OOS", "ERROR")


def test_ask_still_allows_a_legitimate_cte_over_packets(client, monkeypatch):
    """The allow-list must not be so blunt that it refuses real queries."""
    from backend.app.agent import llm as agent_llm
    from backend.app.config import settings as app_settings

    sql = (
        "WITH recent AS (SELECT predicted_label FROM packets) "
        "SELECT predicted_label, COUNT(*) AS n FROM recent GROUP BY predicted_label"
    )
    monkeypatch.setattr(app_settings, "SAQR_ALLOW_RAW_SQL", True)
    monkeypatch.setattr(agent_llm, "chat", _chat_calling("run_sql", {"sql": sql}, "Done."))
    ask_router.cache.store.clear()
    body = client.post("/ask", json={"question": "cte please"}).json()
    assert body["mode"] == "SQL"
    assert body["rows"], "a legitimate CTE over packets must still run"
