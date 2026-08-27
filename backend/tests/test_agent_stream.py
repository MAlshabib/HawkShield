"""Tests for the SSE transport on ``POST /agent/ask``.

No network, no OPENROUTER_API_KEY, no PostgreSQL.  Most tests stub the loop
itself: what is under test here is the *transport* -- ordering, framing,
termination and the pre-flight boundary -- not the agent's reasoning, which
``test_agent_loop.py`` already covers.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.agent import events, llm, loop, ratelimit  # noqa: E402
from backend.app.agent.events import Emitter  # noqa: E402
from backend.app.config import settings  # noqa: E402
from backend.app.db import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Packet  # noqa: E402
from backend.app.routers import agent as agent_router  # noqa: E402

SSE = {"Accept": "text/event-stream"}


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _agent_config(monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ENABLED", True)
    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(settings, "SAQR_DEFAULT_LOCALE", "en")
    monkeypatch.setattr(settings, "SAQR_STREAM_KEEPALIVE_S", 0.2)
    monkeypatch.setattr(settings, "SAQR_RATE_MAX", 100)
    monkeypatch.setattr(settings, "SAQR_MAX_CONCURRENT_RUNS", 4)
    ratelimit.reset_all()
    llm.reset_client()
    yield
    ratelimit.reset_all()
    llm.reset_client()


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    db_path: Path = tmp_path_factory.mktemp("saqr_stream") / "stream.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=eng)
    maker = sessionmaker(bind=eng, autocommit=False, autoflush=False)
    session = maker()
    try:
        session.add_all(
            [
                Packet(
                    src_mac="AA:BB:CC:DD:EE:01",
                    bssid="AA:AA:AA:AA:AA:01",
                    channel_freq=2437,
                    proba_attack=0.9,
                    predicted_label="Deauth",
                    raw={"iface": "wlan1"},
                )
                for _ in range(3)
            ]
        )
        session.commit()
    finally:
        session.close()
    yield eng
    eng.dispose()


@pytest.fixture()
def client(engine):
    def override_get_db():
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        session: Session = maker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_db, None)


# --------------------------------------------------------------------------- #
# SSE parsing helper                                                           #
# --------------------------------------------------------------------------- #
def parse_sse(body: str) -> Tuple[List[Tuple[str, Dict[str, Any]]], List[str]]:
    """Return ``([(event, data), ...], [comment, ...])`` from a raw SSE body."""
    frames: List[Tuple[str, Dict[str, Any]]] = []
    comments: List[str] = []
    for block in body.split("\n\n"):
        block = block.strip("\n")
        if not block:
            continue
        if block.startswith(":"):
            comments.append(block)
            continue
        name: Optional[str] = None
        data_lines: List[str] = []
        for line in block.split("\n"):
            if line.startswith("event: "):
                name = line[len("event: "):]
            elif line.startswith("data: "):
                data_lines.append(line[len("data: "):])
            elif line.startswith(":"):
                comments.append(line)
        if name is not None:
            frames.append((name, json.loads("\n".join(data_lines))))
    return frames, comments


def stub_run(*, emit, answer: str = "done.", raises: Optional[BaseException] = None):
    """Build a ``run_agent`` replacement that drives ``emit(emitter)`` then finishes."""

    async def fake_run_agent(question, **kwargs):
        emitter: Emitter = kwargs["emitter"]
        await emitter.run_start(
            question=question, locale=kwargs.get("locale") or "en",
            max_steps=6, tools=["query_threats"],
        )
        await emit(emitter)
        if raises is not None:
            await emitter.error(events.classify_error(raises), str(raises), fatal=True)
            await emitter.done(steps=1, tool_calls=0, elapsed_ms=1, stop_reason="error")
            raise raises
        await emitter.answer(answer, ["query_threats"])
        await emitter.done(steps=1, tool_calls=1, elapsed_ms=1, stop_reason="answered")
        return SimpleNamespace(answer=answer)

    return fake_run_agent


async def _nothing(emitter: Emitter) -> None:
    return None


# --------------------------------------------------------------------------- #
# Ordering and framing                                                         #
# --------------------------------------------------------------------------- #
def test_stream_starts_with_run_start_and_ends_with_done(client, monkeypatch):
    async def emit(emitter: Emitter) -> None:
        await emitter.status(events.PHASE_CALLING_MODEL, 1)
        await emitter.token("3 Deauth ")
        await emitter.token("frames.")

    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=emit))
    response = client.post("/agent/ask", json={"question": "how many?"}, headers=SSE)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    frames, _ = parse_sse(response.text)
    names = [name for name, _ in frames]
    assert names[0] == "run_start"
    assert names[-1] == "done"


def test_seq_is_strictly_increasing_with_no_gaps(client, monkeypatch):
    async def emit(emitter: Emitter) -> None:
        await emitter.status(events.PHASE_CALLING_MODEL, 1)
        await emitter.tool_call(
            step=1, call_id="c1", tool="query_threats",
            label_key="saqr.tool.query_threats", mutating=False, args={"limit": 5},
        )
        await emitter.tool_result(
            step=1, call_id="c1", tool="query_threats", ok=True,
            duration_ms=4, summary="3 row(s)", row_count=3,
        )
        for chunk in ("a", "b", "c"):
            await emitter.token(chunk)

    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=emit))
    response = client.post("/agent/ask", json={"question": "how many?"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    seqs = [data["seq"] for _, data in frames]
    assert seqs == list(range(len(seqs)))


def test_every_payload_carries_the_same_run_id(client, monkeypatch):
    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=_nothing))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    run_ids = {data["run_id"] for _, data in frames}
    assert len(run_ids) == 1
    assert len(run_ids.pop()) == 32  # uuid4 hex


def test_every_tool_call_has_a_matching_tool_result(client, monkeypatch):
    async def emit(emitter: Emitter) -> None:
        for call_id, tool in (("c1", "query_threats"), ("c2", "aggregate_threats")):
            await emitter.tool_call(
                step=1, call_id=call_id, tool=tool,
                label_key=f"saqr.tool.{tool}", mutating=False, args={},
            )
            await emitter.tool_result(
                step=1, call_id=call_id, tool=tool, ok=True,
                duration_ms=1, summary="ok",
            )

    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=emit))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    calls = {d["call_id"]: d for n, d in frames if n == "tool_call"}
    results = {d["call_id"]: d for n, d in frames if n == "tool_result"}
    assert set(calls) == set(results)
    for call_id, call in calls.items():
        assert results[call_id]["tool"] == call["tool"]
    # ...and each result comes *after* its call.
    order = [(n, d.get("call_id")) for n, d in frames if n in ("tool_call", "tool_result")]
    for call_id in calls:
        assert order.index(("tool_call", call_id)) < order.index(("tool_result", call_id))


def test_token_events_reassemble_into_the_answer(client, monkeypatch):
    async def emit(emitter: Emitter) -> None:
        for chunk in ("3 ", "Deauth ", "frames."):
            await emitter.token(chunk)

    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=emit, answer="3 Deauth frames."))
    response = client.post("/agent/ask", json={"question": "how many?"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    tokens = "".join(d["delta"] for n, d in frames if n == "token")
    answer = next(d for n, d in frames if n == "answer")
    assert tokens == answer["text"] == "3 Deauth frames."
    # The answer event carries the whole text, so a client never has to
    # reassemble tokens to persist a transcript.
    assert answer["used_tools"] == ["query_threats"]


def test_token_payload_is_minimal(client, monkeypatch):
    async def emit(emitter: Emitter) -> None:
        await emitter.token("x")

    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=emit))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    token = next(d for n, d in frames if n == "token")
    assert set(token) == {"run_id", "seq", "delta"}  # no ts on the hot path


# --------------------------------------------------------------------------- #
# Termination                                                                  #
# --------------------------------------------------------------------------- #
def test_a_run_that_errors_still_ends_with_done(client, monkeypatch):
    monkeypatch.setattr(
        agent_router, "run_agent",
        stub_run(emit=_nothing, raises=RuntimeError("openrouter exploded")),
    )
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    assert response.status_code == 200
    frames, _ = parse_sse(response.text)
    names = [name for name, _ in frames]
    assert "error" in names
    assert names[-1] == "done"
    error = next(d for n, d in frames if n == "error")
    assert error["fatal"] is True
    assert error["code"] in events.ERROR_CODES


def test_a_missing_key_mid_run_is_an_error_event_not_a_503(client, monkeypatch):
    """Once the stream is open the status is 200 forever; say so in-band."""
    monkeypatch.setattr(
        agent_router, "run_agent",
        stub_run(emit=_nothing, raises=llm.SaqrUnavailable("no key")),
    )
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    assert response.status_code == 200
    frames, _ = parse_sse(response.text)
    error = next(d for n, d in frames if n == "error")
    assert error["code"] == events.ERR_NO_API_KEY
    assert [n for n, _ in frames][-1] == "done"


def test_done_is_emitted_even_if_the_loop_forgets(client, monkeypatch):
    """The transport guarantees termination; it does not trust the loop to."""

    async def forgetful(question, **kwargs):
        emitter: Emitter = kwargs["emitter"]
        await emitter.run_start(
            question=question, locale="en", max_steps=6, tools=[],
        )
        return SimpleNamespace(answer="")

    monkeypatch.setattr(agent_router, "run_agent", forgetful)
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    assert [n for n, _ in frames][-1] == "done"


def test_done_is_emitted_at_most_once(client, monkeypatch):
    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=_nothing))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    assert [n for n, _ in frames].count("done") == 1


def test_done_reports_the_run_statistics(client, monkeypatch):
    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=_nothing))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, _ = parse_sse(response.text)
    done = next(d for n, d in frames if n == "done")
    assert done["stop_reason"] == "answered"
    assert {"steps", "tool_calls", "elapsed_ms", "ts"} <= set(done)


# --------------------------------------------------------------------------- #
# Keep-alive                                                                   #
# --------------------------------------------------------------------------- #
def test_a_slow_run_sends_keepalive_comments(client, monkeypatch):
    async def emit(emitter: Emitter) -> None:
        await asyncio.sleep(0.7)  # > 3 keep-alive ticks at 0.2s

    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=emit))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    frames, comments = parse_sse(response.text)
    assert comments, "a silent stream must still send : ka comments"
    assert all(c.startswith(":") for c in comments)
    assert [n for n, _ in frames][-1] == "done"


def test_keepalive_comments_are_not_events(client, monkeypatch):
    """A comment must not reach the client's message handler as data."""
    assert events.KEEPALIVE_FRAME.startswith(":")
    assert "event:" not in events.KEEPALIVE_FRAME
    assert "data:" not in events.KEEPALIVE_FRAME


# --------------------------------------------------------------------------- #
# Headers                                                                      #
# --------------------------------------------------------------------------- #
def test_proxy_buffering_is_disabled(client, monkeypatch):
    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=_nothing))
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    # Without this nginx buffers the whole body and the pane looks frozen.
    assert response.headers["x-accel-buffering"] == "no"
    assert response.headers["cache-control"] == "no-cache"


# --------------------------------------------------------------------------- #
# Pre-flight happens before the stream opens                                   #
# --------------------------------------------------------------------------- #
def test_no_api_key_is_a_json_503_not_an_event_stream(client, monkeypatch):
    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "")
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["detail"] == (
        "OPENROUTER_API_KEY is not configured; the assistant is disabled."
    )


def test_disabled_agent_is_a_json_503_not_an_event_stream(client, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_ENABLED", False)
    response = client.post("/agent/ask", json={"question": "hi"}, headers=SSE)

    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/json")


def test_bad_body_is_a_json_400_not_an_event_stream(client):
    response = client.post("/agent/ask", json={"question": ""}, headers=SSE)
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/json")


def test_rate_limit_is_a_json_429_not_an_event_stream(client, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_RATE_MAX", 1)
    ratelimit.reset_all()
    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=_nothing))

    body = {"question": "hi"}
    assert client.post("/agent/ask", json=body, headers=SSE).status_code == 200
    second = client.post("/agent/ask", json=body, headers=SSE)
    assert second.status_code == 429
    assert second.headers["content-type"].startswith("application/json")
    assert "Retry-After" in second.headers


def test_the_concurrency_slot_is_released_when_the_stream_ends(client, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_MAX_CONCURRENT_RUNS", 1)
    ratelimit.reset_all()
    monkeypatch.setattr(agent_router, "run_agent", stub_run(emit=_nothing))

    for _ in range(3):
        assert client.post("/agent/ask", json={"question": "hi"}, headers=SSE).status_code == 200
    assert ratelimit.gate().in_flight == 0


# --------------------------------------------------------------------------- #
# Content negotiation — the JSON transport is untouched                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "accept", [None, "application/json", "*/*", "text/html,application/xhtml+xml"]
)
def test_non_sse_clients_still_get_json(client, monkeypatch, accept):
    async def fake_run_agent(question, **kwargs):
        return loop.AgentResult(
            answer="json path", locale="en", model="stub", steps=1, run_id="abc"
        )

    monkeypatch.setattr(agent_router, "run_agent", fake_run_agent)
    headers = {"Accept": accept} if accept else {}
    response = client.post("/agent/ask", json={"question": "hi"}, headers=headers)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["answer"] == "json path"


def test_wants_sse_only_on_an_explicit_accept():
    def request_with(accept):
        return SimpleNamespace(headers={"accept": accept} if accept is not None else {})

    assert agent_router._wants_sse(request_with("text/event-stream")) is True
    assert agent_router._wants_sse(request_with("text/event-stream, */*")) is True
    assert agent_router._wants_sse(request_with("TEXT/EVENT-STREAM")) is True
    assert agent_router._wants_sse(request_with("*/*")) is False
    assert agent_router._wants_sse(request_with("application/json")) is False
    assert agent_router._wants_sse(request_with(None)) is False


# --------------------------------------------------------------------------- #
# The Emitter itself                                                           #
# --------------------------------------------------------------------------- #
def test_sse_frames_are_single_line_data():
    frame = events.sse("answer", {"text": "line one\nline two", "seq": 0})
    body = [ln for ln in frame.split("\n") if ln.startswith("data: ")]
    assert len(body) == 1, "a newline in the payload must not split the data field"
    assert json.loads(body[0][len("data: "):])["text"] == "line one\nline two"


def test_a_disabled_emitter_emits_nothing():
    emitter = events.coerce_emitter(None)
    asyncio.run(emitter.status(events.PHASE_COMPOSING, 1))
    assert emitter.seq == 0
    assert emitter.queue is None


def test_a_plain_callable_is_wrapped_and_still_sees_stamped_payloads():
    seen: List[Dict[str, Any]] = []
    emitter = events.coerce_emitter(lambda event, data: seen.append(data))
    asyncio.run(emitter.status(events.PHASE_COMPOSING, 2))
    assert seen[0]["seq"] == 0
    assert seen[0]["run_id"] == emitter.run_id


def test_an_emitter_passes_through_coercion():
    emitter = events.Emitter("fixed-run-id")
    assert events.coerce_emitter(emitter) is emitter


def test_error_codes_are_confined_to_the_published_vocabulary():
    emitter = events.Emitter(buffered=True)
    asyncio.run(emitter.error("not_a_real_code", "boom"))
    _event, data = emitter.queue.get_nowait()
    assert data["code"] == events.ERR_INTERNAL


@pytest.mark.parametrize(
    "error_type, expected",
    [
        ("invalid_arguments", events.ERR_BAD_ARGS),
        ("unknown_class", events.ERR_BAD_ARGS),
        ("rejected_sql", events.ERR_BAD_ARGS),
        ("budget_exhausted", events.ERR_STEP_LIMIT),
        ("tool_timeout", events.ERR_TIMEOUT),
        ("time_budget_exhausted", events.ERR_TIMEOUT),
        ("sql_error", events.ERR_TOOL),
        ("tool_failed", events.ERR_TOOL),
        ("unknown_tool", events.ERR_TOOL),
    ],
)
def test_tool_error_types_map_onto_published_codes(error_type, expected):
    assert events.tool_error_code({"type": error_type}) == expected
    assert expected in events.ERROR_CODES


def test_tool_error_code_is_none_for_a_success():
    assert events.tool_error_code(None) is None


def test_a_credit_failure_is_not_reported_as_a_model_error():
    """402 is the likeliest live failure; 'model_error' sends the operator wrong."""
    assert events.classify_error(RuntimeError("Error code: 402 - insufficient credit")) == (
        events.ERR_NO_CREDIT
    )
    assert events.classify_error(RuntimeError("upstream 500")) == events.ERR_MODEL
    assert events.classify_error(llm.SaqrUnavailable("no key")) == events.ERR_NO_API_KEY


# --------------------------------------------------------------------------- #
# The real loop, streaming, with a faked SDK                                   #
# --------------------------------------------------------------------------- #
def test_the_real_loop_streams_only_the_final_turn(engine, monkeypatch):
    """Tool-selection turns must stay non-streaming; only composing streams."""
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 2)
    monkeypatch.setattr(settings, "SAQR_ALLOW_RAW_SQL", False)
    monkeypatch.setattr(settings, "SAQR_ALLOW_SIMULATION_TOOL", False)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    chat_calls: List[Dict[str, Any]] = []
    stream_calls: List[Dict[str, Any]] = []

    def fake_chat(messages, **kwargs):
        chat_calls.append(kwargs)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="c1",
                    type="function",
                    function=SimpleNamespace(
                        name="aggregate_threats",
                        arguments=json.dumps({"group_by": "label"}),
                    ),
                )
            ],
        )

    def fake_chat_stream(messages, **kwargs) -> Iterator[str]:
        stream_calls.append(kwargs)
        yield from ("3 ", "Deauth ", "frames.")

    monkeypatch.setattr(llm, "chat", fake_chat)
    monkeypatch.setattr(llm, "chat_stream", fake_chat_stream)

    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    result = asyncio.run(
        loop.run_agent(
            "how many?", session_factory=maker, emitter=emitter, stream_tokens=True
        )
    )

    assert result.answer == "3 Deauth frames."
    # Every tool-selection turn went through the non-streaming client...
    assert len(chat_calls) == 2
    assert all(call["tool_choice"] == "auto" for call in chat_calls)
    # ...and exactly one streamed turn, forced to tool_choice="none".
    assert len(stream_calls) == 1
    assert stream_calls[0]["tool_choice"] == "none"

    tokens = "".join(d["delta"] for e, d in seen if e == "token")
    assert tokens == "3 Deauth frames."
    assert [e for e, _ in seen][-1] == "done"


def test_streaming_falls_back_when_the_provider_refuses(engine, monkeypatch):
    """A provider that will not stream must not cost the user their answer."""
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def fake_chat(messages, **kwargs):
        if kwargs.get("tool_choice") == "none":
            return SimpleNamespace(content="unstreamed answer", tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="c1", type="function",
                    function=SimpleNamespace(name="system_status", arguments="{}"),
                )
            ],
        )

    def refusing_stream(messages, **kwargs):
        raise RuntimeError("this model does not support stream=true")
        yield  # pragma: no cover - generator marker

    monkeypatch.setattr(llm, "chat", fake_chat)
    monkeypatch.setattr(llm, "chat_stream", refusing_stream)

    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    result = asyncio.run(
        loop.run_agent(
            "status?", session_factory=maker, emitter=emitter, stream_tokens=True
        )
    )

    assert result.answer == "unstreamed answer"
    # The provider refusing to stream must not degrade the client's experience:
    # the answer is replayed as tokens, so the event sequence is unchanged.
    tokens = "".join(d["delta"] for e, d in seen if e == "token")
    assert tokens == "unstreamed answer"
    assert [e for e, _ in seen][-1] == "done"


def test_an_answer_from_a_tool_selection_turn_is_still_tokenised(engine, monkeypatch):
    """The common case, and the one a live run showed was silently unstreamed.

    The model normally stops calling tools and just answers, on a turn that is
    deliberately *not* streamed.  Without a replay that answer would land in the
    pane as one jump and ``token`` would fire only on the rare step-limit path.
    """
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 4)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    answer = "The worst offender is AA:BB:CC:DD:EE:01, with 3 detected frames."

    calls: List[Dict[str, Any]] = []

    def fake_chat(messages, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            return SimpleNamespace(
                content="",
                tool_calls=[
                    SimpleNamespace(
                        id="c1", type="function",
                        function=SimpleNamespace(
                            name="aggregate_threats",
                            arguments=json.dumps({"group_by": "src_mac"}),
                        ),
                    )
                ],
            )
        return SimpleNamespace(content=answer, tool_calls=None)

    def unused_stream(messages, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("a tool-selection turn must never be streamed")
        yield

    monkeypatch.setattr(llm, "chat", fake_chat)
    monkeypatch.setattr(llm, "chat_stream", unused_stream)

    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    result = asyncio.run(
        loop.run_agent(
            "worst offender?", session_factory=maker, emitter=emitter, stream_tokens=True
        )
    )

    assert result.stop_reason == "answered"
    names = [e for e, _ in seen]
    assert names.count("token") > 1, "the answer must arrive in fragments, not one jump"
    assert "".join(d["delta"] for e, d in seen if e == "token") == answer
    # Ordering the client relies on: every token precedes the answer event.
    assert names.index("answer") > max(i for i, n in enumerate(names) if n == "token")
    assert names[-1] == "done"


def test_tokens_are_split_on_word_boundaries(engine, monkeypatch):
    """A mid-word split reads as a glitch rather than as typing."""
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    answer = "Deauth frames dominate, with AA:BB:CC:DD:EE:01 as the loudest source here."
    monkeypatch.setattr(
        llm, "chat", lambda messages, **kw: SimpleNamespace(content=answer, tool_calls=None)
    )

    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    asyncio.run(
        loop.run_agent("hi", session_factory=maker, emitter=emitter, stream_tokens=True)
    )

    deltas = [d["delta"] for e, d in seen if e == "token"]
    assert "".join(deltas) == answer
    # Every fragment except the last ends at whitespace, so no word is cut.
    for delta in deltas[:-1]:
        assert delta[-1].isspace(), f"fragment {delta!r} splits a word"


def test_no_tokens_are_emitted_when_the_transport_is_not_streaming(engine, monkeypatch):
    """The JSON path must not pay for event construction it will never send."""
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(
        llm, "chat", lambda messages, **kw: SimpleNamespace(content="plain", tool_calls=None)
    )

    seen: List[str] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append(e))
    asyncio.run(loop.run_agent("hi", session_factory=maker, emitter=emitter))

    assert "token" not in seen
    assert seen[-1] == "done"


def test_an_arabic_correction_replaces_the_streamed_text(engine, monkeypatch):
    """The user must not be shown English tokens and then an Arabic answer."""
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    monkeypatch.setattr(settings, "SAQR_DEFAULT_LOCALE", "ar")
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    replies = [
        SimpleNamespace(content="3 Deauth frames were detected.", tool_calls=None),
        SimpleNamespace(content="تم رصد 3 إطارات Deauth.", tool_calls=None),
    ]

    def fake_chat(messages, **kwargs):
        return replies.pop(0) if replies else SimpleNamespace(content="", tool_calls=None)

    monkeypatch.setattr(llm, "chat", fake_chat)
    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    result = asyncio.run(
        loop.run_agent(
            "كم؟", locale="ar", session_factory=maker, emitter=emitter, stream_tokens=True
        )
    )

    assert result.answer == "تم رصد 3 إطارات Deauth."
    tokens = "".join(d["delta"] for e, d in seen if e == "token")
    assert tokens == result.answer
    assert "were detected" not in tokens


def test_tool_call_events_publish_validated_arguments(engine, monkeypatch):
    """A hallucinated field must never render in the UI as though it was accepted."""
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def fake_chat(messages, **kwargs):
        if kwargs.get("tool_choice") == "none":
            return SimpleNamespace(content="done", tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="c1", type="function",
                    function=SimpleNamespace(
                        name="query_threats",
                        arguments=json.dumps({"limit": 5, "label": "deauthentication"}),
                    ),
                )
            ],
        )

    monkeypatch.setattr(llm, "chat", fake_chat)
    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    asyncio.run(loop.run_agent("show me", session_factory=maker, emitter=emitter))

    call = next(d for e, d in seen if e == "tool_call")
    assert call["tool"] == "query_threats"
    assert call["label_key"] == "saqr.tool.query_threats"
    assert call["mutating"] is False
    # The validated model: non-None defaults are present (they are what the tool
    # will actually do)...
    assert call["args"]["limit"] == 5
    assert call["args"]["order"] == "newest"
    # ...the plain-language label survives as the model sent it, because
    # resolution to the DB spelling happens inside the tool...
    assert call["args"]["label"] == "deauthentication"
    # ...unset optional filters are omitted rather than sent as eight nulls...
    assert "src_mac" not in call["args"]
    assert "min_confidence" not in call["args"]
    # ...and a field the schema does not define never appears.
    assert "nonsense" not in call["args"]


def test_tool_call_event_for_an_unknown_tool_is_keyed_not_raw(engine, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def fake_chat(messages, **kwargs):
        if kwargs.get("tool_choice") == "none":
            return SimpleNamespace(content="sorry", tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="c1", type="function",
                    function=SimpleNamespace(name="invented_tool", arguments="{}"),
                )
            ],
        )

    monkeypatch.setattr(llm, "chat", fake_chat)
    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    asyncio.run(loop.run_agent("do it", session_factory=maker, emitter=emitter))

    call = next(d for e, d in seen if e == "tool_call")
    assert call["label_key"] == "saqr.tool.unknown"
    assert call["args"] == {}
    result = next(d for e, d in seen if e == "tool_result")
    assert result["ok"] is False
    assert result["error"]["code"] in events.ERROR_CODES


def test_tool_result_events_carry_a_summary_and_compact_data(engine, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def fake_chat(messages, **kwargs):
        if kwargs.get("tool_choice") == "none":
            return SimpleNamespace(content="3 Deauth.", tool_calls=None)
        return SimpleNamespace(
            content="",
            tool_calls=[
                SimpleNamespace(
                    id="c1", type="function",
                    function=SimpleNamespace(
                        name="aggregate_threats",
                        arguments=json.dumps({"group_by": "label"}),
                    ),
                )
            ],
        )

    monkeypatch.setattr(llm, "chat", fake_chat)
    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    asyncio.run(loop.run_agent("how many?", session_factory=maker, emitter=emitter))

    result = next(d for e, d in seen if e == "tool_result")
    assert result["ok"] is True
    assert result["call_id"] == "c1"
    assert "group(s) by label" in result["summary"]
    assert result["data"]["groups"] == [{"key": "Deauth", "count": 3}]
    assert result["sql_preview"].upper().startswith("SELECT")
    assert result["error"] is None
    # data must not repeat what the event already carries in its own fields.
    assert "sql_preview" not in result["data"]
    assert "ok" not in result["data"]


def test_status_events_use_only_the_published_phases(engine, monkeypatch):
    monkeypatch.setattr(settings, "SAQR_MAX_STEPS", 1)
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def fake_chat(messages, **kwargs):
        return SimpleNamespace(content="hello", tool_calls=None)

    monkeypatch.setattr(llm, "chat", fake_chat)
    seen: List[Tuple[str, Dict[str, Any]]] = []
    emitter = events.Emitter(buffered=False, forward=lambda e, d: seen.append((e, d)))
    asyncio.run(loop.run_agent("hi", session_factory=maker, emitter=emitter))

    phases = {d["phase"] for e, d in seen if e == "status"}
    assert phases
    assert phases <= set(events.PHASES)


def test_compact_drops_an_oversized_payload_rather_than_half_serialising_it():
    from backend.app.agent import tools as tools_module

    huge = {"ok": True, "tool": "run_sql", "rows": [{"blob": "x" * 400} for _ in range(200)]}
    data = tools_module.compact("run_sql", huge, max_rows=200)
    assert data == {
        "omitted": True,
        "reason": "result too large for the event stream; see the answer text",
    }
