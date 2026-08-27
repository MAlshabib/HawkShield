"""The Saqr agent loop: model turn -> tool calls -> model turn -> prose answer.

Everything here is bounded, and every bound has a defined outcome:

* ``SAQR_MAX_STEPS`` model turns may call tools.  Exhausting them does not end
  the run -- it forces one final turn with ``tool_choice="none"``, so the user
  always gets prose rather than a blank answer.
* ``SAQR_MAX_TOOL_CALLS`` tool executions per run.  A refused call is reported to
  the model as a normal tool result ("budget exhausted, answer with what you
  have") rather than raised.
* ``SAQR_TOOL_TIMEOUT_S`` per tool and ``SAQR_RUN_TIMEOUT_S`` per run.  A run
  that runs out of time stops calling tools and goes straight to the final turn.
* Repeated calls are not re-executed.  The key is ``(tool, canonical json of
  args)``; a repeat returns the cached result with a note telling the model it
  has already asked this, which is what actually breaks a stuck model out of a
  loop -- an error would just make it try again with a tweak.

Tools run in ``asyncio.to_thread`` against a ``sessionmaker`` bound to the
request's engine, the pattern ``routers/stream.py`` and ``routers/simulate.py``
already use.  Nothing here opens an HTTP connection back into this process.

Bad tool names and arguments that fail validation are results, never exceptions:
the model reads the error and corrects itself, which is the whole point of using
a tool-calling model rather than a single-shot one.

**Capability is an argument, not a conversation.**  ``run_agent`` takes
``is_admin`` and ``confirmation`` as plain Python parameters.  The router
resolves both from request headers *before* this function is entered, and
nothing inside the loop recomputes them: no model turn, no tool result and no
string from the database can reach the code that decided them.  The registry is
built from ``is_admin`` once, so a non-admin run is not a run whose admin calls
are refused -- it is a run in which the admin tools have no names.

The one value that flows the other way is a confirmation token, and it is
deliberately blocked: :func:`_redact_for_model` removes ``confirm_token`` from
every tool result before it becomes a ``role: "tool"`` message, while the
``tool_result`` event keeps it for the operator's UI.  So the model can report
that a confirmation is needed and cannot supply one.

**Streaming.**  Only the final ``tool_choice="none"`` composing turn streams, as
``token`` events.  The intermediate tool-selection turns are deliberately *not*
streamed -- see :func:`backend.app.agent.llm.chat_stream` for why reassembling
streamed tool-call fragments is a bug factory, and note that the
``status`` / ``tool_call`` / ``tool_result`` events already give the UI its
motion during those turns.  A run emits ``done`` exactly once and always last,
including after a fatal error.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from backend.app.agent import events as ev
from backend.app.agent import llm, tools as tools_module
from backend.app.agent.confirm import Confirmation
from backend.app.agent.events import Emitter
from backend.app.agent.llm import SaqrUnavailable
from backend.app.agent.prompts import build_system_prompt
from backend.app.agent.tools import ToolContext, ToolSpec
from backend.app.config import settings

logger = logging.getLogger(__name__)

__all__ = ["AgentResult", "ToolCallRecord", "run_agent"]

#: Any Arabic-script codepoint.  Used only to detect an ``ar`` run that came back
#: in English, which is the failure mode a cheap model actually has.
_ARABIC_RE = re.compile(
    r"[؀-ۿݐ-ݿࢠ-ࣿﭐ-﷿ﹰ-﻿]"
)

EmitterArg = Union[Emitter, Callable[[str, Dict[str, Any]], Any], None]
SessionFactory = Optional[Callable[[], Any]]


@dataclass
class ToolCallRecord:
    """One tool execution, as reported to the caller and on the event stream."""

    step: int
    name: str
    arguments: Dict[str, Any]
    ok: bool
    duration_ms: int
    cached: bool = False
    sql_preview: Optional[str] = None
    row_count: Optional[int] = None
    error: Optional[Dict[str, Any]] = None


@dataclass
class AgentResult:
    """The outcome of one ``/agent/ask``."""

    answer: str
    locale: str
    model: str
    steps: int
    #: uuid4 hex; every event of this run carries it.
    run_id: str = ""
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    #: The last SQL a tool actually ran, so the UI can show it as ``/ask`` does.
    sql: Optional[str] = None
    #: Rows from the last tool that produced any, capped at ``SAQR_UI_ROWS``.
    cols: List[str] = field(default_factory=list)
    rows: List[Dict[str, Any]] = field(default_factory=list)
    #: ``answered`` | ``step_limit`` | ``call_limit`` | ``timeout`` | ``error``
    stop_reason: str = "answered"
    error: Optional[str] = None
    elapsed_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["tool_calls"] = [asdict(c) if not isinstance(c, dict) else c for c in self.tool_calls]
        return data


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _canonical(args: Dict[str, Any]) -> str:
    """A stable string for ``(tool, args)`` de-duplication."""
    try:
        return json.dumps(args or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(sorted((args or {}).items()))


def _truncate(payload: str, limit: int) -> Tuple[str, bool]:
    """Cap one tool result so a wide query cannot fill the context window."""
    if len(payload) <= limit:
        return payload, False
    head = payload[: max(0, limit - 200)]
    return (
        head
        + '\n... [truncated: this result was too large to include in full. '
        + 'Narrow the filter, lower the limit, or aggregate instead of listing rows.]',
        True,
    )


def _run_tool_sync(
    name: str,
    args: Dict[str, Any],
    session_factory: SessionFactory,
    registry: Dict[str, ToolSpec],
    ctx: ToolContext,
) -> Dict[str, Any]:
    """Execute one tool on a worker thread, with its own short-lived session."""
    spec = registry.get(name)
    if spec is not None and spec.needs_db and session_factory is not None:
        session = session_factory()
        try:
            return tools_module.execute(name, args, session, registry, ctx)
        finally:
            session.close()
    return tools_module.execute(name, args, None, registry, ctx)


def _redact_for_model(result: Dict[str, Any]) -> Dict[str, Any]:
    """The tool result as the *model* may see it.

    Strips ``confirm_token``.  A destructive tool mints that token for the
    operator's client, which returns it in a request header; putting it in front
    of the model would hand the model the one value it would need to authorise
    its own destructive call in the very next turn.  So the model is told a
    confirmation exists and is never told what it is, which makes "the model
    cannot confirm its own delete" a property of the data flow rather than a
    hope about the model's behaviour.

    The ``tool_result`` event is built from the *unredacted* result, so the UI
    still receives the token it needs.
    """
    if not any(key in result for key in tools_module.CLIENT_ONLY_FIELDS):
        return result
    redacted = {k: v for k, v in result.items() if k not in tools_module.CLIENT_ONLY_FIELDS}
    redacted["confirmation"] = (
        "A confirmation token was issued to the operator's interface. You have "
        "not been given it and cannot use it. Report the proposal and ask the "
        "operator to confirm."
    )
    return redacted


def _assistant_message(message: Any, calls: Sequence[Any]) -> Dict[str, Any]:
    """Re-serialise the assistant turn so it can be replayed in the next request."""
    return {
        "role": "assistant",
        "content": getattr(message, "content", None) or "",
        "tool_calls": [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments or "{}",
                },
            }
            for call in calls
        ],
    }


def _parse_arguments(call: Any) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Decode a tool call's JSON arguments, or describe why they could not be."""
    raw = getattr(call.function, "arguments", None) or "{}"
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        return {}, {
            "type": "invalid_arguments",
            "message": f"Your arguments were not valid JSON: {exc}",
            "hint": "Emit a JSON object matching the tool's schema.",
        }
    if not isinstance(parsed, dict):
        return {}, {
            "type": "invalid_arguments",
            "message": f"Arguments must be a JSON object, got {type(parsed).__name__}.",
        }
    return parsed, None


def _harvest_rows(result: Dict[str, Any]) -> Tuple[Optional[str], List[str], List[Dict[str, Any]]]:
    """Pull ``(sql, cols, rows)`` out of a tool result for the response envelope."""
    sql = result.get("sql_preview")
    rows = result.get("rows")
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        cols = list(result.get("columns") or rows[0].keys())
        return sql, cols, rows
    groups = result.get("groups")
    if isinstance(groups, list) and groups and isinstance(groups[0], dict):
        return sql, list(groups[0].keys()), groups
    return sql, [], []


async def _with_beats(
    awaitable: Any, emitter: Emitter, phase: str, step: int, interval: float
) -> Any:
    """Await ``awaitable``, emitting a liveness ``status`` beat every ``interval``.

    A model call routinely takes several seconds with nothing to report.  Without
    a beat the stream is silent, which is indistinguishable from a hung run --
    both to the user watching the pane and to any proxy's idle timer.
    """
    task = asyncio.ensure_future(awaitable)
    if interval <= 0 or not emitter.enabled:
        return await task
    try:
        while True:
            done, _pending = await asyncio.wait({task}, timeout=interval)
            if task in done:
                return task.result()
            await emitter.status(phase, step)
    except BaseException:
        if not task.done():
            task.cancel()
        raise


async def _stream_final_answer(
    messages: List[Dict[str, Any]],
    tool_defs: List[Dict[str, Any]],
    model: str,
    emitter: Emitter,
) -> str:
    """Run the composing turn with ``stream=True``, emitting one ``token`` per delta.

    The SDK's stream is a blocking generator, so it is driven on a worker thread
    and its chunks are handed to the event loop through a queue.  Any failure is
    re-raised for the caller to fall back to a plain non-streaming turn: a
    provider that will not stream must not cost the user their answer.
    """
    running_loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def worker() -> None:
        try:
            for delta in llm.chat_stream(
                messages, tools=tool_defs, tool_choice="none", model=model
            ):
                running_loop.call_soon_threadsafe(queue.put_nowait, ("delta", delta))
        except BaseException as exc:  # noqa: BLE001 - handed back, not swallowed
            running_loop.call_soon_threadsafe(queue.put_nowait, ("error", exc))
        finally:
            running_loop.call_soon_threadsafe(queue.put_nowait, ("end", None))

    worker_task = asyncio.create_task(asyncio.to_thread(worker))
    parts: List[str] = []
    failure: Optional[BaseException] = None
    try:
        while True:
            kind, value = await queue.get()
            if kind == "delta":
                parts.append(str(value))
                await emitter.token(str(value))
            elif kind == "error":
                failure = value
            else:
                break
    finally:
        await asyncio.gather(worker_task, return_exceptions=True)

    if failure is not None:
        raise failure
    return "".join(parts)


# --------------------------------------------------------------------------- #
# The loop                                                                     #
# --------------------------------------------------------------------------- #
async def run_agent(
    question: str,
    *,
    locale: Optional[str] = None,
    session_factory: SessionFactory = None,
    emitter: EmitterArg = None,
    registry: Optional[Dict[str, ToolSpec]] = None,
    model: Optional[str] = None,
    run_id: Optional[str] = None,
    stream_tokens: bool = False,
    is_admin: bool = False,
    confirmation: Optional[Confirmation] = None,
) -> AgentResult:
    """Answer ``question`` by calling tools, and return the finished answer.

    ``session_factory`` is a zero-argument callable returning a SQLAlchemy
    ``Session`` -- a ``sessionmaker`` bound to the request's engine, so a
    ``get_db`` dependency override is honoured.

    ``is_admin`` and ``confirmation`` are the request's capability, resolved by
    the router from ``SAQR_ADMIN_TOKEN`` and ``X-HawkShield-Confirm`` *before*
    this coroutine is entered.  They are ordinary arguments and are never
    re-derived from the conversation: the registry is built from ``is_admin``
    once, at the top, so a non-admin run is one in which the operator tools were
    never named to the model, and ``confirmation`` is re-validated against the
    server's own store at the moment it is spent.

    ``emitter`` is an :class:`~backend.app.agent.events.Emitter`, a plain
    ``(event, payload)`` callable, or ``None``.  ``stream_tokens`` additionally
    streams the final composing turn as ``token`` events; it needs an emitter to
    be of any use, and falls back to a single non-streaming call if the provider
    refuses ``stream=True``.

    The run emits ``done`` exactly once, always last, on every path including a
    fatal one.  ``SaqrUnavailable`` is still re-raised afterwards so the JSON
    transport can answer 503.
    """
    started = time.monotonic()
    em = ev.coerce_emitter(emitter, run_id)

    loc = str(locale or settings.SAQR_DEFAULT_LOCALE or "en").strip().lower()
    if loc not in ("en", "ar"):
        loc = "en"
    active_model = model or settings.saqr_model
    admin = bool(is_admin)
    ctx = ToolContext(is_admin=admin, confirmation=confirmation)
    specs = (
        registry
        if registry is not None
        else tools_module.build_registry(is_admin=admin)
    )
    tool_defs = tools_module.tool_definitions(specs)

    max_steps = int(settings.SAQR_MAX_STEPS)
    max_calls = int(settings.SAQR_MAX_TOOL_CALLS)
    tool_timeout = float(settings.SAQR_TOOL_TIMEOUT_S)
    max_chars = int(settings.SAQR_MAX_TOOL_CHARS)
    ui_rows = int(settings.SAQR_UI_ROWS)
    beat = float(settings.SAQR_STREAM_KEEPALIVE_S)
    deadline = started + float(settings.SAQR_RUN_TIMEOUT_S)

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": build_system_prompt(loc, is_admin=admin)},
        {"role": "user", "content": question.strip()},
    ]

    result = AgentResult(
        answer="", locale=loc, model=active_model, steps=0, run_id=em.run_id
    )
    seen: Dict[str, Dict[str, Any]] = {}
    calls_used = 0
    stop_reason = "step_limit"
    #: True once the answer the user will read has been emitted as tokens.
    streamed = False

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    def used_tools() -> List[str]:
        ordered: List[str] = []
        for call in result.tool_calls:
            if call.ok and call.name not in ordered:
                ordered.append(call.name)
        return ordered

    # Emitted (and, on the SSE path, flushed) before the first model call: the
    # pane must not sit blank through 1-3s of first-token latency.
    # The model identifier is deliberately absent from the event: it is a server
    # detail the client has no use for. It is logged here instead, where an
    # operator debugging a run can find it and a visitor cannot.
    logger.info(
        "Saqr run %s starting: locale=%s model=%s admin=%s tools=%d",
        em.run_id, loc, active_model, admin, len(specs),
    )
    await em.run_start(
        question=question.strip(), locale=loc,
        max_steps=max_steps, tools=list(specs), is_admin=admin,
    )

    try:
        for step in range(1, max_steps + 1):
            result.steps = step
            await em.status(ev.PHASE_CALLING_MODEL, step)

            message = await _with_beats(
                asyncio.to_thread(
                    llm.chat, messages, tools=tool_defs, tool_choice="auto", model=active_model
                ),
                em, ev.PHASE_CALLING_MODEL, step, beat,
            )
            calls = list(getattr(message, "tool_calls", None) or [])

            if not calls:
                result.answer = (getattr(message, "content", "") or "").strip()
                stop_reason = "answered"
                break

            messages.append(_assistant_message(message, calls))

            for call in calls:
                name = call.function.name
                call_id = getattr(call, "id", "") or f"call_{uuid.uuid4().hex[:8]}"
                args, parse_error = _parse_arguments(call)
                started_call = time.monotonic()

                # Publish the *validated* arguments, never the model's raw ones:
                # a hallucinated field must not render in the UI as though the
                # tool had accepted it.  When validation fails there are no
                # validated arguments, so the event carries {} and the error
                # arrives in the tool_result that immediately follows.
                validated, validation_error = tools_module.validate_args(name, args, specs)
                spec = specs.get(name)
                await em.status(ev.PHASE_EXECUTING_TOOL, step)
                await em.tool_call(
                    step=step,
                    call_id=call_id,
                    tool=name,
                    label_key=spec.label_key if spec else "saqr.tool.unknown",
                    mutating=bool(spec.mutating) if spec else False,
                    # exclude_none: every filter defaults to None meaning "not
                    # applied", and eight explicit nulls in the payload is noise
                    # a UI would have to filter back out.  Non-None defaults
                    # (group_by, limit, order) are kept -- they are what the tool
                    # will actually do, which is exactly what the operator wants
                    # to see next to the result.
                    args=validated.model_dump(exclude_none=True) if validated else {},
                )

                if parse_error is not None:
                    payload = {"ok": False, "tool": name, "error": parse_error}
                    record = ToolCallRecord(
                        step=step, name=name, arguments={}, ok=False,
                        duration_ms=0, error=parse_error,
                    )
                elif validation_error is not None:
                    payload = {"ok": False, "tool": name, "error": validation_error}
                    record = ToolCallRecord(
                        step=step, name=name, arguments={}, ok=False,
                        duration_ms=0, error=validation_error,
                    )
                elif calls_used >= max_calls:
                    error = {
                        "type": "budget_exhausted",
                        "message": (
                            f"Tool-call budget of {max_calls} is used up for this "
                            "question. Answer now with the results you already have."
                        ),
                    }
                    payload = {"ok": False, "tool": name, "error": error}
                    record = ToolCallRecord(
                        step=step, name=name, arguments=args, ok=False,
                        duration_ms=0, error=error,
                    )
                    stop_reason = "call_limit"
                elif time.monotonic() >= deadline:
                    error = {
                        "type": "time_budget_exhausted",
                        "message": (
                            "This question has used its time budget. Answer now with "
                            "the results you already have."
                        ),
                    }
                    payload = {"ok": False, "tool": name, "error": error}
                    record = ToolCallRecord(
                        step=step, name=name, arguments=args, ok=False,
                        duration_ms=0, error=error,
                    )
                    stop_reason = "timeout"
                else:
                    key = f"{name}:{_canonical(args)}"
                    cached = seen.get(key)
                    if cached is not None:
                        payload = dict(cached)
                        payload["repeat_note"] = (
                            "You already made this identical call. This is the same "
                            "result. Do not call it again -- answer with what you have."
                        )
                        record = ToolCallRecord(
                            step=step, name=name, arguments=args,
                            ok=bool(payload.get("ok")), duration_ms=0, cached=True,
                            sql_preview=payload.get("sql_preview"),
                            row_count=payload.get("row_count"),
                            error=payload.get("error"),
                        )
                    else:
                        calls_used += 1
                        try:
                            payload = await asyncio.wait_for(
                                asyncio.to_thread(
                                    _run_tool_sync,
                                    name, args, session_factory, specs, ctx,
                                ),
                                timeout=tool_timeout,
                            )
                        except asyncio.TimeoutError:
                            payload = {
                                "ok": False,
                                "tool": name,
                                "error": {
                                    "type": "tool_timeout",
                                    "message": (
                                        f"{name} did not finish within {tool_timeout:g}s. "
                                        "Narrow the time window or lower the limit."
                                    ),
                                },
                            }
                        seen[key] = payload
                        record = ToolCallRecord(
                            step=step, name=name, arguments=args,
                            ok=bool(payload.get("ok")),
                            duration_ms=int((time.monotonic() - started_call) * 1000),
                            sql_preview=payload.get("sql_preview"),
                            row_count=payload.get("row_count"),
                            error=payload.get("error"),
                        )
                        if payload.get("ok"):
                            sql, cols, rows = _harvest_rows(payload)
                            if sql:
                                result.sql = sql
                            if rows:
                                result.cols = cols
                                result.rows = rows[:ui_rows]

                result.tool_calls.append(record)

                error_payload = dict(record.error) if record.error else None
                if error_payload is not None:
                    # Publish a code from the frontend's fixed error vocabulary
                    # alongside the internal type, so the UI never has to render
                    # an unkeyed identifier.
                    error_payload["code"] = ev.tool_error_code(error_payload)
                await em.tool_result(
                    step=step,
                    call_id=call_id,
                    tool=name,
                    ok=record.ok,
                    duration_ms=record.duration_ms,
                    summary=tools_module.summarise(name, payload),
                    data=tools_module.compact(name, payload, ui_rows),
                    row_count=record.row_count,
                    truncated=bool(payload.get("truncated")),
                    sql_preview=record.sql_preview,
                    error=error_payload,
                    cached=record.cached,
                )

                body, truncated = _truncate(
                    json.dumps(
                        _redact_for_model(payload), ensure_ascii=False, default=str
                    ),
                    max_chars,
                )
                if truncated:
                    logger.info("Truncated %s result to %d chars", name, max_chars)
                messages.append(
                    {"role": "tool", "tool_call_id": call_id, "content": body}
                )

        # ---- final prose turn -------------------------------------------- #
        if not result.answer:
            result.stop_reason = stop_reason
            messages.append(
                {
                    "role": "system",
                    "content": (
                        "No further tool calls are possible for this question. Answer "
                        "the user now, in prose, using only the tool results above. "
                        "If they are not enough, say exactly what is missing."
                    ),
                }
            )
            await em.status(ev.PHASE_COMPOSING, result.steps)
            result.answer, streamed = await _compose(
                messages, tool_defs, active_model, em, result.steps, beat, stream_tokens
            )
        else:
            result.stop_reason = "answered"

        # ---- one bounded Arabic correction, outside SAQR_MAX_STEPS -------- #
        if loc == "ar" and result.answer and not _ARABIC_RE.search(result.answer):
            logger.info("Saqr answered an ar request without Arabic script; correcting once.")
            await em.status(ev.PHASE_COMPOSING, result.steps)
            corrected = await _arabic_retry(messages, result.answer, active_model)
            if corrected:
                # The text the user will read has changed, so anything already
                # streamed is stale: replay the corrected answer instead.
                result.answer = corrected
                streamed = False

        if not result.answer:
            result.answer = (
                "لم أتمكن من صياغة إجابة لهذا السؤال. حاول صياغته بشكل أضيق."
                if loc == "ar"
                else "I could not produce an answer for that question. Try narrowing it."
            )
            result.stop_reason = "error"

    except SaqrUnavailable as exc:
        # The JSON transport turns this into a 503.  The SSE transport cannot --
        # its status is already 200 -- so the stream is told, and closed properly.
        result.stop_reason = "error"
        result.error = str(exc)
        result.elapsed_ms = elapsed_ms()
        await em.error(ev.classify_error(exc), str(exc), fatal=True)
        await em.done(
            steps=result.steps, tool_calls=len(result.tool_calls),
            elapsed_ms=result.elapsed_ms, stop_reason="error",
        )
        raise
    except Exception as exc:  # noqa: BLE001 - the caller gets a reply, not a 500
        logger.exception("Saqr run failed for question: %s", question)
        result.stop_reason = "error"
        result.error = f"{type(exc).__name__}: {exc}"
        await em.error(ev.classify_error(exc), result.error, fatal=not result.answer)
        if not result.answer:
            result.answer = (
                "تعذّر إكمال الطلب بسبب خطأ داخلي."
                if loc == "ar"
                else "The request could not be completed because of an internal error."
            )

    result.elapsed_ms = elapsed_ms()
    # The answer usually comes from a tool-selection turn, which is deliberately
    # never streamed, so the tokens are replayed here.  Either way the client
    # receives the same sequence: token* then answer.
    if stream_tokens and em.enabled and result.answer and not streamed:
        await _replay_as_tokens(em, result.answer)
    await em.answer(result.answer, used_tools())
    await em.done(
        steps=result.steps,
        tool_calls=len(result.tool_calls),
        elapsed_ms=result.elapsed_ms,
        stop_reason=result.stop_reason,
    )
    logger.info(
        "Saqr run %s finished: locale=%s steps=%d tools=%d stop=%s in %dms",
        em.run_id, loc, result.steps, len(result.tool_calls),
        result.stop_reason, result.elapsed_ms,
    )
    return result


async def _compose(
    messages: List[Dict[str, Any]],
    tool_defs: List[Dict[str, Any]],
    model: str,
    emitter: Emitter,
    step: int,
    beat: float,
    stream_tokens: bool,
) -> Tuple[str, bool]:
    """The final ``tool_choice="none"`` turn.

    Returns ``(text, streamed)``.  ``streamed`` is False when the provider
    refused ``stream=True`` and the answer came back in one piece, so the caller
    knows it still owes the client its ``token`` events.
    """
    if stream_tokens and emitter.enabled:
        try:
            text = await _stream_final_answer(messages, tool_defs, model, emitter)
            return text.strip(), True
        except Exception as exc:  # noqa: BLE001 - fall back rather than lose the answer
            logger.warning("Streaming the final turn failed (%s); answering unstreamed.", exc)

    final = await _with_beats(
        asyncio.to_thread(
            llm.chat, messages, tools=tool_defs, tool_choice="none", model=model
        ),
        emitter, ev.PHASE_COMPOSING, step, beat,
    )
    return (getattr(final, "content", "") or "").strip(), False


async def _replay_as_tokens(emitter: Emitter, text: str, chunk: int = 24) -> None:
    """Emit an already-complete answer as ``token`` events.

    Needed because the answer usually does *not* come from the forced composing
    turn.  Whenever the model decides it has enough, it simply returns prose on a
    tool-selection turn -- and those turns are deliberately not streamed (see
    :func:`backend.app.agent.llm.chat_stream`).  Without this, streaming would
    fire only on the rare step-limit path, and the common case would drop a
    finished paragraph into the pane in one jump.

    So this replays locally rather than streaming from the provider.  The client
    cannot tell, and must not need to: a ``token`` event is defined as *a
    fragment of the final answer*, not as a provider-side chunk.  The honest
    alternative -- discarding a paid-for answer and re-asking with
    ``stream=True`` -- would double the cost and the latency of every question.

    Split on whitespace so fragments land on word boundaries; a mid-word split
    reads as a glitch rather than as typing.
    """
    if not text:
        return
    buffer = ""
    for piece in re.split(r"(\s+)", text):
        if not piece:
            continue
        buffer += piece
        # Flush only once a whitespace run has been appended, so a fragment never
        # ends mid-word.  The hard cap is the escape hatch for an unbroken run
        # with no whitespace to break on -- a URL or a hash, never prose.
        if (piece.isspace() and len(buffer) >= chunk) or len(buffer) >= chunk * 4:
            await emitter.token(buffer)
            buffer = ""
    if buffer:
        await emitter.token(buffer)


async def _arabic_retry(
    messages: List[Dict[str, Any]], answer: str, model: str
) -> Optional[str]:
    """Ask once for the same answer in Arabic, keeping the Latin carve-outs.

    Budgeted outside ``SAQR_MAX_STEPS`` on purpose: it is a formatting fix, not
    another chance to reason, and it calls no tools.
    """
    try:
        corrective = list(messages) + [
            {
                "role": "system",
                "content": (
                    "أعد كتابة الإجابة التالية بالعربية الفصحى دون تغيير أي رقم أو "
                    "حقيقة. اترك عناوين MAC و BSSID وأسماء SSID وأسماء الواجهات "
                    "وأرقام القنوات وأسماء فئات الهجمات (Deauth، Disas، (Re)Assoc، "
                    "RogueAP، Krack، Kr00k، Evil_Twin، SSDP) وأي SQL بالحروف "
                    "اللاتينية كما هي. لا تضف معلومات جديدة."
                ),
            },
            {"role": "user", "content": answer},
        ]
        message = await asyncio.to_thread(llm.chat, corrective, model=model)
        rewritten = (getattr(message, "content", "") or "").strip()
        return rewritten if rewritten and _ARABIC_RE.search(rewritten) else None
    except Exception:  # noqa: BLE001 - the English answer is better than none
        logger.warning("Arabic corrective turn failed; keeping the original answer.")
        return None
