"""Server-Sent Event vocabulary for a Saqr run.

One agent run produces one ordered stream of events.  Two invariants make that
stream safe to consume:

* **``seq`` is strictly increasing from 0** within a run, with no gaps.  A client
  that sees ``seq`` jump knows it dropped a frame rather than silently rendering
  an incomplete transcript.
* **``done`` is always the last event, including after ``error``.**  A consumer
  therefore has exactly one termination condition and never has to guess whether
  a stream that stopped was finished or broken.

Every payload also carries ``run_id`` (uuid4 hex), so a UI that multiplexes or
reconnects can tell two runs apart.

Transport note: this is a *response-body* stream on ``POST /agent/ask``, not a
POST-then-GET with a run id.  A run registry would need a GC timer and would
leak orphaned runs on a Pi whenever a browser tab closed mid-answer.  Here the
run is the response: the client aborts, ``request.is_disconnected()`` goes true,
and everything is collected.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

__all__ = [
    "EVENTS",
    "ERROR_CODES",
    "PHASES",
    "SSE_HEADERS",
    "KEEPALIVE_FRAME",
    "Emitter",
    "classify_error",
    "coerce_emitter",
    "sse",
    "tool_error_code",
]

# --- event names ----------------------------------------------------------- #
EVENT_RUN_START = "run_start"
EVENT_STATUS = "status"
EVENT_TOOL_CALL = "tool_call"
EVENT_TOOL_RESULT = "tool_result"
EVENT_TOKEN = "token"
EVENT_ANSWER = "answer"
EVENT_ERROR = "error"
EVENT_DONE = "done"

EVENTS = (
    EVENT_RUN_START, EVENT_STATUS, EVENT_TOOL_CALL, EVENT_TOOL_RESULT,
    EVENT_TOKEN, EVENT_ANSWER, EVENT_ERROR, EVENT_DONE,
)

# --- status phases --------------------------------------------------------- #
# These are i18n keys on the frontend (``saqr.phase.<phase>``).  Adding one here
# without adding the key there renders a raw identifier to the user.
PHASE_CALLING_MODEL = "calling_model"
PHASE_EXECUTING_TOOL = "executing_tool"
PHASE_COMPOSING = "composing"

PHASES = (PHASE_CALLING_MODEL, PHASE_EXECUTING_TOOL, PHASE_COMPOSING)

# --- error codes ----------------------------------------------------------- #
# Likewise ``saqr.error.<code>`` on the frontend.  This tuple is the whole
# vocabulary: every internal error type is mapped onto one of these before it
# reaches the wire, so a UI never has to render an unkeyed identifier.
ERR_NO_API_KEY = "no_api_key"
ERR_NO_CREDIT = "no_credit"
ERR_MODEL = "model_error"
ERR_TOOL = "tool_error"
ERR_BAD_ARGS = "bad_args"
ERR_STEP_LIMIT = "step_limit"
ERR_TIMEOUT = "timeout"
ERR_INTERNAL = "internal"

ERROR_CODES = (
    ERR_NO_API_KEY, ERR_NO_CREDIT, ERR_MODEL, ERR_TOOL,
    ERR_BAD_ARGS, ERR_STEP_LIMIT, ERR_TIMEOUT, ERR_INTERNAL,
)

#: Internal tool-error ``type`` -> published ``code``.  The ``type`` stays in the
#: payload for an operator reading the raw stream; the ``code`` is what the UI
#: looks up.  Anything not listed is a plain ``tool_error``.
_TOOL_ERROR_CODES: Dict[str, str] = {
    "invalid_arguments": ERR_BAD_ARGS,
    "unknown_class": ERR_BAD_ARGS,
    "rejected_sql": ERR_BAD_ARGS,
    "budget_exhausted": ERR_STEP_LIMIT,
    "time_budget_exhausted": ERR_TIMEOUT,
    "tool_timeout": ERR_TIMEOUT,
}

#: Substrings that identify a spent account rather than a broken request.  A 402
#: from OpenRouter is the single most likely live failure at a demo, and
#: ``model_error`` would send the operator hunting the wrong thing.
_NO_CREDIT_MARKERS = (
    "402", "insufficient credit", "insufficient_quota", "quota exceeded",
    "billing", "payment required",
)

# --- SSE framing ----------------------------------------------------------- #
# Copied from routers/stream.py.  X-Accel-Buffering matters: without it nginx
# (and most other reverse proxies) buffer the response, and the agent pane looks
# frozen until the whole answer is finished -- the exact opposite of why this
# endpoint streams at all.
SSE_HEADERS: Dict[str, str] = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}

#: Comment frame sent on an idle tick.  A comment resets a proxy's idle timer
#: without being delivered to the client's message handler.
KEEPALIVE_FRAME = ": ka\n\n"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sse(event: str, data: Dict[str, Any]) -> str:
    """Frame one event.  ``json.dumps`` is single-line, so ``data:`` stays one field."""
    body = json.dumps(data, ensure_ascii=False, default=str)
    return f"event: {event}\ndata: {body}\n\n"


def classify_error(exc: BaseException) -> str:
    """Map an exception onto one of :data:`ERROR_CODES`."""
    from backend.app.agent.llm import SaqrUnavailable

    if isinstance(exc, SaqrUnavailable):
        return ERR_NO_API_KEY
    if isinstance(exc, asyncio.TimeoutError):
        return ERR_TIMEOUT
    text = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in text for marker in _NO_CREDIT_MARKERS):
        return ERR_NO_CREDIT
    return ERR_MODEL


def tool_error_code(error: Optional[Dict[str, Any]]) -> Optional[str]:
    """Published ``code`` for a tool-error payload, or ``None`` when it succeeded."""
    if not error:
        return None
    return _TOOL_ERROR_CODES.get(str(error.get("type") or ""), ERR_TOOL)


Sink = Optional[Callable[[str, Dict[str, Any]], Union[None, Awaitable[None]]]]


class Emitter:
    """Builds ordered event payloads and hands them to a queue and/or a callable.

    ``buffered=True`` gives the emitter an :class:`asyncio.Queue`, which
    :meth:`stream` drains as SSE frames.  ``forward`` is called with
    ``(event, payload)`` after ``run_id`` and ``seq`` have been stamped on, which
    is what a non-streaming caller (or a test) uses to observe a run.

    A disabled emitter is a cheap no-op, so the JSON path pays nothing for the
    instrumentation the SSE path needs.
    """

    def __init__(
        self,
        run_id: Optional[str] = None,
        *,
        buffered: bool = False,
        forward: Sink = None,
        enabled: bool = True,
    ) -> None:
        self.run_id = run_id or uuid.uuid4().hex
        self.enabled = bool(enabled)
        self.queue: Optional[asyncio.Queue] = asyncio.Queue() if buffered else None
        self._forward = forward
        self._seq = 0
        self.done_emitted = False

    # -- plumbing ---------------------------------------------------------- #
    @property
    def seq(self) -> int:
        """The sequence number the *next* event will carry."""
        return self._seq

    async def _emit(self, event: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        data: Dict[str, Any] = {"run_id": self.run_id, "seq": self._seq}
        data.update(payload)
        self._seq += 1
        if event == EVENT_DONE:
            self.done_emitted = True
        if self.queue is not None:
            self.queue.put_nowait((event, data))
        if self._forward is not None:
            try:
                outcome = self._forward(event, data)
                if inspect.isawaitable(outcome):
                    await outcome
            except Exception:  # noqa: BLE001 - an observer must not fail the observed
                logger.warning("Saqr emitter sink raised on %s", event, exc_info=True)
        return data

    async def __call__(self, event: str, payload: Dict[str, Any]) -> None:
        """Accept a raw ``(event, payload)`` pair, for callers that build their own."""
        await self._emit(event, dict(payload))

    # -- typed events ------------------------------------------------------ #
    async def run_start(
        self, *, question: str, locale: str, model: str, max_steps: int, tools: List[str]
    ) -> None:
        await self._emit(EVENT_RUN_START, {
            "ts": _now_iso(),
            "question": question,
            "locale": locale,
            "model": model,
            "max_steps": int(max_steps),
            "tools": list(tools),
        })

    async def status(self, phase: str, step: int) -> None:
        if phase not in PHASES:  # pragma: no cover - guards a typo, not user input
            logger.warning("Unknown Saqr phase %r; the UI has no label for it", phase)
        await self._emit(EVENT_STATUS, {"ts": _now_iso(), "phase": phase, "step": int(step)})

    async def tool_call(
        self, *, step: int, call_id: str, tool: str, label_key: str,
        mutating: bool, args: Dict[str, Any],
    ) -> None:
        await self._emit(EVENT_TOOL_CALL, {
            "ts": _now_iso(),
            "step": int(step),
            "call_id": call_id,
            "tool": tool,
            "label_key": label_key,
            "mutating": bool(mutating),
            "args": args,
        })

    async def tool_result(
        self, *, step: int, call_id: str, tool: str, ok: bool, duration_ms: int,
        summary: str = "", data: Optional[Dict[str, Any]] = None,
        row_count: Optional[int] = None, truncated: bool = False,
        sql_preview: Optional[str] = None, error: Optional[Dict[str, Any]] = None,
        cached: bool = False,
    ) -> None:
        await self._emit(EVENT_TOOL_RESULT, {
            "ts": _now_iso(),
            "step": int(step),
            "call_id": call_id,
            "tool": tool,
            "ok": bool(ok),
            "duration_ms": int(duration_ms),
            "summary": summary,
            "data": data if data is not None else {},
            "row_count": row_count,
            "truncated": bool(truncated),
            "sql_preview": sql_preview,
            "error": error,
            "cached": bool(cached),
        })

    async def token(self, delta: str) -> None:
        """One fragment of the final answer.  No ``ts``: this is the hot path."""
        await self._emit(EVENT_TOKEN, {"delta": delta})

    async def answer(self, text: str, used_tools: Optional[List[str]] = None) -> None:
        await self._emit(EVENT_ANSWER, {
            "ts": _now_iso(),
            "text": text,
            "used_tools": list(used_tools or []),
        })

    async def error(self, code: str, message: str, *, fatal: bool = False) -> None:
        if code not in ERROR_CODES:  # pragma: no cover - guards a typo
            logger.warning("Unknown Saqr error code %r; the UI has no label for it", code)
            code = ERR_INTERNAL
        await self._emit(EVENT_ERROR, {
            "ts": _now_iso(),
            "code": code,
            "message": message,
            "fatal": bool(fatal),
        })

    async def done(
        self, *, steps: int, tool_calls: int, elapsed_ms: int, stop_reason: str
    ) -> None:
        """Always the last event of a run, error or not.  Emitted at most once."""
        if self.done_emitted:
            return
        await self._emit(EVENT_DONE, {
            "ts": _now_iso(),
            "steps": int(steps),
            "tool_calls": int(tool_calls),
            "elapsed_ms": int(elapsed_ms),
            "stop_reason": stop_reason,
        })

    # -- transport --------------------------------------------------------- #
    async def stream(
        self,
        keepalive_s: float = 15.0,
        is_disconnected: Optional[Callable[[], Awaitable[bool]]] = None,
    ) -> AsyncIterator[str]:
        """Drain the queue as SSE frames until ``done``, or until the client leaves.

        An idle tick yields a ``: ka`` comment rather than a data event, so a
        proxy's idle timer resets without the client's message handler seeing
        anything.
        """
        if self.queue is None:  # pragma: no cover - programming error
            raise RuntimeError("Emitter.stream() needs buffered=True")
        interval = max(0.1, float(keepalive_s))
        while True:
            if is_disconnected is not None and await is_disconnected():
                logger.debug("Saqr client disconnected from run %s", self.run_id)
                break
            try:
                event, data = await asyncio.wait_for(self.queue.get(), timeout=interval)
            except asyncio.TimeoutError:
                yield KEEPALIVE_FRAME
                continue
            yield sse(event, data)
            if event == EVENT_DONE:
                break


def coerce_emitter(
    emitter: Union["Emitter", Sink, None], run_id: Optional[str] = None
) -> "Emitter":
    """Normalise the caller's ``emitter`` argument into an :class:`Emitter`.

    ``None`` becomes a disabled no-op, a plain callable is wrapped so it receives
    the same stamped payloads the stream does, and an ``Emitter`` passes through.
    """
    if isinstance(emitter, Emitter):
        return emitter
    if emitter is None:
        return Emitter(run_id, enabled=False)
    return Emitter(run_id, forward=emitter)
