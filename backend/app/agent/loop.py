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
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from backend.app.agent import llm, tools as tools_module
from backend.app.agent.llm import SaqrUnavailable
from backend.app.agent.prompts import build_system_prompt
from backend.app.agent.tools import ToolSpec
from backend.app.config import settings

logger = logging.getLogger(__name__)

__all__ = ["AgentResult", "ToolCallRecord", "run_agent"]

#: Any Arabic-script codepoint.  Used only to detect an ``ar`` run that came back
#: in English, which is the failure mode a cheap model actually has.
_ARABIC_RE = re.compile(
    r"[؀-ۿݐ-ݿࢠ-ࣿﭐ-﷿ﹰ-﻿]"
)

#: Emitted event names.  S3 accepts an emitter and calls it; the streaming
#: transport that consumes these arrives later.
EVENTS = ("run_start", "step", "tool_call", "tool_result", "answer", "run_end")

Emitter = Optional[Callable[[str, Dict[str, Any]], Any]]
SessionFactory = Optional[Callable[[], Any]]


@dataclass
class ToolCallRecord:
    """One tool execution, as reported to the caller (and, later, streamed)."""

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
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    #: The last SQL a tool actually ran, so the UI can show it as ``/ask`` does.
    sql: Optional[str] = None
    #: Rows from the last tool that produced any, capped at ``SAQR_UI_ROWS``.
    cols: List[str] = field(default_factory=list)
    rows: List[Dict[str, Any]] = field(default_factory=list)
    #: ``answered`` | ``step_limit`` | ``call_limit`` | ``timeout`` | ``error``
    stop_reason: str = "answered"
    error: Optional[str] = None

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


async def _emit(emitter: Emitter, event: str, data: Dict[str, Any]) -> None:
    """Call the emitter if there is one; never let it break the run."""
    if emitter is None:
        return
    try:
        result = emitter(event, data)
        if inspect.isawaitable(result):
            await result
    except Exception:  # noqa: BLE001 - an observer must not fail the observed
        logger.warning("Saqr emitter raised on event %s", event, exc_info=True)


def _run_tool_sync(
    name: str,
    args: Dict[str, Any],
    session_factory: SessionFactory,
    registry: Dict[str, ToolSpec],
) -> Dict[str, Any]:
    """Execute one tool on a worker thread, with its own short-lived session."""
    spec = registry.get(name)
    if spec is not None and spec.needs_db and session_factory is not None:
        session = session_factory()
        try:
            return tools_module.execute(name, args, session, registry)
        finally:
            session.close()
    return tools_module.execute(name, args, None, registry)


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


# --------------------------------------------------------------------------- #
# The loop                                                                     #
# --------------------------------------------------------------------------- #
async def run_agent(
    question: str,
    *,
    locale: Optional[str] = None,
    session_factory: SessionFactory = None,
    emitter: Emitter = None,
    registry: Optional[Dict[str, ToolSpec]] = None,
    model: Optional[str] = None,
) -> AgentResult:
    """Answer ``question`` by calling tools, and return the finished answer.

    ``session_factory`` is a zero-argument callable returning a SQLAlchemy
    ``Session`` -- a ``sessionmaker`` bound to the request's engine, so a
    ``get_db`` dependency override is honoured.  ``emitter`` is called with
    ``(event, payload)`` at each milestone and may be ``None``; it is accepted
    now so the streaming transport can be added without touching this function.
    """
    loc = str(locale or settings.SAQR_DEFAULT_LOCALE or "en").strip().lower()
    if loc not in ("en", "ar"):
        loc = "en"
    active_model = model or settings.saqr_model
    specs = registry if registry is not None else tools_module.build_registry()
    tool_defs = tools_module.tool_definitions(specs)

    max_steps = int(settings.SAQR_MAX_STEPS)
    max_calls = int(settings.SAQR_MAX_TOOL_CALLS)
    tool_timeout = float(settings.SAQR_TOOL_TIMEOUT_S)
    max_chars = int(settings.SAQR_MAX_TOOL_CHARS)
    ui_rows = int(settings.SAQR_UI_ROWS)
    deadline = time.monotonic() + float(settings.SAQR_RUN_TIMEOUT_S)

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": build_system_prompt(loc)},
        {"role": "user", "content": question.strip()},
    ]

    result = AgentResult(answer="", locale=loc, model=active_model, steps=0)
    seen: Dict[str, Dict[str, Any]] = {}
    calls_used = 0
    stop_reason = "step_limit"

    await _emit(emitter, "run_start", {"locale": loc, "model": active_model,
                                       "tools": list(specs)})

    try:
        for step in range(1, max_steps + 1):
            result.steps = step
            await _emit(emitter, "step", {"step": step})

            message = await asyncio.to_thread(
                llm.chat, messages, tools=tool_defs, tool_choice="auto", model=active_model
            )
            calls = list(getattr(message, "tool_calls", None) or [])

            if not calls:
                result.answer = (getattr(message, "content", "") or "").strip()
                stop_reason = "answered"
                break

            messages.append(_assistant_message(message, calls))

            for call in calls:
                name = call.function.name
                args, parse_error = _parse_arguments(call)
                started = time.monotonic()

                if parse_error is not None:
                    payload = {"ok": False, "tool": name, "error": parse_error}
                    record = ToolCallRecord(
                        step=step, name=name, arguments={}, ok=False,
                        duration_ms=0, error=parse_error,
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
                    await _emit(emitter, "tool_call",
                                {"step": step, "name": name, "arguments": args,
                                 "cached": cached is not None})
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
                                    _run_tool_sync, name, args, session_factory, specs
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
                            duration_ms=int((time.monotonic() - started) * 1000),
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
                await _emit(emitter, "tool_result", asdict(record))

                body, truncated = _truncate(
                    json.dumps(payload, ensure_ascii=False, default=str), max_chars
                )
                if truncated:
                    logger.info("Truncated %s result to %d chars", name, max_chars)
                messages.append(
                    {"role": "tool", "tool_call_id": call.id, "content": body}
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
            final = await asyncio.to_thread(
                llm.chat, messages, tools=tool_defs, tool_choice="none", model=active_model
            )
            result.answer = (getattr(final, "content", "") or "").strip()
        else:
            result.stop_reason = "answered"

        # ---- one bounded Arabic correction, outside SAQR_MAX_STEPS -------- #
        if loc == "ar" and result.answer and not _ARABIC_RE.search(result.answer):
            logger.info("Saqr answered an ar request without Arabic script; correcting once.")
            corrected = await _arabic_retry(messages, result.answer, active_model)
            if corrected:
                result.answer = corrected

        if not result.answer:
            result.answer = (
                "لم أتمكن من صياغة إجابة لهذا السؤال. حاول صياغته بشكل أضيق."
                if loc == "ar"
                else "I could not produce an answer for that question. Try narrowing it."
            )
            result.stop_reason = "error"

    except SaqrUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - the router turns this into a 500-free reply
        logger.exception("Saqr run failed for question: %s", question)
        result.stop_reason = "error"
        result.error = f"{type(exc).__name__}: {exc}"
        if not result.answer:
            result.answer = (
                "تعذّر إكمال الطلب بسبب خطأ داخلي."
                if loc == "ar"
                else "The request could not be completed because of an internal error."
            )

    await _emit(emitter, "answer", {"answer": result.answer, "locale": loc})
    await _emit(
        emitter, "run_end",
        {"steps": result.steps, "tool_calls": len(result.tool_calls),
         "stop_reason": result.stop_reason},
    )
    logger.info(
        "Saqr run finished: locale=%s steps=%d tools=%d stop=%s",
        loc, result.steps, len(result.tool_calls), result.stop_reason,
    )
    return result


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
