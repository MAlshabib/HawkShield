"""``/agent/*`` -- Saqr, the tool-calling assistant.

Two routes:

* ``POST /agent/ask`` -- ask a question.  **One endpoint, two transports**,
  chosen by the ``Accept`` header: ``text/event-stream`` streams the run as it
  happens, anything else returns the JSON envelope.  Not POST-then-GET with a
  run id: that needs a run registry, a GC timer, and leaks an orphaned run
  every time a browser tab closes mid-answer.  Here the run *is* the response,
  so cancellation is an ``AbortController`` client-side and
  ``request.is_disconnected()`` server-side -- exactly what ``stream.py`` does.
* ``GET /agent/tools`` -- publish the tool catalogue (name, i18n label key,
  whether it mutates, and its argument schema) so the frontend generates its
  label table from the server instead of hand-copying one that then drifts.
  It honours the same admin gate the model does, so a page loaded without the
  operator token cannot even render a control for a tool it could not invoke.

**Capability is resolved here, once, before anything else runs.**  Two headers
are read: ``X-HawkShield-Admin`` (compared against ``SAQR_ADMIN_TOKEN`` in
constant time) and ``X-HawkShield-Confirm`` (looked up in the server's own
confirmation store).  Both become plain Python values that are handed to
``run_agent`` as arguments.  Nothing downstream re-derives them, so no model
turn, no tool result and no SSID can influence what this request is allowed to
do.  The token itself is never logged, never echoed and never reaches the model.

The question is admitted or refused here too, by ``guard.sanitise_question``:
over ``SAQR_MAX_QUESTION_CHARS`` is a **400**, and so is a question carrying C0
control characters or invisible/bidi-override codepoints.  Those are the two
tricks that work on a length-bounded prompt -- push the system prompt out of the
window, or hide text from the human reading the transcript -- and both are
refused before a single token is spent.

Pre-flight ordering matters and is deliberate: **every rejection is decided
before the stream opens**, because once a ``StreamingResponse`` starts the
status is 200 forever and a 503 can no longer be sent.  Missing key or
``SAQR_ENABLED=0`` -> **503** with the same sentence ``/ask`` returns today;
over the rate limit or the concurrency gate -> **429**; a body that fails
validation -> **400**.  Anything the run itself survives is reported inside the
200 (as ``stop_reason``/``error``, or as an ``error`` event followed by
``done``), because a half-answered question is more useful to an operator than
an opaque 500.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent import confirm, events, guard, ratelimit, tools as tools_module
from backend.app.agent.llm import SaqrUnavailable
from backend.app.agent.loop import run_agent
from backend.app.config import settings
from backend.app.db import get_db
from backend.app.schemas import AgentAskPayload, AgentAskResponse, AgentToolInfo

logger = logging.getLogger(__name__)

router = APIRouter(tags=["agent"])


def _preflight() -> None:
    """Refuse early and clearly when the agent cannot possibly serve a request."""
    if not settings.SAQR_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="The Saqr agent is disabled (SAQR_ENABLED=0).",
        )
    if not settings.OPENROUTER_API_KEY.strip():
        # Deliberately the same sentence /ask answers with today.
        raise HTTPException(
            status_code=503,
            detail="OPENROUTER_API_KEY is not configured; the assistant is disabled.",
        )
    if not settings.saqr_model:
        raise HTTPException(
            status_code=503,
            detail="No model is configured; set SAQR_MODEL (or GEN_MODEL) in .env.",
        )


async def _parse_body(request: Request) -> AgentAskPayload:
    """Validate the request body, answering **400** rather than FastAPI's 422.

    The body is read by hand for one reason: a declared body parameter makes
    FastAPI raise ``RequestValidationError``, which its default handler renders
    as 422.  Overriding that handler would change the status of every other
    route in the app, so the validation is done here instead and the rest of the
    contract is left exactly as it was.
    """
    try:
        raw = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Body is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise HTTPException(
            status_code=400, detail=f"Body must be a JSON object, got {type(raw).__name__}."
        )
    try:
        payload = AgentAskPayload.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors(include_url=False)) from exc

    # The admissibility gate. Deliberately after pydantic and before anything
    # that costs money: a question that is too long, or that carries hidden
    # characters, never reaches a model, a tool or the rate limiter's budget.
    try:
        cleaned = guard.sanitise_question(payload.question)
    except guard.InputRejected as exc:
        logger.info("/agent/ask rejected a question: %s", exc.reason)
        raise HTTPException(
            status_code=400, detail={"reason": exc.reason, "message": str(exc)}
        ) from exc
    return payload.model_copy(update={"question": cleaned})


def _capability(request: Request) -> Tuple[bool, Optional[confirm.Confirmation]]:
    """``(is_admin, confirmation)`` for this request, from its headers alone.

    Called once, before the loop starts.  ``is_admin`` is a boolean that has
    already been decided by the time any model sees any text, and the token that
    produced it is not carried any further -- what travels down is the boolean.
    An unknown or expired confirmation resolves to ``None`` rather than an error:
    the request may not have concerned a destructive tool at all, and if it did,
    the tool will simply propose again instead of acting.
    """
    is_admin = guard.resolve_admin(request.headers.get(guard.ADMIN_HEADER))
    confirmation = confirm.resolve(request.headers.get(guard.CONFIRM_HEADER))
    if confirmation is not None and not is_admin:
        # A confirmation without operator authorisation authorises nothing:
        # every destructive tool is admin-gated, so carrying it further could
        # only ever produce a more confusing refusal.
        logger.info("A Saqr confirmation was presented without operator authorisation.")
        confirmation = None
    logger.info(
        "Saqr request capability resolved: admin=%s confirmation=%s",
        is_admin, bool(confirmation),
    )
    return is_admin, confirmation


def _wants_sse(request: Request) -> bool:
    """True when the client asked for the event stream.

    Naming ``text/event-stream`` in ``Accept`` is the signal.  A bare ``*/*``
    (curl, the test client, any ordinary JSON caller) is deliberately **not**
    enough: the JSON envelope stays the default, so nothing that worked before
    streaming existed starts receiving a stream it cannot parse.
    """
    accept = (request.headers.get("accept") or "").lower()
    return "text/event-stream" in accept


async def _sse_body(
    request: Request,
    payload: AgentAskPayload,
    maker: sessionmaker,
    is_admin: bool = False,
    confirmation: Optional[confirm.Confirmation] = None,
) -> AsyncIterator[str]:
    """Stream one run as SSE frames, then release the concurrency slot.

    The run is driven by a background task that writes into the emitter's queue;
    this generator drains that queue.  Two properties matter and are tested:

    * ``done`` terminates the stream, and the loop emits it on every path
      including a fatal one -- so a consumer has exactly one end condition;
    * if the client goes away, ``request.is_disconnected()`` ends the drain and
      the ``finally`` cancels the run rather than letting it keep billing.
    """
    run_id = uuid.uuid4().hex
    emitter = events.Emitter(run_id, buffered=True)
    released = False
    started = time.monotonic()

    def release() -> None:
        nonlocal released
        if not released:
            released = True
            ratelimit.gate().release()

    async def drive() -> None:
        try:
            await run_agent(
                payload.question,
                locale=payload.locale,
                session_factory=maker,
                emitter=emitter,
                run_id=run_id,
                stream_tokens=True,
                is_admin=is_admin,
                confirmation=confirmation,
            )
        except SaqrUnavailable:
            # The loop has already emitted `error` + `done`; the status line was
            # committed as 200 the moment the stream opened, so there is no 503
            # left to send and nothing further to do here.
            logger.info("Saqr run %s ended: assistant unavailable", run_id)
        except Exception:  # noqa: BLE001 - the loop reports; this must not escape
            logger.exception("Saqr run %s failed outside the loop", run_id)
            await emitter.error(events.ERR_INTERNAL, "The run failed unexpectedly.", fatal=True)
        finally:
            # Belt and braces: whatever happened, the stream must terminate.
            # No-op when the loop already emitted its own `done`; when it did
            # not, this is the only `done` the client will see, so it carries a
            # real elapsed time rather than a placeholder zero.
            await emitter.done(
                steps=0,
                tool_calls=0,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                stop_reason="error",
            )

    runner: Optional[asyncio.Task] = None
    try:
        runner = asyncio.create_task(drive())
        async for frame in emitter.stream(
            keepalive_s=float(settings.SAQR_STREAM_KEEPALIVE_S),
            is_disconnected=request.is_disconnected,
        ):
            yield frame
    finally:
        if runner is not None and not runner.done():
            runner.cancel()
            await asyncio.gather(runner, return_exceptions=True)
        release()
        logger.debug("Saqr SSE stream closed for run %s", run_id)


@router.get("/agent/tools", response_model=List[AgentToolInfo])
def agent_tools(request: Request) -> List[Dict[str, Any]]:
    """The tools Saqr can currently call, with their argument schemas.

    Published unconditionally -- a UI that knows the agent is switched off can
    still render the catalogue and explain why nothing is available.  The list
    honours ``SAQR_ALLOW_RAW_SQL`` and ``SAQR_ALLOW_SIMULATION_TOOL``, and the
    operator tools appear only when the request carries ``SAQR_ADMIN_TOKEN`` --
    exactly the list that request's model would be offered, so the catalogue can
    never advertise a capability the caller does not have.

    It reports no model identifier: which model answers is a server detail.
    """
    is_admin = guard.resolve_admin(request.headers.get(guard.ADMIN_HEADER))
    return tools_module.public_catalogue(is_admin=is_admin)


@router.post(
    "/agent/ask",
    response_model=AgentAskResponse,
    # The body is validated by hand (see ``_parse_body``), so its schema is
    # declared here explicitly rather than inferred from a parameter.
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": AgentAskPayload.model_json_schema()}
            },
        }
    },
)
async def agent_ask(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Any:
    """Answer a question about the captured traffic by calling tools.

    Returns ``text/event-stream`` when the client accepts it, else the JSON
    envelope.  Both transports run the identical loop over the identical tools.
    """
    _preflight()
    payload = await _parse_body(request)
    is_admin, confirmation = _capability(request)

    try:
        ratelimit.limiter().check()
        ratelimit.gate().acquire()
    except ratelimit.RateLimited as exc:
        logger.info("/agent/ask rejected: %s", exc)
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(max(1, int(exc.retry_after_s)))},
        ) from exc

    # A sessionmaker bound to *this request's* engine, so the tools honour a
    # get_db dependency override (tests) and the configured database alike --
    # the pattern stream.py and simulate.py already use.  Never self-HTTP: one
    # uvicorn worker calling back into itself would deadlock on a Pi.
    #
    # It is built here, in the handler, and the request's own session is never
    # touched inside the streaming generator: a `yield` dependency is torn down
    # before the streaming body runs, so `db` is closed by then.  `stream.py`
    # takes the bind for exactly this reason.
    maker = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)

    if _wants_sse(request):
        return StreamingResponse(
            _sse_body(request, payload, maker, is_admin, confirmation),
            media_type="text/event-stream",
            headers=events.SSE_HEADERS,
        )

    try:
        result = await run_agent(
            payload.question,
            locale=payload.locale,
            session_factory=maker,
            emitter=None,
            is_admin=is_admin,
            confirmation=confirmation,
        )
    except SaqrUnavailable as exc:
        logger.info("/agent/ask rejected: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        ratelimit.gate().release()

    response.headers["Cache-Control"] = "no-store"
    return {
        "answer": result.answer,
        "locale": result.locale,
        "steps": result.steps,
        "is_admin": is_admin,
        "run_id": result.run_id,
        "stop_reason": result.stop_reason,
        "elapsed_ms": result.elapsed_ms,
        "sql": result.sql,
        "cols": result.cols,
        "rows": result.rows,
        "tool_calls": [
            {
                "step": call.step,
                "name": call.name,
                "arguments": call.arguments,
                "ok": call.ok,
                "duration_ms": call.duration_ms,
                "cached": call.cached,
                "sql_preview": call.sql_preview,
                "row_count": call.row_count,
                "error": call.error,
            }
            for call in result.tool_calls
        ],
        "error": result.error,
    }
