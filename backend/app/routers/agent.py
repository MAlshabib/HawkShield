"""``/agent/*`` -- Saqr, the tool-calling assistant.

Two routes:

* ``POST /agent/ask`` -- ask a question.  JSON in, JSON out.  Streaming is a
  later change; the loop already accepts an emitter, so this handler will not
  need restructuring for it.
* ``GET /agent/tools`` -- publish the tool catalogue (name, i18n label key,
  whether it mutates, and its argument schema) so the frontend generates its
  label table from the server instead of hand-copying one that then drifts.

Pre-flight ordering matters and is deliberate: configuration is checked before
any work, so a misconfigured host answers instantly and identically every time.
Missing key or ``SAQR_ENABLED=0`` -> **503** with the same sentence ``/ask``
returns today; over the rate limit or the concurrency gate -> **429**; a body
FastAPI cannot validate -> **400** (via pydantic); anything else the run itself
survives and reports inside a 200 response, because a half-answered question is
more useful to an operator than an opaque 500.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent import ratelimit, tools as tools_module
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
        return AgentAskPayload.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors(include_url=False)) from exc


@router.get("/agent/tools", response_model=List[AgentToolInfo])
def agent_tools() -> List[Dict[str, Any]]:
    """The tools Saqr can currently call, with their argument schemas.

    Published unconditionally -- a UI that knows the agent is switched off can
    still render the catalogue and explain why nothing is available.  The list
    honours ``SAQR_ALLOW_RAW_SQL`` and ``SAQR_ALLOW_SIMULATION_TOOL``, so what
    it shows is what the model is really offered.
    """
    return tools_module.public_catalogue()


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
) -> Dict[str, Any]:
    """Answer a question about the captured traffic by calling tools."""
    _preflight()
    payload = await _parse_body(request)

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
    maker = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)

    try:
        result = await run_agent(
            payload.question,
            locale=payload.locale,
            session_factory=maker,
            emitter=None,  # streaming transport lands later
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
        "model": result.model,
        "steps": result.steps,
        "stop_reason": result.stop_reason,
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
