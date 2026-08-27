"""Natural-language question endpoint -- a thin shim over the Saqr agent.

``POST /ask`` predates the agent.  The already-built ``frontend/out`` bundle
calls it and destructures a fixed envelope out of the reply, so the route
survives, but everything behind it is now
:func:`backend.app.agent.loop.run_agent` -- the same loop, the same eight tools
and the same guards that serve ``POST /agent/ask``.  There is one assistant in
this system, not two.

What this router still owns, unchanged: the TTL cache, the five-turn per-session
memory, and a 503 when the assistant is not configured.  It **shares** the
assistant's rate limit and concurrency gate with ``/agent/ask`` rather than
holding a second budget of its own -- the ceiling belongs to the assistant, not
to a URL.

**The envelope is the contract, and the bundle is unforgiving about it.**  Its
handler reads, in order: ``error`` (truthy short-circuits to an error bubble and
nothing else renders), then ``mode``, where the literal string ``"SQL"`` is the
*only* value that renders the sample-rows table -- every other value falls
through to prose and the table silently disappears.  That is why ``mode`` is
derived from which tools actually ran rather than from anything the model says,
and why ``backend/scripts/check_frontend.py`` asserts it explicitly.
"""
from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent import ratelimit
from backend.app.config import settings
from backend.app.db import get_db
from backend.app.schemas import AskPayload

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ask"])

# The agent stack is imported defensively for the same reason the RAG module was:
# registering this router must never be what stops the API from booting.  A
# failure here becomes a clean 503 rather than an import-time crash.
try:
    from backend.app.agent.llm import SaqrUnavailable
    from backend.app.agent.loop import run_agent
except Exception as _import_exc:  # noqa: BLE001 - any failure means "not installed"
    logger.warning("Saqr agent unavailable (%s); /ask will answer 503.", _import_exc)

    class SaqrUnavailable(RuntimeError):  # type: ignore[no-redef]
        """Raised when the assistant cannot serve a question."""

    _AGENT_IMPORT_ERROR = str(_import_exc)

    async def run_agent(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        raise SaqrUnavailable(f"The assistant is not installed: {_AGENT_IMPORT_ERROR}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


MAX_TURNS = 5
CACHE_MAXSIZE = 200
CACHE_TTL_SECONDS = 600

#: The one tool that answers from the knowledge base rather than from packet
#: data.  A run that used only this is ``DOCS``; a run that touched anything else
#: is ``SQL``, because the bundle keys its rows table on that exact string.
DOCS_ONLY_TOOLS: Set[str] = {"explain_attack_class"}


class TTLCache:
    """Small LRU cache with a wall-clock TTL."""

    def __init__(self, maxsize: int = CACHE_MAXSIZE, ttl_seconds: int = CACHE_TTL_SECONDS) -> None:
        self.store: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.maxsize = maxsize
        self.ttl = timedelta(seconds=ttl_seconds)

    def _purge_expired(self) -> None:
        now = _now()
        drop = [k for k, v in self.store.items() if now - v["ts"] > self.ttl]
        for k in drop:
            del self.store[k]

    def get(self, key: str) -> Optional[Any]:
        self._purge_expired()
        if key in self.store:
            val = self.store.pop(key)
            self.store[key] = val
            return val["data"]
        return None

    def set(self, key: str, value: Any) -> None:
        self._purge_expired()
        if key in self.store:
            self.store.pop(key)
        elif len(self.store) >= self.maxsize:
            self.store.popitem(last=False)
        self.store[key] = {"data": value, "ts": _now()}


cache = TTLCache()
SESSION_MEMORY: Dict[str, List[Dict[str, str]]] = {}


def _norm_key(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()


def _build_context(session_id: str) -> str:
    turns = SESSION_MEMORY.get(session_id, [])
    if not turns:
        return ""
    return "\n\n".join(f"Q: {t['q']}\nA: {t['a']}" for t in turns[-MAX_TURNS:])


def _mode_for(result: Any) -> str:
    """Map an agent run onto the four modes the bundle understands.

    Derived from which tools *actually executed*, never from anything the model
    asserts about itself: the bundle renders its rows table on ``"SQL"`` alone,
    so this is the one field that must not depend on a model's self-report.

      * ``ERROR`` -- the run failed;
      * ``SQL``   -- at least one tool that reads packet data ran, so there are
                     rows (or a real ``sql_preview``) to show;
      * ``DOCS``  -- only the knowledge-base tool ran;
      * ``OOS``   -- no tool ran at all, so the model answered from scope alone.
    """
    if getattr(result, "error", None):
        return "ERROR"
    executed = {call.name for call in getattr(result, "tool_calls", []) if call.ok}
    if executed - DOCS_ONLY_TOOLS:
        return "SQL"
    if executed:
        return "DOCS"
    return "OOS"


@router.post("/ask")
async def ask(payload: AskPayload, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Answer a question about the captured traffic, with cache + session memory."""
    if not settings.OPENROUTER_API_KEY.strip():
        # Deliberately the same sentence the RAG path answered with, and the same
        # one /agent/ask uses; the bundle renders any non-2xx as a network error.
        raise HTTPException(
            status_code=503,
            detail="OPENROUTER_API_KEY is not configured; the assistant is disabled.",
        )
    if not settings.SAQR_ENABLED:
        raise HTTPException(
            status_code=503, detail="The Saqr agent is disabled (SAQR_ENABLED=0)."
        )

    session_id = payload.session_id or "default-session"
    context = _build_context(session_id)
    if context:
        full_q = (
            "Use the prior short transcript as conversational context ONLY if needed.\n\n"
            f"Transcript (most-recent first):\n{context}\n\n"
            f"Now the new user question: {payload.question.strip()}"
        )
    else:
        full_q = payload.question.strip()

    ck = _norm_key(session_id + "||" + full_q)
    cached = cache.get(ck)
    if cached:
        # Served before the rate limit is consulted, deliberately: a cache hit
        # costs no model call and no money, so it should not spend budget. What
        # the budget exists to bound is *new* questions, which is exactly what
        # gets past this line.
        return {"cached": True, **cached}

    # The same limiter and the same concurrency gate /agent/ask uses -- not a
    # second budget of this route's own. The ceiling belongs to the assistant,
    # not to a URL: one run is now up to SAQR_MAX_STEPS model turns of real
    # money, and this endpoint is reachable unauthenticated on whatever network
    # the Pi is sitting on.
    try:
        ratelimit.limiter().check()
        ratelimit.gate().acquire()
    except ratelimit.RateLimited as exc:
        logger.info("/ask rejected: %s", exc)
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": str(max(1, int(exc.retry_after_s)))},
        ) from exc

    # A sessionmaker bound to this request's engine, so the tools honour a get_db
    # override (tests) and the configured database (production) alike -- and so
    # nothing here ever calls back into this process over HTTP.
    maker = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)

    try:
        result = await run_agent(full_q, session_factory=maker, emitter=None)
    except SaqrUnavailable as exc:
        logger.info("/ask rejected: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        ratelimit.gate().release()

    compact_answer = (result.answer or "")[:800]
    SESSION_MEMORY.setdefault(session_id, []).append(
        {"q": payload.question.strip(), "a": compact_answer}
    )
    if len(SESSION_MEMORY[session_id]) > MAX_TURNS:
        SESSION_MEMORY[session_id] = SESSION_MEMORY[session_id][-MAX_TURNS:]

    resp = {
        "mode": _mode_for(result),
        # The last tabular tool's real SELECT, values inlined, so the panel can
        # still show the query behind the numbers.
        "sql": result.sql or "",
        "answer": result.answer,
        "cols": list(result.cols),
        "rows": list(result.rows),
        "error": result.error,
    }
    cache.set(ck, resp)
    return {"cached": False, **resp}
