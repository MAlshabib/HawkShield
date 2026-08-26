"""Natural-language question endpoint.

This router is deliberately thin: it owns the TTL cache and the short per-session
conversational memory, then delegates all retrieval / generation to
``backend.app.rag.packet_qa`` (owned by the RAG component).
"""
from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from backend.app.schemas import AskPayload

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ask"])

try:
    from backend.app.rag.packet_qa import RagUnavailable, packet_ask
except Exception as _import_exc:  # noqa: BLE001 - the RAG module is optional at boot
    logger.warning("RAG module unavailable (%s); /ask will answer 503.", _import_exc)

    class RagUnavailable(RuntimeError):  # type: ignore[no-redef]
        """Raised when the RAG backend cannot serve a question."""

    _RAG_IMPORT_ERROR = str(_import_exc)

    def packet_ask(question: str) -> Dict[str, Any]:  # type: ignore[misc]
        raise RagUnavailable(f"RAG backend is not installed: {_RAG_IMPORT_ERROR}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


MAX_TURNS = 5
CACHE_MAXSIZE = 200
CACHE_TTL_SECONDS = 600


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


@router.post("/ask")
def ask(payload: AskPayload) -> Dict[str, Any]:
    """Answer a question about the captured traffic, with cache + session memory."""
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
        return {"cached": True, **cached}

    try:
        result = packet_ask(full_q)
    except RagUnavailable as exc:
        logger.info("/ask rejected: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    compact_answer = (result.get("answer") or "")[:800]
    SESSION_MEMORY.setdefault(session_id, []).append(
        {"q": payload.question.strip(), "a": compact_answer}
    )
    if len(SESSION_MEMORY[session_id]) > MAX_TURNS:
        SESSION_MEMORY[session_id] = SESSION_MEMORY[session_id][-MAX_TURNS:]

    resp = {
        "mode": result.get("mode"),
        "sql": result.get("sql"),
        "answer": result.get("answer"),
        "cols": result.get("cols"),
        "rows": result.get("rows"),
        "error": result.get("error"),
    }
    cache.set(ck, resp)
    return {"cached": False, **resp}
