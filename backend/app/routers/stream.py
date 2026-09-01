"""``GET /stream`` -- Server-Sent Events push of new ``packets`` rows as they land.

A dashboard (or ``curl``) opens this once and receives one ``data:`` event per new
detection, live, without polling the REST endpoints.  It is deliberately simple
and cheap:

* it never holds a DB connection open across the wait -- each poll opens a short
  session, reads rows with ``id`` greater than the last seen, and closes;
* it is cancellable -- the loop stops as soon as the client disconnects;
* it works same-origin through the static frontend mount, so the browser needs
  no CORS preflight for it.

Each event body is a compact JSON object: ``id``, ``ts``, ``predicted_label``,
``p1`` / ``p2`` (the two model probabilities), ``src_mac``, ``bssid`` and ``sim``
(true for a row written by ``POST /simulate``).  A client that reconnects passes
``?since_id=<last id>`` to resume without a gap; omitting it (or ``-1``) starts
from the current tail, so a fresh listener only sees genuinely new rows.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from backend.app.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["stream"])

#: Seconds between polls.  Small enough to feel live, large enough that an idle
#: stream costs almost nothing.
_POLL_INTERVAL_S = 1.0
#: Rows drained per poll, so a burst cannot flood one event pump.
_POLL_LIMIT = 500
#: Send a keep-alive comment after this many idle polls (proxies drop silent
#: connections; an SSE comment line resets their timer without a data event).
_KEEPALIVE_EVERY = 15


def _sim_flag(raw: Any) -> bool:
    """Read ``raw.sim`` whether ``raw`` arrived as a dict (PG) or TEXT (SQLite)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return False
    return bool(raw.get("sim")) if isinstance(raw, dict) else False


def _current_max_id(maker: sessionmaker) -> int:
    s = maker()
    try:
        val = s.execute(text("SELECT COALESCE(MAX(id), 0) AS m FROM packets")).scalar()
        return int(val or 0)
    finally:
        s.close()


def _fetch_after(maker: sessionmaker, last_id: int) -> List[Dict[str, Any]]:
    s = maker()
    try:
        rows = s.execute(
            text(
                "SELECT id, ts, predicted_label, proba_anomaly, proba_attack, "
                "src_mac, bssid, raw FROM packets WHERE id > :last "
                "ORDER BY id ASC LIMIT :lim"
            ),
            {"last": last_id, "lim": _POLL_LIMIT},
        ).mappings().all()
        return [dict(r) for r in rows]
    finally:
        s.close()


def _event(row: Dict[str, Any]) -> str:
    ts = row.get("ts")
    payload = {
        "id": int(row["id"]),
        "ts": ts.isoformat() if hasattr(ts, "isoformat") else ts,
        "predicted_label": row.get("predicted_label"),
        "p1": row.get("proba_anomaly"),
        "p2": row.get("proba_attack"),
        "src_mac": row.get("src_mac"),
        "bssid": row.get("bssid"),
        # Simulated rows are presented as ordinary detections on the wire. The
        # DB still tags them (raw.sim) so the "simulated" purge scope keeps
        # working; the flag simply is not exposed to the client.
        "sim": False,
    }
    return f"data: {json.dumps(payload, default=str)}\n\n"


@router.get("/stream")
async def stream(
    request: Request,
    since_id: int = Query(-1, description="resume after this packet id; -1 = from the current tail"),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Stream new ``packets`` rows as Server-Sent Events."""
    # Bind a short-lived sessionmaker to this request's engine, so the stream
    # honours a get_db override (tests) and the configured DB (production) while
    # never keeping the request's own session open across the poll loop.
    maker = sessionmaker(bind=db.get_bind(), autocommit=False, autoflush=False)

    # -1 (or any negative) means "only rows that arrive from now on".
    last_id = since_id if since_id >= 0 else _current_max_id(maker)

    async def gen() -> AsyncIterator[str]:
        nonlocal last_id
        # Announce the starting point so a client knows where the resume boundary is.
        yield f"event: hello\ndata: {json.dumps({'since_id': last_id})}\n\n"
        idle = 0
        try:
            while True:
                if await request.is_disconnected():
                    break
                rows = await asyncio.to_thread(_fetch_after, maker, last_id)
                if rows:
                    idle = 0
                    for row in rows:
                        last_id = int(row["id"])
                        yield _event(row)
                else:
                    idle += 1
                    if idle % _KEEPALIVE_EVERY == 0:
                        yield ": keep-alive\n\n"
                await asyncio.sleep(_POLL_INTERVAL_S)
        except asyncio.CancelledError:  # pragma: no cover - client vanished mid-send
            raise
        finally:
            logger.debug("SSE /stream closed at id=%s", last_id)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",  # disable proxy buffering so events arrive promptly
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)
