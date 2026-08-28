"""``POST /admin/purge`` -- empty the ``packets`` table from the operator console.

The operator page at ``/admin`` needs a plain REST lever that resets every count
to zero: ``/attacks/analysis``, ``/dashboard``, ``/threats`` and
``/health.packets`` all read from ``packets``, so deleting its rows returns the
whole product to a clean slate for the next demo.

Three properties make a destructive, deliberately unauthenticated endpoint on a
device sitting on a conference network defensible:

* **A fixed sentinel is required.**  The body must carry ``{"confirm": "DELETE"}``
  exactly.  Without it the request is a 400 and nothing is deleted -- so a stray
  or replayed call with an empty or wrong body is inert, and the button in the UI
  has to have made the user type the word before it will send it.
* **A kill switch.**  ``ALLOW_PURGE=0`` makes the route answer 403 and delete
  nothing, so a hardened deployment can remove the capability rather than trust
  the sentinel.
* **``simulated`` scope is decided in Python.**  ``raw`` is a JSON column and the
  two dialects HawkShield runs on disagree about how to reach inside one, so the
  blobs are read and inspected in Python -- a row is simulated when ``raw`` is a
  mapping whose ``sim`` key is truthy, which is the same rule
  ``backend.detector.sink`` writes and ``/simulate`` tags with.  A real captured
  frame has no ``sim`` key at all, so it can never satisfy this on either dialect.

This is intentionally *not* routed through Saqr: the agent's ``delete_detections``
refuses an unfiltered "empty the table" by design and gates behind a minted
confirmation token, which is the right shape for a text box but the wrong shape
for a labelled operator button.  This endpoint is the button's contract.
"""
from __future__ import annotations

import logging
from typing import Any, List, Sequence

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db import get_db
from backend.app.models import Packet
from backend.app.schemas import PurgePayload, PurgeResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])

#: The exact confirmation the body must carry.  A fixed sentinel, not a minted
#: token: the operator types it into the dialog, the client sends it verbatim, and
#: the endpoint refuses anything else.  Kept Latin in every locale so the same
#: word is typed on an Arabic page.
PURGE_SENTINEL = "DELETE"


def _is_sim(raw: Any) -> bool:
    """A row is simulated when ``raw`` is a mapping with a truthy ``sim`` key.

    The same rule ``/simulate`` tags with and the agent's purge uses -- evaluated
    in Python so it means the same thing on SQLite and PostgreSQL, where the JSON
    operators and their truthiness rules differ.
    """
    return isinstance(raw, dict) and bool(raw.get("sim"))


def _delete_ids(db: Session, ids: Sequence[int], chunk: int = 500) -> int:
    """Delete rows by explicit primary key, in chunks.  Returns rows removed.

    By id rather than by predicate so the count is exactly the set inspected in
    Python, never a JSON predicate that might match a different set at delete
    time on one dialect.
    """
    removed = 0
    for start in range(0, len(ids), chunk):
        batch = list(ids[start:start + chunk])
        if not batch:
            continue
        removed += int(
            db.execute(Packet.__table__.delete().where(Packet.id.in_(batch))).rowcount or 0
        )
    return removed


@router.post("/admin/purge", response_model=PurgeResponse)
def purge_detections(
    payload: PurgePayload, db: Session = Depends(get_db)
) -> PurgeResponse:
    """Delete stored detections, all of them or only the simulated ones.

    Requires the exact sentinel in the body and the ``ALLOW_PURGE`` switch on.
    Commits once, never partially, and reports what the database actually
    removed alongside what remains.
    """
    if not settings.ALLOW_PURGE:
        raise HTTPException(status_code=403, detail="purge is disabled (ALLOW_PURGE=0)")

    if payload.confirm != PURGE_SENTINEL:
        # Refuse before touching a single row: an empty or wrong body deletes
        # nothing, which is the whole point of the sentinel.
        raise HTTPException(
            status_code=400,
            detail=(
                f'confirmation required: send {{"confirm": "{PURGE_SENTINEL}"}} to purge. '
                "Nothing was deleted."
            ),
        )

    if payload.scope == "simulated":
        ids: List[int] = [
            int(row_id)
            for row_id, raw in db.execute(select(Packet.id, Packet.raw)).all()
            if _is_sim(raw)
        ]
        deleted = _delete_ids(db, ids)
    else:
        # scope == "all": one unfiltered delete; rowcount is authoritative.
        deleted = int(db.execute(Packet.__table__.delete()).rowcount or 0)

    db.commit()

    remaining = int(db.execute(select(func.count(Packet.id))).scalar() or 0)
    logger.info(
        "admin purge scope=%s deleted=%d remaining=%d", payload.scope, deleted, remaining
    )
    return PurgeResponse(deleted=deleted, remaining=remaining)
