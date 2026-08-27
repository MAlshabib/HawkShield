"""Two-phase confirmation for the destructive tools.

A destructive tool never acts on its first call.  It *proposes*: it computes what
would happen, mints a token bound to that exact proposal, and returns

    {"requires_confirmation": true, "action", "summary", "affected_estimate",
     "confirm_token", "expires_in_s"}

The operator sees the summary in the UI and confirms.  The client then replays
the identical question with the token in the ``X-HawkShield-Confirm`` header, the
router resolves it **once, before the model runs**, and the tool -- offered the
same arguments again -- finds a matching confirmation waiting for it and acts.

Three properties are the whole point, and each is enforced here rather than by
asking the model to behave:

**The token travels outside the conversation.**  It is minted by the server,
handed to the *client*, and comes back in a *header*.  Tool argument models set
``extra="forbid"``, so a model that tries to pass a token as an argument has its
call rejected by pydantic before any code runs, and the token it saw in a
previous tool result is stripped from the copy the model reads (see
``loop._redact_for_model``).  A model therefore has no path by which to confirm
its own destructive action, which is a stronger statement than "it was told not
to".

**The token is bound to the arguments.**  ``fingerprint()`` hashes the action
name together with the normalised arguments.  A token minted for "delete Deauth
rows from the last 10 minutes" cannot authorise "delete everything": the
fingerprints differ and :func:`consume` refuses.

**The token is single-use and short-lived.**  It is deleted the moment it is
consumed, and expires after ``SAQR_CONFIRM_TTL_S``.  A replay of a captured
confirmation is refused with the same explicit reason a forgery is.

The store is a process-local dict under a lock.  HawkShield is one uvicorn worker
on a Pi; a token that does not survive a restart is correct behaviour, not a
limitation -- an operator's click should not outlive the process that asked for
it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from backend.app.config import settings

logger = logging.getLogger(__name__)

__all__ = [
    "Confirmation",
    "ConfirmationRejected",
    "DESTRUCTIVE_ACTIONS",
    "clear",
    "consume",
    "fingerprint",
    "mint",
    "pending_count",
    "resolve",
]

#: Every action that requires a confirmation token.  A tool whose name is not in
#: here can never be confirmed, so a token minted for one destructive action can
#: never be redirected at some other tool.
DESTRUCTIVE_ACTIONS = ("purge_simulated_detections", "delete_detections")


class ConfirmationRejected(ValueError):
    """A presented token was absent, forged, expired, replayed or mismatched."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Confirmation:
    """A token the *server* minted and the *server* has now matched.

    Instances only ever come from :func:`resolve`, which is called by the router
    with a header value.  A tool receives one through the tool context, as a
    Python object, never as data it parsed out of a string.
    """

    token: str
    action: str
    fingerprint: str
    minted_at: float
    expires_at: float
    summary: str = ""
    affected_estimate: int = 0

    def matches(self, action: str, args_fingerprint: str) -> bool:
        """True when this confirmation authorises exactly this call."""
        return self.action == action and hmac.compare_digest(
            self.fingerprint, args_fingerprint
        )


@dataclass
class _Pending:
    """One minted, not-yet-consumed token."""

    action: str
    fingerprint: str
    minted_at: float
    expires_at: float
    summary: str
    affected_estimate: int


_STORE: Dict[str, _Pending] = {}
_LOCK = threading.Lock()


def fingerprint(action: str, args: Any) -> str:
    """A stable hash of ``(action, normalised arguments)``.

    ``args`` may be a pydantic model or a plain dict.  It is reduced to canonical
    JSON -- keys sorted, ``None`` values dropped, no incidental whitespace -- so
    that two spellings of the same request (``{"label": "Deauth"}`` and
    ``{"label": "Deauth", "src_mac": null}``) produce the same fingerprint and a
    genuinely different request cannot.
    """
    payload = args
    if hasattr(args, "model_dump"):
        payload = args.model_dump(exclude_none=True)
    if not isinstance(payload, dict):
        payload = {"value": payload}
    normalised = {k: v for k, v in sorted(payload.items()) if v is not None}
    body = json.dumps(normalised, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(f"{action}|{body}".encode("utf-8")).hexdigest()


def _purge_locked(now: float) -> None:
    """Drop expired tokens, then the oldest ones if the store is over budget."""
    for token in [t for t, p in _STORE.items() if p.expires_at <= now]:
        del _STORE[token]
    budget = max(1, int(settings.SAQR_CONFIRM_MAX_PENDING))
    while len(_STORE) > budget:
        oldest = min(_STORE.items(), key=lambda item: item[1].minted_at)[0]
        del _STORE[oldest]
        logger.info("Evicted the oldest pending Saqr confirmation; the store is full.")


def mint(
    action: str,
    args: Any,
    *,
    summary: str = "",
    affected_estimate: int = 0,
) -> Tuple[str, float]:
    """Issue a token for one proposed destructive call.

    Returns ``(token, ttl_seconds)``.  Raises ``ValueError`` for an action that is
    not in :data:`DESTRUCTIVE_ACTIONS`, so a new tool cannot become confirmable by
    accident.
    """
    if action not in DESTRUCTIVE_ACTIONS:
        raise ValueError(f"{action!r} is not a destructive action; it cannot be confirmed.")

    ttl = max(1.0, float(settings.SAQR_CONFIRM_TTL_S))
    now = time.time()
    token = secrets.token_urlsafe(24)
    with _LOCK:
        _purge_locked(now)
        _STORE[token] = _Pending(
            action=action,
            fingerprint=fingerprint(action, args),
            minted_at=now,
            expires_at=now + ttl,
            summary=summary,
            affected_estimate=int(affected_estimate),
        )
    logger.info(
        "Minted a Saqr confirmation for %s (estimate %d row(s), ttl %.0fs)",
        action, int(affected_estimate), ttl,
    )
    return token, ttl


def resolve(presented: Optional[str]) -> Optional[Confirmation]:
    """Look a presented token up **without** consuming it.

    Called by the router, once, before the model runs.  Returns ``None`` for a
    missing, unknown or expired token: an unrecognised token is simply not a
    confirmation, and the run proceeds as an unconfirmed one, which means the
    destructive tool proposes again instead of acting.  Nothing is refused at
    this point, because the request may not have been about a destructive tool
    at all.
    """
    token = (presented or "").strip()
    if not token:
        return None
    now = time.time()
    with _LOCK:
        _purge_locked(now)
        pending = _STORE.get(token)
        if pending is None:
            logger.info("A Saqr confirmation token was presented that this process never minted.")
            return None
    return Confirmation(
        token=token,
        action=pending.action,
        fingerprint=pending.fingerprint,
        minted_at=pending.minted_at,
        expires_at=pending.expires_at,
        summary=pending.summary,
        affected_estimate=pending.affected_estimate,
    )


def consume(confirmation: Optional[Confirmation], action: str, args: Any) -> None:
    """Spend a confirmation for ``(action, args)``, or raise.

    This is the only function that authorises a destructive write, and it
    validates against the server's own store every time -- never by trusting the
    :class:`Confirmation` object it was handed, which is why a forged instance
    buys nothing.  On success the token is deleted, so a second call with the
    same token is a replay and is refused.
    """
    if confirmation is None:
        raise ConfirmationRejected(
            "No confirmation token accompanied this request.", reason="missing"
        )
    if confirmation.action != action:
        raise ConfirmationRejected(
            f"That confirmation was issued for {confirmation.action!r}, not {action!r}.",
            reason="action_mismatch",
        )

    expected = fingerprint(action, args)
    now = time.time()
    with _LOCK:
        _purge_locked(now)
        pending = _STORE.get(confirmation.token)
        if pending is None:
            raise ConfirmationRejected(
                "That confirmation token is unknown, already used, or has expired.",
                reason="unknown_or_spent",
            )
        if pending.expires_at <= now:
            del _STORE[confirmation.token]
            raise ConfirmationRejected(
                "That confirmation token has expired. Ask again to get a fresh one.",
                reason="expired",
            )
        if pending.action != action:
            raise ConfirmationRejected(
                f"That confirmation was issued for {pending.action!r}, not {action!r}.",
                reason="action_mismatch",
            )
        if not hmac.compare_digest(pending.fingerprint, expected):
            raise ConfirmationRejected(
                "That confirmation was issued for different arguments. Confirm the "
                "exact action that was proposed.",
                reason="argument_mismatch",
            )
        # Single use: spent the instant it is accepted, so a captured token
        # cannot be replayed even inside its TTL.
        del _STORE[confirmation.token]

    logger.info("Consumed a Saqr confirmation for %s", action)


def pending_count() -> int:
    """How many unspent tokens exist.  For ``get_runtime_config`` and tests."""
    with _LOCK:
        _purge_locked(time.time())
        return len(_STORE)


def clear() -> None:
    """Drop every pending token.  Used by tests and on a configuration change."""
    with _LOCK:
        _STORE.clear()
