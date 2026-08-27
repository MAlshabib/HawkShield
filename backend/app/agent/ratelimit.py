"""A rolling-window call counter and a concurrency gate for ``/agent/ask``.

The window is the deque pattern ``routers/simulate.py`` already uses, lifted into
a reusable class because the agent needs two of them (one per limit) and because
a limiter with no way to reset it cannot be tested.

Neither of these is a security control.  They exist because one uvicorn worker
on a Pi 4 is the whole deployment: a stuck client retrying an agent run, or three
browser tabs each opening one, is enough to starve the capture loop of CPU.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque, Optional

logger = logging.getLogger(__name__)

__all__ = ["RateLimiter", "ConcurrencyGate", "RateLimited"]


class RateLimited(RuntimeError):
    """The caller exceeded a limit.  The router turns this into HTTP 429."""

    def __init__(self, message: str, retry_after_s: float = 1.0) -> None:
        super().__init__(message)
        self.retry_after_s = max(0.0, float(retry_after_s))


class RateLimiter:
    """At most ``max_calls`` acquisitions per ``window_s`` rolling seconds."""

    def __init__(self, max_calls: int, window_s: float, name: str = "agent") -> None:
        self.max_calls = max(1, int(max_calls))
        self.window_s = max(0.001, float(window_s))
        self.name = name
        self._calls: Deque[float] = deque()
        self._lock = threading.Lock()

    def check(self) -> None:
        """Record one call, or raise :class:`RateLimited`."""
        now = time.monotonic()
        with self._lock:
            while self._calls and now - self._calls[0] > self.window_s:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                oldest = self._calls[0]
                retry_after = max(0.0, self.window_s - (now - oldest))
                raise RateLimited(
                    f"{self.name} rate limit: {self.max_calls} calls per "
                    f"{int(self.window_s)}s. Try again shortly.",
                    retry_after_s=retry_after,
                )
            self._calls.append(now)

    def reset(self) -> None:
        """Forget every recorded call."""
        with self._lock:
            self._calls.clear()


class ConcurrencyGate:
    """At most ``max_concurrent`` holders at once, refusing rather than queueing.

    Queueing would be worse than refusing here: a caller blocked behind two
    90-second agent runs learns nothing until its own request times out, whereas
    an immediate 429 tells it exactly what happened.
    """

    def __init__(self, max_concurrent: int, name: str = "agent") -> None:
        self.max_concurrent = max(1, int(max_concurrent))
        self.name = name
        self._lock = threading.Lock()
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    def acquire(self) -> None:
        """Take a slot, or raise :class:`RateLimited`."""
        with self._lock:
            if self._in_flight >= self.max_concurrent:
                raise RateLimited(
                    f"{self.name} is busy: {self.max_concurrent} runs already in "
                    f"flight on this host. Try again shortly.",
                    retry_after_s=2.0,
                )
            self._in_flight += 1

    def release(self) -> None:
        """Give a slot back.  Safe to call more often than :meth:`acquire`."""
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)

    def reset(self) -> None:
        with self._lock:
            self._in_flight = 0

    def __enter__(self) -> "ConcurrencyGate":
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


_limiter: Optional[RateLimiter] = None
_gate: Optional[ConcurrencyGate] = None
_singleton_lock = threading.Lock()


def limiter() -> RateLimiter:
    """The process-wide ``/agent/ask`` rate limiter, built from settings on demand."""
    global _limiter
    with _singleton_lock:
        if _limiter is None:
            from backend.app.config import settings

            _limiter = RateLimiter(
                settings.SAQR_RATE_MAX, settings.SAQR_RATE_WINDOW_S, name="agent"
            )
        return _limiter


def gate() -> ConcurrencyGate:
    """The process-wide ``/agent/ask`` concurrency gate."""
    global _gate
    with _singleton_lock:
        if _gate is None:
            from backend.app.config import settings

            _gate = ConcurrencyGate(settings.SAQR_MAX_CONCURRENT_RUNS, name="Saqr")
        return _gate


def reset_all() -> None:
    """Drop both singletons.  Used by tests that change the configuration."""
    global _limiter, _gate
    with _singleton_lock:
        _limiter = None
        _gate = None
