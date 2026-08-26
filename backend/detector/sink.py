"""Batched writer for detected attack frames.

The original detector opened a session and committed **once per attack packet**,
which falls over on a Pi 4 during a deauth flood (thousands of frames a second,
one round-trip each).  ``PacketSink`` buffers rows and flushes on whichever comes
first: ``BATCH_SIZE`` rows, ``BATCH_FLUSH_SECONDS`` since the oldest buffered row,
or ``close()``.

The ORM model and the session factory come from ``backend.app`` - this module never
declares its own ``declarative_base()``.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.detector._config import get_settings
from backend.detector.pipeline import Verdict

logger = logging.getLogger(__name__)

__all__ = ["PacketSink"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_int(v: Any) -> Optional[int]:
    try:
        return None if v is None else int(round(float(v)))
    except Exception:
        return None


def _as_float(v: Any) -> Optional[float]:
    try:
        if v is None:
            return None
        f = float(v)
        return None if f != f else f          # NaN means "absent", not 0.0
    except Exception:
        return None


# The `packets` columns are named after the v1 tshark fields.  v2 rows carry the
# same physical quantities under the ``feature_spec`` names, so the DB schema does
# not change -- only the lookup does.  First key present wins.
_COLUMN_ALIASES: Dict[str, tuple] = {
    "frame_len":    ("frame.len",),
    "channel_freq": ("radiotap.channel.freq", "radio.freq_mhz"),
    "datarate":     ("radiotap.datarate", "radio.datarate"),
    "signal_dbm":   ("wlan_radio.signal_dbm", "radio.signal_dbm"),
    "wlan_ds":      ("wlan.fc.ds", "fc.ds"),
    "wlan_retry":   ("wlan.fc.retry", "fc.retry"),
    "wlan_type":    ("wlan.fc.type", "fc.type"),
    "wlan_subtype": ("wlan.fc.subtype", "fc.subtype"),
    "wlan_duration": ("wlan.duration",),
}

#: v2 encodes "this frame has no frame-control type/subtype" as -1, not NaN.
_MINUS_ONE_IS_ABSENT = frozenset({"wlan_type", "wlan_subtype"})


def _column(row: Dict[str, Any], column: str) -> Any:
    """Read one `packets` column out of a v1 *or* v2 feature row."""
    for key in _COLUMN_ALIASES[column]:
        if key in row:
            value = row[key]
            if value is None:
                continue
            if column in _MINUS_ONE_IS_ABSENT:
                try:
                    if float(value) < 0:
                        return None
                except (TypeError, ValueError):
                    pass
            return value
    return None


class PacketSink:
    """Buffered ``packets`` writer.  Thread-safe; safe to use as a context manager."""

    def __init__(
        self,
        batch_size: Optional[int] = None,
        flush_seconds: Optional[float] = None,
        session_factory: Any = None,
        ensure_schema: bool = False,
    ) -> None:
        s = get_settings()
        self.batch_size = int(batch_size if batch_size is not None else getattr(s, "BATCH_SIZE", 20))
        self.flush_seconds = float(
            flush_seconds if flush_seconds is not None else getattr(s, "BATCH_FLUSH_SECONDS", 2.0)
        )

        if session_factory is None:
            from backend.app.db import SessionLocal  # imported lazily: DB is optional in dry-run

            session_factory = SessionLocal
        self._session_factory = session_factory

        from backend.app.models import Packet  # the single ORM definition

        self._Packet = Packet

        if ensure_schema:
            from backend.app.db import init_db

            init_db()

        self._buf: List[Any] = []
        self._oldest: Optional[float] = None
        self._lock = threading.Lock()
        self.written = 0
        self.failed = 0

    # -- context manager ---------------------------------------------------
    def __enter__(self) -> "PacketSink":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- API ---------------------------------------------------------------
    def write(self, raw: Dict[str, Any], row: Dict[str, Any], verdict: Verdict, iface: str) -> None:
        """Buffer one detected attack; flush if the batch is full or stale."""
        rec = self._Packet(
            ts=_utcnow(),
            iface=iface,
            src_mac=raw.get("sa"),
            dst_mac=raw.get("da"),
            bssid=raw.get("bssid"),
            frame_len=_as_int(_column(row, "frame_len")),
            channel_freq=_as_int(_column(row, "channel_freq")),
            datarate=_as_float(_column(row, "datarate")),
            signal_dbm=_as_float(_column(row, "signal_dbm")),
            wlan_ds=_as_int(_column(row, "wlan_ds")),
            wlan_retry=_as_int(_column(row, "wlan_retry")),
            wlan_type=_as_int(_column(row, "wlan_type")),
            wlan_subtype=_as_int(_column(row, "wlan_subtype")),
            wlan_duration=_as_int(_column(row, "wlan_duration")),
            proba_anomaly=_as_float(verdict.p1),
            proba_attack=_as_float(verdict.p2),
            predicted_label=verdict.label,
            raw=raw,
        )
        with self._lock:
            self._buf.append(rec)
            if self._oldest is None:
                self._oldest = time.monotonic()
            due = (
                len(self._buf) >= self.batch_size
                or (time.monotonic() - self._oldest) >= self.flush_seconds
            )
        if due:
            self.flush()

    def maybe_flush(self) -> None:
        """Flush if the buffer has been sitting longer than ``BATCH_FLUSH_SECONDS``.

        Call this from an idle loop (the detector heartbeat does) so the last few
        rows of a burst do not sit in memory until the next attack arrives.
        """
        with self._lock:
            stale = (
                self._buf
                and self._oldest is not None
                and (time.monotonic() - self._oldest) >= self.flush_seconds
            )
        if stale:
            self.flush()

    def flush(self) -> None:
        """Commit everything currently buffered.  Never raises."""
        with self._lock:
            batch, self._buf = self._buf, []
            self._oldest = None
        if not batch:
            return
        try:
            session = self._session_factory()
        except Exception as e:
            self.failed += len(batch)
            logger.error("[db] could not open a session, dropped %d rows: %s", len(batch), e)
            return
        try:
            session.add_all(batch)
            session.commit()
            self.written += len(batch)
            logger.debug("[db] committed %d rows (total %d)", len(batch), self.written)
        except Exception as e:
            self.failed += len(batch)
            try:
                session.rollback()
            except Exception:  # pragma: no cover - defensive
                pass
            logger.error("[db] commit failed, dropped %d rows: %s", len(batch), e)
        finally:
            try:
                session.close()
            except Exception:  # pragma: no cover - defensive
                pass

    def close(self) -> None:
        """Final flush.  Idempotent."""
        self.flush()
        logger.info("[db] sink closed: written=%d failed=%d", self.written, self.failed)
