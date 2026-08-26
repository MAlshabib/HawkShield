"""The single ORM definition for HawkShield.

``Packet`` is the one and only model for the ``packets`` table; no other module
declares a model or a ``declarative_base()``.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Float, Integer, String, Text

from backend.app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Packet(Base):
    """One classified attack frame, written by the detector."""

    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=_utcnow, index=True)

    iface = Column(String(64), index=True, nullable=True)
    src_mac = Column(String(32), nullable=True)
    dst_mac = Column(String(32), nullable=True)
    bssid = Column(String(32), nullable=True)

    frame_len = Column(Integer, nullable=True)
    channel_freq = Column(Integer, nullable=True)
    datarate = Column(Float, nullable=True)
    signal_dbm = Column(Float, nullable=True)
    wlan_ds = Column(Integer, nullable=True)
    wlan_retry = Column(Integer, nullable=True)
    wlan_type = Column(Integer, nullable=True)
    wlan_subtype = Column(Integer, nullable=True)
    wlan_duration = Column(Integer, nullable=True)

    proba_anomaly = Column(Float, nullable=True)
    proba_attack = Column(Float, nullable=True)
    predicted_label = Column(String(64), nullable=True)

    raw = Column(JSON, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Packet id={self.id} ts={self.ts} label={self.predicted_label}>"


class Document(Base):
    """Legacy knowledge-document table.  Kept for schema compatibility."""

    __tablename__ = "documents"

    id = Column(Integer, primary_key=True)
    title = Column(String(256), nullable=True)
    text = Column(Text, nullable=False)
    tags = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow)
