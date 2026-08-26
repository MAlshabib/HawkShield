"""Pydantic (v2) request/response models for the HTTP contract."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class PacketOut(BaseModel):
    """A full ``packets`` row."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: Optional[datetime] = None
    iface: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    bssid: Optional[str] = None
    frame_len: Optional[int] = None
    channel_freq: Optional[int] = None
    datarate: Optional[float] = None
    signal_dbm: Optional[float] = None
    wlan_ds: Optional[int] = None
    wlan_retry: Optional[int] = None
    wlan_type: Optional[int] = None
    wlan_subtype: Optional[int] = None
    wlan_duration: Optional[int] = None
    proba_anomaly: Optional[float] = None
    proba_attack: Optional[float] = None
    predicted_label: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Map
# ---------------------------------------------------------------------------
class APLocation(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bssid: str
    name: str
    lat: float
    lng: float


class RSSIPoint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bssid: str
    avg_rssi: float
    n: int


class SourceRSSIResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sa: str
    points: List[RSSIPoint]


class EstimateOriginPayload(BaseModel):
    sa: str = ""
    minutes: int = 10
    ap_locations: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
class ReportSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    period: str
    totals: Dict[str, int]
    summary: Dict[str, Any]


class ReportExportPayload(BaseModel):
    days: int = 30


# ---------------------------------------------------------------------------
# Ask / RAG
# ---------------------------------------------------------------------------
class AskPayload(BaseModel):
    question: str
    session_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
class ModelsPresent(BaseModel):
    stage1: bool
    stage2: bool


class HealthOut(BaseModel):
    status: str
    database: bool
    packets: int
    latest_packet_ts: Optional[datetime] = None
    models: ModelsPresent
    version: str
