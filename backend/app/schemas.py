"""Pydantic (v2) request/response models for the HTTP contract."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union

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
# Agent (Saqr)
# ---------------------------------------------------------------------------
class AgentAskPayload(BaseModel):
    """Request body for ``POST /agent/ask``.

    The ``max_length`` here is a schema-level backstop, not the policy: a schema
    constraint has to be a constant, and the real, env-configurable limit is
    ``SAQR_MAX_QUESTION_CHARS``, applied by ``guard.sanitise_question`` in the
    handler along with the control- and hidden-character checks.  Both refuse
    with 400.

    There is deliberately no field for an admin token or a confirmation token.
    Both travel in request *headers* and are resolved by the router before the
    model runs, so neither can be smuggled into a body that some other component
    later echoes into a prompt.
    """

    question: str = Field(min_length=1, max_length=64_000)
    #: ``en`` or ``ar``.  ``None`` means "use ``SAQR_DEFAULT_LOCALE``".
    locale: Optional[Literal["en", "ar"]] = None
    session_id: Optional[str] = None


class AgentToolCall(BaseModel):
    """One tool execution inside a run, for the operator to inspect."""

    step: int
    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    ok: bool
    duration_ms: int = 0
    #: The identical call was made earlier in this run and was not re-executed.
    cached: bool = False
    #: The SELECT the tool actually ran, values inlined, when it ran one.
    sql_preview: Optional[str] = None
    row_count: Optional[int] = None
    error: Optional[Dict[str, Any]] = None


class AgentAskResponse(BaseModel):
    """Response body for ``POST /agent/ask``.

    No ``model`` field: which model answered is a server detail, it was being
    rendered in the UI, and it is now written to the server log instead.
    """

    answer: str
    locale: str
    steps: int
    #: Whether the server granted this request the operator tool surface. The
    #: client renders destructive controls from this, never from its own guess.
    is_admin: bool = False
    #: uuid4 hex.  The same value every SSE event of this run carries in
    #: ``run_id``, so the two transports correlate in a log.
    run_id: str = ""
    #: ``answered`` | ``step_limit`` | ``call_limit`` | ``timeout`` | ``error``
    stop_reason: str = "answered"
    elapsed_ms: int = 0
    #: The last SQL a tool ran, mirroring ``/ask``'s ``sql`` field.
    sql: Optional[str] = None
    cols: List[str] = Field(default_factory=list)
    rows: List[Dict[str, Any]] = Field(default_factory=list)
    tool_calls: List[AgentToolCall] = Field(default_factory=list)
    error: Optional[str] = None


class AgentToolInfo(BaseModel):
    """One entry of ``GET /agent/tools``.

    The list itself is already filtered by the request's capability, so an entry
    appearing here is one this caller could actually reach.  ``admin`` and
    ``destructive`` are still published because the UI needs them to decide how
    a control is labelled and whether it needs a confirm step.
    """

    name: str
    #: Stable i18n key, so the frontend generates its label table from here.
    label_key: str
    description: str
    #: True for a tool that writes to the database.
    mutating: bool = False
    #: True for a tool published only to a request carrying ``SAQR_ADMIN_TOKEN``.
    admin: bool = False
    #: True for a tool that destroys data and therefore proposes before acting.
    destructive: bool = False
    tags: List[str] = Field(default_factory=list)
    args_schema: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Simulate
# ---------------------------------------------------------------------------
class SimulatePayload(BaseModel):
    """Request body for ``POST /simulate``.

    ``attacks`` is ``"all"`` or a list of class names / frontend keys
    (``"deauth"``, ``"Kr00k"``, ...).  ``count`` is the target number of
    *persisted detections per requested class*; the endpoint replays the corpus
    segment until it reaches that many, capped at ``SIM_MAX_COUNT``.
    """

    attacks: Union[str, List[str]] = "all"
    # Upper bound is a fixed ceiling, not SIM_MAX_COUNT: a schema constraint
    # must be a constant, and this stops a 2^31 value reaching the handler.
    # The configurable SIM_MAX_COUNT (<= this) is applied again at runtime.
    count: int = Field(default=50, ge=1, le=10000)
    intensity: str = Field(default="burst", pattern="^(burst|trickle)$")


class SimulateClassResult(BaseModel):
    """Per-class outcome of a simulation run."""

    requested: int
    frames_pushed: int
    detected: int
    persisted: int
    #: The label the model actually assigned most often (honest: not always the
    #: requested class -- Kr00k confuses to Disas in isolation).
    top_label: Optional[str] = None
    labels: Dict[str, int] = Field(default_factory=dict)


class SimulateResponse(BaseModel):
    """Summary returned by ``POST /simulate``."""

    sim_batch: str
    model_version: str
    intensity: str
    classes: List[str]
    count_per_class: int
    total_persisted: int
    per_class: Dict[str, SimulateClassResult]


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
class ModelsPresent(BaseModel):
    stage1: bool
    stage2: bool
    #: v2 ONNX (TCN) artefact present *and* matching the running feature_spec.
    v2: bool = False
    #: v2 LightGBM artefact present *and* matching the running feature_spec.
    v2_gbdt: bool = False


class CaptureStatus(BaseModel):
    """What the sensor is configured to do, and what the kernel says it is doing.

    Configuration fields (``iface``, ``channel``, ``target_ssid``) are always
    present.  Everything else is ``None`` when it genuinely cannot be known from
    inside the API process -- off Linux, or when the interface does not exist.
    ``None`` never means "probably fine": the dashboard's existing defect is that
    it infers the interface and channel from the newest stored packet, so a
    guessed value here would be the same bug wearing a better label.
    """

    #: Configured ``CAPTURE_IFACE``.
    iface: Optional[str] = None
    #: Configured ``CAPTURE_CHANNEL``. What the radio is *set to*, not a readback.
    channel: Optional[int] = None
    #: Configured ``TARGET_SSID``; ``None`` when unset (no filter).
    target_ssid: Optional[str] = None
    #: The interface exists in sysfs. ``None`` off Linux, where absence is unknowable.
    present: Optional[bool] = None
    #: True when the link type is a radiotap/prism monitor interface.
    monitor_mode: Optional[bool] = None
    #: Human-readable link type: "monitor-radiotap", "managed", "ethernet", ...
    link_type: Optional[str] = None
    #: Kernel ``operstate``: "up", "down", "unknown", ...
    operstate: Optional[str] = None
    #: ``iface`` on the newest stored packet -- what the sensor is *actually*
    #: delivering, as opposed to what it was told to use. ``None`` when no rows.
    observed_iface: Optional[str] = None
    #: ``channel_freq`` (MHz) on the newest stored packet. ``None`` when no rows.
    observed_channel_freq: Optional[int] = None
    #: "config" or "config+sysfs" -- whether any field here was measured at all.
    source: str = "config"


class HealthOut(BaseModel):
    # ``model_version`` / ``model_problems`` collide with pydantic's protected
    # ``model_`` namespace.  The names are the ones the contract publishes, so
    # disable the guard for this response model rather than rename the fields.
    model_config = ConfigDict(protected_namespaces=())

    status: str
    database: bool
    packets: int
    latest_packet_ts: Optional[datetime] = None
    models: ModelsPresent
    #: Which pipeline the detector would load: "v2-gbdt", "v2-tcn", "v1" or "none".
    model_version: str = "none"
    #: Feature-contract version this build of the code implements.
    spec_version: Optional[str] = None
    #: Version the on-disk v2 artefact claims; differs from ``spec_version``
    #: exactly when the export is stale, which is why it is reported separately.
    artefact_spec_version: Optional[str] = None
    #: Why the v2 artefact was rejected, when it was present but unusable.
    model_problems: List[str] = Field(default_factory=list)
    #: Capture interface and channel. Additive: an older client that does not
    #: know this key ignores it, which is why it could be added to a frozen
    #: response shape.
    capture: CaptureStatus = Field(default_factory=CaptureStatus)
    version: str
