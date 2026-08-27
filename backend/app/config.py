"""Central application configuration.

Every HawkShield component (app, detector, RAG) imports the single ``settings``
object defined here.  All values are environment-driven; nothing is hardcoded to
a developer machine.  The ``.env`` file is read from the repository root.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Annotated, Dict, List, Any, Optional

from pydantic import AliasChoices, Field, field_validator
from pydantic_core.core_schema import ValidationInfo
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# The ONE permitted ``backend.app -> backend.detector`` import (CONTRACT section 6).
# ``feature_spec`` is a stdlib-only leaf module: it imports ``math``, ``re`` and
# ``typing`` and nothing else, so it drags neither scapy nor lightgbm into the web
# process.  Importing it here means the class list, the feature list and the spec
# version have exactly one definition in the repository -- which is what v1 did not
# have, and is why v1 shipped a model whose feature space nobody could reproduce.
from backend.detector.feature_spec import (  # noqa: E402
    ATTACK_CLASSES,
    CLASSES,
    FEATURE_ORDER,
    SPEC_VERSION,
)

logger = logging.getLogger(__name__)

# backend/app/config.py -> backend/app -> backend -> <repo root>
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

#: Reported by GET /health.
APP_VERSION: str = "1.0.0"

__all__ = [
    "APP_VERSION",
    "ATTACK_CLASSES",
    "CLASSES",
    "FEATURE_ORDER",
    "FRONT_TYPE_MAP",
    "FRONT_TYPES",
    "REPO_ROOT",
    "SPEC_VERSION",
    "Settings",
    "MODEL_VERSIONS",
    "MODEL_VERSION_ALIASES",
    "canonical_model_version",
    "configure_logging",
    "front_key",
    "gbdt_status",
    "gbdt_model_problems",
    "redact_url",
    "settings",
    "v2_meta_problems",
    "v2_status",
]

# --------------------------------------------------------------------------- #
# Model selection vocabulary                                                    #
# --------------------------------------------------------------------------- #
# Duplicated, deliberately, from ``backend.detector.pipeline``: this module must
# stay importable in the web process without dragging lightgbm and onnxruntime in
# behind it, and ``GET /health`` needs to name the same three targets the detector
# chooses between.  ``test_pipeline_v2.test_model_version_vocabulary_is_shared``
# asserts the two copies are equal, so they cannot drift.
MODEL_VERSIONS = ("auto", "v1", "v2-tcn", "v2-gbdt")

#: ``v2`` predates the tcn/gbdt split and still means the TCN, so an existing
#: ``.env`` or ``--model-version v2`` keeps working unchanged.
MODEL_VERSION_ALIASES = {
    "v2": "v2-tcn",
    "tcn": "v2-tcn",
    "v2tcn": "v2-tcn",
    "gbdt": "v2-gbdt",
    "v2gbdt": "v2-gbdt",
    "lightgbm": "v2-gbdt",
}


def canonical_model_version(value: Any) -> str:
    """Normalise a requested model version, or raise ``ValueError``."""
    raw = str(value or "auto").strip().lower()
    version = MODEL_VERSION_ALIASES.get(raw, raw)
    if version not in MODEL_VERSIONS:
        raise ValueError(
            f"model_version must be one of {MODEL_VERSIONS} "
            f"(aliases: {sorted(MODEL_VERSION_ALIASES)}), got {value!r}"
        )
    return version


# Defaults for the path settings, also used when the environment supplies a blank
# value (see Settings._blank_means_default).
_PATH_DEFAULTS = {
    "MODEL_DIR": REPO_ROOT / "models",
    "FRONTEND_DIST": REPO_ROOT / "frontend" / "out",
    "AP_LOCATIONS_FILE": REPO_ROOT / "backend" / "config" / "ap_locations.json",
}


class Settings(BaseSettings):
    """Runtime configuration, populated from the environment / repo-root ``.env``."""

    model_config = SettingsConfigDict(
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---- database -------------------------------------------------------
    DATABASE_URL: str = "postgresql+psycopg2://hawkshield:CHANGE_ME@localhost:5432/hawkshield"

    # ---- model bundles --------------------------------------------------
    MODEL_DIR: Path = REPO_ROOT / "models"
    STAGE1_MODEL: str = "stage1_binary_bundle.joblib"
    STAGE2_MODEL: str = "stage2_multiclass_bundle.joblib"
    STAGE1_THRESHOLD: float = 0.40
    STAGE2_THRESHOLD: float = 0.80

    # ---- v2 models (LightGBM + rollups, and the causal TCN) --------------
    #: One of ``MODEL_VERSIONS``.  ``auto`` -> v2-gbdt, else v2-tcn, else v1,
    #: taking the first whose artefact is present and matches ``feature_spec``.
    #: ``v2`` is accepted and means ``v2-tcn`` (see ``MODEL_VERSION_ALIASES``).
    MODEL_VERSION: str = "auto"
    V2_MODEL: str = "hawkshield_v2.onnx"
    V2_META: str = "hawkshield_v2_meta.json"
    #: LightGBM text model: 46 per-frame features + 36 causal rolling aggregates.
    V2_GBDT: str = "hawkshield_v2_gbdt.txt"
    #: LightGBM predict threads.  Pinned for the same reason V2_ORT_THREADS is:
    #: the library default is one thread per core, which starves the capture loop
    #: on a 4-core Pi that is also running scapy, the API and Postgres.
    GBDT_NUM_THREADS: int = 2
    #: Frames scored per onnxruntime call.  See ``V2Pipeline`` for the tradeoff.
    V2_BATCH_FRAMES: int = 32
    #: onnxruntime intra-op threads; 0 means "leave the runtime default".
    #
    # Not 0.  The default lets onnxruntime spin up one thread per core and
    # spin-wait between calls, which is right for a batch job and wrong for a
    # capture loop that calls it every 32 frames: measured over 5000 frames of
    # data/samples/deauth_raw_decrypted.pcapng on a 16-core dev box, the default
    # cost 302 frame/s and 166 us/frame of inference, and pinning it to 2 threads
    # cost 723 frame/s and 55 us/frame.  Same graph, same maths, 2.4x throughput.
    # A Pi 4 has 4 cores it also needs for capture, the API and Postgres.
    V2_ORT_THREADS: int = 2

    # ---- capture --------------------------------------------------------
    CAPTURE_IFACE: str = "wlan1"
    CAPTURE_CHANNEL: int = 6
    TARGET_SSID: str = ""
    BATCH_SIZE: int = 20
    BATCH_FLUSH_SECONDS: float = 2.0

    # ---- RAG (OpenRouter; OpenAI-compatible API) -------------------------
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    # DeepSeek V4 Flash: strong SQL + strict JSON, 1M context, ~$0.08/$0.16 per M.
    # Alternatives: z-ai/glm-5.3-flash, qwen/qwen3.7-flash
    GEN_MODEL: str = "deepseek/deepseek-v4-flash"
    OPENROUTER_SITE_URL: str = "https://github.com/MAlshabib/HawkShield"
    OPENROUTER_APP_NAME: str = "HawkShield"
    HUMANIZE_SQL: int = 1

    # ---- Saqr agent (POST /agent/ask) -----------------------------------
    #: Master switch.  ``0`` makes every ``/agent/*`` route answer 503 without
    #: touching OpenRouter, exactly as a missing key does.
    SAQR_ENABLED: bool = True
    #: Model id for the agent.  Blank means "reuse ``GEN_MODEL``", so an existing
    #: ``.env`` written before the agent existed keeps working untouched.  Read
    #: through :attr:`saqr_model`, never directly.
    SAQR_MODEL: str = ""
    #: ``en`` or ``ar``.  Used when the request body does not say.
    SAQR_DEFAULT_LOCALE: str = "en"
    SAQR_TEMPERATURE: float = 0.1
    #: Model turns that may call tools before the loop forces a prose answer.
    SAQR_MAX_STEPS: int = 6
    #: Total tool executions per run, across all steps.
    SAQR_MAX_TOOL_CALLS: int = 12
    #: Wall-clock budget for one ``/agent/ask``, and for one tool inside it.
    SAQR_RUN_TIMEOUT_S: float = 90.0
    SAQR_TOOL_TIMEOUT_S: float = 20.0
    #: ``LIMIT`` safety net appended to an unbounded ``SELECT``.  ``RAG_MAX_ROWS``
    #: is accepted as a deprecated alias so an existing ``.env`` still tunes it.
    SAQR_MAX_ROWS: int = Field(
        default=500, validation_alias=AliasChoices("SAQR_MAX_ROWS", "RAG_MAX_ROWS")
    )
    #: Rows handed back to the UI in the response envelope (the model sees fewer).
    SAQR_UI_ROWS: int = 50
    #: Hard cap on the JSON a single tool result may add to the conversation.
    SAQR_MAX_TOOL_CHARS: int = 12000
    #: Postgres ``statement_timeout`` for agent SQL.  ``RAG_SQL_TIMEOUT_MS`` is
    #: accepted as a deprecated alias.
    SAQR_SQL_TIMEOUT_MS: int = Field(
        default=15000, validation_alias=AliasChoices("SAQR_SQL_TIMEOUT_MS", "RAG_SQL_TIMEOUT_MS")
    )
    #: Publish the ``run_sql`` escape hatch.  Off by default: the seven structured
    #: tools cover the dashboard, and model-authored SQL is the widest attack
    #: surface the agent has.
    SAQR_ALLOW_RAW_SQL: bool = False
    #: Publish ``run_simulation``, the one mutating tool.
    SAQR_ALLOW_SIMULATION_TOOL: bool = True
    #: Per-class detection cap the agent may ask ``/simulate`` for.  The effective
    #: cap is ``min(requested, this, SIM_MAX_COUNT)``.
    SAQR_SIM_TOOL_MAX_COUNT: int = 50
    #: Rolling-window rate limit on ``/agent/ask``.
    SAQR_RATE_MAX: int = 20
    SAQR_RATE_WINDOW_S: float = 60.0
    #: Agent runs allowed to be in flight at once on this (single) process.
    SAQR_MAX_CONCURRENT_RUNS: int = 2

    # ---- simulation (POST /simulate) ------------------------------------
    #: Master switch for the demo/testing endpoint.  On by default; set to 0 to
    #: return 403 from /simulate on a box where writing synthetic rows is not
    #: wanted.  Simulated rows are always tagged ``raw.sim = true`` so they stay
    #: filterable and purgeable whether or not this is on.
    ALLOW_SIMULATION: bool = True
    #: Hard ceiling on the per-class ``count`` a single /simulate call may request,
    #: so the endpoint can never be turned into a DB-fill weapon.
    SIM_MAX_COUNT: int = 500
    #: Parquet of held-out AWID3 rows /simulate replays.  Blank means the default
    #: committed file (``data/sim/awid3_sim_corpus.parquet``).
    SIM_CORPUS: str = ""

    # ---- web ------------------------------------------------------------
    CORS_ORIGINS: Annotated[List[str], NoDecode] = ["http://localhost:3000"]
    FRONTEND_DIST: Path = REPO_ROOT / "frontend" / "out"
    AP_LOCATIONS_FILE: Path = REPO_ROOT / "backend" / "config" / "ap_locations.json"

    # ---- misc -----------------------------------------------------------
    LOG_LEVEL: str = "INFO"

    # -- validators -------------------------------------------------------
    @field_validator("SIM_MAX_COUNT")
    @classmethod
    def _sim_cap_at_least_one(cls, v: int) -> int:
        """A zero or negative cap would make min(count, cap) select an invalid
        value and break every simulation run. Clamp to a sane floor."""
        return max(1, int(v))

    @field_validator(
        "SAQR_MAX_STEPS", "SAQR_MAX_TOOL_CALLS", "SAQR_MAX_ROWS", "SAQR_UI_ROWS",
        "SAQR_SIM_TOOL_MAX_COUNT", "SAQR_RATE_MAX", "SAQR_MAX_CONCURRENT_RUNS",
    )
    @classmethod
    def _at_least_one(cls, v: int) -> int:
        """A zero or negative budget would make every agent run fail closed."""
        return max(1, int(v))

    @field_validator("SAQR_DEFAULT_LOCALE")
    @classmethod
    def _known_locale(cls, v: str) -> str:
        """Only the two locales the prompt actually has a block for."""
        locale = str(v or "").strip().lower()
        if locale not in {"en", "ar"}:
            logger.warning("SAQR_DEFAULT_LOCALE=%r is not en/ar; falling back to en", v)
            return "en"
        return locale

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors(cls, v: object) -> List[str]:
        """Accept a comma-separated string (env) or an already-parsed list."""
        if v is None:
            return []
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        if isinstance(v, (list, tuple)):
            return [str(item).strip() for item in v if str(item).strip()]
        return [str(v)]

    @field_validator("MODEL_DIR", "FRONTEND_DIST", "AP_LOCATIONS_FILE", mode="before")
    @classmethod
    def _blank_means_default(cls, v: Any, vinfo: ValidationInfo) -> Any:
        """An empty value in .env means "unset", not "the repo root".

        `MODEL_DIR=` with nothing after it is a natural way to write "use the
        default", and .env.example ships exactly that. Without this, Path("")
        resolves to the repo root, which would make FRONTEND_DIST serve the whole
        checkout -- .env included -- over HTTP.
        """
        if v is None or (isinstance(v, str) and not v.strip()):
            return _PATH_DEFAULTS[vinfo.field_name]
        return v

    @field_validator("MODEL_DIR", "FRONTEND_DIST", "AP_LOCATIONS_FILE", mode="after")
    @classmethod
    def _absolutise(cls, v: Path) -> Path:
        """Relative paths in the environment are resolved against the repo root."""
        return v if v.is_absolute() else (REPO_ROOT / v)

    # -- derived helpers --------------------------------------------------
    @property
    def repo_root(self) -> Path:
        return REPO_ROOT

    @property
    def stage1_path(self) -> Path:
        return self.MODEL_DIR / self.STAGE1_MODEL

    @property
    def stage2_path(self) -> Path:
        return self.MODEL_DIR / self.STAGE2_MODEL

    @property
    def v2_model_path(self) -> Path:
        return self.MODEL_DIR / self.V2_MODEL

    @property
    def v2_meta_path(self) -> Path:
        return self.MODEL_DIR / self.V2_META

    @property
    def v2_gbdt_path(self) -> Path:
        return self.MODEL_DIR / self.V2_GBDT

    @property
    def rag_enabled(self) -> bool:
        return bool(self.OPENROUTER_API_KEY.strip())

    @property
    def saqr_model(self) -> str:
        """The model id the agent actually calls.

        ``SAQR_MODEL`` when set, otherwise ``GEN_MODEL`` -- so an ``.env`` that
        predates the agent needs no edit to run it.
        """
        return self.SAQR_MODEL.strip() or self.GEN_MODEL.strip()

    @property
    def saqr_enabled(self) -> bool:
        """The agent can serve requests: switched on *and* holding a key."""
        return bool(self.SAQR_ENABLED) and bool(self.OPENROUTER_API_KEY.strip())

    @property
    def sql_dialect(self) -> str:
        """``"sqlite"`` or ``"postgresql"``, derived from ``DATABASE_URL``."""
        return "sqlite" if self.DATABASE_URL.strip().lower().startswith("sqlite") else "postgresql"

    def safe_database_url(self) -> str:
        """``DATABASE_URL`` with any password replaced by ``***`` for logging."""
        return redact_url(self.DATABASE_URL)


def redact_url(url: str) -> str:
    """Strip credentials out of a SQLAlchemy URL so it is safe to log."""
    try:
        scheme, _, rest = url.partition("://")
        if not rest or "@" not in rest:
            return url
        userinfo, _, hostpart = rest.rpartition("@")
        user, sep, _pwd = userinfo.partition(":")
        userinfo = f"{user}:***" if sep else user
        return f"{scheme}://{userinfo}@{hostpart}"
    except Exception:  # pragma: no cover - defensive only
        return "<unparseable database url>"


settings = Settings()


# --------------------------------------------------------------------------- #
# Class names -> frontend keys                                                  #
# --------------------------------------------------------------------------- #
# Derived from ``feature_spec.ATTACK_CLASSES``, never re-listed.  Adding a class
# to the spec adds it here, to /attacks/analysis and to /reports/summary with no
# further edit; that is the point.
def front_key(class_name: str) -> str:
    """DB class name -> the lower-case key the frontend uses.

    ``"(Re)Assoc" -> "reassoc"``, ``"Evil_Twin" -> "evil_twin"``,
    ``"Kr00k" -> "kr00k"``.  Punctuation is dropped rather than escaped, so no
    class name can produce a key that needs URL- or JSON-quoting.
    """
    return re.sub(r"[^a-z0-9_]", "", class_name.lower())


#: DB label -> frontend key, for every attack class in the spec.
FRONT_TYPE_MAP: Dict[str, str] = {c: front_key(c) for c in ATTACK_CLASSES}

# Display order only.  The six v1 keys keep their historical positions because the
# frontend renders them in this order; anything the spec adds is appended.
_LEGACY_FRONT_ORDER: List[str] = ["deauth", "ssdp", "evil_twin", "reassoc", "rogueap", "krack"]
_derived = list(FRONT_TYPE_MAP.values())
FRONT_TYPES: List[str] = [k for k in _LEGACY_FRONT_ORDER if k in _derived] + [
    k for k in _derived if k not in _LEGACY_FRONT_ORDER
]
_missing_legacy = [k for k in _LEGACY_FRONT_ORDER if k not in _derived]
if _missing_legacy:  # pragma: no cover - only if a class is renamed upstream
    logger.error(
        "feature_spec no longer defines the frontend keys %s; /reports/summary will "
        "stop reporting them", _missing_legacy,
    )
del _derived, _missing_legacy


# --------------------------------------------------------------------------- #
# v2 artefact validation                                                        #
# --------------------------------------------------------------------------- #
# Lives here, not in the detector, so the web process can answer "which model is
# deployed?" on /health without importing scapy/lightgbm, and the detector can use
# the *same* check when it actually loads the graph.  A silent train/serve feature
# mismatch is precisely how v1 died: 16 of 29 features were permanently NULL in the
# field and nothing anywhere said so.
def v2_meta_problems(meta: Any) -> List[str]:
    """Every way ``meta`` disagrees with the running ``feature_spec``.

    An empty list means the artefact is safe to serve.  Returns *all* problems
    rather than the first, because a stale export usually has several and fixing
    them one round-trip at a time is miserable.
    """
    problems: List[str] = []
    if not isinstance(meta, dict):
        return [f"meta is {type(meta).__name__}, expected a JSON object"]

    got_spec = str(meta.get("spec_version"))
    if got_spec != SPEC_VERSION:
        problems.append(
            f"spec_version mismatch: artefact says {got_spec!r}, "
            f"backend.detector.feature_spec is {SPEC_VERSION!r}"
        )

    feats = meta.get("feature_order")
    if not isinstance(feats, list):
        problems.append("meta has no feature_order list")
    else:
        feats = [str(f) for f in feats]
        if len(feats) != len(FEATURE_ORDER):
            problems.append(
                f"feature count mismatch: artefact has {len(feats)}, "
                f"feature_spec has {len(FEATURE_ORDER)}"
            )
        missing = [f for f in FEATURE_ORDER if f not in feats]
        extra = [f for f in feats if f not in FEATURE_ORDER]
        if missing:
            problems.append(f"features the artefact is missing: {missing}")
        if extra:
            problems.append(f"features the artefact has but feature_spec does not: {extra}")
        if not missing and not extra and feats != FEATURE_ORDER:
            first = next(i for i, (a, b) in enumerate(zip(feats, FEATURE_ORDER)) if a != b)
            problems.append(
                f"feature ORDER differs at index {first}: artefact {feats[first]!r} "
                f"vs feature_spec {FEATURE_ORDER[first]!r} (same names, wrong order - "
                f"every column would be fed to the wrong channel)"
            )

    n_feat = meta.get("n_features")
    if n_feat is not None and int(n_feat) != len(FEATURE_ORDER):
        problems.append(
            f"n_features mismatch: artefact says {int(n_feat)}, "
            f"feature_spec has {len(FEATURE_ORDER)}"
        )

    classes = meta.get("classes")
    if not isinstance(classes, list):
        problems.append("meta has no classes list")
    elif [str(c) for c in classes] != CLASSES:
        problems.append(
            f"class mismatch: artefact {[str(c) for c in classes]} vs feature_spec {CLASSES}"
        )

    norm = meta.get("normalisation")
    if not isinstance(norm, dict):
        problems.append("meta has no normalisation block")
    else:
        for key in ("mean", "std"):
            vec = norm.get(key)
            if not isinstance(vec, list):
                problems.append(f"normalisation.{key} is missing")
            elif len(vec) != len(FEATURE_ORDER):
                problems.append(
                    f"normalisation.{key} has {len(vec)} entries, "
                    f"expected {len(FEATURE_ORDER)}"
                )

    try:
        if int(meta.get("window", 0)) < 1:
            problems.append(f"window must be >= 1, got {meta.get('window')!r}")
        if int(meta.get("context", -1)) < 0:
            problems.append(f"context must be >= 0, got {meta.get('context')!r}")
    except (TypeError, ValueError):
        problems.append(
            f"window/context are not integers: {meta.get('window')!r} / {meta.get('context')!r}"
        )

    return problems


def v2_status(model_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Filesystem-only view of the v2 artefact, for ``GET /health``.

    Advisory, not authoritative: the API process does not load the graph, so this
    reports what the files on disk *claim*.  The detector's startup log records
    what it actually loaded.
    """
    base = Path(model_dir) if model_dir is not None else settings.MODEL_DIR
    onnx_path = base / settings.V2_MODEL
    meta_path = base / settings.V2_META
    out: Dict[str, Any] = {
        "present": onnx_path.is_file() and meta_path.is_file(),
        "usable": False,
        "artefact_spec_version": None,
        "problems": [],
    }
    if not out["present"]:
        out["problems"] = [
            p for p, ok in ((str(onnx_path), onnx_path.is_file()),
                            (str(meta_path), meta_path.is_file())) if not ok
        ]
        out["problems"] = [f"missing: {p}" for p in out["problems"]]
        return out
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - health must never raise
        out["problems"] = [f"{meta_path} is not readable JSON: {exc}"]
        return out
    out["artefact_spec_version"] = (
        str(meta.get("spec_version")) if isinstance(meta, dict) else None
    )
    out["problems"] = v2_meta_problems(meta)
    out["usable"] = not out["problems"]
    return out


# --------------------------------------------------------------------------- #
# GBDT artefact validation                                                      #
# --------------------------------------------------------------------------- #
# A LightGBM text model states, in its own header, the columns it was fitted on
# and how many scores it emits per iteration.  Reading those two lines needs no
# lightgbm and no numpy, so the web process can answer "is the GBDT servable?"
# the same way it already answers it for the ONNX graph.
#
# Advisory, and deliberately structural rather than exact: the authoritative
# check is ``GBDTPipeline._validate_booster``, which compares the model's names
# against ``GBDT_FEATURE_NAMES`` element for element.  This one verifies the
# shape of the contract -- the 46 spec features first, in order, then a block of
# well-formed rolling-aggregate names, then the right number of classes -- which
# is everything that can be checked without owning the rollup spec.
_ROLLUP_NAME_RE = re.compile(r"^roll(\d+)\.(.+)\.(mean|std|rate)$")


def gbdt_model_problems(header: Dict[str, str]) -> List[str]:
    """Every way a parsed GBDT header disagrees with the running ``feature_spec``."""
    problems: List[str] = []

    names = header.get("feature_names", "").split()
    if not names:
        problems.append("model file has no feature_names line")
    else:
        head, tail = names[: len(FEATURE_ORDER)], names[len(FEATURE_ORDER):]
        if head != FEATURE_ORDER:
            missing = [f for f in FEATURE_ORDER if f not in names]
            if missing:
                problems.append(f"per-frame features the model is missing: {missing}")
            else:
                first = next(
                    (i for i, (a, b) in enumerate(zip(head, FEATURE_ORDER)) if a != b),
                    len(head),
                )
                problems.append(
                    f"the model's first {len(FEATURE_ORDER)} columns are not "
                    f"feature_spec.FEATURE_ORDER (differs at index {first})"
                )
        bad = [n for n in tail if not _ROLLUP_NAME_RE.match(n)]
        if bad:
            problems.append(f"columns that are neither spec features nor rolling aggregates: {bad}")
        if not tail:
            problems.append(
                "the model has no rolling-aggregate columns; the GBDT is trained on "
                "per-frame features PLUS causal rollups and cannot be served without them"
            )

    n_feat = header.get("max_feature_idx")
    if n_feat is not None and names:
        try:
            if int(n_feat) + 1 != len(names):
                problems.append(
                    f"max_feature_idx says {int(n_feat) + 1} columns, feature_names lists {len(names)}"
                )
        except ValueError:
            problems.append(f"max_feature_idx is not an integer: {n_feat!r}")

    n_class = header.get("num_class")
    if n_class is None:
        problems.append("model file has no num_class line")
    else:
        try:
            if int(n_class) != len(CLASSES):
                problems.append(
                    f"class mismatch: model emits {int(n_class)} classes, "
                    f"feature_spec has {len(CLASSES)}"
                )
        except ValueError:
            problems.append(f"num_class is not an integer: {n_class!r}")

    return problems


def _read_gbdt_header(path: Path, max_lines: int = 40) -> Dict[str, str]:
    """The ``key=value`` preamble of a LightGBM text model, up to the first tree."""
    out: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            line = line.rstrip("\n")
            if line.startswith("Tree=") or i >= max_lines:
                break
            key, sep, value = line.partition("=")
            if sep:
                out[key.strip()] = value
    return out


def gbdt_status(model_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Filesystem-only view of the GBDT artefact, for ``GET /health``.

    Advisory, like :func:`v2_status`: the API process does not load the booster,
    so this reports what the file on disk claims about itself.
    """
    base = Path(model_dir) if model_dir is not None else settings.MODEL_DIR
    gbdt_path = base / settings.V2_GBDT
    meta_path = base / settings.V2_META
    out: Dict[str, Any] = {"present": False, "usable": False, "problems": []}

    missing = [str(p) for p in (gbdt_path, meta_path) if not p.is_file()]
    if missing:
        out["problems"] = [f"missing: {p}" for p in missing]
        return out
    out["present"] = True

    # The GBDT shares the meta file -- and therefore the spec version, class list
    # and per-frame feature contract -- with the TCN.
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - health must never raise
        out["problems"] = [f"{meta_path} is not readable JSON: {exc}"]
        return out
    problems = v2_meta_problems(meta)

    try:
        problems += gbdt_model_problems(_read_gbdt_header(gbdt_path))
    except Exception as exc:  # noqa: BLE001 - health must never raise
        problems.append(f"{gbdt_path} is not readable: {exc}")

    out["problems"] = problems
    out["usable"] = not problems
    return out


def configure_logging() -> None:
    """Apply ``LOG_LEVEL`` to the root logger (idempotent)."""
    level = getattr(logging, str(settings.LOG_LEVEL).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logging.getLogger().setLevel(level)
