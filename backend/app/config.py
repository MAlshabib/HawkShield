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

from pydantic import field_validator
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
    "configure_logging",
    "front_key",
    "redact_url",
    "settings",
    "v2_meta_problems",
    "v2_status",
]


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

    # ---- v2 model (single causal TCN, ONNX) ------------------------------
    #: ``auto`` -> v2 when the ONNX artefact is present and validates, else v1.
    MODEL_VERSION: str = "auto"
    V2_MODEL: str = "hawkshield_v2.onnx"
    V2_META: str = "hawkshield_v2_meta.json"
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

    # ---- web ------------------------------------------------------------
    CORS_ORIGINS: Annotated[List[str], NoDecode] = ["http://localhost:3000"]
    FRONTEND_DIST: Path = REPO_ROOT / "frontend" / "out"
    AP_LOCATIONS_FILE: Path = REPO_ROOT / "backend" / "config" / "ap_locations.json"

    # ---- misc -----------------------------------------------------------
    LOG_LEVEL: str = "INFO"

    # -- validators -------------------------------------------------------
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
    def rag_enabled(self) -> bool:
        return bool(self.OPENROUTER_API_KEY.strip())

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


def configure_logging() -> None:
    """Apply ``LOG_LEVEL`` to the root logger (idempotent)."""
    level = getattr(logging, str(settings.LOG_LEVEL).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logging.getLogger().setLevel(level)
