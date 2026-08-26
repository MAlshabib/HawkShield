"""Central application configuration.

Every HawkShield component (app, detector, RAG) imports the single ``settings``
object defined here.  All values are environment-driven; nothing is hardcoded to
a developer machine.  The ``.env`` file is read from the repository root.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, List

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

logger = logging.getLogger(__name__)

# backend/app/config.py -> backend/app -> backend -> <repo root>
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

#: Reported by GET /health.
APP_VERSION: str = "1.0.0"


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

    # ---- capture --------------------------------------------------------
    CAPTURE_IFACE: str = "wlan1"
    CAPTURE_CHANNEL: int = 6
    TARGET_SSID: str = ""
    BATCH_SIZE: int = 20
    BATCH_FLUSH_SECONDS: float = 2.0

    # ---- RAG ------------------------------------------------------------
    OPENAI_API_KEY: str = ""
    GEN_MODEL: str = "gpt-4o"
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
    def rag_enabled(self) -> bool:
        return bool(self.OPENAI_API_KEY.strip())

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


def configure_logging() -> None:
    """Apply ``LOG_LEVEL`` to the root logger (idempotent)."""
    level = getattr(logging, str(settings.LOG_LEVEL).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logging.getLogger().setLevel(level)
