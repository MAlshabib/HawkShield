"""Settings accessor for ``backend.detector``.

Prefers the project-wide ``backend.app.config.settings``.  If that module is not
importable (e.g. pydantic-settings absent on a bare box), falls back to a tiny shim
exposing the *same* attribute names, read from the *same* environment variables
documented in ``docs/CONTRACT.md`` section 3.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]


class _FallbackSettings:
    """Env-backed stand-in with the documented Settings field names."""

    def __init__(self) -> None:
        self.DATABASE_URL = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://hawkshield:CHANGE_ME@localhost:5432/hawkshield",
        )
        self.MODEL_DIR = Path(os.getenv("MODEL_DIR", str(_REPO_ROOT / "models")))
        self.STAGE1_MODEL = os.getenv("STAGE1_MODEL", "stage1_binary_bundle.joblib")
        self.STAGE2_MODEL = os.getenv("STAGE2_MODEL", "stage2_multiclass_bundle.joblib")
        self.STAGE1_THRESHOLD = float(os.getenv("STAGE1_THRESHOLD", "0.40"))
        self.STAGE2_THRESHOLD = float(os.getenv("STAGE2_THRESHOLD", "0.80"))
        self.CAPTURE_IFACE = os.getenv("CAPTURE_IFACE", "wlan1")
        self.CAPTURE_CHANNEL = int(os.getenv("CAPTURE_CHANNEL", "6"))
        self.TARGET_SSID = os.getenv("TARGET_SSID", "")
        self.BATCH_SIZE = int(os.getenv("BATCH_SIZE", "20"))
        self.BATCH_FLUSH_SECONDS = float(os.getenv("BATCH_FLUSH_SECONDS", "2.0"))
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @property
    def stage1_path(self) -> Path:
        return self.MODEL_DIR / self.STAGE1_MODEL

    @property
    def stage2_path(self) -> Path:
        return self.MODEL_DIR / self.STAGE2_MODEL


def get_settings() -> Any:
    """Return the shared Settings object, or the env-backed fallback."""
    try:
        from backend.app.config import settings  # type: ignore
    except Exception as exc:  # pragma: no cover - only on a partial install
        logger.warning("backend.app.config unavailable (%s); using env fallback", exc)
        return _FallbackSettings()
    return settings
