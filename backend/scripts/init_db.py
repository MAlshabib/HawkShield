"""Create the HawkShield schema.  Idempotent - safe to re-run.

Usage (from the repo root):
    python -m backend.scripts.init_db
"""
from __future__ import annotations

import sys

from backend.app.config import configure_logging, settings
from backend.app.db import init_db


def main() -> int:
    configure_logging()
    target = settings.safe_database_url()
    print(f"HawkShield: ensuring schema on {target}")
    try:
        init_db()
    except Exception as exc:  # noqa: BLE001 - CLI reports the failure plainly
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    print("Done. Tables: packets, documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
