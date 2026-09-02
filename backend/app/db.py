"""SQLAlchemy engine / session wiring.

This is the *only* place an engine, a ``sessionmaker`` or a ``declarative_base``
is created in HawkShield.  Both ``backend.app`` and ``backend.detector`` import
from here.
"""
from __future__ import annotations

import logging
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from backend.app.config import settings

logger = logging.getLogger(__name__)

Base = declarative_base()

# Pin every PostgreSQL connection's session time zone to UTC. ``ts`` is a
# ``timestamp without time zone`` written from tz-aware ``datetime.now(utc)``:
# Postgres converts an aware value into the *session* time zone before dropping
# the tzinfo, so a non-UTC server default (e.g. Asia/Riyadh) would silently
# store local wall-clock time. The frontend reads the naive value back as UTC,
# which then double-shifts. Forcing the session to UTC keeps storage and
# interpretation aligned regardless of the host's configured zone. (No-op for
# SQLite, used in tests.)
_connect_args: dict = {}
if settings.DATABASE_URL.startswith("postgresql"):
    _connect_args["options"] = "-c timezone=utc"

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    future=True,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create every table declared on ``Base``.  Idempotent."""
    # Import for the side effect of registering the ORM classes on ``Base``.
    from backend.app import models  # noqa: F401  pylint: disable=unused-import

    Base.metadata.create_all(bind=engine)
    logger.info("Schema ensured on %s", settings.safe_database_url())
