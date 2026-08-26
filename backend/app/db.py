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

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    future=True,
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
