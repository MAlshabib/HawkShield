"""
Regression tests for the dual-target runtime (laptop + Raspberry Pi).

Two bugs are pinned here, both found by running the launcher end to end:

1. A blank value in .env (``MODEL_DIR=`` with nothing after it, which is exactly
   what .env.example ships) used to become ``Path("")`` and resolve to the repo
   root. For FRONTEND_DIST that meant FastAPI served the entire checkout --
   including .env -- as static files.

2. The /ask SQL executor spoke psycopg only, so it broke on the SQLite database
   the laptop mode falls back to.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest


# --------------------------------------------------------------------------- #
# 1. blank env values must fall back to the packaged defaults                   #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "field, tail",
    [
        ("MODEL_DIR", ("models",)),
        ("FRONTEND_DIST", ("frontend", "out")),
        ("AP_LOCATIONS_FILE", ("backend", "config", "ap_locations.json")),
    ],
)
def test_blank_path_env_falls_back_to_default(monkeypatch, field, tail):
    monkeypatch.setenv(field, "")
    from backend.app import config as config_module

    importlib.reload(config_module)
    value = Path(getattr(config_module.Settings(), field))

    assert value.parts[-len(tail):] == tail
    assert value != config_module.REPO_ROOT, (
        f"{field}='' resolved to the repo root; FRONTEND_DIST would expose the whole checkout"
    )


def test_whitespace_only_path_env_also_falls_back(monkeypatch):
    monkeypatch.setenv("FRONTEND_DIST", "   ")
    from backend.app import config as config_module

    importlib.reload(config_module)
    assert config_module.Settings().FRONTEND_DIST.parts[-2:] == ("frontend", "out")


def test_explicit_path_env_is_still_honoured(monkeypatch, tmp_path):
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    from backend.app import config as config_module

    importlib.reload(config_module)
    assert config_module.Settings().MODEL_DIR == tmp_path


def test_relative_path_env_resolves_against_repo_root(monkeypatch):
    monkeypatch.setenv("MODEL_DIR", "custom_models")
    from backend.app import config as config_module

    importlib.reload(config_module)
    settings = config_module.Settings()
    assert settings.MODEL_DIR.is_absolute()
    assert settings.MODEL_DIR == config_module.REPO_ROOT / "custom_models"


# --------------------------------------------------------------------------- #
# 2. the assistant must target whichever SQL dialect is configured              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url, expected",
    [
        ("sqlite:///./hawkshield.db", "sqlite"),
        ("sqlite:////absolute/path.db", "sqlite"),
        ("postgresql+psycopg2://u:p@localhost:5432/db", "postgresql"),
        ("postgresql://u:p@localhost:5432/db", "postgresql"),
        ("", "postgresql"),
    ],
)
def test_sql_dialect_detection(monkeypatch, url, expected):
    """``DATABASE_URL`` selects the dialect the assistant is told it is talking to.

    Lives in ``agent/sqlguard`` now; it was ``packet_qa._sql_dialect`` until the
    RAG module was deleted. The behaviour, and the reason it matters, are
    unchanged: the same repository runs on PostgreSQL on the Pi and SQLite on a
    laptop demo, and SQL written for the wrong one simply fails.
    """
    from backend.app.agent.sqlguard import sql_dialect

    monkeypatch.setenv("DATABASE_URL", url)
    assert sql_dialect() == expected


def test_dialect_notes_match_the_database(monkeypatch):
    from backend.app.agent.sqlguard import dialect_notes, sql_dialect

    monkeypatch.setenv("DATABASE_URL", "sqlite:///./x.db")
    sqlite_notes = dialect_notes(sql_dialect())
    assert "SQLite" in sqlite_notes
    assert "datetime('now'" in sqlite_notes
    assert "json_extract" in sqlite_notes

    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost/db")
    pg_notes = dialect_notes(sql_dialect())
    assert "PostgreSQL" in pg_notes
    assert "date_trunc" in pg_notes
    assert "NOW()" in pg_notes


def test_sqlite_select_executes_without_psycopg(monkeypatch, tmp_path):
    """A SELECT must run on SQLite: psycopg cannot parse a sqlite:// URL at all.

    The engine is swapped explicitly rather than by reloading modules, so this
    test does not depend on which other test touched the shared engine first.
    """
    from sqlalchemy import create_engine

    from backend.app import db as db_module
    from backend.app.agent.sqlguard import run_select, sql_dialect
    from backend.app.models import Base

    db_file = tmp_path / "guard.db"
    engine = create_engine(f"sqlite:///{db_file.as_posix()}", future=True)
    Base.metadata.create_all(engine)

    monkeypatch.setattr(db_module, "engine", engine)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file.as_posix()}")

    assert sql_dialect() == "sqlite"

    # No session passed, so this takes the module-engine path -- the one that
    # exists precisely because psycopg cannot handle a sqlite:// URL.
    cols, rows = run_select("SELECT COUNT(*) AS count FROM packets", dialect="sqlite")
    assert cols == ["count"]
    assert rows[0][0] == 0

    engine.dispose()
