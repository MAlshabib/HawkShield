"""Tests for ``POST /admin/purge`` -- the operator "delete all detections" lever.

These prove the destructive endpoint is safe and honest:

* the sentinel is required -- an empty or wrong ``confirm`` deletes nothing (400);
* ``scope: "all"`` empties the table and reports what it removed and what remains;
* ``scope: "simulated"`` removes only ``raw.sim`` rows and leaves captured frames;
* ``ALLOW_PURGE=0`` makes the route 403 and deletes nothing;
* the response is exactly ``{deleted, remaining}``.

Everything runs against a temporary SQLite DB via a ``get_db`` dependency
override (the pattern from ``test_api.py`` / ``test_simulate.py``); no model
artefacts and no PostgreSQL are needed.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("OPENROUTER_API_KEY", "")

from backend.app.config import settings  # noqa: E402
from backend.app.db import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Packet  # noqa: E402


@pytest.fixture()
def engine(tmp_path: Path):
    eng = create_engine(
        f"sqlite:///{tmp_path / 'purge.db'}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def maker(engine):
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture()
def client(engine, maker) -> Iterator[TestClient]:
    def _override_get_db() -> Iterator[Session]:
        db = maker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _seed(maker, *, captured: int = 3, simulated: int = 2) -> None:
    """Insert a mix of captured (no sim flag) and simulated (raw.sim) rows."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    s = maker()
    try:
        for i in range(captured):
            s.add(
                Packet(
                    ts=now - timedelta(minutes=i),
                    iface="wlan1",
                    src_mac=f"AA:BB:CC:DD:EE:{i:02d}",
                    predicted_label="Deauth",
                    proba_attack=0.9,
                    raw={"iface": "wlan1"},  # a real frame: no sim key
                )
            )
        for i in range(simulated):
            s.add(
                Packet(
                    ts=now - timedelta(minutes=100 + i),
                    iface="sim0",
                    src_mac=f"11:22:33:44:55:{i:02d}",
                    predicted_label="Krack",
                    proba_attack=0.95,
                    raw={"iface": "sim0", "sim": True, "sim_batch": "abc"},
                )
            )
        s.commit()
    finally:
        s.close()


def _count(maker) -> int:
    s = maker()
    try:
        return int(s.query(func.count(Packet.id)).scalar() or 0)
    finally:
        s.close()


# ---------------------------------------------------------------------------
# the sentinel guard
# ---------------------------------------------------------------------------
def test_missing_sentinel_deletes_nothing(client, maker) -> None:
    _seed(maker)
    before = _count(maker)
    r = client.post("/admin/purge", json={})
    assert r.status_code == 400, r.text
    assert _count(maker) == before  # nothing removed


def test_wrong_sentinel_deletes_nothing(client, maker) -> None:
    _seed(maker)
    before = _count(maker)
    r = client.post("/admin/purge", json={"confirm": "delete"})  # wrong case
    assert r.status_code == 400
    assert _count(maker) == before


# ---------------------------------------------------------------------------
# the happy paths
# ---------------------------------------------------------------------------
def test_scope_all_empties_the_table(client, maker) -> None:
    _seed(maker, captured=3, simulated=2)
    r = client.post("/admin/purge", json={"confirm": "DELETE"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"deleted": 5, "remaining": 0}
    assert _count(maker) == 0


def test_scope_all_is_the_default(client, maker) -> None:
    _seed(maker, captured=2, simulated=1)
    r = client.post("/admin/purge", json={"confirm": "DELETE"})
    assert r.status_code == 200
    assert r.json()["remaining"] == 0


def test_scope_simulated_leaves_captured_rows(client, maker) -> None:
    _seed(maker, captured=3, simulated=2)
    r = client.post("/admin/purge", json={"confirm": "DELETE", "scope": "simulated"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"deleted": 2, "remaining": 3}
    assert _count(maker) == 3

    # The survivors are exactly the captured frames (no sim flag).
    s = maker()
    try:
        raws = [row.raw for row in s.query(Packet).all()]
    finally:
        s.close()
    assert all(not (isinstance(raw, dict) and raw.get("sim")) for raw in raws)


def test_response_shape_is_deleted_and_remaining(client, maker) -> None:
    _seed(maker, captured=1, simulated=1)
    body = client.post("/admin/purge", json={"confirm": "DELETE"}).json()
    assert set(body.keys()) == {"deleted", "remaining"}
    assert all(isinstance(v, int) for v in body.values())


def test_purge_on_empty_table_is_a_clean_zero(client, maker) -> None:
    r = client.post("/admin/purge", json={"confirm": "DELETE"})
    assert r.status_code == 200
    assert r.json() == {"deleted": 0, "remaining": 0}


# ---------------------------------------------------------------------------
# the kill switch
# ---------------------------------------------------------------------------
def test_disabled_purge_is_403_and_deletes_nothing(client, maker, monkeypatch) -> None:
    _seed(maker)
    before = _count(maker)
    monkeypatch.setattr(settings, "ALLOW_PURGE", False)
    r = client.post("/admin/purge", json={"confirm": "DELETE"})
    assert r.status_code == 403
    assert _count(maker) == before
