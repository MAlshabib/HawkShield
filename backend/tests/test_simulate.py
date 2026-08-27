"""Tests for ``POST /simulate``.

These are the tests that prove the feature is honest, not just wired:

* every simulated row is tagged ``raw.sim = true`` and shares one ``sim_batch``;
* the per-class summary counts match what actually landed in the DB;
* for the classes the model handles cleanly, the *persisted label is the
  requested class* -- i.e. the corpus + real pipeline produce believable data,
  which is the whole point of the endpoint;
* the ``count`` cap, the ``ALLOW_SIMULATION`` gate and the no-model 503 all hold.

Everything runs against a temporary SQLite DB via a ``get_db`` dependency
override (the pattern from ``test_api.py``), and against the real model artefacts
on disk -- so the classification is the genuine article, not a stub.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, List

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("OPENROUTER_API_KEY", "")

from backend.app.config import settings  # noqa: E402
from backend.app.db import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.routers import simulate as sim_router  # noqa: E402

# A model must be present for /simulate to do anything real; skip the whole module
# cleanly on a checkout without the artefacts rather than reporting red.
_MODELS_PRESENT = (
    settings.v2_gbdt_path.is_file()
    or settings.v2_model_path.is_file()
    or (settings.stage1_path.is_file() and settings.stage2_path.is_file())
)
pytestmark = pytest.mark.skipif(
    not _MODELS_PRESENT, reason="no model artefacts on disk; /simulate would 503"
)


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    db_path: Path = tmp_path_factory.mktemp("hawksim") / "sim.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def maker(engine):
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="module")
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


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """Each test starts with a clean rate-limit window."""
    sim_router._CALLS.clear()
    yield
    sim_router._CALLS.clear()


def _all_rows(maker) -> List[dict]:
    s = maker()
    try:
        rows = s.execute(text("SELECT * FROM packets ORDER BY id")).mappings().all()
        return [dict(r) for r in rows]
    finally:
        s.close()


def _sim_rows(maker) -> List[dict]:
    import json

    out = []
    for r in _all_rows(maker):
        raw = r.get("raw")
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, dict) and raw.get("sim"):
            r["_raw"] = raw
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# the happy path: real detections, correctly tagged, summary matches the DB
# ---------------------------------------------------------------------------
def test_simulate_persists_clean_classes_with_correct_labels(client, maker) -> None:
    before = len(_all_rows(maker))
    r = client.post("/simulate", json={"attacks": ["deauth", "krack"], "count": 5})
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["classes"] == ["Deauth", "Krack"]
    assert body["count_per_class"] == 5
    assert set(body["per_class"]) == {"Deauth", "Krack"}

    # The clean classes persist as themselves: this is the corpus+pipeline proof.
    for cls in ("Deauth", "Krack"):
        res = body["per_class"][cls]
        assert res["persisted"] == 5
        assert res["top_label"] == cls, f"{cls} should self-classify, got {res['top_label']}"

    # Summary total matches rows actually written to the DB.
    new_rows = len(_all_rows(maker)) - before
    assert new_rows == body["total_persisted"] == 10

    # Every new row is tagged, and the persisted label matches the request.
    sims = _sim_rows(maker)
    assert len(sims) == 10
    batch = body["sim_batch"]
    assert all(r["_raw"]["sim"] is True for r in sims)
    assert all(r["_raw"]["sim_batch"] == batch for r in sims)
    labels = sorted(r["predicted_label"] for r in sims)
    assert labels == ["Deauth"] * 5 + ["Krack"] * 5


def test_each_run_uses_a_fresh_batch_id(client) -> None:
    b1 = client.post("/simulate", json={"attacks": ["deauth"], "count": 2}).json()["sim_batch"]
    b2 = client.post("/simulate", json={"attacks": ["deauth"], "count": 2}).json()["sim_batch"]
    assert b1 != b2


def test_all_expands_to_every_corpus_class(client) -> None:
    r = client.post("/simulate", json={"attacks": "all", "count": 1})
    assert r.status_code == 200
    from backend.app.config import ATTACK_CLASSES

    assert set(r.json()["per_class"]) == set(ATTACK_CLASSES)


# ---------------------------------------------------------------------------
# caps and gates
# ---------------------------------------------------------------------------
def test_count_is_capped_at_sim_max_count(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "SIM_MAX_COUNT", 3)
    r = client.post("/simulate", json={"attacks": ["krack"], "count": 10_000})
    assert r.status_code == 200
    body = r.json()
    assert body["count_per_class"] == 3
    assert body["per_class"]["Krack"]["persisted"] == 3


def test_unknown_attack_is_400(client) -> None:
    r = client.post("/simulate", json={"attacks": ["not_a_class"], "count": 1})
    assert r.status_code == 400


def test_disabled_simulation_is_403(client, monkeypatch) -> None:
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", False)
    r = client.post("/simulate", json={"attacks": ["deauth"], "count": 1})
    assert r.status_code == 403


def test_no_model_is_503(client, monkeypatch) -> None:
    def _boom() -> None:
        raise FileNotFoundError("no model could be loaded")

    monkeypatch.setattr(sim_router, "_get_pipeline", _boom)
    r = client.post("/simulate", json={"attacks": ["deauth"], "count": 1})
    assert r.status_code == 503


def test_missing_corpus_is_503(client, monkeypatch) -> None:
    from backend.detector import attack_sim

    def _missing(path=None, use_cache=True):
        raise attack_sim.CorpusUnavailable("simulation corpus not found")

    monkeypatch.setattr(sim_router, "load_sim_corpus", _missing, raising=False)
    # patch the symbol the router imports lazily
    monkeypatch.setattr(attack_sim, "load_sim_corpus", _missing)
    r = client.post("/simulate", json={"attacks": ["deauth"], "count": 1})
    assert r.status_code == 503


def test_rate_limit_returns_429(client, monkeypatch) -> None:
    monkeypatch.setattr(sim_router, "_RATE_MAX", 2)
    sim_router._CALLS.clear()
    codes = [
        client.post("/simulate", json={"attacks": ["deauth"], "count": 1}).status_code
        for _ in range(3)
    ]
    assert codes[-1] == 429
