"""API tests.

They run entirely against a temporary SQLite database via a ``get_db``
dependency override, so no PostgreSQL instance is needed.  The ``raw`` JSON
column works on SQLite because SQLAlchemy's generic ``JSON`` type serialises to
TEXT there.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# The app must never require a real API key or a real Postgres to import.
os.environ.setdefault("OPENROUTER_API_KEY", "")

from backend.app.db import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Packet  # noqa: E402

DAY_ORDER_SUN_FIRST = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
KNOWN_LABELS = ["Deauth", "SSDP", "Evil_Twin", "(Re)Assoc", "RogueAP", "Krack"]


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    db_path: Path = tmp_path_factory.mktemp("hawkshield") / "test.db"
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
def seeded(engine) -> List[Packet]:
    """Insert a handful of synthetic attack packets."""
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = [
        Packet(
            ts=now - timedelta(hours=1),
            iface="wlan1",
            src_mac="AA:BB:CC:DD:EE:01",
            dst_mac="FF:FF:FF:FF:FF:FF",
            bssid="AA:AA:AA:AA:AA:01",
            frame_len=128,
            channel_freq=2437,
            datarate=1.0,
            signal_dbm=-42.0,
            wlan_ds=0,
            wlan_retry=0,
            wlan_type=0,
            wlan_subtype=12,
            wlan_duration=0,
            proba_anomaly=0.95,
            proba_attack=0.91,
            predicted_label="Deauth",
            raw={"iface": "wlan1", "sa": "AA:BB:CC:DD:EE:01", "len": 128},
        ),
        Packet(
            ts=now - timedelta(hours=2),
            iface="wlan1",
            src_mac="AA:BB:CC:DD:EE:01",
            bssid="AA:AA:AA:AA:AA:01",
            frame_len=140,
            channel_freq=2437,
            signal_dbm=-50.0,
            proba_anomaly=0.90,
            proba_attack=0.88,
            predicted_label="Deauth",
            raw={"iface": "wlan1"},
        ),
        Packet(
            ts=now - timedelta(hours=3),
            iface="wlan1",
            src_mac="AA:BB:CC:DD:EE:02",
            bssid="AA:AA:AA:AA:AA:02",
            frame_len=200,
            channel_freq=2412,
            signal_dbm=-70.0,
            proba_anomaly=0.85,
            proba_attack=0.84,
            predicted_label="Evil_Twin",
            raw=None,
        ),
        Packet(
            ts=now - timedelta(hours=4),
            iface="wlan1",
            src_mac="AA:BB:CC:DD:EE:03",
            bssid="AA:AA:AA:AA:AA:03",
            frame_len=90,
            channel_freq=5180,
            signal_dbm=-61.0,
            proba_anomaly=0.99,
            proba_attack=0.97,
            predicted_label="Krack",
            raw=None,
        ),
        Packet(
            ts=now - timedelta(hours=5),
            iface="wlan1",
            src_mac="AA:BB:CC:DD:EE:03",
            bssid="AA:AA:AA:AA:AA:03",
            frame_len=95,
            channel_freq=5180,
            signal_dbm=-65.0,
            proba_anomaly=0.80,
            proba_attack=0.83,
            predicted_label="Weird_Label",
            raw=None,
        ),
    ]
    with maker() as db:
        db.add_all(rows)
        db.commit()
    return rows


@pytest.fixture(scope="module")
def client(engine, seeded) -> Iterator[TestClient]:
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)

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


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------
def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {
        "status",
        "database",
        "packets",
        "latest_packet_ts",
        "models",
        "version",
    }
    assert body["status"] in ("ok", "degraded")
    assert body["database"] is True
    assert body["packets"] == 5
    assert body["latest_packet_ts"] is not None
    assert set(body["models"]) == {"stage1", "stage2"}
    assert isinstance(body["version"], str) and body["version"]


# ---------------------------------------------------------------------------
# attacks
# ---------------------------------------------------------------------------
def test_packets_count(client: TestClient) -> None:
    r = client.get("/packets/count")
    assert r.status_code == 200
    assert r.json() == {"count": 5}


def test_attacks_listing_newest_first(client: TestClient) -> None:
    r = client.get("/attacks", params={"limit": 10, "offset": 0})
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 5
    ids = [row["id"] for row in rows]
    assert ids == sorted(ids, reverse=True)
    assert "predicted_label" in rows[0]
    # the JSON `raw` column comes back as an object, not a string
    assert rows[-1]["raw"] == {"iface": "wlan1", "sa": "AA:BB:CC:DD:EE:01", "len": 128}


def test_attacks_analysis_all_six_keys(client: TestClient) -> None:
    r = client.get("/attacks/analysis")
    assert r.status_code == 200
    body = r.json()
    assert list(body) == KNOWN_LABELS
    assert body["Deauth"] == 2
    assert body["Evil_Twin"] == 1
    assert body["Krack"] == 1
    # Unknown labels are excluded, and every known key is present zero-filled.
    assert body["SSDP"] == 0
    assert body["(Re)Assoc"] == 0
    assert body["RogueAP"] == 0


def test_top_offenders(client: TestClient) -> None:
    r = client.get("/top-offenders")
    assert r.status_code == 200
    body = r.json()
    assert body, "expected at least one offender"
    assert set(body[0]) == {"wlan_sa", "count"}  # legacy key name kept
    counts = [row["count"] for row in body]
    assert counts == sorted(counts, reverse=True)
    assert body[0]["count"] == 2


def test_channel_usage(client: TestClient) -> None:
    r = client.get("/channel-usage")
    assert r.status_code == 200
    body = r.json()
    assert set(body[0]) == {"channel_freq", "count"}
    counts = [row["count"] for row in body]
    assert counts == sorted(counts, reverse=True)
    assert {row["channel_freq"] for row in body} == {2437, 2412, 5180}


def test_heatmap_shape_sun_first(client: TestClient) -> None:
    r = client.get("/heatmap-attack")
    assert r.status_code == 200
    body = r.json()
    assert [d["day"] for d in body] == DAY_ORDER_SUN_FIRST
    assert len(body) == 7
    for day in body:
        assert len(day["hours"]) == 24
        assert [h["hour"] for h in day["hours"]] == list(range(24))
        assert all(isinstance(h["intensity"], int) for h in day["hours"])
    total = sum(h["intensity"] for d in body for h in d["hours"])
    assert total == 5


# ---------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------
def test_reports_summary(client: TestClient) -> None:
    r = client.get("/reports/summary", params={"days": 30})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"period", "totals", "summary"}
    assert body["period"] == "Last 30 day(s)"
    assert set(body["totals"]) == {
        "deauth",
        "ssdp",
        "evil_twin",
        "reassoc",
        "rogueap",
        "krack",
        "other",
    }
    assert body["totals"]["deauth"] == 2
    assert body["totals"]["evil_twin"] == 1
    assert body["totals"]["krack"] == 1
    assert body["totals"]["other"] == 1  # the unmapped "Weird_Label" row
    assert set(body["summary"]) == {
        "totalAttacks",
        "mostFrequentType",
        "peakHour",
        "uniqueSources",
    }
    assert body["summary"]["totalAttacks"] == 5
    assert body["summary"]["mostFrequentType"] == "deauth"
    assert body["summary"]["uniqueSources"] == 3


def test_reports_export_pdf(client: TestClient) -> None:
    r = client.post("/reports/export", json={"days": 7})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")
    expected = 'attachment; filename="hawkshield_report_7d.pdf"'
    assert r.headers["content-disposition"] == expected
    assert r.content.startswith(b"%PDF-")


# ---------------------------------------------------------------------------
# map
# ---------------------------------------------------------------------------
def test_ap_locations_from_file(client: TestClient) -> None:
    r = client.get("/map/ap-locations")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    for ap in body:
        assert set(ap) == {"bssid", "name", "lat", "lng"}


def test_source_rssi(client: TestClient) -> None:
    r = client.get("/map/source-rssi", params={"sa": "AA:BB:CC:DD:EE:01", "minutes": 10000})
    assert r.status_code == 200
    body = r.json()
    assert body["sa"] == "AA:BB:CC:DD:EE:01"
    assert len(body["points"]) == 1
    pt = body["points"][0]
    assert pt["bssid"] == "AA:AA:AA:AA:AA:01"
    assert pt["n"] == 2
    assert pt["avg_rssi"] == pytest.approx(-46.0)


def test_estimate_origin(client: TestClient) -> None:
    r = client.post(
        "/map/estimate-origin",
        json={
            "sa": "AA:BB:CC:DD:EE:01",
            "minutes": 10000,
            "ap_locations": [
                {"bssid": "AA:AA:AA:AA:AA:01", "lat": 24.7136, "lng": 46.6753},
            ],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["sa"] == "AA:BB:CC:DD:EE:01"
    assert body["method"] == "weighted-centroid"
    assert body["used"] == 1
    assert body["center"]["lat"] == pytest.approx(24.7136)
    assert body["center"]["lng"] == pytest.approx(46.6753)


def test_estimate_origin_no_match(client: TestClient) -> None:
    r = client.post(
        "/map/estimate-origin",
        json={
            "sa": "AA:BB:CC:DD:EE:01",
            "minutes": 10000,
            "ap_locations": [{"bssid": "ZZ", "lat": 1, "lng": 2}],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["used"] == 0
    assert body["center"] is None


# ---------------------------------------------------------------------------
# ask
# ---------------------------------------------------------------------------
def test_ask_returns_503_without_api_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from backend.app.config import settings
    from backend.app.routers import ask as ask_router

    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "", raising=False)
    ask_router.cache.store.clear()

    r = client.post("/ask", json={"question": "how many deauth attacks?", "session_id": "t1"})
    assert r.status_code == 503, r.text
    assert "detail" in r.json()


# ---------------------------------------------------------------------------
# removed endpoints must stay removed
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/detector/start", "/reports/email"])
def test_removed_endpoints_are_gone(path: str) -> None:
    # Checked against the route table rather than an HTTP status, because a
    # built frontend mounted at "/" turns an unknown POST into 405, not 404.
    registered = {getattr(r, "path", None) for r in app.routes}
    assert path not in registered
