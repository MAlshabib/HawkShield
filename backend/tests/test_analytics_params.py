"""Range, limit and timezone parameters on the analytics endpoints.

Same shape as ``test_api.py``: a temporary SQLite database behind a ``get_db``
override, no PostgreSQL and no network.

The governing rule for every test here is that the parameters are **additive**.
The shipped ``frontend/out`` bundle calls all of these endpoints with no query
string at all, so "omitted" has to keep meaning exactly what it meant before:
all time, UTC, and the same rows.  The one deliberate exception is
``/top-offenders``, which is now bounded by default -- pinned explicitly below
so the change cannot happen twice by accident.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, List
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.config import ATTACK_CLASSES  # noqa: E402
from backend.app.db import Base, get_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Packet  # noqa: E402

DAY_ORDER_SUN_FIRST = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
RIYADH = ZoneInfo("Asia/Riyadh")  # UTC+3, no DST -- the deployment's zone

#: A moment chosen so that +03:00 pushes it into the next hour *and* the next
#: day: 22:30 UTC is 01:30 the following morning in Riyadh.  Bucketing that in
#: the wrong zone is visibly, not subtly, wrong.
CROSSOVER_UTC = datetime(2026, 8, 24, 22, 30, tzinfo=timezone.utc)


def _naive_utc(when: datetime) -> datetime:
    """Timestamps are stored naive UTC; match that shape."""
    return when.astimezone(timezone.utc).replace(tzinfo=None)


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory):
    db_path: Path = tmp_path_factory.mktemp("analytics") / "params.db"
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
def seeded(engine) -> None:
    """Rows inside and outside a one-day window, across MACs and channels."""
    maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    now = datetime.now(timezone.utc)
    rows: List[Packet] = []

    # 6 recent rows (last 6 hours): 3 MACs x 2, channels 2437/5180.
    for i in range(6):
        rows.append(
            Packet(
                ts=_naive_utc(now - timedelta(hours=i)),
                iface="wlan1",
                src_mac=f"AA:BB:CC:00:00:{i % 3:02d}",
                bssid="AA:AA:AA:AA:AA:01",
                channel_freq=2437 if i % 2 else 5180,
                proba_attack=0.9,
                predicted_label=("Deauth", "Kr00k", "Disas")[i % 3],
                raw={"iface": "wlan1"},
            )
        )
    # 4 old rows (10 days back) on a MAC and channel seen nowhere else, so an
    # all-time query and a windowed one are trivially distinguishable.
    for i in range(4):
        rows.append(
            Packet(
                ts=_naive_utc(now - timedelta(days=10, hours=i)),
                iface="wlan0",
                src_mac="AA:BB:CC:FF:FF:FF",
                bssid="AA:AA:AA:AA:AA:02",
                channel_freq=2412,
                proba_attack=0.8,
                predicted_label="RogueAP",
                raw={"iface": "wlan0"},
            )
        )
    # One row at the timezone crossover, for the tz tests.
    rows.append(
        Packet(
            ts=_naive_utc(CROSSOVER_UTC),
            iface="wlan1",
            src_mac="AA:BB:CC:DD:EE:FF",
            bssid="AA:AA:AA:AA:AA:03",
            channel_freq=2437,
            proba_attack=0.99,
            predicted_label="Evil_Twin",
            raw={"iface": "wlan1"},
        )
    )

    session = maker()
    try:
        session.add_all(rows)
        session.commit()
    finally:
        session.close()


@pytest.fixture()
def client(engine, seeded) -> Iterator[TestClient]:
    def override_get_db() -> Iterator[Session]:
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        session: Session = maker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.pop(get_db, None)


# --------------------------------------------------------------------------- #
# /top-offenders                                                               #
# --------------------------------------------------------------------------- #
def test_top_offenders_without_params_is_still_all_time(client):
    body = client.get("/top-offenders").json()
    macs = {row["wlan_sa"] for row in body}
    assert "AA:BB:CC:FF:FF:FF" in macs, "the 10-day-old MAC must still appear by default"
    assert all(set(row) == {"wlan_sa", "count"} for row in body), "key set is frozen"


def test_top_offenders_days_window_excludes_older_rows(client):
    body = client.get("/top-offenders?days=1").json()
    macs = {row["wlan_sa"] for row in body}
    assert "AA:BB:CC:FF:FF:FF" not in macs
    assert macs == {"AA:BB:CC:00:00:00", "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"}


def test_top_offenders_is_bounded_by_default(client):
    """The one intentional default change: previously every distinct MAC."""
    body = client.get("/top-offenders").json()
    assert len(body) <= 50


def test_top_offenders_limit_is_a_prefix_of_the_unlimited_result(client):
    """Ordering is unchanged, so no caller loses a row it used to display."""
    everything = client.get("/top-offenders?limit=500").json()
    limited = client.get("/top-offenders?limit=2").json()
    assert len(limited) == 2
    assert limited == everything[:2]


def test_top_offenders_is_ordered_by_count_descending(client):
    counts = [row["count"] for row in client.get("/top-offenders").json()]
    assert counts == sorted(counts, reverse=True)


@pytest.mark.parametrize("query", ["limit=0", "limit=501", "days=0", "days=4000"])
def test_top_offenders_rejects_out_of_range_parameters(client, query):
    assert client.get(f"/top-offenders?{query}").status_code == 422


def test_top_offenders_never_returns_a_null_mac(client):
    assert all(row["wlan_sa"] for row in client.get("/top-offenders").json())


# --------------------------------------------------------------------------- #
# /channel-usage                                                               #
# --------------------------------------------------------------------------- #
def test_channel_usage_without_params_is_still_all_time(client):
    body = client.get("/channel-usage").json()
    freqs = {row["channel_freq"] for row in body}
    assert 2412 in freqs, "the 10-day-old channel must still appear by default"
    assert all(set(row) == {"channel_freq", "count"} for row in body)


def test_channel_usage_days_window_excludes_older_rows(client):
    body = client.get("/channel-usage?days=1").json()
    assert 2412 not in {row["channel_freq"] for row in body}


def test_channel_usage_counts_match_the_window(client):
    windowed = sum(row["count"] for row in client.get("/channel-usage?days=1").json())
    all_time = sum(row["count"] for row in client.get("/channel-usage").json())
    assert 0 < windowed < all_time


def test_channel_usage_is_never_truncated(client):
    """Unlike /top-offenders this endpoint returns every channel, by design.

    That is why it carries no ORDER BY tiebreaker: tie order cannot change
    *which* rows a caller receives, so leaving the ordering exactly as it was
    keeps the no-parameter response byte-identical for the shipped bundle.
    """
    body = client.get("/channel-usage").json()
    assert {row["channel_freq"] for row in body} == {2437, 5180, 2412}


@pytest.mark.parametrize("query", ["days=0", "days=4000"])
def test_channel_usage_rejects_out_of_range_days(client, query):
    assert client.get(f"/channel-usage?{query}").status_code == 422


# --------------------------------------------------------------------------- #
# /heatmap-attack                                                              #
# --------------------------------------------------------------------------- #
def test_heatmap_without_params_is_unchanged(client):
    body = client.get("/heatmap-attack").json()
    assert [entry["day"] for entry in body] == DAY_ORDER_SUN_FIRST
    for entry in body:
        assert [h["hour"] for h in entry["hours"]] == list(range(24))


def test_heatmap_default_matches_an_explicit_utc_request(client):
    """The default must be byte-identical to tz=UTC, or it is not a safe default."""
    assert client.get("/heatmap-attack").json() == client.get("/heatmap-attack?tz=UTC").json()


def _cell(body, day: str, hour: int) -> int:
    entry = next(e for e in body if e["day"] == day)
    return entry["hours"][hour]["intensity"]


def test_heatmap_buckets_on_the_requested_wall_clock(client):
    """22:30 UTC is 01:30 next-day in Riyadh: a different hour AND a different day.

    This is the defect the parameter exists to close -- the grid used to sit
    three hours off the timestamps rendered beside it.
    """
    utc_dt = CROSSOVER_UTC
    riyadh_dt = CROSSOVER_UTC.astimezone(RIYADH)
    utc_day = DAY_ORDER_SUN_FIRST[(utc_dt.weekday() + 1) % 7]
    riyadh_day = DAY_ORDER_SUN_FIRST[(riyadh_dt.weekday() + 1) % 7]
    assert (utc_day, utc_dt.hour) != (riyadh_day, riyadh_dt.hour), "bad fixture"

    utc_body = client.get("/heatmap-attack?tz=UTC").json()
    riyadh_body = client.get("/heatmap-attack?tz=Asia/Riyadh").json()

    assert _cell(utc_body, utc_day, utc_dt.hour) >= 1
    assert _cell(riyadh_body, riyadh_day, riyadh_dt.hour) >= 1


def test_heatmap_total_is_unchanged_by_the_timezone(client):
    """A zone moves counts between cells; it must never create or lose one."""
    def total(body) -> int:
        return sum(h["intensity"] for entry in body for h in entry["hours"])

    assert total(client.get("/heatmap-attack?tz=UTC").json()) == total(
        client.get("/heatmap-attack?tz=Asia/Riyadh").json()
    )


def test_heatmap_days_window_reduces_the_total(client):
    def total(body) -> int:
        return sum(h["intensity"] for entry in body for h in entry["hours"])

    assert total(client.get("/heatmap-attack?days=1").json()) < total(
        client.get("/heatmap-attack").json()
    )


def test_heatmap_rejects_an_unknown_timezone(client):
    """400, not a silent fall back to UTC -- that would restore the original bug."""
    response = client.get("/heatmap-attack?tz=Mars/Olympus")
    assert response.status_code == 400
    assert "Mars/Olympus" in response.json()["detail"]


@pytest.mark.parametrize("tz", ["", "Not/AZone", "GMT+3", "../../etc/passwd"])
def test_heatmap_rejects_malformed_timezones(client, tz):
    assert client.get("/heatmap-attack", params={"tz": tz}).status_code == 400


# --------------------------------------------------------------------------- #
# /attacks/series                                                              #
# --------------------------------------------------------------------------- #
def test_series_defaults(client):
    body = client.get("/attacks/series").json()
    assert body["bucket"] == "hour"
    assert body["tz"] == "UTC"
    assert body["days"] == 7
    assert body["label"] is None
    assert len(body["points"]) == 7 * 24


def test_series_buckets_are_zero_filled_and_ordered(client):
    """A quiet hour must be a zero, not a gap -- a chart with holes lies."""
    points = client.get("/attacks/series?days=1").json()["points"]
    assert len(points) == 24
    assert any(p["count"] == 0 for p in points), "the fixture should have quiet hours"
    stamps = [p["t"] for p in points]
    assert stamps == sorted(stamps), "points must be chronological"
    assert len(set(stamps)) == len(stamps), "no duplicate buckets"


def test_series_day_bucket_returns_one_point_per_day(client):
    body = client.get("/attacks/series?days=5&bucket=day").json()
    assert body["bucket"] == "day"
    assert len(body["points"]) == 5


def test_series_total_matches_the_sum_of_its_points(client):
    body = client.get("/attacks/series?days=2").json()
    assert body["total"] == sum(p["count"] for p in body["points"])


def test_series_counts_only_the_window(client):
    """The 10-day-old rows are outside a 2-day window and must not appear."""
    recent = client.get("/attacks/series?days=2&bucket=day").json()
    wide = client.get("/attacks/series?days=30&bucket=day").json()
    assert wide["total"] > recent["total"]


def test_series_label_filter(client):
    everything = client.get("/attacks/series?days=2").json()
    deauth = client.get("/attacks/series?days=2&label=Deauth").json()
    assert deauth["label"] == "Deauth"
    assert 0 < deauth["total"] < everything["total"]
    assert len(deauth["points"]) == len(everything["points"])


@pytest.mark.parametrize("label", ATTACK_CLASSES)
def test_series_accepts_every_class_in_the_spec(client, label):
    """Iterates the spec rather than a hand-written list, like the rest of the repo."""
    response = client.get("/attacks/series", params={"days": 1, "label": label})
    assert response.status_code == 200
    assert response.json()["label"] == label


def test_series_rejects_an_unknown_label(client):
    response = client.get("/attacks/series?label=Nonsense")
    assert response.status_code == 400
    assert "Nonsense" in response.json()["detail"]


def test_series_rejects_a_window_too_long_for_its_bucket(client):
    """An explicit 400 beats silently clamping to 31 and letting the caller wonder."""
    response = client.get("/attacks/series?days=90&bucket=hour")
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "31" in detail and "day" in detail


def test_series_allows_a_long_window_with_day_buckets(client):
    body = client.get("/attacks/series?days=90&bucket=day").json()
    assert len(body["points"]) == 90


@pytest.mark.parametrize("query", ["bucket=week", "days=0", "days=4000"])
def test_series_rejects_bad_parameters(client, query):
    assert client.get(f"/attacks/series?{query}").status_code == 422


def test_series_aligns_buckets_to_the_requested_zone(client):
    """Riyadh day boundaries are 21:00 UTC, so the bucket stamps must carry +03:00."""
    body = client.get("/attacks/series?days=3&bucket=day&tz=Asia/Riyadh").json()
    assert body["tz"] == "Asia/Riyadh"
    for point in body["points"]:
        assert point["t"].endswith("+03:00")
        assert point["t"][11:19] == "00:00:00", "day buckets start at local midnight"


def test_series_hour_stamps_are_parseable_and_one_hour_apart(client):
    points = client.get("/attacks/series?days=1&tz=Asia/Riyadh").json()["points"]
    stamps = [datetime.fromisoformat(p["t"]) for p in points]
    assert all(
        (b - a) == timedelta(hours=1) for a, b in zip(stamps, stamps[1:])
    ), "hour buckets must be exactly one hour apart"


def test_series_rejects_an_unknown_timezone(client):
    assert client.get("/attacks/series?tz=Mars/Olympus").status_code == 400


def test_series_start_and_end_bracket_the_points(client):
    body = client.get("/attacks/series?days=2").json()
    assert body["start"] == body["points"][0]["t"]
    assert body["end"] == body["points"][-1]["t"]


# --------------------------------------------------------------------------- #
# /health capture block                                                        #
# --------------------------------------------------------------------------- #
def test_health_reports_the_configured_capture_interface(client):
    from backend.app.config import settings

    capture = client.get("/health").json()["capture"]
    assert capture["iface"] == settings.CAPTURE_IFACE
    assert capture["channel"] == settings.CAPTURE_CHANNEL
    assert capture["source"] in ("config", "config+sysfs")


def test_health_capture_has_every_documented_field(client):
    capture = client.get("/health").json()["capture"]
    assert set(capture) == {
        "iface", "channel", "target_ssid", "present", "monitor_mode",
        "link_type", "operstate", "observed_iface", "observed_channel_freq",
        "source",
    }


def test_health_reports_what_the_sensor_is_actually_delivering(client):
    """The value the dashboard currently infers from the newest packet itself."""
    capture = client.get("/health").json()["capture"]
    assert capture["observed_iface"] in ("wlan1", "wlan0")
    assert isinstance(capture["observed_channel_freq"], int)


def test_health_capture_never_guesses_an_unknowable_field(client):
    """Off Linux there is no sysfs, so the measured fields must be null, not false.

    ``monitor_mode: false`` would read as "the radio is in managed mode", which
    is a claim this process cannot make.
    """
    from backend.app.config import capture_status

    status = capture_status()
    if status["source"] == "config":
        assert status["monitor_mode"] is None
        assert status["link_type"] is None
        assert status["present"] is None


def test_health_still_carries_every_pre_existing_field(client):
    """The capture block is additive; nothing may have been displaced."""
    body = client.get("/health").json()
    for key in (
        "status", "database", "packets", "latest_packet_ts", "models",
        "model_version", "spec_version", "artefact_spec_version",
        "model_problems", "version",
    ):
        assert key in body, f"/health lost {key!r}"


def test_capture_status_reads_a_monitor_interface(monkeypatch, tmp_path):
    """The sysfs path, exercised against a fake /sys tree.

    803 is ARPHRD_IEEE80211_RADIOTAP -- the interface is in monitor mode and
    delivering radiotap headers, which is what the detector needs.
    """
    from backend.app import config as config_module

    fake_net = tmp_path / "sys" / "class" / "net" / "wlan1"
    fake_net.mkdir(parents=True)
    (fake_net / "type").write_text("803\n", encoding="utf-8")
    (fake_net / "operstate").write_text("up\n", encoding="utf-8")

    def fake_read(iface: str, attribute: str):
        path = tmp_path / "sys" / "class" / "net" / iface / attribute
        try:
            return path.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    monkeypatch.setattr(config_module, "_read_sysfs", fake_read)
    status = config_module.capture_status("wlan1")
    assert status["present"] is True
    assert status["monitor_mode"] is True
    assert status["link_type"] == "monitor-radiotap"
    assert status["operstate"] == "up"
    assert status["source"] == "config+sysfs"


def test_capture_status_reports_a_managed_interface_as_not_monitoring(monkeypatch, tmp_path):
    from backend.app import config as config_module

    def fake_read(iface: str, attribute: str):
        return {"type": "1", "operstate": "up"}.get(attribute)

    monkeypatch.setattr(config_module, "_read_sysfs", fake_read)
    status = config_module.capture_status("wlan0")
    assert status["monitor_mode"] is False
    assert status["link_type"] == "ethernet"


def test_capture_status_survives_a_missing_interface(monkeypatch):
    from backend.app import config as config_module

    monkeypatch.setattr(config_module, "_read_sysfs", lambda iface, attribute: None)
    status = config_module.capture_status("nope0")
    assert status["present"] is None
    assert status["monitor_mode"] is None
    assert status["source"] == "config"
