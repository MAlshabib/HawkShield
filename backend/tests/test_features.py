"""Parity regression for ``backend.detector.features.packet_to_row``.

The original ``scapy_to_row()`` left 13 of the 29 numeric features permanently
``None`` and hardcoded ``wlan.fc.ds = 0``; those rows were then mean/median-imputed
on every live packet.  These tests pin the fix: the previously-null features must
now be populated on real frames, and fields the frame genuinely does not carry must
still be ``None``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.detector.features import (  # noqa: E402
    ENCAP_TYPE_RADIOTAP_80211,
    FEATURE_ORDER,
    ExtractState,
    freq_to_channel,
    packet_to_row,
)

SAMPLE = REPO_ROOT / "data" / "samples" / "deauth_raw_decrypted.pcapng"
N_PACKETS = 2000

#: the 13 numeric features the original extractor never filled, plus wlan.fc.ds
#: which it hardcoded to 0.  All of them are carried by (or derivable from) the
#: RadioTap + Dot11 headers of the sample captures.
PREVIOUSLY_NULL = [
    "frame.encap_type",
    "frame.time_delta",
    "frame.time_delta_displayed",
    "frame.time_relative",
    "radiotap.channel.freq",
    "radiotap.channel.flags.cck",
    "radiotap.channel.flags.ofdm",
    "radiotap.rxflags",
    "wlan.fc.frag",
    "wlan.fc.order",
    "wlan.seq",
    "wlan_radio.channel",
    "wlan_radio.duration",
    "wlan_radio.phy",
]

#: coverage floor asserted for every feature above, over frames that carry RadioTap.
COVERAGE_FLOOR_PCT = 90.0


@pytest.fixture(scope="module")
def rows():
    pytest.importorskip("scapy")
    if not SAMPLE.is_file():
        pytest.skip(f"sample capture missing: {SAMPLE}")
    from scapy.utils import PcapReader

    out = []
    state = ExtractState()
    with PcapReader(str(SAMPLE)) as rd:
        for pkt in rd:
            out.append(packet_to_row(pkt, "wlan1", state))
            if len(out) >= N_PACKETS:
                break
    assert out, "no packets read from the sample capture"
    return out


def test_row_has_exactly_the_31_model_features(rows):
    row, _ = rows[0]
    assert list(row.keys()) == FEATURE_ORDER
    assert len(FEATURE_ORDER) == 31


def test_previously_null_features_are_now_populated(rows):
    n = len(rows)
    for feat in PREVIOUSLY_NULL:
        filled = sum(1 for row, _ in rows if row[feat] is not None)
        pct = 100.0 * filled / n
        assert pct >= COVERAGE_FLOOR_PCT, (
            f"{feat} populated on only {pct:.1f}% of {n} frames "
            f"(floor {COVERAGE_FLOOR_PCT}%)"
        )


def test_every_numeric_feature_is_populated_on_this_capture(rows):
    """All 29 numeric columns are available from these captures - none may regress."""
    n = len(rows)
    for feat in FEATURE_ORDER[:29]:
        filled = sum(1 for row, _ in rows if row[feat] is not None)
        assert filled == n, f"{feat} null on {n - filled}/{n} frames"


def test_absent_fields_stay_null(rows):
    """The two cat_cols are not carried by a frame; they must remain None.

    ``TwoStagePipeline`` fills them with 0.0 when reindexing into the model space -
    inventing a value here would silently change what the model sees.
    """
    for row, _ in rows:
        assert row["wlan.country_info.fnm"] is None
        assert row["wlan.country_info.code"] is None


def test_encap_type_is_the_tshark_radiotap_constant(rows):
    for row, _ in rows:
        assert row["frame.encap_type"] == ENCAP_TYPE_RADIOTAP_80211 == 23


def test_time_features_are_monotonic_and_consistent(rows):
    """time_relative must be non-decreasing and time_delta must match its increments."""
    first_row, _ = rows[0]
    assert first_row["frame.time_delta"] == 0.0
    assert first_row["frame.time_relative"] == 0.0

    prev_rel = 0.0
    for row, _ in rows[1:]:
        rel = row["frame.time_relative"]
        delta = row["frame.time_delta"]
        assert rel is not None and delta is not None
        assert rel >= prev_rel - 1e-9
        assert delta == pytest.approx(rel - prev_rel, abs=1e-6)
        assert row["frame.time_delta_displayed"] == delta
        prev_rel = rel
    assert prev_rel > 0.0, "capture span collapsed to zero"


def test_ds_is_a_real_two_bit_value_not_a_hardcoded_zero(rows):
    """The original hardcoded wlan.fc.ds = 0; it must now be the real ToDS|FromDS<<1."""
    seen = {row["wlan.fc.ds"] for row, _ in rows}
    assert seen, "no ds values extracted"
    assert seen <= {0, 1, 2, 3}
    for row, _ in rows:
        # data frames in an infrastructure BSS are never DS=0
        if row["wlan.fc.type"] == 2:
            assert row["wlan.fc.ds"] in (1, 2, 3)


def test_flag_features_are_booleans(rows):
    for row, _ in rows:
        for feat in ("wlan.fc.frag", "wlan.fc.order", "wlan.fc.retry", "wlan.fc.pwrmgt",
                     "wlan.fc.moredata", "wlan.fc.protected",
                     "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm"):
            assert row[feat] in (0, 1), f"{feat}={row[feat]!r}"


def test_seq_drops_the_fragment_number(rows):
    """wlan.seq is the 12-bit sequence number: Dot11.SC >> 4."""
    from scapy.layers.dot11 import Dot11
    from scapy.utils import PcapReader

    state = ExtractState()
    with PcapReader(str(SAMPLE)) as rd:
        for i, pkt in enumerate(rd):
            row, _ = packet_to_row(pkt, "wlan1", state)
            d11 = pkt.getlayer(Dot11)
            if d11 is not None and getattr(d11, "SC", None) is not None:
                assert row["wlan.seq"] == float(int(d11.SC) >> 4)
                assert 0 <= row["wlan.seq"] <= 4095
            if i >= 200:
                break


def test_radio_summary_agrees_with_radiotap(rows):
    for row, _ in rows:
        assert row["wlan_radio.frequency"] == row["radiotap.channel.freq"]
        assert row["wlan_radio.data_rate"] == row["radiotap.datarate"]
        assert row["wlan_radio.channel"] == float(freq_to_channel(int(row["radiotap.channel.freq"])))
        # signal is the strongest chain, dbm_antsignal the sum over chains
        assert row["wlan_radio.signal_dbm"] >= row["radiotap.dbm_antsignal"]


def test_raw_min_shape(rows):
    _, raw = rows[0]
    assert set(raw) == {"iface", "sa", "da", "bssid", "len", "type", "subtype",
                        "rate", "sig", "ssid"}
    assert raw["iface"] == "wlan1"


def test_ssid_is_extracted_from_beacons(rows):
    ssids = {raw["ssid"] for row, raw in rows if row["wlan.fc.subtype"] == 8 and row["wlan.fc.type"] == 0}
    ssids.discard(None)
    assert ssids, "no SSID extracted from any beacon frame"


@pytest.mark.parametrize(
    "freq,channel",
    [(2412, 1), (2437, 6), (2472, 13), (2484, 14), (5180, 36), (5745, 149), (None, None), (1, None)],
)
def test_freq_to_channel(freq, channel):
    assert freq_to_channel(freq) == channel


def test_state_isolates_captures():
    state = ExtractState()
    assert state.observe(100.0) == (0.0, 0.0)
    assert state.observe(100.5) == (0.5, 0.5)
    state.reset()
    assert state.observe(500.0) == (0.0, 0.0)


def test_missing_layers_do_not_raise():
    """A non-802.11 packet must produce an all-null row rather than an exception."""
    from scapy.layers.inet import IP, UDP

    row, raw = packet_to_row(IP() / UDP(), "wlan0", ExtractState())
    assert row["frame.len"] is not None
    assert row["radiotap.channel.freq"] is None
    assert row["wlan.fc.type"] is None
    assert raw["sa"] is None
