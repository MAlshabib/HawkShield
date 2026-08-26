"""Parity tests for the v2 live extractor.

v1 died of a structural problem: training read tshark columns, inference built a
different dict in different code, and 16 of 29 features were permanently NULL on
the Pi. v2 makes that impossible by construction --
``features.scapy_to_raw()`` emits the *tshark-named* dict and
``feature_spec.derive_frame_features()`` (the same function
``ml/prepare_awid3.py`` calls) turns it into the vector.

So these tests are not "does the extractor run". They pin the things that would
let the two paths drift apart again:

* every feature in ``FEATURE_ORDER_V2`` is present on every frame, no silent gaps;
* the fields only v2 can see (reason code, EAPOL msgnr, RSN, capabilities) are
  read correctly off crafted frames whose ground truth we chose;
* a field the frame does not carry stays NaN and is never invented as 0;
* the real captures are run end to end and their per-feature coverage is
  printed, so the number is measured rather than assumed.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
)
from scapy.layers.eap import EAPOL, EAPOL_KEY  # noqa: E402
from scapy.layers.l2 import LLC, SNAP  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from backend.detector.feature_spec import _f as spec_float  # noqa: E402
from backend.detector.features import (  # noqa: E402
    FEATURE_ORDER,
    FEATURE_ORDER_V2,
    ExtractState,
    FrameState,
    all_dbm_antsignal,
    packet_to_features_v2,
    packet_to_row,
    scapy_to_raw,
)

SAMPLES = REPO_ROOT / "data" / "samples"
IFACE = "wlan0mon"


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def roundtrip(pkt: Any) -> Any:
    """Serialise and re-dissect, so we test the *parsing* path the Pi will run.

    A freshly-constructed scapy packet still has its Python-level field values;
    a frame off the air has only bytes. Everything here is round-tripped so a
    field that only works pre-serialisation cannot pass.
    """
    return RadioTap(bytes(pkt)) if pkt.haslayer(RadioTap) else Dot11(bytes(pkt))


def features(pkt: Any, state: FrameState | None = None) -> Dict[str, float]:
    feats, _raw_min = packet_to_features_v2(roundtrip(pkt), IFACE, state or FrameState())
    return feats


def is_nan(v: float) -> bool:
    return isinstance(v, float) and math.isnan(v)


def mgmt(subtype: int, **kw: Any) -> Dot11:
    kw.setdefault("addr1", "ff:ff:ff:ff:ff:ff")
    kw.setdefault("addr2", "02:11:22:33:44:55")
    kw.setdefault("addr3", "02:11:22:33:44:55")
    return Dot11(type=0, subtype=subtype, **kw)


def rsn_ie(mfpc: bool = True, pmkid: bytes | None = None) -> bytes:
    """A minimal but structurally real RSN information element body."""
    body = (
        b"\x01\x00"                       # version
        + b"\x00\x0f\xac\x04"             # group cipher: CCMP
        + b"\x01\x00" + b"\x00\x0f\xac\x04"   # 1 pairwise: CCMP
        + b"\x01\x00" + b"\x00\x0f\xac\x02"   # 1 AKM: PSK
        + (b"\x80\x00" if mfpc else b"\x00\x00")   # capabilities, bit 7 = MFPC
    )
    if pmkid is not None:
        body += b"\x01\x00" + pmkid
    return body


def eapol_key(**bits: Any) -> Any:
    """One EAPOL-Key frame in a from-DS data frame, as it appears on the air."""
    return (
        RadioTap()
        / Dot11(type=2, subtype=0, FCfield="from-DS",
                addr1="02:aa:bb:cc:dd:01", addr2="02:11:22:33:44:55",
                addr3="02:11:22:33:44:55")
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(code=0x888E)
        / EAPOL(version=2, type=3)
        / EAPOL_KEY(key_descriptor_type=2, key_length=16, **bits)
    )


# --------------------------------------------------------------------------- #
# The key test: the contract itself                                            #
# --------------------------------------------------------------------------- #
def test_feature_keys_exactly_match_the_spec() -> None:
    """No feature may be silently missing, extra, or renamed."""
    pkt = RadioTap() / mgmt(12) / Dot11Deauth(reason=7)
    feats, raw_min = packet_to_features_v2(roundtrip(pkt), IFACE, FrameState())

    assert sorted(feats.keys()) == sorted(FEATURE_ORDER_V2)
    assert len(feats) == len(FEATURE_ORDER_V2)
    assert set(raw_min) == {
        "iface", "sa", "da", "bssid", "len", "type", "subtype", "rate", "sig", "ssid"
    }


@pytest.mark.parametrize(
    "pkt",
    [
        RadioTap() / mgmt(8) / Dot11Beacon() / Dot11Elt(ID=0, info=b"x"),
        RadioTap() / mgmt(12) / Dot11Deauth(reason=7),
        RadioTap() / Dot11(type=1, subtype=11, addr1="02:00:00:00:00:01"),   # RTS
        RadioTap() / Dot11(type=2, subtype=4, FCfield="to-DS",               # null data
                           addr1="02:11:22:33:44:55", addr2="02:00:00:00:00:01",
                           addr3="02:11:22:33:44:55"),
        eapol_key(has_key_mic=1, key_ack=1, install=1, secure=1, key_data_length=0),
    ],
    ids=["beacon", "deauth", "rts", "null-data", "eapol"],
)
def test_every_frame_type_yields_the_full_vector(pkt: Any) -> None:
    feats = features(pkt)
    assert sorted(feats) == sorted(FEATURE_ORDER_V2)
    assert all(isinstance(v, float) for v in feats.values())


def test_v1_api_still_works() -> None:
    """The live detector runs v1 until the v2 model ships; do not break it."""
    pkt = roundtrip(RadioTap() / mgmt(8) / Dot11Beacon() / Dot11Elt(ID=0, info=b"net"))
    row, raw_min = packet_to_row(pkt, IFACE, ExtractState())
    assert set(row) == set(FEATURE_ORDER)
    assert raw_min["ssid"] == "net"


# --------------------------------------------------------------------------- #
# wlan.fixed.reason_code - the single most valuable v2 feature                 #
# --------------------------------------------------------------------------- #
def test_deauth_reason_code() -> None:
    feats = features(RadioTap() / mgmt(12) / Dot11Deauth(reason=7))
    assert feats["fc.type"] == 0
    assert feats["fc.subtype"] == 12
    assert feats["mgmt.has_reason"] == 1
    assert feats["mgmt.reason_code"] == 7


def test_disas_reason_code() -> None:
    feats = features(RadioTap() / mgmt(10) / Dot11Disas(reason=1))
    assert feats["fc.type"] == 0
    assert feats["fc.subtype"] == 10
    assert feats["mgmt.has_reason"] == 1
    assert feats["mgmt.reason_code"] == 1


@pytest.mark.parametrize("reason", [1, 2, 3, 4, 6, 7, 8, 15])
def test_reason_code_is_not_clipped_or_bucketed(reason: int) -> None:
    feats = features(RadioTap() / mgmt(12) / Dot11Deauth(reason=reason))
    assert feats["mgmt.reason_code"] == reason


def test_frames_without_a_reason_field_have_none() -> None:
    """has_reason must be 0 and reason_code NaN - not a fabricated 0."""
    feats = features(RadioTap() / mgmt(8) / Dot11Beacon() / Dot11Elt(ID=0, info=b"n"))
    assert feats["mgmt.has_reason"] == 0
    assert is_nan(feats["mgmt.reason_code"])


def test_reason_code_zero_is_a_value_not_an_absence() -> None:
    feats = features(RadioTap() / mgmt(12) / Dot11Deauth(reason=0))
    assert feats["mgmt.has_reason"] == 1
    assert feats["mgmt.reason_code"] == 0


# --------------------------------------------------------------------------- #
# management body: SSID, country, capabilities, RSN                            #
# --------------------------------------------------------------------------- #
def beacon_pkt(ssid: bytes = b"HawkShieldNet", country: bool = True,
               rsn: bytes | None = None, cap: str = "ESS+privacy") -> Any:
    pkt = RadioTap() / mgmt(8) / Dot11Beacon(cap=cap, beacon_interval=100)
    pkt /= Dot11Elt(ID=0, info=ssid)
    pkt /= Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")          # supported rates
    if country:
        pkt /= Dot11Elt(ID=7, info=b"SA \x01\x0d\x14")
    if rsn is not None:
        pkt /= Dot11Elt(ID=48, info=rsn)
    return pkt


def test_beacon_ssid_country_and_capabilities() -> None:
    feats = features(beacon_pkt())
    assert feats["mgmt.ssid_len"] == len("HawkShieldNet")
    assert feats["rsn.country_present"] == 1
    assert feats["mgmt.cap_ess"] == 1
    assert feats["mgmt.cap_ibss"] == 0
    assert feats["mgmt.beacon_interval"] == 100


def test_country_code_read_from_the_right_element() -> None:
    raw = scapy_to_raw(roundtrip(beacon_pkt()), IFACE, FrameState())
    assert raw["wlan.country_info.code"] == "SA"
    assert raw["wlan.ssid"] == "HawkShieldNet"


def test_no_country_ie_means_absent_not_zero() -> None:
    feats = features(beacon_pkt(country=False))
    assert feats["rsn.country_present"] == 0


def test_ibss_capability() -> None:
    feats = features(beacon_pkt(cap="IBSS"))
    assert feats["mgmt.cap_ibss"] == 1
    assert feats["mgmt.cap_ess"] == 0


def test_hidden_ssid_is_absent_not_length_zero() -> None:
    """A wildcard SSID is an empty tshark field, so the spec makes it NaN."""
    feats = features(beacon_pkt(ssid=b""))
    assert is_nan(feats["mgmt.ssid_len"])


def test_rsn_mfpc_and_pmkid() -> None:
    pmkid = bytes(range(16))
    feats = features(beacon_pkt(rsn=rsn_ie(mfpc=True, pmkid=pmkid)))
    assert feats["rsn.mfpc"] == 1
    assert feats["rsn.has_pmkid"] == 1

    feats = features(beacon_pkt(rsn=rsn_ie(mfpc=False)))
    assert feats["rsn.mfpc"] == 0
    assert feats["rsn.has_pmkid"] == 0


def test_truncated_rsn_ie_does_not_raise_or_invent() -> None:
    """The RSN IE is variable-length; a short one must yield nothing, not a guess."""
    feats = features(beacon_pkt(rsn=b"\x01\x00\x00\x0f\xac"))
    assert feats["rsn.mfpc"] == 0
    assert feats["rsn.has_pmkid"] == 0


def test_data_frames_carry_no_management_body() -> None:
    pkt = RadioTap() / Dot11(type=2, subtype=0, FCfield="to-DS",
                             addr1="02:11:22:33:44:55", addr2="02:00:00:00:00:09",
                             addr3="02:aa:bb:cc:dd:ee") / (b"\x00" * 32)
    feats = features(pkt)
    assert is_nan(feats["mgmt.beacon_interval"])
    assert is_nan(feats["mgmt.ssid_len"])
    assert feats["mgmt.cap_ess"] == 0
    assert feats["mgmt.has_reason"] == 0


# --------------------------------------------------------------------------- #
# address semantics                                                            #
# --------------------------------------------------------------------------- #
def test_broadcast_destination() -> None:
    feats = features(RadioTap() / mgmt(12, addr1="ff:ff:ff:ff:ff:ff")
                     / Dot11Deauth(reason=7))
    assert feats["addr.da_broadcast"] == 1
    assert feats["addr.da_multicast"] == 1        # broadcast is also group-addressed


def test_multicast_destination() -> None:
    feats = features(RadioTap() / mgmt(12, addr1="01:00:5e:00:00:fb")
                     / Dot11Deauth(reason=7))
    assert feats["addr.da_multicast"] == 1
    assert feats["addr.da_broadcast"] == 0


def test_unicast_destination() -> None:
    feats = features(RadioTap() / mgmt(12, addr1="00:c0:ca:a8:26:3e")
                     / Dot11Deauth(reason=7))
    assert feats["addr.da_multicast"] == 0
    assert feats["addr.da_broadcast"] == 0


def test_locally_administered_source() -> None:
    """The bit almost every injection/spoofing tool leaves set."""
    feats = features(RadioTap() / mgmt(12, addr2="02:11:22:33:44:55")
                     / Dot11Deauth(reason=7))
    assert feats["addr.sa_local_admin"] == 1

    feats = features(RadioTap() / mgmt(12, addr2="8c:e5:ef:a1:c3:a4")
                     / Dot11Deauth(reason=7))
    assert feats["addr.sa_local_admin"] == 0


def test_sa_is_bssid_and_ta_eq_sa() -> None:
    ap = "8c:e5:ef:a1:c3:a4"
    feats = features(RadioTap() / mgmt(8, addr2=ap, addr3=ap)
                     / Dot11Beacon() / Dot11Elt(ID=0, info=b"n"))
    assert feats["addr.sa_is_bssid"] == 1
    assert feats["addr.ta_eq_sa"] == 1


def test_ds_bits_decide_which_address_is_which() -> None:
    """from-DS puts the BSSID in addr2 and the SA in addr3; getting this wrong
    silently corrupts three of the six address features."""
    ap, sta, host = "8c:e5:ef:a1:c3:a4", "00:c0:ca:a8:26:3e", "00:0c:29:cf:08:aa"
    raw = scapy_to_raw(
        roundtrip(RadioTap() / Dot11(type=2, subtype=0, FCfield="from-DS",
                                     addr1=sta, addr2=ap, addr3=host)),
        IFACE, FrameState())
    assert (raw["wlan.da"], raw["wlan.bssid"], raw["wlan.sa"]) == (sta, ap, host)

    raw = scapy_to_raw(
        roundtrip(RadioTap() / Dot11(type=2, subtype=0, FCfield="to-DS",
                                     addr1=ap, addr2=sta, addr3=host)),
        IFACE, FrameState())
    assert (raw["wlan.bssid"], raw["wlan.sa"], raw["wlan.da"]) == (ap, sta, host)


def test_control_frames_have_no_sa_da_bssid() -> None:
    """tshark leaves those columns empty for control frames; so must we."""
    raw = scapy_to_raw(
        roundtrip(RadioTap() / Dot11(type=1, subtype=11, addr1="02:00:00:00:00:01",
                                     addr2="02:00:00:00:00:02")),
        IFACE, FrameState())
    assert "wlan.sa" not in raw and "wlan.da" not in raw and "wlan.bssid" not in raw
    assert raw["wlan.ta"] == "02:00:00:00:00:02"


def test_same_bssid_as_prev_tracks_state() -> None:
    state = FrameState()
    a = RadioTap() / mgmt(8, addr3="8c:e5:ef:a1:c3:a4") / Dot11Beacon() / Dot11Elt(ID=0, info=b"n")
    b = RadioTap() / mgmt(8, addr3="02:de:ad:be:ef:00") / Dot11Beacon() / Dot11Elt(ID=0, info=b"n")
    assert features(a, state)["addr.same_bssid_as_prev"] == 0     # nothing seen yet
    assert features(a, state)["addr.same_bssid_as_prev"] == 1
    assert features(b, state)["addr.same_bssid_as_prev"] == 0


# --------------------------------------------------------------------------- #
# sequence numbers: a 12-bit counter, so deltas must wrap                      #
# --------------------------------------------------------------------------- #
def seq_frame(seq: int) -> Any:
    return RadioTap() / mgmt(8, SC=seq << 4) / Dot11Beacon() / Dot11Elt(ID=0, info=b"n")


def test_seq_delta_consecutive() -> None:
    state = FrameState()
    assert is_nan(features(seq_frame(100), state)["wlan.seq_delta"])   # no predecessor
    assert features(seq_frame(101), state)["wlan.seq_delta"] == 1


def test_seq_delta_wraps_at_4096() -> None:
    state = FrameState()
    features(seq_frame(4095), state)
    assert features(seq_frame(0), state)["wlan.seq_delta"] == 1


def test_seq_delta_gap_and_retransmit() -> None:
    state = FrameState()
    features(seq_frame(100), state)
    assert features(seq_frame(140), state)["wlan.seq_delta"] == 40
    assert features(seq_frame(140), state)["wlan.seq_delta"] == 0
    assert features(seq_frame(139), state)["wlan.seq_delta"] == -1


# --------------------------------------------------------------------------- #
# EAPOL - the Krack signal                                                      #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bits,expected",
    [
        # every Key Information bit is stated explicitly: scapy defaults
        # has_key_mic to 1, so an omitted bit is not the bit being clear.
        (dict(key_ack=1, has_key_mic=0, secure=0, install=0, key_data_length=0), 1),
        (dict(key_ack=0, has_key_mic=1, secure=0, install=0, key_data_length=22), 2),
        (dict(key_ack=1, has_key_mic=1, secure=1, install=1, key_data_length=56), 3),
        (dict(key_ack=0, has_key_mic=1, secure=1, install=0, key_data_length=0), 4),
    ],
    ids=["msg1", "msg2", "msg3", "msg4"],
)
def test_eapol_handshake_message_numbers(bits: Dict[str, int], expected: int) -> None:
    feats = features(eapol_key(key_replay_counter=3, **bits))
    assert feats["eapol.present"] == 1
    assert feats["eapol.type"] == 3
    assert feats["eapol.msgnr"] == expected
    assert feats["eapol.key_len"] == 16
    assert feats["eapol.replay_counter"] == 3
    assert feats["eapol.len"] > 0


def test_non_eapol_frame_has_no_eapol_features() -> None:
    feats = features(RadioTap() / mgmt(8) / Dot11Beacon() / Dot11Elt(ID=0, info=b"n"))
    assert feats["eapol.present"] == 0
    for key in ("eapol.type", "eapol.len", "eapol.msgnr",
                "eapol.key_len", "eapol.replay_counter"):
        assert is_nan(feats[key]), key


def test_krack_replayed_msg3_keeps_its_replay_counter() -> None:
    """Krack is msg 3 sent again; the pair (msgnr, replay_counter) is the evidence."""
    state = FrameState()
    msg3 = dict(key_ack=1, has_key_mic=1, secure=1, install=1, key_data_length=56)
    first = features(eapol_key(key_replay_counter=4, **msg3), state)
    again = features(eapol_key(key_replay_counter=4, **msg3), state)
    assert first["eapol.msgnr"] == again["eapol.msgnr"] == 3
    assert first["eapol.replay_counter"] == again["eapol.replay_counter"] == 4


# --------------------------------------------------------------------------- #
# radio: absence must stay absent                                              #
# --------------------------------------------------------------------------- #
def test_missing_rate_is_nan_not_zero() -> None:
    """The v1 failure in miniature: an absent field imputed to 0 is a lie the
    model will happily learn."""
    pkt = RadioTap() / mgmt(4) / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"")
    feats = features(pkt)
    assert feats["radio.has_rate"] == 0
    assert is_nan(feats["radio.datarate"])


def test_no_radiotap_at_all() -> None:
    feats = features(mgmt(12) / Dot11Deauth(reason=7))
    assert feats["radio.has_rate"] == 0
    assert feats["radio.has_signal"] == 0
    for key in ("radio.datarate", "radio.signal_dbm", "radio.freq_mhz", "radio.rt_len"):
        assert is_nan(feats[key]), key
    assert feats["mgmt.reason_code"] == 7        # the MAC layer still parses


def test_radiotap_channel_and_signal_are_read() -> None:
    pkt = (RadioTap(present="Rate+Channel+dBm_AntSignal", Rate=6.0,
                    ChannelFrequency=5180, ChannelFlags="OFDM+5GHz",
                    dBm_AntSignal=-42)
           / mgmt(12) / Dot11Deauth(reason=7))
    feats = features(pkt)
    assert feats["radio.freq_mhz"] == 5180
    assert feats["radio.is_5ghz"] == 1
    assert feats["radio.ofdm"] == 1
    assert feats["radio.cck"] == 0
    assert feats["radio.has_rate"] == 1
    assert feats["radio.datarate"] == 6.0
    assert feats["radio.has_signal"] == 1
    assert feats["radio.signal_dbm"] == -42


def test_duration_is_little_endian_like_tshark() -> None:
    """Scapy decodes Duration/ID as a big-endian ShortField; the 802.11 MAC header
    is little-endian, so ``d11.ID`` is byte-swapped.

    ``ID=0x3A01`` puts the bytes ``3a 01`` on the wire, which tshark reads as
    ``0x013a`` = 314 us. Unswapped it reads as 14849 - not just wrong but above
    the 32767 us the field can hold, which is how the bug was spotted.
    """
    pkt = roundtrip(RadioTap() / mgmt(12, ID=0x3A01) / Dot11Deauth(reason=7))
    raw = scapy_to_raw(pkt, IFACE, FrameState())
    assert raw["wlan.duration"] == 314
    assert pkt.getlayer(Dot11).ID == 0x3A01      # what scapy alone would report


def test_frame_time_delta_is_relative_only() -> None:
    """No absolute session time may reach the vector - that was 42% of v1's gain."""
    state = FrameState()
    a = roundtrip(RadioTap() / mgmt(12) / Dot11Deauth(reason=7))
    b = roundtrip(RadioTap() / mgmt(12) / Dot11Deauth(reason=7))
    a.time, b.time = 1_700_000_000.0, 1_700_000_000.25
    first, _ = packet_to_features_v2(a, IFACE, state)
    second, _ = packet_to_features_v2(b, IFACE, state)
    assert first["frame.dt"] == 0.0
    assert second["frame.dt"] == pytest.approx(0.25)
    assert second["frame.dt_log"] == pytest.approx(math.log1p(0.25))
    assert "frame.time_epoch" not in second and "frame.time_relative" not in second


def test_raw_dict_never_invents_a_field() -> None:
    """Absence is information. A minimal frame must produce a *small* raw dict."""
    raw = scapy_to_raw(roundtrip(Dot11(type=1, subtype=13,
                                       addr1="02:00:00:00:00:01")), IFACE, FrameState())
    for key in ("radiotap.datarate", "radiotap.channel.freq", "wlan.fixed.reason_code",
                "wlan.ssid", "eapol.type", "wlan_radio.signal_dbm",
                "wlan.rsn.capabilities.mfpc", "wlan.fcs.bad_checksum"):
        assert key not in raw, key


# --------------------------------------------------------------------------- #
# The real captures                                                            #
# --------------------------------------------------------------------------- #
CAPTURES = ["deauth_raw_decrypted.pcapng", "beacon_raw_decrypted.pcapng"]
MAX_FRAMES = 4000


def run_capture(path: Path, limit: int = MAX_FRAMES) -> Tuple[int, Dict[str, List[int]]]:
    """``(frames, {feature: [non-null count, distinct values]})``."""
    state = FrameState()
    stats: Dict[str, List[Any]] = {k: [0, set()] for k in FEATURE_ORDER_V2}
    n = 0
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if n >= limit:
                break
            n += 1
            feats, _ = packet_to_features_v2(pkt, IFACE, state)
            assert sorted(feats) == sorted(FEATURE_ORDER_V2)
            for key, value in feats.items():
                if not is_nan(value):
                    stats[key][0] += 1
                    if len(stats[key][1]) < 32:
                        stats[key][1].add(value)
    return n, stats


@pytest.mark.parametrize("name", CAPTURES)
def test_real_capture_feature_coverage(name: str, capsys: Any) -> None:
    """Run a real monitor-mode capture end to end and *print* the coverage.

    v1 left 16 of 29 features permanently null in the field. This does not assert
    a coverage target - it measures one, and fails only if the extractor throws,
    drops a feature, or leaves a feature null on every single frame.
    """
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"{path} not present")

    frames, stats = run_capture(path)
    assert frames > 0

    with capsys.disabled():
        print(f"\n  {name}: {frames} frames")
        print(f"  {'feature':26s} {'non-null':>9s}  {'distinct':>8s}")
        always_null = []
        for key in FEATURE_ORDER_V2:
            count, values = stats[key]
            pct = 100.0 * count / frames
            print(f"  {key:26s} {pct:8.2f}%  {len(values):8d}")
            if count == 0:
                always_null.append(key)
        print(f"  always-null: {always_null or 'none'}")

    # Per capture, only features whose *evidence* is absent may be null: a
    # beacon-only capture has no deauth and no handshake, and asserting
    # otherwise would test the pcap rather than the extractor. The cross-capture
    # union is checked in test_no_feature_is_dead_across_all_captures.
    always_null = {k for k in FEATURE_ORDER_V2 if stats[k][0] == 0}
    assert always_null <= {
        "mgmt.tag_len",          # multi-valued tshark field, see the module notes
        "mgmt.reason_code", "mgmt.beacon_interval", "mgmt.ssid_len",
        "eapol.type", "eapol.len", "eapol.msgnr",
        "eapol.key_len", "eapol.replay_counter",
    }, always_null


def test_real_capture_carries_the_v2_signal() -> None:
    """The features v1 could not see must actually fire on real attack traffic."""
    path = SAMPLES / "deauth_raw_decrypted.pcapng"
    if not path.exists():
        pytest.skip(f"{path} not present")

    _frames, stats = run_capture(path)
    assert stats["mgmt.reason_code"][0] > 0, "no reason codes in a deauth capture"
    assert 7 in stats["mgmt.reason_code"][1] or len(stats["mgmt.reason_code"][1]) > 1
    assert len(stats["radio.signal_dbm"][1]) > 1
    assert len(stats["wlan.duration"][1]) > 1
    assert max(stats["wlan.duration"][1]) <= 32767, "duration byte-swapped again"


def test_real_capture_is_stateful_but_not_order_fragile() -> None:
    """A fresh FrameState must not change any per-frame feature except the two
    delta features - otherwise restarting the detector shifts the whole vector."""
    path = SAMPLES / "beacon_raw_decrypted.pcapng"
    if not path.exists():
        pytest.skip(f"{path} not present")

    stateful, isolated = [], []
    shared = FrameState()
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            if i >= 200:
                break
            stateful.append(packet_to_features_v2(pkt, IFACE, shared)[0])
            isolated.append(packet_to_features_v2(pkt, IFACE, FrameState())[0])

    delta_features = {"wlan.seq_delta", "addr.same_bssid_as_prev", "frame.dt",
                      "frame.dt_log"}
    for a, b in zip(stateful, isolated):
        for key in FEATURE_ORDER_V2:
            if key in delta_features:
                continue
            assert (is_nan(a[key]) and is_nan(b[key])) or a[key] == b[key], key


def test_no_feature_is_dead_across_all_captures() -> None:
    """Every feature must fire on at least one frame of the sample captures.

    A feature that is null everywhere is dead weight the model cannot learn from,
    and -- worse -- one that is dead in *training* while varying in the field is
    how v1 died. This asserts the set is empty.

    History: ``mgmt.tag_len`` used to be the lone exception. ``wlan.tag.length``
    is a repeated tshark field and AWID3 joins its occurrences with "-"
    ("0-8-26-12"), which ``feature_spec._f()`` could not parse. Spec 2.1.0 fixed
    the parser (and made the feature the *sum* of the tag lengths), reviving it on
    both the training and the live path at once. ``frame.fcs_bad`` was removed in
    the same release for being constant in AWID3.
    """
    paths = sorted(SAMPLES.glob("*.pcapng"))
    if not paths:
        pytest.skip("no sample captures present")

    seen = {k: 0 for k in FEATURE_ORDER_V2}
    for path in paths:
        # far enough in to reach the handshakes: the only EAPOL frames in the
        # sample set are at index 1609-1612 and 4067-4074 of the deauth capture
        # and 2272-2273 of the disassoc one.
        _frames, stats = run_capture(path, limit=3000)
        for key in FEATURE_ORDER_V2:
            seen[key] += stats[key][0]

    dead = sorted(k for k, n in seen.items() if n == 0)
    assert dead == [], f"features null on every frame of every capture: {dead}"


def test_signal_dbm_is_the_last_antenna_chain() -> None:
    """Wireshark reports the LAST dBm_AntSignal as wlan_radio.signal_dbm.

    Not the first, not the strongest, not the weakest. Verified against tshark on
    this capture: [-37,-37,-41] -> -41 but [-34,-35,-34] -> -34. Reading the
    first chain instead disagreed with tshark on 97.6% of frames.
    """
    path = SAMPLES / "deauth_raw_decrypted.pcapng"
    if not path.exists():
        pytest.skip(f"{path} not present")

    state = FrameState()
    multi = 0
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            if i >= 500:
                break
            chains = all_dbm_antsignal(pkt)
            raw = scapy_to_raw(pkt, IFACE, state)
            if len(chains) > 1:
                multi += 1
                assert raw["wlan_radio.signal_dbm"] == chains[-1]
            if chains:
                assert raw["radiotap.dbm_antsignal"] == "-".join(str(c) for c in chains)
    assert multi > 0, "capture has no multi-chain frames; test proves nothing"


# --------------------------------------------------------------------------- #
# Ground truth: the real dissector, when it is available                       #
# --------------------------------------------------------------------------- #
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")

#: Columns whose tshark text form is stable across versions. Deliberately
#: excluded: every boolean field (tshark 4.x prints "True"/"False" where AWID3
#: has "1"/"0") and wlan.ssid (tshark 4.x hex-encodes it, AWID3 has the
#: characters). We match AWID3's convention on those, not this tshark's -- see
#: the notes handed back with this work.
TSHARK_STABLE = [
    "frame.len", "radiotap.length", "radiotap.mactime", "radiotap.channel.freq",
    "radiotap.datarate", "radiotap.dbm_antsignal",
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.ds", "wlan.duration", "wlan.seq",
    "wlan.fixed.reason_code", "wlan.fixed.beacon", "wlan.country_info.code",
    "wlan_rsna_eapol.keydes.msgnr", "wlan_rsna_eapol.keydes.data_len",
    "eapol.type", "eapol.len", "eapol.keydes.key_len", "eapol.keydes.replay_counter",
    "wlan_radio.signal_dbm", "wlan_radio.data_rate", "wlan_radio.phy",
    "wlan.sa", "wlan.da", "wlan.bssid", "wlan.ta",
]
TEXT_COLUMNS = {"wlan.sa", "wlan.da", "wlan.bssid", "wlan.ta",
                "wlan.country_info.code", "radiotap.dbm_antsignal"}


@pytest.mark.skipif(not TSHARK.exists(), reason="tshark not installed")
def test_scapy_raw_dict_matches_tshark() -> None:
    """The parity claim, checked against the dissector AWID3 was built with.

    ``scapy_to_raw`` exists to emit what tshark would have emitted. When tshark
    is on the box we can stop arguing about it and diff the two field by field.
    """
    import subprocess

    path = SAMPLES / "deauth_raw_decrypted.pcapng"
    if not path.exists():
        pytest.skip(f"{path} not present")
    frames = 2000

    cmd = [str(TSHARK), "-r", str(path), "-c", str(frames), "-T", "fields",
           "-E", "separator=|", "-E", "aggregator=-", "-E", "occurrence=a"]
    for column in TSHARK_STABLE:
        cmd += ["-e", column]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        pytest.skip(f"tshark failed: {proc.stderr[-200:]}")
    rows = [line.split("|") for line in proc.stdout.splitlines()]
    assert rows, "tshark produced no output"

    state = FrameState()
    disagreements: Dict[str, int] = {c: 0 for c in TSHARK_STABLE}
    examples: Dict[str, Any] = {}
    checked = 0
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            if i >= len(rows):
                break
            checked += 1
            raw = scapy_to_raw(pkt, IFACE, state)
            for j, column in enumerate(TSHARK_STABLE):
                theirs = rows[i][j].strip() if j < len(rows[i]) else ""
                mine = "" if raw.get(column) is None else str(raw[column]).strip()
                if not theirs and not mine:
                    continue
                if column in TEXT_COLUMNS:
                    same = theirs.lower() == mine.lower()
                else:
                    a, b = spec_float(theirs), spec_float(mine)
                    same = a is not None and b is not None and abs(a - b) < 1e-6
                if not same:
                    disagreements[column] += 1
                    examples.setdefault(column, (i, theirs, mine))

    assert checked > 1000
    bad = {c: (n, examples[c]) for c, n in disagreements.items() if n}
    # wlan.tag.length is not in the stable set; nothing here is allowed to drift.
    assert not bad, f"disagrees with tshark on {checked} frames: {bad}"
