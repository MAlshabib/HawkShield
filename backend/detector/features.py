"""Scapy packet -> model feature row.

This replaces the original ``scapy_to_row()``, which left **13 of the 29 numeric
features permanently ``None``** (so they were mean/median-imputed on every single
live packet) and hardcoded ``wlan.fc.ds = 0``.

Guiding rule: a field the frame genuinely does not carry stays ``None`` so the
bundle's ``SimpleImputer`` fills it. Nothing is invented.

The 31 model feature names are fixed by the bundles; see ``docs/CONTRACT.md`` section 5.
"""
from __future__ import annotations

import logging
import math
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.dot11 import Dot11, Dot11Disas, Dot11Deauth, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL

from backend.detector.feature_spec import FEATURE_ORDER as FEATURE_ORDER_V2
from backend.detector.feature_spec import FrameState, derive_frame_features

logger = logging.getLogger(__name__)

__all__ = [
    "ExtractState",
    "packet_to_row",
    "FEATURE_ORDER",
    "freq_to_channel",
    "all_dbm_antsignal",
    # v2
    "FEATURE_ORDER_V2",
    "FrameState",
    "scapy_to_raw",
    "packet_to_features_v2",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: 31 feature names in the exact order both Boosters expect.
FEATURE_ORDER: List[str] = [
    "frame.encap_type", "frame.len", "frame.time_delta", "frame.time_delta_displayed",
    "frame.time_relative", "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm",
    "radiotap.channel.freq", "radiotap.datarate", "radiotap.dbm_antsignal",
    "radiotap.length", "radiotap.rxflags", "wlan.duration", "wlan.fc.ds", "wlan.fc.frag",
    "wlan.fc.order", "wlan.fc.moredata", "wlan.fc.protected", "wlan.fc.pwrmgt",
    "wlan.fc.type", "wlan.fc.retry", "wlan.fc.subtype", "wlan_radio.duration",
    "wlan.seq", "wlan_radio.channel", "wlan_radio.data_rate", "wlan_radio.frequency",
    "wlan_radio.signal_dbm", "wlan_radio.phy",
    "wlan.country_info.fnm", "wlan.country_info.code",   # cat_cols, always absent live
]

#: 29 numeric columns the imputer/scaler were fit on.
NUM_COLS: List[str] = FEATURE_ORDER[:29]

#: tshark ``frame.encap_type`` for "IEEE 802.11 plus radiotap header".
#: Verified constant (variance 0) in the training set - the bundle's scaler records
#: mean 23.0 / std 0 for this column.
ENCAP_TYPE_RADIOTAP_80211 = 23

# 802.11 FCfield bit layout (scapy order: to-DS, from-DS, MF, retry, pw-mgt, MD, protected, order)
_FC_TO_DS = 0x01
_FC_FROM_DS = 0x02
_FC_MORE_FRAG = 0x04
_FC_RETRY = 0x08
_FC_PWRMGT = 0x10
_FC_MOREDATA = 0x20
_FC_PROTECTED = 0x40
_FC_ORDER = 0x80

# radiotap channel-flags bits (scapy ``_rt_channelflags``)
_CH_TURBO = 0x0010
_CH_CCK = 0x0020
_CH_OFDM = 0x0040
_CH_2GHZ = 0x0080
_CH_5GHZ = 0x0100
_CH_GFSK = 0x0800

# radiotap ``Flags`` bits (scapy ``_rt_flags``)
_RTF_SHORT_PREAMBLE = 0x02

# tshark / wiretap ``wlan_radio.phy`` enum
PHY_11_FHSS = 1
PHY_11_DSSS = 3
PHY_11B = 4
PHY_11A = 5
PHY_11G = 6
PHY_11N = 7
PHY_11AC = 8
PHY_11AX = 11

# radiotap presence-bit names, in bit order (default namespace)
_RT_BIT = {
    "TSFT": 0, "Flags": 1, "Rate": 2, "Channel": 3, "FHSS": 4, "dBm_AntSignal": 5,
    "dBm_AntNoise": 6, "Lock_Quality": 7, "TX_Attenuation": 8, "dB_TX_Attenuation": 9,
    "dBm_TX_Power": 10, "Antenna": 11, "dB_AntSignal": 12, "dB_AntNoise": 13,
    "RXFlags": 14, "TXFlags": 15, "b16": 16, "b17": 17, "ChannelPlus": 18, "MCS": 19,
    "A_MPDU": 20, "VHT": 21, "timestamp": 22, "HE": 23, "HE_MU": 24,
    "HE_MU_other_user": 25, "zero_length_psdu": 26, "L_SIG": 27, "TLV": 28,
    "RadiotapNS": 29, "VendorNS": 30, "Ext": 31,
}

# bit -> (alignment, size) in the radiotap default namespace
_RT_LAYOUT: Dict[int, Tuple[int, int]] = {
    0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (1, 2), 5: (1, 1), 6: (1, 1),
    7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1),
    14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 18: (4, 8), 19: (1, 3),
    20: (4, 8), 21: (2, 12), 22: (8, 12), 23: (2, 12), 24: (2, 12), 25: (2, 6),
    26: (1, 1), 27: (2, 4), 28: (4, 0), 29: (0, 0), 30: (2, 6), 31: (0, 0),
}


# ---------------------------------------------------------------------------
# Extraction state
# ---------------------------------------------------------------------------
@dataclass
class ExtractState:
    """Carries the per-capture timing state needed for the delta features.

    ``frame.time_delta`` needs the previous captured packet's timestamp and
    ``frame.time_relative`` needs the capture-start timestamp; neither can be
    derived from a packet in isolation.
    """

    prev_ts: Optional[float] = None
    start_ts: Optional[float] = None
    count: int = 0

    def observe(self, ts: Optional[float]) -> Tuple[Optional[float], Optional[float]]:
        """Record ``ts`` and return ``(delta, relative)`` seconds."""
        self.count += 1
        if ts is None:
            return None, None
        if self.start_ts is None:
            self.start_ts = ts
        delta = 0.0 if self.prev_ts is None else max(0.0, ts - self.prev_ts)
        relative = max(0.0, ts - self.start_ts)
        self.prev_ts = ts
        return delta, relative

    def reset(self) -> None:
        self.prev_ts = None
        self.start_ts = None
        self.count = 0


# ---------------------------------------------------------------------------
# Small coercers
# ---------------------------------------------------------------------------
def _to_int(v: Any) -> Optional[int]:
    try:
        if v is None or v == "":
            return None
        return int(float(v))
    except Exception:
        return None


def _to_float(v: Any) -> Optional[float]:
    try:
        if v is None or v == "":
            return None
        f = float(v)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except Exception:
        return None


# ---------------------------------------------------------------------------
# RadioTap helpers
# ---------------------------------------------------------------------------
def _present_names(rt: Any) -> set:
    """Names of the presence bits set in the *first* radiotap presence mask."""
    try:
        return set(str(x) for x in list(rt.present))
    except Exception:
        return set()


def _radiotap_masks(pkt: Any) -> Tuple[bytes, int, List[int], int]:
    """``(raw bytes, radiotap header length, presence masks, offset past masks)``.

    Scapy 2.6.1 decodes only the first presence namespace, so anything that needs
    the extended masks (per-chain signal, the raw presence bitmap) has to walk the
    header itself. Returns ``(b"", 0, [], 0)`` when the header cannot be parsed.
    """
    try:
        raw = bytes(pkt.original if getattr(pkt, "original", None) else bytes(pkt))
        if len(raw) < 8:
            return b"", 0, [], 0
        _ver, _pad, hdr_len = struct.unpack_from("<BBH", raw, 0)
        if hdr_len < 8 or hdr_len > len(raw):
            return b"", 0, [], 0

        masks: List[int] = []
        off = 4
        while True:
            if off + 4 > hdr_len:
                return b"", 0, [], 0
            (m,) = struct.unpack_from("<I", raw, off)
            masks.append(m)
            off += 4
            if not (m & (1 << 31)):
                break
        return raw, hdr_len, masks, off
    except Exception:  # pragma: no cover - defensive; malformed radiotap
        return b"", 0, [], 0


def all_dbm_antsignal(pkt: Any) -> List[int]:
    """Every ``dBm_AntSignal`` value in the radiotap header, in order.

    Multi-antenna adapters (the Pi's, and the ones the training captures were
    taken with) emit one value per chain. Returns ``[]`` when nothing can be
    parsed.
    """
    raw, hdr_len, masks, off = _radiotap_masks(pkt)
    if not masks:
        return []
    try:
        out: List[int] = []
        for mask in masks:
            if mask & (1 << _RT_BIT["VendorNS"]):
                # vendor namespace: field meanings are not ours to guess
                break
            for bit in range(0, 31):
                if not (mask & (1 << bit)):
                    continue
                align, size = _RT_LAYOUT.get(bit, (1, 0))
                if size == 0 and align == 0:
                    continue
                if align > 1:
                    off += (-off) % align
                if off + size > hdr_len:
                    return out
                if bit == _RT_BIT["dBm_AntSignal"]:
                    (val,) = struct.unpack_from("<b", raw, off)
                    out.append(int(val))
                off += size
        return out
    except Exception:  # pragma: no cover - defensive; malformed radiotap
        return []


def freq_to_channel(freq: Optional[int]) -> Optional[int]:
    """802.11 channel number for a centre frequency in MHz."""
    if freq is None:
        return None
    f = int(freq)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 4910 <= f <= 4980:
        return (f - 4000) // 5
    if 5000 <= f <= 5925:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:                # 6 GHz / 802.11ax
        return (f - 5950) // 5
    return None


def _derive_phy(
    present: set, chan_flags: Optional[int], freq: Optional[int]
) -> Optional[int]:
    """tshark ``wlan_radio.phy`` enum, or None when the radiotap does not say."""
    if "HE" in present:
        return PHY_11AX
    if "VHT" in present:
        return PHY_11AC
    if "MCS" in present:
        return PHY_11N
    if chan_flags is None:
        return None
    if chan_flags & _CH_OFDM:
        if freq is not None and freq >= 4000:
            return PHY_11A
        if freq is not None and freq < 3000:
            return PHY_11G
        return None
    if chan_flags & _CH_CCK:
        return PHY_11B
    if chan_flags & _CH_GFSK:
        return PHY_11_FHSS
    return None


def _derive_wlan_radio_duration(
    phy: Optional[int],
    mpdu_len: Optional[int],
    rate_mbps: Optional[float],
    short_preamble: bool,
) -> Optional[float]:
    """PLCP-level frame duration in microseconds, as the wlan_radio dissector computes it.

    DSSS/CCK : preamble (192 us long / 96 us short) + ceil(bits / rate)
    OFDM     : 20 us preamble+SIGNAL + 4 us * ceil((22 + 8*len) / N_DBPS),
               plus a 6 us signal extension for ERP-OFDM (802.11g).
    Returns None when the inputs needed are not available.
    """
    if phy is None or mpdu_len is None or not rate_mbps or rate_mbps <= 0:
        return None
    if mpdu_len <= 0:
        return None
    if phy in (PHY_11B, PHY_11_DSSS, PHY_11_FHSS):
        preamble = 96.0 if short_preamble else 192.0
        return preamble + math.ceil(mpdu_len * 8.0 / rate_mbps)
    if phy in (PHY_11A, PHY_11G, PHY_11N, PHY_11AC, PHY_11AX):
        n_dbps = rate_mbps * 4.0          # 4 us OFDM symbol
        symbols = math.ceil((22.0 + 8.0 * mpdu_len) / n_dbps)
        duration = 20.0 + 4.0 * symbols
        if phy == PHY_11G:
            duration += 6.0               # ERP-OFDM signal extension
        return duration
    return None


def _ssid_from_beacon_or_probe(pkt: Any) -> Optional[str]:
    """SSID from information element ID 0 of a beacon / probe frame."""
    try:
        if not pkt.haslayer(Dot11Elt):
            return None
        elt = pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            if getattr(elt, "ID", None) == 0:
                info = bytes(getattr(elt, "info", b"") or b"")
                return info.decode(errors="ignore")
            elt = elt.payload if hasattr(elt, "payload") else None
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------
def packet_to_row(pkt: Any, iface: str, state: ExtractState) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return ``(row_for_model, raw_min_for_db)`` for one scapy packet.

    ``row`` keys are the 31 names in :data:`FEATURE_ORDER`. Any value the frame
    does not actually carry is ``None`` so the bundle imputer handles it.
    """
    row: Dict[str, Any] = {k: None for k in FEATURE_ORDER}

    # ---- frame-level -------------------------------------------------------
    row["frame.encap_type"] = ENCAP_TYPE_RADIOTAP_80211
    try:
        frame_len = len(pkt)
    except Exception:
        frame_len = None
    row["frame.len"] = _to_int(frame_len)

    ts = _to_float(getattr(pkt, "time", None))
    delta, relative = state.observe(ts)
    row["frame.time_delta"] = delta
    row["frame.time_delta_displayed"] = delta      # no display filter applied
    row["frame.time_relative"] = relative

    # ---- radiotap ----------------------------------------------------------
    rt = pkt.getlayer(RadioTap) if hasattr(pkt, "getlayer") else None
    present: set = set()
    chan_flags: Optional[int] = None
    freq: Optional[int] = None
    short_preamble = False
    rt_len: Optional[int] = None

    if rt is not None:
        present = _present_names(rt)

        rt_len = _to_int(getattr(rt, "len", None))
        row["radiotap.length"] = _to_float(rt_len)

        if "Rate" in present:
            row["radiotap.datarate"] = _to_float(getattr(rt, "Rate", None))

        if "Channel" in present:
            freq = _to_int(getattr(rt, "ChannelFrequency", None))
            row["radiotap.channel.freq"] = _to_float(freq)
            cf = getattr(rt, "ChannelFlags", None)
            if cf is not None:
                try:
                    chan_flags = int(cf)
                except Exception:
                    chan_flags = None
            if chan_flags is not None:
                row["radiotap.channel.flags.cck"] = 1 if chan_flags & _CH_CCK else 0
                row["radiotap.channel.flags.ofdm"] = 1 if chan_flags & _CH_OFDM else 0

        if "RXFlags" in present:
            try:
                row["radiotap.rxflags"] = float(int(getattr(rt, "RXFlags", 0) or 0))
            except Exception:
                row["radiotap.rxflags"] = None

        if "Flags" in present:
            try:
                short_preamble = bool(int(getattr(rt, "Flags", 0) or 0) & _RTF_SHORT_PREAMBLE)
            except Exception:
                short_preamble = False

        if "dBm_AntSignal" in present:
            chains = all_dbm_antsignal(pkt)
            if not chains:
                one = _to_int(getattr(rt, "dBm_AntSignal", None))
                chains = [one] if one is not None else []
            if chains:
                # tshark reports one radiotap.dbm_antsignal per chain; the training
                # extraction collapsed them by summing, while wlan_radio.signal_dbm
                # keeps the strongest chain. Reproduce both.
                row["radiotap.dbm_antsignal"] = float(sum(chains))
                row["wlan_radio.signal_dbm"] = float(max(chains))

    # ---- 802.11 MAC header -------------------------------------------------
    d11 = pkt.getlayer(Dot11) if hasattr(pkt, "getlayer") else None
    if d11 is not None:
        row["wlan.fc.type"] = _to_int(getattr(d11, "type", None))
        row["wlan.fc.subtype"] = _to_int(getattr(d11, "subtype", None))

        try:
            fc = int(getattr(d11, "FCfield", 0) or 0)
        except Exception:
            fc = 0
        row["wlan.fc.ds"] = (1 if fc & _FC_TO_DS else 0) | (2 if fc & _FC_FROM_DS else 0)
        row["wlan.fc.frag"] = 1 if fc & _FC_MORE_FRAG else 0
        row["wlan.fc.retry"] = 1 if fc & _FC_RETRY else 0
        row["wlan.fc.pwrmgt"] = 1 if fc & _FC_PWRMGT else 0
        row["wlan.fc.moredata"] = 1 if fc & _FC_MOREDATA else 0
        row["wlan.fc.protected"] = 1 if fc & _FC_PROTECTED else 0
        row["wlan.fc.order"] = 1 if fc & _FC_ORDER else 0

        row["wlan.duration"] = _to_int(getattr(d11, "ID", None))

        sc = getattr(d11, "SC", None)
        if sc is not None:
            sc_i = _to_int(sc)
            if sc_i is not None:
                row["wlan.seq"] = float(sc_i >> 4)   # low 4 bits are the fragment number

    # ---- wlan_radio.* (tshark's synthesised radio summary) -----------------
    row["wlan_radio.frequency"] = row["radiotap.channel.freq"]
    row["wlan_radio.channel"] = _to_float(freq_to_channel(freq))
    row["wlan_radio.data_rate"] = row["radiotap.datarate"]

    phy = _derive_phy(present, chan_flags, freq)
    row["wlan_radio.phy"] = _to_float(phy)

    mpdu_len = None
    if row["frame.len"] is not None and rt_len is not None:
        mpdu_len = int(row["frame.len"]) - int(rt_len)
    row["wlan_radio.duration"] = _derive_wlan_radio_duration(
        phy, mpdu_len, row["radiotap.datarate"], short_preamble
    )

    # wlan.country_info.* stay absent; the model space fills the 2 cat_cols with 0.0.

    # ---- raw_min for the DB -----------------------------------------------
    sa = getattr(d11, "addr2", None) if d11 is not None else None
    da = getattr(d11, "addr1", None) if d11 is not None else None
    bssid = getattr(d11, "addr3", None) if d11 is not None else None

    raw_min: Dict[str, Any] = {
        "iface": iface,
        "sa": sa,
        "da": da,
        "bssid": bssid,
        "len": row["frame.len"],
        "type": row["wlan.fc.type"],
        "subtype": row["wlan.fc.subtype"],
        "rate": row["radiotap.datarate"],
        "sig": row["wlan_radio.signal_dbm"],
        "ssid": _ssid_from_beacon_or_probe(pkt),
    }
    return row, raw_min


# ===========================================================================
# v2: scapy packet -> normalised tshark-like dict -> feature_spec derivation
# ===========================================================================
# The v1 failure was structural: training read tshark columns, inference built a
# different dict in different code, and 16 of 29 features were silently NULL in
# the field. v2 removes the possibility: both paths emit the *same* raw dict and
# call the *same* ``derive_frame_features()``.
#
# Multi-value convention
# ----------------------
# AWID3's CSV export joins tshark's repeated fields with "-", not "," --
# ``radiotap.dbm_antsignal='-29-32-29'``, ``wlan.tag.length='0-8-26-12'``,
# ``radiotap.present.tsft='1-0-0'`` (one entry per radiotap presence word).
# We reproduce that shape exactly rather than a cleaned-up single value, so that
# whatever ``feature_spec`` does with a multi-value cell it does identically on
# both sides. See the notes in ``backend/tests/test_features_v2.py``.

#: separator AWID3 uses to join tshark's repeated field occurrences
AWID3_MULTI_SEP = "-"

# radiotap Flags bits
_RTF_BADFCS = 0x40

# 802.11 capability-info bits, as scapy's FlagsField numbers them
_CAP_ESS = 0x0100
_CAP_IBSS = 0x0200

# information-element IDs
_IE_SSID = 0
_IE_COUNTRY = 7
_IE_RSN = 48

# EAPOL Key Information bits (IEEE 802.11-2016 12.7.2)
_KI_INSTALL = 0x0040
_KI_ACK = 0x0080
_KI_MIC = 0x0100
_KI_SECURE = 0x0200

#: (bits/subcarrier, coding rate) per HT/VHT MCS index
_MCS_MODULATION: Dict[int, Tuple[int, float]] = {
    0: (1, 1 / 2), 1: (2, 1 / 2), 2: (2, 3 / 4), 3: (4, 1 / 2), 4: (4, 3 / 4),
    5: (6, 2 / 3), 6: (6, 3 / 4), 7: (6, 5 / 6), 8: (8, 3 / 4), 9: (8, 5 / 6),
    10: (10, 3 / 4), 11: (10, 5 / 6),
}

#: data subcarriers per channel width (MHz)
_N_SUBCARRIERS: Dict[int, int] = {20: 52, 40: 108, 80: 234, 160: 468}


def _mcs_rate_mbps(
    mcs_index: int, nss: int, bw_mhz: int, short_gi: bool
) -> Optional[float]:
    """PHY rate in Mb/s for an HT/VHT MCS, as ``wlan_radio.data_rate`` reports it.

    ``rate = N_SD * bits_per_subcarrier * coding_rate * N_SS / T_sym``, with
    ``T_sym`` 4.0 us (long GI) or 3.6 us (short GI). Reproduces the published
    tables exactly: HT MCS 21 at 20 MHz short-GI -> 173.333 Mb/s, which is one of
    the values AWID3 actually contains.
    """
    mod = _MCS_MODULATION.get(mcs_index)
    nsd = _N_SUBCARRIERS.get(bw_mhz)
    if mod is None or nsd is None or nss < 1 or nss > 8:
        return None
    bits, coding = mod
    t_sym = 3.6 if short_gi else 4.0
    return round(nsd * bits * coding * nss / t_sym, 3)


def _ht_rate(rt: Any) -> Optional[float]:
    """``wlan_radio.data_rate`` from a radiotap MCS field."""
    idx = _to_int(getattr(rt, "MCS_index", None))
    if idx is None or idx >= 32:      # >=32 is the 40 MHz duplicate mode
        return None
    bw_code = _to_int(getattr(rt, "MCS_bandwidth", None)) or 0
    short_gi = bool(_to_int(getattr(rt, "guard_interval", None)) or 0)
    return _mcs_rate_mbps(idx % 8, idx // 8 + 1, 40 if bw_code == 1 else 20, short_gi)


def _vht_rate(rt: Any) -> Optional[float]:
    """``wlan_radio.data_rate`` from a radiotap VHT field (first user only)."""
    try:
        mcs_nss = getattr(rt, "mcs_nss", None)
        if not mcs_nss:
            return None
        first = mcs_nss[0]
        if hasattr(first, "mcs"):
            mcs, nss = _to_int(first.mcs), _to_int(first.nss)
        else:
            v = _to_int(first) or 0
            mcs, nss = (v >> 4) & 0x0F, v & 0x0F
        if mcs is None or not nss:
            return None
        bw_code = _to_int(getattr(rt, "VHT_bandwidth", None)) or 0
        bw = 20 if bw_code == 0 else 40 if bw_code <= 3 else 80 if bw_code <= 10 else 160
        short_gi = bool((_to_int(getattr(rt, "PresentVHT", None)) or 0) & 0x04)
        return _mcs_rate_mbps(mcs, nss, bw, short_gi)
    except Exception:  # pragma: no cover - defensive; vendor-mangled VHT field
        return None


def _flags_int(v: Any) -> Optional[int]:
    """Integer value of a scapy ``FlagsField``.

    ``_to_int`` cannot be used: it goes through ``float()``, and ``float()`` of a
    ``FlagValue`` raises, so every radiotap flags field would silently read as
    ``None`` (which is how ``radiotap.channel.flags.cck/ofdm`` came out constant-0
    on the first pass over the real captures).
    """
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _dot11_duration(d11: Any) -> Optional[int]:
    """``wlan.duration`` in microseconds.

    Scapy declares the Duration/ID field as a big-endian ``ShortField``, but the
    802.11 MAC header is little-endian, so ``d11.ID`` comes back byte-swapped:
    a 314 us duration reads as 14849, and 69 of 4000 frames in
    ``disassoc_raw_decrypted.pcapng`` exceed the 32767 us the field can even hold.
    Swap it back to what tshark reports.
    """
    raw = _to_int(getattr(d11, "ID", None))
    if raw is None:
        return None
    return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)


def _present_tsft_field(pkt: Any, present: set) -> Optional[str]:
    """``radiotap.present.tsft`` in AWID3's shape: one 0/1 per presence word.

    tshark emits the TSFT presence bit once per radiotap presence word, so a
    header with two extension words reads ``"1-0-0"``. The value is a property of
    the *bitmap*, not of the frame body, so ``"0"`` is a real observation and is
    reported as such -- it is not an invented value.
    """
    _raw, _hdr, masks, _off = _radiotap_masks(pkt)
    if not masks:
        return "1" if "TSFT" in present else None
    return AWID3_MULTI_SEP.join("1" if (m & 0x01) else "0" for m in masks)


def _walk_ies(pkt: Any) -> List[Tuple[int, bytes, int]]:
    """``(element id, body, declared length)`` for every 802.11 information element.

    Walks the raw TLV bytes rather than scapy's per-IE dissectors: the specialised
    classes (``Dot11EltCountry``, ``Dot11EltRSN``, ...) expose different attribute
    names and some real-world IEs fail to dissect at all. Truncated elements are
    returned with whatever body survived and terminate the walk.
    """
    try:
        first = pkt.getlayer(Dot11Elt)
        if first is None:
            return []
        blob = bytes(first)
    except Exception:
        return []

    out: List[Tuple[int, bytes, int]] = []
    off, n = 0, len(blob)
    while off + 2 <= n and len(out) < 128:
        eid, declared = blob[off], blob[off + 1]
        body = blob[off + 2: off + 2 + declared]
        out.append((eid, body, declared))
        if len(body) < declared:            # truncated capture
            break
        off += 2 + declared
    return out


def _parse_rsn_ie(body: bytes) -> Dict[str, Any]:
    """MFP-capable bit and PMKID presence from an RSN information element.

    The RSN IE is variable-length and every section after the version is optional,
    so each step is bounds-checked and a short IE simply yields fewer keys.
    Layout: version(2) group-cipher(4) n_pairwise(2) suites(4n) n_akm(2)
    suites(4n) capabilities(2) [n_pmkid(2) pmkids(16n)] [group-mgmt-cipher(4)].
    """
    out: Dict[str, Any] = {}
    try:
        off = 2 + 4                                 # past version + group cipher
        for _ in range(2):                          # pairwise then AKM suite lists
            if off + 2 > len(body):
                return out
            count = int.from_bytes(body[off:off + 2], "little")
            off += 2
            if count > 16:                          # implausible; refuse to guess
                return out
            off += 4 * count
        if off + 2 > len(body):
            return out
        caps = int.from_bytes(body[off:off + 2], "little")
        off += 2
        out["mfpc"] = (caps >> 7) & 0x01
        out["mfpr"] = (caps >> 6) & 0x01
        if off + 2 <= len(body):
            n_pmkid = int.from_bytes(body[off:off + 2], "little")
            off += 2
            if 0 < n_pmkid <= 16 and off + 16 <= len(body):
                out["pmkid"] = body[off:off + 16].hex()
    except Exception:  # pragma: no cover - defensive; malformed RSN IE
        pass
    return out


def _eapol_msgnr(key_info: int, key_data_len: Optional[int]) -> Optional[int]:
    """Which of the four 4-way-handshake messages this EAPOL-Key frame is.

    Same rule the wlan_rsna_eapol dissector uses, off the Key Information bits:

    ==== ==== ====== ======================================================
    Ack  MIC  Secure message
    ==== ==== ====== ======================================================
    1    0    -      1  (AP -> STA, ANonce, no MIC yet)
    0    1    0      2  (STA -> AP, SNonce + MIC, key data present)
    1    1    -      3  (AP -> STA, GTK, MIC; the frame Krack replays)
    0    1    1      4  (STA -> AP, MIC only, no key data)
    ==== ==== ====== ======================================================
    """
    ack = bool(key_info & _KI_ACK)
    mic = bool(key_info & _KI_MIC)
    secure = bool(key_info & _KI_SECURE)
    if ack:
        return 3 if mic else 1
    if mic:
        if secure or (key_data_len is not None and key_data_len == 0):
            return 4
        return 2
    return None


def _eapol_key_body(pkt: Any) -> Dict[str, Any]:
    """Key-descriptor fields of an EAPOL-Key frame.

    Scapy's ``EAPOL_KEY`` is used when it dissected; otherwise the 802.1X key
    frame is unpacked by hand from the EAPOL payload, because a truncated or
    vendor-padded body is common on the air and losing the whole handshake to one
    short frame would cost the Krack signal.
    """
    out: Dict[str, Any] = {}
    eapol = pkt.getlayer(EAPOL)
    if eapol is None:
        return out

    try:
        from scapy.layers.eap import EAPOL_KEY   # optional in older scapy

        key = pkt.getlayer(EAPOL_KEY)
    except Exception:  # pragma: no cover - very old scapy
        key = None

    key_info: Optional[int] = None
    key_len: Optional[int] = None
    replay: Optional[int] = None
    data_len: Optional[int] = None
    nonce: Optional[bytes] = None

    if key is not None:
        key_info = 0
        for attr, bit in (
            ("install", _KI_INSTALL), ("key_ack", _KI_ACK),
            ("has_key_mic", _KI_MIC), ("secure", _KI_SECURE),
        ):
            if _to_int(getattr(key, attr, 0)):
                key_info |= bit
        key_len = _to_int(getattr(key, "key_length", None))
        replay = _to_int(getattr(key, "key_replay_counter", None))
        data_len = _to_int(getattr(key, "key_data_length", None))
        n = getattr(key, "key_nonce", None)
        nonce = bytes(n) if n else None
    else:
        body = bytes(eapol.payload) if eapol.payload else b""
        if len(body) >= 95:
            #  0 descriptor-type, 1..2 key-info, 3..4 key-len, 5..12 replay,
            # 13..44 nonce, 45..60 IV, 61..68 RSC, 69..76 reserved,
            # 77..92 MIC, 93..94 key-data-len
            key_info = int.from_bytes(body[1:3], "big")
            key_len = int.from_bytes(body[3:5], "big")
            replay = int.from_bytes(body[5:13], "big")
            nonce = body[13:45]
            data_len = int.from_bytes(body[93:95], "big")

    if key_info is None:
        return out
    out["eapol.keydes.key_len"] = key_len
    out["eapol.keydes.replay_counter"] = replay
    out["wlan_rsna_eapol.keydes.data_len"] = data_len
    out["wlan_rsna_eapol.keydes.key_info.key_mic"] = 1 if key_info & _KI_MIC else 0
    if nonce:
        out["wlan_rsna_eapol.keydes.nonce"] = nonce.hex()
    out["wlan_rsna_eapol.keydes.msgnr"] = _eapol_msgnr(key_info, data_len)
    return out


def _ds_addresses(d11: Any) -> Dict[str, Optional[str]]:
    """tshark's ``wlan.sa/da/bssid/ta/ra`` for one MAC header.

    Which of addr1..addr4 is which depends on the DS bits, and getting it wrong
    silently corrupts ``addr.sa_is_bssid``, ``addr.ta_eq_sa`` and
    ``addr.same_bssid_as_prev``:

    ====== ======== ====== ====== ====== ======
    ToDS   FromDS   addr1  addr2  addr3  addr4
    ====== ======== ====== ====== ====== ======
    0      0        DA     SA     BSSID  -
    1      0        BSSID  SA     DA     -
    0      1        DA     BSSID  SA     -
    1      1        RA     TA     DA     SA
    ====== ======== ====== ====== ====== ======

    Control frames (type 1) carry only RA and sometimes TA, so no SA/DA/BSSID is
    reported for them -- exactly as tshark leaves those columns empty.
    """
    a1 = getattr(d11, "addr1", None)
    a2 = getattr(d11, "addr2", None)
    a3 = getattr(d11, "addr3", None)
    a4 = getattr(d11, "addr4", None)
    out: Dict[str, Optional[str]] = {
        "wlan.ra": a1, "wlan.ta": a2,
        "wlan.sa": None, "wlan.da": None, "wlan.bssid": None,
    }
    if _to_int(getattr(d11, "type", None)) == 1:
        return out                                   # control frame: RA/TA only

    try:
        fc = int(getattr(d11, "FCfield", 0) or 0)
    except Exception:
        fc = 0
    to_ds, from_ds = bool(fc & _FC_TO_DS), bool(fc & _FC_FROM_DS)
    if to_ds and from_ds:
        out.update({"wlan.da": a3, "wlan.sa": a4})   # WDS: no single BSSID
    elif to_ds:
        out.update({"wlan.bssid": a1, "wlan.sa": a2, "wlan.da": a3})
    elif from_ds:
        out.update({"wlan.da": a1, "wlan.bssid": a2, "wlan.sa": a3})
    else:
        out.update({"wlan.da": a1, "wlan.sa": a2, "wlan.bssid": a3})
    return out


def scapy_to_raw(pkt: Any, iface: str, state: FrameState) -> Dict[str, Any]:
    """One scapy packet -> the tshark-named dict ``derive_frame_features`` eats.

    Keys use tshark's own field names (see ``AWID3_SOURCE_COLUMNS``). **A field
    the frame does not carry is absent**, never zero-filled: the spec turns
    absence into NaN for a magnitude and 0 for a flag, and the model is trained on
    that convention. ``state`` supplies the previous frame's timestamp so
    ``frame.time_delta`` matches tshark's, and is advanced here.
    """
    raw: Dict[str, Any] = {}

    def put(key: str, value: Any) -> None:
        if value is not None:
            raw[key] = value

    # ---- frame ------------------------------------------------------------
    try:
        put("frame.len", len(pkt))
    except Exception:
        pass

    ts = _to_float(getattr(pkt, "time", None))
    if ts is not None:
        prev = state.prev_epoch
        put("frame.time_epoch", ts)
        # tshark reports 0 for the first frame of a capture, not "unknown".
        put("frame.time_delta", 0.0 if prev is None else max(0.0, ts - prev))
        state.prev_epoch = ts

    # ---- radiotap ---------------------------------------------------------
    rt = pkt.getlayer(RadioTap) if hasattr(pkt, "getlayer") else None
    present: set = set()
    chan_flags: Optional[int] = None
    freq: Optional[int] = None
    legacy_rate: Optional[float] = None

    if rt is not None:
        present = _present_names(rt)
        put("radiotap.length", _to_int(getattr(rt, "len", None)))
        put("radiotap.present.tsft", _present_tsft_field(pkt, present))

        if "TSFT" in present:
            put("radiotap.mactime", _to_float(getattr(rt, "mac_timestamp", None)))

        if "Rate" in present:
            legacy_rate = _to_float(getattr(rt, "Rate", None))
            put("radiotap.datarate", legacy_rate)

        if "Channel" in present:
            freq = _to_int(getattr(rt, "ChannelFrequency", None))
            put("radiotap.channel.freq", freq)
            chan_flags = _flags_int(getattr(rt, "ChannelFlags", None))
            if chan_flags is not None:
                put("radiotap.channel.flags.cck", 1 if chan_flags & _CH_CCK else 0)
                put("radiotap.channel.flags.ofdm", 1 if chan_flags & _CH_OFDM else 0)

        if "RXFlags" in present:
            put("radiotap.rxflags", _flags_int(getattr(rt, "RXFlags", None)))

        if "Flags" in present:
            flags = _flags_int(getattr(rt, "Flags", None)) or 0
            if flags & _RTF_BADFCS:
                # only ever asserted, never denied: tshark leaves the column empty
                # when the FCS was fine, and AWID3 has it empty on every row.
                put("wlan.fcs.bad_checksum", 1)

        if "dBm_AntSignal" in present:
            chains = all_dbm_antsignal(pkt)
            if not chains:
                one = _to_int(getattr(rt, "dBm_AntSignal", None))
                chains = [one] if one is not None else []
            if chains:
                put("radiotap.dbm_antsignal",
                    AWID3_MULTI_SEP.join(str(c) for c in chains))
                # wlan_radio.signal_dbm is the LAST dBm_AntSignal in the header,
                # not the first, strongest or weakest. Verified against tshark
                # 4.x on data/samples/deauth_raw_decrypted.pcapng: chains
                # [-37,-37,-41] -> -41, [-34,-35,-34] -> -34. Taking the first
                # chain disagreed with tshark on 97.6% of frames.
                put("wlan_radio.signal_dbm", chains[-1])

    # ---- 802.11 MAC header ------------------------------------------------
    d11 = pkt.getlayer(Dot11) if hasattr(pkt, "getlayer") else None
    ftype: Optional[int] = None
    if d11 is not None:
        ftype = _to_int(getattr(d11, "type", None))
        put("wlan.fc.type", ftype)
        put("wlan.fc.subtype", _to_int(getattr(d11, "subtype", None)))
        try:
            fc = int(getattr(d11, "FCfield", 0) or 0)
        except Exception:
            fc = 0
        put("wlan.fc.ds", (1 if fc & _FC_TO_DS else 0) | (2 if fc & _FC_FROM_DS else 0))
        put("wlan.fc.frag", 1 if fc & _FC_MORE_FRAG else 0)
        put("wlan.fc.retry", 1 if fc & _FC_RETRY else 0)
        put("wlan.fc.pwrmgt", 1 if fc & _FC_PWRMGT else 0)
        put("wlan.fc.moredata", 1 if fc & _FC_MOREDATA else 0)
        put("wlan.fc.protected", 1 if fc & _FC_PROTECTED else 0)
        put("wlan.fc.order", 1 if fc & _FC_ORDER else 0)
        put("wlan.duration", _dot11_duration(d11))

        sc = _to_int(getattr(d11, "SC", None))
        if sc is not None:
            put("wlan.seq", sc >> 4)          # low 4 bits are the fragment number

        for key, value in _ds_addresses(d11).items():
            put(key, value)

    # ---- management body (unencrypted, so always readable) ----------------
    if d11 is not None and ftype == 0:
        body = d11.payload

        if isinstance(body, (Dot11Deauth, Dot11Disas)):
            # The single most valuable v2 feature: carried by ~100% of
            # Deauth/Disas/Kr00k attack frames and 0.3% of Normal.
            put("wlan.fixed.reason_code", _to_int(getattr(body, "reason", None)))

        put("wlan.fixed.beacon", _to_float(getattr(body, "beacon_interval", None)))

        cap = getattr(body, "cap", None)
        if cap is not None:
            try:
                ess = 1 if getattr(cap, "ESS") else 0
                ibss = 1 if getattr(cap, "IBSS") else 0
            except AttributeError:
                cap_i = _to_int(cap) or 0
                ess = 1 if cap_i & _CAP_ESS else 0
                ibss = 1 if cap_i & _CAP_IBSS else 0
            put("wlan.fixed.capabilities.ess", ess)
            put("wlan.fixed.capabilities.ibss", ibss)

        ies = _walk_ies(pkt)
        if ies:
            put("wlan.tag.length",
                AWID3_MULTI_SEP.join(str(declared) for _id, _b, declared in ies))
        for eid, ie_body, _declared in ies:
            if eid == _IE_SSID and "wlan.ssid" not in raw:
                # latin-1 so len(str) == len(bytes), matching AWID3's ISO-8859-1
                # CSV encoding; the string itself never reaches the model.
                put("wlan.ssid", ie_body.decode("latin-1"))
            elif eid == _IE_COUNTRY and len(ie_body) >= 2:
                put("wlan.country_info.code", ie_body[:2].decode("latin-1"))
            elif eid == _IE_RSN:
                rsn = _parse_rsn_ie(ie_body)
                put("wlan.rsn.capabilities.mfpc", rsn.get("mfpc"))
                put("wlan.rsn.ie.pmkid", rsn.get("pmkid"))

    # ---- EAPOL (unencrypted; the Krack evidence) --------------------------
    eapol = pkt.getlayer(EAPOL) if hasattr(pkt, "getlayer") else None
    if eapol is not None:
        put("eapol.type", _to_int(getattr(eapol, "type", None)))
        put("eapol.len", _to_float(getattr(eapol, "len", None)))
        for key, value in _eapol_key_body(pkt).items():
            put(key, value)

    # ---- wlan_radio.* (wireshark's synthesised radio summary) -------------
    rate = legacy_rate
    if rate is None and rt is not None:
        if "MCS" in present:
            rate = _ht_rate(rt)
        elif "VHT" in present:
            rate = _vht_rate(rt)
    put("wlan_radio.data_rate", rate)
    put("wlan_radio.phy", _derive_phy(present, chan_flags, freq))

    return raw


def packet_to_features_v2(
    pkt: Any, iface: str, state: FrameState
) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """``(47-feature vector, raw_min for the DB)`` for one scapy packet.

    The whole point of v2: this function does no feature maths of its own. It
    normalises the packet and hands it to the same ``derive_frame_features()``
    the training pipeline calls, so parity is structural rather than reviewed.
    """
    raw = scapy_to_raw(pkt, iface, state)
    features = derive_frame_features(raw, state)

    raw_min: Dict[str, Any] = {
        "iface": iface,
        "sa": raw.get("wlan.sa"),
        "da": raw.get("wlan.da"),
        "bssid": raw.get("wlan.bssid"),
        "len": raw.get("frame.len"),
        "type": raw.get("wlan.fc.type"),
        "subtype": raw.get("wlan.fc.subtype"),
        "rate": raw.get("radiotap.datarate"),
        "sig": raw.get("wlan_radio.signal_dbm"),
        "ssid": _ssid_from_beacon_or_probe(pkt),
    }
    return features, raw_min
