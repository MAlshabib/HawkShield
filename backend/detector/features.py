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

from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap

logger = logging.getLogger(__name__)

__all__ = ["ExtractState", "packet_to_row", "FEATURE_ORDER", "freq_to_channel"]


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


def all_dbm_antsignal(pkt: Any) -> List[int]:
    """Every ``dBm_AntSignal`` value in the radiotap header, in order.

    Scapy 2.6.1 decodes only the first namespace, leaving the per-antenna repeats
    in ``notdecoded``. Multi-antenna adapters (the Pi's, and the ones the training
    captures were taken with) emit one value per chain, so we walk the raw
    presence masks ourselves. Returns ``[]`` when nothing can be parsed.
    """
    try:
        raw = bytes(pkt.original if getattr(pkt, "original", None) else bytes(pkt))
        if len(raw) < 8:
            return []
        _ver, _pad, hdr_len = struct.unpack_from("<BBH", raw, 0)
        if hdr_len < 8 or hdr_len > len(raw):
            return []

        masks: List[int] = []
        off = 4
        while True:
            if off + 4 > hdr_len:
                return []
            (m,) = struct.unpack_from("<I", raw, off)
            masks.append(m)
            off += 4
            if not (m & (1 << 31)):
                break

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
