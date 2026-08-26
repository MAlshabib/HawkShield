"""
HawkShield v2 feature contract - the single source of truth for both training and inference.

Why this module exists
----------------------
The v1 models failed in a specific, avoidable way: they were trained on tshark
fields that the live scapy extractor could not produce, so 16 of 29 features were
always NULL in the field and got mean-imputed to training medians. The model then
keyed on those imputed constants. Separately, ``frame.time_relative`` carried 42%
of stage-1 split gain while encoding nothing but *which capture session a row came
from*.

Both failures share one root cause: training features and inference features were
defined in different places by different code.

Here they are defined once. Both paths converge on :func:`derive_frame_features`,
which consumes a normalised "tshark-like" dict:

    AWID3 CSV row  --\\
                      >--> normalise --> derive_frame_features() --> model input
    live scapy pkt --/

If a feature cannot be produced live, it does not belong in this file.

Deployment assumption
---------------------
The Pi captures in **monitor mode without decryption keys**. Available at
inference: radiotap headers, the 802.11 MAC header, and the bodies of unencrypted
management frames (beacon, probe, auth, assoc, deauth, disassoc) plus EAPOL
handshake frames. NOT available: any IP/TCP/UDP/TLS field, and the payload of
protected data frames. Nothing in FEATURE_ORDER may depend on those.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional

__all__ = [
    "CLASSES",
    "ATTACK_CLASSES",
    "FEATURE_ORDER",
    "EXCLUDED_COLUMNS",
    "AWID3_SOURCE_COLUMNS",
    "AWID3_CLASS_MAP",
    "WINDOW_SIZE",
    "WINDOW_STRIDE",
    "derive_frame_features",
    "SPEC_VERSION",
]

SPEC_VERSION = "2.1.0"

# --------------------------------------------------------------------------- #
# Classes                                                                      #
# --------------------------------------------------------------------------- #
# Only attacks that leave evidence in the clear on a monitor-mode capture.
#
# Deliberately EXCLUDED from AWID3: SSH, Botnet, Malware, SQL_Injection,
# Website_spoofing. Those are application-layer attacks whose AWID3 labels are
# separable only via decrypted TCP/TLS payload fields. On the Pi those columns are
# always NULL, so including them would rebuild exactly the train/inference gap
# that broke v1. They are a documented non-goal, not an oversight.
ATTACK_CLASSES: List[str] = [
    "Deauth",       # deauthentication flood       - unencrypted mgmt + reason code
    "Disas",        # disassociation flood         - unencrypted mgmt + reason code
    "(Re)Assoc",    # (re)association flood        - unencrypted mgmt
    "RogueAP",      # rogue access point           - beacon/SSID/BSSID inconsistency
    "Krack",        # key reinstallation           - EAPOL msg 3 replay (unencrypted)
    "Kr00k",        # all-zero TK after disassoc   - data-frame pattern
    "Evil_Twin",    # SSID impersonation           - beacon/capability/radio mismatch
    "SSDP",         # SSDP amplification           - volumetric data-frame pattern
]
CLASSES: List[str] = ["Normal"] + ATTACK_CLASSES

# AWID3 folder label -> our class name.
AWID3_CLASS_MAP: Dict[str, str] = {
    "Normal": "Normal",
    "Deauth": "Deauth",
    "Disas": "Disas",
    "(Re)Assoc": "(Re)Assoc",
    "RogueAP": "RogueAP",
    "Krack": "Krack",
    "Kr00k": "Kr00k",
    "Evil_Twin": "Evil_Twin",
    "SSDP": "SSDP",
}

# --------------------------------------------------------------------------- #
# Explicitly excluded columns, with the reason. Enforced by a training test.    #
# --------------------------------------------------------------------------- #
EXCLUDED_COLUMNS: Dict[str, str] = {
    # --- session / capture identity: the v1 leakage ---
    "frame.number": "monotonic capture index; identifies the capture, not the traffic",
    "frame.time": "absolute wall-clock of the capture session",
    "frame.time_epoch": "absolute wall-clock of the capture session",
    "frame.time_relative": "seconds since capture start; 42% of v1 stage-1 gain, pure leakage",
    "radiotap.mactime": "raw radio TSF counter; device- and session-specific",
    "wlan_radio.start_tsf": "raw TSF counter",
    "wlan_radio.end_tsf": "raw TSF counter",
    "wlan_radio.timestamp": "raw TSF counter",
    "wlan.fixed.timestamp": "AP TSF timestamp; encodes AP uptime, not behaviour",
    # --- identifiers: memorising the testbed's MACs is not detection ---
    "wlan.sa": "raw MAC; model would memorise the attacker's address",
    "wlan.da": "raw MAC",
    "wlan.ta": "raw MAC",
    "wlan.ra": "raw MAC",
    "wlan.bssid": "raw MAC",
    "wlan.ssid": "raw SSID string; memorises the testbed network name",
    # --- unavailable at inference (encrypted or post-decryption only) ---
    "ip.src": "requires decryption", "ip.dst": "requires decryption",
    "tcp.srcport": "requires decryption", "tcp.dstport": "requires decryption",
    "udp.srcport": "requires decryption", "udp.dstport": "requires decryption",
    "tcp.payload": "requires decryption", "udp.payload": "requires decryption",
    "data.data": "requires decryption",
}

# --------------------------------------------------------------------------- #
# Raw AWID3 columns the preprocessing pass must read (input to derivation).     #
# --------------------------------------------------------------------------- #
AWID3_SOURCE_COLUMNS: List[str] = [
    "frame.len", "frame.time_delta", "frame.time_epoch",
    "radiotap.length", "radiotap.present.tsft", "radiotap.mactime", "radiotap.rxflags",
    "radiotap.channel.freq", "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm",
    "radiotap.datarate", "radiotap.dbm_antsignal",
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.ds", "wlan.fc.frag", "wlan.fc.order",
    "wlan.fc.moredata", "wlan.fc.protected", "wlan.fc.pwrmgt", "wlan.fc.retry",
    "wlan.duration", "wlan.seq", "wlan.fcs.bad_checksum",
    "wlan.fixed.reason_code", "wlan.fixed.beacon",
    "wlan.fixed.capabilities.ess", "wlan.fixed.capabilities.ibss",
    "wlan.ssid", "wlan.tag.length", "wlan.country_info.code",
    "wlan.rsn.capabilities.mfpc", "wlan.rsn.ie.pmkid",
    "wlan_rsna_eapol.keydes.msgnr", "wlan_rsna_eapol.keydes.data_len",
    "wlan_rsna_eapol.keydes.key_info.key_mic", "wlan_rsna_eapol.keydes.nonce",
    "eapol.type", "eapol.len", "eapol.keydes.key_len", "eapol.keydes.replay_counter",
    "wlan_radio.signal_dbm", "wlan_radio.data_rate", "wlan_radio.phy",
    # read for grouping/derivation only - never fed to the model
    "wlan.sa", "wlan.da", "wlan.bssid", "wlan.ta",
    "Label",
]

# --------------------------------------------------------------------------- #
# The model's per-frame feature vector.                                        #
# --------------------------------------------------------------------------- #
# 46 features. Every one is derivable from a monitor-mode frame with no keys.
#
# `frame.fcs_bad` was removed in 2.1.0: wlan.fcs.bad_checksum is empty on 100% of
# AWID3 rows, so it is constant in training while varying in the field -- a feature
# the model has never seen move is worse than no feature at all.
FEATURE_ORDER: List[str] = [
    # -- radio / PHY (7) --
    "radio.freq_mhz", "radio.is_5ghz", "radio.cck", "radio.ofdm",
    "radio.datarate", "radio.signal_dbm", "radio.rt_len",
    # -- radio presence flags: injected frames often lack fields a real NIC sets (3) --
    "radio.has_tsft", "radio.has_rate", "radio.has_signal",
    # -- frame basics (3) --
    "frame.len", "frame.dt", "frame.dt_log",
    # -- 802.11 frame control (11) --
    "fc.type", "fc.subtype", "fc.ds", "fc.retry", "fc.protected", "fc.pwrmgt",
    "fc.moredata", "fc.frag", "fc.order", "wlan.duration", "wlan.seq_delta",
    # -- address semantics, no raw MACs (6) --
    "addr.da_broadcast", "addr.da_multicast", "addr.sa_is_bssid",
    "addr.sa_local_admin", "addr.ta_eq_sa", "addr.same_bssid_as_prev",
    # -- management-frame body, unencrypted (7) --
    "mgmt.has_reason", "mgmt.reason_code", "mgmt.beacon_interval",
    "mgmt.cap_ess", "mgmt.cap_ibss", "mgmt.ssid_len", "mgmt.tag_len",
    # -- security / RSN (3) --
    "rsn.mfpc", "rsn.has_pmkid", "rsn.country_present",
    # -- EAPOL handshake, unencrypted - the Krack signal (6) --
    "eapol.present", "eapol.type", "eapol.len", "eapol.msgnr",
    "eapol.key_len", "eapol.replay_counter",
]

assert len(FEATURE_ORDER) == 46, f"expected 46 features, got {len(FEATURE_ORDER)}"

# Sliding window over consecutive frames sharing a BSSID. Attacks here are
# *rate* phenomena: a single deauth frame is legitimate, sixty per second is not.
# 64 frames at ~1k frames/s is a ~64 ms decision window.
WINDOW_SIZE = 64
WINDOW_STRIDE = 16


# --------------------------------------------------------------------------- #
# Derivation                                                                   #
# --------------------------------------------------------------------------- #
_BLANK = {"?", "nan", "NaN", "-", "None"}
_NUM_RE = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")


def _f_all(v: Any) -> List[float]:
    """All numeric values in a cell.

    tshark emits one column per *field*, and a frame can carry a field several
    times (four tag lengths, three antenna chains). AWID3 joins those repeats
    with ``-``, which is ambiguous against negative numbers:

        wlan.tag.length          '0-8-26-12'    -> [0, 8, 26, 12]
        radiotap.dbm_antsignal   '-29-32-29'    -> [-29, -32, -29]
        radiotap.present.tsft    '1-0-0'        -> [1, 0, 0]

    A naive split on ``-`` turns the first into negatives; a naive regex turns
    the second into nonsense. The leading sign disambiguates, so branch on it.
    Getting this wrong silently NaNs every multi-tag management frame, which is
    most of them.
    """
    if v is None:
        return []
    if isinstance(v, (int, float)):
        return [] if (isinstance(v, float) and math.isnan(v)) else [float(v)]
    s = str(v).strip()
    if not s or s in _BLANK:
        return []
    try:                                   # single value, incl. sci notation
        return [float(s)]
    except ValueError:
        pass
    if s.lower().startswith("0x"):
        try:
            return [float(int(s, 16))]
        except ValueError:
            return []
    if "," in s:
        parts = [p.strip() for p in s.split(",") if p.strip()]
    elif s.startswith("-"):
        parts = _NUM_RE.findall(s)         # negative series
    else:
        parts = [p for p in s.split("-") if p]
    out: List[float] = []
    for part in parts:
        try:
            out.append(float(part))
        except ValueError:
            continue
    return out


def _f(v: Any) -> Optional[float]:
    """First numeric value in a cell, or None."""
    vals = _f_all(v)
    return vals[0] if vals else None


def _f_sum(v: Any) -> Optional[float]:
    """Sum of every numeric value in a cell (repeated fields)."""
    vals = _f_all(v)
    return float(sum(vals)) if vals else None


def _i(v: Any) -> Optional[int]:
    f = _f(v)
    return None if f is None else int(f)


def _present(v: Any) -> int:
    if v is None:
        return 0
    s = str(v).strip()
    return 0 if (not s or s in {"?", "nan", "NaN", "-"}) else 1


def _mac_is_broadcast(mac: Optional[str]) -> int:
    return 1 if mac and mac.strip().lower() == "ff:ff:ff:ff:ff:ff" else 0


def _mac_is_multicast(mac: Optional[str]) -> int:
    """Group bit = low bit of the first octet."""
    if not mac:
        return 0
    try:
        return int(int(mac.split(":")[0], 16) & 0x01)
    except (ValueError, IndexError):
        return 0


def _mac_is_local_admin(mac: Optional[str]) -> int:
    """Locally-administered bit - set by most spoofing/injection tools."""
    if not mac:
        return 0
    try:
        return int((int(mac.split(":")[0], 16) >> 1) & 0x01)
    except (ValueError, IndexError):
        return 0


def _norm_mac(mac: Any) -> Optional[str]:
    if mac is None:
        return None
    s = str(mac).strip().lower()
    if not s or s in {"?", "nan", "-"}:
        return None
    return s.split(",", 1)[0].strip()


class FrameState:
    """Per-stream carry-over needed for delta features.

    One instance per capture during training; one long-lived instance in the live
    detector. Keeps only the previous frame's sequence number and BSSID, so it is
    O(1) and cannot leak absolute session time into the features.
    """

    __slots__ = ("prev_seq", "prev_bssid", "prev_epoch")

    def __init__(self) -> None:
        self.prev_seq: Optional[int] = None
        self.prev_bssid: Optional[str] = None
        self.prev_epoch: Optional[float] = None

    def reset(self) -> None:
        self.prev_seq = None
        self.prev_bssid = None
        self.prev_epoch = None


def derive_frame_features(raw: Dict[str, Any], state: FrameState) -> Dict[str, float]:
    """Map one normalised tshark-like frame dict to the 46-feature vector.

    ``raw`` uses AWID3/tshark column names. Missing keys are fine - anything the
    frame does not carry becomes 0.0 for a flag or NaN for a magnitude, and the
    model is trained with those same conventions. **Never invent a value.**

    ``state`` supplies the two delta features and is mutated on the way out.
    """
    out: Dict[str, float] = {}
    nan = float("nan")

    # -- radio -----------------------------------------------------------------
    freq = _f(raw.get("radiotap.channel.freq"))
    out["radio.freq_mhz"] = freq if freq is not None else nan
    out["radio.is_5ghz"] = 1.0 if (freq or 0) >= 5000 else 0.0
    out["radio.cck"] = float(_i(raw.get("radiotap.channel.flags.cck")) or 0)
    out["radio.ofdm"] = float(_i(raw.get("radiotap.channel.flags.ofdm")) or 0)
    rate = _f(raw.get("radiotap.datarate"))
    if rate is None:
        rate = _f(raw.get("wlan_radio.data_rate"))
    out["radio.datarate"] = rate if rate is not None else nan
    sig = _f(raw.get("wlan_radio.signal_dbm"))
    if sig is None:
        sig = _f(raw.get("radiotap.dbm_antsignal"))
    out["radio.signal_dbm"] = sig if sig is not None else nan
    rt_len = _f(raw.get("radiotap.length"))
    out["radio.rt_len"] = rt_len if rt_len is not None else nan

    # Presence, not value. A frame injected by a different card frequently lacks
    # TSF/rate that the AP's own NIC always stamps. Hardware-dependent, so it is
    # kept as a flag and its transferability is checked by grouped validation.
    # The value of radiotap.present.tsft is itself the flag. AWID3 fills this
    # column on 100% of rows (as "0-0-0" or "1-0-0"), so testing key presence
    # made the feature a constant 1.0 and therefore useless.
    tsft_flag = _f(raw.get("radiotap.present.tsft"))
    out["radio.has_tsft"] = float(
        1 if (tsft_flag == 1 or _present(raw.get("radiotap.mactime"))) else 0
    )
    out["radio.has_rate"] = float(_present(raw.get("radiotap.datarate")))
    out["radio.has_signal"] = float(
        _present(raw.get("wlan_radio.signal_dbm")) or _present(raw.get("radiotap.dbm_antsignal"))
    )

    # -- frame basics ----------------------------------------------------------
    flen = _f(raw.get("frame.len"))
    out["frame.len"] = flen if flen is not None else nan

    dt = _f(raw.get("frame.time_delta"))
    if dt is None:
        epoch = _f(raw.get("frame.time_epoch"))
        if epoch is not None and state.prev_epoch is not None:
            dt = max(0.0, epoch - state.prev_epoch)
        if epoch is not None:
            state.prev_epoch = epoch
    out["frame.dt"] = dt if dt is not None else nan
    # log-scaled: inter-frame gaps span microseconds to seconds
    out["frame.dt_log"] = math.log1p(max(dt, 0.0)) if dt is not None else nan

    # -- frame control ---------------------------------------------------------
    out["fc.type"] = float(_i(raw.get("wlan.fc.type")) if _i(raw.get("wlan.fc.type")) is not None else -1)
    out["fc.subtype"] = float(_i(raw.get("wlan.fc.subtype")) if _i(raw.get("wlan.fc.subtype")) is not None else -1)
    out["fc.ds"] = float(_i(raw.get("wlan.fc.ds")) or 0)
    out["fc.retry"] = float(_i(raw.get("wlan.fc.retry")) or 0)
    out["fc.protected"] = float(_i(raw.get("wlan.fc.protected")) or 0)
    out["fc.pwrmgt"] = float(_i(raw.get("wlan.fc.pwrmgt")) or 0)
    out["fc.moredata"] = float(_i(raw.get("wlan.fc.moredata")) or 0)
    out["fc.frag"] = float(_i(raw.get("wlan.fc.frag")) or 0)
    out["fc.order"] = float(_i(raw.get("wlan.fc.order")) or 0)
    dur = _f(raw.get("wlan.duration"))
    out["wlan.duration"] = dur if dur is not None else nan

    seq = _i(raw.get("wlan.seq"))
    if seq is not None and state.prev_seq is not None:
        d = (seq - state.prev_seq) % 4096      # 12-bit sequence counter wraps
        out["wlan.seq_delta"] = float(d if d < 2048 else d - 4096)
    else:
        out["wlan.seq_delta"] = nan
    if seq is not None:
        state.prev_seq = seq

    # -- address semantics -----------------------------------------------------
    sa = _norm_mac(raw.get("wlan.sa"))
    da = _norm_mac(raw.get("wlan.da"))
    ta = _norm_mac(raw.get("wlan.ta"))
    bssid = _norm_mac(raw.get("wlan.bssid"))
    out["addr.da_broadcast"] = float(_mac_is_broadcast(da))
    out["addr.da_multicast"] = float(_mac_is_multicast(da))
    out["addr.sa_is_bssid"] = float(1 if (sa and bssid and sa == bssid) else 0)
    out["addr.sa_local_admin"] = float(_mac_is_local_admin(sa))
    out["addr.ta_eq_sa"] = float(1 if (ta and sa and ta == sa) else 0)
    out["addr.same_bssid_as_prev"] = float(
        1 if (bssid and state.prev_bssid and bssid == state.prev_bssid) else 0
    )
    if bssid:
        state.prev_bssid = bssid

    # -- management body (unencrypted) ----------------------------------------
    reason = _i(raw.get("wlan.fixed.reason_code"))
    out["mgmt.has_reason"] = float(1 if reason is not None else 0)
    out["mgmt.reason_code"] = float(reason) if reason is not None else nan
    beacon = _f(raw.get("wlan.fixed.beacon"))
    out["mgmt.beacon_interval"] = beacon if beacon is not None else nan
    out["mgmt.cap_ess"] = float(_i(raw.get("wlan.fixed.capabilities.ess")) or 0)
    out["mgmt.cap_ibss"] = float(_i(raw.get("wlan.fixed.capabilities.ibss")) or 0)
    ssid = raw.get("wlan.ssid")
    # length only - never the string itself
    out["mgmt.ssid_len"] = float(len(str(ssid).strip())) if _present(ssid) else nan
    # Sum, not first: a beacon carries many tags and the total body size is the
    # signal. With the old single-value parser this was NaN on every multi-tag
    # frame -- i.e. on essentially every management frame.
    tag_len = _f_sum(raw.get("wlan.tag.length"))
    out["mgmt.tag_len"] = tag_len if tag_len is not None else nan

    # -- RSN -------------------------------------------------------------------
    out["rsn.mfpc"] = float(_i(raw.get("wlan.rsn.capabilities.mfpc")) or 0)
    out["rsn.has_pmkid"] = float(_present(raw.get("wlan.rsn.ie.pmkid")))
    out["rsn.country_present"] = float(_present(raw.get("wlan.country_info.code")))

    # -- EAPOL (unencrypted; carries the Krack evidence) -----------------------
    eapol_type = _i(raw.get("eapol.type"))
    out["eapol.present"] = float(1 if (eapol_type is not None or _present(raw.get("eapol.len"))) else 0)
    out["eapol.type"] = float(eapol_type) if eapol_type is not None else nan
    elen = _f(raw.get("eapol.len"))
    out["eapol.len"] = elen if elen is not None else nan
    msgnr = _i(raw.get("wlan_rsna_eapol.keydes.msgnr"))
    out["eapol.msgnr"] = float(msgnr) if msgnr is not None else nan
    klen = _f(raw.get("eapol.keydes.key_len"))
    out["eapol.key_len"] = klen if klen is not None else nan
    replay = _f(raw.get("eapol.keydes.replay_counter"))
    out["eapol.replay_counter"] = replay if replay is not None else nan

    return out


def feature_vector(raw: Dict[str, Any], state: FrameState) -> List[float]:
    """:func:`derive_frame_features` flattened into FEATURE_ORDER order."""
    d = derive_frame_features(raw, state)
    return [d[k] for k in FEATURE_ORDER]
