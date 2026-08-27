"""Tests for ``backend.detector.attack_sim`` -- crafted frames and the sim corpus.

Two independent guarantees:

* every crafted class builds a frame that yields a *complete* feature vector
  through the real ``packet_to_features_v2`` extractor (the self-test's premise);
* ``resolve_classes`` maps keys / names / 'all' / unknown correctly, and the
  held-out AWID3 corpus loads, groups by class and resolves the same way.
"""
from __future__ import annotations

import re

import numpy as np
import pytest

from backend.detector.attack_sim import (
    ATTACK_SPECS,
    SIM_CLASSES,
    build_frames,
    load_sim_corpus,
    resolve_classes,
    sim_mac,
)
from backend.detector.feature_spec import ATTACK_CLASSES, CLASSES, FEATURE_ORDER
from backend.detector.features import FEATURE_ORDER_V2, FrameState, packet_to_features_v2


# ---------------------------------------------------------------------------
# crafted frames
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cls", list(SIM_CLASSES))
def test_every_class_yields_a_complete_feature_vector(cls: str) -> None:
    """Each crafted class -> a frame -> all 46 v2 features present in the row."""
    spec = ATTACK_SPECS[cls]
    pkt = spec.build()
    state = FrameState()
    row, raw = packet_to_features_v2(pkt, "test0", state)

    missing = [k for k in FEATURE_ORDER_V2 if k not in row]
    assert not missing, f"{cls}: missing features {missing}"
    assert len(FEATURE_ORDER_V2) == 46
    # Vectorisable: every value coerces to float (NaN allowed = 'field absent').
    vec = np.fromiter((float(row[k]) for k in FEATURE_ORDER_V2), dtype=np.float32)
    assert vec.shape == (46,)
    assert raw["iface"] == "test0"


def test_build_frames_interleaves_each_class() -> None:
    classes = ["Deauth", "Krack"]
    frames = build_frames(classes, 3)
    assert len(frames) == len(classes) * 3


# ---------------------------------------------------------------------------
# resolve_classes (crafted vocabulary)
# ---------------------------------------------------------------------------
def test_resolve_classes_accepts_keys_names_and_all() -> None:
    assert resolve_classes("all") == list(SIM_CLASSES)
    assert resolve_classes(["deauth"]) == ["Deauth"]
    assert resolve_classes(["Deauth"]) == ["Deauth"]
    assert resolve_classes(["reassoc", "(Re)Assoc"]) == ["(Re)Assoc"]  # de-duped
    assert resolve_classes(["evil_twin", "eviltwin"]) == ["Evil_Twin"]


def test_resolve_classes_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        resolve_classes(["not_an_attack"])
    with pytest.raises(ValueError):
        resolve_classes(None)


# ---------------------------------------------------------------------------
# held-out AWID3 corpus
# ---------------------------------------------------------------------------
def test_corpus_loads_and_groups_by_class() -> None:
    corpus = load_sim_corpus()
    # Corpus covers all eight attack classes (wider than the crafted six).
    assert set(corpus.classes) == set(ATTACK_CLASSES)
    # feature_spec order is preserved, not the parquet's row order.
    assert corpus.classes == [c for c in CLASSES if c in corpus.rows]
    for cls, arr in corpus.rows.items():
        assert arr.ndim == 2 and arr.shape[1] == len(FEATURE_ORDER)
        assert corpus.labels[cls].shape[0] == arr.shape[0]


def test_corpus_resolve_handles_all_and_aliases() -> None:
    corpus = load_sim_corpus()
    assert corpus.resolve("all") == list(corpus.classes)
    assert corpus.resolve(["kr00k"]) == ["Kr00k"]      # crafted vocab can't; corpus can
    assert corpus.resolve(["ssdp"]) == ["SSDP"]
    assert corpus.resolve(["Deauth", "deauth"]) == ["Deauth"]
    with pytest.raises(ValueError):
        corpus.resolve(["nope"])


def test_corpus_is_cached() -> None:
    assert load_sim_corpus() is load_sim_corpus()


def test_sim_mac_is_deterministic_and_locally_administered() -> None:
    a = sim_mac("Deauth", "sa")
    assert a == sim_mac("Deauth", "sa")             # deterministic
    assert sim_mac("Deauth", "sa") != sim_mac("Deauth", "bssid")
    assert re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", a)
    first_octet = int(a.split(":")[0], 16)
    assert first_octet & 0x02, "locally-administered bit must be set"
    assert not (first_octet & 0x01), "must not be a multicast/group address"
