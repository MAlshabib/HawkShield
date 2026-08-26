"""Smoke test: real bundles + real capture -> a well-formed Verdict stream.

Deliberately capped so the whole module runs in a few seconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.detector.features import ExtractState, packet_to_row  # noqa: E402
from backend.detector.pipeline import (  # noqa: E402
    Stage1,
    Stage2,
    TwoStagePipeline,
    Verdict,
)

SAMPLE = REPO_ROOT / "data" / "samples" / "deauth_raw_decrypted.pcapng"
MODEL_DIR = REPO_ROOT / "models"
N_PACKETS = 1500

EXPECTED_CLASSES = ["SSDP", "Evil_Twin", "Krack", "Deauth", "(Re)Assoc", "RogueAP"]


@pytest.fixture(scope="module")
def pipe() -> TwoStagePipeline:
    for name in ("stage1_binary_bundle.joblib", "stage2_multiclass_bundle.joblib"):
        if not (MODEL_DIR / name).is_file():
            pytest.skip(f"model bundle missing: {name}")
    return TwoStagePipeline(model_dir=MODEL_DIR)


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
            row, _raw = packet_to_row(pkt, "wlan1", state)
            out.append(row)
            if len(out) >= N_PACKETS:
                break
    return out


@pytest.fixture(scope="module")
def verdicts(pipe, rows):
    return [pipe.predict(r) for r in rows]


# ---------------------------------------------------------------------------
def test_bundles_load_with_the_documented_shapes(pipe):
    assert isinstance(pipe.stage1, Stage1)
    assert isinstance(pipe.stage2, Stage2)
    assert len(pipe.stage1.feature_order) == 31
    assert len(pipe.stage1.imputer_features) == 29
    assert pipe.stage1.feature_order == pipe.stage2.feature_order, "one extractor feeds both"
    assert pipe.stage1.best_iteration == 245
    assert pipe.stage2.best_iteration == 116
    assert pipe.classes == EXPECTED_CLASSES


def test_thresholds_come_from_settings(pipe):
    assert 0.0 <= pipe.thr1 <= 1.0
    assert 0.0 <= pipe.thr2 <= 1.0


def test_transform_produces_the_31_column_model_space(pipe, rows):
    X = pipe.stage1._prepare_X(rows[0])
    assert X is not None
    assert list(X.columns) == pipe.stage1.feature_order
    assert X.shape == (1, 31)
    assert not X.isna().any().any(), "imputer left a NaN in the model space"
    # the two cat_cols are not carried by a frame and must be filled with 0.0
    assert X["wlan.country_info.fnm"].iloc[0] == 0.0
    assert X["wlan.country_info.code"].iloc[0] == 0.0


def test_no_sklearn_feature_name_warnings(pipe, rows, recwarn):
    pipe.stage1.predict_proba(rows[0])
    pipe.stage2.predict(rows[0])
    bad = [w for w in recwarn if "feature names" in str(w.message)]
    assert not bad, [str(w.message) for w in bad]


def test_verdict_shape(pipe, verdicts):
    assert len(verdicts) == N_PACKETS
    for v in verdicts:
        assert isinstance(v, Verdict)
        assert isinstance(v.is_attack, bool)
        assert v.stage in (0, 1, 2)
        assert v.p1 is not None, "stage-1 must score every frame of this capture"
        assert 0.0 <= v.p1 <= 1.0
        if v.stage == 2:
            assert v.label in EXPECTED_CLASSES
            assert 0.0 <= v.p2 <= 1.0
        else:
            assert v.p2 is None
        if v.is_attack:
            assert v.stage == 2 and v.label is not None
            assert v.p1 >= pipe.thr1 and v.p2 >= pipe.thr2


def test_decision_rule_is_applied(pipe, verdicts):
    for v in verdicts:
        if v.p1 is not None and v.p1 < pipe.thr1:
            assert not v.is_attack and v.stage == 1 and v.label is None
        if v.stage == 2 and v.p2 is not None and v.p2 < pipe.thr2:
            assert not v.is_attack


def test_label_distribution_is_plausible(pipe, verdicts):
    labels = [v.label for v in verdicts if v.stage == 2 and v.label]
    assert set(labels) <= set(EXPECTED_CLASSES)
    # this capture is 97% deauthentication frames, so stage 1 must not be silent
    scored = [v for v in verdicts if v.p1 is not None]
    assert len(scored) == len(verdicts)
    assert max(v.p1 for v in scored) > 0.0


def test_batch_scoring_matches_per_packet(pipe, rows, verdicts):
    """The replay tool batches; the maths must be identical to the live per-packet path."""
    import numpy as np

    sample = rows[:256]
    batch_p1 = pipe.stage1.predict_proba_batch(sample)
    assert batch_p1 is not None and len(batch_p1) == len(sample)
    single_p1 = np.array([v.p1 for v in verdicts[:256]], dtype=float)
    np.testing.assert_allclose(batch_p1, single_p1, rtol=0, atol=1e-12)


def test_unscorable_row_returns_stage_zero(pipe):
    """A row of pure garbage must not raise - it must come back is_attack=False."""
    v = pipe.predict({})
    assert isinstance(v, Verdict)
    assert v.is_attack is False
