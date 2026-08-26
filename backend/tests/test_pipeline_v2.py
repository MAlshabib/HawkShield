"""v2 pipeline integration: artefact validation, streaming, fallback, API keys.

These tests never touch ``models/hawkshield_v2.onnx``.  They build their own
throwaway ONNX graph so they pin the *plumbing* -- the load-time guard, the ring
buffer's arithmetic, the v1 fallback, the class list reaching the API -- and stay
green whatever the real model happens to be at the time.

The fixture graph is deliberately not a 1x1 convolution.  A model with a
receptive field of 1 makes the streaming-equivalence test pass for free and prove
nothing; this one has a genuine 5-frame causal receptive field, so a ring buffer
that dropped or mis-ordered history would fail it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.app.config import ATTACK_CLASSES, v2_meta_problems  # noqa: E402
from backend.detector.feature_spec import CLASSES, FEATURE_ORDER, SPEC_VERSION  # noqa: E402
from backend.detector.pipeline import (  # noqa: E402
    SpecMismatchError,
    TwoStagePipeline,
    V2Pipeline,
    Verdict,
    build_pipeline,
    load_v2_meta,
)

onnx = pytest.importorskip("onnx", reason="onnx is needed to build the test graph")
pytest.importorskip("onnxruntime", reason="onnxruntime is needed to run the test graph")

N_FEATURES = len(FEATURE_ORDER)
N_CLASSES = len(CLASSES)

# Causal receptive field of the fixture graph: kernel 3 at dilation 2.
FIXTURE_KERNEL = 3
FIXTURE_DILATION = 2
FIXTURE_RF = 1 + (FIXTURE_KERNEL - 1) * FIXTURE_DILATION      # 5 frames
FIXTURE_CONTEXT = 8                                           # > RF - 1, as in production
FIXTURE_WINDOW = 16


# --------------------------------------------------------------------------- #
# Fixture artefact                                                             #
# --------------------------------------------------------------------------- #
def _build_fixture_onnx(path: Path) -> None:
    """A tiny but genuinely causal ``(B, F, T) -> (B, C, T)`` graph.

    NaN -> 0 (the real graph uses a learned sentinel; for the plumbing all that
    matters is that NaN does not poison the arithmetic), then a left-padded
    dilated convolution, which is exactly how a causal TCN layer is built.
    """
    from onnx import TensorProto, helper, numpy_helper

    rng = np.random.default_rng(20260827)
    pad_left = (FIXTURE_KERNEL - 1) * FIXTURE_DILATION

    weight = rng.normal(0, 0.5, (N_CLASSES, N_FEATURES, FIXTURE_KERNEL)).astype(np.float32)
    bias = rng.normal(0, 0.1, (N_CLASSES,)).astype(np.float32)
    # Pad only the time axis, only on the left: (b0, c0, t0, b1, c1, t1).
    pads = np.array([0, 0, pad_left, 0, 0, 0], dtype=np.int64)

    initialisers = [
        numpy_helper.from_array(weight, "W"),
        numpy_helper.from_array(bias, "B"),
        numpy_helper.from_array(pads, "pads"),
        numpy_helper.from_array(np.array(0.0, dtype=np.float32), "zero"),
    ]
    nodes = [
        helper.make_node("IsNaN", ["frames"], ["nanmask"]),
        helper.make_node("Shape", ["frames"], ["shape"]),
        helper.make_node("ConstantOfShape", ["shape"], ["zeros"],
                         value=numpy_helper.from_array(np.array([0.0], dtype=np.float32))),
        helper.make_node("Where", ["nanmask", "zeros", "frames"], ["clean"]),
        helper.make_node("Pad", ["clean", "pads", "zero"], ["padded"], mode="constant"),
        helper.make_node("Conv", ["padded", "W", "B"], ["logits"],
                         kernel_shape=[FIXTURE_KERNEL], dilations=[FIXTURE_DILATION],
                         pads=[0, 0], strides=[1]),
    ]
    graph = helper.make_graph(
        nodes, "hawkshield_v2_fixture",
        [helper.make_tensor_value_info(
            "frames", TensorProto.FLOAT, ["batch", N_FEATURES, "time"])],
        [helper.make_tensor_value_info(
            "logits", TensorProto.FLOAT, ["batch", N_CLASSES, "time"])],
        initialisers,
    )
    model = helper.make_model(
        graph, opset_imports=[helper.make_operatorsetid("", 17)], ir_version=10
    )
    onnx.checker.check_model(model)
    path.write_bytes(model.SerializeToString())


def _fixture_meta() -> Dict[str, Any]:
    rng = np.random.default_rng(7)
    return {
        "spec_version": SPEC_VERSION,
        "model": "hawkshield_v2",
        "architecture": "causal dilated TCN (test fixture)",
        "classes": list(CLASSES),
        "feature_order": list(FEATURE_ORDER),
        "n_features": N_FEATURES,
        "window": FIXTURE_WINDOW,
        "context": FIXTURE_CONTEXT,
        "receptive_field": FIXTURE_RF,
        "normalisation": {
            "mean": [0.0] * N_FEATURES,
            "std": [1.0] * N_FEATURES,
            "clamp": 8.0,
            "mask_feature_indices": list(range(0, N_FEATURES, 4)),
        },
        "_note": "random weights; shape fixture only",
        "_unused": float(rng.random()),
    }


@pytest.fixture(scope="module")
def v2_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A model directory holding a valid, spec-matching v2 artefact."""
    d = tmp_path_factory.mktemp("models_v2")
    _build_fixture_onnx(d / "hawkshield_v2.onnx")
    (d / "hawkshield_v2_meta.json").write_text(
        json.dumps(_fixture_meta(), indent=2), encoding="utf-8"
    )
    return d


@pytest.fixture()
def frames() -> List[Dict[str, float]]:
    """200 frames of plausible feature dicts, with a realistic NaN density."""
    rng = np.random.default_rng(11)
    x = rng.normal(0.0, 2.0, (200, N_FEATURES))
    x[rng.random(x.shape) < 0.2] = np.nan
    return [dict(zip(FEATURE_ORDER, row.tolist())) for row in x]


def _key(v: Verdict) -> tuple:
    """The *decision* part of a verdict: what must be identical, exactly."""
    return (v.is_attack, v.label, v.stage)


def _assert_same_verdict(got: Verdict, expected: Verdict, where: str) -> None:
    """Same decision exactly; same probabilities to float32 precision.

    Not bit-equality: onnxruntime picks different convolution kernels and
    accumulation orders for different sequence lengths, so the same frame scored
    in a batch of 32 and alone can differ in the 9th decimal.  Requiring bit
    equality there would pin an onnxruntime implementation detail, not our
    arithmetic.  What must hold is that no such difference ever changes a label
    or crosses a threshold.
    """
    assert _key(got) == _key(expected), where
    for name in ("p1", "p2"):
        a, b = getattr(got, name), getattr(expected, name)
        if a is None or b is None:
            assert a is b, f"{where}: {name} {a!r} != {b!r}"
        else:
            assert a == pytest.approx(b, abs=1e-6), f"{where}: {name}"


# --------------------------------------------------------------------------- #
# 1. The load-time guard                                                       #
# --------------------------------------------------------------------------- #
def test_valid_artefact_loads(v2_dir: Path) -> None:
    pipe = V2Pipeline(model_dir=v2_dir)
    assert pipe.model_version == "v2"
    assert pipe.spec_version == SPEC_VERSION
    assert pipe.n_features == N_FEATURES
    assert pipe.n_classes == N_CLASSES
    assert pipe.classes == CLASSES
    assert pipe.context == FIXTURE_CONTEXT


@pytest.mark.parametrize(
    "corrupt, expect",
    [
        pytest.param(
            lambda m: m.update(spec_version="1.9.9"), "spec_version mismatch",
            id="stale-spec-version",
        ),
        pytest.param(
            lambda m: m.__setitem__("feature_order", m["feature_order"][:-1]),
            "feature count mismatch", id="one-feature-short",
        ),
        pytest.param(
            lambda m: m.__setitem__("feature_order", m["feature_order"] + ["frame.fcs_bad"]),
            "feature_spec does not", id="feature-removed-from-spec",
        ),
        pytest.param(
            # Same 46 names, two of them swapped: every column would be fed to the
            # wrong channel, and nothing about the shapes would give it away.
            lambda m: m.__setitem__(
                "feature_order",
                [m["feature_order"][1], m["feature_order"][0]] + m["feature_order"][2:],
            ),
            "feature ORDER differs", id="permuted-feature-order",
        ),
        pytest.param(
            lambda m: m.__setitem__("classes", m["classes"][:-1]),
            "class mismatch", id="class-dropped",
        ),
        pytest.param(
            lambda m: m.__setitem__("classes", ["Normal", "Deauth", "Disassoc"] + m["classes"][3:]),
            "class mismatch", id="class-renamed",
        ),
        pytest.param(
            lambda m: m["normalisation"].__setitem__("mean", [0.0] * (N_FEATURES - 1)),
            "normalisation.mean", id="short-normalisation-vector",
        ),
        pytest.param(
            lambda m: m.__setitem__("normalisation", None),
            "no normalisation block", id="no-normalisation",
        ),
    ],
)
def test_meta_spec_mismatch_is_refused(
    v2_dir: Path, tmp_path: Path, corrupt: Any, expect: str
) -> None:
    """A corrupted copy of the meta file must stop the pipeline from starting.

    This is the v1 post-mortem encoded as a test: v1 shipped a model whose feature
    space did not match what the extractor produced, and nothing anywhere said so.
    """
    bad = tmp_path / "models"
    bad.mkdir()
    (bad / "hawkshield_v2.onnx").write_bytes((v2_dir / "hawkshield_v2.onnx").read_bytes())
    meta = _fixture_meta()
    corrupt(meta)
    (bad / "hawkshield_v2_meta.json").write_text(json.dumps(meta), encoding="utf-8")

    with pytest.raises(SpecMismatchError) as excinfo:
        V2Pipeline(model_dir=bad)
    message = str(excinfo.value)
    assert expect in message
    # The message must name the offending file and how to fix it, not just fail.
    assert "hawkshield_v2_meta.json" in message
    assert "export_onnx" in message


def test_meta_problems_lists_every_fault_not_just_the_first() -> None:
    """A stale export usually has several faults; report them in one pass."""
    meta = _fixture_meta()
    meta["spec_version"] = "0.0.1"
    meta["classes"] = meta["classes"][:-1]
    meta["feature_order"] = meta["feature_order"][:-1]
    problems = v2_meta_problems(meta)
    assert len(problems) >= 3
    assert any("spec_version" in p for p in problems)
    assert any("class" in p for p in problems)
    assert any("feature" in p for p in problems)


def test_valid_meta_has_no_problems() -> None:
    assert v2_meta_problems(_fixture_meta()) == []


def test_unreadable_meta_is_refused(tmp_path: Path) -> None:
    (tmp_path / "hawkshield_v2_meta.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(SpecMismatchError, match="not readable JSON"):
        load_v2_meta(tmp_path / "hawkshield_v2_meta.json")


def test_graph_shape_is_checked_not_just_the_meta(v2_dir: Path, tmp_path: Path) -> None:
    """A meta file that lies about the graph must not get past the loader.

    The meta file and the ONNX graph are two separate artefacts; validating only
    the cheap one is how they drift apart.
    """
    from onnx import TensorProto, helper, numpy_helper

    bad = tmp_path / "models"
    bad.mkdir()
    wrong_channels = N_FEATURES + 1
    w = np.zeros((N_CLASSES, wrong_channels, 1), dtype=np.float32)
    graph = helper.make_graph(
        [helper.make_node("Conv", ["frames", "W"], ["logits"], kernel_shape=[1])],
        "wrong_input_width",
        [helper.make_tensor_value_info(
            "frames", TensorProto.FLOAT, ["batch", wrong_channels, "time"])],
        [helper.make_tensor_value_info(
            "logits", TensorProto.FLOAT, ["batch", N_CLASSES, "time"])],
        [numpy_helper.from_array(w, "W")],
    )
    model = helper.make_model(
        graph, opset_imports=[helper.make_operatorsetid("", 17)], ir_version=10
    )
    (bad / "hawkshield_v2.onnx").write_bytes(model.SerializeToString())
    # The meta file is entirely correct -- only the graph is wrong.
    (bad / "hawkshield_v2_meta.json").write_text(
        json.dumps(_fixture_meta()), encoding="utf-8"
    )

    with pytest.raises(SpecMismatchError, match="graph input channel dim"):
        V2Pipeline(model_dir=bad)


# --------------------------------------------------------------------------- #
# 2. Ring buffer / streaming equivalence                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("batch_frames", [1, 2, 7, 32, 64, 1000])
def test_streaming_equivalence(
    v2_dir: Path, frames: List[Dict[str, float]], batch_frames: int
) -> None:
    """Frame *t* gets the same verdict however the frames were grouped.

    The whole point of the ring buffer: batching is a cost decision, never a
    correctness one.  Batch sizes above and below the model's receptive field,
    coprime with it (7), and larger than the whole stream are all covered.
    """
    reference = V2Pipeline(model_dir=v2_dir, batch_frames=1)
    expected = [reference.predict(f) for f in frames]

    batched = V2Pipeline(model_dir=v2_dir, batch_frames=batch_frames)
    got: List[Verdict] = []
    for f in frames:
        got.extend(batched.push(f))
    got.extend(batched.flush())

    assert len(got) == len(frames)
    for i, (g, e) in enumerate(zip(got, expected)):
        _assert_same_verdict(g, e, f"frame {i} at batch_frames={batch_frames}")


def test_batching_actually_reduces_inference_calls(
    v2_dir: Path, frames: List[Dict[str, float]]
) -> None:
    """Guards against a regression that quietly flushes on every frame."""
    pipe = V2Pipeline(model_dir=v2_dir, batch_frames=32)
    pipe.predict_stream(frames)
    assert pipe.frames_seen == len(frames)
    assert pipe.inferences == -(-len(frames) // 32)      # ceil
    assert pipe.failures == 0


def test_history_actually_reaches_the_model(
    v2_dir: Path, frames: List[Dict[str, float]]
) -> None:
    """A frame's verdict must depend on the frames before it.

    Without this, a ring buffer that silently threw its history away would pass
    the equivalence test above -- consistently wrong is still wrong.
    """
    pipe_a = V2Pipeline(model_dir=v2_dir, batch_frames=8)
    with_history = pipe_a.predict_stream(frames)[FIXTURE_RF]

    pipe_b = V2Pipeline(model_dir=v2_dir, batch_frames=8)
    cold = pipe_b.predict(frames[FIXTURE_RF])           # same frame, no history

    assert _key(with_history) != _key(cold)


def test_reset_clears_history(v2_dir: Path, frames: List[Dict[str, float]]) -> None:
    """A stream boundary must not leak context across captures."""
    pipe = V2Pipeline(model_dir=v2_dir, batch_frames=4)
    pipe.predict_stream(frames[:64])
    pipe.reset()
    after_reset = pipe.predict(frames[0])

    fresh = V2Pipeline(model_dir=v2_dir, batch_frames=4)
    _assert_same_verdict(after_reset, fresh.predict(frames[0]), "after reset")


def test_flush_drains_a_partial_batch(v2_dir: Path, frames: List[Dict[str, float]]) -> None:
    """The tail of a burst must not sit unscored until the next packet."""
    pipe = V2Pipeline(model_dir=v2_dir, batch_frames=32)
    for f in frames[:5]:
        assert pipe.push(f) == []
    assert pipe.pending == 5
    drained = pipe.flush()
    assert len(drained) == 5
    assert pipe.pending == 0
    assert pipe.flush() == []                            # idempotent


# --------------------------------------------------------------------------- #
# 3. Feature vectorisation and the Verdict contract                            #
# --------------------------------------------------------------------------- #
def test_features_are_read_by_name_not_by_dict_order(v2_dir: Path) -> None:
    """A dict built in a different order must not transpose the channels."""
    pipe = V2Pipeline(model_dir=v2_dir)
    row = {k: float(i) for i, k in enumerate(FEATURE_ORDER)}
    shuffled = dict(reversed(list(row.items())))
    assert np.array_equal(pipe.vectorise(row), pipe.vectorise(shuffled))
    assert pipe.vectorise(row).tolist() == [float(i) for i in range(N_FEATURES)]


def test_missing_feature_becomes_nan_not_zero(v2_dir: Path) -> None:
    """NaN is the model's "field absent" signal; imputing 0.0 is what killed v1."""
    pipe = V2Pipeline(model_dir=v2_dir)
    vec = pipe.vectorise({FEATURE_ORDER[0]: 1.0})
    assert vec[0] == 1.0
    assert np.isnan(vec[1:]).all()


def test_wrong_length_vector_is_rejected(v2_dir: Path) -> None:
    pipe = V2Pipeline(model_dir=v2_dir)
    with pytest.raises(ValueError, match="expected 46 features"):
        pipe.vectorise(np.zeros(N_FEATURES - 1, dtype=np.float32))


def test_verdict_shape_matches_v1(v2_dir: Path, frames: List[Dict[str, float]]) -> None:
    """``sink.py`` and the packets schema must not need to change for v2."""
    pipe = V2Pipeline(model_dir=v2_dir, batch_frames=16)
    for v in pipe.predict_stream(frames):
        assert isinstance(v, Verdict)
        assert isinstance(v.is_attack, bool)
        assert v.stage in (0, 1, 2)
        if v.stage >= 1:
            assert 0.0 <= v.p1 <= 1.0
        if v.stage == 2:
            assert v.label in ATTACK_CLASSES        # never "Normal"
            assert 0.0 <= v.p2 <= 1.0
        else:
            assert v.p2 is None


def test_thresholds_gate_the_verdict(v2_dir: Path, frames: List[Dict[str, float]]) -> None:
    """thr1 decides "attack at all"; thr2 decides "confident which one"."""
    permissive = V2Pipeline(model_dir=v2_dir, thr1=0.0, thr2=0.0, batch_frames=16)
    assert all(v.is_attack for v in permissive.predict_stream(frames))

    impossible_thr2 = V2Pipeline(model_dir=v2_dir, thr1=0.0, thr2=1.01, batch_frames=16)
    got = impossible_thr2.predict_stream(frames)
    assert not any(v.is_attack for v in got)
    assert all(v.stage == 2 and v.label is not None for v in got)   # classified, not persisted

    impossible_thr1 = V2Pipeline(model_dir=v2_dir, thr1=1.01, thr2=0.0, batch_frames=16)
    got = impossible_thr1.predict_stream(frames)
    assert all(v.stage == 1 and v.label is None for v in got)


# --------------------------------------------------------------------------- #
# 4. Version selection and fallback                                            #
# --------------------------------------------------------------------------- #
def test_auto_falls_back_to_v1_when_onnx_is_absent(tmp_path: Path, caplog: Any) -> None:
    """No v2 artefact is a normal state, not an error: serve v1 and say so."""
    empty = tmp_path / "no_v2"
    empty.mkdir()
    real_models = _REPO_ROOT / "models"
    for name in ("stage1_binary_bundle.joblib", "stage2_multiclass_bundle.joblib"):
        if not (real_models / name).is_file():
            pytest.skip(f"v1 bundle {name} not present")
        (empty / name).write_bytes((real_models / name).read_bytes())

    with caplog.at_level("INFO", logger="backend.detector.pipeline"):
        pipe = build_pipeline("auto", model_dir=empty)

    assert isinstance(pipe, TwoStagePipeline)
    assert pipe.model_version == "v1"
    assert "ACTIVE MODEL: v1" in caplog.text


def test_auto_prefers_v2_when_present(v2_dir: Path, caplog: Any) -> None:
    with caplog.at_level("INFO", logger="backend.detector.pipeline"):
        pipe = build_pipeline("auto", model_dir=v2_dir)
    assert isinstance(pipe, V2Pipeline)
    assert "ACTIVE MODEL: v2" in caplog.text


def test_explicit_v2_refuses_to_downgrade_on_mismatch(tmp_path: Path, v2_dir: Path) -> None:
    """``--model-version v2`` means v2 or nothing -- never a silent v1 fallback."""
    bad = tmp_path / "models"
    bad.mkdir()
    (bad / "hawkshield_v2.onnx").write_bytes((v2_dir / "hawkshield_v2.onnx").read_bytes())
    meta = _fixture_meta()
    meta["spec_version"] = "0.0.1"
    (bad / "hawkshield_v2_meta.json").write_text(json.dumps(meta), encoding="utf-8")

    with pytest.raises(SpecMismatchError):
        build_pipeline("v2", model_dir=bad)


def test_explicit_v2_refuses_when_the_artefact_is_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        build_pipeline("v2", model_dir=tmp_path)


def test_auto_falls_back_loudly_on_mismatch(tmp_path: Path, v2_dir: Path, caplog: Any) -> None:
    """A rejected v2 artefact degrades to v1, but never quietly."""
    bad = tmp_path / "models"
    bad.mkdir()
    (bad / "hawkshield_v2.onnx").write_bytes((v2_dir / "hawkshield_v2.onnx").read_bytes())
    meta = _fixture_meta()
    meta["spec_version"] = "0.0.1"
    (bad / "hawkshield_v2_meta.json").write_text(json.dumps(meta), encoding="utf-8")
    real_models = _REPO_ROOT / "models"
    for name in ("stage1_binary_bundle.joblib", "stage2_multiclass_bundle.joblib"):
        if not (real_models / name).is_file():
            pytest.skip(f"v1 bundle {name} not present")
        (bad / name).write_bytes((real_models / name).read_bytes())

    with caplog.at_level("ERROR", logger="backend.detector.pipeline"):
        pipe = build_pipeline("auto", model_dir=bad)

    assert isinstance(pipe, TwoStagePipeline)
    assert "REJECTED" in caplog.text
    assert "spec_version mismatch" in caplog.text


def test_unknown_model_version_is_rejected() -> None:
    with pytest.raises(ValueError, match="model_version must be one of"):
        build_pipeline("v3")


# --------------------------------------------------------------------------- #
# 5. The capture loop pairs verdicts with the right packets                    #
# --------------------------------------------------------------------------- #
def test_detector_pairs_batched_verdicts_with_their_packets(v2_dir: Path) -> None:
    """Batching must not shift a verdict onto a neighbouring packet."""
    from backend.detector.capture import Detector

    pipe = V2Pipeline(model_dir=v2_dir, thr1=0.0, thr2=0.0, batch_frames=8)

    class _Sink:
        def __init__(self) -> None:
            self.rows: List[tuple] = []

        def write(self, raw, row, verdict, iface):        # noqa: ANN001
            self.rows.append((raw["sa"], row["frame.len"], verdict))

        def maybe_flush(self) -> None: ...
        def close(self) -> None: ...

    sink = _Sink()
    det = Detector(iface="wlan0", pipeline=pipe, sink=sink, dry_run=True)
    assert det.is_v2 and det.model_version == "v2"

    for i in range(20):
        raw = {"sa": f"aa:bb:cc:00:00:{i:02x}", "ssid": None}
        row = {k: float(i) for k in FEATURE_ORDER}
        det._pending.append((raw, row))
        for r, w, v in det._take_pending(pipe.push(row)):
            det._emit(r, w, v)
    det._flush_pipeline()

    assert len(sink.rows) == 20
    # Every packet arrives exactly once, in order, carrying its own frame_len.
    assert [sa for sa, _, _ in sink.rows] == [f"aa:bb:cc:00:00:{i:02x}" for i in range(20)]
    assert [length for _, length, _ in sink.rows] == [float(i) for i in range(20)]


def test_detector_v1_path_is_unchanged(v2_dir: Path) -> None:
    """A v1 pipeline must still get ExtractState and packet_to_row."""
    from backend.detector.capture import Detector
    from backend.detector.features import ExtractState

    class _FakeV1:
        model_version = "v1"
        thr1 = 0.4
        thr2 = 0.8

        def predict(self, row):                            # noqa: ANN001
            return Verdict(is_attack=False, stage=1)

    det = Detector(pipeline=_FakeV1(), dry_run=True)
    assert det.is_v2 is False
    assert isinstance(det.state, ExtractState)
    det._flush_pipeline()                                   # no-op, must not raise


# --------------------------------------------------------------------------- #
# 6. Nine classes through the API                                              #
# --------------------------------------------------------------------------- #
def test_attacks_analysis_returns_every_attack_class_zero_filled(tmp_path: Path) -> None:
    """Eight attack keys, all present, all zero on an empty database."""
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.app.db import Base, get_db
    from backend.app.main import app
    from backend.app.models import Packet  # noqa: F401 - registers the table

    # A file, not ``sqlite://``: an in-memory SQLite database is per-connection,
    # so the table created here would not exist in the request's session.
    engine = create_engine(
        f"sqlite:///{tmp_path / 'analysis.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _override():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    try:
        body = TestClient(app).get("/attacks/analysis").json()
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert list(body) == list(ATTACK_CLASSES)
    assert len(body) == len(CLASSES) - 1 == 8               # 9 classes minus Normal
    assert set(body) == set(ATTACK_CLASSES)
    assert all(v == 0 for v in body.values())
    # The two classes v1 never knew about:
    assert body["Disas"] == 0
    assert body["Kr00k"] == 0
    assert "Normal" not in body


def test_report_front_keys_cover_every_class_and_need_no_escaping() -> None:
    from backend.app.routers.reports import FRONT_TYPES, TYPE_MAP_DB_TO_FRONT

    assert set(TYPE_MAP_DB_TO_FRONT) == set(ATTACK_CLASSES)
    assert set(FRONT_TYPES) == set(TYPE_MAP_DB_TO_FRONT.values())
    assert TYPE_MAP_DB_TO_FRONT["(Re)Assoc"] == "reassoc"
    assert TYPE_MAP_DB_TO_FRONT["Kr00k"] == "kr00k"
    assert TYPE_MAP_DB_TO_FRONT["Disas"] == "disas"
    # The six v1 keys keep their names and their historical positions.
    assert FRONT_TYPES[:6] == ["deauth", "ssdp", "evil_twin", "reassoc", "rogueap", "krack"]
    # No key needs URL- or JSON-quoting.
    from urllib.parse import quote

    for key in FRONT_TYPES:
        assert quote(key) == key
        assert json.dumps(key) == f'"{key}"'


# --------------------------------------------------------------------------- #
# 7. The sink writes v2 rows into the unchanged schema                         #
# --------------------------------------------------------------------------- #
def test_sink_maps_v2_feature_names_onto_the_packets_columns() -> None:
    """v2 renamed the features; the `packets` columns did not change."""
    from backend.detector.sink import _column

    v2_row = {
        "frame.len": 128.0, "radio.freq_mhz": 2437.0, "radio.datarate": 54.0,
        "radio.signal_dbm": -42.0, "fc.ds": 1.0, "fc.retry": 0.0,
        "fc.type": 0.0, "fc.subtype": 12.0, "wlan.duration": 314.0,
    }
    assert _column(v2_row, "channel_freq") == 2437.0
    assert _column(v2_row, "datarate") == 54.0
    assert _column(v2_row, "signal_dbm") == -42.0
    assert _column(v2_row, "wlan_type") == 0.0
    assert _column(v2_row, "wlan_subtype") == 12.0

    v1_row = {
        "frame.len": 128, "radiotap.channel.freq": 5180, "radiotap.datarate": 6.0,
        "wlan_radio.signal_dbm": -71.0, "wlan.fc.type": 0, "wlan.fc.subtype": 8,
    }
    assert _column(v1_row, "channel_freq") == 5180
    assert _column(v1_row, "signal_dbm") == -71.0

    # v2 writes -1 for "no frame-control type", which is absent, not type -1.
    assert _column({"fc.type": -1.0, "fc.subtype": -1.0}, "wlan_type") is None
    assert _column({"fc.type": -1.0, "fc.subtype": -1.0}, "wlan_subtype") is None
    # NaN magnitudes become NULL, never 0.0.
    from backend.detector.sink import _as_float

    assert _as_float(float("nan")) is None
    assert _as_float(-42.0) == -42.0
