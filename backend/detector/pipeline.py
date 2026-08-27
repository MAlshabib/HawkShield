"""Inference pipelines: v2-gbdt (LightGBM + causal rollups), v2-tcn (ONNX) and v1.

``build_pipeline()`` picks between the three.  ``auto`` -- the default -- prefers
**v2-gbdt**, falls back to **v2-tcn**, then to **v1**, and says in the log which
one is live and why it is not the one above it.  All three expose
``predict(row) -> Verdict``, so ``sink.py`` and the ``packets`` schema are
untouched by the choice.

Why v2-gbdt is first
--------------------
Both v2 models were trained on the full AWID3 archive and scored on the same
5,943,908 held-out frames.  Measured test macro-F1: **GBDT 0.9907**, TCN 0.9856.
Per class it is the attacks that matter that separate them -- Krack 0.9999 vs
0.9644, (Re)Assoc 0.9975 vs 0.9671, RogueAP 1.0000 vs 0.9955 -- against one class
where the TCN is ahead, Disas 0.9738 vs 0.9578.  The committed rule is that
whichever model wins on measurement ships, so ``auto`` serves the GBDT.  The TCN
stays a first-class, fully supported target: it is 348 KB against 3.0 MB, needs no
lightgbm wheel, and is the right choice on a box where the GBDT will not run.

v2-gbdt -- ``GBDTPipeline``
---------------------------
One LightGBM multiclass booster, 49 boosting rounds x 9 classes = 441 trees, over
**82** columns: the 46 per-frame spec features **plus 36 causal rolling
aggregates**.  A tree sees one row at a time, so on its own it cannot represent
"sixty deauths in the last second"; the aggregates hand it a bounded past.  They
are computed live by :class:`RollupState`, whose arithmetic is
prefix-sum-identical to ``ml.windows.causal_rollups`` -- the training-time
builder -- and pinned to it by ``test_pipeline_v2.py``.  See ``RollupState`` for
why "identical" there means bit-for-bit and not merely close.

v2-tcn -- ``V2Pipeline``
------------------------
One causal dilated TCN, ``(batch, 46, T) float32 -> (batch, 9, T)`` per-frame
logits.  NaN in the input means "this frame does not carry that field"; the graph
handles it with a learned sentinel plus a mask channel, so **nothing is imputed
here**.  Streaming keeps a ring buffer of the last ``context`` frames and scores
``V2_BATCH_FRAMES`` new frames per onnxruntime call -- see ``V2Pipeline`` for why
that is 25x cheaper per frame than calling once per packet.  Both v2 pipelines
consume the *same* 46-feature extractor output (``packet_to_features_v2``); that
is what ``feature_space == "v2"`` on a pipeline object means, and it is what
``capture.py`` and ``replay_pcap.py`` branch on.

v1 -- ``TwoStagePipeline``
--------------------------
Ported from ``_archive/source/.../detector_scapy.py`` with these defects fixed:

* the duplicated ``Stage1._transform_to_imputer_space`` is gone (one implementation,
  shared by both stages),
* the ``/mnt/data/...`` fallback paths are gone (bundle location is env-driven),
* ``print()`` replaced by a module logger,
* sha256 of every bundle is still logged at load time.

Transform order (``docs/CONTRACT.md`` section 5)::

    DataFrame(imputer.feature_names_in_ -> 29 cols)
      -> imputer.transform  (kept as a named DataFrame)
      -> scaler.transform   (kept as a named DataFrame; avoids sklearn feature-name warnings)
      -> reindex into the 31-name model space, absent columns filled with 0.0
      -> Booster.predict(X.values, num_iteration=best_iteration)
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd
from joblib import load as joblib_load

from backend.detector._config import get_settings
from backend.detector.feature_spec import ATTACK_CLASSES, CLASSES, FEATURE_ORDER, SPEC_VERSION

logger = logging.getLogger(__name__)

__all__ = [
    "Verdict",
    "Stage1",
    "Stage2",
    "TwoStagePipeline",
    "V2Meta",
    "V2Pipeline",
    "GBDTPipeline",
    "RollupState",
    "SpecMismatchError",
    "MODEL_VERSIONS",
    "MODEL_VERSION_ALIASES",
    "ROLLUP_MEAN_STD",
    "ROLLUP_RATE",
    "ROLLUP_WINDOWS",
    "GBDT_FEATURE_NAMES",
    "canonical_model_version",
    "rollup_names",
    "build_pipeline",
    "load_v2_meta",
    "sha256_file",
]


# ---------------------------------------------------------------------------
# Model selection vocabulary
# ---------------------------------------------------------------------------
#: The values ``--model-version`` / ``MODEL_VERSION`` accept, canonical spelling.
#:
#: ``backend.app.config`` carries the same tuple so that ``GET /health`` can
#: report the selection without importing the detector (and dragging lightgbm and
#: onnxruntime into the web process).  ``test_pipeline_v2`` asserts the two are
#: equal, so they cannot drift apart silently.
MODEL_VERSIONS: Tuple[str, ...] = ("auto", "v1", "v2-tcn", "v2-gbdt")

#: Accepted spellings that are not canonical.  ``v2`` predates the split and
#: still means the TCN, so an existing ``.env`` keeps working unchanged.
MODEL_VERSION_ALIASES: Dict[str, str] = {
    "v2": "v2-tcn",
    "tcn": "v2-tcn",
    "v2tcn": "v2-tcn",
    "gbdt": "v2-gbdt",
    "v2gbdt": "v2-gbdt",
    "lightgbm": "v2-gbdt",
}


def canonical_model_version(value: Any) -> str:
    """Normalise a requested model version, or raise ``ValueError``."""
    raw = str(value or "auto").strip().lower()
    version = MODEL_VERSION_ALIASES.get(raw, raw)
    if version not in MODEL_VERSIONS:
        raise ValueError(
            f"model_version must be one of {MODEL_VERSIONS} "
            f"(aliases: {sorted(MODEL_VERSION_ALIASES)}), got {value!r}"
        )
    return version


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Verdict:
    """Outcome of one packet passing through the two stages.

    ``stage`` records where the packet was decided: 0 -> stage-1 could not score
    it, 1 -> decided at stage 1, 2 -> reached stage 2.
    """

    is_attack: bool
    label: Optional[str] = None
    p1: Optional[float] = None
    p2: Optional[float] = None
    stage: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    """Streaming sha256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _imputer_feature_names(imputer: Any, fallback: List[str]) -> List[str]:
    """``feature_names_in_`` may be a numpy array - never put one in an ``or`` chain."""
    names = getattr(imputer, "feature_names_in_", None)
    if names is not None:
        try:
            out = [str(x) for x in list(names)]
            if out:
                return out
        except Exception:  # pragma: no cover - defensive
            pass
    return list(fallback)


def _model_feature_names(model: Any, bundle: Dict[str, Any]) -> List[str]:
    feats = bundle.get("feature_order") or bundle.get("features")
    if feats:
        return [str(x) for x in feats]
    getter = getattr(model, "feature_name", None)
    if callable(getter):
        try:
            return [str(x) for x in getter()]
        except Exception:  # pragma: no cover - defensive
            pass
    return []


# ---------------------------------------------------------------------------
# Shared transform machinery
# ---------------------------------------------------------------------------
@dataclass
class _StageBase:
    model: Any
    imputer: Any
    scaler: Any
    feature_order: List[str]      # 31 names the Booster expects
    imputer_features: List[str]   # 29 names the imputer/scaler were fit on
    best_iteration: Optional[int] = None
    path: Optional[Path] = None

    @property
    def _tag(self) -> str:
        return self.__class__.__name__.lower()

    def _build_df(self, row: Dict[str, Any]) -> pd.DataFrame:
        cols = self.imputer_features
        X = pd.DataFrame([{k: row.get(k, None) for k in cols}], columns=cols)
        for c in X.columns:
            if X[c].dtype == object:
                X[c] = pd.to_numeric(X[c], errors="coerce")
        return X

    def _transform_to_imputer_space(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        X = self._build_df(row)
        try:
            Xi = self.imputer.transform(X)
        except Exception as e:
            logger.error("[%s] imputer.transform failed: %s", self._tag, e)
            return None
        if not isinstance(Xi, pd.DataFrame):
            Xi = pd.DataFrame(Xi, columns=self.imputer_features)
        try:
            Xs = self.scaler.transform(Xi)
        except Exception as e:
            logger.error("[%s] scaler.transform failed: %s", self._tag, e)
            return None
        if not isinstance(Xs, pd.DataFrame):
            Xs = pd.DataFrame(Xs, columns=self.imputer_features)
        return Xs

    def _align_to_model_space(self, X_imp: pd.DataFrame) -> pd.DataFrame:
        if not self.feature_order:
            return X_imp
        out = pd.DataFrame(0.0, index=X_imp.index, columns=self.feature_order, dtype=float)
        inter = [c for c in self.feature_order if c in X_imp.columns]
        if inter:
            out[inter] = X_imp[inter]
        return out

    def _prepare_X(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        X_imp = self._transform_to_imputer_space(row)
        if X_imp is None:
            return None
        return self._align_to_model_space(X_imp)

    def _prepare_batch(self, rows: List[Dict[str, Any]]) -> Optional[pd.DataFrame]:
        """Vectorised variant of :meth:`_prepare_X` used by the offline replay tool."""
        cols = self.imputer_features
        X = pd.DataFrame([{k: r.get(k, None) for k in cols} for r in rows], columns=cols)
        for c in X.columns:
            if X[c].dtype == object:
                X[c] = pd.to_numeric(X[c], errors="coerce")
        try:
            Xi = self.imputer.transform(X)
            if not isinstance(Xi, pd.DataFrame):
                Xi = pd.DataFrame(Xi, columns=cols)
            Xs = self.scaler.transform(Xi)
            if not isinstance(Xs, pd.DataFrame):
                Xs = pd.DataFrame(Xs, columns=cols)
        except Exception as e:
            logger.error("[%s] batch transform failed: %s", self._tag, e)
            return None
        return self._align_to_model_space(Xs)

    def _booster_predict(self, X: pd.DataFrame) -> Optional[np.ndarray]:
        num_iter = self.best_iteration or getattr(self.model, "best_iteration", None) or None
        try:
            y = self.model.predict(X.values, num_iteration=num_iter, raw_score=False)
        except Exception as e:
            logger.error("[%s] booster.predict failed: %s", self._tag, e)
            return None
        return np.asarray(y)


# ---------------------------------------------------------------------------
# Stage 1 - binary anomaly
# ---------------------------------------------------------------------------
@dataclass
class Stage1(_StageBase):
    best_threshold: float = 0.40

    @classmethod
    def from_bundle(cls, path: Path, default_threshold: float = 0.40) -> "Stage1":
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError("stage-1 bundle not found: %s" % path)
        b = joblib_load(path)

        model = b["model"]
        imputer = b.get("imputer") or b.get("num_imputer")
        scaler = b.get("scaler")
        if imputer is None or scaler is None:
            raise KeyError("stage-1 bundle %s is missing imputer/scaler" % path)

        feat_model = _model_feature_names(model, b)
        feat_imp = _imputer_feature_names(imputer, b.get("num_cols") or feat_model)
        thr = float(b.get("best_threshold", default_threshold))
        best_iter = b.get("best_iteration") or getattr(model, "best_iteration", None)

        logger.info(
            "Stage-1 loaded: %s sha256=%s n_features_model=%d n_features_imputer=%d "
            "best_iteration=%s best_threshold=%.3f",
            path, sha256_file(path), len(feat_model), len(feat_imp), best_iter, thr,
        )
        return cls(
            model=model, imputer=imputer, scaler=scaler,
            feature_order=feat_model, imputer_features=feat_imp,
            best_iteration=best_iter, path=path, best_threshold=thr,
        )

    def _proba_from_output(self, y: np.ndarray) -> Optional[float]:
        try:
            return float(np.ravel(y)[0])
        except Exception as e:  # pragma: no cover - defensive
            logger.error("[stage1] unusable booster output: %s", e)
            return None

    def predict_proba(self, row: Dict[str, Any]) -> Optional[float]:
        """P(attack) for a single feature row, or None if the transform failed."""
        X = self._prepare_X(row)
        if X is None:
            return None
        m = self.model
        if hasattr(m, "predict_proba"):  # sklearn-style estimator fallback path
            try:
                return float(m.predict_proba(X)[0][1])
            except Exception as e:
                logger.error("[stage1] model.predict_proba failed: %s", e)
                return None
        y = self._booster_predict(X)
        if y is None:
            return None
        return self._proba_from_output(y)

    def predict_proba_batch(self, rows: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        X = self._prepare_batch(rows)
        if X is None:
            return None
        m = self.model
        if hasattr(m, "predict_proba"):
            try:
                return np.asarray(m.predict_proba(X))[:, 1].astype(float)
            except Exception as e:
                logger.error("[stage1] batch predict_proba failed: %s", e)
                return None
        y = self._booster_predict(X)
        if y is None:
            return None
        return np.ravel(np.asarray(y)).astype(float)


# ---------------------------------------------------------------------------
# Stage 2 - multiclass attack type
# ---------------------------------------------------------------------------
@dataclass
class Stage2(_StageBase):
    id_to_class: Dict[int, str] = field(default_factory=dict)

    @classmethod
    def from_bundle(cls, path: Path) -> "Stage2":
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError("stage-2 bundle not found: %s" % path)
        b = joblib_load(path)

        model = b["model"]
        imputer = b.get("num_imputer") or b.get("imputer")   # stage-2 key is num_imputer
        scaler = b.get("scaler")
        if imputer is None or scaler is None:
            raise KeyError("stage-2 bundle %s is missing num_imputer/scaler" % path)

        feat_model = _model_feature_names(model, b)
        feat_imp = _imputer_feature_names(imputer, b.get("num_cols") or feat_model)
        id_to_class = {int(k): str(v) for k, v in dict(b.get("id_to_class", {})).items()}
        if not id_to_class:
            id_to_class = {i: str(c) for i, c in enumerate(b.get("class_order", []))}
        best_iter = b.get("best_iteration") or getattr(model, "best_iteration", None)

        logger.info(
            "Stage-2 loaded: %s sha256=%s n_features_model=%d n_features_imputer=%d "
            "n_classes=%d best_iteration=%s",
            path, sha256_file(path), len(feat_model), len(feat_imp), len(id_to_class), best_iter,
        )
        return cls(
            model=model, imputer=imputer, scaler=scaler,
            feature_order=feat_model, imputer_features=feat_imp,
            best_iteration=best_iter, path=path, id_to_class=id_to_class,
        )

    def _as_probs(self, y: np.ndarray) -> Optional[np.ndarray]:
        """Normalise 0-d / 1-d / 2-d Booster output to a 1-d class-probability vector."""
        try:
            n_class = len(self.id_to_class) or 2
            if y.ndim == 0:
                p1 = float(y)
                return np.array([1.0 - p1, p1], dtype=float)
            if y.ndim == 1:
                if n_class > 2 and y.shape[0] == n_class:
                    return y.astype(float)
                p1 = float(y[0])
                return np.array([1.0 - p1, p1], dtype=float)
            return np.asarray(y[0], dtype=float)
        except Exception as e:  # pragma: no cover - defensive
            logger.error("[stage2] unusable booster output: %s", e)
            return None

    def predict(self, row: Dict[str, Any]) -> Tuple[Optional[str], Optional[float]]:
        """Return ``(label, confidence)``; ``(None, None)`` if inference failed."""
        X = self._prepare_X(row)
        if X is None:
            return None, None
        m = self.model

        if hasattr(m, "predict_proba"):  # sklearn-style estimator fallback path
            try:
                probs = np.asarray(m.predict_proba(X)[0], dtype=float)
            except Exception as e:
                logger.error("[stage2] predict_proba failed: %s", e)
                return None, None
            cls_id = int(np.argmax(probs))
            return self.id_to_class.get(cls_id, str(cls_id)), float(probs[cls_id])

        y = self._booster_predict(X)
        if y is None:
            return None, None
        probs = self._as_probs(y)
        if probs is None:
            return None, None
        cls_id = int(np.argmax(probs))
        return self.id_to_class.get(cls_id, str(cls_id)), float(probs[cls_id])

    def predict_batch(self, rows: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        """(n, n_class) probability matrix; used by the offline replay tool."""
        X = self._prepare_batch(rows)
        if X is None:
            return None
        m = self.model
        if hasattr(m, "predict_proba"):
            try:
                return np.asarray(m.predict_proba(X), dtype=float)
            except Exception as e:
                logger.error("[stage2] batch predict_proba failed: %s", e)
                return None
        y = self._booster_predict(X)
        if y is None:
            return None
        y = np.asarray(y, dtype=float)
        if y.ndim == 1:
            y = y.reshape(1, -1)
        return y


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
class TwoStagePipeline:
    """Load both bundles once, then score feature rows.

    ``predict`` applies the contract decision rule: ``p1 < thr1`` -> drop; else
    stage 2, and ``p2 < thr2`` -> drop; otherwise it is a persisted attack.
    """

    #: Consumed by ``capture.py`` to choose the feature extractor and by the CLI log.
    model_version = "v1"
    feature_space = "v1"
    spec_version = None

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        thr1: Optional[float] = None,
        thr2: Optional[float] = None,
    ) -> None:
        s = get_settings()
        self.model_dir = Path(model_dir if model_dir is not None else s.MODEL_DIR)
        self.thr1 = float(thr1 if thr1 is not None else s.STAGE1_THRESHOLD)
        self.thr2 = float(thr2 if thr2 is not None else s.STAGE2_THRESHOLD)

        self.stage1_path = self.model_dir / getattr(s, "STAGE1_MODEL", "stage1_binary_bundle.joblib")
        self.stage2_path = self.model_dir / getattr(s, "STAGE2_MODEL", "stage2_multiclass_bundle.joblib")

        self.stage1 = Stage1.from_bundle(self.stage1_path, default_threshold=self.thr1)
        self.stage2 = Stage2.from_bundle(self.stage2_path)
        logger.info(
            "TwoStagePipeline ready: thr1=%.3f thr2=%.3f dir=%s",
            self.thr1, self.thr2, self.model_dir,
        )

    @property
    def classes(self) -> List[str]:
        return [self.stage2.id_to_class[k] for k in sorted(self.stage2.id_to_class)]

    def predict(self, row: Dict[str, Any]) -> Verdict:
        p1 = self.stage1.predict_proba(row)
        if p1 is None:
            return Verdict(is_attack=False, stage=0)
        if p1 < self.thr1:
            return Verdict(is_attack=False, p1=p1, stage=1)

        label, p2 = self.stage2.predict(row)
        if label is None or p2 is None:
            return Verdict(is_attack=False, p1=p1, stage=1)
        if p2 < self.thr2:
            return Verdict(is_attack=False, label=label, p1=p1, p2=p2, stage=2)
        return Verdict(is_attack=True, label=label, p1=p1, p2=p2, stage=2)


# ---------------------------------------------------------------------------
# v2 - single causal TCN, ONNX
# ---------------------------------------------------------------------------
class SpecMismatchError(RuntimeError):
    """The exported v2 artefact and the running ``feature_spec`` disagree.

    Raised at *load* time, never at predict time.  v1 died by scoring frames with
    a feature space nobody had checked; v2 refuses to start instead.
    """


@dataclass(frozen=True)
class V2Meta:
    """The validated contents of ``hawkshield_v2_meta.json``."""

    path: Path
    spec_version: str
    classes: List[str]
    feature_order: List[str]
    window: int
    context: int
    mean: np.ndarray
    std: np.ndarray
    clamp: float
    mask_feature_indices: List[int]
    raw: Dict[str, Any]

    @property
    def n_features(self) -> int:
        return len(self.feature_order)

    @property
    def n_classes(self) -> int:
        return len(self.classes)


def load_v2_meta(path: Path) -> V2Meta:
    """Read and validate the meta file.  Raises :class:`SpecMismatchError`.

    The validator itself lives in ``backend.app.config`` so that ``GET /health``
    can reuse it without importing the detector (CONTRACT section 6).  It is
    imported lazily: if the web dependencies are missing on a bare box, v2 simply
    declines to load and ``auto`` falls back to v1 with the reason logged, rather
    than the whole detector failing to import.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"v2 meta file not found: {path}")
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SpecMismatchError(f"{path} is not readable JSON: {exc}") from exc

    from backend.app.config import v2_meta_problems  # lazy: see docstring

    problems = v2_meta_problems(meta)
    if problems:
        raise SpecMismatchError(
            "the exported v2 artefact does not match backend/detector/feature_spec.py "
            f"(spec {SPEC_VERSION}, {len(FEATURE_ORDER)} features, {len(CLASSES)} classes).\n"
            f"  artefact: {path}\n"
            + "\n".join(f"  - {p}" for p in problems)
            + "\nRe-export with `python ml/export_onnx.py` against the current spec, "
              "or pin --model-version v1. Refusing to serve a model whose feature "
              "space is not the one the extractor produces."
        )

    norm = meta["normalisation"]
    return V2Meta(
        path=path,
        spec_version=str(meta["spec_version"]),
        classes=[str(c) for c in meta["classes"]],
        feature_order=[str(f) for f in meta["feature_order"]],
        window=int(meta["window"]),
        context=int(meta["context"]),
        mean=np.asarray(norm["mean"], dtype=np.float32),
        std=np.asarray(norm["std"], dtype=np.float32),
        clamp=float(norm.get("clamp", 8.0)),
        mask_feature_indices=[int(i) for i in norm.get("mask_feature_indices", [])],
        raw=meta,
    )


def _softmax(z: np.ndarray, axis: int = 0) -> np.ndarray:
    """Numerically stable softmax."""
    z = np.asarray(z, dtype=np.float64)
    z = z - np.max(z, axis=axis, keepdims=True)
    e = np.exp(z)
    return e / np.sum(e, axis=axis, keepdims=True)


def verdict_from_probs(p: np.ndarray, thr1: float, thr2: float) -> Verdict:
    """One 9-class probability vector -> the v1-shaped ``Verdict``.

    ``p1 = 1 - P(Normal)``  -- "is this an attack at all", against thr1.
    ``p2 = P(argmax attack class)`` -- "am I confident which one", against thr2.
    The label is the argmax over the eight *attack* classes, so a frame that
    clears thr1 always carries a class name even when Normal is still the overall
    argmax.

    One implementation, shared by both v2 pipelines: the decision rule is part of
    the contract, and two copies of it would eventually disagree about a
    threshold boundary and be invisible in the API, which reports only the
    outcome.
    """
    if not np.all(np.isfinite(p)):
        logger.warning("[v2] non-finite probabilities; dropping frame")
        return Verdict(is_attack=False, stage=0)
    p1 = float(1.0 - p[0])
    if p1 < thr1:
        return Verdict(is_attack=False, p1=p1, stage=1)
    k = int(np.argmax(p[1:]))
    return Verdict(
        is_attack=float(p[1 + k]) >= thr2,
        label=ATTACK_CLASSES[k],
        p1=p1,
        p2=float(p[1 + k]),
        stage=2,
    )


#: What ``V2Pipeline.push`` accepts: the dict ``packet_to_features_v2`` returns,
#: or an already-ordered 46-vector.
FrameFeatures = Union[Dict[str, float], Sequence[float], np.ndarray]


class V2Pipeline:
    """Streaming per-frame classifier over the exported causal TCN.

    Ring buffer
    -----------
    The net is causal: the logits at position *t* depend only on positions
    ``<= t``.  So the prediction for the newest frame is valid as long as it is
    fed ``context`` frames of history, which is what the buffer holds.  This
    mirrors ``ml.windows.inference_chunks`` exactly, including the head of a
    stream: there is no synthetic padding, the sequence is simply shorter than
    ``context`` until enough frames have arrived, which is the same thing the
    trainer does at the head of a block.

    Batching policy
    ---------------
    One inference call scores ``batch_frames`` new frames at once by feeding
    ``context + batch_frames`` positions and reading the last ``batch_frames``
    outputs.  Every scored frame still sees a full ``context`` of history, so the
    answer is identical to scoring one frame at a time -- it is purely a cost
    decision, and a large one, because a call's cost is dominated by fixed
    per-call overhead rather than by ``T``.  Isolated benchmark, dev box, 4 ORT
    intra-op threads, fp32 graph, ``context = 126``:

        N=1    T=127   0.362 ms/call   361.7 us/frame
        N=8    T=134   0.399 ms/call    49.8 us/frame
        N=32   T=158   0.466 ms/call    14.6 us/frame     <-- default
        N=64   T=190   0.504 ms/call     7.9 us/frame
        N=128  T=254   0.612 ms/call     4.8 us/frame

    And in situ, replaying 5000 frames of ``deauth_raw_decrypted.pcapng`` through
    the full capture path (``V2_ORT_THREADS=2``), which is the number that
    actually matters:

        N=1    5000 calls   1347.5 us/frame   292 frame/s   39% of wall time
        N=32    157 calls     54.7 us/frame   723 frame/s    4% of wall time
        N=64     79 calls     41.4 us/frame   716 frame/s    3% of wall time

    ``N = 32`` is the default: 25x cheaper per frame than per-packet scoring, for
    at most 32 frames of added detection delay (~32 ms at 1000 frame/s).  N=64
    buys another 1.3x on a cost that is already only 4% of the loop -- the other
    96% is scapy parsing and feature derivation -- and doubles the delay for it,
    so the extra latency buys nothing measurable.  Anything below N=8 is a real
    regression, not a tuning preference.

    Because verdicts arrive in batches, the streaming API is
    :meth:`push` / :meth:`flush`, and the caller holds the matching packets.
    :meth:`predict` is the single-frame, contract-compatible entry point; it
    forces an immediate flush and therefore costs the N=1 row above.
    """

    model_version = "v2-tcn"
    #: Which extractor feeds this pipeline; ``capture.py`` branches on it.
    feature_space = "v2"

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        thr1: Optional[float] = None,
        thr2: Optional[float] = None,
        batch_frames: Optional[int] = None,
        onnx_path: Optional[Path] = None,
        meta_path: Optional[Path] = None,
        ort_threads: Optional[int] = None,
    ) -> None:
        s = get_settings()
        self.model_dir = Path(model_dir if model_dir is not None else s.MODEL_DIR)
        self.thr1 = float(thr1 if thr1 is not None else s.STAGE1_THRESHOLD)
        self.thr2 = float(thr2 if thr2 is not None else s.STAGE2_THRESHOLD)

        self.onnx_path = Path(
            onnx_path if onnx_path is not None
            else self.model_dir / getattr(s, "V2_MODEL", "hawkshield_v2.onnx")
        )
        self.meta_path = Path(
            meta_path if meta_path is not None
            else self.model_dir / getattr(s, "V2_META", "hawkshield_v2_meta.json")
        )
        if not self.onnx_path.is_file():
            raise FileNotFoundError(f"v2 ONNX model not found: {self.onnx_path}")

        self.meta = load_v2_meta(self.meta_path)
        self.spec_version = self.meta.spec_version

        # CLASSES[0] must be the negative class; p1 = 1 - P(CLASSES[0]).
        if CLASSES[0] != "Normal":
            raise SpecMismatchError(
                f"feature_spec.CLASSES[0] is {CLASSES[0]!r}, expected 'Normal': "
                "V2Pipeline derives p1 as 1 - P(class 0)"
            )

        import onnxruntime as ort  # imported here so v1-only boxes need not have it

        so = ort.SessionOptions()
        threads = int(ort_threads if ort_threads is not None else getattr(s, "V2_ORT_THREADS", 0))
        if threads > 0:
            so.intra_op_num_threads = threads
            so.inter_op_num_threads = 1
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(
            str(self.onnx_path), so, providers=["CPUExecutionProvider"]
        )
        self._input_name = self._validate_session()

        self.n_features = len(FEATURE_ORDER)
        self.n_classes = len(CLASSES)
        self.context = int(self.meta.context)
        self.batch_frames = max(
            1, int(batch_frames if batch_frames is not None
                   else getattr(s, "V2_BATCH_FRAMES", 32))
        )

        self._hist = np.zeros((self.n_features, 0), dtype=np.float32)
        self._pend: List[np.ndarray] = []
        self.frames_seen = 0
        self.inferences = 0
        self.failures = 0

        logger.info(
            "V2Pipeline ready: %s sha256=%s spec=%s features=%d classes=%d "
            "window=%d context=%d batch_frames=%d thr1=%.3f thr2=%.3f",
            self.onnx_path, sha256_file(self.onnx_path)[:16], self.spec_version,
            self.n_features, self.n_classes, self.meta.window, self.context,
            self.batch_frames, self.thr1, self.thr2,
        )

    # -- load-time validation ---------------------------------------------
    def _validate_session(self) -> str:
        """Check the *graph's* declared shapes, not just the meta file's claims."""
        inputs = self.session.get_inputs()
        outputs = self.session.get_outputs()
        problems: List[str] = []
        if len(inputs) != 1:
            problems.append(f"expected 1 graph input, found {[i.name for i in inputs]}")
        if len(outputs) < 1:
            problems.append("graph has no output")
        if inputs:
            shape = list(inputs[0].shape)
            if len(shape) != 3:
                problems.append(f"input {inputs[0].name!r} has rank {len(shape)}, expected 3")
            elif isinstance(shape[1], int) and shape[1] != len(FEATURE_ORDER):
                problems.append(
                    f"graph input channel dim is {shape[1]}, feature_spec has "
                    f"{len(FEATURE_ORDER)} features"
                )
        if outputs:
            oshape = list(outputs[0].shape)
            if len(oshape) != 3:
                problems.append(f"output {outputs[0].name!r} has rank {len(oshape)}, expected 3")
            elif isinstance(oshape[1], int) and oshape[1] != len(CLASSES):
                problems.append(
                    f"graph output class dim is {oshape[1]}, feature_spec has "
                    f"{len(CLASSES)} classes"
                )
        if problems:
            raise SpecMismatchError(
                f"the ONNX graph at {self.onnx_path} does not match "
                f"backend/detector/feature_spec.py:\n"
                + "\n".join(f"  - {p}" for p in problems)
            )
        return inputs[0].name

    # -- properties --------------------------------------------------------
    @property
    def classes(self) -> List[str]:
        return list(CLASSES)

    @property
    def attack_classes(self) -> List[str]:
        return list(ATTACK_CLASSES)

    @property
    def pending(self) -> int:
        """Frames buffered but not yet scored."""
        return len(self._pend)

    # -- feature vectorisation --------------------------------------------
    def vectorise(self, features: FrameFeatures) -> np.ndarray:
        """One frame -> a ``(46,)`` float32 vector in ``FEATURE_ORDER`` order.

        A dict is read **by name**, never by iteration order: a dict that happens
        to be built in a different order must not silently transpose the channels.
        A missing key is NaN, which is the model's own "field absent" convention.
        """
        if isinstance(features, dict):
            return np.fromiter(
                (float(features.get(k, np.nan)) for k in FEATURE_ORDER),
                dtype=np.float32, count=self.n_features,
            )
        vec = np.asarray(features, dtype=np.float32).ravel()
        if vec.size != self.n_features:
            raise ValueError(f"expected {self.n_features} features, got {vec.size}")
        return vec

    # -- streaming ---------------------------------------------------------
    def push(self, features: FrameFeatures) -> List[Verdict]:
        """Buffer one frame.

        Returns ``[]`` while the batch is filling, and a list of
        ``batch_frames`` verdicts -- oldest first, one per buffered frame -- on
        the call that completes it.  The caller keeps the matching packets and
        zips them together.
        """
        self._pend.append(self.vectorise(features))
        self.frames_seen += 1
        if len(self._pend) >= self.batch_frames:
            return self.flush()
        return []

    def flush(self) -> List[Verdict]:
        """Score whatever is buffered, however few frames that is.

        Call it from an idle loop (the detector heartbeat does) so the tail of a
        burst is not stranded until the next packet arrives.
        """
        if not self._pend:
            return []
        pend = np.stack(self._pend, axis=1)                       # (F, n)
        n = pend.shape[1]
        x = np.concatenate([self._hist, pend], axis=1) if self._hist.size else pend
        self._pend.clear()

        try:
            inp = np.ascontiguousarray(x[None, :, :], dtype=np.float32)
            logits = self.session.run(None, {self._input_name: inp})[0]
            self.inferences += 1
        except Exception as exc:
            self.failures += 1
            logger.error("[v2] onnxruntime failed on %d frames: %s", n, exc)
            self._advance(x)
            return [Verdict(is_attack=False, stage=0)] * n

        arr = np.asarray(logits)
        if arr.ndim != 3 or arr.shape[1] != self.n_classes or arr.shape[2] < n:
            self.failures += 1
            logger.error(
                "[v2] unusable output shape %s for %d frames (expected (1, %d, >=%d))",
                arr.shape, n, self.n_classes, n,
            )
            self._advance(x)
            return [Verdict(is_attack=False, stage=0)] * n

        probs = _softmax(arr[0, :, -n:], axis=0)                  # (C, n)
        self._advance(x)
        return [self._verdict(probs[:, j]) for j in range(n)]

    def _advance(self, x: np.ndarray) -> None:
        """Keep the last ``context`` columns as history for the next call."""
        if self.context <= 0:
            self._hist = np.zeros((self.n_features, 0), dtype=np.float32)
        else:
            self._hist = np.ascontiguousarray(x[:, -self.context:], dtype=np.float32)

    def reset(self) -> None:
        """Drop the ring buffer.  Use at a stream boundary (a new capture file)."""
        self._hist = np.zeros((self.n_features, 0), dtype=np.float32)
        self._pend.clear()

    # -- verdicts ----------------------------------------------------------
    def _verdict(self, p: np.ndarray) -> Verdict:
        return verdict_from_probs(p, self.thr1, self.thr2)

    # -- contract-compatible single-frame API ------------------------------
    def predict(self, row: FrameFeatures) -> Verdict:
        """Score one frame now.

        Same signature and same ``Verdict`` as :meth:`TwoStagePipeline.predict`,
        so ``sink.py`` and the DB schema do not change.  This forces an inference
        call per frame (~362 us here vs ~15 us batched), so the capture loop uses
        :meth:`push` instead; keep this for tests, tooling, and any caller that
        genuinely needs a synchronous answer.
        """
        self._pend.append(self.vectorise(row))
        self.frames_seen += 1
        verdicts = self.flush()
        return verdicts[-1] if verdicts else Verdict(is_attack=False, stage=0)

    def predict_stream(self, rows: Iterable[FrameFeatures]) -> List[Verdict]:
        """Score a whole stream, batched, one verdict per row in order.

        Identical results to calling :meth:`predict` on each row -- the batching
        changes only how many onnxruntime calls it takes.
        """
        out: List[Verdict] = []
        for row in rows:
            out.extend(self.push(row))
        out.extend(self.flush())
        return out


# ---------------------------------------------------------------------------
# v2-gbdt - LightGBM over per-frame features + causal rolling aggregates
# ---------------------------------------------------------------------------
# These four constants ARE the GBDT's half of the feature contract, exactly as
# FEATURE_ORDER is the per-frame half.  They are the runtime mirror of
# ``ml.windows.ROLLUP_*``; ``test_pipeline_v2.test_rollup_spec_matches_training``
# imports the training module and asserts they are equal, element for element, so
# a change on either side fails the suite instead of quietly shifting 36 columns.
#
# They are *not* imported from ``ml.windows`` at runtime, deliberately:
# ``ml.windows`` pulls in pyarrow, which has no business on a capture box and is
# not installed on one.  The load-time check below is stronger than an import
# anyway -- it compares against the names LightGBM itself wrote into the model
# file at training time.
ROLLUP_MEAN_STD: List[str] = [
    "frame.len", "frame.dt_log", "radio.signal_dbm",
    "wlan.duration", "wlan.seq_delta", "radio.datarate",
]
ROLLUP_RATE: List[str] = [
    "mgmt.has_reason", "fc.retry", "addr.da_broadcast",
    "eapol.present", "fc.protected", "addr.da_multicast",
]
ROLLUP_WINDOWS: List[int] = [16, 64]


def rollup_names(windows: Sequence[int] = tuple(ROLLUP_WINDOWS)) -> List[str]:
    """Column names of the rolling block, in the order the model expects them."""
    names: List[str] = []
    for n in windows:
        names += [f"roll{n}.{c}.mean" for c in ROLLUP_MEAN_STD]
        names += [f"roll{n}.{c}.std" for c in ROLLUP_MEAN_STD]
        names += [f"roll{n}.{c}.rate" for c in ROLLUP_RATE]
    return names


#: The 82 columns the booster was trained on: 46 per-frame + 36 rolling.
GBDT_FEATURE_NAMES: List[str] = list(FEATURE_ORDER) + rollup_names()


class RollupState:
    """Streaming causal rolling aggregates for one frame sequence.

    Reproduces ``ml.windows.causal_rollups`` -- the builder that produced the
    training matrix -- **bit for bit**, not approximately.  That is the whole
    point of this class, so it is worth being explicit about how, because the
    obvious implementation gets two things wrong.

    1. The window is ``w + 1`` frames, not ``w``
       ------------------------------------------
       ``causal_rollups`` aggregates rows ``[max(i - w, 0), i + 1)`` for row *i*.
       For ``w = 16`` that is **seventeen** frames: the current one and the
       sixteen before it.  A streaming buffer that keeps "the last 16 frames" is
       off by one against training on every single row.  It would not crash, it
       would not look wrong, it would just feed the booster 36 columns that are
       systematically not the ones it was fitted on -- which is precisely the
       train/serve gap this project exists to eliminate.

    2. Prefix sums, not a sliding re-sum
       ----------------------------------
       Training computes ``cumsum`` over the whole block and subtracts two
       prefixes.  Re-summing a 17- or 65-row window per frame would be *correct*
       maths and a *different* float64 rounding, and ``std`` is computed as
       ``E[x^2] - E[x]^2``, where that difference is amplified: on a run of
       near-constant ``frame.len`` the cancellation leaves ~1e-9 of noise whose
       square root is ~3e-5, so two arithmetically-equivalent implementations can
       disagree in the 5th decimal of a feature the model splits on.  So this
       keeps running prefix sums and a ring of the last ``max(w) + 2`` prefix
       snapshots, and subtracts exactly the same two float64 numbers training
       subtracted.  Equality is then exact, and the test asserts exact.

    NaN is "the frame does not carry that field": excluded from both numerator
    and denominator, never treated as zero.  ``mean`` is NaN when the window
    holds no values at all, ``std`` when it holds fewer than two -- the model was
    trained with those NaNs present and reads them as information.

    :meth:`reset` returns the state to the head of a fresh stream, which is the
    live equivalent of a ``block_id`` boundary: no aggregate ever spans a
    detector restart, exactly as none ever spanned two source files in training.
    """

    def __init__(self, windows: Optional[Sequence[int]] = None) -> None:
        self.windows: List[int] = [int(w) for w in (windows or ROLLUP_WINDOWS)]
        if not self.windows or any(w < 1 for w in self.windows):
            raise ValueError(f"rollup windows must all be >= 1, got {self.windows}")
        self.names: List[str] = rollup_names(self.windows)

        # Column groups, resolved once against FEATURE_ORDER and concatenated into
        # one gather: mean/std columns first, then rate columns.  Both groups get
        # the same treatment except that only the first needs squares, so keeping
        # them in one array halves the number of numpy calls per frame, and numpy
        # call overhead -- not arithmetic -- is what this costs.
        self._ms_idx = np.asarray([FEATURE_ORDER.index(c) for c in ROLLUP_MEAN_STD])
        self._rate_idx = np.asarray([FEATURE_ORDER.index(c) for c in ROLLUP_RATE])
        self._idx = np.concatenate((self._ms_idx, self._rate_idx))
        self._n_ms = len(self._ms_idx)
        self._n_cols = self._n_ms + len(self._rate_idx)

        # See the class docstring: prefix index j for row i runs over
        # [i - max(w), i + 1], which is max(w) + 2 distinct values.  Sizing the
        # ring exactly that means slot 0 still holds the all-zero prefix cs[0]
        # for as long as any window is still clamped to the head of the stream.
        self._cap = max(self.windows) + 2
        self.reset()

    # -- state -------------------------------------------------------------
    def reset(self) -> None:
        """Start a fresh stream: no aggregate spans this boundary."""
        self._cs = np.zeros(self._n_cols, dtype=np.float64)     # sum of values
        self._cs2 = np.zeros(self._n_ms, dtype=np.float64)      # sum of squares
        self._cn = np.zeros(self._n_cols, dtype=np.float64)     # count of non-NaN
        self._h_cs = np.zeros((self._cap, self._n_cols), dtype=np.float64)
        self._h_cs2 = np.zeros((self._cap, self._n_ms), dtype=np.float64)
        self._h_cn = np.zeros((self._cap, self._n_cols), dtype=np.float64)
        self._rows = 0                                          # frames consumed
        #: Ring slots to subtract, one per window; rewritten in place each frame.
        self._lo_slots = np.zeros(len(self.windows), dtype=np.intp)

    @property
    def n_features(self) -> int:
        return len(self.names)

    @property
    def rows(self) -> int:
        return self._rows

    # -- the aggregate -----------------------------------------------------
    def update(self, vec: np.ndarray) -> np.ndarray:
        """Consume one 46-feature frame; return its ``(36,)`` float32 rollups.

        Causal by construction: the returned row is a function of this frame and
        the ones already consumed, and of nothing else.
        """
        nms = self._n_ms
        v = np.asarray(vec, dtype=np.float64)[self._idx]
        valid = ~np.isnan(v)
        v0 = np.where(valid, v, 0.0)

        # Same accumulation order as np.cumsum, so the same float64 values.
        self._cs += v0
        self._cn += valid
        self._cs2 += v0[:nms] * v0[:nms]

        self._rows += 1
        j = self._rows                       # prefix index of the row just added
        slot = j % self._cap
        self._h_cs[slot] = self._cs
        self._h_cs2[slot] = self._cs2
        self._h_cn[slot] = self._cn

        # Window w for row i = j - 1 covers rows [max(i - w, 0), i + 1): w + 1 of
        # them.  Both windows are evaluated in one shot below, as (n_windows, n_cols).
        i = j - 1
        lo = self._lo_slots
        for k, w in enumerate(self.windows):
            lo[k] = max(i - w, 0) % self._cap

        cnt = self._cn - self._h_cn[lo]
        tot = self._cs - self._h_cs[lo]
        denom = np.maximum(cnt, 1.0)
        mean = tot / denom
        mean[cnt == 0] = np.nan              # an empty window has no mean, not 0.0

        d_ms = denom[:, :nms]
        var = np.maximum(
            (self._cs2 - self._h_cs2[lo]) / d_ms - (tot[:, :nms] / d_ms) ** 2, 0.0
        )
        std = np.sqrt(var)
        std[cnt[:, :nms] <= 1] = np.nan      # one sample has no spread, not 0.0

        out = np.empty(self.n_features, dtype=np.float32)
        step = 2 * nms + (self._n_cols - nms)
        for k in range(len(self.windows)):
            base = k * step
            out[base:base + nms] = mean[k, :nms]                  # mean, mean/std group
            out[base + nms:base + 2 * nms] = std[k]               # std,  mean/std group
            out[base + 2 * nms:base + step] = mean[k, nms:]       # rate group
        return out


class GBDTPipeline:
    """Streaming per-frame classifier over the exported LightGBM booster.

    Same ``Verdict`` and the same ``push``/``flush``/``predict`` surface as
    :class:`V2Pipeline`, so ``capture.py``, ``sink.py``, ``replay_pcap.py`` and
    the ``packets`` schema do not know which of the two is running.

    Batching
    --------
    Unlike the TCN, a tree ensemble has no temporal receptive field, so batching
    here is a *pure* cost decision with no correctness component at all: the 36
    rolling columns are built by :class:`RollupState` at ``push`` time, one frame
    at a time, in arrival order.  A frame's 82-column row is therefore fully
    determined before any prediction happens, and grouping rows into one
    ``Booster.predict`` call cannot change a single verdict.  ``test_pipeline_v2``
    asserts that across batch sizes anyway, because "cannot" is a claim.

    Threads
    -------
    ``GBDT_NUM_THREADS`` is passed to every ``predict`` call for the same reason
    ``V2_ORT_THREADS`` is pinned for onnxruntime: the default is one thread per
    core, which is right for a batch job and wrong for a capture loop sharing 4
    cores with scapy, the API and Postgres.
    """

    model_version = "v2-gbdt"
    #: Same 46-feature extractor as the TCN.  See ``V2Pipeline``.
    feature_space = "v2"

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        thr1: Optional[float] = None,
        thr2: Optional[float] = None,
        batch_frames: Optional[int] = None,
        gbdt_path: Optional[Path] = None,
        meta_path: Optional[Path] = None,
        num_threads: Optional[int] = None,
    ) -> None:
        s = get_settings()
        self.model_dir = Path(model_dir if model_dir is not None else s.MODEL_DIR)
        self.thr1 = float(thr1 if thr1 is not None else s.STAGE1_THRESHOLD)
        self.thr2 = float(thr2 if thr2 is not None else s.STAGE2_THRESHOLD)

        self.gbdt_path = Path(
            gbdt_path if gbdt_path is not None
            else self.model_dir / getattr(s, "V2_GBDT", "hawkshield_v2_gbdt.txt")
        )
        self.meta_path = Path(
            meta_path if meta_path is not None
            else self.model_dir / getattr(s, "V2_META", "hawkshield_v2_meta.json")
        )
        if not self.gbdt_path.is_file():
            raise FileNotFoundError(f"v2 GBDT model not found: {self.gbdt_path}")

        # The same meta file, and the same validator, as the TCN: spec version,
        # class list and the 46 per-frame feature names are one contract shared by
        # both v2 targets, and neither may serve against a stale one.
        self.meta = load_v2_meta(self.meta_path)
        self.spec_version = self.meta.spec_version

        if CLASSES[0] != "Normal":
            raise SpecMismatchError(
                f"feature_spec.CLASSES[0] is {CLASSES[0]!r}, expected 'Normal': "
                "GBDTPipeline derives p1 as 1 - P(class 0)"
            )

        import lightgbm as lgb  # imported here so TCN-only boxes need not have it

        try:
            self.booster = lgb.Booster(model_file=str(self.gbdt_path))
        except Exception as exc:
            raise SpecMismatchError(
                f"{self.gbdt_path} is not a loadable LightGBM model: {exc}"
            ) from exc

        self.rollups = RollupState()
        self.feature_names = list(GBDT_FEATURE_NAMES)
        self._validate_booster()

        self.n_features = len(self.feature_names)
        self.n_classes = len(CLASSES)
        self.num_threads = int(
            num_threads if num_threads is not None else getattr(s, "GBDT_NUM_THREADS", 2)
        )
        self.batch_frames = max(
            1, int(batch_frames if batch_frames is not None
                   else getattr(s, "V2_BATCH_FRAMES", 32))
        )

        self._pend: List[np.ndarray] = []
        self.frames_seen = 0
        self.inferences = 0
        self.failures = 0

        logger.info(
            "GBDTPipeline ready: %s sha256=%s spec=%s features=%d (%d frame + %d rolling, "
            "windows %s) classes=%d trees=%d iterations=%d batch_frames=%d threads=%d "
            "thr1=%.3f thr2=%.3f",
            self.gbdt_path, sha256_file(self.gbdt_path)[:16], self.spec_version,
            self.n_features, len(FEATURE_ORDER), self.rollups.n_features,
            self.rollups.windows, self.n_classes, self.booster.num_trees(),
            self.booster.current_iteration(), self.batch_frames, self.num_threads,
            self.thr1, self.thr2,
        )

    # -- load-time validation ---------------------------------------------
    def _validate_booster(self) -> str:
        """Check the *model file's own* column names, not just the meta's claims.

        LightGBM writes ``feature_names=`` into the saved model, so the artefact
        states, in its own words, the 82 columns it was fitted on.  Comparing that
        against ``GBDT_FEATURE_NAMES`` catches every way the two sides can drift:
        a feature added to or removed from the spec, a different rollup window, a
        renamed aggregate, and -- the one nothing else would catch -- the same 82
        names in a different order, which would feed every column to the wrong
        split and produce confident nonsense.
        """
        problems: List[str] = []
        got = [str(n) for n in self.booster.feature_name()]
        want = self.feature_names

        if got != want:
            if len(got) != len(want):
                problems.append(
                    f"feature count mismatch: model has {len(got)}, this build expects "
                    f"{len(want)} ({len(FEATURE_ORDER)} per-frame + "
                    f"{self.rollups.n_features} rolling over windows {self.rollups.windows})"
                )
            missing = [n for n in want if n not in got]
            extra = [n for n in got if n not in want]
            if missing:
                problems.append(f"columns the model is missing: {missing}")
            if extra:
                problems.append(f"columns the model has but this build does not: {extra}")
            if not missing and not extra:
                first = next(i for i, (a, b) in enumerate(zip(got, want)) if a != b)
                problems.append(
                    f"column ORDER differs at index {first}: model {got[first]!r} vs "
                    f"this build {want[first]!r} (same names, wrong order - every "
                    f"column would be fed to the wrong split)"
                )

        n_out = int(self.booster.num_model_per_iteration())
        if n_out != len(CLASSES):
            problems.append(
                f"model emits {n_out} scores per iteration, feature_spec has "
                f"{len(CLASSES)} classes"
            )

        if not problems:
            # The names and counts can all agree and the model still be a
            # regressor or a binary classifier saved with 9 names.  One probe row
            # settles what it actually returns, at load time rather than at 3am.
            try:
                probe = self.booster.predict(
                    np.zeros((1, len(want)), dtype=np.float32), num_threads=1
                )
                shape = tuple(np.asarray(probe).shape)
            except Exception as exc:
                problems.append(f"predict() failed on a probe row: {exc}")
                shape = ()
            if shape and shape != (1, len(CLASSES)):
                problems.append(
                    f"predict() returned shape {shape}, expected (1, {len(CLASSES)}) - "
                    f"this is not a {len(CLASSES)}-class probability model"
                )

        if problems:
            raise SpecMismatchError(
                "the exported GBDT artefact does not match "
                "backend/detector/feature_spec.py + the rolling-aggregate spec "
                f"(spec {SPEC_VERSION}, {len(FEATURE_ORDER)} per-frame features, "
                f"{len(CLASSES)} classes).\n"
                f"  artefact: {self.gbdt_path}\n"
                + "\n".join(f"  - {p}" for p in problems)
                + "\nRetrain with `python ml/train.py --model gbdt` against the current "
                  "spec and re-export with `python ml/export_onnx.py`, or pin "
                  "--model-version v2-tcn. Refusing to serve a model whose feature "
                  "space is not the one the extractor produces."
            )
        return "ok"

    # -- properties --------------------------------------------------------
    @property
    def classes(self) -> List[str]:
        return list(CLASSES)

    @property
    def attack_classes(self) -> List[str]:
        return list(ATTACK_CLASSES)

    @property
    def pending(self) -> int:
        """Frames buffered but not yet scored."""
        return len(self._pend)

    # -- feature vectorisation --------------------------------------------
    def vectorise(self, features: FrameFeatures) -> np.ndarray:
        """One frame -> a ``(46,)`` float32 vector in ``FEATURE_ORDER`` order.

        Identical rules to :meth:`V2Pipeline.vectorise`: a dict is read by name,
        never by iteration order, and a missing key is NaN, not 0.0.
        """
        if isinstance(features, dict):
            return np.fromiter(
                (float(features.get(k, np.nan)) for k in FEATURE_ORDER),
                dtype=np.float32, count=len(FEATURE_ORDER),
            )
        vec = np.asarray(features, dtype=np.float32).ravel()
        if vec.size != len(FEATURE_ORDER):
            raise ValueError(f"expected {len(FEATURE_ORDER)} features, got {vec.size}")
        return vec

    def build_row(self, features: FrameFeatures) -> np.ndarray:
        """Consume one frame into the rolling state; return its ``(82,)`` row.

        This *advances* the stream.  Call it once per frame, in arrival order.
        """
        vec = self.vectorise(features)
        return np.concatenate((vec, self.rollups.update(vec)))

    # -- streaming ---------------------------------------------------------
    def push(self, features: FrameFeatures) -> List[Verdict]:
        """Buffer one frame; returns verdicts when the batch completes."""
        self._pend.append(self.build_row(features))
        self.frames_seen += 1
        if len(self._pend) >= self.batch_frames:
            return self.flush()
        return []

    def flush(self) -> List[Verdict]:
        """Score whatever is buffered, however few frames that is."""
        if not self._pend:
            return []
        X = np.stack(self._pend, axis=0)
        n = X.shape[0]
        self._pend.clear()

        try:
            probs = np.asarray(
                self.booster.predict(X, num_threads=self.num_threads), dtype=np.float64
            )
            self.inferences += 1
        except Exception as exc:
            self.failures += 1
            logger.error("[v2-gbdt] booster.predict failed on %d frames: %s", n, exc)
            return [Verdict(is_attack=False, stage=0)] * n

        if probs.ndim != 2 or probs.shape != (n, self.n_classes):
            self.failures += 1
            logger.error(
                "[v2-gbdt] unusable output shape %s for %d frames (expected (%d, %d))",
                probs.shape, n, n, self.n_classes,
            )
            return [Verdict(is_attack=False, stage=0)] * n

        return [verdict_from_probs(probs[j], self.thr1, self.thr2) for j in range(n)]

    def reset(self) -> None:
        """Drop the rolling state.  Use at a stream boundary (a new capture file).

        The live counterpart of "a window never spans a ``block_id`` boundary":
        after this, no aggregate mixes frames from the two streams.
        """
        self.rollups.reset()
        self._pend.clear()

    # -- contract-compatible single-frame API ------------------------------
    def predict(self, row: FrameFeatures) -> Verdict:
        """Score one frame now.  Same ``Verdict`` as ``TwoStagePipeline.predict``."""
        self._pend.append(self.build_row(row))
        self.frames_seen += 1
        verdicts = self.flush()
        return verdicts[-1] if verdicts else Verdict(is_attack=False, stage=0)

    def predict_stream(self, rows: Iterable[FrameFeatures]) -> List[Verdict]:
        """Score a whole stream, batched, one verdict per row in order."""
        out: List[Verdict] = []
        for row in rows:
            out.extend(self.push(row))
        out.extend(self.flush())
        return out


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
AnyPipeline = Union["GBDTPipeline", "V2Pipeline", TwoStagePipeline]

#: ``auto``'s preference order, and the one-line reason each is where it is.
#: The order is a measurement, not a taste: both v2 models were scored on the same
#: 5,943,908 held-out AWID3 frames and the GBDT won, so the GBDT serves.
_AUTO_ORDER: Tuple[Tuple[str, str], ...] = (
    ("v2-gbdt", "test macro-F1 0.9907 - the best measured model"),
    ("v2-tcn", "test macro-F1 0.9856, no lightgbm wheel needed"),
    ("v1", "legacy two-stage bundles; last resort"),
)

_DESCRIPTIONS: Dict[str, str] = {
    "v2-gbdt": "LightGBM + causal rolling aggregates",
    "v2-tcn": "causal TCN, ONNX",
    "v1": "two-stage LightGBM",
}


def _load_one(
    version: str,
    model_dir: Optional[Path],
    thr1: Optional[float],
    thr2: Optional[float],
    batch_frames: Optional[int],
) -> AnyPipeline:
    if version == "v2-gbdt":
        return GBDTPipeline(
            model_dir=model_dir, thr1=thr1, thr2=thr2, batch_frames=batch_frames
        )
    if version == "v2-tcn":
        return V2Pipeline(
            model_dir=model_dir, thr1=thr1, thr2=thr2, batch_frames=batch_frames
        )
    return TwoStagePipeline(model_dir=model_dir, thr1=thr1, thr2=thr2)


def build_pipeline(
    model_version: str = "auto",
    model_dir: Optional[Path] = None,
    thr1: Optional[float] = None,
    thr2: Optional[float] = None,
    batch_frames: Optional[int] = None,
) -> AnyPipeline:
    """Load the requested pipeline and say, in the log, which one is live and why.

    ``auto``      v2-gbdt, else v2-tcn, else v1 -- each downgrade logged with its
                  reason, because a silent downgrade to a worse model is the same
                  failure mode as a silent feature mismatch.
    ``v2-gbdt``   the LightGBM booster or nothing.
    ``v2-tcn``    the ONNX TCN or nothing (``v2`` is still accepted, and means this).
    ``v1``        the two-stage LightGBM bundles.

    An explicit choice never downgrades: a missing artefact or a spec mismatch
    raises.  Only ``auto`` falls through, and only loudly.
    """
    version = canonical_model_version(model_version)

    if version != "auto":
        pipe = _load_one(version, model_dir, thr1, thr2, batch_frames)
        logger.info(
            "ACTIVE MODEL: %s (%s) spec=%s classes=%d - requested explicitly",
            version, _DESCRIPTIONS[version], getattr(pipe, "spec_version", None),
            len(pipe.classes),
        )
        return pipe

    tried: List[str] = []
    for candidate, why in _AUTO_ORDER:
        try:
            pipe = _load_one(candidate, model_dir, thr1, thr2, batch_frames)
        except FileNotFoundError as exc:
            tried.append(f"{candidate}: artefact not available ({exc})")
            logger.info("auto: %s artefact not available (%s)", candidate, exc)
            continue
        except SpecMismatchError as exc:
            tried.append(f"{candidate}: REJECTED, does not match feature_spec")
            logger.error(
                "auto: %s artefact REJECTED - it does not match the running "
                "feature_spec. Details:\n%s", candidate, exc,
            )
            continue
        except Exception as exc:  # noqa: BLE001 - any load failure downgrades, loudly
            tried.append(f"{candidate}: failed to load ({type(exc).__name__}: {exc})")
            logger.error("auto: %s failed to load (%s: %s)",
                         candidate, type(exc).__name__, exc)
            continue

        logger.info(
            "ACTIVE MODEL: %s (%s) spec=%s classes=%d - %s%s",
            candidate, _DESCRIPTIONS[candidate], getattr(pipe, "spec_version", None),
            len(pipe.classes), why,
            "" if not tried else "; passed over " + " | ".join(tried),
        )
        return pipe

    raise FileNotFoundError(
        "no model could be loaded. Tried, in preference order:\n"
        + "\n".join(f"  - {t}" for t in tried)
    )
