"""Two-stage LightGBM inference pipeline.

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
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from joblib import load as joblib_load

from backend.detector._config import get_settings

logger = logging.getLogger(__name__)

__all__ = ["Verdict", "Stage1", "Stage2", "TwoStagePipeline", "sha256_file"]


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
