#!/usr/bin/env python3
"""Check that the two model bundles on disk are the ones the detector expects.

    python -m backend.scripts.verify_models
    python -m backend.scripts.verify_models --model-dir /srv/hawkshield/models --json

Exits non-zero if a bundle is missing, unreadable, or internally inconsistent
(feature counts that disagree, a missing imputer/scaler, an empty class map, ...).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.detector._config import get_settings  # noqa: E402

EXPECTED_CLASSES = ["SSDP", "Evil_Twin", "Krack", "Deauth", "(Re)Assoc", "RogueAP"]
EXPECTED_N_FEATURES = 31
EXPECTED_N_NUM = 29
EXPECTED_N_CAT = 2

#: md5 of the bundles as shipped (docs/CONTRACT.md section 5).
KNOWN_MD5 = {
    "stage1": "d67bfee99f1188513eb46f9c3a83f1cb",
    "stage2": "4ef700bd22eed51dea526e03f77befe0",
}


def _digests(path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk)
            sha.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha.hexdigest()}


def _names(obj: Any) -> List[str]:
    v = getattr(obj, "feature_names_in_", None)
    if v is None:
        return []
    try:
        return [str(x) for x in list(v)]
    except Exception:
        return []


def inspect(stage: str, path: Path, thresholds: Dict[str, float]) -> Dict[str, Any]:
    """Return a report dict with an ``errors`` list (empty means healthy)."""
    rep: Dict[str, Any] = {
        "stage": stage, "path": str(path), "errors": [], "warnings": [],
        "configured_threshold": thresholds[stage],
    }
    if not path.is_file():
        rep["errors"].append("file not found")
        return rep

    rep["size_bytes"] = path.stat().st_size
    rep.update(_digests(path))
    if KNOWN_MD5.get(stage) and rep["md5"] != KNOWN_MD5[stage]:
        rep["warnings"].append(
            "md5 differs from the contract (%s != %s)" % (rep["md5"], KNOWN_MD5[stage])
        )

    try:
        from joblib import load as joblib_load

        b = joblib_load(path)
    except Exception as e:
        rep["errors"].append("joblib load failed: %s" % e)
        return rep

    rep["bundle_keys"] = sorted(str(k) for k in b.keys())

    model = b.get("model")
    if model is None:
        rep["errors"].append("bundle has no 'model'")
        return rep
    rep["model_class"] = type(model).__name__

    imputer = b.get("imputer") if stage == "stage1" else b.get("num_imputer")
    if imputer is None:
        imputer = b.get("num_imputer") or b.get("imputer")
        if imputer is not None:
            rep["warnings"].append("imputer found under the other stage's key name")
    scaler = b.get("scaler")
    if imputer is None:
        rep["errors"].append("bundle has no imputer")
    if scaler is None:
        rep["errors"].append("bundle has no scaler")

    feature_order = [str(x) for x in (b.get("feature_order") or [])]
    num_cols = [str(x) for x in (b.get("num_cols") or [])]
    cat_cols = [str(x) for x in (b.get("cat_cols") or [])]
    imp_names = _names(imputer)
    sc_names = _names(scaler)

    try:
        n_model = int(model.num_feature())
    except Exception:
        n_model = len(feature_order)

    rep["n_features_model"] = n_model
    rep["n_features_feature_order"] = len(feature_order)
    rep["n_features_imputer"] = len(imp_names)
    rep["n_features_scaler"] = len(sc_names)
    rep["n_num_cols"] = len(num_cols)
    rep["n_cat_cols"] = len(cat_cols)
    rep["best_iteration"] = b.get("best_iteration")
    rep["feature_order"] = feature_order

    if len(feature_order) != EXPECTED_N_FEATURES:
        rep["errors"].append(
            "feature_order has %d names, expected %d" % (len(feature_order), EXPECTED_N_FEATURES)
        )
    if n_model != len(feature_order):
        rep["errors"].append(
            "model expects %d features but feature_order has %d" % (n_model, len(feature_order))
        )
    if len(num_cols) != EXPECTED_N_NUM:
        rep["errors"].append("num_cols has %d names, expected %d" % (len(num_cols), EXPECTED_N_NUM))
    if len(cat_cols) != EXPECTED_N_CAT:
        rep["errors"].append("cat_cols has %d names, expected %d" % (len(cat_cols), EXPECTED_N_CAT))
    if imp_names and imp_names != num_cols:
        rep["errors"].append("imputer.feature_names_in_ does not match num_cols")
    if sc_names and sc_names != imp_names:
        rep["errors"].append("scaler.feature_names_in_ does not match the imputer's")
    if feature_order and feature_order != num_cols + cat_cols:
        rep["errors"].append("feature_order != num_cols + cat_cols")

    if stage == "stage1":
        thr = b.get("best_threshold")
        rep["best_threshold"] = thr
        rep["configured_threshold"] = thresholds["stage1"]
        if thr is None:
            rep["warnings"].append("bundle carries no best_threshold")
    else:
        id_to_class = {int(k): str(v) for k, v in dict(b.get("id_to_class", {})).items()}
        rep["id_to_class"] = {str(k): v for k, v in sorted(id_to_class.items())}
        rep["class_order"] = [str(x) for x in (b.get("class_order") or [])]
        rep["configured_threshold"] = thresholds["stage2"]
        if not id_to_class:
            rep["errors"].append("stage-2 bundle has no id_to_class")
        else:
            got = [id_to_class[k] for k in sorted(id_to_class)]
            if got != EXPECTED_CLASSES:
                rep["errors"].append(
                    "class map is %r, expected %r" % (got, EXPECTED_CLASSES)
                )
            try:
                n_class = int(model.num_model_per_iteration())
                rep["n_classes_model"] = n_class
                if n_class != len(id_to_class):
                    rep["errors"].append(
                        "model has %d classes but id_to_class has %d" % (n_class, len(id_to_class))
                    )
            except Exception:
                pass
    return rep


def _print(rep: Dict[str, Any]) -> None:
    print("-" * 78)
    print(f"{rep['stage'].upper()}  {rep['path']}")
    if "size_bytes" in rep:
        print(f"  size          : {rep['size_bytes']:,} bytes")
        print(f"  md5           : {rep.get('md5')}")
        print(f"  sha256        : {rep.get('sha256')}")
    if "bundle_keys" in rep:
        print(f"  bundle keys   : {', '.join(rep['bundle_keys'])}")
        print(f"  model class   : {rep.get('model_class')}  best_iteration={rep.get('best_iteration')}")
        print(
            "  n features    : model={} feature_order={} imputer={} scaler={} "
            "(num={} cat={})".format(
                rep.get("n_features_model"), rep.get("n_features_feature_order"),
                rep.get("n_features_imputer"), rep.get("n_features_scaler"),
                rep.get("n_num_cols"), rep.get("n_cat_cols"),
            )
        )
    if rep["stage"] == "stage1":
        print(f"  threshold     : bundle={rep.get('best_threshold')} configured={rep.get('configured_threshold')}")
    else:
        print(f"  threshold     : configured={rep.get('configured_threshold')}")
        if rep.get("id_to_class"):
            print(f"  classes       : {rep['id_to_class']}")
    for w in rep["warnings"]:
        print(f"  WARNING       : {w}")
    for e in rep["errors"]:
        print(f"  ERROR         : {e}")
    if not rep["errors"]:
        print("  status        : OK")


def main(argv: Optional[List[str]] = None) -> int:
    s = get_settings()
    ap = argparse.ArgumentParser(description="Verify the HawkShield model bundles")
    ap.add_argument("--model-dir", default=None, help="default: MODEL_DIR from settings")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    model_dir = Path(args.model_dir) if args.model_dir else Path(getattr(s, "MODEL_DIR"))
    thresholds = {
        "stage1": float(getattr(s, "STAGE1_THRESHOLD", 0.40)),
        "stage2": float(getattr(s, "STAGE2_THRESHOLD", 0.80)),
    }
    targets = [
        ("stage1", model_dir / getattr(s, "STAGE1_MODEL", "stage1_binary_bundle.joblib")),
        ("stage2", model_dir / getattr(s, "STAGE2_MODEL", "stage2_multiclass_bundle.joblib")),
    ]

    reports = [inspect(stage, path, thresholds) for stage, path in targets]

    # Cross-stage consistency: both stages must share one feature space.
    cross: List[str] = []
    fo = [r.get("feature_order") for r in reports]
    if all(fo) and fo[0] != fo[1]:
        cross.append("stage-1 and stage-2 feature_order differ - one extractor cannot feed both")

    if args.json:
        print(json.dumps(
            {"model_dir": str(model_dir), "reports": reports, "cross_errors": cross}, indent=2
        ))
    else:
        print(f"MODEL_DIR = {model_dir}")
        for rep in reports:
            _print(rep)
        print("-" * 78)
        for c in cross:
            print(f"ERROR: {c}")

    n_err = sum(len(r["errors"]) for r in reports) + len(cross)
    if not args.json:
        print("RESULT: " + ("OK" if n_err == 0 else f"{n_err} problem(s) found"))
    return 1 if n_err else 0


if __name__ == "__main__":
    raise SystemExit(main())
