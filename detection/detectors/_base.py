# detection/detectors/_base.py
"""
Shared XGBoost detector machinery: HMAC-verified load, batched DMatrix
inference, lazy SHAP (only for above-threshold rows), training-time min/max
input clipping (v).

Subclasses set the detector-specific metadata (name, mitre techniques,
detection_type, description prefix) — everything else is inherited.
"""

import json
import os
from pathlib import Path
from typing import Optional

import numpy as np
import xgboost as xgb

from detection.explainer import SHAPExplainer
from detection.model_store import ModelStore
from shared.enums import DetectionType, Severity
from shared.interfaces import BaseDetector
from shared.logging import get_logger
from shared.schemas import Detection, FeatureVector

logger = get_logger("detection.detectors")


class XGBoostDetectorBase(BaseDetector):
    """Concrete behaviour shared by every XGBoost-backed detector."""

    DESCRIPTION_PREFIX = "Detection"

    def __init__(self):
        self.model: Optional[xgb.Booster] = None
        # Per-detector threshold drives lazy SHAP — set by load_model from the
        # detectors.yml config, but the subscriber overrides it per-batch.
        self.threshold: float = 0.5
        # Training-time min/max for input clipping (v). Filled when the
        # manifest carries feature_min/feature_max arrays. Empty = no clip.
        self._feat_min: Optional[np.ndarray] = None
        self._feat_max: Optional[np.ndarray] = None
        # Cached feature schema (booster's; canonical column order).
        self._feature_names: list[str] = []

    # ── Subclass hooks ──────────────────────────────────────────────────────

    def description_for(self, confidence: float) -> str:
        return f"{self.DESCRIPTION_PREFIX} detected (confidence: {confidence:.0%})"

    # ── Model load ──────────────────────────────────────────────────────────

    def load_model(self, model_path: str) -> None:
        store = ModelStore(
            base_dir="detection/models",
            signing_key=os.environ.get("MODEL_SIGNING_KEY", ""),
        )
        self.model = store.load_from_path(model_path)
        self._feature_names = list(self.model.feature_names or [])

        # Pull training-time min/max from the manifest if present (v).
        # Resolve the model_path to its versioned directory:
        #   - dir → manifest.json sibling
        #   - file → parent / manifest.json
        p = Path(model_path)
        manifest_path = (p / "manifest.json") if p.is_dir() else (p.parent / "manifest.json")
        if manifest_path.exists():
            try:
                meta = json.loads(manifest_path.read_text()).get("metadata", {}) or {}
            except Exception:
                meta = {}
            fmin = meta.get("feature_min")
            fmax = meta.get("feature_max")
            if isinstance(fmin, list) and isinstance(fmax, list) \
                    and len(fmin) == len(fmax) == len(self._feature_names):
                self._feat_min = np.asarray(fmin, dtype=np.float32)
                self._feat_max = np.asarray(fmax, dtype=np.float32)

    # ── Single-row inference (BaseDetector contract) ────────────────────────

    def predict(self, features: FeatureVector) -> Detection:
        out = self.predict_batch([features])
        return out[0]

    # ── Batched inference (s) ───────────────────────────────────────────────

    def predict_batch(
        self,
        feature_vectors: list[FeatureVector],
        *,
        threshold: Optional[float] = None,
    ) -> list[Detection]:
        """
        Run one DMatrix predict over N feature vectors.

        threshold — when given, SHAP is computed only for rows whose
        confidence >= threshold (u). When None, every row gets SHAP. Either
        way exactly one batched predict() and at most one batched
        pred_contribs=True call run, regardless of N.
        """
        if not feature_vectors:
            return []
        if self.model is None:
            raise RuntimeError(f"{self.name()}: load_model() must be called first")

        names = self._feature_names or list(feature_vectors[0].features.keys())
        # Build float matrix in the canonical column order. Missing keys
        # zero-fill — should never happen post schema-pin, but defensive.
        rows = np.array(
            [[float(fv.features.get(n, 0.0)) for n in names] for fv in feature_vectors],
            dtype=np.float32,
        )

        # Training-time clip (v). Audit signal: count rows that got clipped
        # on any feature, log if non-zero (not per-detection).
        if self._feat_min is not None and self._feat_max is not None:
            before = rows.copy()
            np.clip(rows, self._feat_min, self._feat_max, out=rows)
            clipped = int(np.any(before != rows, axis=1).sum())
            if clipped:
                logger.warning(
                    "Inference rows clipped to training bounds",
                    detector=self.name(), rows=clipped, total=len(rows),
                )

        dmatrix = xgb.DMatrix(rows, feature_names=names)
        confidences = self.model.predict(dmatrix).tolist()

        # Decide which rows need SHAP. When threshold is None we compute SHAP
        # for everything (preserves single-row predict() behaviour). When set,
        # only above-threshold rows get explained.
        if threshold is None:
            explain_idx = set(range(len(confidences)))
        else:
            explain_idx = {i for i, c in enumerate(confidences) if c >= threshold}

        contribs_all: Optional[np.ndarray] = None
        if explain_idx:
            try:
                # XGBoost computes SHAP for all rows at once even when we want
                # a subset — the subset filter is applied below. Slicing the
                # dmatrix into a subset has its own cost; for typical fleet
                # sizes (≤50 hosts/window) batched SHAP is faster.
                contribs_all = self.model.predict(dmatrix, pred_contribs=True)
            except Exception as e:
                logger.warning("SHAP batch failed", detector=self.name(), error=str(e))

        detections: list[Detection] = []
        for i, fv in enumerate(feature_vectors):
            conf = float(confidences[i])
            contributing: dict[str, float] = {}
            if contribs_all is not None and i in explain_idx:
                contributing = _shap_top_k(contribs_all[i], names, top_k=5)
            detections.append(Detection(
                detection_id=f"det_{fv.event_window_id}_{self.name()}",
                detector_name=self.name(),
                detection_type=self.detection_type(),
                confidence=conf,
                severity=self._score_severity(conf),
                source_entity=fv.source_entity,
                description=self.description_for(conf),
                contributing_features=contributing,
                mitre_techniques=self.get_mitre_techniques(),
                timestamp=fv.timestamp_end,
                event_window_id=fv.event_window_id,
            ))
        return detections

    # ── Severity laddering (shared) ─────────────────────────────────────────

    @staticmethod
    def _score_severity(confidence: float) -> Severity:
        if confidence > 0.8:
            return Severity.CRITICAL
        if confidence > 0.6:
            return Severity.HIGH
        if confidence > 0.4:
            return Severity.MEDIUM
        return Severity.LOW


def _shap_top_k(row: np.ndarray, names: list[str], top_k: int) -> dict[str, float]:
    """Extract top-K |contribution| features from a single SHAP row."""
    sample = row[:-1]  # drop bias term
    if len(names) != len(sample):
        return {}
    ranked = sorted(
        zip(names, sample),
        key=lambda kv: abs(float(kv[1])),
        reverse=True,
    )[:top_k]
    return {name: float(val) for name, val in ranked}
