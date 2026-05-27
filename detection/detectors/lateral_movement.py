# detection/detectors/lateral_movement.py
import os

import xgboost as xgb

from detection.model_store import ModelStore
from detection.registry import registry
from shared.enums import DetectionType, Severity
from shared.interfaces import BaseDetector
from shared.schemas import Detection, FeatureVector


class LateralMovementDetector(BaseDetector):

    def name(self) -> str:
        return "lateral_movement"

    def detection_type(self) -> DetectionType:
        return DetectionType.LATERAL_MOVEMENT

    def required_features(self) -> list[str]:
        return ["auth", "process", "temporal", "behavioral", "network"]

    def load_model(self, model_path: str) -> None:
        # Use ModelStore for HMAC-verified loading. Falls back to plain load
        # only when no manifest is present (logged as a warning).
        store = ModelStore(
            base_dir="detection/models",
            signing_key=os.environ.get("MODEL_SIGNING_KEY", ""),
        )
        self.model = store.load_from_path(model_path)

    def predict(self, features: FeatureVector) -> Detection:
        from detection.explainer import SHAPExplainer

        feature_names = list(features.features.keys())
        dmatrix = xgb.DMatrix(
            [list(features.features.values())],
            feature_names=feature_names,
        )
        confidence = float(self.model.predict(dmatrix)[0])

        # SHAP explainability — top 5 features that drove this prediction
        contributing = SHAPExplainer(top_k=5).explain(
            self.model, dmatrix, feature_names
        )

        return Detection(
            detection_id=f"det_{features.event_window_id}_{self.name()}",
            detector_name=self.name(),
            detection_type=self.detection_type(),
            confidence=confidence,
            severity=self._score_severity(confidence),
            source_entity=features.source_entity,
            description=f"Credential-based lateral movement detected (confidence: {confidence:.0%})",
            contributing_features=contributing,
            mitre_techniques=self.get_mitre_techniques(),
            timestamp=features.timestamp_end,
            event_window_id=features.event_window_id,
        )

    def get_mitre_techniques(self) -> list[str]:
        return ["T1003.001", "T1021.002", "T1550.002", "T1078"]

    def _score_severity(self, confidence: float) -> Severity:
        if confidence > 0.8:
            return Severity.CRITICAL
        if confidence > 0.6:
            return Severity.HIGH
        if confidence > 0.4:
            return Severity.MEDIUM
        return Severity.LOW


# AUTO-REGISTER when module is imported
registry.register(LateralMovementDetector())
