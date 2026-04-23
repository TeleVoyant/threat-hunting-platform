# detection/detectors/lateral_movement.py
import xgboost as xgb
from shared.interfaces import BaseDetector
from shared.schemas import FeatureVector, Detection
from shared.enums import Severity, DetectionType
from detection.registry import registry


class LateralMovementDetector(BaseDetector):

    def name(self) -> str:
        return "lateral_movement"

    def detection_type(self) -> str:
        return DetectionType.LATERAL_MOVEMENT

    def required_features(self) -> list[str]:
        return ["auth", "process", "temporal", "behavioral", "network"]

    def load_model(self, model_path: str) -> None:
        self.model = xgb.Booster()
        self.model.load_model(model_path)

    def predict(self, features: FeatureVector) -> Detection:
        import xgboost as xgb

        dmatrix = xgb.DMatrix([list(features.features.values())])
        confidence = float(self.model.predict(dmatrix)[0])

        return Detection(
            detection_id=f"det_{features.event_window_id}_{self.name()}",
            detector_name=self.name(),
            detection_type=self.detection_type(),
            confidence=confidence,
            severity=self._score_severity(confidence),
            source_entity=features.source_entity,
            description=f"Credential-based lateral movement detected (confidence: {confidence:.0%})",
            contributing_features={},  # Filled by explainer
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
