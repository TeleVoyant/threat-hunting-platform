# detection/detectors/dns_exfiltration.py
import os

import xgboost as xgb

from detection.model_store import ModelStore
from detection.registry import registry
from shared.enums import DetectionType, Severity
from shared.interfaces import BaseDetector
from shared.schemas import Detection, FeatureVector


class DnsExfiltrationDetector(BaseDetector):

    def name(self) -> str:
        return "dns_exfiltration"

    def detection_type(self) -> str:
        return DetectionType.DNS_EXFILTRATION

    def required_features(self) -> list[str]:
        return ["dns", "temporal", "network"]

    def load_model(self, model_path: str) -> None:
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
            description=f"DNS tunneling / covert exfiltration detected (confidence: {confidence:.0%})",
            contributing_features=contributing,
            mitre_techniques=self.get_mitre_techniques(),
            timestamp=features.timestamp_end,
            event_window_id=features.event_window_id,
        )

    def get_mitre_techniques(self) -> list[str]:
        return ["T1048.001", "T1071.004"]

    def _score_severity(self, confidence: float) -> Severity:
        if confidence > 0.8:
            return Severity.CRITICAL
        if confidence > 0.6:
            return Severity.HIGH
        if confidence > 0.4:
            return Severity.MEDIUM
        return Severity.LOW


# AUTO-REGISTER
registry.register(DnsExfiltrationDetector())
