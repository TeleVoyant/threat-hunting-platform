# detection/detectors/dns_exfiltration.py
import xgboost as xgb
from shared.interfaces import BaseDetector
from shared.schemas import FeatureVector, Detection
from shared.enums import Severity, DetectionType
from detection.registry import registry


class DnsExfiltrationDetector(BaseDetector):

    def name(self) -> str:
        return "dns_exfiltration"

    def detection_type(self) -> str:
        return DetectionType.DNS_EXFILTRATION

    def required_features(self) -> list[str]:
        return ["dns", "temporal", "network"]

    def load_model(self, model_path: str) -> None:
        self.model = xgb.Booster()
        self.model.load_model(model_path)

    def predict(self, features: FeatureVector) -> Detection:
        dmatrix = xgb.DMatrix([list(features.features.values())])
        confidence = float(self.model.predict(dmatrix)[0])

        return Detection(
            detection_id=f"det_{features.event_window_id}_{self.name()}",
            detector_name=self.name(),
            detection_type=self.detection_type(),
            confidence=confidence,
            severity=self._score_severity(confidence),
            source_entity=features.source_entity,
            description=f"DNS tunneling / covert exfiltration detected (confidence: {confidence:.0%})",
            contributing_features={},
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
