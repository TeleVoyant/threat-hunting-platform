# detection/detectors/dns_exfiltration.py
from detection.detectors._base import XGBoostDetectorBase
from detection.registry import registry
from shared.enums import DetectionType


class DnsExfiltrationDetector(XGBoostDetectorBase):

    DESCRIPTION_PREFIX = "DNS tunneling / covert exfiltration"

    def name(self) -> str:
        return "dns_exfiltration"

    def detection_type(self) -> DetectionType:
        return DetectionType.DNS_EXFILTRATION

    def required_features(self) -> list[str]:
        return ["dns", "temporal"]

    def get_mitre_techniques(self) -> list[str]:
        return [
            "T1048.003",  # Exfiltration over DNS
            "T1071.004",  # Application Layer Protocol: DNS (C2)
            "T1568.001",  # Fast Flux DNS
        ]


# AUTO-REGISTER
registry.register(DnsExfiltrationDetector())
