# detection/detectors/lateral_movement.py
from detection.detectors._base import XGBoostDetectorBase
from detection.registry import registry
from shared.enums import DetectionType


class LateralMovementDetector(XGBoostDetectorBase):

    DESCRIPTION_PREFIX = "Credential-based lateral movement"

    def name(self) -> str:
        return "lateral_movement"

    def detection_type(self) -> DetectionType:
        return DetectionType.LATERAL_MOVEMENT

    def required_features(self) -> list[str]:
        # Must match the extractors actually wired into the FeaturePipeline at
        # train AND inference time. See training/train_models.py for the
        # canonical list (i).
        return ["auth", "temporal"]

    def get_mitre_techniques(self) -> list[str]:
        return [
            "T1003.001",  # OS Credential Dumping (LSASS)
            "T1021.002",  # Remote services: SMB/Admin Shares
            "T1078",      # Valid accounts
            "T1110",      # Brute force
            "T1136",      # Create account
            "T1550.002",  # Pass-the-Hash
            "T1550.003",  # Pass-the-Ticket
        ]


# AUTO-REGISTER when module is imported
registry.register(LateralMovementDetector())
