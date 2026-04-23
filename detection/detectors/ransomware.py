# detection/detectors/ransomware.py   ← New file, that's it
from shared.interfaces import BaseDetector
from detection.registry import registry


class RansomwareDetector(BaseDetector):
    def name(self) -> str:
        return "ransomware"

    # ... implement the interface ...


registry.register(RansomwareDetector())

# Then in detectors.yaml, enable it:
# detectors:
#   ransomware:
#     enabled: true
#     model_path: "models/ransomware_v1.json"
#     threshold: 0.6
