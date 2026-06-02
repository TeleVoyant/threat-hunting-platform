# detection/detectors/ransomware.py
# ─────────────────────────────────────────────────────────────────────────────
# Pattern reference, NOT a working detector. Documents how a new detector
# plugs into the registry; auto-discovery imports this file but the class is
# never instantiated (no registry.register() call) so it can't error on
# startup. To enable, fill in the BaseDetector abstract methods, register
# below, and add an entry in config/detectors.yml.
# ─────────────────────────────────────────────────────────────────────────────

from shared.interfaces import BaseDetector


class RansomwareDetector(BaseDetector):  # noqa: ABC — intentional skeleton
    """
    To make this real:
      1. Implement name() / detection_type() / required_features()
      2. Implement load_model() / predict() (or subclass XGBoostDetectorBase)
      3. Implement get_mitre_techniques()
      4. Uncomment registry.register(RansomwareDetector()) below.
      5. Add to config/detectors.yml:
            ransomware:
              enabled: true
              model_path: "detection/models/ransomware/latest"
              threshold: 0.6
    """
    # ... implement the interface ...


# Intentionally NOT registered — uncomment to activate the detector.
# from detection.registry import registry
# registry.register(RansomwareDetector())
