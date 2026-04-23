"""
Detector Plugin Registry with auto-discovery.

Adding a new detector:
1. Create detection/detectors/my_detector.py
2. Implement BaseDetector interface
3. Call registry.register(MyDetector()) at module level
4. It's automatically discovered and loaded at startup
"""

import importlib
import pkgutil
from pathlib import Path
from shared.interfaces import BaseDetector
from shared.logging import get_logger

logger = get_logger("detection.registry")


class DetectorRegistry:

    def __init__(self):
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector):
        self._detectors[detector.name()] = detector
        logger.info("Detector registered", name=detector.name())

    def get(self, name: str) -> BaseDetector:
        if name not in self._detectors:
            raise KeyError(
                f"Detector '{name}' not registered. Available: {list(self._detectors.keys())}"
            )
        return self._detectors[name]

    def all(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def list_names(self) -> list[str]:
        return list(self._detectors.keys())

    def discover_and_load(self, package_path: str = "detection.detectors"):
        """
        Auto-discover all detector modules in the detectors/ directory.
        Any module that calls registry.register() in its module body
        will be automatically loaded.
        """
        try:
            package = importlib.import_module(package_path)
        except ImportError as e:
            logger.error("Failed to import detector package", package=package_path, error=str(e))
            return

        package_dir = Path(package.__file__).parent

        for module_info in pkgutil.iter_modules([str(package_dir)]):
            if module_info.name.startswith("_"):
                continue
            module_name = f"{package_path}.{module_info.name}"
            try:
                importlib.import_module(module_name)
                logger.info("Detector module loaded", module=module_name)
            except Exception as e:
                logger.error("Failed to load detector module", module=module_name, error=str(e))

    def hot_reload(self, detector_name: str, model_path: str):
        """Reload a single detector's model (e.g., after FL update)."""
        if detector_name in self._detectors:
            detector = self._detectors[detector_name]
            detector.load_model(model_path)
            logger.info("Detector hot-reloaded", name=detector_name, model_path=model_path)


# Global registry instance
registry = DetectorRegistry()
