# shared/interfaces.py
from abc import ABC, abstractmethod
import pandas as pd
from shared.enums import DetectionType
from shared.schemas import NormalizedEvent, FeatureVector, Detection


class BaseFeatureExtractor(ABC):
    """Every feature extractor implements this."""

    @abstractmethod
    def name(self) -> str:
        """Unique name: 'auth', 'dns', 'process', etc."""
        ...

    @abstractmethod
    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        """Take a window of events, return feature dict."""
        ...

    @abstractmethod
    def required_event_types(self) -> list[str]:
        """Which event types this extractor needs. e.g., ['authentication']"""
        ...


class BaseDetector(ABC):
    """Every detection model implements this. This is the plugin interface."""

    @abstractmethod
    def name(self) -> str:
        """Unique detector name: 'lateral_movement', 'dns_exfiltration'"""
        ...

    @abstractmethod
    def detection_type(self) -> DetectionType: ...

    @abstractmethod
    def required_features(self) -> list[str]:
        """Which feature extractor names this detector needs."""
        ...

    @abstractmethod
    def load_model(self, model_path: str) -> None: ...

    @abstractmethod
    def predict(self, features: FeatureVector) -> Detection: ...

    @abstractmethod
    def get_mitre_techniques(self) -> list[str]:
        """MITRE techniques this detector covers."""
        ...
