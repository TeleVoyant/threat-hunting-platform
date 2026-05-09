# features/pipeline.py
from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent, FeatureVector
from datetime import datetime
import uuid


class FeaturePipeline:
    """
    Orchestrates multiple feature extractors.
    Each extractor is independent — add/remove without affecting others.
    """

    def __init__(self):
        self._extractors: list[BaseFeatureExtractor] = []

    def register_extractor(self, extractor: BaseFeatureExtractor):
        self._extractors.append(extractor)

    def extract_all(
        self, events: list[NormalizedEvent], source_entity: str
    ) -> FeatureVector:
        """
        Run every registered extractor and merge their outputs.

        Each extractor is ALWAYS called — even when no events match its
        required_event_types() — so it returns its zero-valued empty
        feature dict. This guarantees a stable feature schema across every
        window, which the XGBoost detectors rely on (column count and
        order must be identical between training and inference).
        """
        all_features: dict[str, float] = {}

        for extractor in self._extractors:
            req = extractor.required_event_types()
            if req == ["*"]:
                relevant = events
            else:
                relevant = [e for e in events if e.event_type in req]

            features = extractor.extract(relevant)  # always — empty list returns zeros
            for key, value in features.items():
                all_features[f"{extractor.name()}__{key}"] = value

        return FeatureVector(
            event_window_id=str(uuid.uuid4()),
            timestamp_start=min(e.timestamp for e in events),
            timestamp_end=max(e.timestamp for e in events),
            source_entity=source_entity,
            features=all_features,
            feature_source="combined",
        )
