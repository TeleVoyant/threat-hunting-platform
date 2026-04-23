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
        """Run all registered extractors and merge into one feature vector."""
        all_features = {}

        for extractor in self._extractors:
            # Filter events to only what this extractor needs
            relevant = [
                e
                for e in events
                if e.event_type in extractor.required_event_types()
                or extractor.required_event_types() == ["*"]
            ]

            if relevant:
                features = extractor.extract(relevant)
                # Prefix features with extractor name to avoid collisions
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
