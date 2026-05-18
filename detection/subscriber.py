# detection/subscriber.py
"""
Event-bus subscriber that turns ingested events into detections.

Subscribes: EVENT_INGESTED   (batch of NormalizedEvents from the ingestion loop)
Emits:      DETECTION_MADE   (one per detector that fires above its threshold)

Pipeline per batch:

      events grouped by (hostname, user)
      └── for each group:
              FeaturePipeline.extract_all() ──► FeatureVector
              └── for each enabled detector with a loaded model:
                      detector.predict(features) ──► Detection
                      if confidence >= threshold ──► emit DETECTION_MADE

Why grouping?
-------------
A FeatureVector represents activity from ONE source entity in a window. Mixing
events from different users/hosts into one vector would dilute the signal. The
(hostname, user) tuple captures both axes the detectors care about:
  * lateral movement: one credential being abused across hosts
  * DNS exfiltration: one host's DNS activity (user often missing on EID 22)
"""

from collections import defaultdict
from typing import Optional

from detection.drift_monitor import DriftMonitor
from detection.registry import registry
from features.pipeline import FeaturePipeline
from shared.events import bus, DETECTION_MADE, EVENT_INGESTED, MODEL_DRIFT_DETECTED
from shared.logging import get_logger
from shared.schemas import NormalizedEvent

logger = get_logger("detection.subscriber")


class DetectionSubscriber:
    """
    Wires the feature pipeline + detector registry into the event bus.

    Construction loads all enabled detector models once (eager). If a model
    file is missing, that detector is logged and skipped — the platform keeps
    running, just without that detector. This makes deployments resilient
    when only one of {lateral_movement, dns_exfiltration} has a trained model.
    """

    def __init__(
        self,
        pipeline: FeaturePipeline,
        detector_config: dict,
        *,
        drift_persistence_dir: str = "data/drift",
    ):
        self.pipeline = pipeline
        # detector_config matches config/detectors.yml structure:
        #   {"lateral_movement": {"enabled": True, "threshold": 0.5,
        #                         "model_path": "detection/models/.."}, ...}
        self.detector_config = detector_config
        self._loaded: set[str] = set()
        # One DriftMonitor per loaded detector. Tracks confidence distribution
        # and detection rate. check_drift() is called per batch (cheap — just
        # rolling stats over the last 1000 predictions).
        self._monitors: dict[str, DriftMonitor] = {}
        # Debounce: only emit MODEL_DRIFT_DETECTED on state TRANSITIONS
        # (clean → drift). Without this we'd fire on every batch while drift
        # persists, swamping subscribers.
        self._drift_state: dict[str, bool] = {}

        for name, cfg in detector_config.items():
            if not cfg.get("enabled"):
                continue
            model_path = cfg.get("model_path")
            try:
                det = registry.get(name)
                if model_path:
                    det.load_model(model_path)
                    self._loaded.add(name)
                    self._monitors[name] = DriftMonitor(
                        detector_name=name,
                        persistence_dir=drift_persistence_dir,
                    )
                    logger.info("Detector model loaded", name=name, path=model_path)
                else:
                    logger.warning("Detector enabled but no model_path", name=name)
            except KeyError:
                logger.warning("Detector enabled but not registered", name=name)
            except FileNotFoundError:
                logger.warning(
                    "Detector model file missing — detector skipped",
                    name=name, path=model_path,
                )
            except Exception as e:
                logger.error("Failed to load detector model",
                             name=name, error=str(e))

    # ── Bus wiring ──────────────────────────────────────────────────────────

    def register(self) -> None:
        """Subscribe to EVENT_INGESTED on the global bus."""
        bus.subscribe(EVENT_INGESTED, self.on_events_ingested)
        logger.info(
            "DetectionSubscriber registered",
            loaded_detectors=sorted(self._loaded),
        )

    def set_drift_baselines(self) -> dict[str, bool]:
        """
        Snapshot current per-detector confidence distributions as the drift
        baseline. Call after the platform has processed enough events for the
        models to be in a representative steady state (e.g., after 1 hour
        of normal traffic). Returns {detector_name: success_bool}.
        """
        results = {}
        for name, monitor in self._monitors.items():
            had_baseline_before = monitor.baseline_stats is not None
            monitor.set_baseline()
            results[name] = monitor.baseline_stats is not None and not had_baseline_before
        return results

    # ── Handler ─────────────────────────────────────────────────────────────

    async def on_events_ingested(self, data: dict) -> None:
        events: list[NormalizedEvent] = data.get("events", []) or []
        if not events:
            return

        if not self._loaded:
            # Nothing to do until at least one model is loaded
            return

        groups = self._group_by_entity(events)
        logger.info("Processing batch",
                    groups=len(groups), total_events=len(events))

        for source_entity, group_events in groups.items():
            try:
                features = self.pipeline.extract_all(group_events, source_entity)
            except Exception as e:
                logger.error("Feature extraction failed",
                             source_entity=source_entity, error=str(e))
                continue

            for name, cfg in self.detector_config.items():
                if name not in self._loaded:
                    continue
                threshold = float(cfg.get("threshold", 0.5))
                detector = registry.get(name)

                try:
                    detection = detector.predict(features)
                except Exception as e:
                    logger.error("Detector predict failed",
                                 detector=name, error=str(e))
                    continue

                # Drift monitor sees EVERY prediction (above OR below threshold)
                # — that's how it tracks confidence distribution shifts.
                self._monitors[name].record_prediction(detection)

                if detection.confidence < threshold:
                    continue

                logger.info(
                    "Detection fired",
                    detector=name,
                    confidence=round(detection.confidence, 3),
                    severity=detection.severity.value,
                    source_entity=source_entity,
                    window_id=features.event_window_id,
                )

                await bus.emit(DETECTION_MADE, {
                    "detection": detection,
                    "features":  features,
                    "events":    group_events,
                })

        # ── Per-batch drift check (cheap — just compares rolling stats) ──────
        for name, monitor in self._monitors.items():
            report = monitor.check_drift()
            currently_drifting = report is not None
            previously_drifting = self._drift_state.get(name, False)

            # Emit only on state transition: was-clean → now-drifting
            if currently_drifting and not previously_drifting:
                await bus.emit(MODEL_DRIFT_DETECTED, {
                    "detector": name,
                    "drift":    report,
                })
                logger.warning("Drift state transition: clean → drifting",
                               detector=name)
            elif not currently_drifting and previously_drifting:
                logger.info("Drift state transition: drifting → clean",
                            detector=name)
            self._drift_state[name] = currently_drifting

    # ── Grouping ────────────────────────────────────────────────────────────

    @staticmethod
    def _group_by_entity(
        events: list[NormalizedEvent],
    ) -> dict[str, list[NormalizedEvent]]:
        """
        Group by (hostname, user). Events without a user (e.g., DNS queries)
        fall back to hostname-only — they still aggregate per laptop.
        """
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in events:
            key = f"{e.hostname}:{e.user}" if e.user else e.hostname
            groups[key].append(e)
        return groups
