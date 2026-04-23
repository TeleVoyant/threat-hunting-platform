# shared/events.py
"""
Lightweight internal event bus using asyncio.
Decouples modules: producers publish events, consumers subscribe to event types.
No external dependencies (no Kafka/Redis needed for FYP).

Upgrade path: swap this for Redis Streams in production with zero code changes
to publishers/subscribers, because they use the same EventBus interface.
"""

import asyncio
from collections import defaultdict
from typing import Callable, Any
from shared.logging import get_logger

logger = get_logger("shared.events")


# Event type constants
EVENT_INGESTED = "events.ingested"  # Batch of NormalizedEvents ready
FEATURES_EXTRACTED = "features.extracted"  # FeatureVector ready
DETECTION_MADE = "detection.made"  # Detection with confidence > threshold
ALERT_ENRICHED = "alert.enriched"  # EnrichedAlert ready for publishing
ALERT_PUBLISHED = "alert.published"  # Alert sent to Wazuh
MODEL_DRIFT_DETECTED = "model.drift_detected"  # Drift monitor triggered
FL_ROUND_COMPLETED = "fl.round_completed"  # New global model available


class EventBus:
    """
    Async publish/subscribe event bus.

    Usage:
        bus = EventBus()

        # Subscribe
        @bus.on(EVENT_INGESTED)
        async def handle_events(data):
            features = extract_features(data["events"])
            await bus.emit(FEATURES_EXTRACTED, {"features": features})

        # Publish
        await bus.emit(EVENT_INGESTED, {"events": normalized_events})
    """

    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._history: list[dict] = []  # Recent events for debugging
        self._max_history = 1000

    def on(self, event_type: str):
        """Decorator to subscribe a handler to an event type."""

        def decorator(func: Callable):
            self._subscribers[event_type].append(func)
            logger.debug("Handler registered", event=event_type, handler=func.__name__)
            return func

        return decorator

    def subscribe(self, event_type: str, handler: Callable):
        """Programmatic subscription (alternative to decorator)."""
        self._subscribers[event_type].append(handler)

    async def emit(self, event_type: str, data: Any = None):
        """
        Publish an event. All subscribed handlers are called concurrently.
        Errors in one handler don't affect others.
        """
        handlers = self._subscribers.get(event_type, [])

        if not handlers:
            logger.debug("No handlers for event", event=event_type)
            return

        # Record in history
        self._history.append({"type": event_type, "handlers": len(handlers)})
        if len(self._history) > self._max_history:
            self._history.pop(0)

        # Run all handlers concurrently, isolate failures
        tasks = []
        for handler in handlers:
            tasks.append(self._safe_call(handler, event_type, data))
        await asyncio.gather(*tasks)

    async def _safe_call(self, handler: Callable, event_type: str, data: Any):
        """Call handler with error isolation — one failure doesn't break others."""
        try:
            result = handler(data)
            if asyncio.iscoroutine(result):
                await result
        except Exception as e:
            logger.error(
                "Event handler failed",
                event=event_type,
                handler=handler.__name__,
                error=str(e),
            )

    def get_stats(self) -> dict:
        return {
            "registered_events": {k: len(v) for k, v in self._subscribers.items()},
            "recent_events": len(self._history),
        }


# Global bus instance (shared across all modules)
bus = EventBus()
