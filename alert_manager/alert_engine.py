"""
Alert Engine: scores, deduplicates, and prioritizes alerts.
"""

from shared.schemas import EnrichedAlert
from shared.logging import get_logger

logger = get_logger("alert_manager.alert_engine")


class AlertEngine:

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.min_confidence = 0.5
        self.dedup_window = 30  # minutes

    def process(self, alert: EnrichedAlert) -> EnrichedAlert:
        """Process an enriched alert: validate, score, and return."""
        if alert.overall_confidence < self.min_confidence:
            logger.info("Alert below confidence threshold", alert_id=alert.alert_id)
            return alert

        logger.info(
            "Alert processed",
            alert_id=alert.alert_id,
            severity=alert.overall_severity.value,
            confidence=alert.overall_confidence,
        )
        return alert
