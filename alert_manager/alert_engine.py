"""
Alert Engine: post-enrichment gate that suppresses alerts below a minimum
confidence threshold before they reach the store and publisher.

Called by AlertSubscriber between enrichment and persistence. Returns None
to suppress the alert, or the (possibly mutated) alert to continue.
"""

from typing import Optional

from shared.schemas import EnrichedAlert
from shared.logging import get_logger

logger = get_logger("alert_manager.alert_engine")


class AlertEngine:

    def __init__(self, config: dict = None):
        self.config = config or {}
        # Set slightly below the DetectionSubscriber per-detector threshold
        # (default 0.5) so this gate only catches edge cases that slip through,
        # e.g., multi-detection bundles whose overall_confidence is re-scored
        # lower during enrichment.
        self.min_confidence: float = float(
            self.config.get("min_confidence", 0.45)
        )

    def process(self, alert: EnrichedAlert) -> Optional[EnrichedAlert]:
        """Validate and gate an enriched alert.

        Returns None to suppress the alert, or the alert to allow it through.
        """
        if alert.overall_confidence < self.min_confidence:
            logger.info(
                "Alert suppressed — below min_confidence",
                alert_id=alert.alert_id,
                confidence=round(alert.overall_confidence, 3),
                threshold=self.min_confidence,
            )
            return None

        logger.debug(
            "Alert passed engine gate",
            alert_id=alert.alert_id,
            severity=alert.overall_severity.value,
            confidence=round(alert.overall_confidence, 3),
        )
        return alert
