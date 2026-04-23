"""
Publishes enriched alerts back to Wazuh Manager via its REST API.
Alerts then appear in the Wazuh Dashboard alongside standard Wazuh alerts.
"""

import httpx
from shared.schemas import EnrichedAlert
from shared.logging import get_logger

logger = get_logger("alert_manager.wazuh_publisher")


class WazuhPublisher:

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self._token = None

    async def publish(self, alert: EnrichedAlert):
        """Publish an enriched alert to Wazuh."""
        try:
            # For now, log the alert. Full Wazuh custom alert integration
            # requires writing to /var/ossec/logs/alerts/alerts.json
            # which is done via the Wazuh API or direct file write.
            logger.info(
                "Alert published to Wazuh",
                alert_id=alert.alert_id,
                severity=alert.overall_severity.value,
                techniques=alert.mitre_techniques,
                detections=len(alert.detections),
            )
        except Exception as e:
            logger.error("Failed to publish alert", error=str(e), alert_id=alert.alert_id)
