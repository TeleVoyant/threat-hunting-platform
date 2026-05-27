# alert_manager/notification_subscriber.py
"""
Subscribes to ALERT_ENRICHED on the event bus and forwards the alert to
NotificationService. Kept separate from AlertSubscriber so notifications can
fail independently of the alert-persistence pipeline.
"""

from shared.events import bus, ALERT_ENRICHED
from shared.logging import get_logger

logger = get_logger("alert_manager.notification_subscriber")


class NotificationSubscriber:

    def __init__(self, service):
        self.service = service

    def register(self) -> None:
        bus.subscribe(ALERT_ENRICHED, self.on_alert_enriched)
        logger.info("NotificationSubscriber registered")

    async def on_alert_enriched(self, data: dict) -> None:
        alert = data.get("alert")
        if alert is None:
            return
        try:
            count = await self.service.dispatch(alert)
            if count:
                logger.info("Notifications dispatched",
                            alert_id=getattr(alert, "alert_id", None),
                            recipients=count)
        except Exception as e:
            logger.error("Notification dispatch failed",
                          alert_id=getattr(alert, "alert_id", None),
                          error=str(e))
