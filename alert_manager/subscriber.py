# alert_manager/subscriber.py
"""
Event-bus subscriber that turns Detections into stored, published EnrichedAlerts.

Subscribes: DETECTION_MADE
Emits:      ALERT_ENRICHED   (after enrichment + persistence)
            ALERT_PUBLISHED  (after successful publish to Wazuh)

Per detection:
  1. Dedup check against AlertStore (same source + detector within window)
  2. ThreatIntelEnricher.enrich([detection]) → EnrichedAlert
  3. AlertStore.store_alert(alert)
  4. emit ALERT_ENRICHED
  5. WazuhPublisher.publish(alert)
  6. emit ALERT_PUBLISHED  (only on successful publish — failures are logged
     but don't break the chain; the alert is already in the store and
     queryable via /alerts)

Why per-detection rather than batched?
--------------------------------------
A future improvement is to bundle related detections (same source_entity
within ~30s) into a single EnrichedAlert so the enricher can escalate to
CRITICAL when BOTH lateral_movement AND dns_exfiltration fire on the same
host (full kill chain). For the FYP scaffold we ship per-detection alerts
and rely on the dashboard to surface the correlation visually.
"""

from typing import Optional

from alert_manager.store         import AlertStore
from alert_manager.wazuh_publisher import WazuhPublisher
from observability.audit         import AuditTrail
from shared.events               import bus, DETECTION_MADE, ALERT_ENRICHED, ALERT_PUBLISHED
from shared.logging              import get_logger
from shared.schemas              import Detection, EnrichedAlert
from threat_intel.enricher       import ThreatIntelEnricher

logger = get_logger("alert_manager.subscriber")


class AlertSubscriber:

    def __init__(
        self,
        enricher:  ThreatIntelEnricher,
        store:     AlertStore,
        publisher: WazuhPublisher,
        audit:     Optional[AuditTrail] = None,
        dedup_window_minutes: int = 30,
    ):
        self.enricher = enricher
        self.store    = store
        self.publisher = publisher
        self.audit    = audit
        self.dedup_window = dedup_window_minutes

    def register(self) -> None:
        bus.subscribe(DETECTION_MADE, self.on_detection_made)
        logger.info("AlertSubscriber registered",
                    dedup_window_minutes=self.dedup_window)

    async def on_detection_made(self, data: dict) -> None:
        det: Detection = data.get("detection")
        if det is None:
            logger.warning("DETECTION_MADE arrived with no detection in payload")
            return

        # ── 1. Dedup ──────────────────────────────────────────────────────────
        if self.store.is_duplicate(
            det.source_entity, det.detector_name, self.dedup_window
        ):
            logger.debug(
                "Suppressing duplicate detection",
                detector=det.detector_name,
                entity=det.source_entity,
                window_min=self.dedup_window,
            )
            return

        # ── 2. Enrich ─────────────────────────────────────────────────────────
        try:
            alert: EnrichedAlert = self.enricher.enrich([det])
        except Exception as e:
            logger.error("Enrichment failed",
                         detector=det.detector_name, error=str(e))
            return

        # ── 3. Persist ────────────────────────────────────────────────────────
        try:
            self.store.store_alert(alert)
        except Exception as e:
            logger.error("Persist failed",
                         alert_id=alert.alert_id, error=str(e))
            return

        await bus.emit(ALERT_ENRICHED, {"alert": alert})

        if self.audit:
            self.audit.log(
                action="alert.enriched",
                actor="platform",
                target=alert.alert_id,
                details={
                    "severity":   alert.overall_severity.value,
                    "confidence": alert.overall_confidence,
                    "detectors":  [d.detector_name for d in alert.detections],
                    "techniques": alert.mitre_techniques,
                },
            )

        # ── 4. Publish to Wazuh ──────────────────────────────────────────────
        try:
            await self.publisher.publish(alert)
        except Exception as e:
            # Publish failure is non-fatal — alert is in the store and
            # admins can still see + acknowledge it via /alerts.
            logger.error("Publish to Wazuh failed",
                         alert_id=alert.alert_id, error=str(e))
            return

        await bus.emit(ALERT_PUBLISHED, {"alert": alert})
        logger.info(
            "Alert dispatched",
            alert_id=alert.alert_id,
            severity=alert.overall_severity.value,
            confidence=round(alert.overall_confidence, 3),
            techniques=alert.mitre_techniques,
        )
