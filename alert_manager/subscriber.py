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

import asyncio
import time
from collections import defaultdict
from typing import Optional

from alert_manager.alert_engine  import AlertEngine
from alert_manager.store         import AlertStore
from alert_manager.wazuh_publisher import WazuhPublisher
from observability.audit         import AuditTrail
from shared.enums                import Severity
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
        engine:    Optional[AlertEngine] = None,
        dedup_window_minutes: int = 30,
        correlation_window_seconds: int = 300,
    ):
        self.enricher = enricher
        self.store    = store
        self.publisher = publisher
        self.audit    = audit
        self.engine   = engine
        self.dedup_window = dedup_window_minutes
        # Per-entity recent detections for kill-chain correlation (z). Tuple
        # of (timestamp, detector_name, detection_id). When ≥2 distinct
        # detectors fire on the same source_entity inside the window, we
        # emit a bundled CRITICAL alert with the union of MITRE techniques.
        self.correlation_window_seconds = correlation_window_seconds
        self._recent: dict[str, list[tuple[float, str, Detection]]] = defaultdict(list)
        # Per-entity flag — once we've fired a correlated alert for this
        # source_entity within the window, don't re-fire on every further
        # detection in the same chain.
        self._correlated_until: dict[str, float] = {}

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
        # Pass the events that triggered this detection so the enricher can
        # pull IPs/domains for MISP IoC correlation. Older enricher versions
        # ignored the kwarg; we use a guarded call for back-compat.
        events = data.get("events", []) or []
        try:
            try:
                alert: EnrichedAlert = self.enricher.enrich([det], related_events=events)
            except TypeError:
                # Enricher predates the related_events kwarg
                alert = self.enricher.enrich([det])
        except Exception as e:
            logger.error("Enrichment failed",
                         detector=det.detector_name, error=str(e))
            return

        # Thread the correlation_id from the poll-cycle through the alert (ee)
        # so a single Wazuh pull's full chain (ingest → detect → publish) is
        # one grep away in the logs.
        corr_id = data.get("correlation_id") or det.correlation_id
        if corr_id and not alert.correlation_id:
            alert.correlation_id = corr_id

        # ── 2b. Engine gate ───────────────────────────────────────────────────
        # AlertEngine.process() returns None to suppress below-threshold alerts.
        if self.engine is not None:
            alert = self.engine.process(alert)
            if alert is None:
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
            correlation_id=alert.correlation_id,
        )

        # ── 5. Multi-detector correlation (z) ───────────────────────────────
        await self._maybe_correlate(det, events)

    # ── Correlation buffer ─────────────────────────────────────────────────

    async def _maybe_correlate(
        self, det: Detection, events: list
    ) -> None:
        """Bundle related detections on the same source_entity into a
        CRITICAL kill-chain alert when ≥2 distinct detectors fire within the
        correlation window."""
        now = time.time()
        entity = det.source_entity or "unknown"

        # GC stale entries up front so the buffer can't grow unbounded.
        cutoff = now - self.correlation_window_seconds
        recent = [t for t in self._recent[entity] if t[0] >= cutoff]
        recent.append((now, det.detector_name, det))
        self._recent[entity] = recent

        if self._correlated_until.get(entity, 0.0) >= now:
            return  # Already fired the chain alert for this entity recently.

        distinct = {t[1] for t in recent}
        if len(distinct) < 2:
            return

        # Build a bundled EnrichedAlert from all detections in the window.
        chain_detections = [t[2] for t in recent]
        try:
            try:
                bundle = self.enricher.enrich(chain_detections, related_events=events)
            except TypeError:
                bundle = self.enricher.enrich(chain_detections)
        except Exception as e:
            logger.error("Chain enrichment failed",
                         entity=entity, error=str(e))
            return

        # Escalate — full kill chain on one entity is CRITICAL by definition.
        bundle.overall_severity = Severity.CRITICAL
        bundle.overall_confidence = max(d.confidence for d in chain_detections)
        if det.correlation_id and not bundle.correlation_id:
            bundle.correlation_id = det.correlation_id

        try:
            self.store.store_alert(bundle)
        except Exception as e:
            logger.error("Chain alert persist failed",
                         alert_id=bundle.alert_id, error=str(e))
            return

        await bus.emit(ALERT_ENRICHED, {"alert": bundle})
        try:
            await self.publisher.publish(bundle)
            await bus.emit(ALERT_PUBLISHED, {"alert": bundle})
        except Exception as e:
            logger.error("Chain alert publish failed",
                         alert_id=bundle.alert_id, error=str(e))

        if self.audit:
            self.audit.log(
                action="alert.chain_correlated", actor="platform",
                target=bundle.alert_id,
                details={
                    "entity":    entity,
                    "detectors": sorted(distinct),
                    "window_s":  self.correlation_window_seconds,
                },
            )
        logger.warning(
            "Multi-detector chain alert fired",
            alert_id=bundle.alert_id, entity=entity,
            detectors=sorted(distinct),
        )
        # Suppress further chain alerts for this entity until the window ages.
        self._correlated_until[entity] = now + self.correlation_window_seconds
