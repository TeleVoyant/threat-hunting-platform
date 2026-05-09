# alert_manager/wazuh_publisher.py
"""
Publishes EnrichedAlerts to Wazuh by writing Wazuh-format JSON to a file
the Wazuh Manager tails. Wazuh decoders + rules then surface them in the
Wazuh Dashboard alongside native alerts.

Why a log file (not the Wazuh API)?
-----------------------------------
Wazuh's REST API does not expose an "inject custom alert" endpoint —
alerts are produced by the manager's analysisd from logs that pass
through decoders + rules. The standard pattern for 3rd-party / AI alerts
is therefore to emit them as a log source the manager already knows how
to ingest.

Deployment requires a one-time Wazuh-side configuration:

  /var/ossec/etc/decoders/local_decoder.xml:
    <decoder name="apt-platform">
      <prematch>^\\{"timestamp":</prematch>
      <plugin_decoder>JSON_Decoder</plugin_decoder>
    </decoder>

  /var/ossec/etc/rules/local_rules.xml:
    <group name="apt_platform,">
      <rule id="100100" level="5">
        <decoded_as>apt-platform</decoded_as>
        <field name="rule.groups">apt_detection</field>
        <description>APT Platform detection: $(rule.description)</description>
      </rule>
      <rule id="100101" level="12">
        <if_sid>100100</if_sid>
        <field name="rule.level">^12$</field>
        <description>APT Platform CRITICAL: $(rule.description)</description>
      </rule>
    </group>

  /var/ossec/etc/ossec.conf:
    <localfile>
      <log_format>json</log_format>
      <location>/var/ossec/logs/external/apt_platform_alerts.json</location>
    </localfile>

The default file path here matches that location, assuming this container
mounts a shared volume with the wazuh-manager container.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.enums   import Severity
from shared.logging import get_logger
from shared.schemas import EnrichedAlert

logger = get_logger("alert_manager.wazuh_publisher")


# Severity → Wazuh log level (Wazuh levels: 0–15)
_SEVERITY_TO_LEVEL = {
    Severity.LOW:      5,
    Severity.MEDIUM:   8,
    Severity.HIGH:     10,
    Severity.CRITICAL: 12,
}

# Custom Wazuh rule ID range for AI Platform alerts (avoid collision with
# Wazuh's default rules at <100000).
_RULE_ID_BASE = 100100


class WazuhPublisher:

    def __init__(
        self,
        log_file_path: str = "/var/ossec/logs/external/apt_platform_alerts.json",
        max_file_bytes: int = 100 * 1024 * 1024,   # 100 MB, then rolled
    ):
        self.log_file = Path(log_file_path)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.max_file_bytes = max_file_bytes
        # File appends from a single subscriber thread, but use a lock as
        # defense in depth (and to make rotation atomic).
        self._lock = threading.Lock()
        # Sanity check writability at construction so we fail fast at startup.
        self.log_file.touch(exist_ok=True)
        logger.info("WazuhPublisher initialised", path=str(self.log_file))

    async def publish(self, alert: EnrichedAlert) -> None:
        """Append one Wazuh-formatted JSON line for this alert."""
        wazuh_event = self._to_wazuh_format(alert)
        line = json.dumps(wazuh_event, default=str) + "\n"

        with self._lock:
            self._maybe_rotate()
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                # fsync would be paranoid for alert delivery — Wazuh's tailer
                # picks up writes within ~1s anyway. Skip for throughput.

        logger.info(
            "Alert published to Wazuh log",
            alert_id=alert.alert_id,
            wazuh_level=wazuh_event["rule"]["level"],
            file=str(self.log_file),
        )

    # ── Wazuh format ────────────────────────────────────────────────────────

    def _to_wazuh_format(self, alert: EnrichedAlert) -> dict:
        """
        Map our EnrichedAlert into the canonical Wazuh alert JSON shape so
        the dashboard treats it like any other alert. Custom data lives
        under `data.ai_platform`.
        """
        wazuh_level = _SEVERITY_TO_LEVEL.get(alert.overall_severity, 5)
        rule_id = _RULE_ID_BASE + wazuh_level   # spread across our reserved range

        return {
            "timestamp": alert.timestamp.astimezone(timezone.utc).isoformat(),
            "rule": {
                "id":          str(rule_id),
                "level":       wazuh_level,
                "description": self._build_description(alert),
                "groups":      ["ai_platform", "apt_detection"]
                                + [t.split(" - ")[0] for t in alert.mitre_tactics],
                "mitre": {
                    "id":     alert.mitre_techniques,
                    "tactic": alert.mitre_tactics,
                },
            },
            "agent": {
                "id":   "000",
                "name": "ai-platform",
            },
            "manager": {"name": "ai-platform"},
            "location": "ai-platform/detection",
            "decoder":  {"name": "apt-platform"},
            "full_log":  self._build_description(alert),
            "data": {
                "ai_platform": {
                    "alert_id":            alert.alert_id,
                    "overall_confidence":  alert.overall_confidence,
                    "overall_severity":    alert.overall_severity.value,
                    "detector_count":      len(alert.detections),
                    "source_entities":     sorted(
                        {d.source_entity for d in alert.detections}
                    ),
                    "detections": [
                        {
                            "detector_name": d.detector_name,
                            "detection_type": d.detection_type.value,
                            "confidence":    d.confidence,
                            "source_entity": d.source_entity,
                            "mitre":         d.mitre_techniques,
                        }
                        for d in alert.detections
                    ],
                    "recommended_actions": alert.recommended_actions,
                },
            },
        }

    @staticmethod
    def _build_description(alert: EnrichedAlert) -> str:
        if not alert.detections:
            return f"AI Platform alert {alert.alert_id}"
        types = sorted({d.detection_type.value for d in alert.detections})
        entities = sorted({d.source_entity for d in alert.detections})
        return (
            f"{alert.overall_severity.value.upper()} | "
            f"{', '.join(types)} | "
            f"entities={','.join(entities)} | "
            f"confidence={alert.overall_confidence:.0%}"
        )

    # ── File rotation ───────────────────────────────────────────────────────

    def _maybe_rotate(self) -> None:
        """Roll the log file when it exceeds max_file_bytes. Caller holds lock."""
        try:
            if self.log_file.exists() and self.log_file.stat().st_size >= self.max_file_bytes:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                rolled = self.log_file.with_suffix(f".{ts}.json")
                self.log_file.rename(rolled)
                self.log_file.touch()
                logger.info("Wazuh alert log rotated",
                            old=str(rolled), new=str(self.log_file))
        except OSError as e:
            logger.warning("Log rotation skipped", error=str(e))
