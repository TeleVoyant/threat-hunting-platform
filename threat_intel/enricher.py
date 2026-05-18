"""
Threat Intelligence Enricher.

Takes raw Detections and enriches them with:
- MITRE ATT&CK technique/tactic descriptions
- MISP IoC correlation (if available)
- Recommended response actions
"""

import uuid
from datetime import datetime
from typing import Optional

from shared.schemas import Detection, EnrichedAlert
from shared.enums import Severity
from shared.logging import get_logger
from threat_intel.misp_client import MispClient

logger = get_logger("threat_intel.enricher")

# MITRE ATT&CK technique → tactic mapping (subset relevant to this platform)
TECHNIQUE_TO_TACTIC = {
    "T1003": "TA0006 - Credential Access",
    "T1003.001": "TA0006 - Credential Access",
    "T1021": "TA0008 - Lateral Movement",
    "T1021.002": "TA0008 - Lateral Movement",
    "T1550": "TA0008 - Lateral Movement",
    "T1550.002": "TA0008 - Lateral Movement",
    "T1078": "TA0001 - Initial Access / TA0003 - Persistence",
    "T1048": "TA0010 - Exfiltration",
    "T1048.001": "TA0010 - Exfiltration",
    "T1071.004": "TA0011 - Command and Control",
}

TECHNIQUE_DESCRIPTIONS = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1550.002": "Use Alternate Authentication: Pass the Hash",
    "T1078": "Valid Accounts",
    "T1048.001": "Exfiltration Over Alternative Protocol: DNS",
    "T1071.004": "Application Layer Protocol: DNS",
}

RESPONSE_ACTIONS = {
    "credential_lateral_movement": [
        "Isolate affected hosts from the network",
        "Reset credentials for compromised accounts",
        "Check for additional compromised hosts on the lateral movement path",
        "Review Kerberos ticket activity for Golden/Silver ticket attacks",
        "Enable enhanced monitoring on affected subnet",
    ],
    "dns_covert_exfiltration": [
        "Block the suspicious DNS domain at the firewall/DNS resolver",
        "Capture full DNS traffic from the source host",
        "Check for data staging on the source host",
        "Review DNS query logs for the past 7 days for this domain",
        "Assess what data may have been exfiltrated",
    ],
}


class ThreatIntelEnricher:

    def __init__(self, misp_client: Optional[MispClient] = None):
        # MISP correlation is optional. When supplied, populates
        # EnrichedAlert.ioc_matches with hits against IPs/domains/hashes
        # observed in the related events.
        self.misp = misp_client

    def enrich(self, detections: list[Detection],
                related_events: Optional[list] = None) -> EnrichedAlert:
        """Enrich a list of related detections into a single alert.
        related_events: optional NormalizedEvent list whose IPs/domains/hashes
        get cross-referenced against the MISP IoC index."""

        all_techniques = []
        all_tactics = set()

        for det in detections:
            all_techniques.extend(det.mitre_techniques)
            for tech in det.mitre_techniques:
                tactic = TECHNIQUE_TO_TACTIC.get(tech, "")
                if tactic:
                    all_tactics.add(tactic)

        # Determine overall severity (worst of all detections)
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        worst_severity = max(detections, key=lambda d: severity_order.index(d.severity)).severity

        # Escalate if BOTH lateral movement AND exfiltration are detected (full kill chain)
        detection_types = set(d.detection_type.value for d in detections)
        if len(detection_types) > 1:
            worst_severity = Severity.CRITICAL

        # Gather response actions
        actions = []
        for det in detections:
            det_actions = RESPONSE_ACTIONS.get(det.detection_type.value, [])
            actions.extend(det_actions)
        actions = list(dict.fromkeys(actions))  # Deduplicate preserving order

        overall_confidence = max(d.confidence for d in detections)

        # ── MISP IoC correlation (FR-06) ────────────────────────────────────
        ioc_matches: list[dict] = []
        if self.misp is not None and related_events:
            ips = sorted({e.dest_ip for e in related_events if e.dest_ip} |
                          {e.source_ip for e in related_events if e.source_ip})
            # Base domains from any DNS query
            domains = set()
            for e in related_events:
                if e.dns_query:
                    parts = e.dns_query.rstrip(".").split(".")
                    if len(parts) >= 2:
                        domains.add(".".join(parts[-2:]))
            try:
                ioc_matches = self.misp.match(
                    ips=ips, domains=sorted(domains),
                )
                if ioc_matches:
                    logger.info("MISP IoC matches found",
                                count=len(ioc_matches),
                                indicators=[m["indicator"] for m in ioc_matches])
                    # Any IoC match escalates severity to CRITICAL — by
                    # definition the source is on a known-bad list
                    worst_severity = Severity.CRITICAL
            except Exception as e:
                logger.warning("MISP correlation failed", error=str(e))

        alert = EnrichedAlert(
            alert_id=f"alert_{uuid.uuid4().hex[:12]}",
            detections=detections,
            overall_severity=worst_severity,
            overall_confidence=overall_confidence,
            mitre_techniques=list(set(all_techniques)),
            mitre_tactics=sorted(all_tactics),
            ioc_matches=ioc_matches,
            attack_path=None,  # Filled by visualization module
            recommended_actions=actions,
            timestamp=datetime.utcnow(),
        )

        logger.info(
            "Alert enriched",
            alert_id=alert.alert_id,
            severity=alert.overall_severity.value,
            techniques=alert.mitre_techniques,
            tactics=len(alert.mitre_tactics),
        )

        return alert
