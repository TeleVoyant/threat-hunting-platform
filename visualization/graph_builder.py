# visualization/graph_builder.py
"""
Builds attack-path graphs from detections.

Each detection contributes:
  - A node for the source entity (the compromised laptop / credential)
  - One or more edges to inferred destinations:
      * lateral movement → distinct dest_ips from the network events
        that triggered the detection
      * DNS exfiltration → distinct base domains from the DNS events
        that triggered the detection

Edges carry: MITRE technique IDs, confidence, top SHAP feature, timestamp.
The renderer (visualization/renderer.py) turns this graph into an
interactive pyvis HTML page colored by severity.
"""

from collections import Counter
from typing import Iterable, Optional

import networkx as nx

from shared.allowlist import get_default as get_dns_allowlist
from shared.schemas import Detection, NormalizedEvent


# Fallback set used when no admin-managed allowlist has been wired (CLI
# tests, training scripts, etc.). At runtime, `shared.allowlist.get_default()`
# is consulted FIRST — so admin add/remove operations take effect immediately
# without a graph rebuild.
_FALLBACK_BENIGN_DOMAINS = frozenset({
    "windowsupdate.com", "microsoft.com", "windows.com", "msftncsi.com",
    "msftconnecttest.com", "office.com", "office365.com", "live.com",
    "msedge.net", "google.com", "googleapis.com", "github.com",
    "github.io", "mozilla.org",
})


def _is_benign_domain(domain: str) -> bool:
    """Live allowlist if configured, fallback set otherwise."""
    al = get_dns_allowlist()
    if al is not None:
        return al.contains(domain)
    return domain.lower() in _FALLBACK_BENIGN_DOMAINS


class AttackGraphBuilder:

    def __init__(self):
        self.graph = nx.MultiDiGraph()  # multi-edge: one entity may attack same dest via multiple techniques

    # ── Public API ─────────────────────────────────────────────────────────

    def add_from_detection(
        self,
        detection: Detection,
        related_events: Optional[list[NormalizedEvent]] = None,
    ) -> None:
        """
        Add a detection to the graph, inferring destinations from the events
        that triggered it.
        """
        related_events = related_events or []
        self._upsert_node(
            detection.source_entity,
            node_type="host",
            severity=detection.severity.value,
        )

        # Most-influential SHAP feature, used as edge label context
        top_feature = ""
        if detection.contributing_features:
            top_feature = max(
                detection.contributing_features.items(),
                key=lambda kv: abs(kv[1]),
            )[0]

        # Route by detection type
        dtype = (
            detection.detection_type.value
            if hasattr(detection.detection_type, "value")
            else str(detection.detection_type)
        )

        if dtype == "credential_lateral_movement":
            for dest in self._lateral_destinations(related_events):
                self._upsert_node(dest, node_type="host")
                self.graph.add_edge(
                    detection.source_entity,
                    dest,
                    detection_id=detection.detection_id,
                    technique=", ".join(detection.mitre_techniques),
                    confidence=detection.confidence,
                    timestamp=detection.timestamp.isoformat(),
                    top_feature=top_feature,
                    label=f"Lateral ({detection.confidence:.0%})",
                    edge_type="lateral_movement",
                )

        elif dtype == "dns_covert_exfiltration":
            for domain in self._dns_destinations(related_events):
                ext_node = f"DNS-EXT: {domain}"
                self._upsert_node(ext_node, node_type="external")
                self.graph.add_edge(
                    detection.source_entity,
                    ext_node,
                    detection_id=detection.detection_id,
                    technique=", ".join(detection.mitre_techniques),
                    confidence=detection.confidence,
                    timestamp=detection.timestamp.isoformat(),
                    top_feature=top_feature,
                    label=f"DNS Exfil ({detection.confidence:.0%})",
                    edge_type="dns_exfiltration",
                )
        else:
            # Unknown detection type — still record the source node so the
            # operator can see SOMETHING happened on this entity
            return

    # Backwards-compat shim so the old graph-builder test code still works.
    def add_detection(self, detection: Detection) -> None:
        self.add_from_detection(detection, related_events=[])

    def to_dict(self) -> dict:
        """Export as JSON-serializable dict for /attack-graph API."""
        return nx.node_link_data(self.graph)

    # ── Internals ──────────────────────────────────────────────────────────

    def _upsert_node(self, node_id: str, **attrs) -> None:
        """Add or update node attributes; promote severity to the worst seen."""
        existing = self.graph.nodes.get(node_id, {})
        new_attrs = dict(existing)
        for k, v in attrs.items():
            # severity uses worst-of-all rule (critical > high > medium > low)
            if k == "severity":
                order = ["low", "medium", "high", "critical"]
                cur = new_attrs.get("severity", "low")
                if order.index(v) > order.index(cur):
                    new_attrs[k] = v
            else:
                new_attrs[k] = v
        self.graph.add_node(node_id, **new_attrs)

    @staticmethod
    def _lateral_destinations(events: Iterable[NormalizedEvent]) -> list[str]:
        """Distinct destination IPs from network events with lateral-movement ports."""
        LATERAL_PORTS = {445, 3389, 5985, 5986, 135, 22, 23, 139}
        seen: Counter = Counter()
        for e in events:
            if e.event_type == "network" and e.dest_ip and e.dest_port in LATERAL_PORTS:
                seen[e.dest_ip] += 1
        # Sort by frequency so the most-targeted hosts render with higher rank
        return [ip for ip, _ in seen.most_common()]

    @staticmethod
    def _dns_destinations(events: Iterable[NormalizedEvent]) -> list[str]:
        """
        Distinct base domains from DNS query events, excluding any in the
        admin-managed DNS allowlist (or the fallback set in CLI contexts).
        Admin operations against the allowlist take effect immediately —
        no graph rebuild required.
        """
        seen: Counter = Counter()
        for e in events:
            if e.event_type == "dns_query" and e.dns_query:
                parts = e.dns_query.rstrip(".").split(".")
                base = ".".join(parts[-2:]) if len(parts) >= 2 else e.dns_query
                if _is_benign_domain(base):
                    continue
                seen[base] += 1
        return [d for d, _ in seen.most_common()]
