# visualization/graph_builder.py
import networkx as nx
from shared.schemas import Detection, EnrichedAlert


class AttackGraphBuilder:
    """
    Builds attack path graphs from correlated detections.
    No Neo4j needed — pure Python with NetworkX.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_detection(self, detection: Detection):
        """Add a detection as a node + edge in the attack graph."""

        # Node = affected entity (IP/hostname)
        self.graph.add_node(
            detection.source_entity,
            node_type="host",
            severity=detection.severity.value,
        )

        # If lateral movement, add edge to destination
        if detection.detection_type == "credential_lateral_movement":
            # Extract dest from contributing features
            dest = detection.contributing_features.get("dest_entity", "unknown")
            self.graph.add_node(dest, node_type="host")
            self.graph.add_edge(
                detection.source_entity,
                dest,
                technique=", ".join(detection.mitre_techniques),
                confidence=detection.confidence,
                timestamp=detection.timestamp.isoformat(),
                label=f"Lateral Movement ({detection.confidence:.0%})",
            )

        # If DNS exfiltration, add edge to external
        if detection.detection_type == "dns_covert_exfiltration":
            ext_node = "EXTERNAL (DNS tunnel)"
            self.graph.add_node(ext_node, node_type="external")
            self.graph.add_edge(
                detection.source_entity,
                ext_node,
                technique=", ".join(detection.mitre_techniques),
                confidence=detection.confidence,
                timestamp=detection.timestamp.isoformat(),
                label=f"DNS Exfiltration ({detection.confidence:.0%})",
            )

    def to_dict(self) -> dict:
        """Export graph as JSON-serializable dict for API responses."""
        return nx.node_link_data(self.graph)
