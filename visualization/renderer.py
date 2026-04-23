# visualization/renderer.py
from pyvis.network import Network
from visualization.graph_builder import AttackGraphBuilder


class AttackGraphRenderer:
    """Renders attack graph to interactive HTML page."""

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
    }

    def render_html(self, builder: AttackGraphBuilder, output_path: str) -> str:
        net = Network(
            height="700px",
            width="100%",
            directed=True,
            bgcolor="#1e1e1e",
            font_color="white",
        )

        for node_id, data in builder.graph.nodes(data=True):
            color = self.SEVERITY_COLORS.get(data.get("severity", "low"), "#6b7280")
            shape = "diamond" if data.get("node_type") == "external" else "dot"
            net.add_node(node_id, label=node_id, color=color, shape=shape, size=25)

        for src, dst, data in builder.graph.edges(data=True):
            net.add_edge(
                src,
                dst,
                title=data.get("label", ""),
                label=data.get("technique", ""),
                color="#ef4444" if data.get("confidence", 0) > 0.7 else "#fbbf24",
                width=2,
            )

        net.save_graph(output_path)
        return output_path
