# visualization/renderer.py
import json
import os
import time
from html import escape

from pyvis.network import Network
from visualization.graph_builder import AttackGraphBuilder

_SEV_ORDER = ["low", "medium", "high", "critical"]


class AttackGraphRenderer:
    """Renders attack graph to interactive HTML page."""

    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
    }

    # Human labels for the edge_type AttackGraphBuilder stamps on each edge.
    _EDGE_KIND = {
        "lateral_movement": "Lateral movement",
        "dns_exfiltration": "DNS exfiltration",
    }

    # pyvis 0.3.2 renders a node/edge `title` via `popup.innerHTML = title`
    # (templates/template.html), so tooltips are HTML - every telemetry-derived
    # field below is escape()'d to keep a hostile hostname/domain from injecting
    # markup into the operator's browser.

    @classmethod
    def _edge_tooltip(cls, data: dict) -> str:
        """
        Hover card for an attack edge. Surfaces the SHAP `top_feature` that the
        builder already records but the graph never displayed: once the
        detectors are feature-domain restricted, a DNS-exfil edge shows a
        `dns__*` driver and a lateral edge an auth/network driver, so the
        model's reasoning is legible right on the attack path.
        """
        kind = cls._EDGE_KIND.get(data.get("edge_type", ""), "Detection")
        conf = data.get("confidence") or 0.0
        tech = data.get("technique") or "-"
        feat = data.get("top_feature") or "-"
        ts = (data.get("timestamp") or "")[:19]
        rows = [
            f"<b>{escape(kind)}</b>",
            f"Confidence: {conf:.0%}",
            f"MITRE: {escape(tech)}",
            f"Top feature: {escape(feat)}",
        ]
        if ts:
            rows.append(f"<span style='color:#9ca3af'>{escape(ts)} UTC</span>")
        return "<br>".join(rows)

    @staticmethod
    def _node_tooltip(node_id: str, data: dict) -> str:
        ntype = ("External domain" if data.get("node_type") == "external"
                 else "Host / entity")
        sev = data.get("severity", "low")
        return (f"<b>{escape(str(node_id))}</b><br>{escape(ntype)}"
                f"<br>Worst severity: {escape(str(sev))}")

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
            net.add_node(
                node_id, label=node_id, color=color, shape=shape, size=25,
                title=self._node_tooltip(node_id, data),
            )

        for src, dst, data in builder.graph.edges(data=True):
            conf = data.get("confidence", 0) or 0
            net.add_edge(
                src,
                dst,
                title=self._edge_tooltip(data),
                label=data.get("technique", ""),
                color="#ef4444" if conf > 0.7 else "#fbbf24",
                width=2,
            )

        net.save_graph(output_path)
        self._write_meta(builder, output_path)
        return output_path

    @staticmethod
    def _write_meta(builder: AttackGraphBuilder, output_path: str) -> None:
        """
        Emit a small `<stem>.meta.json` sidecar next to the rendered HTML so
        downstream viewers (the standalone 8080 page, the dashboard) can show a
        structured summary - node/edge counts, severity breakdown, and the mix
        of lateral vs DNS-exfil edges - without parsing the pyvis HTML. The
        standalone viewer mounts data/graphs read-only, so this is the only way
        it can surface graph state. Best-effort: a failure here never blocks the
        graph render itself.
        """
        try:
            g = builder.graph
            severity: dict = {}
            external = 0
            for _, d in g.nodes(data=True):
                if d.get("node_type") == "external":
                    external += 1
                s = d.get("severity", "low")
                severity[s] = severity.get(s, 0) + 1
            edge_types: dict = {}
            for _, _, d in g.edges(data=True):
                et = d.get("edge_type", "other")
                edge_types[et] = edge_types.get(et, 0) + 1
            present = [s for s in _SEV_ORDER if severity.get(s)]
            meta = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "nodes": g.number_of_nodes(),
                "edges": g.number_of_edges(),
                "host_nodes": g.number_of_nodes() - external,
                "external_nodes": external,
                "severity": severity,
                "worst_severity": present[-1] if present else None,
                "edge_types": edge_types,
            }
            meta_path = os.path.splitext(output_path)[0] + ".meta.json"
            with open(meta_path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
        except Exception:
            # Never let a sidecar write failure break the graph itself.
            pass
