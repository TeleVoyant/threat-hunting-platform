# visualization/subscriber.py
"""
Event-bus subscriber that maintains a live attack graph.

Subscribes: DETECTION_MADE
Output:     <output_dir>/current.html  (always the latest snapshot)
            <output_dir>/snap_<timestamp>.html  (optional history)

The web server (visualization/web.py) lists every HTML file in the dir
and serves the most-recent one as the dashboard's "live" attack graph.
"""

import time
from pathlib import Path
from typing import Optional

from shared.events  import bus, DETECTION_MADE
from shared.logging import get_logger
from visualization.graph_builder import AttackGraphBuilder
from visualization.renderer      import AttackGraphRenderer

logger = get_logger("visualization.subscriber")


class GraphSubscriber:

    def __init__(
        self,
        output_dir: str = "data/graphs",
        keep_snapshots: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.builder  = AttackGraphBuilder()
        self.renderer = AttackGraphRenderer()
        self.keep_snapshots = keep_snapshots

    def register(self) -> None:
        bus.subscribe(DETECTION_MADE, self.on_detection_made)
        logger.info("GraphSubscriber registered", output_dir=str(self.output_dir))

    async def on_detection_made(self, data: dict) -> None:
        detection = data.get("detection")
        events    = data.get("events", []) or []
        if detection is None:
            return

        try:
            self.builder.add_from_detection(detection, related_events=events)
        except Exception as e:
            logger.error("Graph update failed",
                         detection_id=getattr(detection, "detection_id", "?"),
                         error=str(e))
            return

        # Always update the "live" snapshot
        live_path = self.output_dir / "current.html"
        try:
            self.renderer.render_html(self.builder, str(live_path))
        except Exception as e:
            logger.error("Graph render failed", error=str(e))
            return

        # Optionally keep a timestamped history snapshot for forensic review
        if self.keep_snapshots:
            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            snap_path = self.output_dir / f"snap_{ts}_{detection.detection_id[:8]}.html"
            try:
                self.renderer.render_html(self.builder, str(snap_path))
            except Exception as e:
                logger.warning("Snapshot render failed", error=str(e))

        logger.info(
            "Attack graph updated",
            detection_id=detection.detection_id,
            nodes=self.builder.graph.number_of_nodes(),
            edges=self.builder.graph.number_of_edges(),
            file=str(live_path),
        )
