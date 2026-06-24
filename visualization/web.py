"""
Standalone web server for attack-graph visualization (port 8080).

Read-only companion to the authenticated dashboard view (/dashboard/graph on
the main API). It mounts data/graphs read-only and renders whatever the
GraphSubscriber (in the API process) writes:

  - <dir>/current.html       latest live graph (pyvis)
  - <dir>/current.meta.json  structured summary sidecar (renderer._write_meta)
  - <dir>/snap_*.html        timestamped history snapshots

The page embeds the live graph, the same legend the dashboard shows, and a
summary built from the meta sidecar, so the SHAP `top_feature` / MITRE /
severity context surfaced by the renderer is legible here too.
"""

import json
import re
from html import escape
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse

app = FastAPI(title="Attack Graph Visualization")

GRAPH_DIR = Path("data/graphs")

_SEV_COLORS = {
    "critical": "#dc2626", "high": "#ea580c",
    "medium": "#d97706", "low": "#65a30d",
}

# Shared legend - mirrors the dashboard graph.html so the two viewers explain
# the graph identically (node colour = severity, shape = host/external, edge
# colour = confidence, hover = MITRE + top SHAP feature).
_LEGEND = """
<div class="card">
  <h3>Legend</h3>
  <div class="muted">Node colour = worst severity</div>
  <div class="row">
    <span><i class="dot" style="background:#dc2626"></i>critical</span>
    <span><i class="dot" style="background:#ea580c"></i>high</span>
    <span><i class="dot" style="background:#d97706"></i>medium</span>
    <span><i class="dot" style="background:#65a30d"></i>low</span>
  </div>
  <div class="muted" style="margin-top:10px;">Shape</div>
  <div>&#9679; host / entity &nbsp;&middot;&nbsp; &#9670; external domain (DNS exfil target)</div>
  <div class="muted" style="margin-top:10px;">Edge colour = confidence</div>
  <div><span style="color:#ef4444;">&#9473;</span> &gt; 70% &nbsp;&middot;&nbsp;
       <span style="color:#fbbf24;">&#9473;</span> &le; 70%</div>
  <div class="muted" style="margin-top:10px; border-top:1px solid #334155; padding-top:8px;">
    Hover an edge for MITRE technique, confidence, and the top SHAP feature
    that drove the detection.
  </div>
</div>
"""


def _read_meta() -> dict:
    """Best-effort read of the current graph's summary sidecar."""
    try:
        return json.loads((GRAPH_DIR / "current.meta.json").read_text())
    except Exception:
        return {}


def _summary_chips(meta: dict) -> str:
    if not meta:
        return ""
    chips = [
        f'<span class="chip">{int(meta.get("nodes", 0))} nodes</span>',
        f'<span class="chip">{int(meta.get("edges", 0))} edges</span>',
    ]
    etypes = meta.get("edge_types") or {}
    if etypes.get("lateral_movement"):
        chips.append(f'<span class="chip">{int(etypes["lateral_movement"])} lateral</span>')
    if etypes.get("dns_exfiltration"):
        chips.append(f'<span class="chip">{int(etypes["dns_exfiltration"])} DNS exfil</span>')
    worst = meta.get("worst_severity")
    if worst in _SEV_COLORS:
        chips.append(
            f'<span class="chip" style="border-color:{_SEV_COLORS[worst]};'
            f'color:{_SEV_COLORS[worst]};">worst: {escape(str(worst))}</span>'
        )
    gen = meta.get("generated_at")
    if gen:
        chips.append(f'<span class="chip muted-chip">updated {escape(str(gen))}</span>')
    return '<div class="chips">' + "".join(chips) + "</div>"


def _snapshot_items() -> str:
    """Snapshot links with readable UTC timestamps parsed from the filename."""
    if not GRAPH_DIR.exists():
        return "<li class='muted'>none</li>"
    snaps = sorted(
        (p for p in GRAPH_DIR.glob("snap_*.html")), reverse=True
    )[:50]
    if not snaps:
        return "<li class='muted'>none yet</li>"
    items = []
    for p in snaps:
        name = escape(p.name)
        m = re.match(r"snap_(\d{8})T(\d{6})Z_([0-9a-fA-F]+)", p.stem)
        if m:
            d, t, did = m.groups()
            label = (f"{d[:4]}-{d[4:6]}-{d[6:8]} {t[:2]}:{t[2:4]}:{t[4:6]}Z "
                     f"&middot; {escape(did)}")
        else:
            label = escape(p.stem)
        items.append(f'<li><a href="/graph/{name}" target="_blank">{label}</a></li>')
    return "".join(items)


@app.get("/", response_class=HTMLResponse)
async def index():
    has_current = (GRAPH_DIR / "current.html").exists()
    meta = _read_meta()
    if has_current:
        graph_block = (
            '<iframe src="/graph/current.html" title="Live attack graph" '
            'style="width:100%; height:720px; border:0; border-radius:8px; '
            'background:#1e1e1e;"></iframe>'
        )
    else:
        graph_block = (
            '<div class="card" style="text-align:center; padding:48px; color:#94a3b8;">'
            'No attack graph rendered yet. Detections will populate this graph '
            'automatically as they fire.</div>'
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Attack Path Visualizations</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background:#0f172a; color:#e2e8f0; margin:0; padding:20px; font-size:14px; }}
    h1 {{ font-size:20px; margin:0 0 4px 0; }}
    h3 {{ font-size:12px; text-transform:uppercase; letter-spacing:.5px;
          color:#94a3b8; margin:0 0 8px 0; }}
    a {{ color:#38bdf8; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
    .muted {{ color:#94a3b8; font-size:12px; }}
    .layout {{ display:grid; grid-template-columns: 3fr 1fr; gap:16px; margin-top:14px; }}
    .card {{ background:#1e293b; border-radius:8px; padding:14px 16px; margin-bottom:16px; }}
    .row {{ display:flex; flex-wrap:wrap; gap:10px; font-size:12px; }}
    .dot {{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:4px; vertical-align:middle; }}
    .chips {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }}
    .chip {{ border:1px solid #334155; border-radius:12px; padding:2px 10px; font-size:12px; color:#cbd5e1; }}
    .muted-chip {{ color:#64748b; }}
    ul {{ list-style:none; padding:0; margin:0; }}
    li {{ font-family:monospace; font-size:12px; padding:3px 0; border-bottom:1px solid #1e293b; }}
  </style>
</head>
<body>
  <h1>&#128269; Attack Path Visualizations</h1>
  <div class="muted">Lateral movement and DNS-exfiltration paths, auto-rendered from detections.
    Read-only mirror of the authenticated <code>/dashboard/graph</code> view.</div>
  {_summary_chips(meta)}
  <div class="layout">
    <div>{graph_block}</div>
    <div>
      {_LEGEND}
      <div class="card">
        <h3>Snapshots</h3>
        <ul>{_snapshot_items()}</ul>
      </div>
    </div>
  </div>
</body>
</html>"""


@app.get("/graph/{filename}")
async def serve_graph(filename: str):
    # Path-traversal defence: reject separators, only serve .html from the dir.
    if "/" in filename or "\\" in filename or not filename.endswith(".html"):
        return HTMLResponse("<h1>Invalid filename</h1>", status_code=400)
    filepath = GRAPH_DIR / filename
    if filepath.exists() and filepath.is_file():
        return FileResponse(filepath)
    return HTMLResponse("<h1>Graph not found</h1>", status_code=404)
