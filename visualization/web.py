"""
Standalone web server for attack graph visualization.
Serves the interactive pyvis HTML page on port 8080.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from pathlib import Path

app = FastAPI(title="Attack Graph Visualization")

GRAPH_DIR = Path("data/graphs")


@app.get("/", response_class=HTMLResponse)
async def index():
    graphs = sorted(GRAPH_DIR.glob("*.html"), reverse=True) if GRAPH_DIR.exists() else []
    links = "".join(f'<li><a href="/graph/{g.name}">{g.stem}</a></li>' for g in graphs[:50])
    return f"""
    <html>
    <head><title>Attack Graph Visualization</title></head>
    <body style="font-family: sans-serif; background: #1e1e1e; color: white; padding: 20px;">
        <h1>🔍 Attack Path Visualizations</h1>
        <p>Interactive attack graphs showing lateral movement and exfiltration paths.</p>
        <ul>{links or '<li>No attack graphs generated yet.</li>'}</ul>
    </body>
    </html>
    """


@app.get("/graph/{filename}")
async def serve_graph(filename: str):
    filepath = GRAPH_DIR / filename
    if filepath.exists() and filepath.suffix == ".html":
        return FileResponse(filepath)
    return HTMLResponse("<h1>Graph not found</h1>", status_code=404)
