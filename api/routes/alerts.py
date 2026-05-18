# api/routes/alerts.py
"""
Dashboard endpoints for the alert workflow.

Authentication: existing JWT/API-key middleware.
Authorization (per-endpoint):
  read_alerts        — list, get, stats
  acknowledge_alerts — mark acknowledged
  view_audit_log     — history
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from api.middleware import require_permission
from shared.security import User

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _store(request: Request):
    return request.app.state.alert_store


def _audit(request: Request):
    return request.app.state.audit_trail


# ── List + filter ──────────────────────────────────────────────────────────

@router.get("")
async def list_alerts(
    request: Request,
    severity: Optional[str] = Query(None, description="low|medium|high|critical"),
    status:   Optional[str] = Query(None, description="open|acknowledged"),
    entity:   Optional[str] = Query(None, description="substring match on source entity"),
    hours:    int = Query(24, ge=1, le=720, description="window in hours"),
    limit:    int = Query(100, ge=1, le=500),
    user: User = Depends(require_permission("read_alerts")),
):
    """Return alerts matching filters, newest first. Used by the dashboard grid."""
    return {
        "alerts": _store(request).query_alerts(
            severity=severity, status=status, entity=entity,
            hours=hours, limit=limit,
        ),
        "filters": {
            "severity": severity, "status": status,
            "entity": entity, "hours": hours, "limit": limit,
        },
    }


# ── Stats (header counters) ────────────────────────────────────────────────

@router.get("/stats")
async def alert_stats(
    request: Request,
    user: User = Depends(require_permission("read_alerts")),
):
    """Counts by severity + total/open. Cheap call — safe to poll every 30s."""
    return _store(request).get_stats()


# ── Single-alert detail ────────────────────────────────────────────────────

@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    request: Request,
    user: User = Depends(require_permission("read_alerts")),
):
    """Full alert payload (detections, MITRE, recommended actions, raw features)."""
    matches = _store(request).query_alerts(hours=720, limit=500)
    for a in matches:
        if a.get("alert_id") == alert_id:
            return a
    raise HTTPException(404, "Alert not found")


# ── Explanation: per-alert SHAP + global feature importance ────────────────

def _resolve_alert(store, alert_id: str) -> Optional[dict]:
    """Find an alert payload by ID. Searches a wide window."""
    for a in store.query_alerts(hours=720, limit=500):
        if a.get("alert_id") == alert_id:
            return a
    return None


def _gather_explanation(request: Request, alert: dict, top_k: int = 20) -> dict:
    """
    Build the structured explanation payload for an alert. Combines:
      - per-alert SHAP from each detection's contributing_features
      - global feature importance for each detector (XGBoost gain)
    """
    from detection.model_store import ModelStore, SecurityError
    from detection.registry    import registry
    import os

    detections = alert.get("detections", []) or []
    explanations = []
    for det in detections:
        det_name      = det.get("detector_name")
        contributing  = det.get("contributing_features", {}) or {}

        # Attempt to retrieve global importance from the live booster
        global_importance: list[dict] = []
        booster = None
        if det_name in registry.list_names():
            booster = getattr(registry.get(det_name), "model", None)

        if booster is None:
            store = ModelStore(
                base_dir=os.environ.get("MODEL_STORE_DIR", "detection/models"),
                signing_key=os.environ.get("MODEL_SIGNING_KEY", ""),
            )
            latest = store.base_dir / det_name / "latest"
            if latest.exists():
                try:
                    booster = store.load_from_path(str(latest))
                except (FileNotFoundError, SecurityError):
                    booster = None

        if booster is not None:
            raw = booster.get_score(importance_type="gain")
            ranked = sorted(raw.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
            total = sum(raw.values()) or 1.0
            global_importance = [
                {"feature": f, "score": float(s),
                 "normalized_share": float(s) / total}
                for f, s in ranked
            ]

        explanations.append({
            "detection_id":           det.get("detection_id"),
            "detector_name":          det_name,
            "detection_type":         det.get("detection_type"),
            "confidence":             det.get("confidence"),
            "severity":               det.get("severity"),
            "source_entity":          det.get("source_entity"),
            "mitre_techniques":       det.get("mitre_techniques", []),
            "timestamp":              det.get("timestamp"),
            "contributing_features":  contributing,
            "global_importance":      global_importance,
        })

    return {
        "alert_id":     alert.get("alert_id"),
        "explanations": explanations,
    }


@router.get("/{alert_id}/explanation")
async def alert_explanation_json(
    alert_id: str,
    request: Request,
    top_k: int = Query(20, ge=5, le=141),
    user: User = Depends(require_permission("read_detections")),
):
    """JSON: per-alert SHAP + global feature importance for each detection."""
    alert = _resolve_alert(_store(request), alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return _gather_explanation(request, alert, top_k=top_k)


@router.get("/{alert_id}/explanation.html", response_class=HTMLResponse)
async def alert_explanation_html(
    alert_id: str,
    request: Request,
    top_k: int = Query(20, ge=5, le=141),
    user: User = Depends(require_permission("read_detections")),
):
    """
    Self-contained HTML widget — embeddable in iframe or viewable standalone.
    No external JS dependency; pure HTML + inline CSS.
    """
    from visualization.explanation_widget import render_explanation
    alert = _resolve_alert(_store(request), alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    payload = _gather_explanation(request, alert, top_k=top_k)
    if not payload["explanations"]:
        return HTMLResponse(
            f"<h1>Alert {alert_id}</h1><p>No detections to explain.</p>",
            status_code=200,
        )
    # If multiple detections, render the FIRST one (most alerts have 1).
    # A future iteration could render all in stacked panels.
    e = payload["explanations"][0]
    html = render_explanation(
        alert_id=alert_id,
        detector_name=e["detector_name"],
        confidence=float(e["confidence"]),
        severity=str(e["severity"]),
        timestamp=str(e["timestamp"]),
        source_entity=str(e["source_entity"]),
        contributing_features=e["contributing_features"],
        global_importance=e["global_importance"],
        mitre_techniques=e["mitre_techniques"],
    )
    return HTMLResponse(html)


# ── Acknowledge ────────────────────────────────────────────────────────────

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    user: User = Depends(require_permission("acknowledge_alerts")),
):
    """SOC analyst marks an alert as acknowledged. Audit-logged."""
    store = _store(request)
    # Verify the alert exists before ack so the audit row reflects reality
    matches = store.query_alerts(hours=720, limit=500)
    if not any(a.get("alert_id") == alert_id for a in matches):
        raise HTTPException(404, "Alert not found")

    store.acknowledge(alert_id, user.username)

    _audit(request).log(
        action="alert.acknowledge",
        actor=user.username,
        target=alert_id,
        details={},
    )
    return {"alert_id": alert_id, "status": "acknowledged",
            "acknowledged_by": user.username}
