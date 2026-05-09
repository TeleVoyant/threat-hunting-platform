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
