# api/routes/dashboard.py
"""
HTML dashboard pages — server-rendered Jinja2 + HTMX.

Auth: every page reads JWT from the apt_session cookie (see api/routes/auth.py).
      Missing/invalid cookie → 303 redirect to /auth/login.

Pages:
  GET  /dashboard           home: alert summary + recent alerts (htmx-refreshable)
  GET  /dashboard/alerts    grid with filters
  GET  /dashboard/alerts/{id} detail + ack button + investigation notes
  POST /dashboard/alerts/{id}/ack  acknowledge action (HTMX form post)
  GET  /dashboard/fleet     inventory + per-row send-command dialog
  POST /dashboard/fleet/{agent_id}/command  enqueue command (HTMX form post)
  GET  /dashboard/graph     attack-graph viewer (iframe to pyvis HTML)

Permissions:
  - read_alerts        — alerts grid + detail + home
  - acknowledge_alerts — ack action
  - manage_fleet       — fleet page + send-command
  - view_graphs        — attack graph page
"""

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from api.routes.auth import require_user_cookie
from shared.commands import CommandType
from shared.security  import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ── Helpers ─────────────────────────────────────────────────────────────────


def _templates(request: Request):
    return request.app.state.templates


def _has_perm(request: Request, user: User, perm: str) -> bool:
    return request.app.state.auth_manager.has_permission(user, perm)


def _require_perm(request: Request, user: User, perm: str) -> None:
    if not _has_perm(request, user, perm):
        raise HTTPException(403, f"Permission '{perm}' required")


def _model_health(request: Request) -> dict:
    """
    Compact model-health summary for the Operations header. Surfaces the two
    model-quality guards on the page operators look at first:

      - retrain CONTAMINATION guard (security): auto-retrain aborts when the
        benign training pool is poisoned by suspected active-intrusion entities
        (scheduler last_status == "skipped:suspected_active_intrusion");
      - degenerate-model AUC guard: the active model tripped the near-perfect
        training-AUC warning (manifest metadata auc_warning).

    Computed server-side so it works for any authenticated viewer without a
    second permission-gated fetch (/retrain/status needs retrain_models). The
    flagged entities are already visible to the same user via the alerts feed,
    so no extra disclosure. Best-effort: any failure degrades to the neutral
    "Detectors live" state — this is a header adornment, never a hard error.
    """
    # 1. Contamination guard takes priority — it is a security stop.
    sched = getattr(request.app.state, "retrain_scheduler", None)
    if sched is not None:
        try:
            st = sched.status()
        except Exception:
            st = {}
        if st.get("last_status") == "skipped:suspected_active_intrusion":
            lr = st.get("last_result") or {}
            return {
                "state": "intrusion",
                "label": "Retrain halted - suspected intrusion",
                "detail": (
                    f'{lr.get("excluded_pct", "?")}% of the benign training pool '
                    "came from already-flagged entities; auto-retrain is paused "
                    "until they are reviewed."
                ),
                "entities": (lr.get("detected_entities") or [])[:8],
            }
    # 2. Degenerate-model AUC guard on the active (latest) models. Read each
    #    detector's latest/manifest.json directly (one file each) rather than
    #    enumerating every saved version.
    base = Path(os.environ.get("MODEL_STORE_DIR", "detection/models"))
    flagged = []
    for name in ("lateral_movement", "dns_exfiltration"):
        try:
            meta = json.loads(
                (base / name / "latest" / "manifest.json").read_text()
            ).get("metadata") or {}
        except Exception:
            continue
        if meta.get("auc_warning"):
            flagged.append(name)
    if flagged:
        return {
            "state": "warn",
            "label": "Model needs validation",
            "detail": (
                "Active model tripped the near-perfect-AUC guard - validate on "
                "real data before trusting detections: " + ", ".join(flagged)
            ),
            "entities": [],
        }
    return {"state": "ok", "label": "Detectors live", "detail": None, "entities": []}


# ── Home ────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse)
async def home(request: Request, user: User = Depends(require_user_cookie)):
    store = request.app.state.alert_store
    stats = store.get_stats()
    by_sev = stats.get("by_severity", {}) or {}
    recent = store.query_alerts(hours=24, limit=10)
    kpis = {
        "total":    stats.get("total_alerts", 0),
        "open":     stats.get("open_alerts", 0),
        "critical": by_sev.get("critical", 0),
        "high":     by_sev.get("high", 0),
    }
    severity_counts = {
        "critical": by_sev.get("critical", 0),
        "high":     by_sev.get("high", 0),
        "medium":   by_sev.get("medium", 0),
        "low":      by_sev.get("low", 0),
    }
    return _templates(request).TemplateResponse(
        request, "home.html",
        {"user": user, "active": "home",
         "kpis": kpis, "severity_counts": severity_counts,
         "recent": recent,
         "model_health": _model_health(request),
         "can_ack": _has_perm(request, user, "acknowledge_alerts")},
    )


# ── Alerts ──────────────────────────────────────────────────────────────────


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_grid(
    request: Request,
    user: User = Depends(require_user_cookie),
    severity: Optional[str] = None,
    status:   Optional[str] = None,
    entity:   Optional[str] = None,
    mitre:    Optional[str] = None,
    hours:    int = 24,
):
    _require_perm(request, user, "read_alerts")
    store = request.app.state.alert_store
    alerts = store.query_alerts(
        severity=severity or None, status=status or None,
        entity=entity or None, hours=hours, limit=200,
    )
    if mitre:
        alerts = [a for a in alerts if mitre.upper() in (a.get("mitre_techniques") or [])]
    return _templates(request).TemplateResponse(
        request, "alerts_grid.html",
        {"user": user, "active": "alerts", "alerts": alerts,
         "filters": {"severity": severity or "", "status": status or "",
                     "entity": entity or "", "hours": hours, "mitre": mitre or ""},
         "stats": store.get_stats()},
    )


@router.get("/alerts/{alert_id}/panel", response_class=HTMLResponse)
async def alert_panel(
    alert_id: str, request: Request,
    user: User = Depends(require_user_cookie),
):
    """HTMX partial — InvestigationPanel body for an alert."""
    _require_perm(request, user, "read_alerts")
    store = request.app.state.alert_store
    alerts = store.query_alerts(hours=720, limit=500)
    alert = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return _templates(request).TemplateResponse(
        request, "partials/investigation_panel.html",
        {"user": user, "alert": alert,
         "can_ack": _has_perm(request, user, "acknowledge_alerts"),
         # `manage_fleet` gates the per-detection "Isolate source host" button.
         # The button is only useful (and only authorized) when the operator
         # could actually issue the fleet command afterwards.
         "can_manage_fleet": _has_perm(request, user, "manage_fleet")},
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
async def alert_detail(
    alert_id: str, request: Request,
    user: User = Depends(require_user_cookie),
):
    _require_perm(request, user, "read_alerts")
    store = request.app.state.alert_store
    alerts = store.query_alerts(hours=720, limit=500)
    alert = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return _templates(request).TemplateResponse(
        request, "alert_detail.html",
        {"user": user, "active": "alerts", "alert": alert,
         "can_ack": _has_perm(request, user, "acknowledge_alerts")},
    )


@router.post("/alerts/{alert_id}/ack")
async def ack_alert(
    alert_id: str, request: Request,
    user: User = Depends(require_user_cookie),
):
    _require_perm(request, user, "acknowledge_alerts")
    store = request.app.state.alert_store
    alerts = store.query_alerts(hours=720, limit=500)
    if not any(a.get("alert_id") == alert_id for a in alerts):
        raise HTTPException(404, "Alert not found")
    store.acknowledge(alert_id, user.username)
    request.app.state.audit_trail.log(
        action="alert.acknowledge", actor=user.username,
        target=alert_id, details={"via": "dashboard"},
    )
    return RedirectResponse(url=f"/dashboard/alerts/{alert_id}", status_code=303)


@router.post("/alerts/{alert_id}/status")
async def set_alert_status_dash(
    alert_id: str, request: Request,
    status: str = Form(...),
    user: User = Depends(require_user_cookie),
):
    """Triage lifecycle: acknowledged -> investigating -> resolved."""
    _require_perm(request, user, "acknowledge_alerts")
    store = request.app.state.alert_store
    if not any(a.get("alert_id") == alert_id for a in store.query_alerts(hours=720, limit=500)):
        raise HTTPException(404, "Alert not found")
    try:
        store.set_status(alert_id, status, user.username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    request.app.state.audit_trail.log(
        action="alert.status", actor=user.username, target=alert_id,
        details={"status": status, "via": "dashboard"})
    return RedirectResponse(url=f"/dashboard/alerts/{alert_id}", status_code=303)


@router.post("/alerts/{alert_id}/verdict")
async def set_alert_verdict_dash(
    alert_id: str, request: Request,
    verdict: str = Form(...),
    user: User = Depends(require_user_cookie),
):
    """Analyst verdict. confirmed_malicious also QUARANTINES the alert's source
    entities from the retrain pool; false_positive keeps them in."""
    _require_perm(request, user, "acknowledge_alerts")
    store = request.app.state.alert_store
    alert = next((a for a in store.query_alerts(hours=720, limit=500)
                  if a.get("alert_id") == alert_id), None)
    if not alert:
        raise HTTPException(404, "Alert not found")
    if verdict not in ("false_positive", "confirmed_malicious"):
        raise HTTPException(400, "verdict must be false_positive or confirmed_malicious")
    store.set_verdict(alert_id, verdict, user.username)
    details = {"verdict": verdict, "via": "dashboard"}
    if verdict == "confirmed_malicious":
        entities = sorted({d.get("source_entity", "") for d in alert.get("detections", [])
                           if d.get("source_entity")})
        for ent in entities:
            store.quarantine_entity(ent, f"confirmed via alert {alert_id[:14]}",
                                    alert_id, user.username)
        details["quarantined"] = entities
        request.app.state.audit_trail.log(
            action="alert.quarantine", actor=user.username, target=alert_id,
            details={"entities": entities, "via": "dashboard"})
    request.app.state.audit_trail.log(
        action="alert.verdict", actor=user.username, target=alert_id, details=details)
    return RedirectResponse(url=f"/dashboard/alerts/{alert_id}", status_code=303)


@router.get("/quarantine", response_class=HTMLResponse)
async def quarantine_view(request: Request, user: User = Depends(require_user_cookie)):
    """Operator view of entities excluded from retraining (with Release)."""
    _require_perm(request, user, "read_alerts")
    store = request.app.state.alert_store
    return _templates(request).TemplateResponse(
        request, "quarantine.html",
        {"user": user, "active": "alerts",
         "quarantine": store.list_quarantine(active_only=False),
         "can_manage": _has_perm(request, user, "acknowledge_alerts")},
    )


@router.post("/quarantine/{entity:path}/release")
async def quarantine_release_dash(
    entity: str, request: Request,
    user: User = Depends(require_user_cookie),
):
    _require_perm(request, user, "acknowledge_alerts")
    request.app.state.alert_store.release_entity(entity, user.username)
    request.app.state.audit_trail.log(
        action="alert.quarantine.release", actor=user.username, target=entity,
        details={"via": "dashboard"})
    return RedirectResponse(url="/dashboard/quarantine", status_code=303)


# ── Fleet ───────────────────────────────────────────────────────────────────


@router.get("/fleet", response_class=HTMLResponse)
async def fleet(request: Request, user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "manage_fleet")
    store = request.app.state.command_queue
    # Resolve the current LIVE handler version so the table can render
    # green "LATEST" vs amber "out of date" per agent. None if no handler
    # has ever been promoted (fresh install).
    handler_store = getattr(request.app.state, "handler_store", None)
    live_handler  = handler_store.get_live() if handler_store else None
    live_handler_version = live_handler["version_label"] if live_handler else None
    return _templates(request).TemplateResponse(
        request, "fleet.html",
        {
            "user": user, "active": "fleet",
            "agents":               store.list_agents(),
            "live_handler_version": live_handler_version,
        },
    )


@router.post("/fleet/{agent_id}/command")
async def fleet_send_command(
    agent_id: str, request: Request,
    command_type: str = Form(...),
    profile:      Optional[str] = Form(None),
    source:       Optional[str] = Form(None),
    enabled:      Optional[str] = Form(None),
    service:      Optional[str] = Form(None),
    user: User = Depends(require_user_cookie),
):
    _require_perm(request, user, "manage_fleet")
    try:
        ct = CommandType(command_type)
    except ValueError:
        raise HTTPException(400, f"Unknown command type: {command_type}")
    params = {}
    if ct == CommandType.SET_PROFILE:
        params = {"profile": profile}
    elif ct == CommandType.TOGGLE_TELEMETRY:
        params = {"source": source, "enabled": (enabled == "on")}
    elif ct == CommandType.RESTART_SERVICES:
        params = {"service": service}

    store = request.app.state.command_queue
    try:
        cmd = store.enqueue_command(
            agent_id=agent_id, command_type=ct, params=params,
            issued_by=user.username,
        )
    except ValueError as e:
        raise HTTPException(404, str(e))

    request.app.state.audit_trail.log(
        action="fleet.command.enqueue", actor=user.username,
        target=agent_id,
        details={"command_id": cmd.command_id,
                  "command_type": ct.value, "params": params, "via": "dashboard"},
    )
    return RedirectResponse(url="/dashboard/fleet", status_code=303)


# ── Models page ─────────────────────────────────────────────────────────────


@router.get("/models", response_class=HTMLResponse)
async def models_page(request: Request,
                      user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_detections")
    return _templates(request).TemplateResponse(
        request, "models.html",
        {"user": user, "active": "models",
         "can_retrain": _has_perm(request, user, "retrain_models"),
         "can_manage_detectors": _has_perm(request, user, "manage_detectors")},
    )


@router.get("/retrain", response_class=HTMLResponse)
async def retrain_page(request: Request,
                       user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "retrain_models")
    return _templates(request).TemplateResponse(
        request, "retrain.html",
        {"user": user, "active": "retrain"},
    )


@router.get("/handler", response_class=HTMLResponse)
async def handler_page(request: Request,
                       user: User = Depends(require_user_cookie)):
    """Operator-facing handler-script version manager.
    Upload, stage, promote, archive, push, rollback — all live here.
    Read also allowed for analysts so they can see fleet-wide version state."""
    _require_perm(request, user, "read_detections")
    return _templates(request).TemplateResponse(
        request, "handler.html",
        {"user": user, "active": "handler",
         "can_manage_versions": _has_perm(request, user, "retrain_models"),
         "can_push_fleet":      _has_perm(request, user, "manage_fleet")},
    )


@router.get("/evaluations", response_class=HTMLResponse)
async def evaluations_page(request: Request,
                            user: User = Depends(require_user_cookie)):
    """Chart-rich, stakeholder-grade evaluation reporting page.

    Operator actions (retrain / promote / rollback / threshold-write) stay on
    /dashboard/models; this page is read-mostly: review reports, scrub a
    non-destructive threshold preview, kick off a new evaluation run."""
    _require_perm(request, user, "read_detections")
    return _templates(request).TemplateResponse(
        request, "evaluations.html",
        {"user": user, "active": "evaluations",
         "can_evaluate":         _has_perm(request, user, "retrain_models"),
         "can_manage_detectors": _has_perm(request, user, "manage_detectors")},
    )


# ── DNS allowlist page ──────────────────────────────────────────────────────


@router.get("/allowlist", response_class=HTMLResponse)
async def allowlist_page(request: Request,
                          user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_detections")
    return _templates(request).TemplateResponse(
        request, "allowlist.html",
        {"user": user, "active": "allowlist",
         "can_edit": _has_perm(request, user, "manage_detectors")},
    )


# ── FL local page ───────────────────────────────────────────────────────────


@router.get("/fl", response_class=HTMLResponse)
async def fl_page(request: Request,
                  user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_detections")
    return _templates(request).TemplateResponse(
        request, "fl_local.html",
        {"user": user, "active": "fl",
         "can_manage": _has_perm(request, user, "manage_fl_local")},
    )


# ── Audit page ──────────────────────────────────────────────────────────────


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request,
                     user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "view_audit_log")
    return _templates(request).TemplateResponse(
        request, "audit.html",
        {"user": user, "active": "audit"},
    )


# ── Users page ──────────────────────────────────────────────────────────────


@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request,
                     user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "manage_users")
    return _templates(request).TemplateResponse(
        request, "users.html",
        {"user": user, "active": "users"},
    )


@router.get("/devices", response_class=HTMLResponse)
async def paired_devices_page(request: Request,
                               user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "manage_users")
    return _templates(request).TemplateResponse(
        request, "devices.html",
        {"user": user, "active": "devices"},
    )


# ── Admin page ──────────────────────────────────────────────────────────────


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request,
                     user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "manage_users")
    return _templates(request).TemplateResponse(
        request, "admin.html",
        {"user": user, "active": "admin"},
    )


# ── Diagnostics page ────────────────────────────────────────────────────────


@router.get("/diagnostics", response_class=HTMLResponse)
async def diagnostics_page(request: Request,
                            user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_detections")
    return _templates(request).TemplateResponse(
        request, "diagnostics.html",
        {"user": user, "active": "diagnostics"},
    )


# ── Notifications pages ─────────────────────────────────────────────────────


@router.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request,
                              user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_alerts")
    return _templates(request).TemplateResponse(
        request, "notifications.html",
        {"user": user, "active": "notifications"},
    )


@router.get("/settings/notifications", response_class=HTMLResponse)
async def notifications_settings_page(request: Request,
                                       user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_alerts")
    return _templates(request).TemplateResponse(
        request, "settings_notifications.html",
        {"user": user, "active": "notifications"},
    )


@router.get("/settings/companion", response_class=HTMLResponse)
async def companion_settings_page(request: Request,
                                   user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "read_alerts")
    return _templates(request).TemplateResponse(
        request, "settings_companion.html",
        {"user": user, "active": "companion"},
    )


# ── Endpoint enrollment helper ─────────────────────────────────────────────


@router.get("/enroll", response_class=HTMLResponse)
async def enroll_page(request: Request,
                      user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "enroll_agents")
    import os
    return _templates(request).TemplateResponse(
        request, "enroll.html",
        {"user": user, "active": "enroll",
         "bootstrap_token_set": bool(os.environ.get("FLEET_BOOTSTRAP_TOKEN")),
         "default_server_ip": os.environ.get("PUBLIC_SERVER_IP", "")},
    )


# ── Attack graph ────────────────────────────────────────────────────────────


@router.get("/graph", response_class=HTMLResponse)
async def attack_graph(request: Request,
                        user: User = Depends(require_user_cookie)):
    _require_perm(request, user, "view_graphs")
    # The graph is rendered to data/graphs/current.html by GraphSubscriber.
    # We serve it via a sibling /dashboard/graph/file route below + iframe it.
    import os
    graph_dir = os.environ.get("GRAPH_DIR", "data/graphs")
    from pathlib import Path
    files = []
    if Path(graph_dir).exists():
        files = sorted(
            (p.name for p in Path(graph_dir).glob("*.html")),
            reverse=True,
        )[:50]
    return _templates(request).TemplateResponse(
        request, "graph.html",
        {"user": user, "active": "graph", "files": files,
         "current_exists": "current.html" in files},
    )


@router.get("/graph/file/{filename}", response_class=HTMLResponse)
async def graph_file(
    filename: str, request: Request,
    user: User = Depends(require_user_cookie),
):
    _require_perm(request, user, "view_graphs")
    # Path traversal defence: only serve files matching expected pattern
    if "/" in filename or "\\" in filename or not filename.endswith(".html"):
        raise HTTPException(400, "Invalid filename")
    import os
    from pathlib import Path
    graph_dir = os.environ.get("GRAPH_DIR", "data/graphs")
    fp = Path(graph_dir) / filename
    if not fp.exists() or not fp.is_file():
        raise HTTPException(404, "Graph not found")
    return HTMLResponse(fp.read_text())
