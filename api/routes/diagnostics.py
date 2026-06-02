# api/routes/diagnostics.py
"""
Diagnostic endpoints for the SOC dashboard.

  GET /diag/services    composite health of platform components
  GET /diag/logs        tail of the API log file (no Docker socket needed)
"""

import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request

from api.middleware import require_permission
from shared.security import User

router = APIRouter(prefix="/diag", tags=["diagnostics"])


@router.get("/uptime")
async def uptime(request: Request):
    """Platform uptime in seconds + a human label.

    Public on purpose — every dashboard page polls this for the topbar pill,
    so gating it on a permission would force a login redirect on first paint
    of the login page itself. Reveals only the boot time, not any state.
    """
    import time as _t
    started = float(getattr(request.app.state, "started_at", _t.time()))
    delta = max(0.0, _t.time() - started)
    return {"started_at": started, "uptime_seconds": delta,
            "label": _format_uptime(delta)}


def _format_uptime(seconds: float) -> str:
    """Compact human label: 47s, 12m, 3h 14m, 5d 2h, 3w 4d, 2mo 1w."""
    s = int(seconds)
    if s < 60:               return f"{s}s"
    if s < 3600:             return f"{s // 60}m"
    if s < 86_400:
        h, m = divmod(s // 60, 60); return f"{h}h {m}m" if m else f"{h}h"
    if s < 7 * 86_400:
        d, rem = divmod(s, 86_400); h = rem // 3600
        return f"{d}d {h}h" if h else f"{d}d"
    if s < 30 * 86_400:
        w, rem = divmod(s, 7 * 86_400); d = rem // 86_400
        return f"{w}w {d}d" if d else f"{w}w"
    mo, rem = divmod(s, 30 * 86_400); w = rem // (7 * 86_400)
    return f"{mo}mo {w}w" if w else f"{mo}mo"


@router.get("/services")
async def services(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """
    Aggregate health: Wazuh connector circuit-breaker, alert store reachable,
    audit DB reachable, drift monitor present, MISP client mode, FL coord reach.
    """
    state = request.app.state
    out = []

    # Wazuh connector
    wz = getattr(state, "wazuh", None)
    out.append({
        "name": "Wazuh connector",
        "status": "ok" if wz and not getattr(wz, "_breaker_open", False) else "degraded",
        "detail": "Circuit-breaker open" if (wz and getattr(wz, "_breaker_open", False)) else "Reachable" if wz else "Not initialised",
    })

    # Alert store
    try:
        n = state.alert_store.get_stats().get("total_alerts", 0)
        out.append({"name": "Alert store", "status": "ok", "detail": f"{n} alerts in DB"})
    except Exception as e:
        out.append({"name": "Alert store", "status": "fail", "detail": str(e)})

    # Audit trail
    try:
        ok, n = state.audit_trail.verify_integrity()
        out.append({"name": "Audit trail",
                    "status": "ok" if ok else "fail",
                    "detail": f"{n} entries · integrity {'OK' if ok else 'BROKEN'}"})
    except Exception as e:
        out.append({"name": "Audit trail", "status": "fail", "detail": str(e)})

    # Detection subscriber / drift monitors
    sub = getattr(state, "detection_subscriber", None)
    if sub:
        loaded = sorted(getattr(sub, "_loaded", set()))
        load_errs = sub.load_errors() if hasattr(sub, "load_errors") else {}
        if load_errs:
            # Any model that failed integrity check (h) flips this red so the
            # SOC can see why a detector is dark instead of silently missing it.
            status = "fail" if any(v.startswith("INTEGRITY:") for v in load_errs.values()) else "degraded"
            detail = "; ".join(f"{k}: {v}" for k, v in load_errs.items())
        else:
            status = "ok"
            detail = f"Loaded: {', '.join(loaded) or 'none'}"
        out.append({"name": "Detection subscriber", "status": status, "detail": detail})
    else:
        out.append({"name": "Detection subscriber", "status": "warn",
                    "detail": "Not initialised (api-only mode?)"})

    # Fleet command queue
    try:
        agents = state.command_queue.list_agents()
        out.append({"name": "Fleet command queue", "status": "ok",
                    "detail": f"{len(agents)} agents enrolled"})
    except Exception as e:
        out.append({"name": "Fleet command queue", "status": "fail", "detail": str(e)})

    return {"services": out}


@router.get("/notifications")
async def diag_notifications(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """SMTP + Beem health for the Diagnostics page.

    Balance is fetched on demand (no caching) so the page always shows live
    credit. A 10s timeout protects the page render.
    """
    state = request.app.state
    out: dict = {"smtp": {"configured": False}, "beem_sms": {"configured": False}}

    email_backend = getattr(state, "email_backend", None)
    if email_backend is not None:
        reach_ok, reach_msg = await email_backend.reachable()
        out["smtp"] = {
            "configured": True,
            "host": email_backend.host,
            "port": email_backend.port,
            "starttls": email_backend.starttls,
            "from_addr": email_backend.from_addr,
            "reachable": reach_ok,
            "reach_detail": reach_msg,
            "last_send": email_backend.last_send(),
        }

    sms_backend = getattr(state, "sms_backend", None)
    if sms_backend is not None:
        balance = await sms_backend.balance()
        out["beem_sms"] = {
            "configured": True,
            "sender_id": sms_backend.sender_id,
            "base_url": sms_backend.base_url,
            "balance": balance,
            "balance_checked_at": __import__("time").time(),
            "last_send": sms_backend.last_send(),
            "last_error": sms_backend.last_error(),
        }
    return out


@router.post("/notifications/test/email")
async def diag_test_email(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    state = request.app.state
    backend = getattr(state, "email_backend", None)
    if backend is None:
        return {"ok": False, "message": "Email backend not configured."}
    if not user.email:
        return {"ok": False,
                "message": "No email on your user row. Add one in Settings → Notifications."}
    # Pull the live dashboard_url from the notification_service (it already
    # resolved PUBLIC_HOST_URL env > yaml > localhost at startup), so the
    # test message embeds the URL a phone on the same WiFi can actually open.
    svc = getattr(state, "notification_service", None)
    dash_url = (svc.dashboard_url if svc else None) \
               or (state.notifications_config or {}).get("dashboard_url", "http://localhost:8000")
    notif = {"severity": "test", "title": "APT THP self-test", "url": dash_url}
    ok, msg = await backend.send(notif, user)
    state.audit_trail.log(
        action="diag.notifications.test_email", actor=user.username, target=user.username,
        details={"status": "ok" if ok else "fail"},
    )
    return {"ok": ok, "message": f"test email: {msg}"}


@router.post("/notifications/test/sms")
async def diag_test_sms(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    state = request.app.state
    backend = getattr(state, "sms_backend", None)
    if backend is None:
        return {"ok": False, "message": "Beem SMS backend not configured."}
    if not user.phone:
        return {"ok": False,
                "message": "No phone on your user row. Add one in Settings → Notifications."}
    # Pull the live dashboard_url from the notification_service (it already
    # resolved PUBLIC_HOST_URL env > yaml > localhost at startup), so the
    # test message embeds the URL a phone on the same WiFi can actually open.
    svc = getattr(state, "notification_service", None)
    dash_url = (svc.dashboard_url if svc else None) \
               or (state.notifications_config or {}).get("dashboard_url", "http://localhost:8000")
    notif = {"severity": "test", "title": "APT THP self-test", "url": dash_url}
    ok, msg = await backend.send(notif, user)
    state.audit_trail.log(
        action="diag.notifications.test_sms", actor=user.username, target=user.username,
        details={"status": "ok" if ok else "fail"},
    )
    return {"ok": ok, "message": f"test SMS: {msg}"}


@router.post("/notifications/test/end-to-end")
async def diag_test_end_to_end(
    request: Request,
    severity: str = Query("critical", regex="^(low|medium|high|critical)$"),
    user: User = Depends(require_permission("read_detections")),
):
    """Fire a synthetic ALERT_ENRICHED through the event bus.

    This exercises the full chain — NotificationSubscriber receives, the
    service dedupes, then fans out to every enabled channel (email + SMS +
    SSE) using each user's stored contact info + min-severity preference.
    Unlike /test/email and /test/sms, this is the path a real detection
    travels, so a green run proves the wiring end-to-end.
    """
    import uuid
    from datetime import datetime, timezone
    from shared.enums import Severity, DetectionType
    from shared.schemas import EnrichedAlert, Detection
    from shared.events import bus, ALERT_ENRICHED

    now = datetime.now(timezone.utc)
    alert_id = f"e2e-{uuid.uuid4().hex[:12]}"  # unique so dedup never suppresses
    sev = Severity(severity)
    detection = Detection(
        detection_id=f"det-{uuid.uuid4().hex[:8]}",
        detector_name="lateral_movement",
        detection_type=DetectionType.LATERAL_MOVEMENT,
        confidence=0.94,
        severity=sev,
        source_entity="DEMO-HOST-01",
        description="Synthetic end-to-end notification test (no real activity).",
        contributing_features={"failed_login_ratio": 0.83, "lateral_hops": 4.0},
        mitre_techniques=["T1078"],
        timestamp=now,
        event_window_id=f"w-{uuid.uuid4().hex[:8]}",
    )
    alert = EnrichedAlert(
        alert_id=alert_id,
        detections=[detection],
        overall_severity=sev,
        overall_confidence=0.94,
        mitre_techniques=["T1078"],
        mitre_tactics=["lateral-movement"],
        ioc_matches=[],
        recommended_actions=["Investigate auth logs on DEMO-HOST-01"],
        timestamp=now,
    )
    await bus.emit(ALERT_ENRICHED, {"alert": alert})

    request.app.state.audit_trail.log(
        action="diag.notifications.test_end_to_end", actor=user.username, target=user.username,
        details={"alert_id": alert_id},
    )
    return {
        "ok": True,
        "alert_id": alert_id,
        "message": "ALERT_ENRICHED emitted — check email + SMS + dashboard alerts feed",
    }


@router.get("/logs")
async def tail_logs(
    request: Request,
    lines: int = Query(200, ge=10, le=2000),
    user: User = Depends(require_permission("read_detections")),
):
    """Tail of data/logs/api.log if it exists; otherwise advisory message."""
    candidates = [
        Path(os.environ.get("DATA_DIR", "data")) / "logs" / "api.log",
        Path("/var/log") / "api.log",
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            with p.open("rb") as f:
                # Read last N lines efficiently for small files; advisory for big
                try:
                    f.seek(0, 2)
                    size = f.tell()
                    block = min(size, 256 * 1024)
                    f.seek(size - block)
                    tail = f.read(block).decode(errors="replace").splitlines()[-lines:]
                    return {"path": str(p), "lines": tail}
                except Exception as e:
                    return {"path": str(p), "lines": [], "error": str(e)}
    return {
        "path": None, "lines": [],
        "note": "No log file mounted. Configure LOG_FILE or run `docker compose logs -f api`.",
    }


# ── Dead-letter queue inspector + replay (dd) ───────────────────────────────
# Without these, the DLQ silently grows and a misconfigured preprocessor
# field can drop hours of traffic before anyone notices.


@router.get("/dead-letter")
async def dlq_list(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    user: User = Depends(require_permission("read_detections")),
):
    pp = getattr(request.app.state, "preprocessor", None)
    if pp is None or not getattr(pp, "dead_letter", None):
        return {"entries": [], "count": 0, "note": "DLQ not initialised"}
    dlq = pp.dead_letter
    return {"entries": dlq.list_recent(limit), "count": dlq.count()}


@router.post("/dead-letter/replay/{dlq_id}")
async def dlq_replay(
    dlq_id: str,
    request: Request,
    user: User = Depends(require_permission("manage_detectors")),
):
    """Re-validate a quarantined event after a preprocessor fix.

    On success the entry is removed from the DLQ and the event is emitted on
    the bus exactly as if it had just arrived from Wazuh. On failure the
    entry stays put with the new reason recorded in the audit log so the
    analyst can iterate."""
    pp = getattr(request.app.state, "preprocessor", None)
    if pp is None or not getattr(pp, "dead_letter", None):
        return {"ok": False, "message": "DLQ not initialised"}

    from shared.events import bus, EVENT_INGESTED  # local to dodge cycles
    try:
        entry = pp.dead_letter.get(dlq_id)
    except FileNotFoundError:
        return {"ok": False, "message": f"DLQ entry not found: {dlq_id}"}

    raw = entry.get("event") or {}
    normalised = pp.normalize_batch([raw])
    if not normalised:
        # The event still fails — stats incremented `rejected`; leave the
        # entry put so the analyst can try again after another fix.
        request.app.state.audit_trail.log(
            action="diag.dlq.replay_failed", actor=user.username, target=dlq_id,
            details={"reason": entry.get("reason")},
        )
        return {"ok": False, "message": "Still invalid — left in DLQ"}

    await bus.emit(EVENT_INGESTED, {"events": normalised, "correlation_id": f"dlq-{dlq_id}"})
    pp.dead_letter.remove(dlq_id)
    request.app.state.audit_trail.log(
        action="diag.dlq.replayed", actor=user.username, target=dlq_id,
        details={"events": len(normalised)},
    )
    return {"ok": True, "events": len(normalised)}


# ── Preprocessor backfill window (hh) ───────────────────────────────────────


@router.post("/preprocessor/backfill")
async def set_backfill(
    request: Request,
    hours: int = Query(..., ge=1, le=24 * 30),
    user: User = Depends(require_permission("manage_detectors")),
):
    """Temporarily widen MAX_EVENT_AGE so outage-replay ingest survives.

    Pass hours=24 to restore the default."""
    pp = getattr(request.app.state, "preprocessor", None)
    if pp is None:
        return {"ok": False, "message": "Preprocessor not initialised"}
    pp.set_backfill_window(hours)
    request.app.state.audit_trail.log(
        action="diag.preprocessor.backfill", actor=user.username,
        target="preprocessor", details={"max_event_age_hours": hours},
    )
    return {"ok": True, "max_event_age_hours": hours}
