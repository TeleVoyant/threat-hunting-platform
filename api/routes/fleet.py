# api/routes/fleet.py
"""
Admin-facing endpoints for fleet remote control.

Authentication: existing JWT/API-key middleware (admin or operator role).
Authorization: every endpoint requires the `manage_fleet` permission;
                /fleet/agents/enroll additionally requires `enroll_agents`
                OR a valid bootstrap token (env var FLEET_BOOTSTRAP_TOKEN)
                so that deploy_endpoint.ps1 can self-enroll on the laptop.

Every issuance is recorded in the hash-chained AuditTrail.
"""

import os
import hmac as _hmac
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware import api_key_header, require_permission, security_bearer
from shared.commands import CommandType, encode_secret
from shared.security import User

router = APIRouter(prefix="/fleet", tags=["fleet"])


# ── Helpers ────────────────────────────────────────────────────────────────

def _store(request: Request):
    return request.app.state.command_queue


def _audit(request: Request):
    return request.app.state.audit_trail


def _bootstrap_token_ok(provided: Optional[str]) -> bool:
    """Verify a bootstrap token in constant time. Empty/missing env var → reject."""
    expected = os.environ.get("FLEET_BOOTSTRAP_TOKEN", "")
    if not expected or not provided:
        return False
    return _hmac.compare_digest(expected, provided)


# ── Request models ─────────────────────────────────────────────────────────

class EnrollRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    profile:  str = "Balanced"


class EnqueueCommandRequest(BaseModel):
    command_type: CommandType
    params:       dict           = Field(default_factory=dict)
    ttl_sec:      Optional[int]  = None


class BroadcastRequest(BaseModel):
    command_type:  CommandType
    params:        dict          = Field(default_factory=dict)
    target_filter: Optional[dict] = None   # e.g. {"profile": "Lean"}
    ttl_sec:       Optional[int] = None


# ── Agent enrollment ───────────────────────────────────────────────────────

@router.post("/agents/enroll", status_code=201)
async def enroll_agent(
    body: EnrollRequest,
    request: Request,
    x_bootstrap_token: Optional[str] = Header(default=None),
    x_enrollment_token: Optional[str] = Header(default=None),
    bearer  = Depends(security_bearer),
    api_key = Depends(api_key_header),
):
    """
    Register a new agent and return its HMAC secret. The secret is shown
    ONCE — the caller must store it securely on the agent.

    Three auth paths (checked in order):
      1. X-Enrollment-Token: single-use installer token from POST /install/tokens.
         Atomically consumed on success; cannot be replayed. This is the path
         the URL-served bootstrap one-liner uses.
      2. X-Bootstrap-Token: long-lived env var FLEET_BOOTSTRAP_TOKEN — kept
         for back-compat / scripted enrolment.
      3. Admin JWT/API-key with `enroll_agents` permission.
    """
    auth_manager = request.app.state.auth_manager
    token_store = getattr(request.app.state, "enrollment_tokens", None)

    if x_enrollment_token and token_store is not None:
        client_ip = request.client.host if request.client else None
        ok, reason = token_store.consume(
            x_enrollment_token, body.agent_id, client_ip=client_ip)
        if not ok:
            status = {"not_found": 403, "expired": 410, "used": 409,
                      "exhausted": 409, "revoked": 410}.get(reason, 403)
            raise HTTPException(status,
                f"Enrollment token {reason.replace('_', ' ')}.")
        actor = "installer"
        auth_via = f"enrollment_token:{x_enrollment_token[:8]}…"
    elif _bootstrap_token_ok(x_bootstrap_token):
        actor = "bootstrap"
        auth_via = "bootstrap_token"
    else:
        # Fall back to admin auth + enroll_agents permission
        user: Optional[User] = None
        if bearer and bearer.credentials:
            user = auth_manager.verify_jwt(bearer.credentials)
        if not user and api_key:
            user = auth_manager.authenticate_api_key(api_key)
        if not user:
            raise HTTPException(401, "Provide an X-Enrollment-Token, X-Bootstrap-Token, or admin credentials.")
        if not auth_manager.has_permission(user, "enroll_agents"):
            raise HTTPException(403, "Permission 'enroll_agents' required")
        actor = user.username
        auth_via = "admin_jwt"

    # Validate profile against known set
    if body.profile not in {"Lean", "Balanced", "Full"}:
        raise HTTPException(400, f"Invalid profile: {body.profile}")

    secret = _store(request).enroll_agent(body.agent_id, body.profile)

    _audit(request).log(
        action="fleet.agent.enroll",
        actor=actor,
        target=body.agent_id,
        details={"profile": body.profile, "auth_via": auth_via},
    )

    return {
        "agent_id":      body.agent_id,
        "agent_secret":  encode_secret(secret),  # base64url, no padding
        "profile":       body.profile,
        "warning":       "Store this secret securely on the agent — it cannot be retrieved again.",
    }


# ── Fleet inventory ────────────────────────────────────────────────────────

@router.get("/agents")
async def list_agents(
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """List every enrolled agent with last-seen status and pending command count.

    Response also carries `live_handler_version` so the dashboard + mobile
    fleet views can colour each agent's handler pill (LATEST vs out-of-date)
    without a second round-trip to /admin/handler/versions.
    """
    handler_store = getattr(request.app.state, "handler_store", None)
    live = handler_store.get_live() if handler_store else None
    return {
        "agents":               _store(request).list_agents(),
        "live_handler_version": live["version_label"] if live else None,
    }


# ── Single-agent commands ──────────────────────────────────────────────────

_VALID_ISOLATION_LEVELS = {"light", "standard", "full"}
_ISOLATION_TTL_MIN = 5
_ISOLATION_TTL_MAX = 1440


def _validate_command_params(command_type: "CommandType", params: dict, request: Request) -> dict:
    """Server-side params sanity-check for high-blast-radius commands.

    Validates ISOLATE / UNISOLATE / UPDATE_HANDLER / ROLLBACK_HANDLER at
    the API boundary so the operator (or mobile app) gets immediate
    feedback on a malformed param rather than waiting 60s for the agent's
    'rejected' result. Returns the cleaned-up params dict (clamped /
    canonicalised) or raises HTTPException(400).

    Other command types pass through unchanged — the agent's per-handler
    validation catches anything else.
    """
    if command_type.value == "isolate":
        level = (params.get("level") or "").lower().strip()
        if level not in _VALID_ISOLATION_LEVELS:
            raise HTTPException(
                400,
                f"isolate: 'level' must be one of {sorted(_VALID_ISOLATION_LEVELS)}, got {level!r}",
            )
        ttl = params.get("ttl_minutes", 240)
        try:
            ttl = int(ttl)
        except (TypeError, ValueError):
            raise HTTPException(400, "isolate: 'ttl_minutes' must be an integer")
        ttl = max(_ISOLATION_TTL_MIN, min(_ISOLATION_TTL_MAX, ttl))
        reason = str(params.get("reason") or "").strip()
        if len(reason) > 500:
            raise HTTPException(400, "isolate: 'reason' is too long (max 500 chars)")
        cleaned = {"level": level, "ttl_minutes": ttl, "reason": reason}
        if "toast" in params:
            cleaned["toast"] = bool(params.get("toast"))
        return cleaned

    if command_type.value == "unisolate":
        reason = str(params.get("reason") or "").strip()
        if len(reason) > 500:
            raise HTTPException(400, "unisolate: 'reason' is too long (max 500 chars)")
        return {"reason": reason}

    if command_type.value == "update_handler":
        version = str(params.get("version") or "").strip()
        if not version:
            raise HTTPException(400, "update_handler: 'version' is required")
        if len(version) > 200:
            raise HTTPException(400, "update_handler: 'version' too long (max 200 chars)")
        # Refuse to push a label the server doesn't have — otherwise the
        # agent's manifest fetch returns 404 60s from now and the operator
        # learns about it then. Fail fast here instead.
        handler_store = getattr(request.app.state, "handler_store", None)
        if handler_store is None:
            raise HTTPException(503, "Handler-version store unavailable")
        if handler_store.get_by_label(version) is None:
            raise HTTPException(
                404,
                f"update_handler: version '{version}' not found in handler_versions store",
            )
        cleaned = {"version": version}
        if "force" in params:
            cleaned["force"] = bool(params.get("force"))
        return cleaned

    if command_type.value == "rollback_handler":
        reason = str(params.get("reason") or "").strip()
        if len(reason) > 500:
            raise HTTPException(400, "rollback_handler: 'reason' too long (max 500 chars)")
        return {"reason": reason} if reason else {}

    return params


# Backwards-compat alias for the old name. Older callers (if any) still
# work; new code should call _validate_command_params directly.
_validate_isolation_params = _validate_command_params


@router.post("/agents/{agent_id}/commands", status_code=202)
async def send_command(
    agent_id: str,
    body: EnqueueCommandRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """Enqueue a command for one agent."""
    # Per-type sanity check on params before they leave the API. Isolation
    # + handler-OTA commands have specific structure; everything else
    # passes through.
    params = _validate_command_params(body.command_type, body.params or {}, request)

    try:
        cmd = _store(request).enqueue_command(
            agent_id=agent_id,
            command_type=body.command_type,
            params=params,
            issued_by=user.username,
            ttl_sec=body.ttl_sec,
        )
    except ValueError as e:
        raise HTTPException(404, str(e))

    _audit(request).log(
        action="fleet.command.enqueue",
        actor=user.username,
        target=agent_id,
        details={
            "command_id":   cmd.command_id,
            "command_type": cmd.command_type.value,
            "params":       cmd.params,
            "sequence":     cmd.sequence,
        },
    )

    # Richer per-action audit row for isolation so a SOC searching by
    # `action = "fleet.isolate.requested"` finds them without parsing the
    # generic command_type column.
    if cmd.command_type.value == "isolate":
        _audit(request).log(
            action="fleet.isolate.requested",
            actor=user.username, target=agent_id,
            details={
                "command_id":  cmd.command_id,
                "level":       params.get("level"),
                "ttl_minutes": params.get("ttl_minutes"),
                "reason":      params.get("reason"),
            },
        )
    elif cmd.command_type.value == "unisolate":
        _audit(request).log(
            action="fleet.unisolate.requested",
            actor=user.username, target=agent_id,
            details={"command_id": cmd.command_id, "reason": params.get("reason")},
        )
    elif cmd.command_type.value == "update_handler":
        # Same audit shape as the /admin/handler/push bulk path so a search
        # by `action = "handler.push.requested"` finds both per-agent and
        # bulk pushes uniformly. The push that came in via /fleet/agents/
        # {id}/commands (e.g. from the mobile app's "Push latest handler"
        # button) is now traceable from this single audit action.
        _audit(request).log(
            action="handler.push.requested",
            actor=user.username, target=agent_id,
            details={
                "command_id":    cmd.command_id,
                "version_label": params.get("version"),
                "via":           "fleet_agents_commands",
            },
        )
    elif cmd.command_type.value == "rollback_handler":
        _audit(request).log(
            action="handler.rollback.requested",
            actor=user.username, target=agent_id,
            details={
                "command_id": cmd.command_id,
                "reason":     params.get("reason"),
                "via":        "fleet_agents_commands",
            },
        )

    return {
        "command_id": cmd.command_id,
        "sequence":   cmd.sequence,
        "expires_at": cmd.expires_at,
        "status":     "pending",
    }


# ── Broadcast (one-to-many) ────────────────────────────────────────────────

@router.post("/commands/broadcast", status_code=202)
async def broadcast_command(
    body: BroadcastRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """
    Send the same command to every agent matching `target_filter`.
    Filter keys supported: `profile`, `last_status`.
    Pass `target_filter: null` to target all agents (use with care).
    """
    store = _store(request)
    agents = store.list_agents()

    if body.target_filter:
        for k, v in body.target_filter.items():
            agents = [a for a in agents if a.get(k) == v]

    enqueued = []
    for a in agents:
        cmd = store.enqueue_command(
            agent_id=a["agent_id"],
            command_type=body.command_type,
            params=body.params,
            issued_by=user.username,
            ttl_sec=body.ttl_sec,
        )
        enqueued.append({"agent_id": a["agent_id"], "command_id": cmd.command_id})

    _audit(request).log(
        action="fleet.command.broadcast",
        actor=user.username,
        target=f"{len(enqueued)}_agents",
        details={
            "command_type": body.command_type.value,
            "params":       body.params,
            "filter":       body.target_filter,
            "agent_ids":    [e["agent_id"] for e in enqueued],
        },
    )
    return {"enqueued_count": len(enqueued), "commands": enqueued}


# ── Command status / results ───────────────────────────────────────────────

@router.get("/commands/{command_id}")
async def get_command(
    command_id: str,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    cmd = _store(request).get_command_with_result(command_id)
    if not cmd:
        raise HTTPException(404, "Command not found")
    return cmd


# ── Rotate per-agent HMAC secret ───────────────────────────────────────────

@router.post("/agents/{agent_id}/rotate-secret")
async def rotate_agent_secret(
    agent_id: str,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """
    Rotate an agent's HMAC secret. Returns the new secret ONCE; the agent
    must be re-deployed (or accept the new envelope) afterward.
    """
    store = _store(request)
    if not any(a["agent_id"] == agent_id for a in store.list_agents()):
        raise HTTPException(404, "Agent not found")
    profile = next(
        (a["profile"] for a in store.list_agents() if a["agent_id"] == agent_id),
        "Balanced",
    )
    secret = store.enroll_agent(agent_id, profile)
    _audit(request).log(
        action="fleet.agent.rotate_secret",
        actor=user.username,
        target=agent_id,
        details={"profile": profile},
    )
    return {
        "agent_id":     agent_id,
        "agent_secret": encode_secret(secret),
        "profile":      profile,
        "warning":      "Store this secret securely. Old secret is now invalid.",
    }


# ── Fleet status history (for the 24h timeline chart) ──────────────────────

@router.get("/agents/history")
async def agents_history(
    request: Request,
    hours: int = 24,
    bucket_minutes: int = 60,
    user: User = Depends(require_permission("manage_fleet")),
):
    """
    Lightweight 24h fleet state timeline. We don't persist per-tick state
    history yet, so this synthesises the curve from each agent's
    `last_seen_at`: an agent is considered Active if seen within the bucket,
    Stale if within the last 30m of the bucket but older than 5m, else
    Offline. Good enough for trend rendering until we add a state log.
    """
    import time
    from datetime import datetime, timezone

    store = _store(request)
    agents = store.list_agents()
    bucket_s = bucket_minutes * 60
    now = int(time.time())
    start = ((now - hours * 3600) // bucket_s) * bucket_s
    n_buckets = ((now - start) // bucket_s) + 1

    buckets = []
    for i in range(n_buckets):
        bucket_end = start + (i + 1) * bucket_s
        active = stale = offline = 0
        for a in agents:
            seen = a.get("last_seen_at") or 0
            if seen >= bucket_end - 300:           # seen in last 5m
                active += 1
            elif seen >= bucket_end - 1800:        # last 30m
                stale += 1
            else:
                offline += 1
        ts_iso = datetime.fromtimestamp(start + i * bucket_s, tz=timezone.utc).isoformat()
        buckets.append({"ts": ts_iso, "active": active,
                        "stale": stale, "offline": offline})
    return {"buckets": buckets, "hours": hours, "bucket_minutes": bucket_minutes}


# ── Endpoint enrollment helper (used by the Enroll page) ───────────────────

class EnrollmentHelperRequest(BaseModel):
    profile: str = "Balanced"
    server_ip: Optional[str] = None  # if omitted, server falls back to "AUTO"


@router.post("/enrollment-helper")
async def enrollment_helper(
    body: EnrollmentHelperRequest,
    request: Request,
    user: User = Depends(require_permission("enroll_agents")),
):
    """
    Returns a ready-to-paste PowerShell one-liner that the operator runs on
    a Windows laptop. The one-liner embeds the FLEET_BOOTSTRAP_TOKEN so the
    agent self-enrolls; the operator does not need to ship admin creds.
    """
    if body.profile not in {"Lean", "Balanced", "Full"}:
        raise HTTPException(400, f"Invalid profile: {body.profile}")
    server_ip = body.server_ip or os.environ.get("PUBLIC_SERVER_IP", "<SERVER_IP>")
    token = os.environ.get("FLEET_BOOTSTRAP_TOKEN", "")
    if not token:
        raise HTTPException(
            503,
            "FLEET_BOOTSTRAP_TOKEN is not set on the server. "
            "Set it in .env and restart before enrolling endpoints.",
        )
    powershell = (
        "powershell -ExecutionPolicy Bypass -File .\\deploy_endpoint.ps1 "
        f"-ServerIP {server_ip} "
        f"-RegistrationPassword \"$env:WAZUH_REGISTRATION_PASSWORD\" "
        f"-Profile {body.profile} "
        f"-PlatformApiUrl https://{server_ip}:8000 "
        f"-EnrollmentToken \"{token}\""
    )
    _audit(request).log(
        action="fleet.enrollment_helper.generate",
        actor=user.username,
        target=f"profile:{body.profile}",
        details={"server_ip": server_ip},
    )
    return {
        "powershell": powershell,
        "server_ip": server_ip,
        "profile": body.profile,
        "bootstrap_token_set": True,
    }
