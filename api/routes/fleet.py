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
    bearer  = Depends(security_bearer),
    api_key = Depends(api_key_header),
):
    """
    Register a new agent and return its HMAC secret. The secret is shown
    ONCE — the caller must store it securely on the agent.

    Two auth paths:
      1. X-Bootstrap-Token header matching env var FLEET_BOOTSTRAP_TOKEN, OR
      2. Admin JWT/API-key with `enroll_agents` permission.

    The bootstrap path lets deploy_endpoint.ps1 self-enroll on the laptop
    without distributing admin credentials to every endpoint.
    """
    auth_manager = request.app.state.auth_manager

    if _bootstrap_token_ok(x_bootstrap_token):
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
            raise HTTPException(401, "Provide a valid X-Bootstrap-Token or admin credentials")
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
    """List every enrolled agent with last-seen status and pending command count."""
    return {"agents": _store(request).list_agents()}


# ── Single-agent commands ──────────────────────────────────────────────────

@router.post("/agents/{agent_id}/commands", status_code=202)
async def send_command(
    agent_id: str,
    body: EnqueueCommandRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """Enqueue a command for one agent."""
    try:
        cmd = _store(request).enqueue_command(
            agent_id=agent_id,
            command_type=body.command_type,
            params=body.params,
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
