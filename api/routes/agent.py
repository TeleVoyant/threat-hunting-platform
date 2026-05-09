# api/routes/agent.py
"""
Agent-facing endpoints for fleet remote control.

Authentication: APT-HMAC Authorization header (see shared/commands.py).
                NO JWT here — agents authenticate with their per-host secret.

Every command sent in the response is HMAC-signed by the server using the
SAME per-agent secret, so agents can verify command integrity before
executing. Commands lifted from the response of one agent are useless to
another (different secret).
"""

import json
import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from shared.commands import (
    CommandResult,
    SignedEnvelope,
    make_signed_command,
    parse_and_verify_auth_header,
    verify,
)
from shared.logging import get_logger

logger = get_logger("api.routes.agent")

router = APIRouter(prefix="/agents", tags=["agent"])


# ── Helpers ────────────────────────────────────────────────────────────────

def _store(request: Request):
    return request.app.state.command_queue


def _audit(request: Request):
    return request.app.state.audit_trail


def _check_agent_auth(request: Request, agent_id_url: str, auth_header: str) -> None:
    """Verify the APT-HMAC header AND that it belongs to the agent in the URL.
    Raises HTTPException on any failure."""
    store = _store(request)
    try:
        verified_id = parse_and_verify_auth_header(
            header=auth_header,
            secret_lookup=store.get_agent_secret,
        )
    except ValueError as e:
        # Single 401 for any auth failure — no info leak (unknown vs bad sig)
        logger.warning("Agent auth failed", agent_id_url=agent_id_url, reason=str(e))
        raise HTTPException(status_code=401, detail="Authentication failed")

    if verified_id != agent_id_url:
        logger.warning(
            "Agent auth header / URL mismatch",
            verified=verified_id, url=agent_id_url,
        )
        raise HTTPException(status_code=403, detail="Auth identity mismatch")


# ── Wire models ────────────────────────────────────────────────────────────

class PollResponse(BaseModel):
    commands:     list[SignedEnvelope]
    server_time:  int


class HeartbeatBody(BaseModel):
    profile: Optional[str] = None
    status:  Optional[str] = "ok"


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.post("/{agent_id}/poll", response_model=PollResponse)
async def poll(
    agent_id: str,
    request: Request,
    authorization: str = Header(default=""),
):
    """Agent polls for pending commands. Each command is individually signed."""
    _check_agent_auth(request, agent_id, authorization)
    store = _store(request)

    secret = store.get_agent_secret(agent_id)
    if secret is None:
        # Race: agent existed at auth time but not now. Treat as auth failure.
        raise HTTPException(401, "Authentication failed")

    pending = store.get_pending_commands(agent_id)
    envelopes = [make_signed_command(secret, c) for c in pending]

    for c in pending:
        store.mark_delivered(c.command_id)

    store.update_agent_status(agent_id, status="ok")

    return PollResponse(commands=envelopes, server_time=int(time.time()))


@router.post("/{agent_id}/results", status_code=200)
async def submit_result(
    agent_id: str,
    envelope: SignedEnvelope,
    request: Request,
    authorization: str = Header(default=""),
):
    """Agent submits the execution result of a command."""
    _check_agent_auth(request, agent_id, authorization)
    store = _store(request)

    secret = store.get_agent_secret(agent_id)
    if secret is None:
        raise HTTPException(401, "Authentication failed")

    # Verify the result envelope was signed by this agent's secret
    if not verify(secret, envelope.signed_payload, envelope.signature):
        logger.warning("Result signature verification failed", agent_id=agent_id)
        raise HTTPException(403, "Result signature verification failed")

    try:
        result_data = json.loads(envelope.signed_payload)
        result = CommandResult(**result_data)
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(400, f"Malformed result payload: {e}")

    if result.agent_id != agent_id:
        raise HTTPException(403, "Result agent_id does not match authenticated agent")

    # Persist result; ownership re-checked inside record_result (defense in depth)
    try:
        store.record_result(
            command_id=result.command_id,
            agent_id=agent_id,
            status=result.status.value,
            output=result.output,
        )
    except (ValueError, PermissionError) as e:
        raise HTTPException(404, str(e))

    # If a SET_PROFILE succeeded, record the new profile on the agent row
    cmd = store.get_command_with_result(result.command_id)
    if (cmd
        and cmd["command_type"] == "set_profile"
        and result.status.value == "success"):
        new_profile = cmd["params"].get("profile")
        if new_profile in {"Lean", "Balanced", "Full"}:
            store.update_agent_status(agent_id, status="ok", profile=new_profile)

    _audit(request).log(
        action="fleet.command.result",
        actor=f"agent:{agent_id}",
        target=result.command_id,
        details={
            "status":         result.status.value,
            "output_preview": result.output[:200] if result.output else "",
        },
    )

    return {"received": True}


@router.post("/{agent_id}/heartbeat")
async def heartbeat(
    agent_id: str,
    body: HeartbeatBody,
    request: Request,
    authorization: str = Header(default=""),
):
    """Lightweight liveness ping. Updates last_seen_at + optional profile."""
    _check_agent_auth(request, agent_id, authorization)
    store = _store(request)
    store.update_agent_status(
        agent_id,
        status=body.status,
        profile=body.profile,
    )
    return {"ok": True, "server_time": int(time.time())}
