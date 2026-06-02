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
from fastapi.responses import PlainTextResponse
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
    # Reported by the agent so the dashboard's Fleet table can flag which
    # endpoints are on the latest handler script. Optional so an old agent
    # build talking to a new server is silently tolerated (handler_version
    # stays NULL in the agents row until the agent upgrades).
    handler_version: Optional[str] = None
    # OTA post-write verification status (added 2026-06-02 after the deadman
    # double-BOM incident). The agent's _HandlerFetchAndApply now runs three
    # post-write checks (sha/parse/self-test invocation) and auto-rolls-back
    # on any failure. This field surfaces the result so an operator sees
    # "UPDATE FAILED" instead of silently watching an agent stay on the old
    # version forever. Values: ok|sha_mismatch|parse_failed|invoke_failed|
    # rolled_back. Null on old agents — server tolerates.
    handler_update_status:      Optional[str] = None
    handler_update_detail:      Optional[str] = None
    handler_update_bad_version: Optional[str] = None


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

    # Richer per-action audit row for isolation results. The agent emits a
    # JSON blob in `output` for isolate/unisolate; surface the parsed fields
    # so a SOC search by action finds them without re-parsing.
    if cmd and cmd["command_type"] in {"isolate", "unisolate"}:
        try:
            parsed = json.loads(result.output) if result.output else {}
        except (json.JSONDecodeError, ValueError):
            parsed = {"raw": result.output[:200] if result.output else ""}
        applied_action = "fleet.isolate.applied" if cmd["command_type"] == "isolate" else "fleet.unisolate.applied"
        _audit(request).log(
            action=applied_action,
            actor=f"agent:{agent_id}",
            target=result.command_id,
            details={
                "status":  result.status.value,
                "level":   parsed.get("level") or parsed.get("unisolated_from"),
                "deadline_at":        parsed.get("deadline_at"),
                "adapters_disabled":  parsed.get("adapters_disabled"),
                "lifeline_verified":  parsed.get("lifeline_verified"),
                "block_verified":     parsed.get("block_verified"),
                "deadman_registered": parsed.get("deadman_registered"),
                "reason":  parsed.get("reason"),
            },
        )

    # Parallel audit row for handler OTA results so the same trail exists
    # for isolation AND for handler updates: search by action, find every
    # apply event regardless of which path issued it.
    if cmd and cmd["command_type"] in {"update_handler", "rollback_handler"}:
        try:
            parsed = json.loads(result.output) if result.output else {}
        except (json.JSONDecodeError, ValueError):
            parsed = {"raw": result.output[:200] if result.output else ""}
        applied_action = (
            "handler.update.applied"
            if cmd["command_type"] == "update_handler"
            else "handler.rollback.applied"
        )
        # The Invoke-UpdateHandler success path returns "applied <version>"
        # as a plain string; rollback returns a JSON blob. Surface whichever
        # structured fields are there + the raw output for anything else.
        _audit(request).log(
            action=applied_action,
            actor=f"agent:{agent_id}",
            target=result.command_id,
            details={
                "status":  result.status.value,
                "from_version": parsed.get("from"),
                "to_version":   parsed.get("to"),
                "reason":       parsed.get("reason"),
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

    # Snapshot the prior update-status so we can emit a single audit event
    # on transitions (ok → failure, or any-failure → ok). Heartbeats arrive
    # every poll (~60s); without dedup we'd spam the audit log.
    prior = store.get_agent(agent_id) or {}
    prior_upd_status = (prior.get("handler_update_status") or "ok")

    store.update_agent_status(
        agent_id,
        status=body.status,
        profile=body.profile,
        handler_version=body.handler_version,
        handler_update_status=body.handler_update_status,
        handler_update_detail=body.handler_update_detail,
        handler_update_bad_version=body.handler_update_bad_version,
    )

    # Audit on status TRANSITION only. Comparing the incoming status (if any)
    # against the prior persisted status — a heartbeat that doesn't report
    # the field at all (old agent) is a no-op for audit purposes.
    new_upd_status = body.handler_update_status
    if new_upd_status and new_upd_status != prior_upd_status:
        if new_upd_status != "ok":
            _audit(request).log(
                action="handler.update.failed",
                actor=f"agent:{agent_id}",
                target=body.handler_update_bad_version or "",
                details={
                    "status":      new_upd_status,
                    "detail":      (body.handler_update_detail or "")[:240],
                    "bad_version": body.handler_update_bad_version,
                    "still_on":    body.handler_version,
                },
            )
        else:
            # Transition from any failure back to ok = recovery.
            _audit(request).log(
                action="handler.update.recovered",
                actor=f"agent:{agent_id}",
                target=body.handler_version or "",
                details={
                    "recovered_from": prior_upd_status,
                    "now_on_version": body.handler_version,
                },
            )

    return {"ok": True, "server_time": int(time.time())}


# ── Handler OTA — manifest + content (agent-facing, HMAC-auth) ─────────────

def _handler_store(request: Request):
    return getattr(request.app.state, "handler_store", None)


@router.get("/{agent_id}/handler/manifest")
async def handler_manifest(
    agent_id: str,
    request: Request,
    authorization: str = Header(default=""),
    version: Optional[str] = None,
):
    """Return the version label + SHA-256 of either the current LIVE handler
    or a specific staged/archived version when `?version=` is passed.

    The agent polls this on every cycle to decide whether to self-update.
    Response is a tiny JSON so the per-poll cost is negligible.
    """
    _check_agent_auth(request, agent_id, authorization)
    store = _handler_store(request)
    if store is None:
        raise HTTPException(503, "Handler-version store unavailable")
    row = store.get_by_label(version) if version else store.get_live()
    if row is None:
        # No version has been uploaded yet. Tell the agent there's nothing
        # to do — it'll keep running whatever it has, no .bak gymnastics.
        return {
            "version": None, "sha256": None, "size_bytes": 0, "status": None,
        }
    return {
        "version":    row["version_label"],
        "sha256":     row["sha256"],
        "size_bytes": row["size_bytes"],
        "status":     row["status"],
    }


@router.get("/{agent_id}/handler/content", response_class=PlainTextResponse)
async def handler_content(
    agent_id: str,
    request: Request,
    authorization: str = Header(default=""),
    version: Optional[str] = None,
):
    """Return the raw .ps1 bytes for the requested version (or the live
    version if `?version=` is omitted). Defence in depth: the response
    carries `X-Handler-SHA256` so the agent can verify the bytes without
    re-decoding the manifest's separate JSON. The agent MUST verify the
    SHA-256 before writing the file to disk.
    """
    _check_agent_auth(request, agent_id, authorization)
    store = _handler_store(request)
    if store is None:
        raise HTTPException(503, "Handler-version store unavailable")
    row = store.get_by_label(version) if version else store.get_live()
    if row is None:
        raise HTTPException(404, "Handler version not found")
    content = store.content_bytes_of(row).decode("utf-8", errors="replace")
    return PlainTextResponse(
        content=content,
        headers={
            "X-Handler-Version": row["version_label"],
            "X-Handler-SHA256":  row["sha256"],
            "Cache-Control":     "no-store",
        },
    )
