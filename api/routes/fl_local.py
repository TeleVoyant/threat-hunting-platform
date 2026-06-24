# api/routes/fl_local.py
"""
Org-side FL admin endpoints.

The org admin can:
  - Configure the FL coordinator URL + the org's API key (one-time)
  - View whether the org is currently opted in
  - Opt the org into the next round (or out of it)
  - View this org's own contribution history

The org admin CANNOT:
  - See other organizations' data
  - See aggregated weights, the global model details, or other clients
  - Manage rounds, block other orgs, or configure DP/trust
  - Authenticate to the FL coordinator's management API
  (those live on the separate apt-fl-coordinator deployment, not here)

All mutations require `manage_fl_local`. Audit-logged.
"""

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware import require_permission
from detection.model_store import ModelStore
from federated import participation
from federated.attestation import (
    generate_keypair, private_key_to_pem, public_key_to_pem, public_key_from_pem,
)
from shared.security import User

router = APIRouter(prefix="/fl/local", tags=["fl-local"])

# Detectors an org can contribute to a round (must match the coordinator's
# feature space — all orgs share the platform's schema-pinned pipeline).
_KNOWN_DETECTORS = ("lateral_movement", "dns_exfiltration")


def _state(request: Request):
    return request.app.state.fl_local_state


def _model_store() -> ModelStore:
    return ModelStore(
        base_dir=os.environ.get("MODEL_STORE_DIR", "detection/models"),
        signing_key=os.environ.get("MODEL_SIGNING_KEY", ""),
    )


def _verify_hours() -> float:
    """Soak window before a fetched global model auto-hot-reloads as the live
    detector (default 24h). Admin can promote/reject earlier via /models/*."""
    try:
        return float(os.environ.get("FL_GLOBAL_MODEL_VERIFY_HOURS", "24"))
    except ValueError:
        return 24.0


def _audit(request: Request):
    return request.app.state.audit_trail


def _fernet() -> Optional[Fernet]:
    """Symmetric encryption key for storing the org's FL API key at rest."""
    key = os.environ.get("FL_LOCAL_FERNET_KEY", "")
    if not key:
        return None
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError):
        return None


# ── Models ──────────────────────────────────────────────────────────────────

class ConfigureRequest(BaseModel):
    coordinator_url:     str = Field(..., min_length=8, max_length=256,
                                     description="HTTPS base URL of the FL coordinator")
    org_id:              str = Field(..., min_length=1, max_length=64,
                                     pattern=r"^[a-zA-Z0-9_-]+$")
    api_key:             str = Field(..., min_length=8,
                                     description="Bootstrap API key from coordinator enrollment response")
    client_cert_pem:     str = Field(..., min_length=20,
                                     description="CA-signed client cert returned by coordinator. Used for mTLS.")
    ca_cert_pem:         str = Field(..., min_length=20,
                                     description="Federation CA cert (trust anchor for coordinator's server cert)")
    coordinator_pub_pem: str = Field(..., min_length=20,
                                     description="Coordinator's Ed25519 public key (verifies coord-signed responses)")


class OptInRequest(BaseModel):
    opted_in: bool


# ── Keypair generation ─────────────────────────────────────────────────────

@router.post("/keypair/init", status_code=201)
async def init_keypair(
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """
    Generate the org's Ed25519 keypair LOCALLY. Returns the public key
    (PEM) — the org admin pastes this into the FL coordinator's
    /fl/orgs/enroll request, which then returns the signed client cert.

    Refuses if a keypair already exists. Rotation requires explicit
    deletion (and re-enrollment with the new public key).
    """
    fernet = _fernet()
    if fernet is None:
        raise HTTPException(
            500,
            "FL_LOCAL_FERNET_KEY not configured — refusing to store keypair "
            "in plaintext. Generate via: python -c 'from cryptography.fernet "
            "import Fernet; print(Fernet.generate_key().decode())'",
        )

    state = _state(request)
    if state.has_keypair():
        raise HTTPException(
            409,
            "Keypair already exists. To rotate: delete the existing keypair "
            "+ re-enroll the org with the new public key.",
        )

    priv, pub = generate_keypair()
    priv_pem = private_key_to_pem(priv)
    pub_pem  = public_key_to_pem(pub)
    enc_priv = base64.b64encode(fernet.encrypt(priv_pem)).decode()

    state.store_keypair(
        private_key_enc=enc_priv,
        public_key_pem=pub_pem.decode(),
        generated_by=user.username,
    )
    _audit(request).log(
        action="fl_local.keypair.init",
        actor=user.username,
        target="self",
        details={"public_key_sha256": __import__("hashlib").sha256(pub_pem).hexdigest()[:16]},
    )
    return {
        "public_key_pem": pub_pem.decode(),
        "instructions":   "Send this public_key_pem to the FL coordinator admin "
                            "for the /fl/orgs/enroll request. The coordinator will "
                            "return: api_key, client_cert_pem, ca_cert_pem, "
                            "coordinator_pub_pem — pass ALL of these to "
                            "POST /fl/local/configure.",
    }


@router.get("/keypair/public")
async def get_public_key(
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """Re-display the org's public key (e.g., for re-enrollment after revoke)."""
    pem = _state(request).get_public_key_pem()
    if not pem:
        raise HTTPException(404, "No keypair generated yet — call /keypair/init first")
    return {"public_key_pem": pem}


# ── Configuration ───────────────────────────────────────────────────────────

@router.post("/configure")
async def configure_coordinator(
    body: ConfigureRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """
    Save the full FL coordinator configuration: URL + bootstrap API key
    (encrypted) + the CA-signed client cert + the federation CA cert +
    the coordinator's public key.

    Requires that /fl/local/keypair/init has been called first.
    """
    if not body.coordinator_url.lower().startswith(("http://", "https://")):
        raise HTTPException(400, "coordinator_url must start with http:// or https://")

    fernet = _fernet()
    if fernet is None:
        raise HTTPException(
            500,
            "FL_LOCAL_FERNET_KEY not configured — cannot store API key safely. "
            "Generate via: python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'",
        )

    state = _state(request)
    if not state.has_keypair():
        raise HTTPException(
            409,
            "No keypair generated — call POST /fl/local/keypair/init first, "
            "share the public key with the FL coordinator admin to enroll, "
            "then return here with the cert + CA + coordinator_pub from the response.",
        )

    # Validate cert and pubkey parse before storing
    try:
        from cryptography import x509
        x509.load_pem_x509_certificate(body.client_cert_pem.encode())
        x509.load_pem_x509_certificate(body.ca_cert_pem.encode())
        public_key_from_pem(body.coordinator_pub_pem.encode())
    except Exception as e:
        raise HTTPException(400, f"Invalid PEM payload: {e}")

    api_key_enc = base64.b64encode(
        fernet.encrypt(body.api_key.encode())
    ).decode()

    state.configure_coordinator(
        coordinator_url=body.coordinator_url,
        org_id=body.org_id,
        api_key_enc=api_key_enc,
        configured_by=user.username,
        client_cert_pem=body.client_cert_pem,
        ca_cert_pem=body.ca_cert_pem,
        coordinator_pub_pem=body.coordinator_pub_pem,
    )
    _audit(request).log(
        action="fl_local.configure",
        actor=user.username,
        target=body.org_id,
        details={
            "coordinator_url": body.coordinator_url,
            "stored": ["api_key", "client_cert", "ca_cert", "coordinator_pub"],
        },
    )
    return {
        "status": "configured",
        "org_id": body.org_id,
        "coordinator_url": body.coordinator_url,
        "mtls_ready": True,
    }


@router.get("/status")
async def status(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """
    Read-only view: is the FL coordinator configured? Is this org opted in?
    Never returns the API key — just whether it's set.
    """
    cfg = _state(request).get_config()
    opt = _state(request).get_opt_in()
    return {
        "configured":      cfg is not None,
        "coordinator_url": cfg["coordinator_url"] if cfg else None,
        "org_id":          cfg["org_id"] if cfg else None,
        "configured_by":   cfg["configured_by"] if cfg else None,
        "opted_in":        opt["opted_in"],
        "opted_at":        opt["set_at"],
        "removal_state":   _state(request).get_removal_state().get("state"),
    }


# ── Opt-in / opt-out ────────────────────────────────────────────────────────

@router.post("/opt-in")
async def set_opt_in(
    body: OptInRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """Toggle this org's participation in the NEXT FL round."""
    cfg = _state(request).get_config()
    if not cfg:
        raise HTTPException(409, "FL coordinator not configured — call /fl/local/configure first")

    _state(request).set_opt_in(body.opted_in, user.username)
    _audit(request).log(
        action="fl_local.opt_in" if body.opted_in else "fl_local.opt_out",
        actor=user.username,
        target=cfg["org_id"],
        details={},
    )
    return {"opted_in": body.opted_in, "set_by": user.username}


# ── Own-contribution history ────────────────────────────────────────────────

@router.get("/contributions")
async def list_own_contributions(
    request: Request,
    limit: int = 50,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """
    History of THIS org's contributions to past FL rounds.
    Does NOT show other orgs' contributions.
    """
    rows = _state(request).list_contributions(limit=limit)
    return {"contributions": rows}


# ── Round participation (contribute + sync the global model) ────────────────

class ParticipateRequest(BaseModel):
    detector: str = Field(..., description="lateral_movement | dns_exfiltration")
    round_id: Optional[int] = Field(None, description="Open round; null = join the latest")
    epsilon:  float = Field(1.0, gt=0.0, le=10.0, description="DP budget before upload")
    sync_after: bool = Field(False, description="Also fetch+stage the global model after")


@router.post("/participate")
async def participate(
    body: ParticipateRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """
    Contribute this org's ACTIVE detector model to a round: load the live model
    (never a staged retrain), DP-noise it, sign + upload over the configured
    transport. Records the attempt in this org's contribution history.
    """
    if body.detector not in _KNOWN_DETECTORS:
        raise HTTPException(400, f"Unknown detector: {body.detector}")
    if not _state(request).get_opt_in().get("opted_in"):
        raise HTTPException(409, "Org is not opted in — POST /fl/local/opt-in first")
    try:
        result = participation.contribute(
            _state(request), _model_store(),
            detector=body.detector, round_id=body.round_id, epsilon=body.epsilon)
    except participation.FLParticipationError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(502, f"Coordinator contribution failed: {e}")

    _audit(request).log(action="fl_local.participate", actor=user.username,
                        target=body.detector,
                        details={"round_id": result["round_id"],
                                 "contribution_id": result["contribution_id"]})
    if body.sync_after:
        try:
            result["sync"] = participation.sync_global(
                _state(request), _model_store(), detector=body.detector,
                verify_hours=_verify_hours())
        except Exception as e:
            result["sync_error"] = str(e)
    return result


@router.post("/sync-global")
async def sync_global_model(
    body: ParticipateRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """
    Fetch the coordinator-signed global model, verify its signature + hash, and
    stage it as a detector version. It soaks for FL_GLOBAL_MODEL_VERIFY_HOURS
    then auto-hot-reloads as the live detector — or the admin promotes/rejects
    it earlier via the normal /models/{detector}/versions/* endpoints.
    """
    if body.detector not in _KNOWN_DETECTORS:
        raise HTTPException(400, f"Unknown detector: {body.detector}")
    try:
        result = participation.sync_global(
            _state(request), _model_store(), detector=body.detector,
            verify_hours=_verify_hours())
    except participation.FLParticipationError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(502, f"Global-model sync failed: {e}")
    _audit(request).log(action="fl_local.sync_global", actor=user.username,
                        target=body.detector, details={k: v for k, v in result.items()
                                                       if k != "model_bytes"})
    return result


# ── Membership removal (mutual-ack leave + force-purge) ─────────────────────

def _require_org_confirm(request: Request, confirm_org_id: str) -> str:
    """Accidental-removal guard: the caller must echo the configured org_id."""
    cfg = _state(request).get_config()
    if not cfg:
        raise HTTPException(409, "FL coordinator not configured — nothing to leave")
    if confirm_org_id != cfg["org_id"]:
        raise HTTPException(
            400, f"confirm_org_id does not match the configured org_id "
                 f"('{cfg['org_id']}') — removal not performed")
    return cfg["org_id"]


class LeaveRequest(BaseModel):
    confirm_org_id: str = Field(..., description="Must equal the configured org_id (typed confirmation)")
    reason:         str = Field("", max_length=300)


@router.post("/leave-request")
async def leave_federation(
    body: LeaveRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """Mutual-ack removal step 1: send a SIGNED leave request to the coordinator.
    Requires confirm_org_id to match the configured org (typed confirmation).
    The org becomes 'leave_pending' on the coordinator; complete with
    POST /fl/local/finalize-leave once the operator approves."""
    org_id = _require_org_confirm(request, body.confirm_org_id)
    try:
        resp = participation.request_leave(_state(request), reason=body.reason)
    except participation.FLParticipationError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(502, f"Coordinator leave-request failed: {e}")
    _audit(request).log(action="fl_local.leave_requested", actor=user.username,
                        target=org_id, details={"reason": body.reason[:200]})
    return resp


@router.post("/finalize-leave")
async def finalize_leave(
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """Mutual-ack removal step 2: poll the coordinator; if the operator approved
    (coordinator signature verified) WIPE local membership credentials (keypair,
    config, certs, opt-in, settings) while KEEPING the contributions history.
    No-op while still awaiting approval."""
    if not _state(request).get_config():
        raise HTTPException(409, "FL coordinator not configured — nothing to finalize")
    try:
        result = participation.finalize_leave(_state(request), keep_contributions=True)
    except participation.FLParticipationError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(502, f"Finalize-leave failed: {e}")
    if result.get("finalized"):
        _audit(request).log(action="fl_local.removed", actor=user.username,
                            target="federation", details=result.get("purge", {}))
    return result


class ForcePurgeRequest(BaseModel):
    confirm_org_id:     str  = Field(..., description="Must equal the configured org_id (typed confirmation)")
    keep_contributions: bool = Field(True, description="Keep the local contributions history")


@router.post("/force-purge")
async def force_purge(
    body: ForcePurgeRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """Escape hatch: wipe local FL membership WITHOUT coordinator coordination —
    for when the coordinator is gone/unreachable. Requires confirm_org_id.
    CAVEAT: the coordinator still lists this org as enrolled (its cert stays
    valid) until an operator revokes it; prefer leave-request/finalize when the
    coordinator is reachable."""
    org_id = _require_org_confirm(request, body.confirm_org_id)
    purge = _state(request).purge_membership(keep_contributions=body.keep_contributions)
    _audit(request).log(action="fl_local.force_purged", actor=user.username,
                        target=org_id, details=purge)
    return {"force_purged": True, "org_id": org_id, **purge}


# ── Participation settings (manual vs automatic) ────────────────────────────

class SettingsRequest(BaseModel):
    mode:     str = Field(..., description="manual | auto")
    detector: Optional[str] = Field(None, description="detector to auto-contribute")
    epsilon:  float = Field(1.0, gt=0.0, le=10.0)


@router.get("/settings")
async def get_settings(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    s = _state(request).get_settings()
    s["global_model_verify_hours"] = _verify_hours()
    return s


@router.post("/settings")
async def set_settings(
    body: SettingsRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fl_local")),
):
    """Choose manual (operator clicks Participate) or automatic (background poller
    contributes the chosen detector when opted in) participation."""
    if body.mode not in ("manual", "auto"):
        raise HTTPException(400, "mode must be 'manual' or 'auto'")
    if body.mode == "auto" and body.detector not in _KNOWN_DETECTORS:
        raise HTTPException(400, "auto mode requires a valid detector")
    _state(request).set_settings(mode=body.mode, detector=body.detector,
                                 epsilon=body.epsilon, by_user=user.username)
    _audit(request).log(action="fl_local.settings", actor=user.username,
                        target=body.mode,
                        details={"detector": body.detector, "epsilon": body.epsilon})
    return _state(request).get_settings()
