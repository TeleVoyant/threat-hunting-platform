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
  (those require federated.fl_security.FLAdmin/Operator on a separate server)

All mutations require `manage_fl_local`. Audit-logged.
"""

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware import require_permission
from federated.attestation import (
    generate_keypair, private_key_to_pem, public_key_to_pem, public_key_from_pem,
)
from shared.security import User

router = APIRouter(prefix="/fl/local", tags=["fl-local"])


def _state(request: Request):
    return request.app.state.fl_local_state


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
