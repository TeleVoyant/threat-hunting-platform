# api/routes/allowlist.py
"""
Admin endpoints for the DNS allowlist.

Domains in the allowlist are excluded from attack-graph DNS exfiltration
edges. Operators add their own legitimate corporate domains here so the
SOC dashboard isn't cluttered with false-positive destinations.

  GET    /allowlist/dns                — list all domains with metadata
  POST   /allowlist/dns                — add a domain (idempotent)
  DELETE /allowlist/dns/{domain}       — remove a domain

All operations require `manage_detectors` permission and are audit-logged
to the hash-chained AuditTrail.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware import require_permission
from shared.security import User

router = APIRouter(prefix="/allowlist/dns", tags=["allowlist"])


def _store(request: Request):
    return request.app.state.dns_allowlist


def _audit(request: Request):
    return request.app.state.audit_trail


class AddDomainRequest(BaseModel):
    domain: str           = Field(..., min_length=2, max_length=253)
    note:   Optional[str] = Field(None, max_length=500,
                                   description="Why this domain is allowlisted")


# ── Read ────────────────────────────────────────────────────────────────────

@router.get("")
async def list_domains(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """List every allowlisted domain with who added it and when."""
    store = _store(request)
    return {
        "domains": store.all(),
        "count":   store.count(),
    }


# ── Add ─────────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def add_domain(
    body: AddDomainRequest,
    request: Request,
    user: User = Depends(require_permission("manage_detectors")),
):
    """
    Add a domain to the allowlist. Returns 201 with `{added: true}` on first
    add, or 200 with `{added: false}` if the domain was already present.
    """
    try:
        added = _store(request).add(body.domain, user.username, body.note)
    except ValueError as e:
        raise HTTPException(400, str(e))

    _audit(request).log(
        action="allowlist.dns.add",
        actor=user.username,
        target=body.domain.lower(),
        details={"already_present": not added, "note": body.note},
    )
    return {
        "domain":  body.domain.lower(),
        "added":   added,
        "note":    body.note,
    }


# ── Remove ──────────────────────────────────────────────────────────────────

@router.delete("/{domain}")
async def remove_domain(
    domain: str,
    request: Request,
    user: User = Depends(require_permission("manage_detectors")),
):
    """Remove a domain from the allowlist. Returns 404 if it wasn't present."""
    removed = _store(request).remove(domain)
    if not removed:
        raise HTTPException(404, f"Domain not in allowlist: {domain.lower()}")

    _audit(request).log(
        action="allowlist.dns.remove",
        actor=user.username,
        target=domain.lower(),
        details={},
    )
    return {"domain": domain.lower(), "removed": True}
