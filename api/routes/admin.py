# api/routes/admin.py
"""
Admin operations exposed to the dashboard:

  GET    /admin/users                — list users from config/security.yml
  POST   /admin/users                — add a user (returns new API key once)
  POST   /admin/users/{name}/regen   — rotate the user's API key (one-shot)
  DELETE /admin/users/{name}         — remove a user

  POST   /admin/rotate-jwt           — issue new JWT secret (manual restart needed)
  POST   /admin/rotate-bootstrap     — new FLEET_BOOTSTRAP_TOKEN (manual restart)

  GET    /admin/hardening            — run scripts/audit_compose_hardening.py
  GET    /admin/threat-intel         — current MISP/threat-intel config
  PUT    /admin/threat-intel         — update MISP env (process-local + persist note)
  POST   /admin/threat-intel/refresh — flush IoC cache

  GET    /admin/backup.tar.gz        — stream a tarball of state directories

All endpoints require `manage_users` (admin). Audit-logged.
"""

import hashlib
import io
import os
import secrets
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from api.middleware import require_permission
from shared.security import AuthManager, Role, User

router = APIRouter(prefix="/admin", tags=["admin"])


def _audit(request: Request):
    return request.app.state.audit_trail


def _security_yml_base_path() -> Path:
    """Read-only seed shipped with the project.

    Lives under config/, which is mounted :ro in docker-compose.
    """
    return Path(os.environ.get("CONFIG_DIR", "config")) / "security.yml"


def _security_yml_overrides_path() -> Path:
    """Writable mirror — every mutation (user CRUD, api_key rotation, contact
    edits) lands here so the read-only config volume stays untouched.
    """
    return Path(os.environ.get("DATA_DIR", "data")) / "security_overrides.yml"


# Back-compat alias for any older callers.
def _security_yml_path() -> Path:
    return _security_yml_overrides_path()


def _read_security_yml() -> dict:
    """Read merged security config: base seed + per-user overrides.

    Overrides take precedence on a per-user (and per-top-level-key) basis.
    """
    base_p = _security_yml_base_path()
    base = yaml.safe_load(base_p.read_text()) if base_p.exists() else {}
    base = base or {"authentication": {}, "users": []}

    over_p = _security_yml_overrides_path()
    if not over_p.exists():
        return base

    over = yaml.safe_load(over_p.read_text()) or {}
    for key in ("authentication", "rate_limiting"):
        if key in over:
            base[key] = over[key]
    # Field-level merge so a stray field in overrides can't accidentally
    # clobber the base credential. Earlier versions of exchange_enroll
    # rotated api_key_hash into overrides — those leftover values are now
    # ignored on read; the writable override fields are limited to phone,
    # email, mobile_api_key_hash (set on pairing) and explicit admin edits.
    OVERRIDE_ALLOWED = {"phone", "email", "mobile_api_key_hash"}
    base_users = {u["username"]: u for u in (base.get("users") or [])}
    for u in over.get("users", []) or []:
        name = u.get("username")
        if not name:
            continue
        if name not in base_users:
            # Override-only user (added via admin UI) — accept as-is.
            base_users[name] = u
            continue
        merged = dict(base_users[name])
        for k, v in u.items():
            if k in OVERRIDE_ALLOWED and v is not None:
                merged[k] = v
        base_users[name] = merged
    base["users"] = list(base_users.values())
    return base


def _write_security_yml(data: dict) -> None:
    """Persist mutations to the writable overrides file. Idempotent."""
    p = _security_yml_overrides_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))


def _reload_auth(request: Request) -> None:
    """Re-hydrate AuthManager.users from disk so the change applies live."""
    data = _read_security_yml()
    auth: AuthManager = request.app.state.auth_manager
    auth.users = {
        u["username"]: User(
            username=u["username"], role=Role(u["role"]),
            api_key_hash=u.get("api_key_hash", ""),
            mobile_api_key_hash=u.get("mobile_api_key_hash"),
            email=u.get("email"),
            phone=u.get("phone"),
        )
        for u in data.get("users", [])
    }


# ── Users ──────────────────────────────────────────────────────────────────


@router.get("/users")
async def list_users(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    data = _read_security_yml()
    return {
        "users": [
            {"username": u["username"], "role": u["role"],
             "email": u.get("email"), "phone": u.get("phone")}
            for u in data.get("users", [])
        ],
    }


# ── Phone / email validation ───────────────────────────────────────────────
#
# Strict TZ default: 12 digits starting with 255 (e.g., 255712345678).
# Loose mode: 8–15 digits (any country). Operators flip the mode in
# config/notifications.yml: allow_international_phones: true.

import re as _re

_PHONE_TZ_RX = _re.compile(r"^255\d{9}$")
_PHONE_INTL_RX = _re.compile(r"^\d{8,15}$")
_EMAIL_RX = _re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _phone_pattern_for(request: Request):
    cfg = getattr(request.app.state, "notifications_config", {}) or {}
    return _PHONE_INTL_RX if cfg.get("allow_international_phones") else _PHONE_TZ_RX


def _normalise_phone(raw: str | None) -> str | None:
    if raw is None or raw == "":
        return None
    cleaned = raw.strip().replace(" ", "").replace("-", "")
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    return cleaned


def _validate_contact(request: Request, email: str | None, phone: str | None) -> str | None:
    """Returns None on success, an error message on failure."""
    if email and not _EMAIL_RX.match(email):
        return f"Invalid email: {email}"
    if phone:
        pat = _phone_pattern_for(request)
        if not pat.match(phone):
            return ("Invalid phone. Expected TZ format 255xxxxxxxxx (no +)."
                    if pat is _PHONE_TZ_RX else
                    "Invalid phone. Expected 8–15 digits (no +).")
    return None


class AddUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    role: str = Field(..., pattern="^(viewer|analyst|operator|admin)$")
    email: str | None = None
    phone: str | None = None


@router.post("/users", status_code=201)
async def add_user(
    body: AddUserRequest, request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    data = _read_security_yml()
    if any(u["username"] == body.username for u in data.get("users", [])):
        raise HTTPException(409, "User exists. Use rotate to issue a new key.")
    phone = _normalise_phone(body.phone)
    err = _validate_contact(request, body.email or None, phone)
    if err:
        raise HTTPException(400, err)
    api_key = secrets.token_urlsafe(32)
    api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    row: dict = {
        "username": body.username, "role": body.role,
        "api_key_hash": api_key_hash,
    }
    if body.email:
        row["email"] = body.email
    if phone:
        row["phone"] = phone
    data.setdefault("users", []).append(row)
    _write_security_yml(data)
    _reload_auth(request)
    _audit(request).log(
        action="admin.user.add", actor=user.username,
        target=body.username,
        details={"role": body.role,
                  "email_set": bool(body.email),
                  "phone_suffix": phone[-4:] if phone else None},
    )
    return {
        "username": body.username, "role": body.role,
        "api_key": api_key,
        "warning": "Copy this key now — it will not be shown again.",
    }


class ContactUpdate(BaseModel):
    email: str | None = None
    phone: str | None = None


@router.put("/users/{name}/contact")
async def admin_update_contact(
    name: str, body: ContactUpdate, request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    """Admin override: set email/phone for any user."""
    data = _read_security_yml()
    target = next((u for u in data.get("users", []) if u["username"] == name), None)
    if not target:
        raise HTTPException(404, "User not found")
    phone = _normalise_phone(body.phone)
    err = _validate_contact(request, body.email or None, phone)
    if err:
        raise HTTPException(400, err)
    if body.email is not None:
        if body.email == "":
            target.pop("email", None)
        else:
            target["email"] = body.email
    if body.phone is not None:
        if phone is None:
            target.pop("phone", None)
        else:
            target["phone"] = phone
    _write_security_yml(data)
    _reload_auth(request)
    _audit(request).log(
        action="admin.user.contact_update", actor=user.username,
        target=name,
        details={"email_set": bool(target.get("email")),
                  "phone_suffix": (target.get("phone") or "")[-4:] or None},
    )
    return {"username": name,
            "email": target.get("email"),
            "phone": target.get("phone")}


@router.post("/users/{name}/regen")
async def regen_key(
    name: str, request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    data = _read_security_yml()
    target = next((u for u in data.get("users", []) if u["username"] == name), None)
    if not target:
        raise HTTPException(404, "User not found")
    api_key = secrets.token_urlsafe(32)
    target["api_key_hash"] = hashlib.sha256(api_key.encode()).hexdigest()
    _write_security_yml(data)
    _reload_auth(request)
    _audit(request).log(
        action="admin.user.rotate_key", actor=user.username, target=name, details={},
    )
    return {
        "username": name, "api_key": api_key,
        "warning": "Copy this key now — it will not be shown again.",
    }


@router.delete("/users/{name}")
async def remove_user(
    name: str, request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    if name == user.username:
        raise HTTPException(400, "Cannot delete your own user.")
    data = _read_security_yml()
    before = len(data.get("users", []))
    data["users"] = [u for u in data.get("users", []) if u["username"] != name]
    if len(data["users"]) == before:
        raise HTTPException(404, "User not found")
    _write_security_yml(data)
    _reload_auth(request)
    _audit(request).log(
        action="admin.user.remove", actor=user.username, target=name, details={},
    )
    return {"username": name, "removed": True}


# ── Secret rotation (generate, persist note) ──────────────────────────────


@router.post("/rotate-jwt")
async def rotate_jwt(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    new = secrets.token_hex(32)
    _audit(request).log(
        action="admin.secret.rotate_jwt", actor=user.username, target="JWT_SECRET",
        details={"note": "Operator must update .env / config/security.yml and restart API."},
    )
    return {
        "new_secret": new,
        "instructions": "Update JWT_SECRET in .env (and config/security.yml if hard-coded) "
                         "then `docker compose restart api`. All sessions will be invalidated.",
    }


@router.post("/rotate-bootstrap")
async def rotate_bootstrap_token(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    new = secrets.token_hex(32)
    _audit(request).log(
        action="admin.secret.rotate_bootstrap", actor=user.username,
        target="FLEET_BOOTSTRAP_TOKEN",
        details={"note": "Operator must update .env and restart API."},
    )
    return {
        "new_token": new,
        "instructions": "Update FLEET_BOOTSTRAP_TOKEN in .env and `docker compose restart api`. "
                         "Endpoints enrolled before the rotation keep their HMAC secrets.",
    }


# ── Hardening checklist ───────────────────────────────────────────────────


@router.get("/hardening")
async def hardening(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    """Run the audit_compose_hardening.py script and return its output."""
    script = Path("scripts") / "audit_compose_hardening.py"
    if not script.exists():
        raise HTTPException(503, "audit_compose_hardening.py is missing.")
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Hardening audit timed out.")
    return {
        "passed": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


# ── Threat intel ──────────────────────────────────────────────────────────


@router.get("/threat-intel")
async def get_threat_intel(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    return {
        "enabled":    os.environ.get("MISP_ENABLED", "1") not in ("0", "false", "False"),
        "mode":       os.environ.get("MISP_MODE", "file"),
        "file_path":  os.environ.get("MISP_FILE_PATH", "threat_intel/iocs.json"),
        "url":        os.environ.get("MISP_URL", ""),
        "verify_ssl": os.environ.get("MISP_VERIFY_SSL", "1") != "0",
        "cache_ttl":  int(os.environ.get("MISP_CACHE_TTL_SECONDS", "3600")),
        # We deliberately never echo MISP_API_KEY.
    }


class ThreatIntelUpdate(BaseModel):
    enabled: bool | None = None
    mode: str | None = Field(None, pattern="^(file|live)$")
    file_path: str | None = None
    url: str | None = None
    api_key: str | None = None
    verify_ssl: bool | None = None
    cache_ttl: int | None = Field(None, ge=60, le=86400)


@router.put("/threat-intel")
async def update_threat_intel(
    body: ThreatIntelUpdate, request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    """
    Update MISP envvars in this process. Persistence to .env is the operator's
    responsibility (we don't write secrets to disk from a web request).
    """
    if body.enabled is not None:
        os.environ["MISP_ENABLED"] = "1" if body.enabled else "0"
    if body.mode is not None:
        os.environ["MISP_MODE"] = body.mode
    if body.file_path is not None:
        os.environ["MISP_FILE_PATH"] = body.file_path
    if body.url is not None:
        os.environ["MISP_URL"] = body.url
    if body.api_key is not None:
        os.environ["MISP_API_KEY"] = body.api_key
    if body.verify_ssl is not None:
        os.environ["MISP_VERIFY_SSL"] = "1" if body.verify_ssl else "0"
    if body.cache_ttl is not None:
        os.environ["MISP_CACHE_TTL_SECONDS"] = str(body.cache_ttl)
    _audit(request).log(
        action="admin.threat_intel.update", actor=user.username, target="misp",
        details={k: v for k, v in body.model_dump().items() if v is not None and k != "api_key"},
    )
    return {"updated": True,
            "note": "Process env updated. For durability, copy these into .env and restart."}


@router.post("/threat-intel/refresh")
async def refresh_threat_intel(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    # Best-effort cache reset on the live MISP client.
    try:
        from threat_intel.misp_client import MispClient
        # The live client is held inside the enricher (alert pipeline). We don't
        # have a direct handle here, so we just log the request — the next IoC
        # lookup will refresh naturally once the cache TTL expires.
        _audit(request).log(
            action="admin.threat_intel.refresh_requested",
            actor=user.username, target="misp", details={},
        )
        return {"requested": True,
                "note": "Cache will refresh on next lookup."}
    except Exception as e:
        raise HTTPException(500, f"Refresh failed: {e}")


# ── Backup ─────────────────────────────────────────────────────────────────


@router.get("/backup.tar.gz")
async def backup(
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    """Stream a tarball of state we'd back up nightly."""
    data_dir = Path(os.environ.get("DATA_DIR", "data"))
    targets = [
        data_dir / "audit" / "audit.db",
        data_dir / "alerts" / "alerts.db",
        data_dir / "fleet" / "fleet.db",
        data_dir / "anonymizer" / "salt.bin",
        data_dir / "drift",
        Path("detection/models"),
    ]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in targets:
            if p.exists():
                tar.add(p, arcname=str(p))
    buf.seek(0)
    _audit(request).log(
        action="admin.backup.download", actor=user.username, target="state",
        details={"size_bytes": buf.getbuffer().nbytes},
    )
    fname = f"apt-thp-backup-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.tar.gz"
    return StreamingResponse(
        iter([buf.read()]),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Paired devices (companion-app inventory) ──────────────────────────────


@router.get("/paired-devices")
async def list_paired_devices(
    request: Request,
    include_inactive: bool = False,
    user: User = Depends(require_permission("manage_users")),
):
    """Return all phones paired to the platform (admin only)."""
    store = getattr(request.app.state, "paired_devices", None)
    if store is None:
        return {"devices": []}
    return {"devices": store.list_all(include_inactive=include_inactive)}


@router.delete("/paired-devices/{row_id}")
async def unpair_device(
    row_id: int,
    request: Request,
    user: User = Depends(require_permission("manage_users")),
):
    """Unpair a phone: rotate the user's api_key (immediately invalidating
    the phone) and mark the inventory row inactive."""
    store = getattr(request.app.state, "paired_devices", None)
    if store is None:
        raise HTTPException(404, "Paired-devices store unavailable")
    row = store.get(row_id)
    if not row:
        raise HTTPException(404, "Paired device not found")
    if not row.get("active"):
        raise HTTPException(409, "Device already unpaired")

    # Clear ONLY the phone slot so the device's stored key dies but the
    # dashboard credential is left untouched.
    data = _read_security_yml()
    target = next((u for u in data.get("users", []) if u["username"] == row["username"]), None)
    if target is not None and target.get("mobile_api_key_hash"):
        target.pop("mobile_api_key_hash", None)
        _write_security_yml(data)
        _reload_auth(request)

    store.unpair(row_id)

    _audit(request).log(
        action="admin.companion_unpair",
        actor=user.username, target=row["username"],
        details={
            "row_id": row_id,
            "device": f"{row.get('brand') or '?'} {row.get('model') or '?'}",
        },
    )
    return {"status": "unpaired", "username": row["username"], "id": row_id}


# ── Auto-retrain scheduler ─────────────────────────────────────────────────
#
# The scheduler runs in the background, retraining lateral_movement +
# dns_exfiltration on a configurable cadence. New versions are staged
# (status="staged") and only become active when an admin promotes them via
# POST /models/{name}/versions/{version}/promote.
#
# These endpoints surface the scheduler's state + controls on the dashboard.

@router.get("/retrain/status")
async def retrain_status(
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    sched = getattr(request.app.state, "retrain_scheduler", None)
    if sched is None:
        return {"running": False, "note": "Scheduler not enabled (set RETRAIN_ENABLED=true)"}
    out = sched.status()

    # Tack on the per-detector staged-version queue so the UI can render
    # promote buttons next to each one without a second round-trip.
    from detection.model_store import ModelStore
    store = ModelStore(base_dir="detection/models",
                       signing_key=os.environ.get("MODEL_SIGNING_KEY", ""))
    out["staged"] = {
        name: store.list_staged(name) for name in ("lateral_movement", "dns_exfiltration")
    }
    out["active"] = {}
    for name in ("lateral_movement", "dns_exfiltration"):
        active = [v for v in store.list_versions(name) if v.get("status") == "active"]
        out["active"][name] = active[-1] if active else None
    return out


class _IntervalBody(BaseModel):
    seconds: int = Field(..., ge=60, le=86400)


@router.post("/retrain/interval")
async def retrain_set_interval(
    body: _IntervalBody,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    sched = getattr(request.app.state, "retrain_scheduler", None)
    if sched is None:
        raise HTTPException(409, "Scheduler not enabled")
    new_value = sched.set_interval(body.seconds)
    _audit(request).log(
        action="retrain.interval.set", actor=user.username, target="scheduler",
        details={"new_interval_s": new_value},
    )
    return {"status": "ok", "interval_seconds": new_value}


@router.post("/retrain/run-now")
async def retrain_run_now(
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Wake the loop so it runs the next cycle immediately. Doesn't wait for
    the cycle to finish — poll /retrain/status to see the result."""
    sched = getattr(request.app.state, "retrain_scheduler", None)
    if sched is None:
        raise HTTPException(409, "Scheduler not enabled")
    sched.trigger_now()
    _audit(request).log(
        action="retrain.trigger_now", actor=user.username, target="scheduler",
        details={},
    )
    return {"status": "triggered"}
