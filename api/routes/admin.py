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
from typing import Optional

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
    # Walk up from this file to find the script — survives both `docker run`
    # (cwd=/app) and ad-hoc invocations (cwd=anywhere). The script itself
    # contains the same fallback logic for finding docker-compose.yml.
    here = Path(__file__).resolve().parent
    script: Path | None = None
    for parent in [here, *here.parents]:
        candidate = parent / "scripts" / "audit_compose_hardening.py"
        if candidate.exists():
            script = candidate
            break
    if script is None:
        raise HTTPException(503, "audit_compose_hardening.py is missing.")
    try:
        # Run from the script's repo root so the script's CWD-based
        # compose-file lookup hits ./docker-compose.yml on the first try.
        proc = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(script.parent.parent),
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

    # Tack on the per-detector staged + discarded queues so the UI can
    # render promote/discard/delete buttons next to each version without
    # second round-trips.
    from detection.model_store import ModelStore
    store = ModelStore(base_dir="detection/models",
                       signing_key=os.environ.get("MODEL_SIGNING_KEY", ""))
    out["staged"] = {
        name: store.list_staged(name) for name in ("lateral_movement", "dns_exfiltration")
    }
    out["discarded"] = {
        name: store.list_discarded(name) for name in ("lateral_movement", "dns_exfiltration")
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


# ── Handler-script OTA (version management + push + rollback) ─────────────
#
# The lifecycle is: operator uploads a new .ps1 → row enters status='staged'
# → operator promotes → exactly one row is 'live' at a time, previous one
# becomes 'archived'. Agents auto-pull the live version via
# /agents/{id}/handler/manifest on each poll. Operator can also push a
# specific version to specific agents via /admin/handler/push, or roll the
# fleet back via /admin/handler/rollback. Every action is audit-logged.
#
# Permissions:
#   manage_fleet   — push + rollback (operationally targets the fleet)
#   retrain_models — upload + promote + archive + delete
#                    (version-store mutations; same perm gates model retrain
#                    because both control what code/model ships to endpoints)

def _handler_store_dep(request: Request):
    store = getattr(request.app.state, "handler_store", None)
    if store is None:
        raise HTTPException(503, "Handler-version store unavailable")
    return store


@router.post("/handler/upload", status_code=201)
async def handler_upload(
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """
    Upload a new agent_command_handler.ps1 as a staged version. Accepts
    multipart/form-data with fields:
      file           — the .ps1 bytes
      version_label  — unique label (e.g. v2026.05.30-1428)
      notes          — optional release-note string

    Server-side syntax check is NOT performed here — the agent does its own
    `[scriptblock]::Create(...)` parse-check before swapping the file on
    disk. Uploading a syntactically-broken script is harmless until it's
    promoted (and even then, agents reject it before applying).
    """
    from fastapi import Form, UploadFile, File
    form = await request.form()
    upload = form.get("file")
    version_label = (form.get("version_label") or "").strip()
    notes = (form.get("notes") or "").strip() or None
    if not isinstance(upload, UploadFile):
        raise HTTPException(400, "file field is required (multipart upload)")
    if not version_label:
        raise HTTPException(400, "version_label is required")
    content_bytes = await upload.read()
    if not content_bytes or len(content_bytes) < 200:
        raise HTTPException(400, "file content too small to be a valid handler")
    if len(content_bytes) > 5 * 1024 * 1024:
        raise HTTPException(413, "handler script too large (max 5 MB)")

    store = _handler_store_dep(request)
    try:
        row = store.create(
            version_label=version_label,
            content_bytes=content_bytes,
            uploaded_by=user.username,
            notes=notes,
        )
    except ValueError as e:
        msg = str(e)
        # Duplicate label → 409 Conflict; every other ValueError comes
        # from _validate_handler_bytes (bad size / encoding / missing
        # markers / unbalanced braces) → 400 Bad Request.
        status = 409 if "already exists" in msg else 400
        raise HTTPException(status, msg)

    _audit(request).log(
        action="handler.upload",
        actor=user.username, target=version_label,
        details={
            "sha256":     row["sha256"],
            "size_bytes": row["size_bytes"],
            "notes":      notes,
        },
    )
    return {"id": row["id"], "version_label": row["version_label"],
            "sha256": row["sha256"], "size_bytes": row["size_bytes"],
            "status": row["status"]}


@router.get("/handler/versions")
async def handler_versions(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """List every uploaded version with status + counts of how many agents
    are currently on each. Read-only, used by the dashboard version page."""
    store = _handler_store_dep(request)
    rows = store.list_all(include_content=False)
    # Annotate with the per-agent count of agents on that version.
    cq = getattr(request.app.state, "command_queue", None)
    by_version: dict[str, int] = {}
    if cq is not None:
        for a in cq.list_agents():
            hv = a.get("handler_version") or ""
            if hv:
                by_version[hv] = by_version.get(hv, 0) + 1
    for r in rows:
        r["agents_on_this"] = by_version.get(r["version_label"], 0)
    return {"versions": rows, "agents_with_no_version": by_version.get("", 0)}


@router.post("/handler/{row_id}/promote")
async def handler_promote(
    row_id: int,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Promote a staged or archived row to LIVE. Previous live → archived."""
    store = _handler_store_dep(request)
    previous_live = store.get_live()
    row = store.promote(row_id, promoted_by=user.username)
    if row is None:
        raise HTTPException(404, "Handler version not found")

    _audit(request).log(
        action="handler.promote",
        actor=user.username, target=row["version_label"],
        details={
            "previous_live": previous_live["version_label"] if previous_live else None,
            "sha256":        row["sha256"],
        },
    )
    return {"status": "live", "id": row["id"], "version_label": row["version_label"]}


@router.delete("/handler/{row_id}", status_code=204)
async def handler_delete(
    row_id: int,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Hard-delete a staged or archived row. Refuses to touch the live one."""
    store = _handler_store_dep(request)
    row = store.get_by_id(row_id)
    if row is None:
        raise HTTPException(404, "Handler version not found")
    try:
        store.delete(row_id)
    except ValueError as e:
        raise HTTPException(409, str(e))
    _audit(request).log(
        action="handler.archive",
        actor=user.username, target=row["version_label"],
        details={"deleted": True},
    )
    from fastapi import Response
    return Response(status_code=204)


class _PushRequest(BaseModel):
    version_label: str
    agent_ids:     list[str] = Field(default_factory=list)
    target_all:    bool      = False


@router.post("/handler/push", status_code=202)
async def handler_push(
    body: _PushRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """Enqueue UPDATE_HANDLER commands for one or many agents. Either
    `agent_ids` lists explicit targets, or `target_all=true` broadcasts to
    every enrolled agent. Returns per-agent enqueue results."""
    store = _handler_store_dep(request)
    cq = getattr(request.app.state, "command_queue", None)
    if cq is None:
        raise HTTPException(503, "Command queue unavailable")

    version = store.get_by_label(body.version_label)
    if version is None:
        raise HTTPException(404, f"Handler version '{body.version_label}' not found")

    targets: list[str]
    if body.target_all:
        targets = [a["agent_id"] for a in cq.list_agents()]
    else:
        targets = list(dict.fromkeys(body.agent_ids))  # de-dupe, preserve order
    if not targets:
        raise HTTPException(400, "no targets (set target_all=true or pass agent_ids)")

    from shared.commands import CommandType
    enqueued: list[dict] = []
    failed:   list[dict] = []
    for agent_id in targets:
        try:
            cmd = cq.enqueue_command(
                agent_id=agent_id,
                command_type=CommandType.UPDATE_HANDLER,
                params={"version": body.version_label},
                issued_by=user.username,
            )
            enqueued.append({"agent_id": agent_id, "command_id": cmd.command_id})
        except ValueError as e:
            failed.append({"agent_id": agent_id, "error": str(e)})

    _audit(request).log(
        action="handler.push.requested",
        actor=user.username, target=body.version_label,
        details={
            "n_targets":   len(targets),
            "n_enqueued":  len(enqueued),
            "n_failed":    len(failed),
            "target_all":  body.target_all,
        },
    )
    return {"enqueued": enqueued, "failed": failed,
            "version_label": body.version_label}


@router.post("/agents/{agent_id}/handler-retry", status_code=202)
async def handler_retry(
    agent_id: str,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """Re-issue the CURRENT LIVE handler version to a single agent whose
    last OTA failed (handler_update_status != 'ok').

    Useful when the failure was transient (network blip, momentary disk
    issue) — re-pushing the same version may succeed on retry. The agent's
    `_HandlerFetchAndApply` is idempotent: if the bytes are already on
    disk and verified, the operation is a no-op.

    The dashboard's "Retry push" button on the UPDATE FAILED pill modal
    calls this endpoint. Returns the new command_id so the modal can poll
    /fleet/commands/{id} for completion."""
    cq = getattr(request.app.state, "command_queue", None)
    if cq is None:
        raise HTTPException(503, "Command queue unavailable")
    store = _handler_store_dep(request)

    agent = cq.get_agent(agent_id)
    if agent is None:
        raise HTTPException(404, f"Agent '{agent_id}' not found")

    live = store.get_live()
    if live is None:
        raise HTTPException(
            409, "No live handler version on server — promote one first"
        )

    from shared.commands import CommandType
    try:
        cmd = cq.enqueue_command(
            agent_id=agent_id,
            command_type=CommandType.UPDATE_HANDLER,
            params={"version": live["version_label"]},
            issued_by=user.username,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    _audit(request).log(
        action="handler.push.requested",
        actor=user.username, target=live["version_label"],
        details={
            "n_targets":         1,
            "n_enqueued":        1,
            "n_failed":          0,
            "target_all":        False,
            "retry_for_agent":   agent_id,
            "prior_status":      agent.get("handler_update_status"),
            "prior_bad_version": agent.get("handler_update_bad_version"),
        },
    )
    return {
        "command_id":    cmd.command_id,
        "agent_id":      agent_id,
        "version_label": live["version_label"],
    }


# Sentinel uploader name on auto-staged rows so the watcher can identify
# its own prior stage and replace it (rather than piling up duplicates).
# Real human uploads have an actual username here.
_HANDLER_FS_SCAN_UPLOADER = "filesystem-scan"


@router.post("/handler/scan")
async def handler_scan(
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Hash `scripts/agent_command_handler.ps1` on the server's filesystem
    and reconcile against the version store.

    Outcomes:
      - File missing      → 404 with the path checked.
      - Bytes match LIVE  → 200 `{status: "already_live", ...}`. Common
                            steady state; no action taken.
      - Bytes match ANY existing row (staged / archived) → 200
                            `{status: "matches_existing", ...}` so the
                            operator can promote that row directly.
      - Bytes are NEW     → either replace the previously-auto-staged row
                            (if one exists) or create a fresh auto-staged
                            row. Returns 201 `{status: "staged", ...}`.

    Replace semantics: there is only ever ONE auto-staged row at a time.
    This keeps the handler-versions list clean during rapid local
    iteration. Re-running the scan three times in five minutes produces a
    single 'auto' row with the most recent bytes — not three rows.

    Promotion is ALWAYS manual. The watcher never auto-promotes; the
    operator clicks Promote on the resulting row to push to the fleet.
    """
    script_path = Path(os.environ.get(
        "HANDLER_SCRIPT_PATH",
        "scripts/agent_command_handler.ps1",
    ))
    if not script_path.exists():
        raise HTTPException(
            404,
            f"Handler script not found at {script_path} "
            f"(set HANDLER_SCRIPT_PATH to override)",
        )

    content_bytes = script_path.read_bytes()
    # Run the same validate + normalise as the store would on store.create.
    # We need the CANONICAL bytes to compare against existing rows' sha256
    # (which are also canonical) — otherwise a disk file with LF endings
    # always looks "new" even when its CRLF-normalised form is already
    # staged or live.
    from api.handler_store import _validate_handler_bytes  # local import to avoid cycle
    try:
        canonical_bytes = _validate_handler_bytes(content_bytes)
    except ValueError as e:
        raise HTTPException(400, f"{script_path}: {e}")
    sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    store = _handler_store_dep(request)
    rows = store.list_all(include_content=False)

    # Look for an exact-bytes match in any existing row.
    match = next((v for v in rows if v["sha256"] == sha256), None)
    if match:
        if match["status"] == "live":
            return {
                "status":        "already_live",
                "message":       f"Disk file matches the live version '{match['version_label']}' — nothing to stage.",
                "matched_id":    match["id"],
                "matched_label": match["version_label"],
                "sha256":        sha256,
            }
        return {
            "status":         "matches_existing",
            "message":        (
                f"Disk file matches existing {match['status']} version "
                f"'{match['version_label']}'. Promote that row directly "
                f"instead of re-staging."
            ),
            "matched_id":     match["id"],
            "matched_label":  match["version_label"],
            "matched_status": match["status"],
            "sha256":         sha256,
        }

    # Bytes are new — either replace prior auto-stage or create fresh.
    prior_auto_label: Optional[str] = None
    for v in rows:
        if v["status"] == "staged" and v["uploaded_by"] == _HANDLER_FS_SCAN_UPLOADER:
            prior_auto_label = v["version_label"]
            try:
                store.delete(v["id"])
            except ValueError as e:
                # store.delete refuses to touch live, but a prior auto-stage
                # is staged by definition. This branch is paranoia.
                raise HTTPException(500, f"could not replace prior auto-stage: {e}")
            break  # only one prior auto-stage by invariant

    label = "auto-" + time.strftime(
        "%Y%m%dT%H%M%SZ",
        time.gmtime(time.time()),
    )
    notes = (
        f"Auto-detected by filesystem scan. "
        f"File: {script_path} · sha256: {sha256[:12]}…"
    )
    try:
        row = store.create(
            version_label=label,
            content_bytes=content_bytes,
            uploaded_by=_HANDLER_FS_SCAN_UPLOADER,
            notes=notes,
        )
    except ValueError as e:
        msg = str(e)
        # Duplicate label → 409; validation failure → 400. The label is
        # auto-generated from a timestamp so duplicate is unlikely but not
        # impossible (clock skew on consecutive scans in the same second).
        status = 409 if "already exists" in msg else 400
        raise HTTPException(status, msg)

    _audit(request).log(
        action="handler.scan.staged",
        actor=user.username, target=label,
        details={
            "sha256":           sha256,
            "size_bytes":       len(content_bytes),
            "path":             str(script_path),
            "replaced_label":   prior_auto_label,
        },
    )
    return {
        "status":         "staged",
        "id":             row["id"],
        "version_label":  label,
        "sha256":         sha256,
        "replaced_label": prior_auto_label,
        "size_bytes":     len(content_bytes),
    }


class _RollbackRequest(BaseModel):
    agent_ids:  list[str] = Field(default_factory=list)
    target_all: bool      = False
    reason:     str       = ""


@router.post("/handler/rollback", status_code=202)
async def handler_rollback(
    body: _RollbackRequest,
    request: Request,
    user: User = Depends(require_permission("manage_fleet")),
):
    """Enqueue ROLLBACK_HANDLER for one or many agents. Each agent swaps
    its live ↔ .bak file on the next poll, reverting to whatever version
    was installed before the most recent update."""
    cq = getattr(request.app.state, "command_queue", None)
    if cq is None:
        raise HTTPException(503, "Command queue unavailable")
    targets: list[str]
    if body.target_all:
        targets = [a["agent_id"] for a in cq.list_agents()]
    else:
        targets = list(dict.fromkeys(body.agent_ids))
    if not targets:
        raise HTTPException(400, "no targets (set target_all=true or pass agent_ids)")
    if len(body.reason) > 500:
        raise HTTPException(400, "reason too long (max 500 chars)")

    from shared.commands import CommandType
    enqueued: list[dict] = []
    failed:   list[dict] = []
    for agent_id in targets:
        try:
            cmd = cq.enqueue_command(
                agent_id=agent_id,
                command_type=CommandType.ROLLBACK_HANDLER,
                params={"reason": body.reason},
                issued_by=user.username,
            )
            enqueued.append({"agent_id": agent_id, "command_id": cmd.command_id})
        except ValueError as e:
            failed.append({"agent_id": agent_id, "error": str(e)})

    _audit(request).log(
        action="handler.rollback.requested",
        actor=user.username, target="fleet",
        details={
            "n_targets":  len(targets),
            "n_enqueued": len(enqueued),
            "n_failed":   len(failed),
            "reason":     body.reason,
        },
    )
    return {"enqueued": enqueued, "failed": failed}
