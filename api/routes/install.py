# api/routes/install.py
"""
URL-served Windows endpoint installer.

Operator flow:
  1. /dashboard/enroll → click Generate → POST /install/tokens
  2. Server returns a single-use 30-min token
  3. Operator copies the one-liner:
        irm http://<server>:8000/install/agent.ps1?token=<t> | iex
  4. Endpoint runs the one-liner. The token survives one enrollment then dies.

Asset routes are token-gated where appropriate. The heavyweight files
(deploy_endpoint.ps1, sysmon configs, Wazuh MSI, Sysmon ZIP) are NOT secret on
their own — they're public installers. The secret is the per-deployment token,
which is validated on /install/agent.ps1 (the entry point) and consumed on
/fleet/agents/enroll. Without a valid token, the agent enrollment fails and
the install is useless.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from api.middleware import require_permission
from shared.security import User

router = APIRouter(prefix="/install", tags=["install"])


# ── Paths ────────────────────────────────────────────────────────────────

# Resolve scripts directory relative to repo root. Works whether the api is
# launched from /app inside the container or from ./ on a dev machine.
_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"
_CACHE_DIR   = _SCRIPTS_DIR / "cache"

WAZUH_MSI_NAME  = os.environ.get("WAZUH_MSI_NAME",  "wazuh-agent-4.7.0-1.msi")
SYSMON_ZIP_NAME = os.environ.get("SYSMON_ZIP_NAME", "Sysmon.zip")


def _store(request: Request):
    s = getattr(request.app.state, "enrollment_tokens", None)
    if s is None:
        raise HTTPException(503, "Enrollment token store not initialised on this server.")
    return s


def _audit(request: Request):
    return request.app.state.audit_trail


def _server_base_url(request: Request, override_ip: Optional[str] = None) -> str:
    """Best-effort base URL the endpoint should call back on.

    Priority: explicit override → PUBLIC_HOST_URL env → request.base_url."""
    if override_ip:
        # Operator-supplied IP wins (e.g. switching the address the endpoint
        # uses without rotating the server's bound IP).
        return f"http://{override_ip}:{request.url.port or 8000}"
    env = os.environ.get("PUBLIC_HOST_URL", "").strip()
    if env:
        return env.rstrip("/")
    return str(request.base_url).rstrip("/")


# ── Token CRUD (admin-gated) ─────────────────────────────────────────────

class CreateTokenRequest(BaseModel):
    profile:             str = Field("Full", pattern="^(Lean|Balanced|Full)$")
    server_ip:           Optional[str] = None
    expires_in_minutes:  int = Field(30, ge=5, le=240)
    # max_uses=0 ⇒ unlimited (still TTL-bounded). Cap at 1000 to bound row
    # growth in enrollment_token_uses and protect against typos.
    max_uses:            int = Field(10, ge=0, le=1000)


@router.post("/tokens", status_code=201)
async def create_token(
    body: CreateTokenRequest,
    request: Request,
    user: User = Depends(require_permission("enroll_agents")),
):
    """Mint a fresh single-use installer token.

    Default profile is **Full** because the detectors are trained on the
    Full-telemetry feature schema — Lean/Balanced will under-perform until
    a model is retrained against that profile's reduced event set."""
    base = _server_base_url(request, body.server_ip)
    token_id, token, expires_at = _store(request).create(
        profile=body.profile,
        server_ip=body.server_ip,
        created_by=user.username,
        ttl_seconds=body.expires_in_minutes * 60,
        max_uses=body.max_uses,
    )
    url = f"{base}/install/agent.ps1?token={token}"
    one_liner = f"irm \"{url}\" | iex"
    _audit(request).log(
        action="install.token.create", actor=user.username, target=str(token_id),
        details={"profile": body.profile, "ttl_min": body.expires_in_minutes,
                 "max_uses": body.max_uses, "server_base": base},
    )
    return {
        "id": token_id, "token": token, "url": url, "one_liner": one_liner,
        "profile": body.profile, "server_base": base,
        "expires_at": expires_at,
        "max_uses": body.max_uses, "use_count": 0,
        # Server-side QR PNG as a data: URL. The plaintext token is in the URL,
        # so we MUST NOT round-trip it through any public QR encoder — that
        # would breach the Tanzania-data-residency rule and turn the QR into
        # a token-leak vector. data: URL embeds inline.
        "qr_data_url": _qr_data_url(url),
    }


def _qr_data_url(url: str) -> str:
    """Render the install URL as a QR PNG and return as data:image/png;base64,…"""
    import base64
    import io
    import qrcode
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


@router.get("/tokens")
async def list_tokens(
    request: Request,
    user: User = Depends(require_permission("enroll_agents")),
):
    return {
        "active": _store(request).list_active(limit=50),
        "recent": _store(request).list_recent(limit=50),
    }


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: int,
    request: Request,
    user: User = Depends(require_permission("enroll_agents")),
):
    if not _store(request).revoke(token_id, user.username):
        raise HTTPException(404, "Token not found or already used/revoked")
    _audit(request).log(
        action="install.token.revoke", actor=user.username, target=str(token_id),
    )
    return Response(status_code=204)


# ── Asset serving ────────────────────────────────────────────────────────

def _static_file(path: Path, media_type: str):
    if not path.exists():
        raise HTTPException(503,
            f"{path.name} not present on server. Run scripts/fetch_install_cache.sh "
            "or place the file manually, then rebuild the image.")
    return FileResponse(
        str(path), media_type=media_type, filename=path.name,
        headers={"Cache-Control": "public, max-age=3600"},
    )


# NOTE on methods: all six static-asset routes below accept GET AND HEAD.
# HEAD is the right semantic for "fetch headers only" -- used by
# scripts/deploy_endpoint.ps1 Step 6 to read the server's Date header for
# clock-skew measurement without downloading 100KB of body. GET-only routes
# returned 405 there; switching to api_route(methods=["GET","HEAD"]) fixes
# that without changing any response logic (Starlette's FileResponse handles
# HEAD by stripping the body automatically). 2026-06-02 fix.
@router.api_route("/deploy_endpoint.ps1", methods=["GET", "HEAD"])
async def deploy_script():
    return _static_file(_SCRIPTS_DIR / "deploy_endpoint.ps1", "text/plain")


@router.api_route("/agent_command_handler.ps1", methods=["GET", "HEAD"])
async def handler_script():
    return _static_file(_SCRIPTS_DIR / "agent_command_handler.ps1", "text/plain")


@router.api_route("/sysmon_config.xml", methods=["GET", "HEAD"])
async def sysmon_config_balanced():
    return _static_file(_SCRIPTS_DIR / "sysmon_config.xml", "application/xml")


@router.api_route("/sysmon_config_lean.xml", methods=["GET", "HEAD"])
async def sysmon_config_lean():
    return _static_file(_SCRIPTS_DIR / "sysmon_config_lean.xml", "application/xml")


@router.api_route("/wazuh-agent.msi", methods=["GET", "HEAD"])
async def wazuh_msi():
    return _static_file(_CACHE_DIR / WAZUH_MSI_NAME,
                        "application/x-msi")


@router.api_route("/sysmon.zip", methods=["GET", "HEAD"])
async def sysmon_zip():
    return _static_file(_CACHE_DIR / SYSMON_ZIP_NAME,
                        "application/zip")


# ── Bootstrap one-liner (token-gated) ────────────────────────────────────

# Embedded PowerShell — kept inline rather than a Jinja template so the
# server can guarantee the script is fully self-contained when served.
_BOOTSTRAP_PS1 = r"""<#
.SYNOPSIS
    APT THP one-liner installer — downloads helpers from the platform server
    and runs deploy_endpoint.ps1 with the right parameters.

.DESCRIPTION
    Generated server-side per enrollment token. Token is single-use and
    expires {expires_in_min} minutes after generation.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Bypass restrictive script policies for THIS process only. iex (used by the
# one-liner) sidesteps file ExecutionPolicy, but the downloaded
# deploy_endpoint.ps1 we invoke below is a file — without this it'd fail with
# "running scripts is disabled on this system" on policy-default endpoints.
try {{ Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue }} catch {{}}

$ServerBase   = '{server_base}'
$Token        = '{token}'
$Profile      = '{profile}'
$ServerIP     = '{server_ip}'
$WazuhRegPwd  = '{wazuh_reg_password}'

# Refuse to run as a non-admin: deploy_endpoint requires elevation.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Host '[apt-thp] ERROR: must be run as Administrator.' -ForegroundColor Red
    Write-Host 'Open PowerShell as Administrator and re-run the one-liner.' -ForegroundColor Yellow
    exit 1
}}

$Stage = Join-Path $env:TEMP 'apt-thp-install'
if (-not (Test-Path $Stage)) {{ New-Item -ItemType Directory -Path $Stage | Out-Null }}

function Fetch($Name) {{
    $url  = "$ServerBase/install/$Name"
    $dest = Join-Path $Stage $Name
    Write-Host "[apt-thp] downloading $Name from $url"
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    # Strip the Mark-of-the-Web so SmartScreen / AppLocker won't quarantine the
    # downloaded .ps1 mid-install. No-op on filesystems without ADS.
    try {{ Unblock-File -Path $dest -ErrorAction SilentlyContinue }} catch {{}}
}}

# The four scripts the deployer needs, all served by the platform.
Fetch 'deploy_endpoint.ps1'
Fetch 'agent_command_handler.ps1'
Fetch 'sysmon_config.xml'
Fetch 'sysmon_config_lean.xml'

# Wazuh MSI + Sysmon ZIP are downloaded by deploy_endpoint.ps1 itself via
# the URL parameters below — no need to fetch them here.

$deployArgs = @{{
    ServerIP             = $ServerIP
    RegistrationPassword = $WazuhRegPwd
    Profile              = $Profile
    PlatformApiUrl       = $ServerBase
    EnrollmentToken      = $Token
    WazuhMsiUrl          = "$ServerBase/install/wazuh-agent.msi"
    SysmonZipUrl         = "$ServerBase/install/sysmon.zip"
}}

Write-Host "[apt-thp] launching deploy_endpoint.ps1 (Profile=$Profile)" -ForegroundColor Cyan
& (Join-Path $Stage 'deploy_endpoint.ps1') @deployArgs
"""


@router.get("/agent.ps1", response_class=PlainTextResponse)
async def bootstrap_agent_ps1(
    request: Request,
    token: str = Query(..., min_length=8, max_length=128),
):
    """Token-gated bootstrap that the operator pipes into PowerShell.

    Errors map to HTTP statuses so an operator can diagnose from a curl:
        404 token unknown    409 already consumed    410 expired
    """
    store = _store(request)
    ok, reason, row = store.validate(token)
    if not ok:
        status = {"not_found": 404, "expired": 410, "used": 409,
                  "exhausted": 409, "revoked": 410}.get(reason, 403)
        _audit(request).log(
            action="install.bootstrap.rejected",
            actor="install",
            target=f"token:{hashlib.sha256(token.encode()).hexdigest()[:8]}",
            details={"reason": reason, "client_ip": request.client.host if request.client else "-"},
        )
        raise HTTPException(status, f"Enrollment token {reason.replace('_', ' ')}.")

    # Resolve the server base URL the endpoint should call back on. Prefer the
    # operator-set server_ip in the token; fall back to whatever address the
    # operator hit us on (works for typical LAN deployments).
    base = _server_base_url(request, row.get("server_ip"))

    wazuh_reg_pwd = os.environ.get("WAZUH_REGISTRATION_PASSWORD", "")
    if not wazuh_reg_pwd:
        # The bootstrap CAN run without it (deploy_endpoint will fail), but the
        # operator would only find out mid-install. Refuse early with a clear
        # message and an audit row so the admin can fix .env once.
        _audit(request).log(
            action="install.bootstrap.misconfigured",
            actor="install", target=str(row["id"]),
            details={"missing_env": "WAZUH_REGISTRATION_PASSWORD"},
        )
        raise HTTPException(
            503,
            "WAZUH_REGISTRATION_PASSWORD is not set on the server — add it to "
            ".env and restart the api container, then regenerate the token.",
        )

    # Server IP for Wazuh manager. If not in the token, derive from the API URL.
    server_ip = row.get("server_ip") or _extract_host(base)

    body = _BOOTSTRAP_PS1.format(
        server_base=base.replace("'", "''"),
        token=token.replace("'", "''"),
        profile=row["profile"],
        server_ip=server_ip.replace("'", "''"),
        wazuh_reg_password=wazuh_reg_pwd.replace("'", "''"),
        expires_in_min=int(max(0, row["expires_at"] - time.time()) / 60),
    )
    _audit(request).log(
        action="install.bootstrap.served", actor="install", target=str(row["id"]),
        details={"profile": row["profile"],
                 "client_ip": request.client.host if request.client else "-"},
    )
    return PlainTextResponse(body, media_type="text/plain")


def _extract_host(url: str) -> str:
    """Pull host out of a URL like 'http://10.0.0.5:8000' → '10.0.0.5'."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.hostname or url


# ── Standalone bundle (.zip) ─────────────────────────────────────────────

# Standalone launcher rendered into the bundle. With no token, the operator
# supplies -ServerIP / -RegistrationPassword at runtime and the bundle just
# installs Sysmon + Wazuh (no fleet control). With a token, all params are
# baked in and the operator just runs the launcher.
_BUNDLE_LAUNCHER_PS1 = r"""#Requires -RunAsAdministrator
<#
.SYNOPSIS
    APT THP — standalone launcher for the bundled installer.

.DESCRIPTION
    Run from inside the unzipped bundle directory. All assets (scripts,
    sysmon configs, Wazuh MSI, Sysmon ZIP) sit next to this file so
    deploy_endpoint.ps1 runs fully offline.
#>
param(
    [string]$ServerIP             = '{server_ip}',
    [string]$RegistrationPassword = '{wazuh_reg_password}',
    [string]$Profile              = '{profile}',
    [string]$PlatformApiUrl       = '{server_base}',
    [string]$EnrollmentToken      = '{token}',
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'
try {{ Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue }} catch {{}}
$Stage = Split-Path $MyInvocation.MyCommand.Path

# Defensive: prompt for missing required params when the bundle was issued
# without a token (no Wazuh password baked in).
if (-not $ServerIP) {{
    $ServerIP = Read-Host 'Wazuh manager IP / hostname'
}}
if (-not $RegistrationPassword -and -not $Verify) {{
    $RegistrationPassword = Read-Host 'Wazuh registration password'
}}

$args = @{{
    ServerIP             = $ServerIP
    RegistrationPassword = $RegistrationPassword
    Profile              = $Profile
}}
if ($PlatformApiUrl)  {{ $args.PlatformApiUrl  = $PlatformApiUrl }}
if ($EnrollmentToken) {{ $args.EnrollmentToken = $EnrollmentToken }}
if ($Verify)          {{ $args.Verify          = $true }}

# Get-ChildItem so deploy_endpoint can resolve $ScriptDir back to $Stage and
# find sysmon_config.xml + the bundled MSI / Sysmon ZIP without a network hop.
& (Join-Path $Stage 'deploy_endpoint.ps1') @args
"""


_BUNDLE_README = """APT THP — Endpoint Install Bundle
================================================================

This ZIP is a self-contained Windows endpoint installer. It bundles:
  - deploy_endpoint.ps1         (Sysmon + Wazuh + handler installer)
  - agent_command_handler.ps1   (fleet remote-control task)
  - sysmon_config.xml           (full Sysmon ruleset)
  - sysmon_config_lean.xml      (low-overhead ruleset)
  - wazuh-agent-*.msi           (the Wazuh agent installer)
  - Sysmon.zip                  (Sysinternals Sysmon binary)
  - launch.ps1                  (one-button launcher)

No network access is required during install (Tanzania data-residency safe).
The endpoint only contacts the platform server for telemetry shipping after
the install completes.

================================================================
HOW TO RUN
================================================================
1. Copy this ZIP to the Windows endpoint (USB / network share / RDP).
2. Right-click → Extract All.
3. Open PowerShell **as Administrator** in the extracted folder.
4. Run:    .\\launch.ps1
5. Wait for the script to finish (3-5 minutes).

If the bundle was generated WITHOUT an enrollment token, the launcher will
ask for the Wazuh registration password at runtime. With a token, every
parameter is pre-filled and the install is fully unattended.

================================================================
DUAL-MODE NOTES
================================================================
- The deploy_endpoint.ps1 script can be re-run independently. Pass
  -ServerIP, -RegistrationPassword, -Profile yourself.
- For URL-served install (no ZIP), use the one-liner on the dashboard
  /dashboard/enroll page instead.
- Enrollment tokens are single-use and expire 30 minutes after generation.
  If the launcher refuses to enroll, regenerate the bundle.
"""


@router.get("/bundle.zip")
async def install_bundle(
    request: Request,
    token: Optional[str] = Query(None, min_length=8, max_length=128),
):
    """Stream a self-contained installer ZIP.

    With ?token=X: all parameters (server IP, profile, registration password,
    token) are baked into launch.ps1 — operator just runs it.

    Without token: a generic bundle that prompts at runtime. Use this for
    air-gapped seeding or scripted batch deploys where the operator supplies
    credentials separately."""
    import io
    import zipfile

    server_base = _server_base_url(request)
    server_ip = _extract_host(server_base)
    profile = "Full"
    embed_token = ""
    embed_pwd = ""
    token_id: Optional[int] = None

    if token:
        ok, reason, row = _store(request).validate(token)
        if not ok:
            status = {"not_found": 404, "expired": 410, "used": 409,
                      "exhausted": 409, "revoked": 410}.get(reason, 403)
            raise HTTPException(status,
                f"Enrollment token {reason.replace('_', ' ')}.")
        # Honour token's profile + server_ip
        profile = row["profile"]
        token_id = row["id"]
        if row.get("server_ip"):
            server_base = _server_base_url(request, row["server_ip"])
            server_ip = row["server_ip"]
        embed_token = token
        embed_pwd = os.environ.get("WAZUH_REGISTRATION_PASSWORD", "")
        if not embed_pwd:
            raise HTTPException(503,
                "WAZUH_REGISTRATION_PASSWORD not set on the server. "
                "Add it to .env and restart, then regenerate the bundle.")
        _audit(request).log(
            action="install.bundle.served", actor="install", target=str(token_id),
            details={"profile": profile,
                     "client_ip": request.client.host if request.client else "-"},
        )

    # Assemble the ZIP in-memory. Bundle is ~12-15MB (Wazuh MSI dominates) so
    # streaming a Response body is fine; no need for chunked file delivery.
    buf = io.BytesIO()
    launcher = _BUNDLE_LAUNCHER_PS1.format(
        server_base=server_base.replace("'", "''"),
        token=embed_token.replace("'", "''"),
        profile=profile,
        server_ip=server_ip.replace("'", "''"),
        wazuh_reg_password=embed_pwd.replace("'", "''"),
    )

    def _add(zf: zipfile.ZipFile, path: Path) -> None:
        if not path.exists():
            raise HTTPException(503,
                f"Bundle source missing: {path.name}. Run "
                "scripts/fetch_install_cache.sh before docker build.")
        zf.write(path, path.name)

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Scripts + Sysmon configs
        _add(zf, _SCRIPTS_DIR / "deploy_endpoint.ps1")
        _add(zf, _SCRIPTS_DIR / "agent_command_handler.ps1")
        _add(zf, _SCRIPTS_DIR / "sysmon_config.xml")
        _add(zf, _SCRIPTS_DIR / "sysmon_config_lean.xml")
        # Binaries (the air-gapped piece)
        _add(zf, _CACHE_DIR / WAZUH_MSI_NAME)
        _add(zf, _CACHE_DIR / SYSMON_ZIP_NAME)
        # Generated launcher + README
        zf.writestr("launch.ps1", launcher)
        zf.writestr("README.txt", _BUNDLE_README)

    payload = buf.getvalue()
    suffix = f"-{token_id}" if token_id else ""
    fname = f"apt-thp-bundle{suffix}.zip"
    return Response(
        content=payload,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Content-Length": str(len(payload)),
            "Cache-Control": "no-store",
        },
    )
