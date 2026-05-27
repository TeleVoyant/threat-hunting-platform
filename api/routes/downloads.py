# api/routes/downloads.py
"""
Companion-app downloads + provisioning QR.

  GET /downloads/companion.apk             signed Android .apk
  GET /downloads/companion/enroll-qr.png   QR that the app scans
  GET /downloads/companion/info            JSON helper (version + build date)

The .apk is built by the mobile CI and copied into data/downloads/. If the
file doesn't exist yet the endpoint returns 404 with a helpful hint instead
of letting the dashboard show a broken link.
"""

import io
import json
import os
import socket
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response

from api.middleware import get_current_user
from shared.security import User

router = APIRouter(prefix="/downloads", tags=["downloads"])


def _apk_path() -> Path:
    data_dir = os.environ.get("DATA_DIR", "data")
    return Path(data_dir) / "downloads" / "companion.apk"


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _lan_ip() -> str:
    """Best-effort LAN IPv4 detection.

    Opens a UDP socket to a public address (no packets actually sent) and
    reads the OS-chosen source IP. Falls back to 127.0.0.1 if no route exists.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _public_server_url(request: Request, cfg: dict) -> str:
    """Resolve the URL the *phone* will use to reach the API.

    Priority:
      1. PUBLIC_HOST_URL env var (production behind a proxy)
      2. dashboard_url in config/notifications.yml — but only if it isn't a
         loopback placeholder.
      3. Host header the operator used to load the dashboard, unless that
         host is loopback (which would be useless to the phone).
      4. LAN IP auto-detected from the operator's default route, on the same
         port the dashboard is currently bound to.
    """
    env = (os.environ.get("PUBLIC_HOST_URL") or "").strip()
    if env:
        return env.rstrip("/")

    cfg_url = (cfg.get("dashboard_url") or "").strip()
    if cfg_url:
        try:
            from urllib.parse import urlparse as _urlparse
            host = (_urlparse(cfg_url).hostname or "").lower()
            if host and host not in _LOOPBACK_HOSTS:
                return cfg_url.rstrip("/")
        except (ValueError, TypeError):
            pass

    host = (request.url.hostname or "").lower()
    port = request.url.port or (443 if request.url.scheme == "https" else 80)
    if host and host not in _LOOPBACK_HOSTS:
        return f"{request.url.scheme}://{host}:{port}".rstrip("/")

    ip = _lan_ip()
    return f"{request.url.scheme}://{ip}:{port}".rstrip("/")


@router.get("/companion.apk")
async def companion_apk(user: User = Depends(get_current_user)):
    p = _apk_path()
    if not p.exists():
        raise HTTPException(
            404,
            "Companion .apk not yet built. Run `./gradlew :app:assembleRelease` "
            "in mobile/android and copy the artifact to "
            f"{p} (CI does this on tag).",
        )
    return FileResponse(
        str(p), media_type="application/vnd.android.package-archive",
        filename="apt-thp-companion.apk",
    )


@router.get("/companion/info")
async def companion_info(request: Request,
                          user: User = Depends(get_current_user)):
    cfg = (getattr(request.app.state, "notifications_config", {}) or {})
    server_url = _public_server_url(request, cfg)
    p = _apk_path()
    base = {
        "server_url": server_url,
        "loopback_browser_host":
            (request.url.hostname or "").lower() in _LOOPBACK_HOSTS,
    }
    if not p.exists():
        return {**base, "available": False, "path_hint": str(p)}
    stat = p.stat()
    return {
        **base,
        "available": True,
        "size_bytes": stat.st_size,
        "built_at": stat.st_mtime,
        "filename": "apt-thp-companion.apk",
    }


@router.get("/companion/enroll-qr.png")
async def enroll_qr(request: Request, user: User = Depends(get_current_user)):
    """Generates a QR PNG embedding {server_url, token} as JSON.

    The token comes from /auth/enroll-token — we mint it inline here so the
    QR is always fresh and bound to the calling user."""
    import jwt as _jwt, secrets as _secrets

    auth_manager = request.app.state.auth_manager
    cfg = (getattr(request.app.state, "notifications_config", {}) or {})
    enroll_cfg = (cfg.get("enroll") or {})
    ttl = int(enroll_cfg.get("jwt_ttl_seconds", 600))
    jti = _secrets.token_urlsafe(12)
    payload = {
        "sub": user.username, "purpose": "companion_enroll",
        "jti": jti,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    token = _jwt.encode(payload, auth_manager.jwt_secret, algorithm="HS256")
    server_url = _public_server_url(request, cfg)
    qr_payload = json.dumps({"server_url": server_url, "token": token,
                              "username": user.username})

    import qrcode
    img = qrcode.make(qr_payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(),
                    media_type="image/png",
                    headers={"Cache-Control": "no-store"})
