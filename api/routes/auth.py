# api/routes/auth.py
"""
Login + logout for the dashboard. JWT in HttpOnly cookie.

Auth model:
  - Login form posts {username, api_key} to /auth/login
  - Server validates via existing AuthManager.authenticate_api_key
  - On success: issues JWT and sets it as HttpOnly + Secure cookie
  - All dashboard pages use the cookie via a `current_user_from_cookie` dep
  - /auth/logout deletes the cookie

Why API key as the "password"?
  - We don't have a separate password table
  - The existing user roster in config/security.yml already has api_key_hash
  - For the FYP, API key = password is acceptable (it's a secret only the user
    has, validated server-side by hash compare). For production, swap in
    bcrypt-hashed passwords with a /auth/change-password flow.
"""

from typing import Optional

from fastapi import APIRouter, Cookie, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from shared.security import User

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_NAME = "apt_session"


def current_user_from_cookie(
    request: Request,
    apt_session: Optional[str] = Cookie(default=None),
) -> Optional[User]:
    """Read JWT from cookie + return User. Returns None if missing/invalid
    (caller decides whether to redirect or 401)."""
    if not apt_session:
        return None
    auth_manager = request.app.state.auth_manager
    return auth_manager.verify_jwt(apt_session)


def require_user_cookie(
    request: Request,
    apt_session: Optional[str] = Cookie(default=None),
) -> User:
    """Dashboard pages: redirect to /auth/login if missing."""
    user = current_user_from_cookie(request, apt_session)
    if not user:
        raise HTTPException(
            status_code=303,
            headers={"Location": "/auth/login"},
            detail="Not authenticated",
        )
    return user


# ── Routes ────────────────────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    error: Optional[str] = None,
    next: Optional[str] = "/dashboard",
):
    """Login form — accepts username + API key. Renders Jinja template."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": error, "next": next or "/dashboard"},
    )


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    api_key:  str = Form(...),
    next:     str = Form("/dashboard"),
):
    """Validate API key + issue JWT cookie. Redirect to `next` on success."""
    auth_manager = request.app.state.auth_manager
    user = auth_manager.authenticate_api_key(api_key)
    if not user or user.username != username:
        # Avoid telling the attacker WHICH part was wrong
        return RedirectResponse(
            url=f"/auth/login?error=Invalid+credentials&next={next}",
            status_code=303,
        )

    # Issue JWT
    token = auth_manager.create_jwt(user, expires_hours=8)

    audit = request.app.state.audit_trail
    audit.log(
        action="auth.login",
        actor=user.username,
        target=user.role.value,
        details={},
    )

    # Sanitise next-url to prevent open-redirect
    if not next.startswith("/"):
        next = "/dashboard"

    resp = RedirectResponse(url=next, status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,        # set True behind HTTPS in production
        samesite="lax",
        max_age=8 * 3600,
        path="/",
    )
    return resp


# ── Companion-app enrolment ────────────────────────────────────────────────
#
# Flow:
#   1. Dashboard hits GET /auth/enroll-token while logged in → server mints a
#      short-lived JWT bound to the user, returns the token string.
#   2. Dashboard renders /downloads/companion/enroll-qr.png embedding the
#      token + server URL.
#   3. Mobile app scans QR → POSTs the token to /auth/exchange-enroll.
#   4. Server verifies the JWT, marks its JTI consumed (single-use), rotates
#      the user's api_key, and returns the fresh plaintext key to the app.
#
# Why rotate the api_key? The platform never stores the plaintext, so we can't
# return the existing one. Rotation is intentional: it ensures the QR — which
# could be photographed — is only useful to the first person who scans it, and
# only for the brief window before the user opens the app.

_CONSUMED_ENROLL_JTIS: set[str] = set()


@router.get("/enroll-token")
async def mint_enroll_token(request: Request):
    """Mint a one-shot enrol JWT for the calling user (cookie auth)."""
    user = current_user_from_cookie(request, request.cookies.get(COOKIE_NAME))
    if not user:
        raise HTTPException(401, "Not authenticated")
    auth_manager = request.app.state.auth_manager
    if not auth_manager.has_permission(user, "read_alerts"):
        raise HTTPException(403, "Permission 'read_alerts' required")
    import jwt as _jwt, secrets as _secrets, time as _time
    cfg = (getattr(request.app.state, "notifications_config", {}) or {}).get("enroll", {}) or {}
    ttl = int(cfg.get("jwt_ttl_seconds", 600))
    jti = _secrets.token_urlsafe(12)
    payload = {
        "sub": user.username, "purpose": "companion_enroll",
        "jti": jti,
        "iat": int(_time.time()),
        "exp": int(_time.time()) + ttl,
    }
    token = _jwt.encode(payload, auth_manager.jwt_secret, algorithm="HS256")
    server_url = (getattr(request.app.state, "notifications_config", {}) or {}) \
                    .get("dashboard_url", "https://localhost:8000")
    return {"token": token, "server_url": server_url, "ttl_seconds": ttl}


from pydantic import BaseModel as _BM


def _mask_last_octet(ip: Optional[str]) -> Optional[str]:
    """Masks the last IPv4 octet so the audit log doesn't carry full phone IPs."""
    if not ip:
        return ip
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    return ip


class _EnrollExchange(_BM):
    token: str
    # Optional device info — sent by the companion app so the dashboard's
    # "Paired phones" page can show which device pairs to which analyst.
    device_brand: Optional[str] = None
    device_model: Optional[str] = None
    device_name:  Optional[str] = None   # user-set "About phone → Device name"
    device_id:    Optional[str] = None
    lat:          Optional[float] = None
    lon:          Optional[float] = None


@router.post("/exchange-enroll")
async def exchange_enroll(body: _EnrollExchange, request: Request):
    """Mobile app trades the enrol JWT for a freshly-rotated api_key."""
    import jwt as _jwt, hashlib as _hash, secrets as _secrets, yaml as _yaml
    auth_manager = request.app.state.auth_manager
    try:
        payload = _jwt.decode(body.token, auth_manager.jwt_secret, algorithms=["HS256"])
    except _jwt.ExpiredSignatureError:
        raise HTTPException(401, "Enrol token expired")
    except _jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid enrol token: {e}")
    if payload.get("purpose") != "companion_enroll":
        raise HTTPException(400, "Token is not an enrol token")
    jti = payload.get("jti")
    if not jti or jti in _CONSUMED_ENROLL_JTIS:
        raise HTTPException(409, "Enrol token already used")
    username = payload.get("sub")
    user = auth_manager.users.get(username)
    if not user:
        raise HTTPException(404, "User not found")

    # Mint a phone-specific key and store it in `mobile_api_key_hash` —
    # NEVER in `api_key_hash`. Rotating the dashboard credential during
    # pairing previously locked the user out of the dashboard after logout
    # (the new plaintext was only known to the phone). Two separate slots
    # means dashboard login keeps working forever; unpair clears the mobile
    # slot only.
    from api.routes.admin import _read_security_yml, _write_security_yml, _reload_auth
    new_key = _secrets.token_urlsafe(32)
    new_hash = _hash.sha256(new_key.encode()).hexdigest()
    data = _read_security_yml()
    target = next((u for u in data.get("users", []) if u["username"] == username), None)
    if not target:
        raise HTTPException(404, "User missing from security.yml")
    target["mobile_api_key_hash"] = new_hash
    _write_security_yml(data)
    _reload_auth(request)
    _CONSUMED_ENROLL_JTIS.add(jti)

    # Record the pairing so admins can see / unpair phones later.
    paired_ip = request.client.host if request.client else None
    devices = getattr(request.app.state, "paired_devices", None)
    if devices is not None:
        try:
            devices.record_pairing(
                username=username,
                brand=body.device_brand,
                model=body.device_model,
                device_name=body.device_name,
                device_id=body.device_id,
                paired_ip=paired_ip,
                jti=jti,
                lat=body.lat, lon=body.lon,
            )
        except Exception:
            # Pairing inventory is informational; don't fail the enrol if it
            # can't be written.
            pass

    has_loc = body.lat is not None and body.lon is not None
    request.app.state.audit_trail.log(
        action="auth.companion_enroll", actor=username, target=username,
        details={
            "jti": jti,
            "device": body.device_name
                        or f"{body.device_brand or '?'} {body.device_model or '?'}",
            "ip_masked": _mask_last_octet(paired_ip),
            "geo_shared": has_loc,
        },
    )

    # Mirror the QR's dynamic-IP resolution so the app stores a server_url
    # the phone can actually reach — never a stale `localhost`.
    from api.routes.downloads import _public_server_url
    cfg = (getattr(request.app.state, "notifications_config", {}) or {})
    server_url = _public_server_url(request, cfg)
    return {
        "username": username, "api_key": new_key,
        "server_url": server_url,
        "role": user.role.value,
        "warning": "Stored once on the device; cannot be retrieved again from the server.",
    }


@router.post("/unpair")
async def unpair(request: Request):
    """Mobile self-unpair. Authenticated by the phone's own X-API-Key —
    looks up the user that key belongs to, clears their `mobile_api_key_hash`
    slot in security.yml, and marks every active `paired_devices` row for
    that user inactive. Symmetric counterpart to the admin-driven
    `DELETE /admin/paired-devices/{id}`, but callable by the phone itself
    so the dashboard's Paired Devices view stays in sync after the phone's
    in-app Unpair flow.

    Refuses dashboard credentials: if the X-API-Key matches the user's
    dashboard `api_key_hash` (rather than the `mobile_api_key_hash`), the
    request is rejected so a dashboard key can never accidentally evict its
    own companion-phone slot.
    """
    import hashlib as _hash
    auth_manager = request.app.state.auth_manager
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(401, "X-API-Key required")
    user = auth_manager.authenticate_api_key(api_key)
    if user is None:
        raise HTTPException(401, "Invalid api_key")

    # Mobile slot match — refuse otherwise.
    key_hash = _hash.sha256(api_key.encode()).hexdigest()
    if (user.mobile_api_key_hash or "") != key_hash:
        raise HTTPException(
            403,
            "Not a mobile api_key; this endpoint is only for the companion app",
        )

    # Clear the phone slot in security.yml. Dashboard credential untouched.
    from api.routes.admin import _read_security_yml, _write_security_yml, _reload_auth
    data = _read_security_yml()
    target = next(
        (u for u in data.get("users", []) if u["username"] == user.username),
        None,
    )
    key_cleared = False
    if target is not None and target.get("mobile_api_key_hash"):
        target.pop("mobile_api_key_hash", None)
        _write_security_yml(data)
        _reload_auth(request)
        key_cleared = True

    # Mark every active paired_devices row for this user inactive. A single
    # user MAY have multiple active rows (if they paired several phones at
    # different times); we mark them all since after this call ALL of them
    # share an invalidated server-side key anyway.
    store = getattr(request.app.state, "paired_devices", None)
    rows_marked = 0
    if store is not None:
        for row in store.list_all(include_inactive=False):
            if row.get("username") == user.username and store.unpair(row["id"]):
                rows_marked += 1

    request.app.state.audit_trail.log(
        action="auth.companion_unpair",
        actor=user.username, target=user.username,
        details={
            "key_cleared": key_cleared,
            "rows_marked": rows_marked,
            "via":         "mobile_self_unpair",
        },
    )
    return {
        "status":      "unpaired",
        "key_cleared": key_cleared,
        "rows_marked": rows_marked,
    }


@router.get("/me")
async def me(request: Request):
    """
    Returns the authenticated user's profile. Mobile uses this on cold-start
    to re-validate that the persisted role still matches the server (e.g.
    after an admin promotes the user via the dashboard). Identical auth
    handling to other API-key-gated routes.
    """
    # X-API-Key header is the supported transport for the mobile app and any
    # external script. The dashboard cookie also resolves to a user via the
    # auth manager's middleware. Both paths land here.
    auth_manager = request.app.state.auth_manager
    api_key = request.headers.get("X-API-Key")
    user = None
    if api_key:
        user = auth_manager.authenticate_api_key(api_key)
    if user is None:
        # Fall back to cookie path so the dashboard can hit /auth/me too.
        user = current_user_from_cookie(request, request.cookies.get(COOKIE_NAME))
    if user is None:
        raise HTTPException(401, "Unauthenticated")
    return {
        "username": user.username,
        "role": user.role.value,
    }


@router.post("/logout")
async def logout(request: Request):
    user = current_user_from_cookie(request, request.cookies.get(COOKIE_NAME))
    if user:
        request.app.state.audit_trail.log(
            action="auth.logout", actor=user.username, target="", details={},
        )
    resp = RedirectResponse(url="/auth/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp
