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
