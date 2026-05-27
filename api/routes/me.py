# api/routes/me.py
"""
Self-service endpoints that operate on the *calling* user only.

  GET /me              who am I (username + role + email + phone, no api key)
  GET /me/contact      same minus role
  PUT /me/contact      update my own email + phone (validated)

Permission rule: an analyst can edit *their own* row via these endpoints; they
cannot impersonate via a username field, because no username is accepted in
the request body. Admins doing bulk edits use /admin/users/{name}/contact.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.middleware import get_current_user
from api.routes.admin import (
    _normalise_phone, _validate_contact, _read_security_yml,
    _write_security_yml, _reload_auth,
)
from shared.security import User

router = APIRouter(prefix="/me", tags=["me"])


@router.get("")
async def whoami(user: User = Depends(get_current_user)):
    return {
        "username": user.username, "role": user.role.value,
        "email": user.email, "phone": user.phone,
    }


@router.get("/contact")
async def get_contact(user: User = Depends(get_current_user)):
    return {"email": user.email, "phone": user.phone}


class MyContactUpdate(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None


@router.put("/contact")
async def put_contact(
    body: MyContactUpdate, request: Request,
    user: User = Depends(get_current_user),
):
    phone = _normalise_phone(body.phone)
    err = _validate_contact(request, body.email or None, phone)
    if err:
        raise HTTPException(400, err)

    data = _read_security_yml()
    target = next((u for u in data.get("users", []) if u["username"] == user.username), None)
    if not target:
        # If user lives only in memory (e.g., temp test user), refuse — the
        # canonical record is security.yml.
        raise HTTPException(404, "Your user row is not in security.yml")
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

    request.app.state.audit_trail.log(
        action="user.contact.update", actor=user.username, target=user.username,
        details={
            "email_changed": body.email is not None,
            "phone_changed": body.phone is not None,
            "phone_suffix": (phone or "")[-4:] or None,
        },
    )
    return {"email": target.get("email"), "phone": target.get("phone")}
