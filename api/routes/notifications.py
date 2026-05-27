# api/routes/notifications.py
"""
Per-user notification endpoints.

  GET    /notifications                 list (filter by unread)
  GET    /notifications/stream          Server-Sent Events
  GET    /notifications/poll?since=…    fallback for companion app
  POST   /notifications/{id}/read       mark a single notification read
  POST   /notifications/read-all        mark all read
  GET    /notifications/prefs           this user's prefs
  PUT    /notifications/prefs           update prefs

All endpoints require the requester to be a logged-in user. Cookie (dashboard),
JWT bearer (companion app), or API key all work via the shared get_current_user.
"""

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from api.middleware import get_current_user
from shared.security import User

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _store(request: Request):
    return request.app.state.notification_store


def _sse(request: Request):
    return getattr(request.app.state, "sse_backend", None)


# ── List ────────────────────────────────────────────────────────────────────

@router.get("")
async def list_notifications(
    request: Request,
    unread: int = Query(0, ge=0, le=1),
    since: Optional[float] = None,
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(get_current_user),
):
    rows = _store(request).list_for_user(
        user.username, unread_only=bool(unread), since=since, limit=limit,
    )
    return {"notifications": rows, "unread": _store(request).count_unread(user.username)}


# ── Polling fallback ───────────────────────────────────────────────────────

@router.get("/poll")
async def poll(
    request: Request,
    since: float = Query(0.0, ge=0.0),
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(get_current_user),
):
    rows = _store(request).list_for_user(
        user.username, since=since, limit=limit,
    )
    return {
        "server_time": __import__("time").time(),
        "notifications": rows,
    }


# ── Mark read ──────────────────────────────────────────────────────────────

@router.post("/{notif_id}/read")
async def mark_read(notif_id: str, request: Request,
                     user: User = Depends(get_current_user)):
    ok = _store(request).mark_read(notif_id, user.username)
    if not ok:
        raise HTTPException(404, "Notification not found or already read")
    return {"id": notif_id, "read": True}


@router.post("/read-all")
async def mark_all_read(request: Request,
                          user: User = Depends(get_current_user)):
    n = _store(request).mark_all_read(user.username)
    return {"marked": n}


# ── Prefs ──────────────────────────────────────────────────────────────────


class PrefsUpdate(BaseModel):
    min_severity:  Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    channel_sse:   Optional[int] = Field(None, ge=0, le=1)
    channel_email: Optional[int] = Field(None, ge=0, le=1)
    channel_sms:   Optional[int] = Field(None, ge=0, le=1)
    channel_app:   Optional[int] = Field(None, ge=0, le=1)
    quiet_start:   Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")
    quiet_end:     Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")


@router.get("/prefs")
async def get_prefs(request: Request, user: User = Depends(get_current_user)):
    return _store(request).get_prefs(user.username)


@router.put("/prefs")
async def put_prefs(body: PrefsUpdate, request: Request,
                     user: User = Depends(get_current_user)):
    merged = _store(request).put_prefs(user.username, **body.model_dump(exclude_none=True))
    request.app.state.audit_trail.log(
        action="notifications.prefs.update", actor=user.username,
        target=user.username,
        details={k: v for k, v in body.model_dump(exclude_none=True).items()},
    )
    return merged


# ── SSE stream ─────────────────────────────────────────────────────────────


@router.get("/stream")
async def stream(request: Request, user: User = Depends(get_current_user)):
    sse = _sse(request)
    if sse is None:
        raise HTTPException(503, "SSE backend not initialised")

    queue = sse.connect(user.username)

    async def gen():
        try:
            # initial hello so the client knows the stream is open
            yield ": connected\n\n"
            yield f"event: hello\ndata: {json.dumps({'username': user.username})}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=25.0)
                    yield f"event: notification\ndata: {json.dumps(payload)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                if await request.is_disconnected():
                    break
        finally:
            sse.disconnect(user.username, queue)

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
