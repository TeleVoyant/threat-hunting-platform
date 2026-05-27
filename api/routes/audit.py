# api/routes/audit.py
"""
Audit-log REST surface.

  GET  /audit                 — query the hash-chained audit DB
  GET  /audit/verify          — integrity check
  GET  /audit/export.csv      — full export, filterable, streamed CSV

All endpoints require `view_audit_log` (admin only by default).
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from api.middleware import require_permission
from shared.security import User

router = APIRouter(prefix="/audit", tags=["audit"])


def _audit(request: Request):
    return request.app.state.audit_trail


@router.get("")
async def query_audit(
    request: Request,
    action: Optional[str] = None,
    actor:  Optional[str] = None,
    target: Optional[str] = None,
    limit:  int = Query(200, ge=1, le=5000),
    user: User = Depends(require_permission("view_audit_log")),
):
    """Filter the audit log. Newest first. `target` filter is post-query."""
    rows = _audit(request).query(action=action, actor=actor, limit=limit)
    if target:
        t = target.lower()
        rows = [r for r in rows if t in (r.get("target") or "").lower()]
    return {"entries": rows, "count": len(rows)}


@router.get("/verify")
async def verify_audit(
    request: Request,
    user: User = Depends(require_permission("view_audit_log")),
):
    ok, n = _audit(request).verify_integrity()
    return {"integrity_ok": bool(ok), "entries": n}


@router.get("/export.csv")
async def export_audit_csv(
    request: Request,
    action: Optional[str] = None,
    actor:  Optional[str] = None,
    target: Optional[str] = None,
    user: User = Depends(require_permission("view_audit_log")),
):
    rows = _audit(request).query(action=action, actor=actor, limit=100000)
    if target:
        t = target.lower()
        rows = [r for r in rows if t in (r.get("target") or "").lower()]

    def gen():
        import io, csv, json as _json
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "timestamp_utc", "action", "actor", "target", "details", "chain_hash"])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for r in rows:
            w.writerow([
                r.get("id"), r.get("timestamp"),
                r.get("action"), r.get("actor"), r.get("target"),
                _json.dumps(r.get("details") or {}, separators=(",", ":")),
                r.get("chain_hash"),
            ])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    return StreamingResponse(
        gen(), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit_log.csv"'},
    )
