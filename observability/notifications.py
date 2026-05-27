# observability/notifications.py
"""
Notification store + per-user preferences for the paging system.

  - notifications:     one row per dispatched notification, with per-channel status
  - notification_prefs: per-user severity threshold + channel toggles

The dispatch service (NotificationService) lives here too — it sits above the
store and the channel backends so the alert_manager subscriber has a single
entry point.
"""

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Iterable, Optional

from shared.logging import get_logger

logger = get_logger("observability.notifications")


# Severity ordering — higher index = more severe.
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_at_least(sev: str, threshold: str) -> bool:
    return _SEV_RANK.get(sev, -1) >= _SEV_RANK.get(threshold, 0)


# ── Per-user preferences ───────────────────────────────────────────────────


_DEFAULT_PREFS = {
    "min_severity":  "high",
    "channel_sse":   1,
    "channel_email": 0,
    "channel_sms":   0,
    "channel_app":   1,
    "quiet_start":   None,
    "quiet_end":     None,
}


class NotificationStore:

    def __init__(self, db_path: str = "data/notifications/notifications.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS notification_prefs (
                username      TEXT PRIMARY KEY,
                min_severity  TEXT    NOT NULL DEFAULT 'high',
                channel_sse   INTEGER NOT NULL DEFAULT 1,
                channel_email INTEGER NOT NULL DEFAULT 0,
                channel_sms   INTEGER NOT NULL DEFAULT 0,
                channel_app   INTEGER NOT NULL DEFAULT 1,
                quiet_start   TEXT,
                quiet_end     TEXT,
                updated_at    REAL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id              TEXT PRIMARY KEY,
                alert_id        TEXT NOT NULL,
                username        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                title           TEXT,
                body            TEXT,
                created_at      REAL NOT NULL,
                read_at         REAL,
                sse_status      TEXT,
                email_status    TEXT,
                sms_status      TEXT,
                sms_request_id  INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_notif_user_unread
                ON notifications(username, read_at);
            CREATE INDEX IF NOT EXISTS idx_notif_created
                ON notifications(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_notif_alert
                ON notifications(alert_id);
        """)
        self.conn.commit()

    # ── Prefs ──────────────────────────────────────────────────────────────

    def get_prefs(self, username: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM notification_prefs WHERE username=?", (username,),
        ).fetchone()
        if not row:
            return {"username": username, **_DEFAULT_PREFS}
        return dict(row)

    def put_prefs(self, username: str, **fields) -> dict:
        existing = self.get_prefs(username)
        merged = {**existing, **{k: v for k, v in fields.items() if v is not None}}
        merged["updated_at"] = time.time()
        self.conn.execute(
            """
            INSERT INTO notification_prefs
                (username, min_severity, channel_sse, channel_email,
                 channel_sms, channel_app, quiet_start, quiet_end, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                min_severity  = excluded.min_severity,
                channel_sse   = excluded.channel_sse,
                channel_email = excluded.channel_email,
                channel_sms   = excluded.channel_sms,
                channel_app   = excluded.channel_app,
                quiet_start   = excluded.quiet_start,
                quiet_end     = excluded.quiet_end,
                updated_at    = excluded.updated_at
            """,
            (
                username, merged["min_severity"],
                int(merged["channel_sse"]), int(merged["channel_email"]),
                int(merged["channel_sms"]), int(merged["channel_app"]),
                merged["quiet_start"], merged["quiet_end"], merged["updated_at"],
            ),
        )
        self.conn.commit()
        return merged

    # ── Notification rows ──────────────────────────────────────────────────

    def insert(self, *, alert_id: str, username: str, severity: str,
                title: str, body: str) -> str:
        nid = uuid.uuid4().hex
        self.conn.execute(
            """
            INSERT INTO notifications
                (id, alert_id, username, severity, title, body, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (nid, alert_id, username, severity, title, body, time.time()),
        )
        self.conn.commit()
        return nid

    def set_channel_status(self, notif_id: str, channel: str, status: str,
                            *, request_id: Optional[int] = None) -> None:
        if channel not in {"sse", "email", "sms"}:
            raise ValueError(f"Unknown channel: {channel}")
        col = f"{channel}_status"
        params: list = [status]
        sql = f"UPDATE notifications SET {col}=?"
        if channel == "sms" and request_id is not None:
            sql += ", sms_request_id=?"
            params.append(request_id)
        sql += " WHERE id=?"
        params.append(notif_id)
        self.conn.execute(sql, params)
        self.conn.commit()

    def mark_read(self, notif_id: str, username: str) -> bool:
        cur = self.conn.execute(
            "UPDATE notifications SET read_at=? WHERE id=? AND username=? AND read_at IS NULL",
            (time.time(), notif_id, username),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def mark_all_read(self, username: str) -> int:
        cur = self.conn.execute(
            "UPDATE notifications SET read_at=? WHERE username=? AND read_at IS NULL",
            (time.time(), username),
        )
        self.conn.commit()
        return cur.rowcount

    def list_for_user(self, username: str, *, unread_only: bool = False,
                       since: Optional[float] = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM notifications WHERE username=?"
        params: list = [username]
        if unread_only:
            sql += " AND read_at IS NULL"
        if since is not None:
            sql += " AND created_at > ?"
            params.append(since)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def count_unread(self, username: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE username=? AND read_at IS NULL",
            (username,),
        ).fetchone()
        return int(row[0]) if row else 0

    def daily_sms_count(self, since: float) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE created_at >= ? AND sms_status LIKE 'sent%'",
            (since,),
        ).fetchone()
        return int(row[0]) if row else 0

    def find_recent_dup(self, *, username: str, source_entity: str,
                         detector_key: str, window_seconds: int) -> Optional[dict]:
        """Look for an equivalent notification within the dedup window.
        Dedup key is encoded in the body for FYP simplicity."""
        cutoff = time.time() - window_seconds
        marker = _dedup_marker(source_entity, detector_key)
        row = self.conn.execute(
            "SELECT * FROM notifications "
            "WHERE username=? AND created_at >= ? AND body LIKE ? "
            "ORDER BY created_at DESC LIMIT 1",
            (username, cutoff, f"%{marker}%"),
        ).fetchone()
        return dict(row) if row else None


def _dedup_marker(source_entity: str, detector_key: str) -> str:
    """Hidden marker we embed once in body text for cheap dedup matching."""
    import hashlib
    h = hashlib.sha1(f"{source_entity}|{detector_key}".encode()).hexdigest()[:10]
    return f"[k:{h}]"


# ── Dispatcher ─────────────────────────────────────────────────────────────


# Roles eligible for paging. Viewers are explicitly excluded — they don't carry
# the on-call burden.
_PAGEABLE_ROLES = {"analyst", "operator", "admin"}


class NotificationService:
    """
    Sits between the alert pipeline and the channel backends. For each
    enriched alert it:
      1. Picks every user with role ≥ analyst whose `min_severity` is met.
      2. Applies a (username, source_entity, detector_key) dedup window.
      3. Inserts a row into `notifications`.
      4. Fans out to enabled channels in parallel; writes per-channel status.

    Channel backends are passed in at construction; missing ones are skipped
    silently so phases can ship channel-by-channel.
    """

    def __init__(
        self,
        store: NotificationStore,
        auth_manager,
        *,
        sse=None, email=None, sms=None,
        default_min_severity: str = "high",
        dedup_window_minutes: int = 5,
        dashboard_url: str = "https://localhost:8000",
        max_sms_per_day: int = 200,
    ):
        self.store = store
        self.auth_manager = auth_manager
        self.sse = sse
        self.email = email
        self.sms = sms
        self.default_min_severity = default_min_severity
        self.dedup_window_seconds = dedup_window_minutes * 60
        self.dashboard_url = dashboard_url.rstrip("/")
        self.max_sms_per_day = max_sms_per_day

    # ── Targeting ──────────────────────────────────────────────────────────

    def _eligible_users(self):
        for u in self.auth_manager.users.values():
            if u.role.value in _PAGEABLE_ROLES:
                yield u

    def _user_prefs(self, username: str) -> dict:
        p = self.store.get_prefs(username)
        # If no row exists, get_prefs returns the in-memory defaults; merge the
        # configured default_min_severity in case it differs from 'high'.
        if "updated_at" not in p or p["updated_at"] is None:
            p["min_severity"] = self.default_min_severity
        return p

    # ── Payload shape ──────────────────────────────────────────────────────

    @staticmethod
    def _pseudonym(source_entity: str) -> str:
        """Best-effort hostname pseudonym for SMS/email bodies. We keep the
        first 8 chars (which include any host prefix the org uses) and
        substitute the rest with a short hash."""
        import hashlib
        if not source_entity:
            return "UNKNOWN"
        prefix = source_entity[:8]
        suf = hashlib.sha1(source_entity.encode()).hexdigest()[:4].upper()
        return f"{prefix}-{suf}" if len(source_entity) > 8 else source_entity

    def _build_title_and_body(self, alert) -> tuple[str, str, str, str]:
        """
        Returns (title, body, detector_key, source_entity).
        `body` carries the embedded dedup marker so the SQL LIKE-lookup works.
        Title/body are intentionally low-PII — the channel-specific renderers
        (email, SMS) further redact when serialising.
        """
        sev = str(alert.overall_severity.value
                  if hasattr(alert.overall_severity, "value")
                  else alert.overall_severity).lower()
        dets = list(getattr(alert, "detections", []) or [])
        det_names = sorted({d.detector_name for d in dets}) or ["unknown"]
        source = (dets[0].source_entity if dets else "unknown")
        det_key = ",".join(det_names)
        marker = _dedup_marker(source, det_key)
        host = self._pseudonym(source)
        title = f"{sev.upper()} · {'+'.join(det_names)} · {host}"
        body = f"New {sev.upper()} detection on {host}. Open dashboard. {marker}"
        return title, body, det_key, source

    # ── Main entry point ───────────────────────────────────────────────────

    async def dispatch(self, alert) -> int:
        import asyncio

        title, body, det_key, source = self._build_title_and_body(alert)
        sev = str(alert.overall_severity.value
                  if hasattr(alert.overall_severity, "value")
                  else alert.overall_severity).lower()
        alert_id = getattr(alert, "alert_id", None) or "unknown"

        delivered = 0
        for u in self._eligible_users():
            prefs = self._user_prefs(u.username)
            if not severity_at_least(sev, prefs["min_severity"]):
                continue

            # Dedup window
            dup = self.store.find_recent_dup(
                username=u.username, source_entity=source,
                detector_key=det_key, window_seconds=self.dedup_window_seconds,
            )
            if dup:
                logger.debug("Dedup hit, skipping",
                             username=u.username, prior=dup["id"])
                continue

            nid = self.store.insert(
                alert_id=alert_id, username=u.username,
                severity=sev, title=title, body=body,
            )

            # Fan-out to enabled channels
            tasks: list = []
            channels: list[tuple[str, object]] = []
            if prefs["channel_sse"] and self.sse:
                channels.append(("sse", self.sse))
            if prefs["channel_email"] and self.email and u.email:
                channels.append(("email", self.email))
            if prefs["channel_sms"] and self.sms and u.phone:
                # Daily-cap guard
                from datetime import datetime, timezone
                start_of_utc_day = int(datetime.now(timezone.utc).replace(
                    hour=0, minute=0, second=0, microsecond=0
                ).timestamp())
                if self.store.daily_sms_count(start_of_utc_day) >= self.max_sms_per_day:
                    self.store.set_channel_status(nid, "sms", "skipped:daily_cap")
                else:
                    channels.append(("sms", self.sms))

            payload = {
                "id": nid, "alert_id": alert_id, "severity": sev,
                "title": title, "body": body,
                "url": f"{self.dashboard_url}/dashboard/alerts/{alert_id}",
            }
            for name, backend in channels:
                tasks.append(self._send_one(nid, name, backend, payload, u))

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            delivered += 1
        return delivered

    async def _send_one(self, nid: str, channel: str, backend, payload: dict, user) -> None:
        try:
            ok, msg = await backend.send(payload, user)
        except Exception as e:
            ok, msg = False, f"exception: {e}"
        status = "sent" if ok else f"failed:{msg}"
        request_id = None
        # The Beem backend appends "sent (req <id>)" to its msg — extract for
        # the dedicated column.
        if channel == "sms" and ok and "req " in msg:
            try:
                request_id = int(msg.split("req")[1].split(")")[0].strip())
            except Exception:
                request_id = None
        try:
            self.store.set_channel_status(nid, channel, status,
                                            request_id=request_id)
        except Exception as e:
            logger.warning("Failed to record channel status",
                            nid=nid, channel=channel, error=str(e))
