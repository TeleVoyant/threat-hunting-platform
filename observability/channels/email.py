# observability/channels/email.py
"""
SMTP email backend.

Designed for an **in-country relay** (org-controlled or a Tanzanian provider).
The body is redacted — no IOCs, no usernames, no IPs, no MITRE codes — because
even an in-country relay typically lacks the same compliance guarantees as the
platform's own database. The email is just a paging signal: it carries a
severity tag, a hostname pseudonym, and a click-through URL.
"""

import os
import time
from email.message import EmailMessage
from typing import Any, Optional

import aiosmtplib

from shared.logging import get_logger

logger = get_logger("observability.channels.email")


_REDACTED_BODY = (
    "APT THP — new {severity} detection on {host}.\n\n"
    "Open the dashboard for full alert details:\n"
    "{url}\n\n"
    "— Sent by the APT Threat Hunting Platform.\n"
    "Reply to this email is not monitored."
)


class EmailBackend:

    def __init__(
        self,
        host: str,
        port: int = 587,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_addr: str = "apt-thp@localhost",
        starttls: bool = True,
        timeout_s: float = 10.0,
    ):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.starttls = starttls
        self.timeout_s = timeout_s
        self._last_send: dict[str, Any] = {}   # surfaced on /diag/notifications

    def configured(self) -> bool:
        return bool(self.host)

    async def send(self, notif: dict, user) -> tuple[bool, str]:
        """notif keys: id, alert_id, severity, title, body, url"""
        if not self.configured():
            return (False, "smtp not configured")
        if not getattr(user, "email", None):
            return (False, "no email on file")

        # ── Build message with the redacted template ──────────────────────
        sev = (notif.get("severity") or "").upper() or "DETECTION"
        host_pseudonym = self._host_from_title(notif.get("title") or "")
        url = notif.get("url") or "the platform dashboard"
        body = _REDACTED_BODY.format(severity=sev, host=host_pseudonym, url=url)

        msg = EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = user.email
        msg["Subject"] = f"[APT THP] {sev} detection on {host_pseudonym}"
        msg.set_content(body)

        try:
            kwargs: dict = {
                "hostname": self.host, "port": self.port,
                "timeout": self.timeout_s,
            }
            if self.starttls:
                kwargs["start_tls"] = True
            if self.username and self.password:
                kwargs["username"] = self.username
                kwargs["password"] = self.password
            await aiosmtplib.send(msg, **kwargs)
            self._last_send = {
                "at": time.time(), "status": "ok",
                "to_domain": (user.email or "").split("@")[-1],
            }
            return (True, "sent")
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            self._last_send = {"at": time.time(), "status": "fail", "error": err}
            logger.warning("SMTP send failed", error=err)
            return (False, err)

    # ── Diagnostics surface ───────────────────────────────────────────────

    async def reachable(self) -> tuple[bool, str]:
        """TCP+EHLO probe. Does NOT send anything."""
        if not self.configured():
            return (False, "not configured")
        try:
            client = aiosmtplib.SMTP(hostname=self.host, port=self.port, timeout=self.timeout_s)
            await client.connect()
            await client.ehlo()
            await client.quit()
            return (True, "reachable")
        except Exception as e:
            return (False, f"{type(e).__name__}: {e}")

    def last_send(self) -> dict | None:
        return self._last_send or None

    @staticmethod
    def _host_from_title(title: str) -> str:
        # Title format: "SEVERITY · <detector> · <HOST-PSEUDO>"
        if "·" in title:
            return title.rsplit("·", 1)[-1].strip()
        return title or "an endpoint"


def make_email_backend_from_env(notif_config: dict | None = None) -> EmailBackend | None:
    """Build an EmailBackend from environment + config/notifications.yml."""
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        return None
    cfg = (notif_config or {}).get("smtp", {}) or {}
    return EmailBackend(
        host=host,
        port=int(os.environ.get("SMTP_PORT", "587")),
        username=os.environ.get("SMTP_USERNAME") or None,
        password=os.environ.get("SMTP_PASSWORD") or None,
        from_addr=os.environ.get("SMTP_FROM") or cfg.get("from_addr", "apt-thp@localhost"),
        starttls=bool(cfg.get("starttls", True)),
    )
