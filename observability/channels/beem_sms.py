# observability/channels/beem_sms.py
"""
Beem Africa SMS backend.

  Send:    POST https://apisms.beem.africa/v1/send
  Balance: GET  https://apisms.beem.africa/public/v1/vendors/balance

HTTP Basic auth with API_KEY:SECRET_KEY (both issued by the Beem dashboard).
Phone numbers are E.164 without the leading "+" (e.g., 255712345678).

Beem returns submission codes inside the JSON body, not as HTTP statuses:
  100 — message submitted successfully (≠ delivered; delivery report is
        a separate webhook, out of scope for the FYP).
  120 — insufficient balance
  121 — invalid recipient
  122 — invalid sender id
  …
We surface whatever Beem reports through `last_error()` for the diagnostics
panel and prefix the channel-status with `failed:<code>` for the audit row.

Redaction rule for SMS — never put IOCs / usernames / IPs / MITRE codes in
the body. The text is a paging signal; analyst clicks the dashboard URL.
"""

import os
import time
from typing import Any, Optional

import httpx

from shared.logging import get_logger

logger = get_logger("observability.channels.beem_sms")


SEND_PATH    = "/v1/send"
BALANCE_PATH = "/public/v1/vendors/balance"


def _build_body(notif: dict, sender_id: str, user) -> dict:
    """Construct the JSON body for /v1/send.
    The message text is the redacted paging template (≤160 chars enforced)."""
    sev = (notif.get("severity") or "").upper() or "DETECTION"
    host = _host_from_title(notif.get("title") or "endpoint")
    url = notif.get("url") or ""
    msg = f"APT THP: {sev} detection on {host}. Open: {url}"
    if len(msg) > 160:
        # Trim the URL last; keep the severity + host intact.
        head = f"APT THP: {sev} detection on {host}. Open dashboard."
        msg = head[:160]
    return {
        "source_addr":   sender_id,
        "schedule_time": "",
        "encoding":      "0",
        "message":       msg,
        "recipients":    [{"recipient_id": 1, "dest_addr": user.phone}],
    }


def _host_from_title(title: str) -> str:
    if "·" in title:
        return title.rsplit("·", 1)[-1].strip()
    return title or "an endpoint"


class BeemSmsBackend:

    def __init__(
        self,
        api_key: str,
        secret: str,
        sender_id: str,
        *,
        base_url: str = "https://apisms.beem.africa",
        timeout_s: float = 8.0,
    ):
        self.api_key = api_key
        self.secret = secret
        self.sender_id = sender_id
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._auth = httpx.BasicAuth(api_key, secret)
        self._last_error: Optional[dict[str, Any]] = None
        self._last_send: Optional[dict[str, Any]] = None

    def configured(self) -> bool:
        return bool(self.api_key and self.secret and self.sender_id)

    async def send(self, notif: dict, user) -> tuple[bool, str]:
        if not self.configured():
            return (False, "beem not configured")
        if not getattr(user, "phone", None):
            return (False, "no phone on file")

        body = _build_body(notif, self.sender_id, user)
        url = self.base_url + SEND_PATH
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as cli:
                r = await cli.post(url, auth=self._auth, json=body)
            try:
                data = r.json()
            except Exception:
                data = {"raw": r.text[:300]}
            # Beem returns a flat `code/message` on success but a nested
            # `data.error_code/data.message` on failure (e.g. invalid sender
            # ID). Normalise both shapes so diagnostics shows the real
            # reason rather than "code None: None".
            nested = data.get("data") if isinstance(data, dict) else None
            if isinstance(nested, dict) and ("error_code" in nested or "message" in nested):
                code = nested.get("error_code") or nested.get("status_code")
                msg  = nested.get("message")
            else:
                code = data.get("code")
                msg  = data.get("message")
            if r.status_code == 200 and code == 100:
                req_id = data.get("request_id")
                self._last_send = {
                    "at": time.time(), "status": "ok",
                    "request_id": req_id, "code": code,
                    "message": msg,
                    "phone_suffix": (user.phone or "")[-4:],
                }
                self._last_error = None
                return (True, f"sent (req {req_id})")
            self._last_error = {
                "at": time.time(), "http": r.status_code,
                "code": code, "message": msg,
                "phone_suffix": (user.phone or "")[-4:],
            }
            self._last_send = {
                "at": time.time(), "status": "fail",
                "http": r.status_code, "code": code,
                "message": msg,
            }
            return (False, f"beem code {code}: {msg}")
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            self._last_error = {"at": time.time(), "exception": err}
            self._last_send  = {"at": time.time(), "status": "fail", "error": err}
            logger.warning("Beem send raised", error=err)
            return (False, f"exception: {e}")

    async def balance(self) -> dict[str, Any]:
        """Returns the parsed JSON body. Caller surfaces it on /diag."""
        if not self.configured():
            return {"error": "not configured"}
        url = self.base_url + BALANCE_PATH
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as cli:
                r = await cli.get(url, auth=self._auth)
            try:
                return {"http": r.status_code, **r.json()}
            except Exception:
                return {"http": r.status_code, "raw": r.text[:300]}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    def last_send(self) -> dict | None:
        return self._last_send or None

    def last_error(self) -> dict | None:
        return self._last_error or None


def make_beem_backend_from_env(notif_config: dict | None = None) -> BeemSmsBackend | None:
    """Build a BeemSmsBackend from environment + config/notifications.yml."""
    api_key = os.environ.get("BEEM_API_KEY", "").strip()
    secret  = os.environ.get("BEEM_SECRET_KEY", "").strip()
    if not (api_key and secret):
        return None
    cfg = (notif_config or {}).get("beem", {}) or {}
    sender = (os.environ.get("BEEM_SENDER_ID") or cfg.get("sender_id") or "APT-THP").strip()
    base = (os.environ.get("BEEM_BASE_URL") or cfg.get("base_url") or "https://apisms.beem.africa").strip()
    return BeemSmsBackend(api_key=api_key, secret=secret, sender_id=sender, base_url=base)
