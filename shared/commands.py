# shared/commands.py
"""
Fleet remote-control: command schemas and crypto primitives.

Wire format
-----------
Both directions use HMAC-SHA256 over a JSON payload. The signed bytes are
transmitted alongside the signature so the verifier never needs to reproduce
canonical serialization (which is fragile across language stacks).

  Server -> Agent (poll response):
    { "commands": [ { "signed_payload": "<json>", "signature": "<hex>" }, ... ] }

  Agent -> Server (result post):
    { "signed_payload": "<json>", "signature": "<hex>" }

Auth header
-----------
Agent -> API requests carry:
    Authorization: APT-HMAC agent_id=<id>,ts=<unix>,sig=<hex>
where sig = HMAC_SHA256(agent_secret, "<id>:<ts>") and ts must be within
+/-MAX_AUTH_AGE_SEC of the server's clock.
"""

import base64
import hmac
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from pydantic import BaseModel, Field


# -- Constants ---------------------------------------------------------------

# +-------------------------------------------------------------------------+
# | CLOCK-SKEW NOTE -- do not widen MAX_AUTH_AGE_SEC as a fix for 401s.     |
# |                                                                         |
# | This window is the platform's primary replay-protection on the agent    |
# | command channel; widening it weakens that guarantee. If an endpoint is  |
# | consistently 401ing on /agents/{id}/poll with reason "Timestamp out of |
# | range", the FIX is to sync the endpoint's clock, not enlarge this      |
# | tolerance.                                                              |
# |                                                                         |
# | The clock-sync fix is implemented in three coordinated places:          |
# |   1. scripts/deploy_endpoint.ps1 Step 6 -- forces NTP sync at install   |
# |   2. scripts/agent_command_handler.ps1 _TimeSyncForce/_TimeSyncIfStale |
# |      -- periodic resync + reactive resync on 401                        |
# |   3. This comment (the temptation site for "just bump the constant")   |
# |                                                                         |
# | See the full LOUD comment block in deploy_endpoint.ps1 Step 6 for       |
# | history (this has bitten us twice) and rationale.                       |
# +-------------------------------------------------------------------------+
MAX_AUTH_AGE_SEC      = 300   # +/-5 min on auth header timestamps
DEFAULT_COMMAND_TTL   = 600   # commands expire 10 min after issuance
SECRET_BYTE_LENGTH    = 32    # 256-bit HMAC key per agent


# -- Enums -------------------------------------------------------------------

class CommandType(str, Enum):
    """Whitelist of operations the agent will execute. ANY value not here
    is rejected by the agent handler -- no arbitrary command execution."""
    SET_PROFILE       = "set_profile"        # params: {"profile": "Lean|Balanced|Full"}
    TOGGLE_TELEMETRY  = "toggle_telemetry"   # params: {"source": <TelemetrySource>, "enabled": bool}
    RESTART_SERVICES  = "restart_services"   # params: {"service": "wazuh|sysmon|all"}
    GET_STATUS        = "get_status"         # params: {}
    UPDATE_SYSMON     = "update_sysmon"      # params: {"config_b64": "<base64 sysmon xml>"}
    # Network containment. Reversible at three independent paths (remote
    # UNISOLATE, deadman scheduled task, panic-local script switch). See
    # scripts/agent_command_handler.ps1 :: Invoke-Isolate for the level
    # semantics and lifeline rules.
    ISOLATE           = "isolate"            # params: {"level": "light|standard|full", "ttl_minutes": int, "reason": str?, "toast": bool?}
    UNISOLATE         = "unisolate"          # params: {"reason": str?}
    # OTA update of agent_command_handler.ps1 itself. UPDATE_HANDLER:
    # agent fetches the named version via /agents/{id}/handler/content,
    # SHA-256 verifies, atomic .new -> live + .bak swap. ROLLBACK_HANDLER:
    # swaps live <-> .bak. See scripts/agent_command_handler.ps1 ::
    # Invoke-UpdateHandler / Invoke-RollbackHandler for the apply flow.
    UPDATE_HANDLER    = "update_handler"     # params: {"version": "<label>", "force": bool?}
    ROLLBACK_HANDLER  = "rollback_handler"   # params: {"reason": str?}


class TelemetrySource(str, Enum):
    SYSMON      = "sysmon"
    DNS_CLIENT  = "dns_client"
    FIREWALL    = "firewall"
    WMI         = "wmi"
    DEFENDER    = "defender"
    TASKSCHED   = "tasksched"
    POWERSHELL  = "powershell"
    FIM         = "fim"


class Profile(str, Enum):
    LEAN     = "Lean"
    BALANCED = "Balanced"
    FULL     = "Full"


class CommandStatus(str, Enum):
    PENDING   = "pending"
    DELIVERED = "delivered"
    COMPLETED = "completed"
    EXPIRED   = "expired"


class ResultStatus(str, Enum):
    SUCCESS  = "success"
    FAILURE  = "failure"
    REJECTED = "rejected"


# -- Wire models -------------------------------------------------------------

class Command(BaseModel):
    """One command targeted at one agent."""
    command_id:   str
    agent_id:     str
    command_type: CommandType
    params:       dict
    issued_by:    str            # admin username (audit trail)
    issued_at:    str            # ISO 8601 UTC
    expires_at:   str            # ISO 8601 UTC
    sequence:     int            # per-agent monotonic -- replay protection


class SignedEnvelope(BaseModel):
    """Wraps an arbitrary payload string + its HMAC-SHA256 signature."""
    signed_payload: str          # raw bytes (JSON string) over which HMAC was computed
    signature:      str          # hex HMAC-SHA256


class CommandResult(BaseModel):
    """Reported by the agent after executing a command."""
    command_id:  str
    agent_id:    str
    status:      ResultStatus
    output:      str             # short human-readable; truncated server-side
    executed_at: str             # ISO 8601 UTC


# -- Crypto primitives -------------------------------------------------------

def sign(secret: bytes, payload: str) -> str:
    """HMAC-SHA256 over UTF-8 bytes of payload. Returns lowercase hex."""
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(secret: bytes, payload: str, signature: str) -> bool:
    """Constant-time comparison of HMAC-SHA256."""
    expected = sign(secret, payload)
    return hmac.compare_digest(expected, signature)


def make_signed_command(secret: bytes, cmd: Command) -> SignedEnvelope:
    """Produce a signed envelope for transport to the agent."""
    payload = json.dumps(cmd.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return SignedEnvelope(signed_payload=payload, signature=sign(secret, payload))


def parse_signed_command(secret: bytes, env: SignedEnvelope) -> Command:
    """Verify the envelope and return the inner Command. Raises on tamper."""
    if not verify(secret, env.signed_payload, env.signature):
        raise ValueError("Signature verification failed")
    return Command(**json.loads(env.signed_payload))


# -- Agent secret encoding ---------------------------------------------------

def generate_agent_secret() -> bytes:
    """256-bit cryptographically-secure random key."""
    return secrets.token_bytes(SECRET_BYTE_LENGTH)


def encode_secret(secret: bytes) -> str:
    """Base64url (no padding) encoding for storage / transmission."""
    return base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")


def decode_secret(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


# -- Auth header -------------------------------------------------------------

def make_auth_header(secret: bytes, agent_id: str, ts: Optional[int] = None) -> str:
    """Build an Authorization: APT-HMAC ... value for an agent request."""
    ts = ts or int(time.time())
    sig = sign(secret, f"{agent_id}:{ts}")
    return f"APT-HMAC agent_id={agent_id},ts={ts},sig={sig}"


def parse_and_verify_auth_header(
    header: str,
    secret_lookup: Callable[[str], Optional[bytes]],
    max_age_sec: int = MAX_AUTH_AGE_SEC,
    now_func: Callable[[], int] = lambda: int(time.time()),
) -> str:
    """
    Parse an APT-HMAC Authorization header, verify timestamp + signature,
    return the verified agent_id. Raises ValueError on any failure.

    secret_lookup is called with agent_id and must return the secret bytes
    (or None if the agent is not registered).
    """
    if not header or not header.startswith("APT-HMAC "):
        raise ValueError("Wrong or missing auth scheme")

    raw = header[len("APT-HMAC "):].strip()
    parts: dict[str, str] = {}
    for kv in raw.split(","):
        if "=" not in kv:
            raise ValueError(f"Malformed auth field: {kv!r}")
        k, v = kv.split("=", 1)
        parts[k.strip()] = v.strip()

    agent_id = parts.get("agent_id")
    sig      = parts.get("sig", "")
    try:
        ts = int(parts.get("ts", "0"))
    except ValueError:
        raise ValueError("Non-integer ts")

    if not agent_id:
        raise ValueError("Missing agent_id")

    now = now_func()
    if abs(now - ts) > max_age_sec:
        raise ValueError(f"Timestamp out of range (ts={ts}, now={now}, max_age={max_age_sec})")

    secret = secret_lookup(agent_id)
    if secret is None:
        raise ValueError("Unknown agent")

    if not verify(secret, f"{agent_id}:{ts}", sig):
        raise ValueError("Signature verification failed")

    return agent_id


# -- Convenience: ISO-8601 helpers -------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_iso_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
