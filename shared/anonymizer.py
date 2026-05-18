# shared/anonymizer.py
r"""
Endpoint-side PII pseudonymization (FR-01).

Strategy: deterministic HMAC-SHA256 with a per-deployment salt.

  - DETERMINISTIC: same input + same salt → same output. So an analyst
    can correlate "user u_a3f9b1c2 logged in 5 times" without ever seeing
    the real username.
  - IRREVERSIBLE without salt: anyone with the alert data alone cannot
    recover usernames. Only those holding the salt (the org's privileged
    incident-response team) can re-derive the mapping for forensics.
  - PERSISTENT salt: rotated only when the org wants to break correlation
    (e.g., yearly). Stored per-deployment in `data/anonymizer/salt.bin`.

Anonymized fields:
  - `user`          → "u_<8-hex-chars>"
  - `process_name`  → image path with C:\Users\<name>\ → C:\Users\u_<hash>\
  - `parent_process` → same
  - `command_line`  → same Users\<name>\ regex replaced
  - `dns_query`     → unchanged (queried domains aren't PII)
  - `source_ip`/`dest_ip` → unchanged (private IPs aren't PII; public IPs
                              are needed for threat-intel correlation)

Toggle: set env var APT_ANONYMIZE=0 to disable (useful in dev). Default: on.
"""

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path
from typing import Optional


# Cache the salt bytes so we hash once at import then never touch disk
_SALT_CACHE: Optional[bytes] = None
_DEFAULT_SALT_PATH = "data/anonymizer/salt.bin"


def _load_salt() -> bytes:
    """Load (or generate) the per-deployment salt."""
    global _SALT_CACHE
    if _SALT_CACHE is not None:
        return _SALT_CACHE

    path = Path(os.environ.get("APT_ANONYMIZER_SALT_FILE", _DEFAULT_SALT_PATH))
    if path.exists():
        _SALT_CACHE = path.read_bytes()
        return _SALT_CACHE

    # First-run: generate + persist
    path.parent.mkdir(parents=True, exist_ok=True)
    _SALT_CACHE = secrets.token_bytes(32)
    path.write_bytes(_SALT_CACHE)
    try:
        path.chmod(0o600)
    except OSError:
        pass    # Windows hosts may reject chmod; not fatal
    return _SALT_CACHE


def is_enabled() -> bool:
    """Anonymization on by default; opt out for dev only."""
    return os.environ.get("APT_ANONYMIZE", "1") not in ("0", "false", "False")


def pseudonymize_user(username: Optional[str]) -> Optional[str]:
    """
    Map a username to a stable opaque token.
    DOMAIN-prefixed names are normalised so DOMAIN\\Alice and ALICE@DOMAIN
    yield the same token.
    """
    if not username:
        return username
    if not is_enabled():
        return username
    # Normalise: lowercase, strip domain prefix/suffix
    norm = username.lower().strip()
    if "\\" in norm:
        norm = norm.rsplit("\\", 1)[1]
    if "@" in norm:
        norm = norm.split("@", 1)[0]
    return "u_" + _hmac_hex(norm)[:8]


# Path patterns that embed usernames (Windows convention)
_USER_PATH_RE = re.compile(
    r"(?P<prefix>[a-zA-Z]:\\Users\\)(?P<user>[^\\/]+)(?P<rest>[\\/])",
    re.IGNORECASE,
)


def pseudonymize_path(path: Optional[str]) -> Optional[str]:
    """Replace C:\\Users\\Alice\\ with C:\\Users\\u_<hash>\\ in any path string."""
    if not path or not is_enabled():
        return path

    def _repl(m: re.Match) -> str:
        token = pseudonymize_user(m.group("user"))
        return f"{m.group('prefix')}{token}{m.group('rest')}"

    return _USER_PATH_RE.sub(_repl, path)


def pseudonymize_command_line(cmd: Optional[str]) -> Optional[str]:
    """
    Same path-based replacement on command-line strings. Doesn't try to
    parse arguments — would need a real shell tokeniser. Path embeddings
    are by far the most common PII leak in command lines.
    """
    return pseudonymize_path(cmd)


# ── Helpers ────────────────────────────────────────────────────────────────

def _hmac_hex(message: str) -> str:
    return hmac.new(_load_salt(), message.encode("utf-8"), hashlib.sha256).hexdigest()


# ── Convenience: anonymize a NormalizedEvent in place ──────────────────────

def anonymize_event(event_dict: dict) -> dict:
    """
    Walk a flat dict (output of preprocessor._extract_wazuh_event) and
    pseudonymize known PII fields. Mutates + returns the dict.
    """
    if not is_enabled():
        return event_dict
    if event_dict.get("user"):
        event_dict["user"] = pseudonymize_user(event_dict["user"])
    if event_dict.get("process_name"):
        event_dict["process_name"] = pseudonymize_path(event_dict["process_name"])
    if event_dict.get("parent_process"):
        event_dict["parent_process"] = pseudonymize_path(event_dict["parent_process"])
    if event_dict.get("command_line"):
        event_dict["command_line"] = pseudonymize_command_line(event_dict["command_line"])
    return event_dict
