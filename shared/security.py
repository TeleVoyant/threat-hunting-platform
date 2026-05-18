# shared/security.py
"""
Platform security utilities: authentication, authorization, input sanitization,
model integrity verification.
"""

import hashlib
import hmac
import secrets
import time
from enum import Enum
from functools import wraps
from typing import Optional

import jwt
from pydantic import BaseModel

# ── RBAC ──────────────────────────────────────────────


class Role(str, Enum):
    VIEWER = "viewer"  # IT admins — view alerts, dashboards
    ANALYST = "analyst"  # SOC analysts — investigate, acknowledge alerts
    OPERATOR = "operator"  # Senior SOC — adjust thresholds, manage configs
    ADMIN = "admin"  # Platform admin — retrain models, manage users


# Permission matrix: what each role can do
PERMISSIONS = {
    Role.VIEWER: {"read_alerts", "read_detections", "view_graphs"},
    Role.ANALYST: {
        "read_alerts",
        "read_detections",
        "view_graphs",
        "acknowledge_alerts",
        "add_notes",
        "export_data",
    },
    Role.OPERATOR: {
        "read_alerts",
        "read_detections",
        "view_graphs",
        "acknowledge_alerts",
        "add_notes",
        "export_data",
        "update_thresholds",
        "manage_detectors",
        "manage_fleet",         # send commands to laptops, switch profiles, toggle telemetry
    },
    Role.ADMIN: {
        "read_alerts",
        "read_detections",
        "view_graphs",
        "acknowledge_alerts",
        "add_notes",
        "export_data",
        "update_thresholds",
        "manage_detectors",
        "manage_fleet",
        "enroll_agents",        # generate per-agent secrets (admin-only)
        "retrain_models",
        "manage_users",
        "view_audit_log",
        # Narrowly scoped: opt THIS organization into the next FL round and
        # view our own contribution history. Does NOT grant access to the FL
        # coordinator itself, other orgs' contributions, or aggregated weights.
        # See federated/fl_security.py for FL coordinator's separate user base.
        "manage_fl_local",
    },
}


class User(BaseModel):
    username: str
    role: Role
    api_key_hash: str


class AuthManager:
    """
    JWT-based authentication with API key fallback.
    Users are stored in config/security.yaml (for FYP scope).
    Production would use LDAP/AD integration.
    """

    def __init__(self, jwt_secret: str, users: list[User]):
        self.jwt_secret = jwt_secret
        self.users = {u.username: u for u in users}

    def authenticate_api_key(self, api_key: str) -> Optional[User]:
        """Validate API key, return user if valid."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        for user in self.users.values():
            if hmac.compare_digest(user.api_key_hash, key_hash):
                return user
        return None

    def create_jwt(self, user: User, expires_hours: int = 8) -> str:
        """Create JWT token for authenticated user."""
        payload = {
            "sub": user.username,
            "role": user.role.value,
            "iat": int(time.time()),
            "exp": int(time.time()) + (expires_hours * 3600),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def verify_jwt(self, token: str) -> Optional[User]:
        """Verify JWT token, return user if valid."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            username = payload["sub"]
            return self.users.get(username)
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def has_permission(self, user: User, permission: str) -> bool:
        """Check if user's role has the required permission."""
        return permission in PERMISSIONS.get(user.role, set())


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key and its hash. Returns (key, hash)."""
    key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash
