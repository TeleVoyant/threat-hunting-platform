# federated/local_state.py
"""
Org-side FL client state — lives on the organization's platform.

Stores:
  - Coordinator endpoint configuration (URL, API key for the org)
  - Local opt-in status for the next round
  - History of THIS org's own contributions (round_id, status, accepted/rejected)

DOES NOT store any other organization's data — the org admin can only
see what this org sent. Aggregated weights and other-org details live on
the FL coordinator and are not visible from here.
"""

import base64
import os
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Optional

from cryptography.fernet import Fernet

from federated.attestation import (
    private_key_from_pem, public_key_from_pem, sign as att_sign, verify as att_verify,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS coordinator_config (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),  -- single-row table
    coordinator_url     TEXT,
    org_id              TEXT,
    -- Bootstrap-only API key (used until mTLS is set up; kept for fallback)
    api_key_enc         TEXT,                            -- base64 of Fernet ciphertext
    -- mTLS material (added Sprint C+):
    client_cert_pem     TEXT,                            -- our cert, CA-signed
    ca_cert_pem         TEXT,                            -- trust anchor for coord's cert
    coordinator_pub_pem TEXT,                            -- verify coord-signed responses
    configured_at       REAL,
    configured_by       TEXT
);

-- Org's own Ed25519 keypair, generated locally. Private key encrypted at
-- rest with FL_LOCAL_FERNET_KEY. NEVER leaves the org's host.
CREATE TABLE IF NOT EXISTS keypair (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    private_key_enc TEXT NOT NULL,                       -- base64 Fernet ciphertext of PEM
    public_key_pem  TEXT NOT NULL,                       -- non-sensitive
    generated_at    REAL NOT NULL,
    generated_by    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS opt_in (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    opted_in    INTEGER NOT NULL DEFAULT 0,
    set_at      REAL,
    set_by      TEXT
);

CREATE TABLE IF NOT EXISTS contributions (
    contribution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    round_id        INTEGER NOT NULL,
    started_at      REAL NOT NULL,
    completed_at    REAL,
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending|accepted|rejected|failed
    num_examples    INTEGER,
    trust_after     REAL,
    reason          TEXT
);
"""


class LocalFLState:

    def __init__(self, db_path: str = "data/fl_local/state.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        self._lock = Lock()

    # ── Org's own keypair ───────────────────────────────────────────────────

    def store_keypair(
        self,
        private_key_enc: str,
        public_key_pem: str,
        generated_by: str,
    ) -> None:
        """Stores a freshly-generated keypair. Refuses if one already exists
        (rotation must explicitly delete first to avoid losing the old key
        while orgs still have certs signed against it)."""
        with self._lock:
            existing = self.conn.execute(
                "SELECT 1 FROM keypair WHERE id = 1"
            ).fetchone()
            if existing:
                raise ValueError(
                    "Keypair already exists — cannot regenerate (would invalidate "
                    "the org's enrollment + cert). Delete keypair first if rotating."
                )
            self.conn.execute(
                "INSERT INTO keypair(id, private_key_enc, public_key_pem, "
                "generated_at, generated_by) VALUES (1, ?, ?, ?, ?)",
                (private_key_enc, public_key_pem, time.time(), generated_by),
            )
            self.conn.commit()

    def get_public_key_pem(self) -> Optional[str]:
        row = self.conn.execute(
            "SELECT public_key_pem FROM keypair WHERE id = 1"
        ).fetchone()
        return row["public_key_pem"] if row else None

    def get_private_key_enc(self) -> Optional[str]:
        """Encrypted form — caller decrypts with FL_LOCAL_FERNET_KEY at sign time."""
        row = self.conn.execute(
            "SELECT private_key_enc FROM keypair WHERE id = 1"
        ).fetchone()
        return row["private_key_enc"] if row else None

    def has_keypair(self) -> bool:
        return self.get_public_key_pem() is not None

    # ── Signing + verification helpers (used by the FL client process) ─────

    def _fernet(self) -> Fernet:
        key = os.environ.get("FL_LOCAL_FERNET_KEY", "")
        if not key:
            raise RuntimeError(
                "FL_LOCAL_FERNET_KEY env var not set — cannot decrypt private key"
            )
        return Fernet(key.encode() if isinstance(key, str) else key)

    def sign_attestation(self, attestation_bytes: bytes) -> bytes:
        """
        Decrypt our Ed25519 private key with FL_LOCAL_FERNET_KEY and sign
        the supplied attestation bytes. Used by the org's FL client to
        produce contribution signatures.
        """
        enc = self.get_private_key_enc()
        if not enc:
            raise RuntimeError("No keypair generated yet — call keypair_init first")
        priv_pem = self._fernet().decrypt(base64.b64decode(enc))
        priv = private_key_from_pem(priv_pem)
        return att_sign(priv, attestation_bytes)

    def verify_coordinator_signature(self, payload_bytes: bytes, signature: bytes) -> bool:
        """
        Verify that a coordinator-side response (e.g., the global model
        attestation, round announcement, trust notification) was actually
        signed by the coordinator we configured against.
        """
        cfg = self.get_full_config()
        if not cfg or not cfg.get("coordinator_pub_pem"):
            raise RuntimeError("Coordinator public key not configured — call /fl/local/configure first")
        pub = public_key_from_pem(cfg["coordinator_pub_pem"].encode())
        return att_verify(pub, payload_bytes, signature)

    # ── Coordinator config ──────────────────────────────────────────────────

    def configure_coordinator(
        self,
        coordinator_url: str,
        org_id: str,
        api_key_enc: str,
        configured_by: str,
        *,
        client_cert_pem: Optional[str] = None,
        ca_cert_pem: Optional[str] = None,
        coordinator_pub_pem: Optional[str] = None,
    ) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO coordinator_config "
                "(id, coordinator_url, org_id, api_key_enc, "
                "client_cert_pem, ca_cert_pem, coordinator_pub_pem, "
                "configured_at, configured_by) "
                "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
                (coordinator_url, org_id, api_key_enc,
                 client_cert_pem, ca_cert_pem, coordinator_pub_pem,
                 time.time(), configured_by),
            )
            self.conn.commit()

    def get_config(self) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT coordinator_url, org_id, configured_at, configured_by, "
            "client_cert_pem IS NOT NULL AS has_client_cert, "
            "ca_cert_pem IS NOT NULL AS has_ca_cert, "
            "coordinator_pub_pem IS NOT NULL AS has_coordinator_pub "
            "FROM coordinator_config WHERE id = 1"
        ).fetchone()
        return dict(row) if row else None

    def get_full_config(self) -> Optional[dict]:
        """Includes the actual cert/pubkey PEMs — for use BY the FL client only."""
        row = self.conn.execute(
            "SELECT coordinator_url, org_id, "
            "client_cert_pem, ca_cert_pem, coordinator_pub_pem, "
            "configured_at, configured_by "
            "FROM coordinator_config WHERE id = 1"
        ).fetchone()
        return dict(row) if row else None

    def get_api_key_enc(self) -> Optional[str]:
        """Returned only to the FL client at round time — never to a REST caller."""
        row = self.conn.execute(
            "SELECT api_key_enc FROM coordinator_config WHERE id = 1"
        ).fetchone()
        return row["api_key_enc"] if row else None

    # ── Opt-in ─────────────────────────────────────────────────────────────

    def set_opt_in(self, opted_in: bool, by_user: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO opt_in (id, opted_in, set_at, set_by) "
                "VALUES (1, ?, ?, ?)",
                (1 if opted_in else 0, time.time(), by_user),
            )
            self.conn.commit()

    def get_opt_in(self) -> dict:
        row = self.conn.execute(
            "SELECT opted_in, set_at, set_by FROM opt_in WHERE id = 1"
        ).fetchone()
        if not row:
            return {"opted_in": False, "set_at": None, "set_by": None}
        d = dict(row)
        d["opted_in"] = bool(d["opted_in"])
        return d

    # ── Contribution history (own org only) ────────────────────────────────

    def record_contribution_start(self, round_id: int, num_examples: int) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO contributions(round_id, started_at, status, "
                "num_examples) VALUES (?, ?, 'pending', ?)",
                (round_id, time.time(), num_examples),
            )
            self.conn.commit()
        return cur.lastrowid

    def record_contribution_result(
        self,
        contribution_id: int,
        status: str,
        trust_after: Optional[float] = None,
        reason: Optional[str] = None,
    ) -> None:
        if status not in {"accepted", "rejected", "failed"}:
            raise ValueError(f"Invalid status: {status}")
        with self._lock:
            self.conn.execute(
                "UPDATE contributions SET completed_at = ?, status = ?, "
                "trust_after = ?, reason = ? WHERE contribution_id = ?",
                (time.time(), status, trust_after, reason, contribution_id),
            )
            self.conn.commit()

    def list_contributions(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM contributions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
