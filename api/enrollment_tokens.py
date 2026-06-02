# api/enrollment_tokens.py
"""
Short-lived enrollment tokens for the URL-served installer.

An admin clicks Generate on /dashboard/enroll → POST /install/tokens creates a
random 32-byte token, stores its SHA-256 hash in SQLite, and returns the
plaintext once. Each token has a `max_uses` cap (default 10, 0 = unlimited) and
a TTL. The endpoint operator distributes the one-liner to N laptop owners; each
laptop's call to POST /fleet/agents/enroll increments use_count atomically.

Dedupe semantics: if the same agent_id calls enroll twice with the same token,
the second call is a no-op for use_count (UNIQUE (token_id, agent_id) in the
uses table). The agent's HMAC secret IS rotated by enroll_agent — expected.

Stored hash, not plaintext: a DB leak doesn't allow replay.
"""

import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

from shared.logging import get_logger

logger = get_logger("api.enrollment_tokens")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class EnrollmentTokenStore:
    """SQLite-backed single-use installer token store."""

    def __init__(self, db_path: str = "data/fleet/enrollment_tokens.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        # WAL + immediate transactions so the atomic mark-used UPDATE is
        # serialisable across concurrent enrollments (deploy_endpoint can
        # race itself if the operator re-runs the one-liner mid-install).
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash    TEXT    NOT NULL UNIQUE,
                profile       TEXT    NOT NULL,
                server_ip     TEXT,
                created_by    TEXT    NOT NULL,
                created_at    REAL    NOT NULL,
                expires_at    REAL    NOT NULL,
                used_at       REAL,
                used_by_agent TEXT,
                revoked_at    REAL,
                revoked_by    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_hash    ON enrollment_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_tokens_expires ON enrollment_tokens(expires_at);

            CREATE TABLE IF NOT EXISTS enrollment_token_uses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id    INTEGER NOT NULL,
                agent_id    TEXT    NOT NULL,
                used_at     REAL    NOT NULL,
                client_ip   TEXT,
                FOREIGN KEY (token_id) REFERENCES enrollment_tokens(id),
                UNIQUE (token_id, agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_uses_token ON enrollment_token_uses(token_id);
        """)
        self._migrate()

    def _migrate(self) -> None:
        """Additive migration for multi-use columns. Idempotent."""
        cols = {r["name"] for r in
                self.conn.execute("PRAGMA table_info(enrollment_tokens)")}
        if "max_uses" not in cols:
            # Default 1 preserves the original single-use semantics for any
            # legacy rows still on disk.
            self.conn.execute(
                "ALTER TABLE enrollment_tokens "
                "ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1")
        if "use_count" not in cols:
            self.conn.execute(
                "ALTER TABLE enrollment_tokens "
                "ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0")
            # One-shot backfill so old "used" rows display 1/1 in the dashboard
            # and don't show up as still-active.
            self.conn.execute(
                "UPDATE enrollment_tokens SET use_count = 1 "
                "WHERE used_at IS NOT NULL")
            # Mirror the legacy first-use into the uses table so the dashboard
            # row-expansion is coherent across the upgrade.
            self.conn.execute(
                """INSERT OR IGNORE INTO enrollment_token_uses
                      (token_id, agent_id, used_at)
                   SELECT id, used_by_agent, used_at
                     FROM enrollment_tokens
                    WHERE used_at IS NOT NULL AND used_by_agent IS NOT NULL""")

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def create(
        self,
        *,
        profile: str,
        server_ip: Optional[str],
        created_by: str,
        ttl_seconds: int,
        max_uses: int = 1,
    ) -> tuple[int, str, float]:
        """Mint a fresh token. Returns (id, plaintext_token, expires_at).

        max_uses = 0 means unlimited (only TTL + revoke can stop it)."""
        if max_uses < 0:
            raise ValueError("max_uses must be >= 0 (0 means unlimited)")
        token = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + ttl_seconds
        cur = self.conn.execute(
            """INSERT INTO enrollment_tokens
               (token_hash, profile, server_ip, created_by,
                created_at, expires_at, max_uses, use_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
            (_hash(token), profile, server_ip, created_by, now, expires_at, max_uses),
        )
        logger.info("Enrollment token issued",
                    id=cur.lastrowid, profile=profile, ttl=ttl_seconds,
                    max_uses=max_uses, by=created_by)
        return cur.lastrowid, token, expires_at

    def lookup(self, token: str) -> Optional[dict]:
        """Return the row for a plaintext token, or None if not found."""
        row = self.conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
            (_hash(token),),
        ).fetchone()
        return dict(row) if row else None

    def validate(self, token: str) -> tuple[bool, str, Optional[dict]]:
        """Check a token without consuming it. Returns (ok, reason, row).

        reason is "" on success, otherwise: 'not_found', 'expired', 'revoked',
        'exhausted'. ('used' is retained only for legacy single-use rows in
        very-old databases where the migration hasn't run yet.) Callers map
        these to HTTP statuses (403/410/409)."""
        row = self.lookup(token)
        if row is None:
            return (False, "not_found", None)
        if row["revoked_at"] is not None:
            return (False, "revoked", row)
        if row["expires_at"] <= time.time():
            return (False, "expired", row)
        # max_uses = 0 ⇒ unlimited (until expiry/revoke)
        if row["max_uses"] > 0 and row["use_count"] >= row["max_uses"]:
            return (False, "exhausted", row)
        return (True, "", row)

    def consume(self, token: str, agent_id: str,
                client_ip: Optional[str] = None) -> tuple[bool, str]:
        """Record an enrollment against this token. Returns (ok, reason).

        Dedupe: the same agent_id re-enrolling with the same token is a no-op
        for use_count (enforced by UNIQUE(token_id, agent_id) on the uses
        table) — operator confusion / reinstall doesn't burn capacity.

        Atomicity: two distinct agent_ids racing the cap go through one
        BEGIN IMMEDIATE; exactly one wins the UPDATE re-check, the loser sees
        rowcount=0 and is rolled back via DELETE on its uses-row insert."""
        ok, reason, row = self.validate(token)
        if not ok:
            return (False, reason)
        now = time.time()

        # `with self.conn:` opens a transaction in autocommit mode (our
        # isolation_level=None setting) and commits/rolls back on exit.
        with self.conn:
            cur = self.conn.execute(
                """INSERT OR IGNORE INTO enrollment_token_uses
                      (token_id, agent_id, used_at, client_ip)
                   VALUES (?, ?, ?, ?)""",
                (row["id"], agent_id, now, client_ip),
            )
            if cur.rowcount == 0:
                # Same endpoint re-enrolling — clean success, no slot consumed.
                logger.info("Enrollment token re-used by same agent",
                            id=row["id"], by_agent=agent_id)
                return (True, "")

            # New endpoint: bump the counter atomically with a capacity recheck.
            cur = self.conn.execute(
                """UPDATE enrollment_tokens
                      SET use_count     = use_count + 1,
                          used_at       = COALESCE(used_at, ?),
                          used_by_agent = COALESCE(used_by_agent, ?)
                    WHERE token_hash = ?
                      AND revoked_at IS NULL
                      AND expires_at > ?
                      AND (max_uses = 0 OR use_count < max_uses)""",
                (now, agent_id, _hash(token), now),
            )
            if cur.rowcount != 1:
                # Lost the race at the cap. Roll back our uses-row insert so
                # the next request can claim that endpoint slot if eligible.
                self.conn.execute(
                    "DELETE FROM enrollment_token_uses "
                    "WHERE token_id = ? AND agent_id = ?",
                    (row["id"], agent_id),
                )
                _, reason, _ = self.validate(token)
                return (False, reason or "exhausted")

        logger.info("Enrollment token consumed",
                    id=row["id"], by_agent=agent_id,
                    use_count=row["use_count"] + 1, max_uses=row["max_uses"])
        return (True, "")

    def revoke(self, token_id: int, revoked_by: str) -> bool:
        """Halt further enrollments on a token. Prior successful enrollments
        are NOT undone. Returns True if a row changed."""
        cur = self.conn.execute(
            """UPDATE enrollment_tokens
               SET revoked_at = ?, revoked_by = ?
               WHERE id = ? AND revoked_at IS NULL""",
            (time.time(), revoked_by, token_id),
        )
        if cur.rowcount:
            logger.info("Enrollment token revoked", id=token_id, by=revoked_by)
        return cur.rowcount > 0

    # ── Inspection ─────────────────────────────────────────────────────────

    def list_active(self, limit: int = 50,
                    include_uses: bool = True,
                    uses_per_token: int = 50) -> list[dict]:
        """Tokens with remaining capacity, unexpired, unrevoked. Newest first.

        Each row carries `uses: [{agent_id, used_at, client_ip}]` when
        include_uses is set, capped at uses_per_token (sane upper bound for the
        dashboard render — unlimited tokens can grow unbounded over time)."""
        now = time.time()
        rows = self.conn.execute(
            """SELECT id, profile, server_ip, created_by, created_at,
                      expires_at, max_uses, use_count,
                      used_at, used_by_agent, revoked_at
               FROM enrollment_tokens
               WHERE revoked_at IS NULL
                 AND expires_at > ?
                 AND (max_uses = 0 OR use_count < max_uses)
               ORDER BY created_at DESC LIMIT ?""",
            (now, limit),
        ).fetchall()
        out = [dict(r) for r in rows]
        if include_uses:
            for r in out:
                r["uses"] = self.list_uses(r["id"], limit=uses_per_token)
        return out

    def list_recent(self, limit: int = 50,
                    include_uses: bool = True,
                    uses_per_token: int = 50) -> list[dict]:
        """Full history (exhausted / revoked / expired included), newest first."""
        rows = self.conn.execute(
            """SELECT id, profile, server_ip, created_by, created_at,
                      expires_at, max_uses, use_count,
                      used_at, used_by_agent, revoked_at, revoked_by
               FROM enrollment_tokens
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        out = [dict(r) for r in rows]
        if include_uses:
            for r in out:
                r["uses"] = self.list_uses(r["id"], limit=uses_per_token)
        return out

    def list_uses(self, token_id: int, limit: int = 50) -> list[dict]:
        """Per-endpoint enrollment trail for one token, newest first."""
        rows = self.conn.execute(
            """SELECT agent_id, used_at, client_ip
                 FROM enrollment_token_uses
                WHERE token_id = ?
                ORDER BY used_at DESC LIMIT ?""",
            (token_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def purge_expired(self, older_than_days: int = 30) -> int:
        """Garbage-collect rows that expired or were used/revoked long ago.

        Keep some history for the dashboard, but prevent unbounded growth."""
        cutoff = time.time() - (older_than_days * 86400)
        cur = self.conn.execute(
            """DELETE FROM enrollment_tokens
               WHERE (used_at IS NOT NULL AND used_at < ?)
                  OR (revoked_at IS NOT NULL AND revoked_at < ?)
                  OR (used_at IS NULL AND revoked_at IS NULL AND expires_at < ?)""",
            (cutoff, cutoff, cutoff),
        )
        return cur.rowcount
