# api/command_queue.py
"""
Persistent command queue + agent registry for fleet remote control.

Backed by SQLite for FYP simplicity (single-server, hundreds of agents).
For higher scale, swap to Postgres or Redis Streams without changing the
public interface.

Tables
------
agents          — registered laptops (id, secret, profile, last_seen)
commands        — issued commands (queued / delivered / completed / expired)
command_results — execution results reported by agents

Concurrency: SQLite WAL mode + check_same_thread=False. FastAPI handlers
share the connection. For >1 worker process, use a real DB.
"""

import json
import sqlite3
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Optional

from shared.commands import (
    Command,
    CommandStatus,
    CommandType,
    DEFAULT_COMMAND_TTL,
    decode_secret,
    encode_secret,
    generate_agent_secret,
    utc_iso_from_ts,
)
from shared.logging import get_logger

logger = get_logger("api.command_queue")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id                    TEXT PRIMARY KEY,
    secret_b64                  TEXT NOT NULL,
    profile                     TEXT,
    registered_at               REAL NOT NULL,
    last_seen_at                REAL,
    last_status                 TEXT,
    current_sequence            INTEGER NOT NULL DEFAULT 0,
    handler_version             TEXT,
    -- OTA post-write verification result reported by agent heartbeat.
    -- ok | sha_mismatch | parse_failed | invoke_failed | rolled_back
    handler_update_status       TEXT,
    handler_update_detail       TEXT,
    handler_update_bad_version  TEXT,
    handler_update_at           REAL
);

CREATE TABLE IF NOT EXISTS commands (
    command_id    TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    command_type  TEXT NOT NULL,
    params_json   TEXT NOT NULL,
    issued_by     TEXT NOT NULL,
    issued_at     REAL NOT NULL,
    expires_at    REAL NOT NULL,
    sequence      INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
);
CREATE INDEX IF NOT EXISTS ix_commands_agent_status
    ON commands(agent_id, status);

CREATE TABLE IF NOT EXISTS command_results (
    command_id   TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    output       TEXT,
    executed_at  REAL NOT NULL,
    FOREIGN KEY(command_id) REFERENCES commands(command_id)
);
"""

# Truncate agent-supplied output fields to prevent log/DB inflation
_MAX_OUTPUT_LEN = 8192


class CommandQueue:

    def __init__(
        self,
        db_path: str = "/data/fleet/fleet.db",
        default_command_ttl_sec: int = DEFAULT_COMMAND_TTL,
    ):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(_SCHEMA)
        # Idempotent migration: add handler_version column on pre-existing
        # databases where CREATE TABLE IF NOT EXISTS won't apply the new
        # column. SQLite doesn't have ADD COLUMN IF NOT EXISTS, so we
        # probe PRAGMA table_info first.
        existing_cols = {
            row[1] for row in self.conn.execute(
                "PRAGMA table_info(agents)"
            ).fetchall()
        }
        if "handler_version" not in existing_cols:
            self.conn.execute(
                "ALTER TABLE agents ADD COLUMN handler_version TEXT"
            )
        # 2026-06-02: OTA post-write verification fields. Each is additive
        # and nullable — old agents that don't report them stay NULL, which
        # the dashboard renders as the existing "LATEST/OUT OF DATE" pill
        # (no UPDATE FAILED red overlay). Same idempotent-ALTER pattern as
        # handler_version above.
        for col_name, col_type in (
            ("handler_update_status",      "TEXT"),
            ("handler_update_detail",      "TEXT"),
            ("handler_update_bad_version", "TEXT"),
            ("handler_update_at",          "REAL"),
        ):
            if col_name not in existing_cols:
                self.conn.execute(
                    f"ALTER TABLE agents ADD COLUMN {col_name} {col_type}"
                )
        self.conn.commit()
        self.default_ttl = default_command_ttl_sec
        # Single lock guards multi-statement transactions (sequence allocation).
        self._lock = Lock()

    # ─────────────────────────────────────────────────────────────────────────
    # Agent registry
    # ─────────────────────────────────────────────────────────────────────────

    def enroll_agent(self, agent_id: str, profile: str = "Balanced") -> bytes:
        """
        Register an agent. If it already exists, ROTATE its secret (this
        revokes any prior secret) and reset its sequence counter. The new
        secret is returned ONCE; the server keeps it in the DB for HMAC
        verification and signing.
        """
        secret = generate_agent_secret()
        secret_b64 = encode_secret(secret)
        now = time.time()
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO agents(agent_id, secret_b64, profile, registered_at, current_sequence)
                VALUES (?, ?, ?, ?, 0)
                ON CONFLICT(agent_id) DO UPDATE SET
                    secret_b64       = excluded.secret_b64,
                    profile          = excluded.profile,
                    registered_at    = excluded.registered_at,
                    current_sequence = 0
                """,
                (agent_id, secret_b64, profile, now),
            )
            self.conn.commit()
        logger.info("Agent enrolled", agent_id=agent_id, profile=profile)
        return secret

    def get_agent_secret(self, agent_id: str) -> Optional[bytes]:
        row = self.conn.execute(
            "SELECT secret_b64 FROM agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
        return decode_secret(row["secret_b64"]) if row else None

    def _agent_row_to_dict(self, r) -> dict:
        """Shared row → dict mapping for list_agents + get_agent."""
        return {
            "agent_id":                   r["agent_id"],
            "profile":                    r["profile"],
            "registered_at":              r["registered_at"],
            "last_seen_at":               r["last_seen_at"],
            "last_status":                r["last_status"],
            "current_sequence":           r["current_sequence"],
            "handler_version":            r["handler_version"],
            "handler_update_status":      r["handler_update_status"],
            "handler_update_detail":      r["handler_update_detail"],
            "handler_update_bad_version": r["handler_update_bad_version"],
            "handler_update_at":          r["handler_update_at"],
        }

    def list_agents(self) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT agent_id, profile, registered_at, last_seen_at, last_status,
                   current_sequence, handler_version,
                   handler_update_status, handler_update_detail,
                   handler_update_bad_version, handler_update_at,
                   (SELECT COUNT(*) FROM commands
                    WHERE agent_id = a.agent_id AND status = 'pending'
                          AND expires_at > ?) AS pending_commands
            FROM agents a
            ORDER BY agent_id
            """,
            (time.time(),),
        ).fetchall()
        out = []
        for r in rows:
            d = self._agent_row_to_dict(r)
            d["pending_commands"] = r["pending_commands"]
            out.append(d)
        return out

    def get_agent(self, agent_id: str) -> Optional[dict]:
        """Single-agent fetch with the full set of fields list_agents returns
        (minus pending_commands which would require a join). Used by the
        heartbeat handler to detect handler_update_status transitions for
        audit emission."""
        r = self.conn.execute(
            """
            SELECT agent_id, profile, registered_at, last_seen_at, last_status,
                   current_sequence, handler_version,
                   handler_update_status, handler_update_detail,
                   handler_update_bad_version, handler_update_at
            FROM agents
            WHERE agent_id = ?
            """,
            (agent_id,),
        ).fetchone()
        return self._agent_row_to_dict(r) if r else None

    def update_agent_status(
        self,
        agent_id: str,
        status: Optional[str] = None,
        profile: Optional[str] = None,
        handler_version: Optional[str] = None,
        handler_update_status:      Optional[str] = None,
        handler_update_detail:      Optional[str] = None,
        handler_update_bad_version: Optional[str] = None,
    ) -> None:
        now = time.time()
        sets = ["last_seen_at = ?"]
        params: list = [now]
        if status is not None:
            sets.append("last_status = ?")
            params.append(status)
        if profile is not None:
            sets.append("profile = ?")
            params.append(profile)
        if handler_version is not None:
            sets.append("handler_version = ?")
            params.append(handler_version)
        # Any of the three OTA update fields being explicitly sent updates
        # all four columns together (status + detail + bad_version + at).
        # An agent that *clears* its failure marker sends status="ok" with
        # null detail / bad_version, which correctly NULLs those columns.
        if handler_update_status is not None:
            sets.append("handler_update_status = ?");      params.append(handler_update_status)
            sets.append("handler_update_detail = ?");      params.append(handler_update_detail)
            sets.append("handler_update_bad_version = ?"); params.append(handler_update_bad_version)
            sets.append("handler_update_at = ?");          params.append(now)
        params.append(agent_id)
        self.conn.execute(
            f"UPDATE agents SET {', '.join(sets)} WHERE agent_id = ?",
            tuple(params),
        )
        self.conn.commit()

    # ─────────────────────────────────────────────────────────────────────────
    # Command lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def enqueue_command(
        self,
        agent_id: str,
        command_type: CommandType,
        params: dict,
        issued_by: str,
        ttl_sec: Optional[int] = None,
    ) -> Command:
        """Allocate a sequence number and persist the command."""
        ttl = ttl_sec or self.default_ttl
        now = time.time()
        with self._lock:
            cur = self.conn.execute(
                "UPDATE agents SET current_sequence = current_sequence + 1 WHERE agent_id = ?",
                (agent_id,),
            )
            if cur.rowcount == 0:
                raise ValueError(f"Unknown agent: {agent_id}")
            seq = self.conn.execute(
                "SELECT current_sequence FROM agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()["current_sequence"]

            command_id = str(uuid.uuid4())
            self.conn.execute(
                """
                INSERT INTO commands(command_id, agent_id, command_type, params_json,
                                     issued_by, issued_at, expires_at, sequence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    command_id, agent_id, command_type.value,
                    json.dumps(params, sort_keys=True),
                    issued_by, now, now + ttl, seq,
                ),
            )
            self.conn.commit()

        return Command(
            command_id=command_id,
            agent_id=agent_id,
            command_type=command_type,
            params=params,
            issued_by=issued_by,
            issued_at=utc_iso_from_ts(now),
            expires_at=utc_iso_from_ts(now + ttl),
            sequence=seq,
        )

    def get_pending_commands(self, agent_id: str, max_count: int = 20) -> list[Command]:
        """Return un-delivered, un-expired commands ordered by sequence."""
        now = time.time()
        rows = self.conn.execute(
            """
            SELECT command_id, agent_id, command_type, params_json,
                   issued_by, issued_at, expires_at, sequence
            FROM commands
            WHERE agent_id = ? AND status = 'pending' AND expires_at > ?
            ORDER BY sequence ASC LIMIT ?
            """,
            (agent_id, now, max_count),
        ).fetchall()

        return [
            Command(
                command_id=r["command_id"],
                agent_id=r["agent_id"],
                command_type=CommandType(r["command_type"]),
                params=json.loads(r["params_json"]),
                issued_by=r["issued_by"],
                issued_at=utc_iso_from_ts(r["issued_at"]),
                expires_at=utc_iso_from_ts(r["expires_at"]),
                sequence=r["sequence"],
            )
            for r in rows
        ]

    def mark_delivered(self, command_id: str) -> None:
        self.conn.execute(
            "UPDATE commands SET status = 'delivered' "
            "WHERE command_id = ? AND status = 'pending'",
            (command_id,),
        )
        self.conn.commit()

    def record_result(self, command_id: str, agent_id: str, status: str, output: str) -> None:
        """Persist a command result. Output is truncated to _MAX_OUTPUT_LEN."""
        # Verify the command exists AND is for this agent (caller can call get_command first
        # for early rejection, but enforce here too as defense-in-depth)
        row = self.conn.execute(
            "SELECT agent_id FROM commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Unknown command_id: {command_id}")
        if row["agent_id"] != agent_id:
            raise PermissionError(
                f"Command {command_id} does not belong to agent {agent_id}"
            )

        truncated_output = (output or "")[:_MAX_OUTPUT_LEN]
        now = time.time()
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO command_results(command_id, status, output, executed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(command_id) DO UPDATE SET
                    status      = excluded.status,
                    output      = excluded.output,
                    executed_at = excluded.executed_at
                """,
                (command_id, status, truncated_output, now),
            )
            self.conn.execute(
                "UPDATE commands SET status = 'completed' WHERE command_id = ?",
                (command_id,),
            )
            self.conn.commit()

    def get_command_with_result(self, command_id: str) -> Optional[dict]:
        row = self.conn.execute(
            """
            SELECT c.command_id, c.agent_id, c.command_type, c.params_json, c.issued_by,
                   c.issued_at, c.expires_at, c.sequence, c.status,
                   r.status      AS result_status,
                   r.output      AS result_output,
                   r.executed_at AS result_executed_at
            FROM commands c
            LEFT JOIN command_results r ON c.command_id = r.command_id
            WHERE c.command_id = ?
            """,
            (command_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "command_id":         row["command_id"],
            "agent_id":           row["agent_id"],
            "command_type":       row["command_type"],
            "params":             json.loads(row["params_json"]),
            "issued_by":          row["issued_by"],
            "issued_at":          utc_iso_from_ts(row["issued_at"]),
            "expires_at":         utc_iso_from_ts(row["expires_at"]),
            "sequence":           row["sequence"],
            "status":             row["status"],
            "result_status":      row["result_status"],
            "result_output":      row["result_output"],
            "result_executed_at": utc_iso_from_ts(row["result_executed_at"])
                                  if row["result_executed_at"] else None,
        }

    def expire_old_commands(self) -> int:
        """Mark expired un-delivered commands. Call periodically."""
        now = time.time()
        cur = self.conn.execute(
            "UPDATE commands SET status = 'expired' "
            "WHERE status = 'pending' AND expires_at <= ?",
            (now,),
        )
        self.conn.commit()
        return cur.rowcount
