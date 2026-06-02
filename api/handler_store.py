"""
Handler-script version store.

Keeps every version of ``scripts/agent_command_handler.ps1`` the operator has
ever uploaded, with exactly one row in `status='live'` at any time. The agent
self-updates by polling /agents/{id}/handler/manifest, comparing the returned
version label to its own registry-tracked `HandlerVersion`, and fetching
/agents/{id}/handler/content?version=<v> if they differ.

Schema:

  handler_versions(
    id            INTEGER PK
    version_label TEXT UNIQUE         human label, e.g. "v2026.05.30-1428"
    sha256        TEXT                hex sha256 of the script content (bytes)
    size_bytes    INTEGER
    content_b64   TEXT                base64 of the script bytes
    status        TEXT                'staged' | 'live' | 'archived'
    uploaded_by   TEXT
    uploaded_at   REAL
    notes         TEXT                operator's release-note (optional)
    promoted_at   REAL
    promoted_by   TEXT
  )

Indexes on `status` for cheap WHERE status='live' lookups, and on
`version_label` for the per-version fetch path.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional


# ── Validation + normalisation ────────────────────────────────────────────
#
# Every byte stream that enters the version store (via upload OR scan) is
# (a) re-encoded to the canonical PS-on-Windows form so the agent always
# parses it cleanly, and (b) sniff-checked for the structural markers that
# identify it as our handler script (not random PowerShell). This is the
# server-side defence against an operator promoting a syntactically-broken
# or wrong-file upload that would brick every endpoint that auto-pulls it.
#
# Deliberately NOT done here: full PowerShell parse / brace-balance check.
# A regex-based brace counter trips on real-world strings (interpolation,
# backtick escapes, here-strings) and produces false negatives that block
# valid uploads. The agent's own `[scriptblock]::Create()` check during
# _HandlerFetchAndApply IS the authoritative syntax gate — bad bytes that
# slip past these size+marker heuristics get rejected on the endpoint
# before the .bak swap, so a malformed live version cannot brick a host.

_BOM = b"\xef\xbb\xbf"

# Markers we expect to find in any valid handler script. Their absence
# indicates the upload is either an entirely different file or has been
# truncated / mangled. Kept narrow — function names + dispatch entries
# that have been stable across handler versions.
_REQUIRED_MARKERS = (
    "$Handlers = @{",            # dispatch table opener
    '"set_profile"',             # baseline command type
    '"get_status"',              # baseline command type
    '"isolate"',                 # ISOLATE handler entry
    '"update_handler"',          # UPDATE_HANDLER handler entry
)


def _normalise_bytes(data: bytes) -> bytes:
    """CRLF + UTF-8-BOM canonical form. Same algorithm as
    scripts/normalize_ps1.py — this is the on-the-wire normaliser for
    uploads + scans, that one is the source-tree normaliser for commits.
    Idempotent: applying twice produces identical bytes."""
    if data.startswith(_BOM):
        data = data[len(_BOM):]
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = [ln.rstrip() for ln in data.split(b"\n")]
    data = b"\r\n".join(lines)
    return _BOM + data


def _validate_handler_bytes(data: bytes) -> bytes:
    """Validate + normalise bytes destined for the handler version store.

    Returns the canonical bytes (BOM + CRLF + trailing-whitespace-stripped)
    if every check passes. Raises ValueError with a single, operator-
    actionable sentence describing the first failure if not.

    Checks (in order, fast-fail):
      1. Size: 200 bytes to 5 MB.
      2. UTF-8 decodes cleanly (BOM-tolerant).
      3. Required content markers present (sniff this is our handler).

    Normalisation (after validation):
      4. CRLF + UTF-8-BOM + per-line trailing-whitespace stripped.
    """
    n = len(data)
    if n < 200:
        raise ValueError(f"handler script too small ({n} bytes)")
    if n > 5 * 1024 * 1024:
        raise ValueError(f"handler script too large ({n} bytes; max 5 MB)")

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise ValueError(f"handler script is not valid UTF-8: {e}") from None

    missing = [m for m in _REQUIRED_MARKERS if m not in text]
    if missing:
        raise ValueError(
            "handler script is missing expected marker(s): "
            + ", ".join(repr(m) for m in missing)
            + " — is this really agent_command_handler.ps1?"
        )

    return _normalise_bytes(data)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS handler_versions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    version_label TEXT    NOT NULL UNIQUE,
    sha256        TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    content_b64   TEXT    NOT NULL,
    status        TEXT    NOT NULL CHECK(status IN ('staged','live','archived')),
    uploaded_by   TEXT    NOT NULL,
    uploaded_at   REAL    NOT NULL,
    notes         TEXT,
    promoted_at   REAL,
    promoted_by   TEXT
);
CREATE INDEX IF NOT EXISTS ix_handler_versions_status ON handler_versions(status);
CREATE INDEX IF NOT EXISTS ix_handler_versions_label  ON handler_versions(version_label);
"""


class HandlerVersionStore:

    def __init__(self, db_path: str | Path):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self._lock = threading.Lock()

    # ── Write ──────────────────────────────────────────────────────────────

    def create(
        self,
        version_label: str,
        content_bytes: bytes,
        uploaded_by: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Stage a new version.

        Bytes are validated AND normalised (CRLF + UTF-8 BOM, trailing
        whitespace stripped) before storage. A broken script is rejected
        with ValueError before ever entering the table — see
        `_validate_handler_bytes` for the checks.

        Raises ValueError on duplicate label OR validation failure.
        """
        version_label = version_label.strip()
        if not version_label:
            raise ValueError("version_label is required")
        # Validate + canonicalise. The sha256 we store is of the CANONICAL
        # bytes, so the agent's manifest check + on-wire SHA verify line
        # up byte-for-byte regardless of what the operator's editor wrote.
        content_bytes = _validate_handler_bytes(content_bytes)
        sha256 = hashlib.sha256(content_bytes).hexdigest()
        b64 = base64.b64encode(content_bytes).decode("ascii")
        now = time.time()
        try:
            with self._lock:
                cur = self.conn.execute(
                    """INSERT INTO handler_versions
                         (version_label, sha256, size_bytes, content_b64, status,
                          uploaded_by, uploaded_at, notes)
                       VALUES (?, ?, ?, ?, 'staged', ?, ?, ?)""",
                    (version_label, sha256, len(content_bytes), b64,
                     uploaded_by, now, notes),
                )
                self.conn.commit()
                return self.get_by_id(cur.lastrowid)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"version_label '{version_label}' already exists") from e

    def promote(self, row_id: int, promoted_by: str) -> Optional[dict]:
        """Flip a staged version to live. Any previous live row is archived
        atomically. Returns the new live row, or None if row_id missing /
        already archived."""
        now = time.time()
        with self._lock:
            row = self.conn.execute(
                "SELECT id, status FROM handler_versions WHERE id=?",
                (row_id,),
            ).fetchone()
            if not row:
                return None
            if row["status"] == "live":
                # Idempotent — already live, just return current state.
                return self.get_by_id(row_id)
            if row["status"] == "archived":
                # Re-promoting an archived version is allowed (operator may
                # want to roll back).
                pass
            # Archive whatever is currently live.
            self.conn.execute(
                "UPDATE handler_versions SET status='archived' WHERE status='live'",
            )
            self.conn.execute(
                """UPDATE handler_versions
                     SET status='live', promoted_at=?, promoted_by=?
                   WHERE id=?""",
                (now, promoted_by, row_id),
            )
            self.conn.commit()
            return self.get_by_id(row_id)

    def archive(self, row_id: int) -> bool:
        """Mark a row archived. Refuses to archive the current `live` row
        (operator must promote a replacement first). Returns True on change."""
        with self._lock:
            row = self.conn.execute(
                "SELECT status FROM handler_versions WHERE id=?", (row_id,),
            ).fetchone()
            if not row:
                return False
            if row["status"] == "live":
                raise ValueError("Cannot archive the current live version; "
                                 "promote a replacement first")
            cur = self.conn.execute(
                "UPDATE handler_versions SET status='archived' WHERE id=?",
                (row_id,),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def delete(self, row_id: int) -> bool:
        """Hard-delete a staged or archived row. Refuses to delete `live`."""
        with self._lock:
            row = self.conn.execute(
                "SELECT status FROM handler_versions WHERE id=?", (row_id,),
            ).fetchone()
            if not row:
                return False
            if row["status"] == "live":
                raise ValueError("Cannot delete the current live version")
            cur = self.conn.execute(
                "DELETE FROM handler_versions WHERE id=?", (row_id,),
            )
            self.conn.commit()
            return cur.rowcount > 0

    # ── Read ───────────────────────────────────────────────────────────────

    def get_by_id(self, row_id: int) -> Optional[dict]:
        row = self.conn.execute(
            """SELECT id, version_label, sha256, size_bytes, status,
                      uploaded_by, uploaded_at, notes, promoted_at, promoted_by
               FROM handler_versions WHERE id=?""",
            (row_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_by_label(self, version_label: str) -> Optional[dict]:
        """Like get_by_id but resolved through version_label.
        Used by the agent fetch path."""
        row = self.conn.execute(
            """SELECT id, version_label, sha256, size_bytes, content_b64,
                      status, uploaded_by, uploaded_at, notes,
                      promoted_at, promoted_by
               FROM handler_versions WHERE version_label=?""",
            (version_label,),
        ).fetchone()
        return dict(row) if row else None

    def get_live(self) -> Optional[dict]:
        """Current live row, or None if none promoted yet."""
        row = self.conn.execute(
            """SELECT id, version_label, sha256, size_bytes, content_b64,
                      status, uploaded_by, uploaded_at, notes,
                      promoted_at, promoted_by
               FROM handler_versions WHERE status='live' LIMIT 1""",
        ).fetchone()
        return dict(row) if row else None

    def list_all(self, include_content: bool = False) -> list[dict]:
        """All rows ordered newest-first. Content excluded by default since
        the dashboard list view doesn't need the bytes."""
        cols = "id, version_label, sha256, size_bytes, status, uploaded_by, " \
               "uploaded_at, notes, promoted_at, promoted_by"
        if include_content:
            cols += ", content_b64"
        rows = self.conn.execute(
            f"SELECT {cols} FROM handler_versions ORDER BY uploaded_at DESC",
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Helpers ────────────────────────────────────────────────────────────

    def content_bytes_of(self, row: dict) -> bytes:
        """Decode the stored base64 back to raw bytes. Caller is responsible
        for SHA-256 re-verification if it matters."""
        return base64.b64decode(row["content_b64"])

    def close(self) -> None:
        self.conn.close()
