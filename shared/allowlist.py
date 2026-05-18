# shared/allowlist.py
"""
Persistent DNS allowlist — domains that are NEVER labelled as DNS exfiltration
destinations even when they appear in detection-related events.

Operators add/remove via REST (api/routes/allowlist.py) and any subscriber
that needs the live list calls `get_default().contains(domain)` — no caching
above this layer because changes must take effect immediately.

Backed by SQLite for durability. The set is loaded from the DB on
construction and refreshed with each query (cheap — typically <100 entries).
For higher scale, swap to a periodic in-memory snapshot.

Seeded on first init with a known-benign default set. Operators can
delete any of these — they are NOT special-cased.
"""

import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Optional

from shared.logging import get_logger

logger = get_logger("shared.allowlist")


_DEFAULT_SEED = (
    "windowsupdate.com", "microsoft.com", "windows.com", "msftncsi.com",
    "msftconnecttest.com", "office.com", "office365.com", "live.com",
    "msedge.net", "google.com", "googleapis.com", "github.com",
    "github.io", "mozilla.org",
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_allowlist (
    domain      TEXT PRIMARY KEY,
    added_by    TEXT NOT NULL,
    added_at    REAL NOT NULL,
    note        TEXT
);
"""


class DnsAllowlist:

    def __init__(self, db_path: str = "data/allowlist/dns.db", seed_defaults: bool = True):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        self._lock = Lock()
        if seed_defaults:
            self._seed_if_empty()

    def _seed_if_empty(self) -> None:
        row = self.conn.execute("SELECT COUNT(*) FROM dns_allowlist").fetchone()
        if row[0] == 0:
            now = time.time()
            self.conn.executemany(
                "INSERT OR IGNORE INTO dns_allowlist(domain, added_by, added_at, note) "
                "VALUES (?, 'system', ?, 'default seed')",
                [(d, now) for d in _DEFAULT_SEED],
            )
            self.conn.commit()
            logger.info("DNS allowlist seeded", count=len(_DEFAULT_SEED))

    # ── Read API (called from hot paths) ───────────────────────────────────

    def contains(self, domain: str) -> bool:
        """True if `domain` should be excluded from attack-graph DNS edges."""
        if not domain:
            return False
        row = self.conn.execute(
            "SELECT 1 FROM dns_allowlist WHERE domain = ? LIMIT 1",
            (domain.lower(),),
        ).fetchone()
        return row is not None

    def all(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT domain, added_by, added_at, note "
            "FROM dns_allowlist ORDER BY added_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM dns_allowlist").fetchone()[0]

    # ── Write API (admin endpoints) ────────────────────────────────────────

    def add(self, domain: str, added_by: str, note: Optional[str] = None) -> bool:
        """Returns True if newly added, False if already present."""
        d = (domain or "").strip().lower()
        if not d:
            raise ValueError("Empty domain")
        # Cheap sanity check — block obvious injection / non-domain payloads
        if any(c in d for c in (" ", "\n", "\r", "\t", "/", "\\")):
            raise ValueError(f"Invalid domain characters in {domain!r}")

        with self._lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO dns_allowlist(domain, added_by, added_at, note) "
                "VALUES (?, ?, ?, ?)",
                (d, added_by, time.time(), note),
            )
            self.conn.commit()
        added = cur.rowcount > 0
        if added:
            logger.info("DNS allowlist add", domain=d, by=added_by)
        return added

    def remove(self, domain: str) -> bool:
        """Returns True if removed, False if not present."""
        d = (domain or "").strip().lower()
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM dns_allowlist WHERE domain = ?", (d,),
            )
            self.conn.commit()
        removed = cur.rowcount > 0
        if removed:
            logger.info("DNS allowlist remove", domain=d)
        return removed


# ── Module-level default for hot-path consumers ────────────────────────────

_DEFAULT: Optional[DnsAllowlist] = None


def configure_default(allowlist: DnsAllowlist) -> None:
    """Call once at app startup to install the live allowlist."""
    global _DEFAULT
    _DEFAULT = allowlist


def get_default() -> Optional[DnsAllowlist]:
    """Returns the configured default allowlist, or None if not yet wired."""
    return _DEFAULT
