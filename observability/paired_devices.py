# observability/paired_devices.py
"""
Tracks which phones an analyst has enrolled. Lets admins see the inventory
and unpair a lost / stolen / replaced device.

  Schema: paired_devices(
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL,
      brand         TEXT,
      model         TEXT,
      device_id     TEXT,   -- stable per-device hash (Build.FINGERPRINT)
      paired_ip     TEXT,   -- last-octet-masked IP from request.client.host
      paired_at     REAL,
      last_seen_at  REAL,
      jti           TEXT,   -- the enrol JWT JTI that minted this pairing
      active        INTEGER DEFAULT 1
  )

The IP is captured *masked* (e.g. 172.16.0.x) so we don't leak the analyst's
exact device address into the audit trail in production. For an FYP demo on
a local LAN this matters less, but the masking is permanent.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional


_DDL = """
CREATE TABLE IF NOT EXISTS paired_devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL,
    brand         TEXT,
    model         TEXT,
    device_name   TEXT,
    device_id     TEXT,
    paired_ip     TEXT,
    paired_at     REAL    NOT NULL,
    last_seen_at  REAL,
    lat           REAL,
    lon           REAL,
    jti           TEXT,
    active        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_paired_devices_username ON paired_devices(username);
CREATE INDEX IF NOT EXISTS ix_paired_devices_active   ON paired_devices(active);
"""

# Idempotent migrations for existing dbs created before these columns existed.
_MIGRATIONS = [
    ("device_name", "TEXT"),
    ("lat",         "REAL"),
    ("lon",         "REAL"),
]


def _mask_ip(ip: Optional[str]) -> Optional[str]:
    """IPv4 → 172.16.0.x (mask last octet). Pass IPv6 / unknown through."""
    if not ip:
        return ip
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    return ip


class PairedDevicesStore:

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # SQLite from multiple threads — same connection guarded by a lock.
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.conn.executescript(_DDL)
            # Apply additive migrations for older schemas.
            existing = {
                row["name"] for row in self.conn.execute(
                    "PRAGMA table_info(paired_devices)"
                ).fetchall()
            }
            for col, type_ in _MIGRATIONS:
                if col not in existing:
                    self.conn.execute(
                        f"ALTER TABLE paired_devices ADD COLUMN {col} {type_}"
                    )
            self.conn.commit()

    def record_pairing(
        self,
        username: str,
        brand: Optional[str],
        model: Optional[str],
        device_name: Optional[str],
        device_id: Optional[str],
        paired_ip: Optional[str],
        jti: Optional[str],
        lat: Optional[float] = None,
        lon: Optional[float] = None,
    ) -> int:
        """Insert a new pairing row. Returns the new id.

        If the same (username, device_id) is already active, unpair the
        previous row so the inventory shows a single live row per device.
        """
        now = time.time()
        masked = _mask_ip(paired_ip)
        with self._lock:
            if device_id:
                self.conn.execute(
                    "UPDATE paired_devices SET active=0 "
                    "WHERE username=? AND device_id=? AND active=1",
                    (username, device_id),
                )
            cur = self.conn.execute(
                "INSERT INTO paired_devices "
                "(username, brand, model, device_name, device_id, paired_ip, "
                " paired_at, last_seen_at, lat, lon, jti, active) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                (username, brand, model, device_name, device_id, masked,
                 now, now, lat, lon, jti),
            )
            self.conn.commit()
            return int(cur.lastrowid or 0)

    def touch_seen(self, username: str, device_id: Optional[str]) -> None:
        """Bump last_seen_at when the phone hits an authenticated endpoint."""
        if not device_id:
            return
        with self._lock:
            self.conn.execute(
                "UPDATE paired_devices SET last_seen_at=? "
                "WHERE username=? AND device_id=? AND active=1",
                (time.time(), username, device_id),
            )
            self.conn.commit()

    def list_all(self, include_inactive: bool = False) -> list[dict]:
        q = ("SELECT * FROM paired_devices"
             + ("" if include_inactive else " WHERE active=1")
             + " ORDER BY paired_at DESC")
        with self._lock:
            rows = self.conn.execute(q).fetchall()
        return [dict(r) for r in rows]

    def get(self, row_id: int) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM paired_devices WHERE id=?", (row_id,),
            ).fetchone()
        return dict(r) if r else None

    def unpair(self, row_id: int) -> bool:
        """Mark the row inactive. Caller is responsible for rotating the
        api_key — the row is just inventory metadata."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE paired_devices SET active=0 WHERE id=? AND active=1",
                (row_id,),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def close(self) -> None:
        with self._lock:
            self.conn.close()
