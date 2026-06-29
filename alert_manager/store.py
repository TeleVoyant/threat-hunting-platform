# alert_manager/store.py
"""
Lightweight alert persistence using SQLite.
Enables: alert history, deduplication across restarts, forensic queries.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import Optional
from shared.schemas import EnrichedAlert, Detection
from shared.logging import get_logger

logger = get_logger("alert_manager.store")


class AlertStore:

    def __init__(self, db_path: str = "/data/alerts/alerts.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                overall_severity TEXT NOT NULL,
                overall_confidence REAL NOT NULL,
                mitre_techniques TEXT,
                source_entities TEXT,
                status TEXT DEFAULT 'open',
                acknowledged_by TEXT,
                acknowledged_at REAL,
                data JSON NOT NULL,
                verdict TEXT,                       -- NULL | false_positive | confirmed_malicious
                updated_by TEXT,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS detections (
                detection_id TEXT PRIMARY KEY,
                alert_id TEXT,
                detector_name TEXT NOT NULL,
                confidence REAL NOT NULL,
                source_entity TEXT NOT NULL,
                timestamp REAL NOT NULL,
                data JSON NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
            );

            -- Entities (hostname or hostname:user) the operator has quarantined
            -- from the retraining benign pool. The auto-retrain reads active rows
            -- and excludes matching events. Released entities (active=0) re-enter.
            CREATE TABLE IF NOT EXISTS training_quarantine (
                entity TEXT PRIMARY KEY,
                reason TEXT,
                alert_id TEXT,
                added_by TEXT,
                added_at REAL,
                released_at REAL,
                active INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(overall_severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_detections_entity ON detections(source_entity);
            CREATE INDEX IF NOT EXISTS idx_quarantine_active ON training_quarantine(active);
        """)
        # Defensive migration: lifecycle columns on an alerts table from an older schema.
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(alerts)")}
        for col, decl in (("verdict", "TEXT"), ("updated_by", "TEXT"), ("updated_at", "REAL")):
            if col not in cols:
                self.conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {decl}")
        self.conn.commit()

    def store_alert(self, alert: EnrichedAlert):
        """Persist an enriched alert and its detections."""
        entities = list(set(d.source_entity for d in alert.detections))

        # New alerts start 'open'; re-storing an existing alert_id refreshes the
        # detection fields but PRESERVES the analyst's status/verdict/ack (the old
        # INSERT OR REPLACE reset them to 'open' on every re-store).
        self.conn.execute(
            "INSERT INTO alerts "
            "(alert_id, timestamp, overall_severity, overall_confidence, "
            " mitre_techniques, source_entities, status, data) "
            "VALUES (?, ?, ?, ?, ?, ?, 'open', ?) "
            "ON CONFLICT(alert_id) DO UPDATE SET "
            " timestamp=excluded.timestamp, overall_severity=excluded.overall_severity, "
            " overall_confidence=excluded.overall_confidence, "
            " mitre_techniques=excluded.mitre_techniques, "
            " source_entities=excluded.source_entities, data=excluded.data",
            (
                alert.alert_id,
                alert.timestamp.timestamp(),
                alert.overall_severity.value,
                alert.overall_confidence,
                json.dumps(alert.mitre_techniques),
                json.dumps(entities),
                alert.model_dump_json(),
            ),
        )

        for det in alert.detections:
            self.conn.execute(
                "INSERT OR REPLACE INTO detections VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    det.detection_id,
                    alert.alert_id,
                    det.detector_name,
                    det.confidence,
                    det.source_entity,
                    det.timestamp.timestamp(),
                    det.model_dump_json(),
                ),
            )

        self.conn.commit()
        logger.info(
            "Alert persisted", alert_id=alert.alert_id, detections=len(alert.detections)
        )

    def acknowledge(self, alert_id: str, username: str):
        self.conn.execute(
            "UPDATE alerts SET status='acknowledged', acknowledged_by=?, acknowledged_at=?, "
            "updated_by=?, updated_at=? WHERE alert_id=?",
            (username, time.time(), username, time.time(), alert_id),
        )
        self.conn.commit()

    # ── Triage lifecycle + verdict ──────────────────────────────────────────

    _STATUSES = {"open", "acknowledged", "investigating", "resolved"}
    _VERDICTS = {None, "false_positive", "confirmed_malicious"}

    def set_status(self, alert_id: str, status: str, username: str) -> None:
        if status not in self._STATUSES:
            raise ValueError(f"Invalid status: {status}")
        self.conn.execute(
            "UPDATE alerts SET status=?, updated_by=?, updated_at=? WHERE alert_id=?",
            (status, username, time.time(), alert_id),
        )
        self.conn.commit()

    def set_verdict(self, alert_id: str, verdict: Optional[str], username: str) -> None:
        if verdict not in self._VERDICTS:
            raise ValueError(f"Invalid verdict: {verdict}")
        self.conn.execute(
            "UPDATE alerts SET verdict=?, updated_by=?, updated_at=? WHERE alert_id=?",
            (verdict, username, time.time(), alert_id),
        )
        self.conn.commit()

    # ── Training quarantine (operator-controlled retrain exclusion) ──────────

    def quarantine_entity(self, entity: str, reason: str, alert_id: Optional[str],
                          username: str) -> None:
        """Exclude an entity (hostname or hostname:user) from the retrain benign
        pool. Idempotent: re-quarantining a released entity reactivates it."""
        self.conn.execute(
            "INSERT INTO training_quarantine (entity, reason, alert_id, added_by, added_at, active) "
            "VALUES (?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(entity) DO UPDATE SET active=1, reason=excluded.reason, "
            "alert_id=excluded.alert_id, added_by=excluded.added_by, "
            "added_at=excluded.added_at, released_at=NULL",
            (entity, reason, alert_id, username, time.time()),
        )
        self.conn.commit()

    def release_entity(self, entity: str, username: str) -> None:
        self.conn.execute(
            "UPDATE training_quarantine SET active=0, released_at=? WHERE entity=?",
            (time.time(), entity),
        )
        self.conn.commit()

    def list_quarantine(self, active_only: bool = True) -> list[dict]:
        cols = ("entity", "reason", "alert_id", "added_by", "added_at", "released_at", "active")
        q = f"SELECT {', '.join(cols)} FROM training_quarantine"
        if active_only:
            q += " WHERE active=1"
        q += " ORDER BY added_at DESC"
        return [dict(zip(cols, r)) for r in self.conn.execute(q).fetchall()]

    def is_duplicate(
        self, source_entity: str, detector_name: str, window_minutes: int = 30
    ) -> bool:
        """Check if a similar alert exists within the deduplication window."""
        cutoff = time.time() - (window_minutes * 60)
        row = self.conn.execute(
            "SELECT COUNT(*) FROM detections WHERE source_entity=? AND detector_name=? AND timestamp>?",
            (source_entity, detector_name, cutoff),
        ).fetchone()
        return row[0] > 0

    def query_alerts(
        self,
        severity: str = None,
        status: str = None,
        entity: str = None,
        hours: int = 24,
        limit: int = 100,
    ) -> list[dict]:
        """Query alerts with filters for the dashboard API."""
        query = "SELECT data, status, verdict FROM alerts WHERE timestamp > ?"
        params = [time.time() - (hours * 3600)]

        if severity:
            query += " AND overall_severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if entity:
            query += " AND source_entities LIKE ?"
            params.append(f"%{entity}%")

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        out = []
        for data, status, verdict in rows:
            d = json.loads(data)
            d["status"] = status        # live columns override the values baked into `data`
            d["verdict"] = verdict
            out.append(d)
        return out

    def get_stats(self) -> dict:
        """Dashboard statistics."""
        return {
            "total_alerts": self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[
                0
            ],
            "open_alerts": self.conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status='open'"
            ).fetchone()[0],
            "by_severity": dict(
                self.conn.execute(
                    "SELECT overall_severity, COUNT(*) FROM alerts WHERE status='open' GROUP BY overall_severity"
                ).fetchall()
            ),
        }
