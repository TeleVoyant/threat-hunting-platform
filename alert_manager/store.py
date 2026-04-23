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
                data JSON NOT NULL
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

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(overall_severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_detections_entity ON detections(source_entity);
        """)
        self.conn.commit()

    def store_alert(self, alert: EnrichedAlert):
        """Persist an enriched alert and its detections."""
        entities = list(set(d.source_entity for d in alert.detections))

        self.conn.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, 'open', NULL, NULL, ?)",
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
            "UPDATE alerts SET status='acknowledged', acknowledged_by=?, acknowledged_at=? WHERE alert_id=?",
            (username, time.time(), alert_id),
        )
        self.conn.commit()

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
        query = "SELECT data FROM alerts WHERE timestamp > ?"
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
        return [json.loads(r[0]) for r in rows]

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
