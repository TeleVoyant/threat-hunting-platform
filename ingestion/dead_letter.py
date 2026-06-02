# ingestion/dead_letter.py
"""
Dead Letter Queue: quarantine events that fail validation.
Allows analysts to inspect rejected events for:
1. Legitimate events that were malformed (fix the parser)
2. Actual attack attempts (injection, data corruption)
"""

import json
import time
from pathlib import Path
from shared.logging import get_logger

logger = get_logger("ingestion.dead_letter")


class DeadLetterQueue:

    def __init__(self, storage_dir: str = "/data/dead_letter"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def enqueue(self, raw_event: dict, reason: str):
        """Store a rejected event with metadata."""
        entry = {
            "rejected_at": time.time(),
            "reason": reason,
            "event": raw_event,
        }
        filename = f"dlq_{int(time.time() * 1000)}.json"
        filepath = self.storage_dir / filename
        filepath.write_text(json.dumps(entry, default=str))
        logger.info("Event quarantined", file=filename, reason=reason)

    def list_recent(self, limit: int = 100) -> list[dict]:
        """List recent dead letter entries for inspection."""
        files = sorted(self.storage_dir.glob("dlq_*.json"), reverse=True)[:limit]
        return [{"id": f.stem, **json.loads(f.read_text())} for f in files]

    def count(self) -> int:
        return len(list(self.storage_dir.glob("dlq_*.json")))

    def get(self, dlq_id: str) -> dict:
        """Fetch a single DLQ entry by id (file stem). Raises FileNotFoundError."""
        # Refuse path-traversal-ish ids.
        if "/" in dlq_id or ".." in dlq_id or not dlq_id.startswith("dlq_"):
            raise ValueError(f"Bad DLQ id: {dlq_id!r}")
        path = self.storage_dir / f"{dlq_id}.json"
        if not path.exists():
            raise FileNotFoundError(dlq_id)
        return {"id": dlq_id, **json.loads(path.read_text())}

    def remove(self, dlq_id: str) -> bool:
        """Delete a DLQ entry — used after a successful replay."""
        if "/" in dlq_id or ".." in dlq_id or not dlq_id.startswith("dlq_"):
            raise ValueError(f"Bad DLQ id: {dlq_id!r}")
        path = self.storage_dir / f"{dlq_id}.json"
        if not path.exists():
            return False
        path.unlink()
        return True
