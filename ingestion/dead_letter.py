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
        return [json.loads(f.read_text()) for f in files]

    def count(self) -> int:
        return len(list(self.storage_dir.glob("dlq_*.json")))
