# ingestion/preprocessor.py — HARDENED
"""
Event preprocessor with security-focused input validation.
Defense-in-depth: even though Wazuh validates its own data,
we validate again because:
1. Wazuh itself could be compromised
2. A malicious Wazuh agent could craft events
3. The API could receive direct submissions in future
"""

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Optional

from pydantic import ValidationError
from shared.schemas import NormalizedEvent
from shared.logging import get_logger
from ingestion.dead_letter import DeadLetterQueue

logger = get_logger("ingestion.preprocessor")


class EventPreprocessor:

    # Maximum acceptable sizes (prevent memory exhaustion)
    MAX_COMMAND_LINE_LENGTH = 8192  # 8KB — longest reasonable PowerShell command
    MAX_DNS_QUERY_LENGTH = 253  # DNS RFC limit
    MAX_PROCESS_NAME_LENGTH = 260  # Windows MAX_PATH
    MAX_EVENT_AGE_HOURS = 24  # Reject events older than 24h
    MAX_FUTURE_DRIFT_SECONDS = 300  # Reject events >5min in the future

    # Patterns that should NEVER appear in certain fields
    # These indicate injection attempts or data corruption
    INJECTION_PATTERNS = re.compile(
        r"(\x00|<script|javascript:|data:text/html|" r"%00|%0a|%0d|\r\n|\n\r)",
        re.IGNORECASE,
    )

    def __init__(self, dead_letter: Optional[DeadLetterQueue] = None):
        self.dead_letter = dead_letter or DeadLetterQueue()
        self._stats = {"processed": 0, "rejected": 0, "sanitized": 0}

    def normalize_batch(self, raw_events: list[dict]) -> list[NormalizedEvent]:
        """Process a batch of raw Wazuh events. Invalid events go to dead letter queue."""
        results = []
        for raw in raw_events:
            try:
                event = self._validate_and_normalize(raw)
                if event:
                    results.append(event)
                    self._stats["processed"] += 1
            except Exception as e:
                self._stats["rejected"] += 1
                logger.warning(
                    "Event rejected",
                    reason=str(e),
                    event_id=raw.get("id", "unknown"),
                    extra={"raw_event_keys": list(raw.keys())},
                )
                self.dead_letter.enqueue(raw, reason=str(e))
        return results

    def _validate_and_normalize(self, raw: dict) -> Optional[NormalizedEvent]:
        """Validate a single event. Returns None if invalid."""

        # ── 1. Timestamp validation ──
        ts = raw.get("timestamp")
        if ts:
            parsed_ts = self._parse_timestamp(ts)
            if not parsed_ts:
                raise ValueError(f"Unparseable timestamp: {ts}")
            # Reject events too old or in the future
            now = datetime.utcnow()
            if parsed_ts < now - timedelta(hours=self.MAX_EVENT_AGE_HOURS):
                raise ValueError(f"Event too old: {parsed_ts}")
            if parsed_ts > now + timedelta(seconds=self.MAX_FUTURE_DRIFT_SECONDS):
                raise ValueError(f"Event timestamp in future: {parsed_ts}")

        # ── 2. IP address validation ──
        for ip_field in ["source_ip", "dest_ip"]:
            ip_val = raw.get(ip_field)
            if ip_val:
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError:
                    raise ValueError(f"Invalid IP in {ip_field}: {ip_val}")

        # ── 3. String length limits (prevent memory bombs) ──
        if (
            raw.get("command_line")
            and len(raw["command_line"]) > self.MAX_COMMAND_LINE_LENGTH
        ):
            raw["command_line"] = raw["command_line"][: self.MAX_COMMAND_LINE_LENGTH]
            self._stats["sanitized"] += 1
            logger.info("Command line truncated", event_id=raw.get("id"))

        if raw.get("dns_query") and len(raw["dns_query"]) > self.MAX_DNS_QUERY_LENGTH:
            raise ValueError(
                f"DNS query exceeds RFC limit: {len(raw['dns_query'])} chars"
            )

        if (
            raw.get("process_name")
            and len(raw["process_name"]) > self.MAX_PROCESS_NAME_LENGTH
        ):
            raise ValueError(f"Process name too long: {len(raw['process_name'])} chars")

        # ── 4. Injection pattern detection ──
        for field in ["user", "hostname", "process_name", "dns_query"]:
            val = raw.get(field, "")
            if val and self.INJECTION_PATTERNS.search(str(val)):
                raise ValueError(f"Injection pattern detected in {field}")

        # ── 5. Numeric bounds ──
        for field in ["bytes_sent", "bytes_received"]:
            val = raw.get(field, 0)
            if (
                not isinstance(val, (int, float)) or val < 0 or val > 10_000_000_000
            ):  # 10GB max
                raw[field] = 0

        # ── 6. Pydantic schema validation (final pass) ──
        try:
            return NormalizedEvent(**raw)
        except ValidationError as e:
            raise ValueError(f"Schema validation failed: {e.error_count()} errors")

    def _parse_timestamp(self, ts) -> Optional[datetime]:
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
            ]:
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue
        return None

    def get_stats(self) -> dict:
        return dict(self._stats)
