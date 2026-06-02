# ingestion/sliding_window.py
"""
Per-host sliding-window buffer (a).

The detection loop polls every poll_interval_seconds, but the feature
extractors compute rate/CV signals that only make sense across the full
analytic window (event_window_minutes). Without buffering, every poll emits
features over ~30-60s of data, biasing beaconing CV and lateral velocity
toward the polling cadence instead of the analytic window.

Buffer holds events per (host) keyed by Wazuh event_id for cheap dedup
across re-fetches. Flushing happens on a timer (window-aligned), not on
every poll — the API thread calls `flush_due()` once per cycle and pushes
the returned events through the bus.

Memory is bounded: oldest events past `window_minutes + grace` are evicted
on insert.
"""

import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from shared.logging import get_logger
from shared.schemas import NormalizedEvent

logger = get_logger("ingestion.sliding_window")


class SlidingWindowBuffer:

    def __init__(self, window_minutes: int = 5, grace_seconds: int = 30):
        self.window_seconds = window_minutes * 60
        self.grace_seconds = grace_seconds
        # event_id → (timestamp_epoch, NormalizedEvent). OrderedDict so eviction
        # walks the oldest entries in insertion order.
        self._seen: OrderedDict[str, tuple[float, NormalizedEvent]] = OrderedDict()
        # Last flush wall-clock time so the API can decide whether to flush.
        self._last_flush: float = 0.0

    # ── Insertion ──────────────────────────────────────────────────────────

    def add_batch(self, events: Iterable[NormalizedEvent]) -> int:
        """Insert events, dropping duplicates by event_id. Returns count added."""
        now = time.time()
        added = 0
        for e in events:
            if not e.event_id:
                # Defensive: synthesize a key from (hostname, timestamp) so
                # un-ID'd events still flow through. Unlikely with Wazuh.
                key = f"{e.hostname}|{e.timestamp.isoformat()}"
            else:
                key = e.event_id
            if key in self._seen:
                continue
            ts_epoch = self._to_epoch(e.timestamp)
            self._seen[key] = (ts_epoch, e)
            added += 1

        # Bound memory: evict events older than window + grace.
        cutoff = now - self.window_seconds - self.grace_seconds
        evicted = 0
        # OrderedDict iteration order is insertion order, not timestamp order,
        # so we walk and pop entries that are past the cutoff.
        to_drop = [k for k, (ts, _) in self._seen.items() if ts < cutoff]
        for k in to_drop:
            self._seen.pop(k, None)
            evicted += 1
        if evicted:
            logger.debug("Sliding window evicted",
                         count=evicted, retained=len(self._seen))
        return added

    # ── Flush ──────────────────────────────────────────────────────────────

    def due_to_flush(self) -> bool:
        """True when window_seconds has elapsed since the last flush."""
        return time.time() - self._last_flush >= self.window_seconds

    def snapshot(self) -> list[NormalizedEvent]:
        """All events currently in the window, ordered by event timestamp.
        Does NOT clear the buffer — eviction is age-based."""
        items = sorted(self._seen.values(), key=lambda v: v[0])
        return [ev for _, ev in items]

    def mark_flushed(self) -> None:
        self._last_flush = time.time()

    def size(self) -> int:
        return len(self._seen)

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _to_epoch(ts: datetime) -> float:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.timestamp()
