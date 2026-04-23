# features/cache.py
"""
Feature cache: avoid recomputing the same features.
Uses LRU in-memory cache with optional disk spillover.
"""

import hashlib
import json
import time
from collections import OrderedDict
from typing import Optional

from shared.schemas import FeatureVector
from shared.logging import get_logger

logger = get_logger("features.cache")


class FeatureCache:

    def __init__(self, max_memory_entries: int = 10000, ttl_seconds: int = 600):
        self.max_entries = max_memory_entries
        self.ttl = ttl_seconds
        self._cache: OrderedDict[str, tuple[float, FeatureVector]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def _make_key(self, entity: str, window_start: str, window_end: str) -> str:
        raw = f"{entity}:{window_start}:{window_end}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get(
        self, entity: str, window_start: str, window_end: str
    ) -> Optional[FeatureVector]:
        key = self._make_key(entity, window_start, window_end)
        if key in self._cache:
            ts, fv = self._cache[key]
            if time.time() - ts < self.ttl:
                self._hits += 1
                self._cache.move_to_end(key)
                return fv
            else:
                del self._cache[key]
        self._misses += 1
        return None

    def put(self, fv: FeatureVector):
        key = self._make_key(
            fv.source_entity,
            fv.timestamp_start.isoformat(),
            fv.timestamp_end.isoformat(),
        )
        self._cache[key] = (time.time(), fv)
        if len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def get_stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "entries": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / max(1, total), 3),
        }
