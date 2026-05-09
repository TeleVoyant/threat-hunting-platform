# features/temporal_features.py
"""
Temporal feature extractor — captures timing patterns across the event window.

These features distinguish APT activity from normal user behaviour:
  - Burst factor: APTs cluster activity in tight bursts; normal users are steady
  - Off-hours bias: APT operators often work outside victim's business hours
  - Inter-event regularity: any kind of beaconing has low coefficient of variation
  - Active minute count: spread of activity across the window
"""

import statistics
from collections import Counter

from shared.interfaces import BaseFeatureExtractor
from shared.schemas import NormalizedEvent


class TemporalFeatureExtractor(BaseFeatureExtractor):

    def name(self) -> str:
        return "temporal"

    def required_event_types(self) -> list[str]:
        # Operate on every event type — temporal patterns span the whole window
        return ["*"]

    def extract(self, events: list[NormalizedEvent]) -> dict[str, float]:
        if not events:
            return self._empty()

        n = len(events)
        timestamps = sorted(e.timestamp for e in events)
        window_secs = max(
            (timestamps[-1] - timestamps[0]).total_seconds(), 1.0
        )

        # ── Rate ─────────────────────────────────────────────────────────────
        events_per_minute = (n / window_secs) * 60.0

        # ── Burst factor: max 1-min count / mean 1-min count ─────────────────
        per_minute: Counter = Counter()
        for ts in timestamps:
            bucket = ts.replace(second=0, microsecond=0)
            per_minute[bucket] += 1

        if len(per_minute) >= 2:
            counts = list(per_minute.values())
            mean_per_min = statistics.mean(counts)
            burst_factor = max(counts) / mean_per_min if mean_per_min > 0 else 0.0
            stdev_per_min = statistics.stdev(counts)
        else:
            burst_factor = 0.0
            stdev_per_min = 0.0

        # ── Time-of-day distribution (UTC) ───────────────────────────────────
        # Off-hours = outside 06:00–18:00 UTC. Production deployments would
        # ideally use the agent's local timezone, but UTC is a robust default
        # for relative comparison and works for cross-tenant federated learning.
        off_hours   = sum(1 for ts in timestamps if ts.hour < 6 or ts.hour >= 18)
        night_hours = sum(1 for ts in timestamps if 0 <= ts.hour < 6)
        weekend     = sum(1 for ts in timestamps if ts.weekday() >= 5)

        # ── Inter-event intervals (beaconing detection) ──────────────────────
        if len(timestamps) >= 3:
            intervals = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            intervals = [x for x in intervals if x > 0] or [0.0]
            mean_int = statistics.mean(intervals)
            cv_int = (
                statistics.stdev(intervals) / mean_int
                if mean_int > 0 and len(intervals) >= 2
                else 0.0
            )
            min_int = min(intervals)
            max_int = max(intervals)
        else:
            mean_int = cv_int = min_int = max_int = 0.0

        return {
            # Volume / rate
            "total_event_count":         float(n),
            "window_duration_seconds":   float(window_secs),
            "events_per_minute":         events_per_minute,

            # Burst characteristics
            "burst_factor":              float(burst_factor),
            "per_minute_stdev":          float(stdev_per_min),
            "active_minute_count":       float(len(per_minute)),

            # Time-of-day bias
            "off_hours_ratio":           off_hours / n,
            "night_hours_ratio":         night_hours / n,
            "weekend_ratio":             weekend / n,

            # Inter-event timing (beaconing)
            "inter_event_interval_mean": float(mean_int),
            "inter_event_interval_cv":   float(cv_int),
            "inter_event_interval_min":  float(min_int),
            "inter_event_interval_max":  float(max_int),
        }

    def _empty(self) -> dict[str, float]:
        return {k: 0.0 for k in [
            "total_event_count", "window_duration_seconds", "events_per_minute",
            "burst_factor", "per_minute_stdev", "active_minute_count",
            "off_hours_ratio", "night_hours_ratio", "weekend_ratio",
            "inter_event_interval_mean", "inter_event_interval_cv",
            "inter_event_interval_min", "inter_event_interval_max",
        ]}
