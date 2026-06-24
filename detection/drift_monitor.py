# detection/drift_monitor.py
"""
Model drift detection.

Tracks per-detector signals over time and reports drift when any of:
1. Confidence-distribution shift (mean Δ vs baseline)               (w-existing)
2. Detection-rate change                                            (existing)
3. Population Stability Index (PSI) on confidence histogram > 0.20  (w-new)

PSI bands (Allianz / standard practice):
    PSI < 0.10 → stable
    0.10 ≤ PSI < 0.20 → minor shift
    PSI ≥ 0.20 → significant shift (we report)

Per-hour baseline (y): we keep 24 baselines so 03:00 traffic is compared
against historic 03:00 traffic, not against whatever happened to be in the
rolling window when set_baseline() was called. Falls back to the global
baseline when an hour's bucket has fewer than 100 samples.
"""

import json
import math
import statistics
import time
from collections import deque
from pathlib import Path
from typing import Optional

from shared.logging import get_logger
from shared.schemas import Detection

logger = get_logger("detection.drift_monitor")


_NUM_BUCKETS = 10  # confidence histogram bins [0.0,0.1) … [0.9,1.0]
_PSI_REPORT_THRESHOLD = 0.20


def _histogram(values: list[float], n_buckets: int = _NUM_BUCKETS) -> list[float]:
    """Return probability mass per bucket — never zero (Laplace-smoothed)."""
    if not values:
        return [1.0 / n_buckets] * n_buckets
    counts = [0] * n_buckets
    for v in values:
        # Clamp to [0, 1) so v=1.0 lands in the last bucket.
        idx = min(int(max(0.0, min(v, 0.999)) * n_buckets), n_buckets - 1)
        counts[idx] += 1
    total = float(sum(counts) + n_buckets)  # +n_buckets for smoothing
    return [(c + 1) / total for c in counts]


def _psi(baseline: list[float], current: list[float]) -> float:
    """Population Stability Index between two distributions."""
    if len(baseline) != len(current):
        return 0.0
    return sum(
        (c - b) * math.log(c / b) for b, c in zip(baseline, current)
    )


class DriftMonitor:

    def __init__(
        self,
        detector_name: str,
        window_size: int = 1000,
        alert_on_accuracy_drop: float = 0.10,
        alert_on_confidence_shift: float = 0.15,
        persistence_dir: str = "/data/drift",
    ):
        self.detector_name = detector_name
        self.window_size = window_size
        self.alert_threshold_accuracy = alert_on_accuracy_drop
        self.alert_threshold_confidence = alert_on_confidence_shift

        # Rolling windows
        self.recent_confidences: deque = deque(maxlen=window_size)
        # Per-hour rolling buffers for the hour-of-day baseline (y).
        # Each hour gets its own deque, capped at window_size/8 so 24 buckets
        # don't exceed ~3x memory of the global buffer.
        self._hourly_buffers: dict[int, deque] = {
            h: deque(maxlen=max(125, window_size // 8)) for h in range(24)
        }
        self.recent_detection_count = 0
        self.recent_total_count = 0
        self.baseline_stats: Optional[dict] = None
        # Per-hour baselines: {hour: {"hist": [...], "mean": float, "n": int}}
        self.hourly_baselines: dict[int, dict] = {}

        self.persistence_dir = Path(persistence_dir) / detector_name
        self.persistence_dir.mkdir(parents=True, exist_ok=True)
        self._load_baseline()

    def record_prediction(self, detection: Detection):
        """Record every prediction for drift tracking."""
        c = float(detection.confidence)
        self.recent_confidences.append(c)
        self._hourly_buffers[time.gmtime().tm_hour].append(c)
        self.recent_total_count += 1
        if c > 0.5:
            self.recent_detection_count += 1
        # Auto-initialize baseline the first time half the rolling window fills.
        # Without this, drift detection is silently disabled in any deployment
        # where an admin never calls POST /admin/drift/baseline manually.
        # set_baseline() has its own >= 100 sample guard so early triggering is safe.
        # The check fires at most once — once baseline_stats is set it stays set.
        if self.baseline_stats is None and len(self.recent_confidences) >= self.window_size // 2:
            self.set_baseline()

    def set_baseline(self):
        """Snapshot current metrics as baseline (global + per-hour)."""
        if len(self.recent_confidences) < 100:
            logger.warning(
                "Not enough data for baseline", count=len(self.recent_confidences)
            )
            return

        confs = list(self.recent_confidences)
        self.baseline_stats = {
            "mean_confidence": statistics.mean(confs),
            "std_confidence":  statistics.stdev(confs),
            "detection_rate":  self.recent_detection_count / max(1, self.recent_total_count),
            "hist":            _histogram(confs),
            "set_at":          time.time(),
            "sample_size":     len(confs),
        }

        # Per-hour baselines (y) — only set buckets with enough samples.
        self.hourly_baselines = {}
        for hour, buf in self._hourly_buffers.items():
            if len(buf) < 50:
                continue
            vals = list(buf)
            self.hourly_baselines[hour] = {
                "hist": _histogram(vals),
                "mean": statistics.mean(vals),
                "n":    len(vals),
            }

        payload = {
            "global": self.baseline_stats,
            "hourly": self.hourly_baselines,
        }
        (self.persistence_dir / "baseline.json").write_text(json.dumps(payload, indent=2))
        logger.info("Drift baseline set",
                    detector=self.detector_name,
                    samples=len(confs),
                    hourly_buckets=len(self.hourly_baselines))

    def check_drift(self) -> Optional[dict]:
        if not self.baseline_stats or len(self.recent_confidences) < 100:
            return None

        current_confs = list(self.recent_confidences)
        current_mean = statistics.mean(current_confs)
        current_rate = self.recent_detection_count / max(1, self.recent_total_count)
        current_hist = _histogram(current_confs)

        # Hour-of-day baseline takes precedence when available (y).
        hour = time.gmtime().tm_hour
        baseline_mean = self.baseline_stats["mean_confidence"]
        baseline_rate = self.baseline_stats["detection_rate"]
        baseline_hist = self.baseline_stats.get("hist") or _histogram([baseline_mean])
        hourly = self.hourly_baselines.get(hour)
        if hourly:
            baseline_mean = hourly["mean"]
            baseline_hist = hourly["hist"]

        issues = []

        confidence_shift = abs(current_mean - baseline_mean)
        if confidence_shift > self.alert_threshold_confidence:
            issues.append({
                "type": "confidence_shift",
                "baseline": round(baseline_mean, 4),
                "current":  round(current_mean, 4),
                "shift":    round(confidence_shift, 4),
            })

        rate_change = baseline_rate - current_rate
        if abs(rate_change) > self.alert_threshold_accuracy:
            issues.append({
                "type": "detection_rate_change",
                "baseline": round(baseline_rate, 4),
                "current":  round(current_rate, 4),
                "change":   round(rate_change, 4),
                "direction": (
                    "decrease (model may be going blind)" if rate_change > 0
                    else "increase (possible false positive spike)"
                ),
            })

        # PSI on confidence histogram (w) — catches shape shifts that mean
        # comparison misses (e.g., bimodal split same-mean as baseline).
        psi = _psi(baseline_hist, current_hist)
        if psi >= _PSI_REPORT_THRESHOLD:
            issues.append({
                "type": "psi_shift",
                "psi":  round(psi, 4),
                "scope": "hour-of-day" if hourly else "global",
            })

        if issues:
            report = {
                "detector": self.detector_name,
                "timestamp": time.time(),
                "issues": issues,
                "recommendation": "Consider retraining with recent data",
            }
            logger.warning("MODEL DRIFT DETECTED", **report)
            return report
        return None

    def _load_baseline(self):
        baseline_path = self.persistence_dir / "baseline.json"
        if not baseline_path.exists():
            return
        try:
            payload = json.loads(baseline_path.read_text())
        except Exception as e:
            logger.warning("Failed to load drift baseline",
                           detector=self.detector_name, error=str(e))
            return
        # New layout: {"global": {...}, "hourly": {...}}; old layout: flat dict.
        if isinstance(payload, dict) and "global" in payload:
            self.baseline_stats = payload.get("global")
            self.hourly_baselines = {
                int(k): v for k, v in (payload.get("hourly") or {}).items()
            }
        else:
            self.baseline_stats = payload
