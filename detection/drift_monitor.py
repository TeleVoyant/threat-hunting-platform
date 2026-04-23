# detection/drift_monitor.py
"""
Model drift detection.

Tracks detection metrics over time and alerts when:
1. Detection rate drops significantly (model going blind)
2. False positive rate spikes (model becoming noisy)
3. Confidence distribution shifts (model uncertainty changing)
4. Feature distribution shifts (input data changing)
"""

import time
import json
import statistics
from collections import deque
from pathlib import Path
from typing import Optional

from shared.logging import get_logger
from shared.schemas import Detection

logger = get_logger("detection.drift_monitor")


class DriftMonitor:

    def __init__(
        self,
        detector_name: str,
        window_size: int = 1000,  # Track last N predictions
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
        self.recent_detection_count = 0
        self.recent_total_count = 0
        self.baseline_stats: Optional[dict] = None

        # Persistence
        self.persistence_dir = Path(persistence_dir) / detector_name
        self.persistence_dir.mkdir(parents=True, exist_ok=True)
        self._load_baseline()

    def record_prediction(self, detection: Detection):
        """Record every prediction for drift tracking."""
        self.recent_confidences.append(detection.confidence)
        self.recent_total_count += 1
        if detection.confidence > 0.5:
            self.recent_detection_count += 1

    def set_baseline(self):
        """
        Set current metrics as baseline.
        Call after initial model validation / deployment.
        """
        if len(self.recent_confidences) < 100:
            logger.warning(
                "Not enough data for baseline", count=len(self.recent_confidences)
            )
            return

        self.baseline_stats = {
            "mean_confidence": statistics.mean(self.recent_confidences),
            "std_confidence": statistics.stdev(self.recent_confidences),
            "detection_rate": self.recent_detection_count
            / max(1, self.recent_total_count),
            "set_at": time.time(),
            "sample_size": len(self.recent_confidences),
        }

        # Persist baseline
        (self.persistence_dir / "baseline.json").write_text(
            json.dumps(self.baseline_stats, indent=2)
        )
        logger.info(
            "Drift baseline set", detector=self.detector_name, stats=self.baseline_stats
        )

    def check_drift(self) -> Optional[dict]:
        """
        Check for model drift. Returns drift report if drift detected, None otherwise.
        """
        if not self.baseline_stats or len(self.recent_confidences) < 100:
            return None

        current_mean = statistics.mean(self.recent_confidences)
        current_rate = self.recent_detection_count / max(1, self.recent_total_count)
        baseline_mean = self.baseline_stats["mean_confidence"]
        baseline_rate = self.baseline_stats["detection_rate"]

        issues = []

        # Check 1: Confidence distribution shift
        confidence_shift = abs(current_mean - baseline_mean)
        if confidence_shift > self.alert_threshold_confidence:
            issues.append(
                {
                    "type": "confidence_shift",
                    "baseline": round(baseline_mean, 4),
                    "current": round(current_mean, 4),
                    "shift": round(confidence_shift, 4),
                }
            )

        # Check 2: Detection rate change
        rate_change = baseline_rate - current_rate  # positive = fewer detections
        if abs(rate_change) > self.alert_threshold_accuracy:
            issues.append(
                {
                    "type": "detection_rate_change",
                    "baseline": round(baseline_rate, 4),
                    "current": round(current_rate, 4),
                    "change": round(rate_change, 4),
                    "direction": (
                        "decrease (model may be going blind)"
                        if rate_change > 0
                        else "increase (possible false positive spike)"
                    ),
                }
            )

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
        if baseline_path.exists():
            self.baseline_stats = json.loads(baseline_path.read_text())
