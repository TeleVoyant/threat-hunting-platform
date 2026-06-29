"""
Retrain contamination guard: operator quarantine + false-positive verdict.

Verifies training/scheduler.py::_filter_detected_entities:
  - operator-quarantined entities are excluded from the benign pool
  - a high-confidence alert marked false_positive does NOT exclude its entity
  - a high-confidence alert with no verdict DOES auto-exclude its entity
  - >30% contamination aborts the cycle (returns None, None)

Run:  PYTHONPATH=. python tests/test_retrain_quarantine.py
"""

import types

from training.scheduler import AutoRetrainScheduler


class _StubAlertStore:
    def __init__(self, alerts, quarantine):
        self._alerts, self._q = alerts, quarantine

    def query_alerts(self, hours=24, limit=1000):
        return self._alerts

    def list_quarantine(self, active_only=True):
        return self._q


def _sched(alerts, quarantine):
    s = types.SimpleNamespace()
    s.app = types.SimpleNamespace(
        state=types.SimpleNamespace(alert_store=_StubAlertStore(alerts, quarantine)))
    s.benign_window_hours = 24
    s.min_benign_samples = 2
    s.last_status = None
    s.last_result = None
    s.last_excluded = {}
    return s


def _ev(host, user=""):
    return types.SimpleNamespace(hostname=host, user=user)


def _alert(entity, conf=0.9, verdict=None):
    return {"overall_confidence": conf, "verdict": verdict,
            "detections": [{"source_entity": entity}]}


def _hosts(labeled):
    return {e.hostname for (e, _lbl) in labeled}


def test_quarantine_excludes():
    s = _sched(alerts=[], quarantine=[{"entity": "HOST-Q"}])
    raw = [_ev("HOST-Q")] + [_ev(f"OK{i}") for i in range(6)]
    labeled, _src = AutoRetrainScheduler._filter_detected_entities(s, raw, [], "r1", None)
    hosts = _hosts(labeled)
    assert "HOST-Q" not in hosts, ("quarantined entity must be excluded", hosts)
    assert {f"OK{i}" for i in range(6)} <= hosts, hosts
    assert s.last_excluded["quarantined"] == ["HOST-Q"], s.last_excluded
    print("PASS test_quarantine_excludes")


def test_false_positive_rescues():
    s = _sched(alerts=[_alert("HOST-FP", verdict="false_positive")], quarantine=[])
    raw = [_ev("HOST-FP")] + [_ev(f"OK{i}") for i in range(6)]
    labeled, _src = AutoRetrainScheduler._filter_detected_entities(s, raw, [], "r2", None)
    assert "HOST-FP" in _hosts(labeled), "false-positive entity must stay in the pool"
    assert s.last_excluded["auto"] == [], s.last_excluded
    print("PASS test_false_positive_rescues")


def test_auto_excludes_unverdicted():
    s = _sched(alerts=[_alert("HOST-BAD", verdict=None)], quarantine=[])
    raw = [_ev("HOST-BAD")] + [_ev(f"OK{i}") for i in range(6)]
    labeled, _src = AutoRetrainScheduler._filter_detected_entities(s, raw, [], "r3", None)
    assert "HOST-BAD" not in _hosts(labeled), "high-confidence alert must auto-exclude"
    assert s.last_excluded["auto"] == ["HOST-BAD"], s.last_excluded
    print("PASS test_auto_excludes_unverdicted")


def test_over_30pct_skips():
    s = _sched(alerts=[_alert("BAD")], quarantine=[])
    raw = [_ev("BAD") for _ in range(5)] + [_ev("OK") for _ in range(5)]  # 50% contaminated
    labeled, src = AutoRetrainScheduler._filter_detected_entities(s, raw, [], "r4", None)
    assert labeled is None and src is None, "over-30% contamination must abort"
    assert s.last_status.startswith("skipped"), s.last_status
    print("PASS test_over_30pct_skips")


if __name__ == "__main__":
    test_quarantine_excludes()
    test_false_positive_rescues()
    test_auto_excludes_unverdicted()
    test_over_30pct_skips()
    print("ALL RETRAIN QUARANTINE TESTS PASSED")
