"""
Auto-retrain scheduler — keeps the XGBoost detectors fresh against the fleet's
live telemetry distribution.

Every `interval_seconds` it:
  1. Pulls the last `benign_window_hours` of normalized events via the existing
     WazuhConnector and tags them label=0 (working assumption: nothing the
     fleet did during that window was attack traffic — same assumption every
     other SOC training pipeline makes for un-flagged data).
  2. Generates a fresh synthetic malicious cohort sized to ~`mal_pct` of the
     final dataset, drawn from `training.synthetic.generate_dataset` with
     lateral + DNS attacks.
  3. Runs `training.trainer.train_model` for each detector against the
     combined dataset.
  4. Persists the new versions as `status="staged"` so detection keeps using
     the existing active version until an admin clicks Promote.
  5. Audit-logs every cycle (start, completed, failed, skipped).

The `asyncio.Lock` prevents overlapping cycles if a previous run hasn't
finished by the time the next interval fires. The loop catches every
exception so a single bad cycle never kills the scheduler — failures land
in the audit trail and surface on /diag/services.

This is *not* an online learner. Each cycle trains from scratch on the
current 24h window; the new model is independent of the previous version
(by design — simplifies rollback and audit).
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Optional

from shared.logging import get_logger

logger = get_logger("training.scheduler")


# (name, grouping, window_minutes) — must match training/train_models.py:224,236
# lateral_movement groups per (host,user) so credential-centric features see
# one credential's activity across hosts. dns_exfiltration groups per host
# because DNS events rarely carry user attribution.
_DETECTORS = (
    ("lateral_movement",  "hostname_user", 5),
    ("dns_exfiltration",  "hostname",      5),
)


class AutoRetrainScheduler:

    def __init__(
        self,
        app,
        *,
        # Cycle cadence -- defaults to 24 h. The retrain pass is memory-heavy
        # (xgboost + synthetic-data generator) and OOM-kills a thin api
        # container if it runs aggressively. Operators can change cadence
        # at runtime via /admin/retrain/interval (dashboard at /dashboard/
        # retrain -> "Change cadence"). Changes are IN-MEMORY only and
        # revert to this default on container restart -- the operator
        # explicitly chose ephemeral semantics so the default is always
        # honoured after restart and operator overrides are deliberate
        # short-term decisions during active iteration.
        interval_seconds: int = 86400,       # 24 h
        # First-cycle delay after start() -- kept long so the api can serve
        # dashboard requests for an hour before competing with the retrain
        # process for RAM. Earlier 60 s default contributed to startup-time
        # OOM crashes during the first scheduled tick.
        initial_delay_seconds: int = 3600,   # 1 h
        benign_window_hours: int = 24,
        synth_hosts: int = 3,
        lateral_attacks_per_day: int = 10,
        dns_attacks_per_day: int = 8,
        min_benign_samples: int = 20,
        num_boost_round: int = 200,
    ):
        self.app = app
        self.interval_seconds = max(60, int(interval_seconds))
        self.initial_delay_seconds = max(0, int(initial_delay_seconds))
        self.benign_window_hours = benign_window_hours
        self.synth_hosts = synth_hosts
        self.lateral_attacks_per_day = lateral_attacks_per_day
        self.dns_attacks_per_day = dns_attacks_per_day
        self.min_benign_samples = min_benign_samples
        self.num_boost_round = num_boost_round

        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        # Wakes the loop early when the interval is changed or run_now() is
        # invoked -- avoids waiting out the rest of a long sleep before the
        # new cadence takes effect.
        self._interval_changed: Optional[asyncio.Event] = None
        self.started_at: Optional[float] = None
        self.last_run_at: Optional[float] = None
        self.last_status: str = "never_ran"
        self.last_result: Optional[dict[str, Any]] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        import time as _time
        self.started_at = _time.time()
        self._interval_changed = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="auto-retrain")
        logger.info(
            "AutoRetrainScheduler started",
            interval_s=self.interval_seconds,
            initial_delay_s=self.initial_delay_seconds,
            benign_window_h=self.benign_window_hours,
        )

    def set_interval(self, seconds: int) -> int:
        """Change the cadence at runtime. Floors at 60s, ceilings at 24h.

        IN-MEMORY ONLY -- a container restart reverts to the constructor
        default (24h). This is intentional per the 2026-06-02 decision:
        the dashboard cadence is for short-term operator overrides during
        active iteration, not durable configuration. To change the durable
        default, edit RETRAIN_INTERVAL_SECONDS in .env and restart.

        Wakes the sleeping loop so the new value takes effect on the next
        tick instead of after the previous (potentially much longer) sleep
        elapses. Returns the value actually set after clamping.
        """
        clamped = max(60, min(int(seconds), 86400))
        self.interval_seconds = clamped
        if self._interval_changed:
            self._interval_changed.set()
        logger.info("AutoRetrain interval changed", new_interval_s=clamped)
        return clamped

    def trigger_now(self) -> None:
        """Run one cycle on the next tick (instead of waiting for the timer)."""
        if self._interval_changed:
            self._interval_changed.set()

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("AutoRetrainScheduler stopped")

    async def _loop(self) -> None:
        # Initial delay (default 1 h) before the first cycle. Two reasons:
        #   1) The rest of the platform finishes wiring (DetectionSubscriber,
        #      AlertSubscriber, etc.) before the first retrain touches the
        #      same model directory.
        #   2) Avoid the cold-start OOM where an api container with a tight
        #      memory limit competes with the retrain pipeline for RAM in
        #      the first minute of life. The retrain pulls in xgboost +
        #      synthetic data and routinely needs ~1-2 GB transiently.
        # Operators who want the old "kick a cycle a minute after boot"
        # behaviour can set RETRAIN_INITIAL_DELAY_SECONDS=60 in the env.
        # trigger_now() / set_interval() still wake the sleep early.
        await self._sleep_interruptible(self.initial_delay_seconds)
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("Retrain cycle crashed", error=str(e))
                self.last_status = f"crashed: {e}"
            await self._sleep_interruptible(self.interval_seconds)

    async def _sleep_interruptible(self, seconds: int) -> None:
        """Sleep, but wake early if `_interval_changed` is set (manual trigger
        or admin set_interval). Clears the flag after waking."""
        if self._interval_changed is None:
            await asyncio.sleep(seconds)
            return
        try:
            await asyncio.wait_for(self._interval_changed.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass
        finally:
            self._interval_changed.clear()

    # ── Cycle ──────────────────────────────────────────────────────────────

    async def run_once(self) -> dict[str, Any]:
        """Run one retrain cycle. Returns a result dict either way."""
        if self._lock.locked():
            logger.info("Retrain still in progress — skipping this tick")
            self.last_status = "skipped:overlap"
            return {"status": self.last_status}

        async with self._lock:
            return await self._cycle()

    async def _cycle(self) -> dict[str, Any]:
        started = time.time()
        self.last_run_at = started
        run_id = f"r-{int(started)}"
        audit = getattr(self.app.state, "audit_trail", None)
        if audit:
            audit.log(action="retrain.cycle.start", actor="scheduler",
                      target=run_id, details={
                          "interval_s": self.interval_seconds,
                          "benign_window_h": self.benign_window_hours,
                      })

        # 1. Gather labeled events ────────────────────────────────────────
        try:
            benign = await self._collect_benign_events()
        except Exception as e:
            logger.warning("Benign collection failed — falling back to synthetic-only", error=str(e))
            benign = []
        synth_mixed = self._generate_synthetic()
        # Split synth into benign and malicious for clarity, then build the
        # final dataset by combining real-benign + synth-benign + synth-malicious.
        synth_benign    = [(e, 0) for e, lbl in synth_mixed if lbl == 0]
        synth_malicious = [(e, 1) for e, lbl in synth_mixed if lbl == 1]

        if len(benign) < self.min_benign_samples:
            logger.info("Insufficient real benign events — supplementing with synthetic benign",
                        real=len(benign), synth=len(synth_benign))
            labeled = benign + synth_benign + synth_malicious
            data_source = "hybrid_with_synth_benign"
        else:
            labeled = [(e, 0) for e in benign] + synth_malicious
            data_source = "real_benign_plus_synth_malicious"

        pos = sum(1 for _, lbl in labeled if lbl == 1)
        logger.info("Retrain dataset assembled",
                    run_id=run_id, total=len(labeled), positives=pos,
                    data_source=data_source)

        if pos == 0 or len(labeled) < 50:
            self.last_status = "skipped:insufficient_data"
            result = {"run_id": run_id, "status": self.last_status,
                      "total": len(labeled), "positives": pos}
            self.last_result = result
            if audit:
                audit.log(action="retrain.cycle.skipped", actor="scheduler",
                          target=run_id, details=result)
            return result

        # 2. Train each detector ──────────────────────────────────────────
        versions = {}
        errors = {}
        try:
            store = self._model_store()
            pipeline = getattr(self.app.state, "_feature_pipeline", None) or self._build_pipeline()
        except Exception as e:
            self.last_status = f"setup_failed:{e}"
            if audit:
                audit.log(action="retrain.cycle.failed", actor="scheduler",
                          target=run_id, details={"error": str(e)})
            return {"run_id": run_id, "status": self.last_status}

        from training.trainer import train_model

        # Training is CPU-heavy and synchronous — push to a thread so the
        # event loop (detection + dashboard) keeps serving.
        loop = asyncio.get_running_loop()
        for name, grouping, window_minutes in _DETECTORS:
            try:
                metrics = await loop.run_in_executor(
                    None,
                    lambda n=name, g=grouping, w=window_minutes: train_model(
                        labeled_events=labeled,
                        pipeline=pipeline,
                        model_name=n,
                        model_store=store,
                        window_minutes=w,
                        grouping=g,
                        num_boost_round=self.num_boost_round,
                        status="staged",
                    ),
                )
                versions[name] = {
                    "version": metrics.get("version"),
                    "auc": metrics.get("eval_auc"),
                    "logloss": metrics.get("eval_logloss"),
                    "saved_at": metrics.get("saved_at"),
                }
            except Exception as e:
                logger.error("Retrain failed", detector=name, error=str(e))
                errors[name] = str(e)

        duration = round(time.time() - started, 2)
        result = {
            "run_id": run_id,
            "status": "completed" if not errors else "partial",
            "duration_s": duration,
            "data_source": data_source,
            "total_samples": len(labeled),
            "positives": pos,
            "versions": versions,
            "errors": errors,
            "note": "New versions are staged — admin must promote via POST /models/{name}/versions/{version}/promote",
        }
        self.last_status = result["status"]
        self.last_result = result
        if audit:
            audit.log(action="retrain.cycle.completed", actor="scheduler",
                      target=run_id, details={
                          "duration_s": duration,
                          "data_source": data_source,
                          "versions": {k: v.get("version") for k, v in versions.items()},
                          "errors": errors,
                      })
        return result

    # ── Helpers ────────────────────────────────────────────────────────────

    def _model_store(self):
        from detection.model_store import ModelStore
        signing_key = os.environ.get("MODEL_SIGNING_KEY", "")
        return ModelStore(base_dir="detection/models", signing_key=signing_key)

    def _build_pipeline(self):
        # Fallback if the app didn't expose its pipeline on state.
        from features.pipeline import FeaturePipeline
        from features.dns_features import DnsFeatureExtractor
        from features.auth_features import AuthFeatureExtractor
        from features.process_features import ProcessFeatureExtractor
        from features.network_features import NetworkFeatureExtractor
        from features.temporal_features import TemporalFeatureExtractor
        from features.behavioral_features import BehavioralFeatureExtractor
        p = FeaturePipeline()
        for ex in (DnsFeatureExtractor(), AuthFeatureExtractor(),
                   ProcessFeatureExtractor(), NetworkFeatureExtractor(),
                   TemporalFeatureExtractor(), BehavioralFeatureExtractor()):
            p.register_extractor(ex)
        return p

    async def _collect_benign_events(self) -> list:
        """Pull the last `benign_window_hours` of events via Wazuh and normalize."""
        wazuh = getattr(self.app.state, "wazuh", None)
        preprocessor = getattr(self.app.state, "_preprocessor", None)
        if not wazuh:
            return []
        try:
            raw = await wazuh.fetch_recent_events(
                window_minutes=self.benign_window_hours * 60
            )
        except Exception as e:
            logger.warning("Wazuh fetch raised during retrain", error=str(e))
            return []
        if not raw:
            return []
        if preprocessor is None:
            # Build a throwaway one — same shape as api/main.py uses.
            from ingestion.preprocessor import EventPreprocessor
            from ingestion.dead_letter import DeadLetterQueue
            preprocessor = EventPreprocessor(
                dead_letter=DeadLetterQueue(storage_dir="data/dead_letter"))
        return preprocessor.normalize_batch(raw)

    def _generate_synthetic(self) -> list:
        from training.synthetic import generate_dataset
        # 24h synthetic background gives the model enough negatives to learn
        # a separating boundary against the malicious bursts.
        return generate_dataset(
            duration_hours=24,
            hosts=[f"SYNTH-{i:03d}" for i in range(1, self.synth_hosts + 1)],
            lateral_attacks_per_day=self.lateral_attacks_per_day,
            dns_attacks_per_day=self.dns_attacks_per_day,
            seed=random.randint(0, 2**31 - 1),
        )

    # ── Public surface ─────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        # Best-effort projection of the next-cycle timestamp. After the first
        # run, the loop sleeps for interval_seconds between cycles, so
        # last_run_at + interval. Before the first run, the loop is in its
        # initial_delay_seconds window so started_at + initial_delay.
        next_run_at: Optional[float] = None
        if self.last_run_at is not None:
            next_run_at = self.last_run_at + self.interval_seconds
        elif self.started_at is not None:
            next_run_at = self.started_at + self.initial_delay_seconds

        return {
            "running": bool(self._task and not self._task.done()),
            "interval_seconds": self.interval_seconds,
            "initial_delay_seconds": self.initial_delay_seconds,
            "started_at": self.started_at,
            "started_iso": (
                datetime.fromtimestamp(self.started_at, tz=timezone.utc).isoformat()
                if self.started_at else None
            ),
            "last_run_at": self.last_run_at,
            "last_run_iso": (
                datetime.fromtimestamp(self.last_run_at, tz=timezone.utc).isoformat()
                if self.last_run_at else None
            ),
            "next_run_at": next_run_at,
            "next_run_iso": (
                datetime.fromtimestamp(next_run_at, tz=timezone.utc).isoformat()
                if next_run_at else None
            ),
            "last_status": self.last_status,
            "last_result": self.last_result,
        }
