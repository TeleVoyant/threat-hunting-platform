# api/routes/models.py
"""
Model lifecycle endpoints.

  GET   /models                             — list all models + current version
  GET   /models/{name}/versions             — list all versions of a model
  POST  /models/{name}/retrain              — kick off a retrain (background)
  POST  /models/{name}/rollback/{version}   — switch `latest` symlink to a prior version

All endpoints require auth. Reads need `read_detections`; mutations need
`retrain_models` (currently ADMIN only). Every mutation hits the AuditTrail.
"""

import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from api.middleware import require_permission
from detection.model_store import ModelStore, SecurityError
from detection.registry import registry
from shared.logging import get_logger
from shared.security import User

logger = get_logger("api.routes.models")
router = APIRouter(prefix="/models", tags=["models"])


def _store() -> ModelStore:
    return ModelStore(
        base_dir=os.environ.get("MODEL_STORE_DIR", "detection/models"),
        signing_key=os.environ.get("MODEL_SIGNING_KEY", ""),
    )


def _audit(request: Request):
    return request.app.state.audit_trail


_KNOWN_MODELS = {"lateral_movement", "dns_exfiltration"}


# ── List + status ──────────────────────────────────────────────────────────

@router.get("")
async def list_models(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """List every known model and its currently-loaded version."""
    store = _store()
    out = []
    for name in _KNOWN_MODELS:
        latest_path = store.base_dir / name / "latest"
        current_version = None
        if latest_path.exists() and latest_path.is_symlink():
            current_version = latest_path.resolve().name
        try:
            versions = store.list_versions(name)
        except FileNotFoundError:
            versions = []
        out.append({
            "name": name,
            "current_version": current_version,
            "version_count": len(versions),
            "registered": name in registry.list_names(),
        })
    return {"models": out}


@router.get("/{name}/versions")
async def list_versions(
    name: str,
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """All saved versions for a model with timestamps and metrics."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    try:
        versions = _store().list_versions(name)
    except FileNotFoundError:
        return {"name": name, "versions": []}
    # Strip verbose per-feature arrays from each manifest. The /versions
    # endpoint feeds dropdowns + summary tiles; the dashboard never needs
    # the full schema. Callers wanting the raw manifest can hit the file.
    for v in versions:
        meta = v.get("metadata", {})
        meta.pop("feature_names", None)
        meta.pop("feature_min", None)
        meta.pop("feature_max", None)
    return {"name": name, "versions": versions}


# ── Global feature importance ─────────────────────────────────────────────

# Valid XGBoost importance types (booster.get_score):
#   "weight"      — number of times a feature appears in trees
#   "gain"        — average reduction in loss when the feature is used (default)
#   "cover"       — average coverage (samples affected) per split
#   "total_gain"  — sum of gain across all uses
#   "total_cover" — sum of cover across all uses
_IMPORTANCE_TYPES = {"weight", "gain", "cover", "total_gain", "total_cover"}


@router.get("/{name}/importance")
async def feature_importance(
    name: str,
    request: Request,
    importance_type: str = "gain",
    top_k: int = 20,
    user: User = Depends(require_permission("read_detections")),
):
    """
    Global feature importance for the currently-loaded model.

    Complements per-alert SHAP (`Detection.contributing_features`) by
    answering "which features does the model rely on OVERALL?" rather than
    "which features drove THIS specific alert?". Use for dashboard summary
    cards and Chapter 7 model-analysis figures.

    Falls back to loading the model from disk via ModelStore if the
    detector hasn't been registered (e.g., in API-only mode).
    """
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    if importance_type not in _IMPORTANCE_TYPES:
        raise HTTPException(
            400,
            f"importance_type must be one of {sorted(_IMPORTANCE_TYPES)}",
        )

    booster = None
    if name in registry.list_names():
        det = registry.get(name)
        booster = getattr(det, "model", None)

    if booster is None:
        # Detector not registered or model not loaded — try loading directly
        store = _store()
        latest_path = store.base_dir / name / "latest"
        if not latest_path.exists():
            raise HTTPException(404, f"No model loaded or saved for {name}")
        try:
            booster = store.load_from_path(str(latest_path))
        except (FileNotFoundError, SecurityError) as e:
            raise HTTPException(503, f"Could not load model: {e}")

    raw = booster.get_score(importance_type=importance_type)
    # Sort descending and take top_k. XGBoost returns {feature_name: score}
    ranked = sorted(raw.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
    total = sum(raw.values()) or 1.0   # for normalisation
    features = [
        {
            "feature":          fname,
            "score":            float(score),
            "normalized_share": float(score) / total,
        }
        for fname, score in ranked
    ]
    return {
        "model_name":       name,
        "importance_type":  importance_type,
        "feature_count":    len(raw),
        "top_k":            top_k,
        "features":         features,
    }


# ── Retrain ────────────────────────────────────────────────────────────────

class RetrainRequest(BaseModel):
    hours:           int  = Field(24,  ge=1,   le=720, description="Synthetic data window")
    hosts:           int  = Field(5,   ge=1,   le=50)
    lateral_attacks: int  = Field(5,   ge=0,   le=200, description="per day")
    dns_attacks:     int  = Field(5,   ge=0,   le=200, description="per day")
    seed:            int  = Field(42,  ge=0)
    num_boost_round: int  = Field(200, ge=10,  le=2000)
    window_minutes:  int  = Field(5,   ge=1,   le=60)
    hot_reload:      bool = Field(True,  description="Reload detector with new model on success")


@router.post("/{name}/retrain", status_code=202)
async def retrain_model(
    name: str,
    body: RetrainRequest,
    background: BackgroundTasks,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """
    Kick off a model retrain in a background task. Returns immediately with
    202; check progress via the audit log or version listing.

    Synthetic-only for now — accepting `--from-jsonl` real data in the
    request payload is the obvious follow-up.
    """
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")

    _audit(request).log(
        action="model.retrain.requested",
        actor=user.username,
        target=name,
        details=body.model_dump(),
    )
    background.add_task(_run_retrain, name, body, user.username, request.app)
    return {
        "status":      "started",
        "model":       name,
        "requested_by": user.username,
        "params":      body.model_dump(),
    }


def _run_retrain(name: str, body: RetrainRequest, actor: str, app) -> None:
    """Background task: train, save through ModelStore, optionally hot-reload."""
    try:
        from training.synthetic   import generate_dataset
        from training.train_models import build_pipeline
        from training.trainer     import train_model

        store = _store()
        labeled = generate_dataset(
            duration_hours=body.hours,
            hosts=[f"LAPTOP-{i:03d}" for i in range(1, body.hosts + 1)],
            lateral_attacks_per_day=body.lateral_attacks,
            dns_attacks_per_day=body.dns_attacks,
            seed=body.seed,
        )
        pipeline = build_pipeline()
        grouping = "hostname_user" if name == "lateral_movement" else "hostname"
        metrics = train_model(
            labeled_events=labeled, pipeline=pipeline,
            model_store=store, model_name=name,
            window_minutes=body.window_minutes,
            grouping=grouping, num_boost_round=body.num_boost_round,
        )

        app.state.audit_trail.log(
            action="model.retrain.succeeded",
            actor=actor,
            target=name,
            details={
                "version":      metrics.get("version"),
                "saved_at":     metrics.get("saved_at"),
                "eval_auc":     metrics.get("eval_auc"),
                "eval_logloss": metrics.get("eval_logloss"),
                "n_train":      metrics.get("n_train"),
            },
        )

        # Hot-reload via the existing registry method
        if body.hot_reload and name in registry.list_names():
            try:
                registry.hot_reload(name, str(store.base_dir / name / "latest"))
                app.state.audit_trail.log(
                    action="model.hot_reload",
                    actor=actor, target=name,
                    details={"version": metrics.get("version")},
                )
            except Exception as e:
                logger.error("Hot reload failed", name=name, error=str(e))
                app.state.audit_trail.log(
                    action="model.hot_reload.failed",
                    actor=actor, target=name,
                    details={"error": str(e)},
                )

    except Exception as e:
        logger.error("Retrain failed", name=name, error=str(e))
        app.state.audit_trail.log(
            action="model.retrain.failed",
            actor=actor, target=name,
            details={"error": str(e)},
        )


# ── Rollback ───────────────────────────────────────────────────────────────

@router.post("/{name}/rollback/{version}")
async def rollback_model(
    name: str,
    version: str,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Re-point `latest` symlink at a previously-saved version."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    store = _store()
    try:
        store.rollback(name, version)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))

    # Hot-reload after rollback (so the running process picks up the older model)
    try:
        registry.hot_reload(name, str(store.base_dir / name / "latest"))
    except (FileNotFoundError, SecurityError) as e:
        # Rollback succeeded but reload failed — operator must restart
        raise HTTPException(500, f"Rollback completed but hot-reload failed: {e}")

    _audit(request).log(
        action="model.rollback",
        actor=user.username,
        target=name,
        details={"to_version": version},
    )
    return {"status": "rolled_back", "name": name, "to_version": version}


@router.post("/{name}/versions/{version}/promote")
async def promote_version(
    name: str,
    version: str,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Promote a staged version: flip its status to active, archive the
    previously-active version, hot-reload detectors. Used after reviewing a
    retrain produced by the auto-retrain scheduler."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    store = _store()
    try:
        manifest = store.promote(name, version)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))

    try:
        registry.hot_reload(name, str(store.base_dir / name / "latest"))
    except (FileNotFoundError, SecurityError) as e:
        raise HTTPException(500, f"Promoted but hot-reload failed: {e}")

    _audit(request).log(
        action="model.promote",
        actor=user.username,
        target=name,
        details={"version": version},
    )
    return {"status": "promoted", "name": name, "version": version,
            "manifest": manifest}


@router.post("/{name}/versions/{version}/discard")
async def discard_version(
    name: str,
    version: str,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Discard a staged version. Flips status staged -> discarded; files
    stay on disk so the operator can still inspect or undo. Permanent
    removal is via DELETE /{name}/versions/{version} after discard."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    store = _store()
    try:
        manifest = store.discard(name, version)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))

    _audit(request).log(
        action="model.discard",
        actor=user.username,
        target=name,
        details={"version": version},
    )
    return {"status": "discarded", "name": name, "version": version,
            "manifest": manifest}


@router.delete("/{name}/versions/{version}", status_code=204)
async def delete_version(
    name: str,
    version: str,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Permanently delete a discarded or archived version. Refuses active
    (would brick detection) and staged (operator must discard first)."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    store = _store()
    try:
        store.delete(name, version)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))

    _audit(request).log(
        action="model.delete",
        actor=user.username,
        target=name,
        details={"version": version},
    )
    return Response(status_code=204)


class _BulkDeleteRequest(BaseModel):
    versions: list[str] = Field(..., min_length=1, max_length=100)


@router.post("/{name}/versions/bulk-delete")
async def bulk_delete_versions(
    name: str,
    body: _BulkDeleteRequest,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Multi-version delete -- same allow-rules as single delete (only
    discarded or archived). Per-version results returned so the operator
    sees which ones got deleted vs which were blocked. Partial success
    is treated as success at the HTTP level (200), with details in body."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    store = _store()
    deleted: list[str] = []
    failed:  list[dict] = []
    for v in body.versions:
        try:
            store.delete(name, v)
            deleted.append(v)
        except FileNotFoundError as e:
            failed.append({"version": v, "error": f"not found: {e}"})
        except ValueError as e:
            failed.append({"version": v, "error": str(e)})

    _audit(request).log(
        action="model.bulk_delete",
        actor=user.username,
        target=name,
        details={
            "requested":  len(body.versions),
            "deleted":    len(deleted),
            "failed":     len(failed),
            "versions":   body.versions[:20],   # cap for audit log size
        },
    )
    return {"deleted": deleted, "failed": failed,
            "n_deleted": len(deleted), "n_failed": len(failed)}


# ── Drift history (for the dashboard chart) ───────────────────────────────

@router.get("/{name}/drift/history")
async def drift_history(
    name: str,
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """
    Return baseline stats + a chunked moving average of the rolling
    confidence window for the detector. Good enough to drive a sparkline;
    a real history log would need its own persistence story.
    """
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")

    sub = getattr(request.app.state, "detection_subscriber", None)
    if sub is None:
        return {"detector": name, "baseline": None, "points": []}

    # Pull the drift monitor for this detector
    monitor = (getattr(sub, "drift_monitors", {}) or {}).get(name)
    if monitor is None:
        return {"detector": name, "baseline": None, "points": []}

    recents = list(monitor.recent_confidences)
    n_chunks = 20
    points = []
    if recents:
        chunk = max(1, len(recents) // n_chunks)
        for i in range(0, len(recents), chunk):
            window = recents[i:i + chunk]
            if not window:
                continue
            window_sorted = sorted(window)
            p50 = window_sorted[len(window_sorted) // 2]
            p95 = window_sorted[min(len(window_sorted) - 1, int(len(window_sorted) * 0.95))]
            mean = sum(window) / len(window)
            points.append({
                "idx": i, "mean": mean, "p50": p50, "p95": p95,
                "size": len(window),
            })
    return {
        "detector": name,
        "baseline": monitor.baseline_stats,
        "current_count": len(recents),
        "points": points,
    }


# ── Detector thresholds (live-edit, persists to config/detectors.yml) ─────

@router.get("/detectors")
async def list_detectors(
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """List loaded detectors with current threshold."""
    out = []
    for name in registry.list_names():
        det = registry.get(name)
        out.append({
            "name": name,
            "threshold": getattr(det, "threshold", None),
        })
    return {"detectors": out}


class ThresholdUpdate(BaseModel):
    threshold: float = Field(..., ge=0.0, le=1.0)


@router.put("/detectors/{name}/threshold")
async def set_detector_threshold(
    name: str,
    body: ThresholdUpdate,
    request: Request,
    user: User = Depends(require_permission("manage_detectors")),
):
    """
    Update a detector's classification threshold and persist to
    `config/detectors.yml`. The change is applied to the in-memory detector
    immediately so the running pipeline picks it up without restart.
    """
    if name not in registry.list_names():
        raise HTTPException(404, f"Unknown detector: {name}")
    import yaml
    cfg_path = Path(os.environ.get("CONFIG_DIR", "config")) / "detectors.yml"
    data: dict = {}
    if cfg_path.exists():
        data = yaml.safe_load(cfg_path.read_text()) or {}
    data.setdefault("detectors", {}).setdefault(name, {})["threshold"] = float(body.threshold)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(data, default_flow_style=False))

    det = registry.get(name)
    if hasattr(det, "threshold"):
        det.threshold = float(body.threshold)

    _audit(request).log(
        action="detector.threshold.update",
        actor=user.username,
        target=name,
        details={"new_threshold": float(body.threshold)},
    )
    return {"name": name, "threshold": float(body.threshold), "applied": True}


# ── Evaluation (subprocess) ────────────────────────────────────────────────

_EVAL_DIR = Path(os.environ.get("DATA_DIR", "data")) / "evaluations"
_TUNE_DIR = Path(os.environ.get("DATA_DIR", "data")) / "tunings"


class EvaluateRequest(BaseModel):
    hours: int = Field(48, ge=1, le=720)
    hosts: int = Field(10, ge=1, le=50)
    lateral_attacks: int = Field(8, ge=0, le=200)
    dns_attacks:     int = Field(8, ge=0, le=200)
    seed: int = Field(42, ge=0)
    threshold: float = Field(0.5, ge=0.0, le=1.0)


@router.post("/{name}/evaluate", status_code=202)
async def evaluate_model(
    name: str,
    body: EvaluateRequest,
    background: BackgroundTasks,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Run NFR-02 evaluation against synthetic data in a background task."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    import uuid, time as _time
    job_id = f"eval_{int(_time.time())}_{uuid.uuid4().hex[:6]}"
    _EVAL_DIR.mkdir(parents=True, exist_ok=True)
    job_path = _EVAL_DIR / f"{name}__{job_id}.json"
    job_path.write_text('{"status":"running","model":"%s","job_id":"%s"}' % (name, job_id))

    _audit(request).log(
        action="model.evaluate.requested",
        actor=user.username, target=name,
        details={"job_id": job_id, **body.model_dump()},
    )
    background.add_task(_run_evaluation, name, body, job_id, job_path, user.username, request.app)
    return {"job_id": job_id, "model": name, "status": "running"}


def _run_evaluation(name, body, job_id, job_path, actor, app):
    """Background task — calls `training.evaluate_models` as a subprocess."""
    import subprocess, json, sys, time as _time
    out_json = _EVAL_DIR / f"{name}__{job_id}__result.json"
    cmd = [
        sys.executable, "-m", "training.evaluate_models",
        "--model-name", name,
        "--model-path", f"detection/models/{name}/latest",
        "--synthetic",
        "--hours", str(body.hours),
        "--hosts", str(body.hosts),
        "--lateral-attacks", str(body.lateral_attacks),
        "--dns-attacks", str(body.dns_attacks),
        "--seed", str(body.seed),
        "--threshold", str(body.threshold),
        "--output-json", str(out_json),
    ]
    env = dict(os.environ)
    started = _time.time()
    # 10-minute ceiling so a runaway eval (e.g. someone passes hours=720 with
    # a huge boost-round override) doesn't pin a worker indefinitely. The
    # current observed duration is ~75s for the default 48h synthetic eval.
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
        timed_out = False
    except subprocess.TimeoutExpired as te:
        proc = te  # carries .stdout/.stderr (possibly None) + .cmd
        timed_out = True
    duration = _time.time() - started
    if timed_out:
        status = "failed"
        exit_code = -15  # mirror SIGTERM convention
        stderr_tail = "evaluation timed out after 600s — child killed (SIGTERM)"
    else:
        status = "ok" if proc.returncode == 0 else "failed"
        exit_code = proc.returncode
        stderr_tail = (proc.stderr or "")[-2000:]
    summary = {
        "job_id": job_id, "model": name,
        "status": status,
        "exit_code": exit_code,
        "duration_sec": round(duration, 2),
        "stderr_tail": stderr_tail,
        "started_at": started,
        "params": body.model_dump(),
    }
    if out_json.exists():
        try:
            summary["report"] = json.loads(out_json.read_text())
        except Exception as e:
            summary["report_error"] = str(e)
    job_path.write_text(json.dumps(summary, indent=2))

    try:
        app.state.audit_trail.log(
            action="model.evaluate." + summary["status"],
            actor=actor, target=name,
            details={k: v for k, v in summary.items() if k != "report"},
        )
    except Exception:
        pass


@router.get("/{name}/evaluations")
async def list_evaluations(
    name: str,
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    """List past evaluation jobs for a model, newest first."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    _EVAL_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    import json as _json
    for p in sorted(_EVAL_DIR.glob(f"{name}__*.json"), reverse=True):
        if "__result.json" in p.name:
            continue
        try:
            out.append(_json.loads(p.read_text()))
        except Exception:
            continue
    return {"name": name, "evaluations": out[:50]}


# ── Tuning (subprocess) ────────────────────────────────────────────────────

class TuneRequest(BaseModel):
    hours: int = Field(48, ge=1, le=720)
    hosts: int = Field(10, ge=1, le=50)
    lateral_attacks: int = Field(8, ge=0, le=200)
    dns_attacks:     int = Field(8, ge=0, le=200)
    seed: int = Field(42, ge=0)
    n_splits: int = Field(3, ge=2, le=10)


@router.post("/{name}/tune", status_code=202)
async def tune_model(
    name: str,
    body: TuneRequest,
    background: BackgroundTasks,
    request: Request,
    user: User = Depends(require_permission("retrain_models")),
):
    """Run GridSearchCV hyperparameter tuning in a background task."""
    if name not in _KNOWN_MODELS:
        raise HTTPException(404, f"Unknown model: {name}")
    import uuid, time as _time
    job_id = f"tune_{int(_time.time())}_{uuid.uuid4().hex[:6]}"
    _TUNE_DIR.mkdir(parents=True, exist_ok=True)
    job_path = _TUNE_DIR / f"{name}__{job_id}.json"
    job_path.write_text('{"status":"running","model":"%s","job_id":"%s"}' % (name, job_id))
    _audit(request).log(
        action="model.tune.requested",
        actor=user.username, target=name,
        details={"job_id": job_id, **body.model_dump()},
    )
    background.add_task(_run_tuning, name, body, job_id, job_path, user.username, request.app)
    return {"job_id": job_id, "model": name, "status": "running"}


def _run_tuning(name, body, job_id, job_path, actor, app):
    import subprocess, json, sys, time as _time
    out_json = _TUNE_DIR / f"{name}__{job_id}__result.json"
    cmd = [
        sys.executable, "-m", "training.tuning",
        "--model-name", name,
        "--synthetic",
        "--hours", str(body.hours),
        "--hosts", str(body.hosts),
        "--lateral-attacks", str(body.lateral_attacks),
        "--dns-attacks", str(body.dns_attacks),
        "--seed", str(body.seed),
        "--n-splits", str(body.n_splits),
        "--output-json", str(out_json),
    ]
    started = _time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ))
    duration = _time.time() - started
    summary = {
        "job_id": job_id, "model": name,
        "status": "ok" if proc.returncode == 0 else "failed",
        "exit_code": proc.returncode,
        "duration_sec": round(duration, 2),
        "stderr_tail": (proc.stderr or "")[-2000:],
        "started_at": started,
        "params": body.model_dump(),
    }
    if out_json.exists():
        try:
            summary["result"] = json.loads(out_json.read_text())
        except Exception as e:
            summary["result_error"] = str(e)
    job_path.write_text(json.dumps(summary, indent=2))
    try:
        app.state.audit_trail.log(
            action="model.tune." + summary["status"],
            actor=actor, target=name,
            details={k: v for k, v in summary.items() if k != "result"},
        )
    except Exception:
        pass


@router.get("/{name}/tunings/{job_id}")
async def get_tuning(
    name: str, job_id: str,
    request: Request,
    user: User = Depends(require_permission("read_detections")),
):
    p = _TUNE_DIR / f"{name}__{job_id}.json"
    if not p.exists():
        raise HTTPException(404, "Tuning job not found")
    import json as _json
    return _json.loads(p.read_text())


# ── Drift baseline ─────────────────────────────────────────────────────────

@router.post("/drift/baseline")
async def set_drift_baseline(
    request: Request,
    user: User = Depends(require_permission("manage_detectors")),
):
    """
    Snapshot current confidence distributions per detector as the drift
    baseline. Run this AFTER the platform has accumulated enough normal-
    operation data (~1h) so the baseline reflects steady state.
    """
    sub = getattr(request.app.state, "detection_subscriber", None)
    if sub is None:
        raise HTTPException(500, "Detection subscriber not initialised")
    results = sub.set_drift_baselines()
    _audit(request).log(
        action="model.drift.baseline_set",
        actor=user.username,
        target="all_detectors",
        details=results,
    )
    return {"baselines_set": results}
