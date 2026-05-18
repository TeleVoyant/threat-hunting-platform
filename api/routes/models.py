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

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
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
    # Strip feature_names from each manifest (verbose) — caller can request
    # full manifest separately if needed
    for v in versions:
        v.get("metadata", {}).pop("feature_names", None)
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
