# training/trainer.py
"""
Training engine — windows labeled events, extracts features, fits XGBoost.

The pipeline is the SAME one used at inference time (features.pipeline +
all six extractors), so the model trained here sees exactly the feature
schema the runtime detector will pass to it. No train/serve skew.

Inputs:
    labeled_events  : list[(NormalizedEvent, int)]  with int ∈ {0, 1}
    window_minutes  : sliding window size for grouping events into samples
    grouping        : "hostname" | "hostname_user" — how to bucket events

Output:
    A trained xgb.Booster with feature names matching extract_all() output,
    plus the train/eval metrics dict.

Why this matters
----------------
A FeatureVector → label sample is "this entity (hostname or hostname:user)
during this 5-minute window". The label is 1 if ANY event in the window
was tagged as part of an attack. This is how a runtime detector frames the
question "is this entity acting maliciously right now" — so we train the
model on exactly that question.
"""

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import xgboost as xgb

from features.pipeline import FeaturePipeline
from shared.logging import get_logger
from shared.schemas import FeatureVector, NormalizedEvent

logger = get_logger("training.trainer")


# ── Windowing ──────────────────────────────────────────────────────────────

def _entity_key(event: NormalizedEvent, mode: str) -> str:
    if mode == "hostname_user":
        return f"{event.hostname}:{event.user}" if event.user else event.hostname
    return event.hostname


def _window_bucket(ts: datetime, window_seconds: int) -> int:
    """Floor a timestamp into a window-aligned bucket index."""
    epoch = ts.replace(tzinfo=timezone.utc).timestamp() if ts.tzinfo is None else ts.timestamp()
    return int(epoch // window_seconds)


def window_events(
    labeled_events: list[tuple[NormalizedEvent, int]],
    window_minutes: int = 5,
    grouping: str = "hostname",
) -> list[tuple[str, list[NormalizedEvent], int]]:
    """
    Bucket events into (entity, window) groups.

    Returns: list of (source_entity, events_in_window, label)
    where label is 1 if any event in the window was attack-tagged.

    A note on label aggregation: we deliberately use OR (any attack event in
    the window flips the label to 1). This trains the detector to fire when
    attack signal is mixed with normal noise — the realistic case. Using
    majority-vote labelling would suppress quiet-and-stealthy attacks which
    is exactly what we want to detect.
    """
    window_secs = window_minutes * 60
    buckets: dict[tuple[str, int], list[NormalizedEvent]] = defaultdict(list)
    label_buckets: dict[tuple[str, int], int] = defaultdict(int)

    for event, label in labeled_events:
        entity = _entity_key(event, grouping)
        bucket = _window_bucket(event.timestamp, window_secs)
        key = (entity, bucket)
        buckets[key].append(event)
        if label == 1:
            label_buckets[key] = 1

    return [
        (entity, sorted(events, key=lambda e: e.timestamp), label_buckets[(entity, bucket)])
        for (entity, bucket), events in buckets.items()
        if len(events) >= 2  # require at least 2 events for meaningful temporal features
    ]


# ── Feature extraction over windows ─────────────────────────────────────────

def extract_training_matrix(
    pipeline: FeaturePipeline,
    windowed: list[tuple[str, list[NormalizedEvent], int]],
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Run the feature pipeline over each window, returning:
        X           : (n_samples, n_features) float matrix
        y           : (n_samples,) label vector
        feature_names: column names matching X (and the runtime detector input)

    Drops any window whose feature vector ends up empty (defensive — should
    never happen since we filter to len(events) >= 2 upstream).
    """
    feature_names: Optional[list[str]] = None
    rows: list[list[float]] = []
    labels: list[int] = []

    for entity, events, label in windowed:
        fv = pipeline.extract_all(events, source_entity=entity)
        if not fv.features:
            continue

        # Lock the feature schema on the first non-empty vector. Every
        # subsequent vector must match it (the pipeline is deterministic
        # so this is a sanity check, not a normal failure path).
        if feature_names is None:
            feature_names = list(fv.features.keys())
        elif list(fv.features.keys()) != feature_names:
            raise RuntimeError(
                f"Feature schema drift detected at entity={entity}: "
                f"expected {len(feature_names)} keys, got {len(fv.features)}"
            )

        rows.append([float(fv.features.get(k, 0.0)) for k in feature_names])
        labels.append(label)

    if not rows:
        raise RuntimeError("No training samples produced — check input data")

    return np.array(rows, dtype=np.float32), np.array(labels, dtype=np.int32), feature_names


# ── XGBoost training ───────────────────────────────────────────────────────

DEFAULT_PARAMS = {
    "objective":        "binary:logistic",
    "eval_metric":      ["logloss", "auc"],
    "max_depth":        6,
    "eta":              0.1,
    "subsample":        0.85,
    "colsample_bytree": 0.85,
    "min_child_weight": 1,
    "verbosity":        0,
}


def train_booster(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    *,
    num_boost_round: int = 200,
    early_stopping_rounds: int = 20,
    train_split: float = 0.8,
    params: Optional[dict] = None,
    random_state: int = 42,
) -> tuple[xgb.Booster, dict]:
    """
    Fit XGBoost binary classifier with held-out eval set + early stopping.

    Returns (model, metrics_dict).
    """
    rng = np.random.default_rng(random_state)
    n = X.shape[0]
    perm = rng.permutation(n)
    cut = int(n * train_split)
    train_idx, eval_idx = perm[:cut], perm[cut:]

    dtrain = xgb.DMatrix(X[train_idx], label=y[train_idx], feature_names=feature_names)
    deval  = xgb.DMatrix(X[eval_idx],  label=y[eval_idx],  feature_names=feature_names)

    # Auto-balance positive class weight if dataset is skewed
    pos = int(y[train_idx].sum())
    neg = int(len(train_idx) - pos)
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    p = dict(DEFAULT_PARAMS)
    if params:
        p.update(params)
    p["scale_pos_weight"] = scale_pos_weight

    evals_result: dict = {}
    booster = xgb.train(
        params=p,
        dtrain=dtrain,
        num_boost_round=num_boost_round,
        evals=[(dtrain, "train"), (deval, "eval")],
        early_stopping_rounds=early_stopping_rounds,
        evals_result=evals_result,
        verbose_eval=False,
    )

    metrics = {
        "n_train":          int(len(train_idx)),
        "n_eval":           int(len(eval_idx)),
        "n_pos_train":      pos,
        "n_pos_eval":       int(y[eval_idx].sum()),
        "scale_pos_weight": float(scale_pos_weight),
        "best_iteration":   int(booster.best_iteration),
        "eval_auc":         float(evals_result["eval"]["auc"][-1]),
        "eval_logloss":     float(evals_result["eval"]["logloss"][-1]),
        "feature_count":    len(feature_names),
    }
    return booster, metrics


# ── End-to-end training ────────────────────────────────────────────────────

def train_model(
    labeled_events: list[tuple[NormalizedEvent, int]],
    pipeline: FeaturePipeline,
    *,
    model_name: Optional[str] = None,
    model_store=None,
    output_path: Optional[str] = None,
    window_minutes: int = 5,
    grouping: str = "hostname",
    num_boost_round: int = 200,
    extra_params: Optional[dict] = None,
) -> dict:
    """
    Train a model end-to-end and persist it.

    Two save modes:
      - PRODUCTION: pass `model_store` (ModelStore) and `model_name`.
        Saves to {store.base_dir}/{model_name}/v{ts}/{model.json,manifest.json}
        with HMAC signature. Updates the `latest` symlink.
      - LEGACY/TEST: pass `output_path` (flat .json file). No manifest.
        DetectionSubscriber will load it without integrity verification.

    Returns the metrics dict (always includes "saved_at" with the resolved path).
    """
    if not (model_store and model_name) and not output_path:
        raise ValueError(
            "Provide either (model_store + model_name) or output_path"
        )

    windowed = window_events(labeled_events, window_minutes, grouping)
    logger.info("Windowing complete",
                window_count=len(windowed),
                positives=sum(1 for *_, lbl in windowed if lbl == 1))

    X, y, feature_names = extract_training_matrix(pipeline, windowed)
    logger.info("Feature matrix built",
                shape=tuple(X.shape), positives=int(y.sum()))

    booster, metrics = train_booster(
        X, y, feature_names,
        num_boost_round=num_boost_round,
        params=extra_params,    # tuner-supplied overrides win over DEFAULT_PARAMS
    )
    metrics["window_minutes"] = window_minutes
    metrics["grouping"]       = grouping
    metrics["feature_names"]  = feature_names  # persisted in manifest
    if extra_params:
        metrics["tuned_params"] = extra_params

    if model_store and model_name:
        version = model_store.save_model(booster, model_name, metadata=metrics)
        saved_at = str(model_store.base_dir / model_name / version)
        metrics["saved_at"] = saved_at
        metrics["version"]  = version
        logger.info("Model saved (signed)", name=model_name,
                    version=version, path=saved_at)
    else:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        booster.save_model(output_path)
        metrics["saved_at"] = output_path
        logger.info("Model saved (UNSIGNED — legacy mode)", path=output_path)

    return metrics
