# training/tuning.py
"""
GridSearchCV-based hyperparameter tuning for the XGBoost detectors.
Closes proposal item 2.12.

Search strategy
---------------
We sweep the four parameters that most affect APT detection on tabular
binary-classification problems:

    max_depth        — tree depth; bigger = captures interactions, risks overfit
    eta              — learning rate; trade-off speed vs. accuracy
    min_child_weight — minimum sum of instance weight per child; regularizer
    subsample        — row subsampling per boost round; regularizer

The grid is intentionally small (3-cell × 3-cell × 2 × 2 = 36 candidates by
default) so a tuning run finishes in a few minutes on synthetic data and
~30 minutes on a realistic Mordor + benign mix. Override via CLI:

    venv/bin/python -m training.tuning \\
        --mordor-dir /path/to/mordor \\
        --add-synthetic-benign-hours 24 \\
        --model-name lateral_movement \\
        --output-json data/tuning/lateral_v1.json

The winning params are written to JSON; pass them to train_models.py via
--params-json on the next training run for the final production model.

Cross-validation
----------------
StratifiedKFold (default n_splits=5) preserves the positive/negative ratio
in each fold — important because Mordor data is heavily skewed.

Scoring
-------
We optimise for `roc_auc` because:
  - It's threshold-independent (we tune the model, not the operating point)
  - It's the headline NFR-02 metric (target ≥ 0.93)
  - It handles class imbalance better than accuracy

After the search, we retrain the winner on the full dataset and report
metrics + the timing of each candidate.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np
import xgboost as xgb
from sklearn.model_selection import GridSearchCV, StratifiedKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.pipeline            import FeaturePipeline
from features.dns_features        import DnsFeatureExtractor
from features.auth_features       import AuthFeatureExtractor
from features.process_features    import ProcessFeatureExtractor
from features.network_features    import NetworkFeatureExtractor
from features.temporal_features   import TemporalFeatureExtractor
from features.behavioral_features import BehavioralFeatureExtractor
from shared.logging               import get_logger, setup_logging
from shared.schemas               import NormalizedEvent
from training.trainer             import extract_training_matrix, window_events

logger = get_logger("training.tuning")


def build_pipeline(window_minutes: int = 5) -> FeaturePipeline:
    p = FeaturePipeline()
    for ex in [
        DnsFeatureExtractor(window_minutes=window_minutes),
        AuthFeatureExtractor(window_minutes=window_minutes),
        ProcessFeatureExtractor(), NetworkFeatureExtractor(),
        TemporalFeatureExtractor(), BehavioralFeatureExtractor(),
    ]:
        p.register_extractor(ex)
    return p


# Default grid — small + fast. Override with --param-grid-json for a wider sweep.
_DEFAULT_GRID = {
    "max_depth":        [4, 6, 8],
    "learning_rate":    [0.05, 0.1, 0.2],
    "min_child_weight": [1, 5],
    "subsample":        [0.7, 0.9],
}


def tune(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    *,
    param_grid: Optional[dict] = None,
    n_splits: int = 5,
    n_jobs: int = -1,
    scoring: str = "roc_auc",
    n_estimators: int = 200,
    random_state: int = 42,
) -> dict:
    """
    Run GridSearchCV. Returns a dict with best_params, best_score, all results,
    and total elapsed seconds.
    """
    grid = param_grid or _DEFAULT_GRID
    candidate_count = 1
    for v in grid.values():
        candidate_count *= len(v)
    logger.info("Starting GridSearchCV",
                candidates=candidate_count, n_splits=n_splits, scoring=scoring)

    # XGBClassifier auto-balances via scale_pos_weight if we pre-compute it
    pos = int(y.sum())
    neg = int(len(y) - pos)
    scale_pos = neg / pos if pos > 0 else 1.0

    estimator = xgb.XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=n_estimators,
        scale_pos_weight=scale_pos,
        random_state=random_state,
        verbosity=0,
        tree_method="hist",     # fast for small-medium tabular
    )

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)

    started = time.time()
    search = GridSearchCV(
        estimator=estimator,
        param_grid=grid,
        scoring=scoring,
        cv=cv,
        n_jobs=n_jobs,
        refit=True,           # winning model retrained on full data
        return_train_score=False,
        error_score="raise",
    )
    search.fit(X, y)
    elapsed = time.time() - started

    # Extract the per-candidate results table for the JSON output
    cv_rows = []
    cv_results = search.cv_results_
    for i in range(len(cv_results["params"])):
        cv_rows.append({
            "params":    cv_results["params"][i],
            "mean_score": float(cv_results["mean_test_score"][i]),
            "std_score":  float(cv_results["std_test_score"][i]),
            "rank":      int(cv_results["rank_test_score"][i]),
            "fit_time":  float(cv_results["mean_fit_time"][i]),
        })
    cv_rows.sort(key=lambda r: r["rank"])

    return {
        "best_params":      search.best_params_,
        "best_score":       float(search.best_score_),
        "scoring":          scoring,
        "n_splits":         n_splits,
        "n_candidates":     candidate_count,
        "elapsed_seconds":  round(elapsed, 2),
        "feature_count":    int(X.shape[1]),
        "n_samples":        int(X.shape[0]),
        "n_positive":       pos,
        "scale_pos_weight": float(scale_pos),
        "cv_results":       cv_rows,
    }


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="GridSearchCV hyperparameter tuning")
    ap.add_argument("--model-name", required=True,
                    choices=["lateral_movement", "dns_exfiltration"])

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--mordor-dir")
    src.add_argument("--from-jsonl")
    src.add_argument("--synthetic", action="store_true")

    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--hosts", type=int, default=5)
    ap.add_argument("--lateral-attacks", type=int, default=5)
    ap.add_argument("--dns-attacks", type=int, default=5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--add-synthetic-benign-hours", type=int, default=0)
    ap.add_argument("--window-minutes", type=int, default=5)

    ap.add_argument("--n-splits", type=int, default=5)
    ap.add_argument("--n-jobs", type=int, default=-1,
                    help="-1 = all CPU cores; 1 = single-threaded debug")
    ap.add_argument("--scoring", default="roc_auc",
                    help="sklearn scoring metric (roc_auc, average_precision, f1, etc.)")
    ap.add_argument("--param-grid-json",
                    help="Path to a JSON file with a custom grid (overrides default)")
    ap.add_argument("--output-json",
                    help="Write best params + full sweep to this path "
                         "(default: data/tuning/<model>_<ts>.json)")
    args = ap.parse_args()

    setup_logging("INFO")

    # ── Load + window data ────────────────────────────────────────────────
    if args.mordor_dir:
        from training.loaders.mordor import MordorLoader
        loader = MordorLoader()
        labeled = loader.load_path(args.mordor_dir)
        if args.add_synthetic_benign_hours > 0:
            from training.synthetic import generate_dataset
            synth = generate_dataset(
                duration_hours=args.add_synthetic_benign_hours,
                hosts=[f"BENIGN-{i:03d}" for i in range(1, args.hosts + 1)],
                lateral_attacks_per_day=0, dns_attacks_per_day=0,
                seed=args.seed,
            )
            labeled.extend((e, 0) for e, _ in synth)
    elif args.from_jsonl:
        labeled = []
        with open(args.from_jsonl) as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                obj = json.loads(ln)
                lbl = int(obj.pop("_label", 0))
                labeled.append((NormalizedEvent(**obj), lbl))
    else:
        from training.synthetic import generate_dataset
        labeled = generate_dataset(
            duration_hours=args.hours,
            hosts=[f"LAPTOP-{i:03d}" for i in range(1, args.hosts + 1)],
            lateral_attacks_per_day=args.lateral_attacks,
            dns_attacks_per_day=args.dns_attacks,
            seed=args.seed,
        )

    grouping = ("hostname_user" if args.model_name == "lateral_movement"
                else "hostname")
    windowed = window_events(labeled, args.window_minutes, grouping)
    X, y, feature_names = extract_training_matrix(build_pipeline(window_minutes=args.window_minutes), windowed)

    # Match the production feature-domain restriction (i) so tuned params
    # reflect the schema the deployed model actually trains on.
    from training.train_models import load_feature_groups
    fg = load_feature_groups().get(args.model_name)
    if fg:
        allowed = set(fg)
        keep = [i for i, n in enumerate(feature_names) if n.split("__")[0] in allowed]
        X = X[:, keep]
        feature_names = [feature_names[i] for i in keep]
        print(f"Feature domain restricted to {sorted(allowed)}: {len(feature_names)} features")

    print(f"Tuning matrix: shape={X.shape}, "
          f"positives={int(y.sum())}, negatives={int((1-y).sum())}")

    # ── Load custom grid if provided ──────────────────────────────────────
    grid = _DEFAULT_GRID
    if args.param_grid_json:
        grid = json.loads(Path(args.param_grid_json).read_text())
        print(f"Using custom grid from {args.param_grid_json}")
    print(f"Grid: {grid}")

    # ── Run search ────────────────────────────────────────────────────────
    result = tune(
        X, y, feature_names,
        param_grid=grid,
        n_splits=args.n_splits,
        n_jobs=args.n_jobs,
        scoring=args.scoring,
        random_state=args.seed,
    )
    result["model_name"]    = args.model_name
    result["grouping"]      = grouping
    result["window_minutes"] = args.window_minutes
    result["timestamp"]     = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # ── Console report ────────────────────────────────────────────────────
    print()
    print("═══════════════════════════════════════════════════════════════")
    print(f"  GRID SEARCH RESULT: {args.model_name}")
    print("═══════════════════════════════════════════════════════════════")
    print(f"  Scoring          : {result['scoring']}")
    print(f"  Best CV score    : {result['best_score']:.4f}")
    print(f"  Best params      : {result['best_params']}")
    print(f"  Candidates tried : {result['n_candidates']}")
    print(f"  Folds (per cand) : {result['n_splits']}")
    print(f"  Elapsed          : {result['elapsed_seconds']:.1f}s")
    print()
    print("  Top-5 candidates:")
    for row in result["cv_results"][:5]:
        print(f"    rank={row['rank']:>2}  "
              f"score={row['mean_score']:.4f} ± {row['std_score']:.4f}  "
              f"fit={row['fit_time']:.2f}s  {row['params']}")
    print("═══════════════════════════════════════════════════════════════")

    out_path = args.output_json or (
        f"data/tuning/{args.model_name}_"
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    )
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(result, indent=2, default=str))
    print(f"\nFull tuning report written to {out_path}")

    # Print the params line ready to paste into train_models.py
    print(f"\n  → Apply via:")
    print(f"      train_models.py ... --params-json {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
