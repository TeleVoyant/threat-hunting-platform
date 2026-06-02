#!/usr/bin/env python3
# training/evaluate_models.py
"""
Evaluation script for NFR-02 metrics.

Loads trained models, runs them against a held-out labeled dataset, and
emits the metrics the proposal commits to:

  Precision  (target: ≥ 0.85)
  Recall     (target: ≥ 0.90)
  F1
  ROC-AUC    (target: ≥ 0.93)
  FPR        (target: <  0.05)
  PR-AUC     (informative — better than ROC for imbalanced classes)
  Confusion matrix
  Threshold sweep (precision/recall at multiple thresholds)

Output:
  - Console table (citable in Chapter 7)
  - JSON file with full results (default: data/evaluation/<model>_<timestamp>.json)
  - Optional CSV of per-window predictions for forensic review

Usage:
  # Evaluate against a Mordor directory (recommended)
  venv/bin/python -m training.evaluate_models \\
      --model-name lateral_movement \\
      --model-path detection/models/lateral_movement/latest \\
      --mordor-dir /path/to/mordor \\
      --add-synthetic-benign-hours 24

  # Evaluate against a JSONL file with explicit labels
  venv/bin/python -m training.evaluate_models \\
      --model-name dns_exfiltration \\
      --model-path detection/models/dns_exfiltration/latest \\
      --from-jsonl test_data.jsonl
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.model_store        import ModelStore
from features.pipeline            import FeaturePipeline
from features.dns_features        import DnsFeatureExtractor
from features.auth_features       import AuthFeatureExtractor
from features.process_features    import ProcessFeatureExtractor
from features.network_features    import NetworkFeatureExtractor
from features.temporal_features   import TemporalFeatureExtractor
from features.behavioral_features import BehavioralFeatureExtractor
from shared.logging               import setup_logging, get_logger
from shared.schemas               import NormalizedEvent
from training.trainer             import extract_training_matrix, window_events

logger = get_logger("training.evaluate")


def build_pipeline() -> FeaturePipeline:
    p = FeaturePipeline()
    for ex in [
        DnsFeatureExtractor(), AuthFeatureExtractor(), ProcessFeatureExtractor(),
        NetworkFeatureExtractor(), TemporalFeatureExtractor(), BehavioralFeatureExtractor(),
    ]:
        p.register_extractor(ex)
    return p


# ── Metrics ────────────────────────────────────────────────────────────────

def confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def precision_recall_f1(cm: dict) -> dict:
    tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"precision": p, "recall": r, "f1": f1}


def fpr(cm: dict) -> float:
    return cm["fp"] / (cm["fp"] + cm["tn"]) if (cm["fp"] + cm["tn"]) else 0.0


def roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Trapezoidal ROC AUC. Robust to ties; handles all-one-class edge case."""
    y_true = y_true.astype(int)
    if len(set(y_true)) < 2:
        return float("nan")  # AUC undefined for one-class
    order = np.argsort(-y_score)
    y_sorted = y_true[order]
    n_pos = int(y_sorted.sum())
    n_neg = len(y_sorted) - n_pos
    tpr_curve = np.cumsum(y_sorted) / n_pos
    fpr_curve = np.cumsum(1 - y_sorted) / n_neg
    fpr_curve = np.concatenate([[0.0], fpr_curve])
    tpr_curve = np.concatenate([[0.0], tpr_curve])
    # np.trapezoid is the NumPy 2.x name; np.trapz is removed in 2.x
    trap = getattr(np, "trapezoid", None) or getattr(np, "trapz")
    return float(trap(tpr_curve, fpr_curve))


def pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Average precision (area under the precision-recall curve)."""
    y_true = y_true.astype(int)
    if y_true.sum() == 0:
        return float("nan")
    order = np.argsort(-y_score)
    y_sorted = y_true[order]
    tp_cum = np.cumsum(y_sorted)
    fp_cum = np.cumsum(1 - y_sorted)
    precision = tp_cum / (tp_cum + fp_cum)
    recall    = tp_cum / y_true.sum()
    # Step-wise area
    return float(np.sum(np.diff(np.concatenate([[0.0], recall])) * precision))


def threshold_sweep(y_true: np.ndarray, y_score: np.ndarray,
                    thresholds: tuple = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)) -> list[dict]:
    rows = []
    for t in thresholds:
        y_pred = (y_score >= t).astype(int)
        cm = confusion_matrix(y_true, y_pred)
        prf = precision_recall_f1(cm)
        rows.append({
            "threshold": t,
            "tp": cm["tp"], "fp": cm["fp"], "tn": cm["tn"], "fn": cm["fn"],
            "precision": round(prf["precision"], 4),
            "recall":    round(prf["recall"],    4),
            "f1":        round(prf["f1"],        4),
            "fpr":       round(fpr(cm),          4),
        })
    return rows


# ── Dense curves for the dashboard ───────────────────────────────────────

def roc_curve_points(y_true: np.ndarray, y_score: np.ndarray, n_points: int = 50) -> list[dict]:
    """ROC curve as {fpr, tpr, threshold} samples across uniformly-spaced thresholds.

    The dashboard renders a line chart with area fill from these points; 50 is
    enough to look smooth without bloating the JSON manifest."""
    if len(np.unique(y_true)) < 2:
        return []
    thresholds = np.linspace(0.0, 1.0, n_points)
    out = []
    for t in thresholds:
        y_pred = (y_score >= t).astype(int)
        cm = confusion_matrix(y_true, y_pred)
        tpr = cm["tp"] / (cm["tp"] + cm["fn"]) if (cm["tp"] + cm["fn"]) else 0.0
        out.append({
            "threshold": float(t),
            "fpr": round(fpr(cm), 6),
            "tpr": round(tpr, 6),
        })
    return out


def pr_curve_points(y_true: np.ndarray, y_score: np.ndarray, n_points: int = 50) -> list[dict]:
    """Precision/recall pairs at uniformly-spaced thresholds (mirror of ROC)."""
    if y_true.sum() == 0:
        return []
    thresholds = np.linspace(0.0, 1.0, n_points)
    out = []
    for t in thresholds:
        y_pred = (y_score >= t).astype(int)
        cm = confusion_matrix(y_true, y_pred)
        prf = precision_recall_f1(cm)
        out.append({
            "threshold": float(t),
            "precision": round(prf["precision"], 6),
            "recall":    round(prf["recall"],    6),
        })
    return out


def score_distribution(y_true: np.ndarray, y_score: np.ndarray, n_bins: int = 20) -> dict:
    """Per-class histogram of model confidences.

    The dashboard renders this as a paired bar chart so the analyst can see
    class separability visually. Strong models show two tight peaks at 0 and 1
    with little overlap; weak models show overlapping distributions."""
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    pos_mask = y_true == 1
    pos_counts, _ = np.histogram(y_score[pos_mask], bins=edges)
    neg_counts, _ = np.histogram(y_score[~pos_mask], bins=edges)
    midpoints = ((edges[:-1] + edges[1:]) / 2).round(4).tolist()
    return {
        "bin_midpoints":   midpoints,
        "positive_counts": [int(c) for c in pos_counts.tolist()],
        "negative_counts": [int(c) for c in neg_counts.tolist()],
    }


def calibration_bins(y_true: np.ndarray, y_score: np.ndarray, n_bins: int = 10) -> list[dict]:
    """Reliability diagram bins: predicted_prob vs observed positive fraction.

    A perfectly-calibrated model places all bins on the y=x diagonal. Wide
    departures mean the model's confidence numbers can't be read as
    probabilities — useful context when deciding the operating threshold."""
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    out = []
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        # Include hi only in the last bin so [0,1] is fully covered without overlap
        if i == n_bins - 1:
            mask = (y_score >= lo) & (y_score <= hi)
        else:
            mask = (y_score >= lo) & (y_score < hi)
        n = int(mask.sum())
        if n == 0:
            continue
        predicted_mean = float(y_score[mask].mean())
        actual_frac = float(y_true[mask].mean())
        out.append({
            "bin_midpoint":    float(round((lo + hi) / 2, 4)),
            "predicted_mean":  float(round(predicted_mean, 4)),
            "actual_positive": float(round(actual_frac, 4)),
            "n": n,
        })
    return out


def alerts_per_day(sweep: list[dict], hours: int) -> list[dict]:
    """Project alerts/day at each threshold from the sweep table.

    'Alerts' = TP + FP (everything the operator would see). Useful to translate
    a precision/recall tradeoff into operator burden ('200 alerts/day' lands
    differently than 'precision 0.4')."""
    if hours <= 0:
        return []
    days = hours / 24.0
    return [
        {
            "threshold":     row["threshold"],
            "alerts_per_day":   round((row["tp"] + row["fp"]) / days, 2),
            "true_alerts_per_day":  round(row["tp"] / days, 2),
            "false_alerts_per_day": round(row["fp"] / days, 2),
        }
        for row in sweep
    ]


# ── NFR-02 grading ─────────────────────────────────────────────────────────

NFR_02_TARGETS = {
    "precision": (">=", 0.85),
    "recall":    (">=", 0.90),
    "roc_auc":   (">=", 0.93),
    "fpr":       ("<",  0.05),
}


def grade(metrics: dict) -> dict:
    out = {}
    for k, (op, target) in NFR_02_TARGETS.items():
        v = metrics.get(k)
        if v is None or (isinstance(v, float) and np.isnan(v)):
            out[k] = {"value": v, "target": target, "op": op, "passes": None}
            continue
        passes = (v >= target) if op == ">=" else (v < target)
        out[k] = {"value": round(v, 4), "target": target, "op": op,
                  "passes": bool(passes)}
    return out


# ── Main ───────────────────────────────────────────────────────────────────

def load_dataset(args) -> list[tuple[NormalizedEvent, int]]:
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
        return labeled

    if args.from_jsonl:
        out = []
        with open(args.from_jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                lbl = int(obj.pop("_label", 0))
                out.append((NormalizedEvent(**obj), lbl))
        return out

    if args.synthetic:
        from training.synthetic import generate_dataset
        return generate_dataset(
            duration_hours=args.hours,
            hosts=[f"LAPTOP-{i:03d}" for i in range(1, args.hosts + 1)],
            lateral_attacks_per_day=args.lateral_attacks,
            dns_attacks_per_day=args.dns_attacks,
            seed=args.seed,
        )

    raise SystemExit("Provide one of: --mordor-dir, --from-jsonl, --synthetic")


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate trained detector against held-out data")
    ap.add_argument("--model-name", required=True,
                    choices=["lateral_movement", "dns_exfiltration"])
    ap.add_argument("--model-path", required=True,
                    help="Path to model directory (versioned dir or 'latest' symlink)")

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
    ap.add_argument("--grouping", default=None,
                    help="hostname | hostname_user (default: matches detector convention)")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="Operating threshold for headline metrics")
    ap.add_argument("--output-json",
                    help="Write metrics JSON to this path "
                         "(default: data/evaluation/<model>_<ts>.json)")
    args = ap.parse_args()

    setup_logging("INFO")

    grouping = args.grouping or (
        "hostname_user" if args.model_name == "lateral_movement" else "hostname"
    )

    # ── Load dataset + extract features ──────────────────────────────────────
    labeled = load_dataset(args)
    pos = sum(1 for _, l in labeled if l == 1)
    print(f"Loaded {len(labeled)} events ({pos} positive, "
          f"{len(labeled) - pos} negative)")

    windowed = window_events(labeled, args.window_minutes, grouping)
    pos_w = sum(1 for *_, l in windowed if l == 1)
    print(f"Windowed → {len(windowed)} samples ({pos_w} positive, "
          f"{len(windowed) - pos_w} negative)")

    pipeline = build_pipeline()
    X, y, feature_names = extract_training_matrix(pipeline, windowed)
    print(f"Feature matrix: shape={X.shape}, positive_rate={y.mean():.4f}")

    # ── Load model ───────────────────────────────────────────────────────────
    store = ModelStore(
        base_dir=os.environ.get("MODEL_STORE_DIR", "detection/models"),
        signing_key=os.environ.get("MODEL_SIGNING_KEY", ""),
    )
    booster = store.load_from_path(args.model_path)
    print(f"Loaded model from {args.model_path}")

    # ── Predict ──────────────────────────────────────────────────────────────
    import xgboost as xgb
    dmatrix = xgb.DMatrix(X, feature_names=feature_names)
    y_score = booster.predict(dmatrix)
    y_pred = (y_score >= args.threshold).astype(int)

    # ── Metrics at the operating threshold ───────────────────────────────────
    cm = confusion_matrix(y, y_pred)
    prf = precision_recall_f1(cm)
    metrics = {
        "model_name":   args.model_name,
        "model_path":   args.model_path,
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": {
            "n_events":      len(labeled),
            "n_positive":    pos,
            "n_windows":     len(windowed),
            "n_pos_windows": pos_w,
            "feature_count": int(X.shape[1]),
        },
        "operating_threshold": args.threshold,
        "confusion_matrix":    cm,
        "precision":           prf["precision"],
        "recall":              prf["recall"],
        "f1":                  prf["f1"],
        "fpr":                 fpr(cm),
        "roc_auc":             roc_auc(y, y_score),
        "pr_auc":              pr_auc(y, y_score),
        "threshold_sweep":     threshold_sweep(y, y_score),
        # Dense curves for the /dashboard/evaluations page. Legacy run JSONs
        # that pre-date these keys still render — the page falls back to
        # threshold_sweep for ROC/PR if these are absent.
        "roc_curve":           roc_curve_points(y, y_score),
        "pr_curve":            pr_curve_points(y, y_score),
        "score_distribution":  score_distribution(y, y_score),
        "calibration":         calibration_bins(y, y_score),
        "grouping":            grouping,
        "window_minutes":      args.window_minutes,
    }
    metrics["alerts_per_day_at_threshold"] = alerts_per_day(
        metrics["threshold_sweep"], args.hours,
    )
    metrics["nfr_02_grade"] = grade(metrics)

    # ── Console report ───────────────────────────────────────────────────────
    print()
    print("═══════════════════════════════════════════════════════════════")
    print(f"  EVALUATION REPORT: {args.model_name}")
    print("═══════════════════════════════════════════════════════════════")
    print(f"  Operating threshold : {args.threshold}")
    print(f"  Confusion matrix    : TP={cm['tp']}  FP={cm['fp']}  "
          f"TN={cm['tn']}  FN={cm['fn']}")
    print(f"  Precision           : {metrics['precision']:.4f}")
    print(f"  Recall              : {metrics['recall']:.4f}")
    print(f"  F1                  : {metrics['f1']:.4f}")
    print(f"  FPR                 : {metrics['fpr']:.4f}")
    print(f"  ROC-AUC             : {metrics['roc_auc']:.4f}")
    print(f"  PR-AUC              : {metrics['pr_auc']:.4f}")
    print()
    print("  NFR-02 grading:")
    for metric, info in metrics["nfr_02_grade"].items():
        passes = info.get("passes")
        symbol = "✓" if passes is True else "✗" if passes is False else "?"
        print(f"    {symbol} {metric:10s} {info['value']!s:8s} "
              f"{info['op']} {info['target']}")
    print()
    print("  Threshold sweep:")
    print(f"    {'thr':>5}  {'P':>6}  {'R':>6}  {'F1':>6}  {'FPR':>6}  "
          f"{'TP':>5}  {'FP':>5}  {'FN':>5}")
    for row in metrics["threshold_sweep"]:
        print(f"    {row['threshold']:>5.2f}  {row['precision']:>6.3f}  "
              f"{row['recall']:>6.3f}  {row['f1']:>6.3f}  {row['fpr']:>6.3f}  "
              f"{row['tp']:>5d}  {row['fp']:>5d}  {row['fn']:>5d}")
    print("═══════════════════════════════════════════════════════════════")

    # ── Persist JSON ─────────────────────────────────────────────────────────
    out_path = args.output_json or (
        f"data/evaluation/{args.model_name}_"
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    )
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(metrics, indent=2, default=str))
    print(f"\nFull metrics written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
