#!/usr/bin/env python3
# federated/run_demo.py
"""
End-to-end Federated Learning demo.

Runs IN-PROCESS (no Flower gRPC, no two-process orchestration) so a single
command produces:

  - A round-by-round convergence trace (round → global ROC-AUC)
  - The convergence graph PNG for Chapter 7
  - Per-org trust-score evolution (especially for the poisoned org)
  - JSON dump of round-by-round metrics

Why in-process?
---------------
The proposal commits to demonstrating FL convergence, the trust manager's
poisoning defense, and the differential-privacy step. All three can be
verified deterministically in one Python process by simulating each org's
client. Real Flower gRPC adds network/multi-process complexity that
doesn't change the ML-level claim being demonstrated.

What it shows
-------------
  Round 1      → each org trains locally; trust manager validates;
                 accepted contributions form the global model
  Round N      → each org continues training from the global model
  Poison round → an attacker org sends a deliberately bad model;
                 trust manager rejects it; trust score drops; eventually blocked

  Output JSON includes per-round:
    - global ROC-AUC on validation set
    - num_accepted / num_rejected per round
    - per-org trust scores
"""

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np
import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from federated.privacy            import apply_differential_privacy
from federated.trust              import FLTrustManager
from features.pipeline            import FeaturePipeline
from features.dns_features        import DnsFeatureExtractor
from features.auth_features       import AuthFeatureExtractor
from features.process_features    import ProcessFeatureExtractor
from features.network_features    import NetworkFeatureExtractor
from features.temporal_features   import TemporalFeatureExtractor
from features.behavioral_features import BehavioralFeatureExtractor
from shared.logging               import get_logger, setup_logging
from training.synthetic           import generate_dataset
from training.trainer             import (
    extract_training_matrix, window_events, train_booster,
)

logger = get_logger("federated.demo")


# ── Simulated organization profiles ────────────────────────────────────────

# Each org gets a different baseline (different attack rates, different
# host counts) so the data is heterogeneous — like real federation.
ORG_PROFILES = {
    "udom":       {"hosts": 4, "lateral": 4, "dns": 3, "seed": 101},
    "hospital":   {"hosts": 6, "lateral": 6, "dns": 2, "seed": 202},
    "bank":       {"hosts": 5, "lateral": 5, "dns": 5, "seed": 303},
}


# ── Pipeline + windowing helpers ───────────────────────────────────────────

def _build_pipeline() -> FeaturePipeline:
    p = FeaturePipeline()
    for ex in [
        DnsFeatureExtractor(), AuthFeatureExtractor(), ProcessFeatureExtractor(),
        NetworkFeatureExtractor(), TemporalFeatureExtractor(), BehavioralFeatureExtractor(),
    ]:
        p.register_extractor(ex)
    return p


def _build_partition(profile: dict, hours: int, grouping: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Generate + window + featurize one org's dataset."""
    labeled = generate_dataset(
        duration_hours=hours,
        hosts=[f"H-{profile['seed']}-{i:02d}" for i in range(1, profile["hosts"] + 1)],
        lateral_attacks_per_day=profile["lateral"],
        dns_attacks_per_day=profile["dns"],
        seed=profile["seed"],
    )
    pipeline = _build_pipeline()
    windowed = window_events(labeled, window_minutes=5, grouping=grouping)
    X, y, names = extract_training_matrix(pipeline, windowed)
    return X, y, names


def _roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Trapezoidal ROC AUC matching training/evaluate_models.roc_auc."""
    y_true = y_true.astype(int)
    if len(set(y_true)) < 2:
        return float("nan")
    order = np.argsort(-y_score)
    y_sorted = y_true[order]
    n_pos = int(y_sorted.sum())
    n_neg = len(y_sorted) - n_pos
    tpr = np.cumsum(y_sorted) / n_pos
    fpr = np.cumsum(1 - y_sorted) / n_neg
    fpr = np.concatenate([[0.0], fpr])
    tpr = np.concatenate([[0.0], tpr])
    trap = getattr(np, "trapezoid", None) or getattr(np, "trapz")
    return float(trap(tpr, fpr))


# ── Round driver ────────────────────────────────────────────────────────────

def run_demo(
    num_rounds: int = 10,
    hours_per_org: int = 12,
    grouping: str = "hostname_user",
    poison_round: Optional[int] = 5,
    epsilon: float = 1.0,
    output_dir: str = "data/fl_demo",
) -> dict:
    """
    Run num_rounds FL rounds, optionally poisoning one org from poison_round
    onwards. Returns the metrics dict (also written to JSON).
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'═'*65}")
    print(f"  FEDERATED LEARNING DEMO")
    print(f"  rounds={num_rounds} hours_per_org={hours_per_org} "
          f"grouping={grouping} poison_round={poison_round} ε={epsilon}")
    print(f"{'═'*65}")

    # ── Step 1: each org builds its own local dataset ────────────────────────
    print("\n[1] Building per-org datasets (each stays local — no cross-org data)")
    org_data = {}
    for org_id, profile in ORG_PROFILES.items():
        X, y, names = _build_partition(profile, hours_per_org, grouping)
        org_data[org_id] = {"X": X, "y": y, "feature_names": names}
        print(f"   {org_id:10s} → {X.shape[0]:>5d} windows, "
              f"{int(y.sum()):>3d} positive ({y.mean():.2%})")

    # ── Step 2: build a held-out validation set on the coordinator ──────────
    # In a real deployment the coordinator wouldn't have raw data; it would
    # have a separately-curated benchmark. Here we synthesise one.
    print("\n[2] Building coordinator's validation set (separate seed)")
    val_data = generate_dataset(
        duration_hours=hours_per_org // 2,
        hosts=[f"VAL-{i:02d}" for i in range(1, 5)],
        lateral_attacks_per_day=4, dns_attacks_per_day=4,
        seed=999,
    )
    val_windowed = window_events(val_data, window_minutes=5, grouping=grouping)
    val_X, val_y, val_names = extract_training_matrix(_build_pipeline(), val_windowed)
    print(f"   validation: {val_X.shape[0]} windows, "
          f"{int(val_y.sum())} positive")

    val_dmatrix = xgb.DMatrix(val_X, label=val_y, feature_names=val_names)
    trust_manager = FLTrustManager(
        validation_data=val_dmatrix,
        min_accuracy_threshold=0.85,
        max_accuracy_drop_per_round=0.10,
        min_trust_to_participate=0.3,
    )

    # ── Step 3: run rounds ──────────────────────────────────────────────────
    print(f"\n[3] Running {num_rounds} federated rounds")
    org_models: dict[str, Optional[xgb.Booster]] = {oid: None for oid in ORG_PROFILES}
    round_history: list[dict] = []
    accepted_models: list[xgb.Booster] = []   # current global ensemble

    for rnd in range(1, num_rounds + 1):
        print(f"\n   ── Round {rnd} ──")
        round_accepted, round_rejected = [], []
        round_trust = {}

        for org_id, profile in ORG_PROFILES.items():
            data = org_data[org_id]
            dtrain = xgb.DMatrix(data["X"], label=data["y"],
                                  feature_names=data["feature_names"])

            # Local training: continue from the org's previous local model
            booster = xgb.train(
                params={
                    "objective": "binary:logistic",
                    "eval_metric": "logloss",
                    "max_depth": 4, "eta": 0.1,
                    "scale_pos_weight": max(1.0,
                        (len(data["y"]) - data["y"].sum()) / max(1, data["y"].sum())),
                    "verbosity": 0,
                },
                dtrain=dtrain,
                num_boost_round=10,            # local epochs per round
                xgb_model=org_models[org_id],
            )
            org_models[org_id] = booster

            # Apply differential privacy to leaf values BEFORE shipping
            model_bytes = booster.save_raw("json")
            dp_bytes = apply_differential_privacy(model_bytes, epsilon=epsilon)

            # POISONING: replace bank's contribution with a corrupted booster
            if poison_round and rnd >= poison_round and org_id == "bank":
                # Train a model that's deliberately bad: flip half the labels
                bad_y = data["y"].copy()
                flip_idx = np.random.RandomState(rnd).choice(
                    len(bad_y), size=len(bad_y) // 2, replace=False)
                bad_y[flip_idx] = 1 - bad_y[flip_idx]
                bad_dtrain = xgb.DMatrix(data["X"], label=bad_y,
                                          feature_names=data["feature_names"])
                bad_booster = xgb.train(
                    params={"objective": "binary:logistic",
                             "max_depth": 4, "eta": 0.5, "verbosity": 0},
                    dtrain=bad_dtrain, num_boost_round=10,
                )
                dp_bytes = bad_booster.save_raw("json")

            # Trust manager validates against the held-out set
            accepted, trust_score, reason = trust_manager.validate_contribution(
                client_id=org_id, model_bytes=dp_bytes,
            )
            round_trust[org_id] = trust_score

            if accepted:
                # Reconstruct booster from DP'd bytes (could be a shifted version
                # of the original due to noise) and add to global ensemble
                accepted_booster = xgb.Booster()
                accepted_booster.load_model(bytearray(dp_bytes))
                accepted_models.append(accepted_booster)
                round_accepted.append(org_id)
                print(f"     ✓ {org_id:10s} accepted (trust={trust_score:.3f})")
            else:
                round_rejected.append({"org_id": org_id, "reason": reason,
                                        "trust": trust_score})
                print(f"     ✗ {org_id:10s} REJECTED (trust={trust_score:.3f}) — {reason}")

        # ── Aggregate: ensemble-average predictions of all accepted models ──
        if accepted_models:
            preds_per_model = [m.predict(val_dmatrix) for m in accepted_models]
            global_score = np.mean(preds_per_model, axis=0)
            global_auc = _roc_auc(val_y, global_score)
        else:
            global_auc = float("nan")

        round_record = {
            "round":            rnd,
            "global_auc":       round(global_auc, 4),
            "global_ensemble_size": len(accepted_models),
            "accepted":         round_accepted,
            "rejected":         round_rejected,
            "trust_scores":     {k: round(v, 3) for k, v in round_trust.items()},
        }
        round_history.append(round_record)
        print(f"   Round {rnd} global AUC = {global_auc:.4f}  "
              f"(ensemble of {len(accepted_models)} accepted models)")

    # ── Step 4: persist + plot ──────────────────────────────────────────────
    metrics = {
        "rounds":          round_history,
        "config": {
            "num_rounds":      num_rounds,
            "hours_per_org":   hours_per_org,
            "grouping":        grouping,
            "poison_round":    poison_round,
            "epsilon":         epsilon,
            "orgs":            list(ORG_PROFILES.keys()),
        },
        "final_trust_scores": {oid: round(rep.trust_score, 3)
                                 for oid, rep in trust_manager.clients.items()},
        "final_accepted_count": sum(rep.rounds_participated
                                      for rep in trust_manager.clients.values()),
    }
    json_path = out_dir / f"convergence_{int(time.time())}.json"
    json_path.write_text(json.dumps(metrics, indent=2, default=str))
    print(f"\n[4] Metrics → {json_path}")

    # Plot convergence (matplotlib if installed, else ASCII)
    plot_path = _plot_convergence(round_history, ORG_PROFILES.keys(),
                                    out_dir, poison_round)
    if plot_path:
        print(f"    Convergence plot → {plot_path}")

    # ── Step 5: summary ─────────────────────────────────────────────────────
    print(f"\n{'═'*65}")
    print(f"  SUMMARY")
    print(f"{'═'*65}")
    print(f"  Final global AUC:  {round_history[-1]['global_auc']}")
    print(f"  Final trust scores:")
    for oid, ts in metrics["final_trust_scores"].items():
        marker = "🚫" if ts < 0.3 else "✓"
        print(f"    {marker} {oid:10s} {ts:.3f}")

    return metrics


def _plot_convergence(rounds: list[dict], org_ids, out_dir: Path,
                      poison_round: Optional[int]) -> Optional[str]:
    """Try matplotlib; if unavailable, skip and return None."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    fig, (ax_top, ax_bot) = plt.subplots(2, 1, figsize=(9, 7), sharex=True,
                                            gridspec_kw={"height_ratios": [3, 2]})

    # Top: global AUC convergence
    rs    = [r["round"] for r in rounds]
    aucs  = [r["global_auc"] for r in rounds]
    ax_top.plot(rs, aucs, marker="o", linewidth=2, color="#1d4ed8",
                 label="global ensemble")
    ax_top.axhline(0.93, color="#dc2626", linestyle="--", alpha=0.6,
                    label="NFR-02 target (0.93)")
    ax_top.set_ylabel("ROC-AUC on validation set")
    ax_top.set_ylim(0.4, 1.02)
    ax_top.legend(loc="lower right")
    ax_top.grid(alpha=0.3)
    ax_top.set_title("Federated Learning convergence + trust dynamics")
    if poison_round:
        ax_top.axvline(poison_round, color="#ea580c", linestyle=":",
                        alpha=0.6, label=f"bank starts poisoning")
        ax_top.text(poison_round + 0.1, 0.45,
                     "← bank starts poisoning", color="#ea580c", fontsize=9)

    # Bottom: per-org trust scores
    for org_id in org_ids:
        scores = [r["trust_scores"].get(org_id, 1.0) for r in rounds]
        ax_bot.plot(rs, scores, marker="s", label=org_id, linewidth=1.5)
    ax_bot.axhline(0.3, color="#dc2626", linestyle="--", alpha=0.6,
                    label="block threshold (0.3)")
    ax_bot.set_xlabel("FL Round")
    ax_bot.set_ylabel("Trust score")
    ax_bot.set_ylim(0, 1.05)
    ax_bot.legend(loc="lower left", ncol=4, fontsize=8)
    ax_bot.grid(alpha=0.3)
    if poison_round:
        ax_bot.axvline(poison_round, color="#ea580c", linestyle=":", alpha=0.6)

    plot_path = out_dir / f"convergence_{int(time.time())}.png"
    fig.tight_layout()
    fig.savefig(plot_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(plot_path)


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="In-process FL demo + convergence graph")
    ap.add_argument("--num-rounds",     type=int, default=10)
    ap.add_argument("--hours-per-org",  type=int, default=12)
    ap.add_argument("--poison-round",   type=int, default=5,
                    help="Round at which 'bank' starts sending poisoned models. "
                         "Set to 0 to disable poisoning.")
    ap.add_argument("--epsilon",        type=float, default=1.0)
    ap.add_argument("--output-dir",     default="data/fl_demo")
    ap.add_argument("--seed",           type=int, default=42)
    args = ap.parse_args()

    setup_logging("WARNING")  # quieter — printing our own progress
    random.seed(args.seed)
    np.random.seed(args.seed)

    run_demo(
        num_rounds=args.num_rounds,
        hours_per_org=args.hours_per_org,
        poison_round=args.poison_round if args.poison_round > 0 else None,
        epsilon=args.epsilon,
        output_dir=args.output_dir,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
