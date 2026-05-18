#!/usr/bin/env python3
# training/train_models.py
"""
CLI: train both lateral_movement and dns_exfiltration models.

By default, generates synthetic training data and trains both models. Use
--from-jsonl to train from real captured events (one NormalizedEvent JSON
per line, with a top-level "_label" int field).

Usage:
    # Bootstrap models from synthetic data (one-shot demo)
    python -m training.train_models --hours 48 --seed 42

    # Train from real labeled events
    python -m training.train_models --from-jsonl ./data/labeled.jsonl

    # Generate synthetic data only (for inspection / FL partition seeding)
    python -m training.train_models --generate-only --output ./data/synthetic.jsonl
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Make `python -m training.train_models` work when invoked from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.auth_features       import AuthFeatureExtractor
from features.behavioral_features import BehavioralFeatureExtractor
from features.dns_features        import DnsFeatureExtractor
from features.network_features    import NetworkFeatureExtractor
from features.pipeline            import FeaturePipeline
from features.process_features    import ProcessFeatureExtractor
from features.temporal_features   import TemporalFeatureExtractor
from shared.logging               import setup_logging, get_logger
from shared.schemas               import NormalizedEvent
from training.trainer             import train_model

logger = get_logger("training.cli")


def build_pipeline() -> FeaturePipeline:
    """Same six extractors as api/main.py — train/serve parity."""
    p = FeaturePipeline()
    p.register_extractor(DnsFeatureExtractor())
    p.register_extractor(AuthFeatureExtractor())
    p.register_extractor(ProcessFeatureExtractor())
    p.register_extractor(NetworkFeatureExtractor())
    p.register_extractor(TemporalFeatureExtractor())
    p.register_extractor(BehavioralFeatureExtractor())
    return p


def load_jsonl(path: str) -> list[tuple[NormalizedEvent, int]]:
    """Load events from JSONL with a "_label" field on each line."""
    out: list[tuple[NormalizedEvent, int]] = []
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                label = int(obj.pop("_label", 0))
                out.append((NormalizedEvent(**obj), label))
            except Exception as e:
                logger.warning("Skipping malformed line", line_no=ln, error=str(e))
    return out


def write_jsonl(path: str, labeled: list[tuple[NormalizedEvent, int]]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for evt, lbl in labeled:
            obj = evt.model_dump(mode="json")
            obj["_label"] = lbl
            f.write(json.dumps(obj) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Train lateral_movement + dns_exfiltration models")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from-jsonl", help="Path to labeled NormalizedEvent JSONL")
    src.add_argument("--mordor-dir",
                     help="Path to Mordor / Security-Datasets directory tree")
    src.add_argument("--hours", type=int, default=24,
                     help="Synthetic-data duration in hours (default: 24)")
    ap.add_argument("--seed", type=int, default=42, help="RNG seed for synthetic data")
    ap.add_argument("--hosts", type=int, default=5, help="Number of hosts to simulate")
    ap.add_argument("--lateral-attacks", type=int, default=5, help="Per-day lateral attacks")
    ap.add_argument("--dns-attacks", type=int, default=5, help="Per-day DNS attacks")
    ap.add_argument("--add-synthetic-benign-hours", type=int, default=0,
                    help="With --mordor-dir: add N hours of synthetic benign "
                         "traffic to balance the negative class. Mordor data "
                         "is mostly attack-only, so the model needs background "
                         "noise to learn what 'normal' looks like.")
    ap.add_argument("--window-minutes", type=int, default=5)
    ap.add_argument("--num-boost-round", type=int, default=200)
    ap.add_argument("--params-json",
                    help="Path to a JSON file with XGBoost params (typically "
                         "produced by `python -m training.tuning`). The "
                         "'best_params' field is merged onto trainer defaults.")
    ap.add_argument("--output-dir", default="detection/models",
                    help="ModelStore base directory; models saved as "
                         "{output-dir}/{name}/v{ts}/{model.json,manifest.json}")
    ap.add_argument("--unsigned", action="store_true",
                    help="Skip ModelStore — write plain .json files (test/dev only)")
    ap.add_argument("--generate-only", action="store_true",
                    help="Only generate synthetic data; don't train")
    ap.add_argument("--output", default="data/synthetic.jsonl",
                    help="Output path for --generate-only")
    args = ap.parse_args()

    setup_logging("INFO")

    # ── 1. Load data ─────────────────────────────────────────────────────────
    if args.from_jsonl:
        logger.info("Loading labeled events from JSONL", path=args.from_jsonl)
        labeled = load_jsonl(args.from_jsonl)

    elif args.mordor_dir:
        from training.loaders.mordor import MordorLoader
        logger.info("Loading Mordor / Security-Datasets",
                    path=args.mordor_dir,
                    add_synthetic_benign_hours=args.add_synthetic_benign_hours)
        loader = MordorLoader()
        labeled = loader.load_path(args.mordor_dir)
        logger.info("Mordor load complete", **loader.stats)

        # Mordor data is heavily attack-skewed. Without enough negative-class
        # background, the model learns "anything that happens is attack".
        if args.add_synthetic_benign_hours > 0:
            from training.synthetic import generate_dataset
            synth = generate_dataset(
                duration_hours=args.add_synthetic_benign_hours,
                hosts=[f"BENIGN-{i:03d}" for i in range(1, args.hosts + 1)],
                lateral_attacks_per_day=0,   # NEGATIVES ONLY
                dns_attacks_per_day=0,
                seed=args.seed,
            )
            # Synthetic generator returns (event, 0) for everything when
            # attacks_per_day=0 — but make sure
            synth = [(e, 0) for e, _ in synth]
            labeled.extend(synth)
            logger.info("Synthetic benign added", events=len(synth))

    else:
        from training.synthetic import generate_dataset
        logger.info("Generating synthetic dataset",
                    hours=args.hours, hosts=args.hosts,
                    lateral_per_day=args.lateral_attacks,
                    dns_per_day=args.dns_attacks, seed=args.seed)
        labeled = generate_dataset(
            duration_hours=args.hours,
            hosts=[f"LAPTOP-{i:03d}" for i in range(1, args.hosts + 1)],
            lateral_attacks_per_day=args.lateral_attacks,
            dns_attacks_per_day=args.dns_attacks,
            seed=args.seed,
        )

    pos = sum(1 for _, l in labeled if l == 1)
    logger.info("Dataset loaded",
                events=len(labeled), positive_events=pos,
                positive_pct=round(pos / max(1, len(labeled)) * 100, 2))

    if args.generate_only:
        write_jsonl(args.output, labeled)
        logger.info("Synthetic data written", path=args.output)
        return 0

    # ── 2. Train each model with the SAME pipeline (train/serve parity) ──────
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pipeline = build_pipeline()

    # Load tuned params (if provided) — sklearn-style names map directly:
    #   learning_rate → eta (XGBoost native)
    extra_params: dict | None = None
    if args.params_json:
        tune_data = json.loads(Path(args.params_json).read_text())
        raw = tune_data.get("best_params", tune_data)
        # Normalise sklearn → XGBoost-native parameter names
        extra_params = {("eta" if k == "learning_rate" else k): v
                         for k, v in raw.items()}
        logger.info("Applying tuned params", params=extra_params)

    # ModelStore wires HMAC-signed manifests by default; --unsigned bypasses
    # for legacy/test workflows.
    store = None
    if not args.unsigned:
        from detection.model_store import ModelStore
        signing_key = os.environ.get("MODEL_SIGNING_KEY", "")
        if not signing_key:
            logger.warning(
                "MODEL_SIGNING_KEY not set — using empty key. "
                "Set this env var in production for meaningful integrity verification."
            )
        store = ModelStore(base_dir=str(out_dir), signing_key=signing_key)

    def _train(name: str, grouping: str) -> dict:
        if store:
            return train_model(
                labeled_events=labeled, pipeline=pipeline,
                model_store=store, model_name=name,
                window_minutes=args.window_minutes,
                grouping=grouping, num_boost_round=args.num_boost_round,
                extra_params=extra_params,
            )
        return train_model(
            labeled_events=labeled, pipeline=pipeline,
            output_path=str(out_dir / f"{name}_v1.json"),
            window_minutes=args.window_minutes,
            grouping=grouping, num_boost_round=args.num_boost_round,
            extra_params=extra_params,
        )

    # Lateral movement: group per (hostname, user) — credential-centric
    print()
    print("═══════════════════════════════════════════════════════════════")
    print("Training: lateral_movement")
    print("═══════════════════════════════════════════════════════════════")
    lat_metrics = _train("lateral_movement", "hostname_user")
    for k, v in lat_metrics.items():
        if k == "feature_names":
            print(f"  {k:20s}: ({len(v)} features)")
        else:
            print(f"  {k:20s}: {v}")

    # DNS exfiltration: group per hostname (DNS rarely has user attribution)
    print()
    print("═══════════════════════════════════════════════════════════════")
    print("Training: dns_exfiltration")
    print("═══════════════════════════════════════════════════════════════")
    dns_metrics = _train("dns_exfiltration", "hostname")
    for k, v in dns_metrics.items():
        if k == "feature_names":
            print(f"  {k:20s}: ({len(v)} features)")
        else:
            print(f"  {k:20s}: {v}")

    print()
    print("═══════════════════════════════════════════════════════════════")
    if store:
        print(f"Models saved (HMAC-signed) to {out_dir}/{{name}}/v{{ts}}/")
        print(f"  detector config should point to {out_dir}/<name>/latest")
    else:
        print(f"Models saved (UNSIGNED) to {out_dir}/")
    print("  Restart the AI Platform to load them via DetectionSubscriber.")
    print("═══════════════════════════════════════════════════════════════")
    return 0


if __name__ == "__main__":
    sys.exit(main())
