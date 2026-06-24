# federated/privacy.py
"""
Client-side differential privacy for this org's federated contributions.

Adds calibrated Laplace noise to the XGBoost leaf values BEFORE a model leaves
the org, so the coordinator (and anyone observing the channel) cannot reconstruct
training data from the shared parameters. Applied entirely on the org side — the
coordinator never sees the un-noised model. Smaller epsilon => more privacy =>
more noise => less accuracy.

Byte-compatible with the coordinator's reference client
(apt-fl-coordinator/client_ref/privacy.py): same leaf-perturbation, so a global
model bagged from DP-noised contributions stays loadable.
"""

import json

import numpy as np

from shared.logging import get_logger

logger = get_logger("federated.privacy")


def apply_differential_privacy(model_raw_bytes: bytes, epsilon: float = 1.0) -> bytes:
    """
    Apply epsilon-differential privacy to an XGBoost JSON model.

    Args:
        model_raw_bytes: bytes of an XGBoost model exported as JSON
            (booster.save_model("model.json")).
        epsilon: privacy budget (1.0 is a reasonable default per the proposal).

    Returns:
        Model bytes with Laplace-perturbed leaf values, re-serialised as JSON.
        Returns the input unchanged if it is not parseable JSON.
    """
    try:
        model_json = json.loads(model_raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("FL contribution is not JSON — returning unmodified (no DP applied)")
        return model_raw_bytes

    # Sensitivity: max change one data point can cause in a leaf value.
    sensitivity = 0.1
    scale = sensitivity / max(epsilon, 0.01)   # Laplace scale = sensitivity/epsilon

    trees_modified = 0
    if "learner" in model_json:
        gbm = model_json["learner"].get("gradient_booster", {})
        trees = gbm.get("model", {}).get("trees", [])
        for tree in trees:
            # Leaf nodes are where left_children[i] == -1; their value lives in
            # split_conditions[i] in current XGBoost JSON.
            if "split_conditions" in tree:
                conditions = tree["split_conditions"]
                left_children = tree.get("left_children", [])
                for i in range(len(conditions)):
                    if i < len(left_children) and left_children[i] == -1:
                        conditions[i] = float(conditions[i]) + float(np.random.laplace(0, scale))
                trees_modified += 1

    logger.info("Differential privacy applied to FL contribution",
                epsilon=epsilon, scale=round(scale, 4), trees=trees_modified)
    return json.dumps(model_json).encode()
