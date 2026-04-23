"""
Differential privacy utilities for federated learning.

Adds noise to XGBoost tree structures before sending to FL server,
preventing reconstruction of training data from model updates.
"""

import json
import numpy as np
from shared.logging import get_logger

logger = get_logger("federated.privacy")


def apply_differential_privacy(model_raw_bytes: bytes, epsilon: float = 1.0) -> bytes:
    """
    Apply differential privacy to XGBoost model before sending to FL server.

    Strategy: Add calibrated Laplace noise to leaf values in the tree structure.
    Smaller epsilon = more privacy = more noise = less accuracy.
    Larger epsilon = less privacy = less noise = more accuracy.

    Args:
        model_raw_bytes: Raw bytes from model.save_raw("json")
        epsilon: Privacy budget (1.0 is a reasonable default)

    Returns:
        Modified model bytes with noisy leaf values
    """
    try:
        model_json = json.loads(model_raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Could not parse model as JSON, returning unmodified")
        return model_raw_bytes

    # Sensitivity: maximum change one data point can cause in a leaf value
    # For XGBoost with typical learning_rate=0.05, sensitivity ≈ 0.1
    sensitivity = 0.1

    # Laplace noise scale: sensitivity / epsilon
    scale = sensitivity / max(epsilon, 0.01)

    trees_modified = 0

    # Navigate the XGBoost JSON model structure
    if "learner" in model_json:
        gbm = model_json["learner"].get("gradient_booster", {})
        model_obj = gbm.get("model", {})
        trees = model_obj.get("trees", [])

        for tree in trees:
            # Each tree has leaf values stored in "split_conditions" for leaf nodes
            # or in a "leaf" field depending on XGBoost version
            if "split_conditions" in tree:
                conditions = tree["split_conditions"]
                left_children = tree.get("left_children", [])

                for i in range(len(conditions)):
                    # Leaf nodes have left_children[i] == -1
                    if i < len(left_children) and left_children[i] == -1:
                        noise = np.random.laplace(0, scale)
                        conditions[i] = float(conditions[i]) + noise

                trees_modified += 1

    logger.info(
        "Differential privacy applied",
        epsilon=epsilon,
        scale=round(scale, 4),
        trees_modified=trees_modified,
    )

    return json.dumps(model_json).encode()
