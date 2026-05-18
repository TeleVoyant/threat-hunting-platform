# detection/explainer.py
"""
SHAP-based detection explainer using XGBoost's TreeSHAP (built-in via
pred_contribs=True). No separate `shap` library dependency needed.

Each detection answers "WHY did the model fire?" by listing the top-K
features that pushed the prediction toward `attack`. Negative values
mean the feature pushed AWAY from attack (counter-evidence).

Used by every detector in detection/detectors/. The SHAP output goes
into Detection.contributing_features, which the dashboard renders next
to the alert and which the attack graph uses to label edges.
"""

from typing import Optional

import xgboost as xgb

from shared.logging import get_logger

logger = get_logger("detection.explainer")


class SHAPExplainer:
    """Computes per-feature contributions for a single prediction."""

    def __init__(self, top_k: int = 5):
        self.top_k = top_k

    def explain(
        self,
        booster: xgb.Booster,
        dmatrix: xgb.DMatrix,
        feature_names: Optional[list[str]] = None,
    ) -> dict[str, float]:
        """
        Return the top-K most influential features for this prediction.

        XGBoost's pred_contribs returns shape (n_samples, n_features + 1)
        where the last column is the bias/expected-value term. We drop
        that, pair contribs with feature names, sort by |contribution|,
        and return the top K as a dict.
        """
        try:
            contribs = booster.predict(dmatrix, pred_contribs=True)
        except Exception as e:
            logger.warning("SHAP computation failed", error=str(e))
            return {}

        # Single-sample inference path — take row 0
        if contribs.ndim != 2 or contribs.shape[0] == 0:
            return {}
        sample = contribs[0][:-1]   # drop bias term

        names = feature_names or booster.feature_names or [
            f"f{i}" for i in range(len(sample))
        ]
        if len(names) != len(sample):
            logger.warning(
                "Feature name count mismatch",
                names=len(names), shap=len(sample),
            )
            return {}

        # Sort by absolute contribution magnitude, take top K, preserve sign
        ranked = sorted(
            zip(names, sample),
            key=lambda kv: abs(float(kv[1])),
            reverse=True,
        )[: self.top_k]
        return {name: float(val) for name, val in ranked}
