# federated/trust.py
"""
FL Client Trust System.

Before accepting a client's tree contribution:
1. Validate tree structure (not corrupted)
2. Evaluate client's trees on a held-out validation set
3. Compare client performance to previous rounds (detect sudden degradation)
4. Score client reputation over time
5. Weight contributions by trust score (low-trust clients have less influence)
"""

import numpy as np
import xgboost as xgb
from dataclasses import dataclass, field
from shared.logging import get_logger

logger = get_logger("federated.trust")


@dataclass
class ClientReputation:
    client_id: str
    trust_score: float = 1.0  # 0.0 to 1.0 — starts trusted
    rounds_participated: int = 0
    performance_history: list = field(default_factory=list)
    violations: int = 0


class FLTrustManager:
    """
    Manages trust scores for FL clients.
    Implements contribution validation and reputation tracking.
    """

    def __init__(
        self,
        validation_data: xgb.DMatrix,  # Held-out validation set on FL server
        min_accuracy_threshold: float = 0.5,
        max_accuracy_drop_per_round: float = 0.15,
        min_trust_to_participate: float = 0.3,
    ):
        self.validation_data = validation_data
        self.min_accuracy = min_accuracy_threshold
        self.max_accuracy_drop = max_accuracy_drop_per_round
        self.min_trust = min_trust_to_participate
        self.clients: dict[str, ClientReputation] = {}

    def validate_contribution(
        self,
        client_id: str,
        model_bytes: bytes,
    ) -> tuple[bool, float, str]:
        """
        Validate a client's model contribution.

        Returns: (accepted: bool, trust_score: float, reason: str)
        """
        rep = self.clients.setdefault(client_id, ClientReputation(client_id=client_id))

        # ── Check 1: Can this client participate? ──
        if rep.trust_score < self.min_trust:
            logger.warning(
                "Client blocked — low trust", client=client_id, trust=rep.trust_score
            )
            return False, rep.trust_score, "Trust score below minimum"

        # ── Check 2: Validate model structure ──
        try:
            model = xgb.Booster()
            model.load_model(bytearray(model_bytes))
        except Exception as e:
            rep.violations += 1
            rep.trust_score = max(0.0, rep.trust_score - 0.2)
            logger.warning("Invalid model from client", client=client_id, error=str(e))
            return False, rep.trust_score, f"Invalid model structure: {e}"

        # ── Check 3: Evaluate on validation set ──
        try:
            preds = model.predict(self.validation_data)
            labels = self.validation_data.get_label()
            accuracy = float(np.mean((preds > 0.5).astype(int) == labels))
        except Exception as e:
            rep.violations += 1
            rep.trust_score = max(0.0, rep.trust_score - 0.1)
            return False, rep.trust_score, f"Model evaluation failed: {e}"

        # ── Check 4: Minimum accuracy ──
        if accuracy < self.min_accuracy:
            rep.violations += 1
            rep.trust_score = max(0.0, rep.trust_score - 0.15)
            logger.warning(
                "Client model below accuracy threshold",
                client=client_id,
                accuracy=accuracy,
                threshold=self.min_accuracy,
            )
            return (
                False,
                rep.trust_score,
                f"Accuracy {accuracy:.2%} below threshold {self.min_accuracy:.2%}",
            )

        # ── Check 5: Sudden accuracy drop (possible poisoning) ──
        if rep.performance_history:
            prev_accuracy = rep.performance_history[-1]
            drop = prev_accuracy - accuracy
            if drop > self.max_accuracy_drop:
                rep.violations += 1
                rep.trust_score = max(0.0, rep.trust_score - 0.2)
                logger.warning(
                    "Suspicious accuracy drop",
                    client=client_id,
                    prev=prev_accuracy,
                    current=accuracy,
                    drop=drop,
                )
                return False, rep.trust_score, f"Suspicious accuracy drop: {drop:.2%}"

        # ── Accepted — update reputation ──
        rep.rounds_participated += 1
        rep.performance_history.append(accuracy)
        # Slowly recover trust for consistently good clients
        rep.trust_score = min(1.0, rep.trust_score + 0.02)

        logger.info(
            "Contribution accepted",
            client=client_id,
            accuracy=accuracy,
            trust=rep.trust_score,
        )
        return True, rep.trust_score, "Accepted"

    def get_contribution_weight(self, client_id: str) -> float:
        """
        Weight for aggregation — higher trust = more influence.
        Used in weighted federated bagging.
        """
        rep = self.clients.get(client_id)
        if not rep:
            return 0.5  # Unknown client gets moderate weight
        return rep.trust_score
