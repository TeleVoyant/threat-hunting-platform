# federated/client.py
"""
Federated Learning Client
Each client represents one organization/department.
Trains XGBoost locally on its own Wazuh data, sends tree structures (NOT raw data) to server.
"""

import flwr as fl
import xgboost as xgb
import numpy as np
from federated.privacy import apply_differential_privacy


class XGBoostFLClient(fl.client.Client):

    def __init__(self, local_data_path: str, params: dict):
        self.params = params
        self.local_dtrain = xgb.DMatrix(local_data_path)
        self.model = None

    def fit(self, ins: fl.common.FitIns) -> fl.common.FitRes:
        """Train XGBoost locally, return tree bytes."""

        # If global model exists from previous round, continue from it
        if ins.parameters.tensors:
            self.model = xgb.Booster()
            self.model.load_model(bytearray(ins.parameters.tensors[0]))

        # Train locally for a few rounds
        self.model = xgb.train(
            self.params,
            self.local_dtrain,
            num_boost_round=10,  # Local epochs
            xgb_model=self.model,  # Continue from global model
        )

        # Apply differential privacy to tree splits before sending
        model_bytes = apply_differential_privacy(
            self.model.save_raw("json"),
            epsilon=1.0,
        )

        return fl.common.FitRes(
            parameters=fl.common.ndarrays_to_parameters(
                [np.frombuffer(model_bytes, dtype=np.uint8)]
            ),
            num_examples=self.local_dtrain.num_row(),
            status=fl.common.Status(code=fl.common.Code.OK, message="OK"),
        )

    def evaluate(self, ins: fl.common.EvaluateIns) -> fl.common.EvaluateRes:
        """Evaluate global model on local test data."""
        model = xgb.Booster()
        model.load_model(bytearray(ins.parameters.tensors[0]))

        preds = model.predict(self.local_dtrain)
        # Return local accuracy
        labels = self.local_dtrain.get_label()
        accuracy = float(np.mean((preds > 0.5).astype(int) == labels))

        return fl.common.EvaluateRes(
            loss=1.0 - accuracy,
            num_examples=self.local_dtrain.num_row(),
            status=fl.common.Status(code=fl.common.Code.OK, message="OK"),
        )
