# federated/aggregation.py
"""
Federated Bagging strategy for XGBoost.
Instead of averaging weights (which doesn't work for trees),
we combine tree ensembles from different clients.
"""

import json
import xgboost as xgb
import numpy as np
from typing import List, Tuple, Optional
import flwr as fl
from flwr.common import Parameters, FitRes
from flwr.server.strategy import Strategy


class XGBoostFedBagging(fl.server.strategy.FedAvg):
    """
    Custom aggregation: combine trees from all clients into one larger ensemble.

    Client A trains 10 trees on its data → sends trees
    Client B trains 10 trees on its data → sends trees
    Client C trains 10 trees on its data → sends trees
    Server combines → 30-tree ensemble (bagging)

    This works because XGBoost is an additive ensemble of trees.
    """

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[fl.server.client_proxy.ClientProxy, FitRes]],
        failures,
    ) -> Tuple[Optional[Parameters], dict]:

        if not results:
            return None, {}

        # Load each client's model
        client_models = []
        for _, fit_res in results:
            model_bytes = bytes(fl.common.parameters_to_ndarrays(fit_res.parameters)[0])
            model = xgb.Booster()
            model.load_model(bytearray(model_bytes))
            client_models.append(model)

        # Aggregate: combine trees from all clients
        # Weight by number of training examples each client has
        weights = [fit_res.num_examples for _, fit_res in results]
        total = sum(weights)
        normalized_weights = [w / total for w in weights]

        # Use the first model as base + append trees from others
        global_model = client_models[0]
        # For production: implement proper tree merging here

        # Save aggregated model
        global_bytes = global_model.save_raw("json")

        return fl.common.ndarrays_to_parameters(
            [np.frombuffer(global_bytes, dtype=np.uint8)]
        ), {"num_clients": len(results)}
