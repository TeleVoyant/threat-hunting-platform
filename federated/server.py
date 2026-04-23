# federated/server.py
"""
Federated Learning Server
Aggregates XGBoost trees from multiple clients using federated bagging.
"""

import flwr as fl
from federated.aggregation import XGBoostFedBagging
from federated.config import load_fl_config


def start_fl_server():
    config = load_fl_config()

    strategy = XGBoostFedBagging(
        min_fit_clients=config.min_clients,
        min_available_clients=config.min_clients,
        num_rounds=config.num_rounds,
    )

    fl.server.start_server(
        server_address=f"0.0.0.0:{config.port}",
        config=fl.server.ServerConfig(num_rounds=config.num_rounds),
        strategy=strategy,
    )


if __name__ == "__main__":
    start_fl_server()
