"""Federated learning configuration loader."""

from shared.config import load_config


class FLConfig:
    """Typed FL config wrapper."""
    def __init__(self, port: int, num_rounds: int, min_clients: int,
                 epsilon: float, gradient_clipping: bool, max_grad_norm: float):
        self.port = port
        self.num_rounds = num_rounds
        self.min_clients = min_clients
        self.epsilon = epsilon
        self.gradient_clipping = gradient_clipping
        self.max_grad_norm = max_grad_norm


def load_fl_config(config_dir: str = "config") -> FLConfig:
    """Load FL config from federated.yaml via centralized config system."""
    cfg = load_config(config_dir)
    return FLConfig(
        port=cfg.federated.server.port,
        num_rounds=cfg.federated.server.num_rounds,
        min_clients=cfg.federated.server.min_clients,
        epsilon=cfg.federated.privacy.epsilon,
        gradient_clipping=cfg.federated.privacy.gradient_clipping,
        max_grad_norm=cfg.federated.privacy.max_grad_norm,
    )
