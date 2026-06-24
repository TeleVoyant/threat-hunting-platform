"""
Centralized configuration loader.

Loads YAML configs, resolves environment variable references (${VAR_NAME}),
and provides typed access to all platform settings.

Usage:
    from shared.config import load_config
    cfg = load_config()
    print(cfg.wazuh.manager.host)
    print(cfg.platform.poll_interval_seconds)
"""

import os
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


def _resolve_env_vars(value):
    """Replace ${VAR_NAME} with environment variable values."""
    if isinstance(value, str):
        pattern = re.compile(r'\$\{(\w+)\}')
        def replacer(match):
            var_name = match.group(1)
            env_val = os.environ.get(var_name, "")
            # Also check Docker secrets path
            secret_path = f"/run/secrets/{var_name.lower()}"
            if not env_val and os.path.exists(secret_path):
                env_val = open(secret_path).read().strip()
            return env_val
        return pattern.sub(replacer, value)
    elif isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_resolve_env_vars(v) for v in value]
    return value


def _load_yaml(path: str) -> dict:
    """Load a YAML file and resolve env vars."""
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(filepath) as f:
        data = yaml.safe_load(f) or {}
    return _resolve_env_vars(data)


@dataclass
class WazuhManagerConfig:
    host: str = "localhost"
    api_port: int = 55000
    api_protocol: str = "https"
    agent_port: int = 1514


@dataclass
class WazuhCredentials:
    username: str = "wazuh-wui"
    password: str = ""


@dataclass
class WazuhApiConfig:
    verify_ssl: bool = False
    timeout_seconds: int = 30
    max_retries: int = 3
    circuit_breaker_threshold: int = 5
    circuit_breaker_reset_seconds: int = 60


@dataclass
class WazuhIndexerConfig:
    # The platform pulls endpoint telemetry from the Wazuh Indexer (OpenSearch),
    # NOT the Manager API (port 55000 has no /alerts endpoint). index_pattern
    # selects the source: "wazuh-alerts-4.x-*" = rule-matched events only;
    # "wazuh-archives-4.x-*" = full event stream (needs filebeat archives on).
    host: str = "wazuh.indexer"
    port: int = 9200
    scheme: str = "https"
    username: str = "admin"
    password: str = ""
    index_pattern: str = "wazuh-alerts-4.x-*"
    time_field: str = "timestamp"


@dataclass
class WazuhConfig:
    manager: WazuhManagerConfig = field(default_factory=WazuhManagerConfig)
    credentials: WazuhCredentials = field(default_factory=WazuhCredentials)
    api: WazuhApiConfig = field(default_factory=WazuhApiConfig)
    indexer: WazuhIndexerConfig = field(default_factory=WazuhIndexerConfig)

    @property
    def base_url(self) -> str:
        return f"{self.manager.api_protocol}://{self.manager.host}:{self.manager.api_port}"

    @property
    def indexer_url(self) -> str:
        return f"{self.indexer.scheme}://{self.indexer.host}:{self.indexer.port}"


@dataclass
class PlatformConfig:
    name: str = "APT Threat Hunting Platform"
    version: str = "1.0.0"
    poll_interval_seconds: int = 120
    event_window_minutes: int = 5


@dataclass
class FederatedServerConfig:
    port: int = 8888
    num_rounds: int = 10
    min_clients: int = 2


@dataclass
class FederatedPrivacyConfig:
    differential_privacy: bool = True
    epsilon: float = 1.0
    gradient_clipping: bool = True
    max_grad_norm: float = 1.0


@dataclass
class FederatedConfig:
    enabled: bool = True
    server: FederatedServerConfig = field(default_factory=FederatedServerConfig)
    privacy: FederatedPrivacyConfig = field(default_factory=FederatedPrivacyConfig)


@dataclass
class AppConfig:
    """Root config object — access everything from here."""
    platform: PlatformConfig = field(default_factory=PlatformConfig)
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    federated: FederatedConfig = field(default_factory=FederatedConfig)


def _dict_to_dataclass(cls, data: dict):
    """Recursively convert nested dicts to dataclass instances."""
    if not isinstance(data, dict):
        return data
    field_types = {f.name: f.type for f in cls.__dataclass_fields__.values()} if hasattr(cls, '__dataclass_fields__') else {}
    kwargs = {}
    for key, val in data.items():
        if key in field_types:
            ft = field_types[key]
            # If the field type is itself a dataclass, recurse
            if hasattr(ft, '__dataclass_fields__') and isinstance(val, dict):
                kwargs[key] = _dict_to_dataclass(ft, val)
            else:
                kwargs[key] = val
        else:
            kwargs[key] = val
    return cls(**{k: v for k, v in kwargs.items() if k in (field_types or {})})


def load_config(config_dir: str = "config") -> AppConfig:
    """
    Load all platform configuration from YAML files.

    Args:
        config_dir: Path to the config/ directory (relative to project root or absolute)

    Returns:
        AppConfig with all settings loaded and env vars resolved
    """
    config_path = Path(config_dir)
    cfg = AppConfig()

    # Load platform.yaml
    platform_file = config_path / "platform.yaml"
    if not platform_file.exists():
        platform_file = config_path / "platform.yml"
    if platform_file.exists():
        data = _load_yaml(str(platform_file))
        p = data.get("platform", {})
        cfg.platform = PlatformConfig(**{k: v for k, v in p.items() if hasattr(PlatformConfig, k)})

    # Load wazuh.yaml
    wazuh_file = config_path / "wazuh.yaml"
    if not wazuh_file.exists():
        wazuh_file = config_path / "wazuh.yml"
    if wazuh_file.exists():
        data = _load_yaml(str(wazuh_file))
        w = data.get("wazuh", {})
        mgr = w.get("manager", {})
        cred = w.get("credentials", {})
        api = w.get("api", {})
        idx = w.get("indexer", {})
        cfg.wazuh = WazuhConfig(
            manager=WazuhManagerConfig(**{k: v for k, v in mgr.items() if hasattr(WazuhManagerConfig, k)}),
            credentials=WazuhCredentials(**{k: v for k, v in cred.items() if hasattr(WazuhCredentials, k)}),
            api=WazuhApiConfig(**{k: v for k, v in api.items() if hasattr(WazuhApiConfig, k)}),
            indexer=WazuhIndexerConfig(**{k: v for k, v in idx.items() if hasattr(WazuhIndexerConfig, k)}),
        )

    # Load federated.yaml
    fed_file = config_path / "federated.yaml"
    if not fed_file.exists():
        fed_file = config_path / "federated.yml"
    if fed_file.exists():
        data = _load_yaml(str(fed_file))
        fl = data.get("federated_learning", {})
        srv = fl.get("server", {})
        prv = fl.get("privacy", {})
        cfg.federated = FederatedConfig(
            enabled=fl.get("enabled", True),
            server=FederatedServerConfig(**{k: v for k, v in srv.items() if hasattr(FederatedServerConfig, k)}),
            privacy=FederatedPrivacyConfig(**{k: v for k, v in prv.items() if hasattr(FederatedPrivacyConfig, k)}),
        )

    return cfg
