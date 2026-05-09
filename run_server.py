#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   APT Threat Hunting Platform — Central Server Entry Point   ║
║                                                              ║
║   This is how you run the server:                            ║
║     python run_server.py                                     ║
║     python run_server.py --config-dir /path/to/config        ║
║     python run_server.py --mode api-only                     ║
║     python run_server.py --mode fl-server                    ║
║                                                              ║
║   Or via Docker:                                             ║
║     docker compose up -d                                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio
import os
import sys
import signal
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)


def parse_args():
    parser = argparse.ArgumentParser(
        description="APT Threat Hunting Platform — Central Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES:
  full        Run everything: API + detection loop + visualization (default)
  api-only    Run only the FastAPI server (no detection loop)
  fl-server   Run only the Federated Learning server
  fl-client   Run only the Federated Learning client

EXAMPLES:
  # Run full platform (for production/demo):
  python run_server.py

  # Run with custom config directory:
  python run_server.py --config-dir /etc/threat-platform/config

  # Run only the API (for development):
  python run_server.py --mode api-only --reload

  # Run FL server separately:
  python run_server.py --mode fl-server

  # Run FL client pointed at FL server:
  python run_server.py --mode fl-client --fl-server-address 192.168.1.100:8888
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["full", "api-only", "fl-server", "fl-client"],
        default="full",
        help="What to run (default: full)",
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help="Path to config/ directory (default: config)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="API server bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API server port (default: 8000)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--fl-server-address",
        default="localhost:8888",
        help="FL server address for fl-client mode",
    )
    parser.add_argument(
        "--fl-client-name",
        default=None,
        help="FL client name (default: hostname)",
    )
    parser.add_argument(
        "--fl-data-path",
        default=None,
        help="Path to local training data for FL client",
    )
    return parser.parse_args()


def run_full(args):
    """Run the complete platform: API + detection loop + visualization."""
    import uvicorn
    from shared.logging import setup_logging, get_logger
    from shared.config import load_config

    setup_logging(args.log_level)
    logger = get_logger("platform")

    cfg = load_config(args.config_dir)
    logger.info(
        "Starting platform",
        mode="full",
        wazuh_host=cfg.wazuh.manager.host,
        api_port=args.port,
    )

    # The FastAPI app in api/main.py starts the detection loop as a background task
    uvicorn.run(
        "api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level.lower(),
    )


def run_api_only(args):
    """Run only the API server (no background detection loop)."""
    import uvicorn
    from shared.logging import setup_logging

    setup_logging(args.log_level)

    # Set env var to tell api/main.py NOT to start the detection loop
    os.environ["DETECTION_LOOP_ENABLED"] = "false"

    uvicorn.run(
        "api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level.lower(),
    )


def run_fl_server(args):
    """Run the Federated Learning server."""
    from shared.logging import setup_logging, get_logger
    from shared.config import load_config

    setup_logging(args.log_level)
    logger = get_logger("fl.server")

    cfg = load_config(args.config_dir)
    fl_port = cfg.federated.server.port

    logger.info(
        "Starting FL Server", port=fl_port, min_clients=cfg.federated.server.min_clients
    )

    from federated.server import start_fl_server

    start_fl_server()


def run_fl_client(args):
    """Run a Federated Learning client."""
    import socket
    from shared.logging import setup_logging, get_logger

    setup_logging(args.log_level)
    logger = get_logger("fl.client")

    client_name = args.fl_client_name or socket.gethostname()
    data_path = args.fl_data_path

    if not data_path:
        logger.error("--fl-data-path is required for fl-client mode")
        sys.exit(1)

    logger.info(
        "Starting FL Client",
        name=client_name,
        server=args.fl_server_address,
        data_path=data_path,
    )

    import flwr as fl
    from federated.client import XGBoostFLClient

    xgb_params = {
        "objective": "binary:logistic",
        "eval_metric": "auc",
        "max_depth": 8,
        "learning_rate": 0.05,
    }

    client = XGBoostFLClient(local_data_path=data_path, params=xgb_params)
    fl.client.start_client(
        server_address=args.fl_server_address,
        client=client,
    )


def main():
    args = parse_args()

    # Load .env file if present
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        from dotenv import load_dotenv

        load_dotenv(env_file)

    print(f"""
    ╔══════════════════════════════════════════════════════╗
    ║   APT Threat Hunting Platform v1.0.0                 ║
    ║   Mode: {args.mode:<44}                              ║
    ║   Config: {args.config_dir:<42}                      ║
    ╚══════════════════════════════════════════════════════╝
    """)

    mode_handlers = {
        "full": run_full,
        "api-only": run_api_only,
        "fl-server": run_fl_server,
        "fl-client": run_fl_client,
    }

    handler = mode_handlers[args.mode]
    handler(args)


if __name__ == "__main__":
    main()
