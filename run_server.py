#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   APT Threat Hunting Platform — Central Server Entry Point   ║
║                                                              ║
║   This is how you run the server:                            ║
║     python run_server.py                                     ║
║     python run_server.py --config-dir /path/to/config        ║
║     python run_server.py --mode api-only                     ║
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

EXAMPLES:
  # Run full platform (for production/demo):
  python run_server.py

  # Run with custom config directory:
  python run_server.py --config-dir /etc/threat-platform/config

  # Run only the API (for development):
  python run_server.py --mode api-only --reload
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["full", "api-only"],
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
    ║   Mode: {args.mode:<44}                     ║
    ║   Config: {args.config_dir:<42}         ║
    ╚══════════════════════════════════════════════════════╝
    """)

    mode_handlers = {
        "full": run_full,
        "api-only": run_api_only,
    }

    handler = mode_handlers[args.mode]
    handler(args)


if __name__ == "__main__":
    main()
