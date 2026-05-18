# federated/coordinator_app.py
"""
FL Coordinator entry point.

Runs the FastAPI management API on the configured port (default 8889),
served separately from the org platform's API (8000). Configure via
env vars:

  FL_JWT_SECRET              — required, min 32 bytes recommended
  FL_USERS_FILE              — YAML with FL user roster (see config/fl_users.example.yml)
  FL_DATA_DIR                — base dir for coordinator DB + audit (default: data/fl_coordinator)
  FL_API_PORT                — default 8889
  FL_GRPC_PORT               — default 8888  (Flower server, separate process recommended)

This file deliberately does NOT import api/main.py or share any state with
the org platform. It can be deployed on a different host.
"""

import os
import sys
from pathlib import Path

import yaml
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from federated.ca                import load_ca, load_coordinator_keypair, load_crl
from federated.coordinator_api   import router as fl_router
from federated.coordinator_store import CoordinatorStore
from federated.fl_security       import FLAuthManager, FLRole, FLUser
from federated.mtls_middleware   import MTLSMiddleware
from observability.audit         import AuditTrail
from shared.logging              import get_logger, setup_logging

logger = get_logger("federated.coordinator_app")


def build_app() -> FastAPI:
    setup_logging("INFO")

    data_dir = os.environ.get("FL_DATA_DIR", "data/fl_coordinator")
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    # ── Load FL user roster ─────────────────────────────────────────────────
    users_file = os.environ.get("FL_USERS_FILE", "config/fl_users.yml")
    if Path(users_file).exists():
        with open(users_file) as f:
            sec = yaml.safe_load(f) or {}
        users = [
            FLUser(username=u["username"],
                   role=FLRole(u["role"]),
                   api_key_hash=u["api_key_hash"])
            for u in sec.get("users", [])
        ]
    else:
        logger.warning("FL_USERS_FILE missing — coordinator boots with no users",
                       path=users_file)
        users = []

    jwt_secret = os.environ.get("FL_JWT_SECRET", "")
    if not jwt_secret or len(jwt_secret) < 32:
        logger.warning(
            "FL_JWT_SECRET missing or short (<32 bytes). Rotate before production."
        )

    fl_auth_manager   = FLAuthManager(jwt_secret=jwt_secret, users=users)
    coordinator_store = CoordinatorStore(db_path=f"{data_dir}/coordinator.db")
    fl_audit_trail    = AuditTrail(db_path=f"{data_dir}/audit.db")

    # ── Load federation CA + coordinator's own keypair + CRL ────────────────
    ca_dir = os.environ.get("FL_CA_DIR", f"{data_dir}/ca")
    fl_ca_priv = fl_ca_cert = fl_coord_priv = fl_coord_cert = fl_crl = None
    if Path(ca_dir).exists() and (Path(ca_dir) / "ca_key.pem").exists():
        try:
            fl_ca_priv,    fl_ca_cert    = load_ca(ca_dir)
            fl_coord_priv, fl_coord_cert = load_coordinator_keypair(ca_dir)
            fl_crl = load_crl(ca_dir)
            logger.info("Federation CA + CRL loaded", ca_dir=ca_dir,
                        ca_subject=fl_ca_cert.subject.rfc4514_string(),
                        coord_subject=fl_coord_cert.subject.rfc4514_string())
        except Exception as e:
            logger.error("Failed to load CA — enrollment will return 503",
                         ca_dir=ca_dir, error=str(e))
    else:
        logger.warning("CA not initialised — run `python -m federated.init_fl_ca` "
                       "before enrolling orgs", ca_dir=ca_dir)

    fl_model_dir = os.environ.get("FL_MODEL_DIR", f"{data_dir}/models")
    Path(fl_model_dir).mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="APT Platform — FL Coordinator",
        description=(
            "Federated learning coordinator for cross-organization model "
            "aggregation. Separate trust boundary from any participating "
            "organization's platform."
        ),
        version="1.0.0",
    )
    app.state.fl_auth_manager   = fl_auth_manager
    app.state.coordinator_store = coordinator_store
    app.state.fl_audit_trail    = fl_audit_trail
    app.state.fl_ca_priv        = fl_ca_priv
    app.state.fl_ca_cert        = fl_ca_cert
    app.state.fl_coord_priv     = fl_coord_priv
    app.state.fl_coord_cert     = fl_coord_cert
    app.state.fl_crl            = fl_crl
    app.state.fl_model_dir      = fl_model_dir

    # mTLS middleware enriches every request with request.state.mtls_org_id
    # when a valid client cert is presented. Route dependencies decide
    # whether to require mTLS or fall back to the bootstrap API key.
    app.add_middleware(MTLSMiddleware)

    app.include_router(fl_router)

    @app.get("/")
    async def root():
        return {
            "service":    "fl-coordinator",
            "users_loaded": len(users),
            "active_orgs": sum(
                1 for o in coordinator_store.list_orgs() if o["status"] == "active"
            ),
        }

    logger.info(
        "FL coordinator initialised",
        data_dir=data_dir,
        users_loaded=len(users),
        api_port=int(os.environ.get("FL_API_PORT", 8889)),
    )
    return app


# Module-level instance so `uvicorn federated.coordinator_app:app` works
app = build_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("FL_API_PORT", 8889)),
    )
