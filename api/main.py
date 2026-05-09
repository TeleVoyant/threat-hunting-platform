"""
FastAPI application — Platform API + Background Detection Loop.

This is the main server process. It:
1. Starts the FastAPI REST API (serves alerts, visualizations, health checks)
2. On startup, initializes all modules (Wazuh connector, feature pipeline, detectors)
3. Runs the detection loop as a background async task
"""

import os
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.config import load_config
from shared.logging import setup_logging, get_logger, set_correlation_id
from shared.events import bus, EVENT_INGESTED

logger = get_logger("api.main")


# ── Module references (initialized at startup) ──
_wazuh = None
_preprocessor = None
_feature_pipeline = None
_config = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown.
    Initializes all platform modules and starts the detection loop.
    """
    global _wazuh, _preprocessor, _feature_pipeline, _config

    config_dir = os.environ.get("CONFIG_DIR", "config")
    _config = load_config(config_dir)

    logger.info(
        "Platform starting",
        wazuh_host=_config.wazuh.manager.host,
        poll_interval=_config.platform.poll_interval_seconds,
    )

    # ── Initialize Wazuh Connector ──
    from ingestion.wazuh_connector import WazuhConnector
    _wazuh = WazuhConnector(
        base_url=_config.wazuh.base_url,
        username=_config.wazuh.credentials.username,
        password=_config.wazuh.credentials.password,
        max_retries=_config.wazuh.api.max_retries,
        timeout_seconds=_config.wazuh.api.timeout_seconds,
        circuit_breaker_threshold=_config.wazuh.api.circuit_breaker_threshold,
        circuit_breaker_reset_seconds=_config.wazuh.api.circuit_breaker_reset_seconds,
    )

    # ── Initialize Preprocessor ──
    from ingestion.preprocessor import EventPreprocessor
    from ingestion.dead_letter import DeadLetterQueue

    data_dir = os.environ.get("DATA_DIR", "data")
    dlq = DeadLetterQueue(storage_dir=f"{data_dir}/dead_letter")
    _preprocessor = EventPreprocessor(dead_letter=dlq)

    # ── Initialize Feature Pipeline ──
    from features.pipeline import FeaturePipeline
    from features.dns_features import DnsFeatureExtractor
    from features.auth_features import AuthFeatureExtractor
    from features.process_features import ProcessFeatureExtractor
    from features.network_features import NetworkFeatureExtractor
    from features.temporal_features import TemporalFeatureExtractor
    from features.behavioral_features import BehavioralFeatureExtractor

    _feature_pipeline = FeaturePipeline()
    # DNS exfiltration detector consumes "dns" features only.
    _feature_pipeline.register_extractor(DnsFeatureExtractor())
    # Lateral movement detector consumes auth + process + network + temporal + behavioral.
    _feature_pipeline.register_extractor(AuthFeatureExtractor())
    _feature_pipeline.register_extractor(ProcessFeatureExtractor())
    _feature_pipeline.register_extractor(NetworkFeatureExtractor())
    _feature_pipeline.register_extractor(TemporalFeatureExtractor())
    _feature_pipeline.register_extractor(BehavioralFeatureExtractor())
    logger.info(
        "Feature pipeline initialized",
        extractors=[ex.name() for ex in _feature_pipeline._extractors],
    )

    # ── Initialize Detection Engine ──
    from detection.registry import registry
    registry.discover_and_load("detection.detectors")
    logger.info("Detectors loaded", detectors=registry.list_names())

    # ── Wire detection subscriber to the event bus ──
    # This is the missing link: the loop emits EVENT_INGESTED but nothing
    # subscribed before. The subscriber runs the full feature pipeline and
    # detector chain whenever a new batch arrives.
    from detection.subscriber import DetectionSubscriber
    detector_config = {}
    detectors_yml = os.path.join(config_dir, "detectors.yml")
    if os.path.exists(detectors_yml):
        with open(detectors_yml) as f:
            import yaml as _yaml
            detector_config = (_yaml.safe_load(f) or {}).get("detectors", {})
    detection_subscriber = DetectionSubscriber(_feature_pipeline, detector_config)
    detection_subscriber.register()

    # ── Alert pipeline: DETECTION_MADE → enrich → store → publish ──
    from alert_manager.store           import AlertStore
    from alert_manager.subscriber      import AlertSubscriber
    from alert_manager.wazuh_publisher import WazuhPublisher
    from threat_intel.enricher         import ThreatIntelEnricher

    alert_store = AlertStore(db_path=f"{data_dir}/alerts/alerts.db")
    enricher    = ThreatIntelEnricher()
    wazuh_alert_path = os.environ.get(
        "WAZUH_ALERT_FILE",
        f"{data_dir}/alerts/wazuh_external.json",
    )
    publisher = WazuhPublisher(log_file_path=wazuh_alert_path)
    dedup_min = int(getattr(_config.platform, "alert_dedup_window_minutes", 30) or 30)
    alert_subscriber = AlertSubscriber(
        enricher=enricher, store=alert_store, publisher=publisher,
        audit=audit_trail, dedup_window_minutes=dedup_min,
    )
    alert_subscriber.register()
    app.state.alert_store = alert_store

    # ── Initialize Audit Trail (hash-chained) ──
    from observability.audit import AuditTrail
    audit_trail = AuditTrail(db_path=f"{data_dir}/audit/audit.db")

    # ── Initialize Auth Manager ──
    # For FYP, JWT secret + users come from env / config/security.yml.
    # In a real deploy these come from Docker secrets.
    import yaml
    from shared.security import AuthManager, User, Role
    sec_config_path = os.path.join(config_dir, "security.yml")
    if os.path.exists(sec_config_path):
        with open(sec_config_path) as f:
            sec_data = yaml.safe_load(f) or {}
    else:
        sec_data = {}
    jwt_secret = (sec_data.get("authentication", {}).get("jwt_secret")
                  or os.environ.get("JWT_SECRET")
                  or "CHANGE-ME-IN-PRODUCTION")
    users = [
        User(username=u["username"], role=Role(u["role"]),
             api_key_hash=u.get("api_key_hash", ""))
        for u in sec_data.get("users", [])
    ]
    auth_manager = AuthManager(jwt_secret=jwt_secret, users=users)

    # ── Initialize Fleet Command Queue ──
    from api.command_queue import CommandQueue
    command_queue = CommandQueue(db_path=f"{data_dir}/fleet/fleet.db")
    logger.info(
        "Fleet command queue initialized",
        bootstrap_token_set=bool(os.environ.get("FLEET_BOOTSTRAP_TOKEN")),
    )

    # ── Store references on app state for route access ──
    app.state.wazuh = _wazuh
    app.state.config = _config
    app.state.health_checkers = {"wazuh_connector": _wazuh}
    app.state.audit_trail = audit_trail
    app.state.auth_manager = auth_manager
    app.state.command_queue = command_queue

    # ── Start background detection loop ──
    detection_enabled = os.environ.get("DETECTION_LOOP_ENABLED", "true").lower() == "true"
    detection_task = None
    if detection_enabled:
        detection_task = asyncio.create_task(_detection_loop())
        logger.info("Detection loop started")
    else:
        logger.info("Detection loop DISABLED (api-only mode)")

    yield  # ── App is running ──

    # ── Shutdown ──
    if detection_task:
        detection_task.cancel()
        try:
            await detection_task
        except asyncio.CancelledError:
            pass
    logger.info("Platform shutdown complete")


async def _detection_loop():
    """
    Background task: polls Wazuh → extracts features → runs detectors → publishes alerts.
    Runs continuously until the server shuts down.
    """
    while True:
        try:
            cid = set_correlation_id()

            # Step 1: Fetch events from Wazuh
            raw_events = await _wazuh.fetch_recent_events(
                window_minutes=_config.platform.event_window_minutes,
            )

            if not raw_events:
                await asyncio.sleep(_config.platform.poll_interval_seconds)
                continue

            # Step 2: Preprocess and validate
            events = _preprocessor.normalize_batch(raw_events)

            if not events:
                await asyncio.sleep(_config.platform.poll_interval_seconds)
                continue

            logger.info("Events ingested", count=len(events), correlation_id=cid)

            # Step 3: Publish to event bus (subscribers handle the rest)
            await bus.emit(EVENT_INGESTED, {
                "events": events,
                "correlation_id": cid,
            })

        except asyncio.CancelledError:
            logger.info("Detection loop cancelled")
            break
        except Exception as e:
            logger.error("Detection loop error", error=str(e))

        await asyncio.sleep(_config.platform.poll_interval_seconds)


# ── FastAPI App ──
app = FastAPI(
    title="APT Threat Hunting Platform",
    description="AI-driven detection of credential-based lateral movement and covert DNS exfiltration",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS (allow Wazuh Dashboard and attack graph viz to call the API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include route modules ──
from api.routes.health import router as health_router
from api.routes.models import router as models_router
from api.routes.fleet  import router as fleet_router
from api.routes.agent  import router as agent_router
from api.routes.alerts import router as alerts_router

app.include_router(health_router)
app.include_router(models_router)
app.include_router(fleet_router)   # admin: /fleet/* (JWT/API-key + manage_fleet)
app.include_router(agent_router)   # agent: /agents/* (per-agent HMAC)
app.include_router(alerts_router)  # dashboard: /alerts/* (read_alerts / acknowledge_alerts)


@app.get("/")
async def root():
    return {
        "name": "APT Threat Hunting Platform",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }
