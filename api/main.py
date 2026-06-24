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
from fastapi.staticfiles import StaticFiles

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
        indexer=_config.wazuh.indexer_url,
        index_pattern=_config.wazuh.indexer.index_pattern,
        poll_interval=_config.platform.poll_interval_seconds,
    )

    # ── Initialize Wazuh Connector ──
    from ingestion.wazuh_connector import WazuhConnector

    # Ingestion reads endpoint telemetry from the Wazuh Indexer (OpenSearch),
    # not the Manager API (which has no /alerts endpoint). See config/wazuh.yaml
    # `indexer:` block -- switch index_pattern to wazuh-archives-* for the full
    # event stream once filebeat archive shipping is enabled.
    _wazuh = WazuhConnector(
        base_url=_config.wazuh.indexer_url,
        username=_config.wazuh.indexer.username,
        password=_config.wazuh.indexer.password,
        max_retries=_config.wazuh.api.max_retries,
        timeout_seconds=_config.wazuh.api.timeout_seconds,
        circuit_breaker_threshold=_config.wazuh.api.circuit_breaker_threshold,
        circuit_breaker_reset_seconds=_config.wazuh.api.circuit_breaker_reset_seconds,
        index_pattern=_config.wazuh.indexer.index_pattern,
        time_field=_config.wazuh.indexer.time_field,
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

    _win = _config.platform.event_window_minutes
    _feature_pipeline = FeaturePipeline()
    # DNS exfiltration detector consumes "dns" features only.
    _feature_pipeline.register_extractor(DnsFeatureExtractor(window_minutes=_win))
    # Lateral movement detector consumes auth + process + network + temporal + behavioral.
    _feature_pipeline.register_extractor(AuthFeatureExtractor(window_minutes=_win))
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
    detection_subscriber = DetectionSubscriber(
        _feature_pipeline,
        detector_config,
        drift_persistence_dir=f"{data_dir}/drift",
    )
    detection_subscriber.register()
    app.state.detection_subscriber = detection_subscriber

    # ── Attack graph subscriber (DETECTION_MADE → graph + HTML) ──
    from visualization.subscriber import GraphSubscriber

    graph_subscriber = GraphSubscriber(
        output_dir=f"{data_dir}/graphs",
        keep_snapshots=True,
    )
    graph_subscriber.register()
    app.state.graph_subscriber = graph_subscriber

    # ── Initialize Audit Trail (hash-chained) ──
    # Must be first — alert pipeline depends on it for immutable alert-logging.
    from observability.audit import AuditTrail

    audit_trail = AuditTrail(db_path=f"{data_dir}/audit/audit.db")

    # ── Alert pipeline: DETECTION_MADE → enrich → engine gate → store → publish ──
    from alert_manager.alert_engine import AlertEngine
    from alert_manager.store import AlertStore
    from alert_manager.subscriber import AlertSubscriber
    from alert_manager.wazuh_publisher import WazuhPublisher
    from threat_intel.enricher import ThreatIntelEnricher

    alert_store = AlertStore(db_path=f"{data_dir}/alerts/alerts.db")

    # MISP IoC correlation (FR-06) — file-mode by default; live MISP via env vars
    from threat_intel.misp_client import MispClient

    misp_client: "MispClient | None" = None
    if os.environ.get("MISP_ENABLED", "1") not in ("0", "false", "False"):
        try:
            mode = os.environ.get("MISP_MODE", "file").lower()
            misp_client = MispClient(
                mode=mode,
                path=os.environ.get("MISP_FILE_PATH", "threat_intel/iocs.json"),
                url=os.environ.get("MISP_URL", ""),
                api_key=os.environ.get("MISP_API_KEY", ""),
                verify_ssl=os.environ.get("MISP_VERIFY_SSL", "1") != "0",
                cache_ttl_seconds=int(os.environ.get("MISP_CACHE_TTL_SECONDS", "3600")),
            )
            logger.info(
                "MISP IoC client initialised", mode=mode, stats=misp_client.stats()
            )
        except Exception as e:
            logger.warning(
                "MISP client init failed — alerts won't have IoC matches", error=str(e)
            )
            misp_client = None

    enricher = ThreatIntelEnricher(misp_client=misp_client)
    wazuh_alert_path = os.environ.get(
        "WAZUH_ALERT_FILE",
        f"{data_dir}/alerts/wazuh_external.json",
    )
    publisher = WazuhPublisher(log_file_path=wazuh_alert_path)
    dedup_min = int(getattr(_config.platform, "alert_dedup_window_minutes", 30) or 30)
    alert_engine = AlertEngine(config={
        "min_confidence": float(os.environ.get("ALERT_MIN_CONFIDENCE", "0.45")),
    })
    alert_subscriber = AlertSubscriber(
        enricher=enricher,
        store=alert_store,
        publisher=publisher,
        audit=audit_trail,
        engine=alert_engine,
        dedup_window_minutes=dedup_min,
    )
    alert_subscriber.register()
    app.state.alert_store = alert_store

    # ── Initialize Auth Manager ──
    # For FYP, JWT secret + users come from env / config/security.yml.
    # In a real deploy these come from Docker secrets.
    import yaml
    from shared.security import AuthManager, User, Role

    # config/security.yml is the read-only seed (dashboard api_key_hash,
    # roles); data/security_overrides.yml carries the writable bits (phone,
    # email, mobile_api_key_hash from pairing). Merged so a restart preserves
    # both — without ever letting overrides clobber the dashboard credential
    # (decoupled in api/routes/auth.py + shared/security.py).
    from api.routes.admin import _read_security_yml
    from shared.config import _resolve_env_vars
    sec_data = _read_security_yml()
    # security.yml stores jwt_secret as the ${JWT_SECRET} placeholder so the real
    # secret never lives in the tracked config file — resolve it from the env
    # (genesis.py writes the value to .env). Unresolved/empty -> env -> hard default.
    jwt_secret = (
        _resolve_env_vars(sec_data.get("authentication", {}).get("jwt_secret") or "")
        or os.environ.get("JWT_SECRET")
        or "CHANGE-ME-IN-PRODUCTION"
    )
    users = [
        User(
            username=u["username"],
            role=Role(u["role"]),
            api_key_hash=u.get("api_key_hash", ""),
            mobile_api_key_hash=u.get("mobile_api_key_hash"),
            email=u.get("email"),
            phone=u.get("phone"),
        )
        for u in sec_data.get("users", [])
    ]
    auth_manager = AuthManager(jwt_secret=jwt_secret, users=users)

    # ── Notification system ────────────────────────────────────────────────
    # Loads config/notifications.yml (channel defaults, dedup window, daily SMS
    # cap, Beem sender id, dashboard URL). Stores config on app.state so admin
    # validation can consult `allow_international_phones`.
    notif_config_path = os.path.join(config_dir, "notifications.yml")
    notif_config: dict = {}
    if os.path.exists(notif_config_path):
        with open(notif_config_path) as f:
            notif_config = yaml.safe_load(f) or {}
    app.state.notifications_config = notif_config

    from observability.notifications import NotificationStore, NotificationService
    from observability.channels.sse import SSEBackend
    from alert_manager.notification_subscriber import NotificationSubscriber

    notification_store = NotificationStore(
        db_path=f"{data_dir}/notifications/notifications.db"
    )
    app.state.notification_store = notification_store

    # Paired-devices inventory — admin can review and unpair phones.
    from observability.paired_devices import PairedDevicesStore

    app.state.paired_devices = PairedDevicesStore(
        db_path=f"{data_dir}/notifications/paired_devices.db"
    )

    sse_backend = SSEBackend()
    app.state.sse_backend = sse_backend

    # Email backend (optional — only constructed if SMTP_HOST is set).
    from observability.channels.email import make_email_backend_from_env

    email_backend = make_email_backend_from_env(notif_config)
    app.state.email_backend = email_backend
    if email_backend:
        logger.info(
            "Email backend configured", host=email_backend.host, port=email_backend.port
        )

    # Beem Africa SMS backend (optional — only if BEEM_API_KEY + BEEM_SECRET_KEY set).
    from observability.channels.beem_sms import make_beem_backend_from_env

    sms_backend = make_beem_backend_from_env(notif_config)
    app.state.sms_backend = sms_backend
    if sms_backend:
        logger.info("Beem SMS backend configured", sender_id=sms_backend.sender_id)

    # dashboard_url priority:
    #   1. PUBLIC_HOST_URL env (injected by scripts/pair-up.sh — reflects the
    #      current WiFi IP, switches automatically when you join a new network)
    #   2. config/notifications.yml dashboard_url (stable override for prod)
    #   3. hard-coded localhost fallback (last resort, only useful on the
    #      platform laptop itself).
    _dashboard_url = (
        os.environ.get("PUBLIC_HOST_URL", "").strip()
        or notif_config.get("dashboard_url")
        or "http://localhost:8000"
    )
    logger.info("Notification dashboard URL resolved", url=_dashboard_url)
    notification_service = NotificationService(
        store=notification_store,
        auth_manager=auth_manager,
        sse=sse_backend,
        email=email_backend,
        sms=sms_backend,
        default_min_severity=notif_config.get("default_min_severity", "high"),
        dedup_window_minutes=int(notif_config.get("dedup_window_minutes", 5)),
        dashboard_url=_dashboard_url,
        max_sms_per_day=int(notif_config.get("max_sms_per_day", 200)),
    )
    app.state.notification_service = notification_service

    NotificationSubscriber(notification_service).register()
    logger.info(
        "Notification system online (SSE channel enabled)",
        db=f"{data_dir}/notifications/notifications.db",
    )

    # ── Initialize DNS allowlist + install as the live default ──
    # Graph builder + any future hot-path consumer reads from this store
    # via shared.allowlist.get_default() — admin add/remove operations
    # take effect immediately without restart.
    from shared.allowlist import DnsAllowlist, configure_default

    dns_allowlist = DnsAllowlist(db_path=f"{data_dir}/allowlist/dns.db")
    configure_default(dns_allowlist)
    app.state.dns_allowlist = dns_allowlist
    logger.info("DNS allowlist loaded", count=dns_allowlist.count())

    # ── Org-side FL state (THIS org only — never sees other orgs) ──
    from federated.local_state import LocalFLState

    fl_local_state = LocalFLState(db_path=f"{data_dir}/fl_local/state.db")
    app.state.fl_local_state = fl_local_state

    # ── Initialize Fleet Command Queue ──
    from api.command_queue import CommandQueue

    command_queue = CommandQueue(db_path=f"{data_dir}/fleet/fleet.db")
    logger.info(
        "Fleet command queue initialized",
        bootstrap_token_set=bool(os.environ.get("FLEET_BOOTSTRAP_TOKEN")),
    )

    # Single-use enrollment-token store for the URL-served installer.
    from api.enrollment_tokens import EnrollmentTokenStore
    enrollment_tokens = EnrollmentTokenStore(
        db_path=f"{data_dir}/fleet/enrollment_tokens.db",
    )
    logger.info("Enrollment token store initialized")

    # Handler-script version store for OTA updates of
    # scripts/agent_command_handler.ps1. Exposed on app.state so
    # api/routes/agent.py's manifest + content endpoints and
    # api/routes/admin.py's operator routes can reach it.
    from api.handler_store import HandlerVersionStore
    app.state.handler_store = HandlerVersionStore(
        db_path=f"{data_dir}/notifications/handler_versions.db",
    )
    logger.info("Handler version store initialized")

    # ── Jinja2 templates for dashboard ──
    from fastapi.templating import Jinja2Templates
    import time as _t_setup

    templates = Jinja2Templates(directory="api/templates")
    # Cache-bust query suffix tied to the platform's start time. Every
    # restart auto-invalidates the browser's cached app.js / styles.css so
    # an operator never sees stale UI after `docker compose up -d api`.
    templates.env.globals["cache_bust"] = int(_t_setup.time())

    # ── Store references on app state for route access ──
    app.state.wazuh = _wazuh
    app.state.config = _config
    app.state.health_checkers = {"wazuh_connector": _wazuh}
    app.state.audit_trail = audit_trail
    app.state.auth_manager = auth_manager
    app.state.command_queue = command_queue
    app.state.enrollment_tokens = enrollment_tokens
    app.state.templates = templates
    # Platform start time — surfaced as uptime on the topbar via /diag/uptime.
    import time as _time

    app.state.started_at = _time.time()

    # Expose preprocessor + feature pipeline so the retrain scheduler can
    # reuse them (avoids double-wiring the same extractors).
    app.state._preprocessor = _preprocessor
    app.state.preprocessor = _preprocessor  # public name for /diag routes
    app.state._feature_pipeline = _feature_pipeline

    # ── Start background detection loop ──
    detection_enabled = (
        os.environ.get("DETECTION_LOOP_ENABLED", "true").lower() == "true"
    )
    detection_task = None
    if detection_enabled:
        detection_task = asyncio.create_task(_detection_loop())
        logger.info("Detection loop started")
    else:
        logger.info("Detection loop DISABLED (api-only mode)")

    # ── FL participation poller ──────────────────────────────────────────────
    # Promotes federated global models past their soak window (auto hot-reload
    # as the live detector) and, in 'auto' mode, contributes the configured
    # detector when opted in. Cheap when FL is unconfigured (each tick no-ops).
    fl_task = None
    if os.environ.get("FL_PARTICIPATION_ENABLED", "true").lower() == "true":
        fl_task = asyncio.create_task(_fl_participation_loop(app))
        logger.info("FL participation poller started")

    # ── Auto-retrain scheduler ──────────────────────────────────────────────
    # Disabled by default — set RETRAIN_ENABLED=true to opt in. Interval is
    # configurable at runtime via POST /admin/retrain/interval (this env var
    # only seeds the initial value at boot).
    retrain_scheduler = None
    if os.environ.get("RETRAIN_ENABLED", "false").lower() == "true":
        from training.scheduler import AutoRetrainScheduler
        retrain_scheduler = AutoRetrainScheduler(
            app,
            # Default cadence: 24 h. Older 30-min default OOM-killed the api
            # container on tight memory budgets; tighten via the env var or
            # the dashboard at runtime when actively iterating.
            interval_seconds=int(os.environ.get("RETRAIN_INTERVAL_SECONDS", "86400")),
            # Default first-cycle delay: 1 h. Keeps the api responsive
            # through cold-start and avoids competing for RAM during boot.
            initial_delay_seconds=int(os.environ.get("RETRAIN_INITIAL_DELAY_SECONDS", "3600")),
            benign_window_hours=int(os.environ.get("RETRAIN_BENIGN_WINDOW_HOURS", "24")),
            lateral_attacks_per_day=int(os.environ.get("RETRAIN_LATERAL_ATTACKS_PER_DAY", "10")),
            dns_attacks_per_day=int(os.environ.get("RETRAIN_DNS_ATTACKS_PER_DAY", "8")),
            num_boost_round=int(os.environ.get("RETRAIN_NUM_BOOST_ROUND", "200")),
        )
        retrain_scheduler.start()
    app.state.retrain_scheduler = retrain_scheduler

    # Drift → retrain wiring (x). When a detector emits MODEL_DRIFT_DETECTED
    # we ask the scheduler to fire a retrain on the next tick. Without this
    # subscriber the drift event is a log-only signal that nobody acts on.
    if retrain_scheduler:
        from shared.events import bus as _bus, MODEL_DRIFT_DETECTED as _MDD

        async def _on_drift(payload: dict) -> None:
            det = (payload or {}).get("detector")
            logger.warning("Drift event → triggering retrain", detector=det)
            try:
                retrain_scheduler.trigger_now()
                app.state.audit_trail.log(
                    action="drift.auto_trigger_retrain", actor="platform",
                    target=det or "unknown",
                    details={"issues": (payload or {}).get("drift", {}).get("issues", [])},
                )
            except Exception as e:
                logger.error("Failed to trigger retrain from drift",
                             detector=det, error=str(e))

        _bus.subscribe(_MDD, _on_drift)

    yield  # ── App is running ──

    # ── Shutdown ──
    if retrain_scheduler:
        await retrain_scheduler.stop()
    if detection_task:
        detection_task.cancel()
        try:
            await detection_task
        except asyncio.CancelledError:
            pass
    if fl_task:
        fl_task.cancel()
        try:
            await fl_task
        except asyncio.CancelledError:
            pass
    logger.info("Platform shutdown complete")


async def _fl_participation_loop(app):
    """Background poller: auto-promote federated global models whose soak window
    elapsed (hot-reload as the live detector), and run automatic participation
    when the org opted into auto mode. No-ops cheaply when FL is unconfigured."""
    from detection.model_store import ModelStore
    from detection.registry import registry as _registry
    from federated import participation as _fp

    interval = int(os.environ.get("FL_PARTICIPATION_INTERVAL_SECONDS", "300"))
    verify_hours = float(os.environ.get("FL_GLOBAL_MODEL_VERIFY_HOURS", "24"))
    detectors = ("lateral_movement", "dns_exfiltration")
    state = getattr(app.state, "fl_local_state", None)
    while True:
        try:
            if state is not None:
                store = ModelStore(
                    base_dir=os.environ.get("MODEL_STORE_DIR", "detection/models"),
                    signing_key=os.environ.get("MODEL_SIGNING_KEY", ""))
                _fp.promote_due(store, _registry, detectors)
                _fp.run_auto_cycle(state, store, verify_hours=verify_hours)
        except Exception as e:
            logger.error("FL participation loop tick failed", error=str(e))
        await asyncio.sleep(interval)


async def _detection_loop():
    """
    Background task: polls Wazuh → buffers into a sliding window keyed by
    event_id → flushes window-aligned snapshots into the bus (a). Subscribers
    handle feature extraction + detection downstream.
    """
    from ingestion.sliding_window import SlidingWindowBuffer

    window_minutes = _config.platform.event_window_minutes
    buffer = SlidingWindowBuffer(window_minutes=window_minutes)
    # Expose for /diag so the operator can see buffer depth + last flush.
    app.state.sliding_window = buffer

    while True:
        try:
            cid = set_correlation_id()

            # Pull fresh events from Wazuh. We ask for `window_minutes` of
            # history every poll so the buffer dedupes overlap by event_id.
            raw_events = await _wazuh.fetch_recent_events(
                window_minutes=window_minutes,
            )
            if raw_events:
                events = _preprocessor.normalize_batch(raw_events)
                added = buffer.add_batch(events) if events else 0
                if added:
                    logger.info("Events buffered",
                                added=added, retained=buffer.size(),
                                correlation_id=cid)

            # Flush once per analytic window so feature extractors see the
            # full window's events at once. A poll-cadence flush would make
            # rate/CV features track polling, not the window.
            if buffer.due_to_flush():
                snapshot = buffer.snapshot()
                if snapshot:
                    logger.info("Flushing sliding window",
                                events=len(snapshot), correlation_id=cid)
                    await bus.emit(EVENT_INGESTED, {
                        "events": snapshot,
                        "correlation_id": cid,
                    })
                buffer.mark_flushed()

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
from fastapi import HTTPException
from fastapi.responses import RedirectResponse


@app.exception_handler(HTTPException)
async def _redirect_303_handler(request, exc: HTTPException):
    """When dashboard dep raises 303 (not authenticated) → real redirect."""
    if exc.status_code == 303 and "Location" in (exc.headers or {}):
        return RedirectResponse(
            url=exc.headers["Location"],
            status_code=303,
        )
    # Fall through to default handling
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers or {},
    )


from api.routes.health import router as health_router
from api.routes.models import router as models_router
from api.routes.fleet import router as fleet_router
from api.routes.agent import router as agent_router
from api.routes.alerts import router as alerts_router
from api.routes.allowlist import router as allowlist_router
from api.routes.fl_local import router as fl_local_router
from api.routes.audit import router as audit_router
from api.routes.admin import router as admin_router
from api.routes.diagnostics import router as diagnostics_router
from api.routes.notifications import router as notifications_router
from api.routes.me import router as me_router
from api.routes.downloads import router as downloads_router
from api.routes.install import router as install_router
from api.routes.auth import router as auth_router
from api.routes.dashboard import router as dashboard_router

app.include_router(health_router)
app.include_router(models_router)
app.include_router(fleet_router)  # admin: /fleet/* (JWT/API-key + manage_fleet)
app.include_router(agent_router)  # agent: /agents/* (per-agent HMAC)
app.include_router(
    alerts_router
)  # dashboard: /alerts/* (read_alerts / acknowledge_alerts)
app.include_router(allowlist_router)  # admin: /allowlist/dns/* (manage_detectors)
app.include_router(
    fl_local_router
)  # org admin: /fl/local/* (manage_fl_local) — NOT FL coordinator
app.include_router(audit_router)  # admin: /audit/* (view_audit_log)
app.include_router(admin_router)  # admin: /admin/* (manage_users)
app.include_router(diagnostics_router)  # /diag/* (read_detections)
app.include_router(notifications_router)  # /notifications/* (per-user)
app.include_router(me_router)  # /me/* (self-service contact info)
app.include_router(downloads_router)  # /downloads/* (companion .apk + QR)
app.include_router(install_router)  # /install/* (URL-served endpoint installer + tokens)
app.include_router(auth_router)  # /auth/login + /auth/logout (HTML + cookie)
app.include_router(dashboard_router)  # /dashboard/* (HTML, cookie auth)

# ── Static assets (design system + JS + CSS) ──
app.mount("/static", StaticFiles(directory="api/static"), name="static")


@app.get("/")
async def root():
    return {
        "name": "APT Threat Hunting Platform",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }
