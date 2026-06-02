# ingestion/wazuh_connector.py — WITH RESILIENCE
"""
Wazuh API connector with:
- Automatic retry with exponential backoff
- Circuit breaker (stop hammering a down server)
- Connection pooling
- Timeout enforcement
"""

import asyncio
import os
import time
from enum import Enum
from typing import Optional

import httpx
from shared.logging import get_logger
from shared.health import HealthCheckable, ComponentHealth, HealthStatus

logger = get_logger("ingestion.wazuh_connector")


class CircuitState(str, Enum):
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing — stop trying
    HALF_OPEN = "half_open"  # Testing if recovered


class WazuhConnector(HealthCheckable):

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        max_retries: int = 3,
        timeout_seconds: int = 30,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_reset_seconds: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.max_retries = max_retries
        self.timeout = timeout_seconds

        # Circuit breaker state
        self._circuit_state = CircuitState.CLOSED
        self._failure_count = 0
        self._cb_threshold = circuit_breaker_threshold
        self._cb_reset_time = circuit_breaker_reset_seconds
        self._last_failure_time = 0.0

        # TLS verification (cc): pin a CA when WAZUH_CA_PATH is set, otherwise
        # accept the self-signed cert the Docker stack ships with.
        ca_path = os.environ.get("WAZUH_CA_PATH", "").strip()
        verify: object = ca_path if ca_path else False

        # Connection pool
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            verify=verify,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        self._token: Optional[str] = None
        self._token_expiry: float = 0

        # Metrics
        self._total_requests = 0
        self._total_failures = 0
        self._last_latency = 0.0

        # Auth-failure cooldown (bb): when /security/user/authenticate keeps
        # returning 401/403, hammering it every poll just locks the account
        # out. Cool down separately and longer than the HTTP-failure breaker.
        self._auth_failures = 0
        self._auth_cooldown_until: float = 0.0
        self._auth_cooldown_seconds = 300  # 5 min after 3 consecutive auth fails

    async def fetch_recent_events(self, window_minutes: int = 5) -> list[dict]:
        """Fetch events from Wazuh API with retry and circuit breaker."""

        # ── Circuit breaker check ──
        if self._circuit_state == CircuitState.OPEN:
            if time.time() - self._last_failure_time > self._cb_reset_time:
                self._circuit_state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker half-open, testing connection")
            else:
                logger.warning("Circuit breaker OPEN, skipping Wazuh request")
                return []

        # ── Retry loop ──
        for attempt in range(self.max_retries):
            try:
                start = time.time()
                await self._ensure_token()

                response = await self._client.get(
                    "/alerts",
                    headers={"Authorization": f"Bearer {self._token}"},
                    params={
                        "offset": 0,
                        "limit": 10000,
                        "q": f"timestamp>{window_minutes}m",
                    },
                )
                response.raise_for_status()

                self._last_latency = (time.time() - start) * 1000
                self._total_requests += 1
                self._on_success()

                data = response.json()
                return data.get("data", {}).get("affected_items", [])

            except (httpx.HTTPError, httpx.TimeoutException) as e:
                self._total_failures += 1
                wait = 2**attempt  # Exponential backoff: 1s, 2s, 4s
                logger.warning(
                    "Wazuh request failed",
                    attempt=attempt + 1,
                    max_retries=self.max_retries,
                    error=str(e),
                    retry_in=wait,
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(wait)

        # All retries exhausted
        self._on_failure()
        return []

    async def _ensure_token(self):
        """Get or refresh Wazuh API auth token."""
        if self._token and time.time() < self._token_expiry:
            return
        if time.time() < self._auth_cooldown_until:
            raise httpx.HTTPError(
                f"Wazuh auth cooldown until {self._auth_cooldown_until:.0f}"
            )
        response = await self._client.post(
            "/security/user/authenticate",
            auth=(self.username, self.password),
        )
        # 401/403 = credentials rotated or revoked. Treat as auth failure and
        # cool down so we don't hammer the account into lockout.
        if response.status_code in (401, 403):
            self._auth_failures += 1
            if self._auth_failures >= 3:
                self._auth_cooldown_until = time.time() + self._auth_cooldown_seconds
                logger.critical(
                    "Wazuh auth failed repeatedly — cooling down",
                    failures=self._auth_failures,
                    cooldown_seconds=self._auth_cooldown_seconds,
                )
            raise httpx.HTTPError(
                f"Wazuh auth rejected: HTTP {response.status_code}"
            )
        response.raise_for_status()
        self._token = response.json()["data"]["token"]
        self._token_expiry = time.time() + 840  # 14 minutes (tokens last 15min)
        # Successful auth resets the auth-failure counter without affecting
        # the request-level circuit breaker.
        self._auth_failures = 0
        self._auth_cooldown_until = 0.0

    def _on_success(self):
        self._failure_count = 0
        if self._circuit_state == CircuitState.HALF_OPEN:
            self._circuit_state = CircuitState.CLOSED
            logger.info("Circuit breaker CLOSED, connection recovered")

    def _on_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self._cb_threshold:
            self._circuit_state = CircuitState.OPEN
            logger.critical(
                "Circuit breaker OPEN — Wazuh API unreachable",
                failures=self._failure_count,
                threshold=self._cb_threshold,
            )

    async def health_check(self) -> ComponentHealth:
        """Health check for monitoring."""
        if self._circuit_state == CircuitState.OPEN:
            return ComponentHealth(
                name="wazuh_connector",
                status=HealthStatus.UNHEALTHY,
                message=f"Circuit breaker OPEN ({self._failure_count} consecutive failures)",
            )
        try:
            start = time.time()
            await self._ensure_token()
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="wazuh_connector",
                status=(
                    HealthStatus.HEALTHY if latency < 2000 else HealthStatus.DEGRADED
                ),
                message=f"Connected, circuit {self._circuit_state.value}",
                latency_ms=latency,
                details={
                    "total_requests": self._total_requests,
                    "total_failures": self._total_failures,
                },
            )
        except Exception as e:
            return ComponentHealth(
                name="wazuh_connector",
                status=HealthStatus.UNHEALTHY,
                message=str(e),
            )
