# api/routes/health.py
"""
Platform health endpoint.
Aggregates health from all components.
"""

from fastapi import APIRouter
from shared.health import HealthStatus, ComponentHealth

router = APIRouter(tags=["health"])


@router.get("/health")
async def platform_health(request):
    """
    Returns health of all platform components.
    Used by Docker healthcheck and monitoring.
    """
    components: list[ComponentHealth] = []

    # Check each component
    for name, checker in request.app.state.health_checkers.items():
        try:
            health = await checker.health_check()
            components.append(health)
        except Exception as e:
            components.append(
                ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=str(e),
                )
            )

    # Overall status: worst of all components
    overall = HealthStatus.HEALTHY
    for c in components:
        if c.status == HealthStatus.UNHEALTHY:
            overall = HealthStatus.UNHEALTHY
            break
        if c.status == HealthStatus.DEGRADED:
            overall = HealthStatus.DEGRADED

    return {
        "status": overall.value,
        "components": [
            {
                "name": c.name,
                "status": c.status.value,
                "message": c.message,
                "latency_ms": c.latency_ms,
                "details": c.details,
            }
            for c in components
        ],
    }
