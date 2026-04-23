# shared/health.py
"""
Health check protocol. Every module implements this.
Enables: Docker healthchecks, Kubernetes probes, monitoring dashboards.
"""

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
import time


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # Working but with issues
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    last_check: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)


class HealthCheckable(ABC):
    """Every module that can fail should implement this."""

    @abstractmethod
    async def health_check(self) -> ComponentHealth: ...
