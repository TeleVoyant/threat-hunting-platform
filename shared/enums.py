"""Shared enumerations used across all platform modules."""

from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionType(str, Enum):
    LATERAL_MOVEMENT = "credential_lateral_movement"
    DNS_EXFILTRATION = "dns_covert_exfiltration"
