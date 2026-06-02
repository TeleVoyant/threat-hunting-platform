# shared/schemas.py
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Optional
from shared.enums import Severity, DetectionType


class NormalizedEvent(BaseModel):
    """
    Standard event format. Every module consumes this.
    Ingestion module produces it. Everyone else reads it.
    """

    event_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None          # Destination port (DNS on non-53 = suspicious)
    user: Optional[str] = None
    hostname: str
    event_type: str  # e.g., "authentication", "process", "dns_query"
    windows_event_id: Optional[int] = None  # e.g., 4624, 4625
    logon_type: Optional[int] = None
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    # DNS fields — populated from Sysmon EID 22 and DNS Client EID 3006/3008/3020
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None     # A, AAAA, TXT, NULL, MX, CNAME, ANY
    dns_response_code: Optional[str] = None  # NOERROR, NXDOMAIN, SERVFAIL, REFUSED
    dns_query_results: Optional[str] = None  # Raw Sysmon QueryResults (IPs, TXT data, etc.)
    dns_ttl: Optional[int] = None            # Response TTL in seconds (very low = fast-flux C2)
    bytes_sent: int = 0
    bytes_received: int = 0
    raw: dict = Field(default_factory=dict)  # Original event preserved


class FeatureVector(BaseModel):
    """
    Output of feature engineering. Input to detection models.
    """

    event_window_id: str  # ID for the batch of events this covers
    timestamp_start: datetime
    timestamp_end: datetime
    source_entity: str  # IP or hostname this feature vector describes
    features: dict[str, float]  # {"failed_login_ratio": 0.45, "dns_entropy": 4.2, ...}
    feature_source: str  # "auth", "dns", "process", etc.


class Detection(BaseModel):
    """
    Output of a single detector. Not yet an alert.
    """

    detection_id: str
    detector_name: str  # "lateral_movement" or "dns_exfiltration"
    detection_type: DetectionType
    confidence: float  # 0.0 to 1.0
    severity: Severity
    source_entity: str
    description: str
    contributing_features: dict[str, float]  # Top features that drove this detection
    mitre_techniques: list[str] = []  # ["T1003.001", "T1021.002"]
    timestamp: datetime
    event_window_id: str
    correlation_id: Optional[str] = None  # ties detection back to the poll cycle


class EnrichedAlert(BaseModel):
    """
    A detection enriched with threat intelligence. Ready for Wazuh/dashboard.
    """

    alert_id: str
    detections: list[Detection]  # May combine multiple detections
    overall_severity: Severity
    overall_confidence: float
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    ioc_matches: list[dict] = []  # From MISP
    attack_path: Optional[dict] = None  # Graph data for visualization
    recommended_actions: list[str]
    timestamp: datetime
    correlation_id: Optional[str] = None  # propagated through the pipeline



