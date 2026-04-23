# Software Requirements Specification — Functional and Non-Functional Requirements

## AI-Driven Threat Hunting Platform for Detecting Credential-Based Lateral Movement and Covert Data Exfiltration in Enterprise Networks

---

## 1. Functional Requirements

### 1.1 Endpoint Telemetry Collection

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-01 | The system shall collect Windows Security Event Logs (Event IDs 4624, 4625, 4648, 4672, 4768, 4769, 4776) from corporate endpoints via Wazuh Agent. | Must |
| FR-02 | The system shall collect Sysmon events (EIDs 1, 3, 7, 8, 10, 13, 22, 25) from corporate endpoints using an APT-optimized Sysmon configuration. | Must |
| FR-03 | The system shall collect PowerShell ScriptBlock logs (Event ID 4104) for detecting encoded command execution. | Must |
| FR-04 | The system shall provide an automated endpoint deployment script (`deploy_endpoint.ps1`) that installs Sysmon, configures Windows audit policies, and installs the Wazuh Agent in a single execution. | Must |
| FR-05 | The system shall anonymize personally identifiable information (usernames, IP addresses, file paths) at the Wazuh Agent level before telemetry leaves the endpoint. | Must |

### 1.2 Data Ingestion and Preprocessing

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-06 | The system shall poll the Wazuh Manager REST API at configurable intervals (default: every 2 minutes) to retrieve recent security events. | Must |
| FR-07 | The system shall authenticate with the Wazuh API using JWT Bearer tokens, with automatic token refresh before expiry. | Must |
| FR-08 | The system shall validate all ingested events through a 6-layer input validation pipeline: timestamp bounds, IP address format, string length limits, injection pattern detection, numeric bounds, and Pydantic schema validation. | Must |
| FR-09 | The system shall quarantine events that fail validation into a dead letter queue for analyst inspection, recording the rejection reason and original event data. | Should |
| FR-10 | The system shall normalize all validated events into a standard `NormalizedEvent` schema containing: event_id, timestamp, source_ip, dest_ip, user, hostname, event_type, windows_event_id, logon_type, process_name, parent_process, command_line, dns_query, dns_query_type, bytes_sent, bytes_received. | Must |

### 1.3 Feature Engineering

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-11 | The system shall extract authentication features (8 features) from security events, including: failed login ratio, off-hours login count, unique source IPs per user, Kerberos ticket requests, privilege escalation events, admin group changes, service account usage, and logon attempt count. | Must |
| FR-12 | The system shall extract DNS features (14 features) from DNS query events, including: query count, average query length, subdomain depth, Shannon entropy, unique subdomain ratio, TXT/NULL record ratio, response size, base64 pattern count, hex pattern count, numeric character ratio, and unique base domain count. | Must |
| FR-13 | The system shall extract process execution features (12 features) including: suspicious process count, encoded command flags, unusual parent-child relationships, LOLBin usage, WMI activity, scheduled task creation, registry modifications, and average command length. | Must |
| FR-14 | The system shall extract temporal features (6 features) including: event rate per hour, maximum events per minute (burst detection), session duration, time variance, weekend activity, and overnight activity. | Must |
| FR-15 | The system shall extract behavioral features (8 features) including: new destination ratio, bytes deviation score, access pattern change, sensitive file access, lateral movement indicator, data exfiltration score, credential access attempts, and discovery command count. | Must |
| FR-16 | The system shall extract network features (6 features) including: connection count, unique destinations, port diversity, protocol diversity, bytes ratio, and external connection count. | Must |
| FR-17 | The system shall support a composable feature pipeline where each extractor implements a common `BaseFeatureExtractor` interface and is independently registrable. | Must |
| FR-18 | The system shall prefix all extracted features with the extractor name (e.g., `auth__failed_login_ratio`, `dns__avg_entropy`) to prevent feature name collisions. | Must |
| FR-19 | The system shall cache computed feature vectors in an LRU cache with configurable TTL (default: 600 seconds) to avoid redundant recomputation. | Should |

### 1.4 Threat Detection

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-20 | The system shall implement a credential-based lateral movement detector using an XGBoost classifier trained on authentication, process, temporal, behavioral, and network features. | Must |
| FR-21 | The system shall implement a DNS tunneling/exfiltration detector using an XGBoost classifier trained on DNS, temporal, and network features. | Must |
| FR-22 | The system shall classify each detection with a confidence score (0.0–1.0) and severity level (LOW, MEDIUM, HIGH, CRITICAL) based on configurable thresholds. | Must |
| FR-23 | The system shall provide SHAP-based explainability for each detection, showing the top contributing features that drove the classification. | Should |
| FR-24 | The system shall implement a plugin-based detector registry that auto-discovers detector modules from the `detection/detectors/` directory at startup. | Must |
| FR-25 | The system shall support adding new detection models by creating a single Python file implementing the `BaseDetector` interface and adding a YAML configuration entry, with zero changes to core platform code. | Must |
| FR-26 | The system shall support configurable detection thresholds per detector via YAML configuration (`config/detectors.yaml`). | Must |
| FR-27 | The system shall track model confidence distribution and detection rate over time, and alert administrators when statistically significant drift is detected. | Should |

### 1.5 Threat Intelligence Enrichment

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-28 | The system shall map each detection to specific MITRE ATT&CK technique identifiers (e.g., T1003.001, T1021.002, T1550.002, T1048.001, T1071.004). | Must |
| FR-29 | The system shall derive MITRE ATT&CK tactic classifications from mapped techniques (e.g., TA0006 Credential Access, TA0008 Lateral Movement, TA0010 Exfiltration). | Must |
| FR-30 | The system shall generate context-specific recommended response actions for each detection type (e.g., "Isolate affected hosts", "Reset compromised credentials", "Block suspicious DNS domain"). | Must |
| FR-31 | The system shall automatically escalate alert severity to CRITICAL when both lateral movement and DNS exfiltration detections occur for related entities, indicating a full APT kill chain. | Should |
| FR-32 | The system shall optionally correlate detections with MISP threat intelligence feeds for IoC matching, functioning correctly when MISP is unavailable. | Could |

### 1.6 Alert Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-33 | The system shall score and validate alerts, filtering out detections below a configurable minimum confidence threshold (default: 0.5). | Must |
| FR-34 | The system shall deduplicate alerts, suppressing repeated detections of the same entity by the same detector within a configurable time window (default: 30 minutes). | Must |
| FR-35 | The system shall persist all alerts to a SQLite database with full detection details, supporting query by severity, status, entity, and time range. | Must |
| FR-36 | The system shall track alert lifecycle status: open → acknowledged → investigating → resolved/dismissed → escalated → closed. | Must |
| FR-37 | The system shall publish enriched alerts back to Wazuh Manager via REST API so they appear in the Wazuh Dashboard alongside native Wazuh alerts. | Must |
| FR-38 | The system shall allow authorized analysts to acknowledge, dismiss (with reason), resolve (with investigation notes), and escalate alerts via the platform API. | Must |

### 1.7 Attack Path Visualization

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-39 | The system shall construct directed attack graphs from correlated detections, with enterprise hosts as nodes and lateral movement or exfiltration events as edges. | Must |
| FR-40 | The system shall render attack graphs as interactive HTML pages with color-coded severity (red=critical, orange=high, yellow=medium, green=low), clickable nodes, and MITRE technique labels on edges. | Must |
| FR-41 | The system shall serve attack graph visualizations via a standalone web interface on a configurable port (default: 8080). | Must |
| FR-42 | The system shall expose attack graph data as JSON via the REST API endpoint `GET /attack-graph/{incident_id}`. | Should |

### 1.8 Federated Learning

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-43 | The system shall implement a Flower-based federated learning server that aggregates XGBoost trees from multiple organizational clients using federated bagging. | Must |
| FR-44 | The system shall implement federated learning clients that train XGBoost models locally on organization-specific data and submit only tree structure bytes (not raw security data) to the FL server. | Must |
| FR-45 | The system shall apply differential privacy (Laplace noise with configurable ε, default: 1.0) to XGBoost leaf values before submitting model updates to the FL server. | Must |
| FR-46 | The system shall validate each FL client contribution against a held-out validation set, checking model structure validity, minimum accuracy (≥0.5), and detecting sudden accuracy drops (>15% per round). | Must |
| FR-47 | The system shall maintain per-client trust scores, reducing trust by 0.2 for each violation and blocking clients whose trust score falls below 0.3 from future rounds. | Must |
| FR-48 | The system shall weight client contributions by trust score during aggregation, giving higher influence to consistently reliable clients. | Should |
| FR-49 | The system shall hot-reload the updated global model into the detection engine after each FL round completes, without requiring platform restart. | Should |
| FR-50 | The system shall support configurable FL parameters via YAML: number of rounds, minimum clients, privacy epsilon, gradient clipping. | Must |

### 1.9 Platform API

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-51 | The system shall provide a REST API (FastAPI) with auto-generated OpenAPI documentation accessible at `/docs`. | Must |
| FR-52 | The system shall provide `GET /health` returning aggregated health status of all platform components (Wazuh connector, detectors, FL client). | Must |
| FR-53 | The system shall provide `GET /alerts` with query parameters for filtering by severity, status, entity, and time range. | Must |
| FR-54 | The system shall provide `GET /detections/{id}` returning full detection details including SHAP feature contributions. | Should |
| FR-55 | The system shall provide `POST /models/retrain` to trigger model retraining (restricted to admin role). | Must |
| FR-56 | The system shall provide `GET /models/status` returning current model versions, integrity status, and drift metrics. | Should |

### 1.10 Security Controls

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-57 | The system shall authenticate all API requests using JWT tokens or API keys, returning HTTP 401 for invalid or missing credentials. | Must |
| FR-58 | The system shall enforce role-based access control (RBAC) with four roles (viewer, analyst, operator, admin) and 11 permissions, returning HTTP 403 for insufficient permissions. | Must |
| FR-59 | The system shall verify the HMAC-SHA256 signature of every XGBoost model file at load time, refusing to load tampered models and alerting administrators. | Must |
| FR-60 | The system shall maintain an immutable, hash-chained audit trail logging every security-relevant action: model retraining, threshold changes, alert acknowledgments, FL round completions, authentication failures. | Must |
| FR-61 | The system shall support audit trail integrity verification, detecting any tampering of the log chain. | Must |

---

## 2. Non-Functional Requirements

### 2.1 Performance

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-01 | The system shall detect threats within a bounded time from event occurrence to alert publication. | Detection latency (95th percentile) | < 2 minutes |
| NFR-02 | The system shall process a polling cycle's event batch within acceptable time. | Batch processing time | < 30 seconds for 10,000 events |
| NFR-03 | The XGBoost models shall perform inference at speed suitable for near-real-time detection. | Single prediction latency | < 100 milliseconds |
| NFR-04 | The attack graph visualization shall render interactive HTML within acceptable time. | Graph rendering time | < 2 seconds for graphs up to 100 nodes |
| NFR-05 | The feature cache shall reduce redundant computation during sustained operation. | Cache hit rate | > 60% after warm-up period |
| NFR-06 | The federated learning rounds shall converge within a bounded number of rounds. | FL convergence | Within 10 rounds |

### 2.2 Accuracy

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-07 | The lateral movement detection model shall achieve acceptable precision on held-out test data. | Precision | ≥ 85% |
| NFR-08 | The lateral movement detection model shall achieve acceptable recall on held-out test data. | Recall | ≥ 90% |
| NFR-09 | The DNS exfiltration detection model shall achieve acceptable precision on held-out test data. | Precision | ≥ 85% |
| NFR-10 | The DNS exfiltration detection model shall achieve acceptable recall on held-out test data. | Recall | ≥ 88% |
| NFR-11 | Both models shall maintain false positive rates below acceptable thresholds to prevent alert fatigue. | False Positive Rate | < 5% |
| NFR-12 | Both models shall achieve acceptable ROC-AUC scores demonstrating discrimination ability. | ROC-AUC | ≥ 0.93 |
| NFR-13 | The federated global model shall outperform any individual client's local model. | Accuracy improvement | ≥ 3% over best local model |
| NFR-14 | Differential privacy application shall not significantly degrade model accuracy. | Accuracy retention | ≥ 95% of non-DP model accuracy |

### 2.3 Reliability and Availability

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-15 | The platform shall maintain high availability during normal operation. | Uptime | > 99% during testing period |
| NFR-16 | The Wazuh API connector shall gracefully handle SIEM downtime using automatic retry with exponential backoff and circuit breaker pattern. | Recovery | Resume within 60 seconds of SIEM recovery |
| NFR-17 | The platform shall persist alert state to SQLite, surviving container restarts without data loss. | Data persistence | Zero alert loss on restart |
| NFR-18 | Individual module failures shall not cascade to crash the entire platform. | Fault isolation | Event bus error isolation per handler |
| NFR-19 | The dead letter queue shall preserve all rejected events for forensic analysis. | Event preservation | 100% of rejected events quarantined |

### 2.4 Security

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-20 | All communication between Wazuh Agents and Wazuh Manager shall be encrypted. | Encryption | AES-256 (Wazuh protocol) |
| NFR-21 | All API communication between the AI Platform and Wazuh shall use encrypted transport. | Encryption | HTTPS / TLS |
| NFR-22 | All Docker containers shall run with minimal privileges. | Container hardening | read-only filesystem, non-root user (UID 1000), all Linux capabilities dropped, no-new-privileges |
| NFR-23 | All secrets (JWT key, Wazuh password, model signing key) shall be managed via Docker Secrets, not environment variables or plaintext files. | Secret management | No secrets in .env or container images |
| NFR-24 | The federated learning network shall be isolated from external access. | Network isolation | fl-net set to `internal: true` (Docker) |
| NFR-25 | No raw security telemetry shall cross organizational boundaries during federated learning. | Data privacy | Only XGBoost tree structure bytes transmitted |
| NFR-26 | The platform shall reject all input containing injection patterns (null bytes, script tags, encoded newlines) in security-sensitive fields. | Input sanitization | 100% rejection of injection patterns |
| NFR-27 | The audit trail shall be tamper-evident through cryptographic hash chaining. | Integrity | Broken chain detected on any modification |
| NFR-28 | Model file integrity shall be verifiable via HMAC-SHA256 signatures. | Model integrity | Tampered model refused with admin alert |

### 2.5 Scalability

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-29 | The endpoint telemetry collection shall scale to support a range of corporate endpoints. | Endpoint count | 10 – 10,000+ endpoints |
| NFR-30 | The platform shall handle enterprise-scale event volumes per polling cycle. | Event throughput | Up to 10,000 events per 2-minute cycle |
| NFR-31 | The federated learning architecture shall support multiple participating organizations. | FL clients | 2 – 20 organizations |
| NFR-32 | Docker resource limits shall prevent any single container from exhausting host resources. | Resource control | Per-container CPU and memory limits enforced |

### 2.6 Usability

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-33 | The platform shall achieve an above-average usability score as measured by the System Usability Scale. | SUS score | ≥ 70 |
| NFR-34 | Evaluation participants shall be able to complete an alert investigation task (view alert, trace attack path, acknowledge) within reasonable time. | Task completion | ≥ 80% completion rate |
| NFR-35 | Participants shall rate AI-generated alerts as actionable (providing sufficient context and recommended actions for investigation). | Alert actionability | ≥ 75% rated actionable |
| NFR-36 | The platform API shall provide auto-generated interactive documentation. | API docs | Available at `/docs` (Swagger UI) |
| NFR-37 | AI-enriched alerts shall appear in the existing Wazuh Dashboard without requiring analysts to learn a separate tool for alert triage. | Integration | Alerts visible in Wazuh Dashboard (:5601) |

### 2.7 Maintainability and Extensibility

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-38 | The platform shall be deployable with a single command. | Deployment | `docker compose up -d` starts all 10 containers |
| NFR-39 | All tunable parameters shall be configurable via YAML files without code changes. | Configuration | platform.yaml, detectors.yaml, federated.yaml, wazuh.yaml, security.yaml |
| NFR-40 | Adding a new detection model shall require zero changes to existing platform code. | Extensibility | One new Python file + one YAML config entry |
| NFR-41 | All modules shall be independently importable and testable without circular dependencies. | Modularity | 10 packages with no circular imports |
| NFR-42 | All inter-module communication shall use defined Pydantic schema contracts. | Contract enforcement | NormalizedEvent → FeatureVector → Detection → EnrichedAlert |
| NFR-43 | The platform shall produce structured JSON logs with correlation IDs enabling end-to-end request tracing. | Observability | Every event traceable from ingestion to alert |
| NFR-44 | Every module with external dependencies shall implement the `HealthCheckable` interface, enabling automated health monitoring. | Health monitoring | Aggregated status via `GET /health` |
| NFR-45 | The platform shall use only open-source software with no licensing costs. | Cost | Total software cost: $0 |

### 2.8 Portability

| ID | Requirement | Metric | Target |
|----|-------------|--------|--------|
| NFR-46 | The platform shall run on any Linux server with Docker installed. | OS compatibility | Ubuntu 22.04 LTS (primary), any Docker-capable Linux |
| NFR-47 | The endpoint deployment script shall support Windows 10 and Windows 11 corporate environments. | Endpoint OS | Windows 10/11 (64-bit) |
| NFR-48 | The platform shall be containerized, with no host-level dependencies beyond Docker and Docker Compose. | Container isolation | All dependencies inside Docker images |

---

## 3. Requirements Traceability to Objectives

| Objective | Functional Requirements | Non-Functional Requirements |
|-----------|------------------------|---------------------------|
| **Obj 1 — Design** (Architecture) | FR-10, FR-17, FR-18, FR-24, FR-25, FR-26, FR-50, FR-57, FR-58, FR-59, FR-60, FR-61 | NFR-22, NFR-23, NFR-24, NFR-27, NFR-28, NFR-38, NFR-39, NFR-40, NFR-41, NFR-42, NFR-43, NFR-44, NFR-45, NFR-46, NFR-48 |
| **Obj 2 — Implement** (Detection Engine) | FR-01 – FR-09, FR-11 – FR-16, FR-19 – FR-23, FR-26, FR-27 | NFR-01, NFR-02, NFR-03, NFR-05, NFR-07 – NFR-12, NFR-16, NFR-19, NFR-26, NFR-29, NFR-30, NFR-47 |
| **Obj 3 — Implement** (Platform Subsystems) | FR-28 – FR-56 | NFR-04, NFR-06, NFR-13, NFR-14, NFR-15, NFR-17, NFR-18, NFR-20, NFR-21, NFR-25, NFR-31, NFR-32, NFR-37 |
| **Obj 4 — Evaluate** (Test) | All FR (validation) | NFR-07 – NFR-14, NFR-33 – NFR-36 |
