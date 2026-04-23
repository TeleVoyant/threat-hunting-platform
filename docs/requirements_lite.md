# Software Requirements Summary

## AI-Driven Threat Hunting Platform for Detecting Credential-Based Lateral Movement APTs in Enterprise Networks

---

## 1. Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-01 | The system shall collect security telemetry (Windows Security Events, Sysmon logs, PowerShell ScriptBlock logs) from corporate Windows endpoints via Wazuh Agent, with PII anonymization at the collection point, deployable through a single automated script. | Must |
| FR-02 | The system shall ingest normalized events from Wazuh SIEM via its REST API at configurable intervals, validating and sanitizing all input data before processing, with failed events quarantined to a dead letter queue. | Must |
| FR-03 | The system shall extract behavioral features from security events through a composable pipeline of pluggable extractors covering authentication, process execution, temporal, behavioral, and network patterns (~40 features total). | Must |
| FR-04 | The system shall detect credential-based lateral movement (Pass-the-Hash, Kerberos abuse, SMB lateral movement) using a trained XGBoost classifier, producing detections with confidence scores, severity levels, and SHAP-based feature explanations. | Must |
| FR-05 | The system shall support a plugin-based detection engine where new detection models can be added by creating a single Python file implementing a standard interface plus a YAML configuration entry, with zero changes to core platform code. | Must |
| FR-06 | The system shall enrich detections with MITRE ATT&CK technique and tactic mappings (T1003, T1021, T1550, T1078) and generate context-specific recommended response actions for analysts. | Must |
| FR-07 | The system shall manage alert lifecycle (scoring, deduplication, persistence, status tracking from open through acknowledged to resolved/closed) and publish enriched alerts back to Wazuh Dashboard for unified SOC visibility. | Must |
| FR-08 | The system shall construct and render interactive attack path graphs from correlated detections, visualizing lateral movement chains as directed graphs with severity-coded nodes and MITRE technique-labeled edges. | Must |
| FR-09 | The system shall implement privacy-preserving federated learning using Flower framework with XGBoost federated bagging, differential privacy (ε=1.0), and trust-based contribution validation, enabling cross-organization model improvement without sharing raw security data. | Must |
| FR-10 | The system shall provide a REST API with endpoints for alert querying, model status, health monitoring, and model retraining, with auto-generated interactive documentation. | Must |

---

## 2. Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | **Performance:** The system shall detect threats within 2 minutes (95th percentile) from event occurrence to alert publication, processing up to 10,000 events per polling cycle. | < 2 min latency, < 30s batch processing |
| NFR-02 | **Accuracy:** The lateral movement detection model shall achieve precision ≥85%, recall ≥90%, ROC-AUC ≥0.93, and false positive rate <5% on held-out test data. | Precision ≥85%, Recall ≥90%, FPR <5% |
| NFR-03 | **Reliability:** The system shall maintain >99% uptime, gracefully handle Wazuh SIEM downtime via circuit breaker with automatic recovery, persist alert state across restarts, and isolate individual module failures from crashing the platform. | >99% uptime, zero alert loss on restart |
| NFR-04 | **Scalability:** The system shall support 10–10,000+ monitored endpoints, 2–20 federated learning organizations, with per-container resource limits preventing host exhaustion. | Enterprise-scale endpoint and FL support |
| NFR-05 | **Usability:** The system shall achieve SUS score ≥70, with ≥80% of evaluation participants able to complete an alert investigation task, and alerts rated actionable by ≥75% of participants. AI-enriched alerts shall appear in the existing Wazuh Dashboard without requiring a separate tool. | SUS ≥70, integrated Wazuh Dashboard view |
| NFR-06 | **Maintainability:** The system shall be deployable via a single `docker compose up -d` command, with all parameters configurable via YAML, all modules independently testable with no circular dependencies, and structured JSON logging with correlation IDs for end-to-end tracing. | Single-command deploy, YAML-driven config |
| NFR-07 | **Portability:** The platform shall run on any Docker-capable Linux server with no host-level dependencies beyond Docker and Docker Compose, using only open-source software with zero licensing cost. Endpoint collection shall support Windows 10/11. | Docker-portable, $0 software cost |

---

## 3. Security Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| SR-01 | **Authentication & Authorization:** All API requests shall be authenticated via JWT tokens or API keys, with role-based access control enforcing four roles (viewer, analyst, operator, admin) across 11 permissions. Unauthenticated requests receive HTTP 401; unauthorized requests receive HTTP 403. | RBAC with 4 roles, 11 permissions |
| SR-02 | **Data Protection:** All endpoint-to-server communication shall be encrypted (AES-256 via Wazuh protocol), all API communication shall use HTTPS, and all credentials shall be managed via Docker Secrets — never stored in environment variables, code, or container images. | AES-256 transport, Docker Secrets |
| SR-03 | **Model Integrity:** Every XGBoost model file shall be HMAC-SHA256 signed at training time and verified at load time. Tampered models shall be refused with an immediate administrator alert. Model versioning shall support rollback to previous verified versions. | HMAC-signed models, tamper rejection |
| SR-04 | **Audit Trail:** All security-relevant actions (model retraining, threshold changes, alert acknowledgments, FL rounds, authentication failures) shall be logged to a hash-chained, append-only audit trail where each entry's hash includes the previous entry's hash, enabling tamper detection through chain integrity verification. | Hash-chained tamper-evident audit log |
| SR-05 | **Federated Learning Privacy:** No raw security telemetry shall cross organizational boundaries during federated learning. Differential privacy (Laplace noise, ε=1.0) shall be applied to all model updates before transmission. FL clients with trust scores below 0.3 (from repeated validation failures) shall be blocked from participation. | DP ε=1.0, trust gating, zero raw data shared |
| SR-06 | **Container Hardening & Input Sanitization:** All Docker containers shall run with read-only filesystems, non-root users, all Linux capabilities dropped, and no-new-privileges enforced. The FL network shall be isolated from external access. All ingested data shall pass 6-layer input validation rejecting injection patterns, malformed IPs, out-of-bounds timestamps, and oversized payloads. | Hardened containers, 6-layer input validation |
