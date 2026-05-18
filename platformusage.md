# APT Threat Hunting Platform — Usage Guide

A complete A‑to‑Z walkthrough: from a fresh server to investigating a real
alert in the dashboard, with pointers for federated learning,
fleet management, and operational maintenance.

---

## Contents

1. [What this platform does](#1-what-this-platform-does)
2. [Prerequisites](#2-prerequisites)
3. [Quick start (10 minutes, synthetic data)](#3-quick-start-10-minutes-synthetic-data)
4. [Server setup in detail](#4-server-setup-in-detail)
5. [Train the initial models](#5-train-the-initial-models)
6. [Deploy the collector to Windows endpoints](#6-deploy-the-collector-to-windows-endpoints)
7. [Dashboard — daily operations](#7-dashboard--daily-operations)
8. [Fleet remote control](#8-fleet-remote-control)
9. [DNS allowlist management](#9-dns-allowlist-management)
10. [Federated learning](#10-federated-learning)
11. [Model lifecycle: retrain, version, roll back](#11-model-lifecycle-retrain-version-roll-back)
12. [Maintenance & operations](#12-maintenance--operations)
13. [Troubleshooting](#13-troubleshooting)
14. [Production security checklist](#14-production-security-checklist)
15. [Reference: endpoints, env vars, ports, files](#15-reference)

---

## 1. What this platform does

```
   Windows laptops             Server (Docker)              Operators
  ┌─────────────────┐       ┌────────────────────┐       ┌──────────────┐
  │ Sysmon +        │ ─AES─►│ Wazuh Manager      │       │ SOC Analyst  │
  │ Wazuh Agent     │       │ + Indexer          │       │  (dashboard) │
  │                 │       │                    │       │              │
  │ Command Handler │ ◄────►│ AI Platform API    │ ─────►│ IT Admin     │
  │ (mTLS + HMAC)   │       │  • Detection loop  │       │  (fleet ops) │
  └─────────────────┘       │  • Alert pipeline  │       │              │
                             │  • Dashboard       │       │ Platform     │
                             │  • Fleet control   │       │ Admin        │
                             └────────────────────┘       └──────────────┘
                                       │
                                       │ optional, separate trust boundary
                                       ▼
                             ┌────────────────────┐
                             │ FL Coordinator     │  ← own host, own users,
                             │ (Flower + REST)    │    own audit DB
                             └────────────────────┘
```

**Two attack types detected:**
- **Credential‑based lateral movement** (Pass‑the‑Hash, Pass‑the‑Ticket,
  PsExec, WMI, RDP, WinRM)
- **Covert DNS exfiltration** (DNS tunnelling, fast‑flux C2)

**Detection chain:** events → preprocessor → 6 feature extractors (141
features) → XGBoost detectors (per‑prediction SHAP) → enrichment (MITRE
ATT&CK + MISP IoCs) → dedup + persist → dashboard + Wazuh log.

---

## 2. Prerequisites

### Server side
- Linux host with **Docker 24+** and **Docker Compose v2**
- 8 GB RAM minimum, 16 GB recommended (Wazuh indexer needs ~2 GB alone)
- Open ports: 8000 (API), 8080 (graph viewer), 1514+1515+55000 (Wazuh),
  5601 (Wazuh dashboard), 8889 (FL coordinator if running it)
- A Python 3.13+ venv for offline tasks (training, evaluation)

### Endpoint side
- **Windows 10 / 11** with **Administrator** PowerShell
- Network reachability to the server (port 1514 for Wazuh, optionally
  HTTPS to the API for fleet control)

### Tools
- `openssl` for generating secrets
- `git` to clone the platform
- A text editor for editing `config/*.yml`

---

## 3. Quick start (10 minutes, synthetic data)

The fastest path to a working detection demo on synthetic data — no
laptops needed, all in one shell.

```bash
# 1. Clone + create venv
cd threat-hunting-platform
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# 2. Generate the secrets you'll need
export JWT_SECRET="$(openssl rand -hex 32)"
export MODEL_SIGNING_KEY="$(openssl rand -hex 32)"
export FLEET_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
export FL_LOCAL_FERNET_KEY="$(venv/bin/python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"

# 3. Train initial models on synthetic data (~30 s)
venv/bin/python -m training.train_models --hours 24 --hosts 5 --seed 42

# 4. Make sure config/security.yml has at least one user (see §4.2)
#    For now create a dev user inline:
mkdir -p config
cat > config/security.yml <<EOF
authentication:
  jwt_secret: "$JWT_SECRET"
  token_expiry_hours: 8
users:
  - username: "admin"
    role: "admin"
    api_key_hash: "$(echo -n 'demo-admin-key' | sha256sum | cut -d' ' -f1)"
EOF

# 5. Run the API + dashboard
venv/bin/python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# 6. In a browser:
#      http://localhost:8000/auth/login
#      username = admin
#      api_key  = demo-admin-key
```

You're now on the dashboard. There won't be alerts yet because no events
are flowing. Skip to §6 for endpoint deployment, or §7 for a guided tour
of the UI with seeded synthetic data.

---

## 4. Server setup in detail

### 4.1 Bootstrap secrets

Every secret should be unique per deployment. Generate them once and
store in `.env`:

```bash
cat > .env <<EOF
JWT_SECRET=$(openssl rand -hex 32)
MODEL_SIGNING_KEY=$(openssl rand -hex 32)
FLEET_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)
FL_LOCAL_FERNET_KEY=$(venv/bin/python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')
WAZUH_API_PASSWORD=$(openssl rand -base64 24)
MISP_API_KEY=             # optional; leave blank to use file‑mode
EOF
chmod 600 .env
```

For Docker Compose, also create the secrets directory:

```bash
mkdir -p secrets
echo "$JWT_SECRET"          > secrets/jwt_secret.txt
echo "$MODEL_SIGNING_KEY"   > secrets/model_signing_key.txt
echo "$WAZUH_API_PASSWORD"  > secrets/wazuh_api_password.txt
chmod 600 secrets/*
```

### 4.2 Configure users in `config/security.yml`

Each user needs a SHA‑256 hash of their API key. Generate a key + hash
together:

```bash
KEY=$(openssl rand -base64 32)
HASH=$(echo -n "$KEY" | sha256sum | cut -d' ' -f1)
echo "API key (give to user):  $KEY"
echo "api_key_hash (paste in security.yml):  $HASH"
```

Then edit `config/security.yml`:

```yaml
authentication:
  jwt_secret: "${JWT_SECRET}"     # resolved from .env / Docker secrets
  token_expiry_hours: 8

users:
  - username: "admin"
    role: "admin"               # admin / operator / analyst / viewer
    api_key_hash: "<paste hash here>"
  - username: "soc_analyst_1"
    role: "analyst"
    api_key_hash: "<paste hash here>"
  - username: "it_admin_view"
    role: "viewer"
    api_key_hash: "<paste hash here>"
```

**Role permissions (full matrix in `shared/security.py`):**

| Role | Can do |
|---|---|
| **viewer** | List alerts + view graphs (read‑only) |
| **analyst** | Acknowledge alerts, add notes, export forensic data |
| **operator** | + Update detection thresholds, manage detectors, manage fleet |
| **admin** | + Enroll agents, retrain models, manage users, view audit log, opt org into FL |

### 4.3 Start the stack

```bash
docker compose up -d
docker compose ps                  # all services should be 'running' / 'healthy'
docker compose logs -f api         # follow the API logs
```

### 4.4 Verify each service

```bash
# Wazuh manager
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# AI Platform API
curl http://localhost:8000/health
# → {"status":"healthy",...}

# Dashboard (browser)
open http://localhost:8000/auth/login

# Wazuh dashboard (browser, separate)
open http://localhost:5601

# Attack graph viewer (auto‑populated as detections fire)
open http://localhost:8080
```

### 4.5 Verify Docker hardening

```bash
venv/bin/python scripts/audit_compose_hardening.py
# → 7/7 OWNED services pass 8/8 checks
```

---

## 5. Train the initial models

Detection cannot fire until both `lateral_movement` and `dns_exfiltration`
models exist. Three options:

### 5.1 Synthetic data (good enough for a demo)

```bash
MODEL_SIGNING_KEY="$MODEL_SIGNING_KEY" \
venv/bin/python -m training.train_models \
  --hours 48 --hosts 10 --lateral-attacks 8 --dns-attacks 8 \
  --num-boost-round 200 \
  --output-dir detection/models
```

Models are saved as **HMAC‑signed versioned directories**:

```
detection/models/
├── lateral_movement/
│   ├── v1715184000/
│   │   ├── model.json
│   │   └── manifest.json     ← SHA‑256 + signature + metrics
│   └── latest -> v1715184000
└── dns_exfiltration/
    ├── v1715184007/
    └── latest -> v1715184007
```

Tampered models are **refused at load time** (`SecurityError` raised).

### 5.2 Real data (production)

Download Mordor / Security‑Datasets from
<https://github.com/OTRF/Security-Datasets>, then:

```bash
MODEL_SIGNING_KEY="$MODEL_SIGNING_KEY" \
venv/bin/python -m training.train_models \
  --mordor-dir /path/to/Security-Datasets \
  --add-synthetic-benign-hours 48 \
  --hosts 10 \
  --num-boost-round 300 \
  --output-dir detection/models
```

The loader auto‑infers labels from the directory taxonomy
(`lateral_movement_*`, `exfiltration_dns_*`, `empire_baseline_*`, …).

### 5.3 Hyperparameter tuning (closes proposal item 2.12)

```bash
venv/bin/python -m training.tuning \
  --model-name lateral_movement \
  --mordor-dir /path/to/Security-Datasets \
  --add-synthetic-benign-hours 48 \
  --output-json data/tuning/lat.json

# Now re‑train with the winning params:
venv/bin/python -m training.train_models \
  --mordor-dir /path/to/Security-Datasets \
  --params-json data/tuning/lat.json \
  --output-dir detection/models
```

### 5.4 Evaluation (NFR‑02 grading)

```bash
MODEL_SIGNING_KEY="$MODEL_SIGNING_KEY" \
venv/bin/python -m training.evaluate_models \
  --model-name lateral_movement \
  --model-path detection/models/lateral_movement/latest \
  --mordor-dir /path/to/test/data \
  --output-json data/evaluation/lat_v1.json
```

Output includes precision, recall, F1, FPR, ROC‑AUC, PR‑AUC, confusion
matrix, threshold sweep, and a ✓/✗ NFR‑02 grading.

### 5.5 Restart the API to load new models

```bash
docker compose restart api
```

---

## 6. Deploy the collector to Windows endpoints

The collector is **Sysmon + Wazuh Agent + (optional) command handler**,
all installed by a single PowerShell script.

### 6.1 Single laptop (test deployment)

On the **target Windows laptop**, in **PowerShell as Administrator**:

```powershell
# Copy the scripts/ folder to the laptop (USB / network share / git)
cd C:\path\to\scripts

# Minimum: collector only (no remote control)
.\deploy_endpoint.ps1 `
    -ServerIP             192.168.1.100 `
    -RegistrationPassword "YourFYPRegPass!" `
    -Profile              Balanced

# With fleet remote control (recommended for production):
.\deploy_endpoint.ps1 `
    -ServerIP             192.168.1.100 `
    -RegistrationPassword "YourFYPRegPass!" `
    -Profile              Balanced `
    -PlatformApiUrl       https://api.example.com:8000 `
    -EnrollmentToken      "$env:FLEET_BOOTSTRAP_TOKEN"
```

**Profiles:**

| Profile | CPU | RAM | Sysmon coverage | Use case |
|---|---|---|---|---|
| **Lean** | ~0.3 % | ~12 MB | Minimum (process, lateral ports, LSASS, DNS) | Older / shared / busy laptops |
| **Balanced** (default) | ~1‑3 % | ~25 MB | + image loads, file create, named pipes, WMI | Standard corporate laptop |
| **Full** | same | same | + Windows Filtering Platform + SAM auditing + Detailed File Share | Dedicated SOC endpoint |

### 6.2 Fleet rollout via PowerShell Remoting

From an admin workstation, push to many laptops in parallel:

```powershell
$laptops = 1..20 | ForEach-Object { "LAPTOP-{0:D2}" -f $_ }
$cred    = Get-Credential
$serverIP = "192.168.1.100"
$bootstrap = "<contents of FLEET_BOOTSTRAP_TOKEN>"

$sessions = New-PSSession -ComputerName $laptops -Credential $cred

foreach ($s in $sessions) {
    Invoke-Command -Session $s -ScriptBlock {
        New-Item -Type Directory C:\Deploy -Force | Out-Null
    }
    Copy-Item -ToSession $s -Path .\scripts\* -Destination C:\Deploy\ -Recurse
}

Invoke-Command -Session $sessions -ScriptBlock {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    & C:\Deploy\deploy_endpoint.ps1 `
        -ServerIP             $using:serverIP `
        -RegistrationPassword "YourFYPRegPass!" `
        -Profile              "Balanced" `
        -PlatformApiUrl       "https://api.example.com:8000" `
        -EnrollmentToken      $using:bootstrap
}

Remove-PSSession $sessions
```

### 6.3 Verify enrollment

```bash
# Server side: list connected Wazuh agents
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# Server side: list fleet (REST)
curl -H "X-API-Key: $YOUR_ADMIN_KEY" http://localhost:8000/fleet/agents | jq

# Or open the dashboard → Fleet tab
```

Each laptop sends a heartbeat every 60 s; you'll see `last_seen_at`
update.

---

## 7. Dashboard — daily operations

### 7.1 Login

`http://localhost:8000/auth/login` → enter **username** + **API key**
(the API key is the "password"; it was generated in §4.2 and shared
out‑of‑band).

The platform issues a JWT in an HttpOnly cookie that lasts 8 hours.
Click "Logout" in the header to clear the cookie.

### 7.2 Triage alerts

**Home** (`/dashboard`) — header counters + 10 most recent alerts in the
last 24 h. Click any alert for details.

**Alerts grid** (`/dashboard/alerts`) — full list with filters:

- `severity` (critical / high / medium / low)
- `status` (open / acknowledged)
- `entity` substring (matches hostname or `host:user`)
- `hours` window (1 to 720)

### 7.3 Acknowledge an alert

Click an alert → **Acknowledge** button (requires the
`acknowledge_alerts` permission, i.e., role ≥ analyst). Every ack hits
the **hash‑chained audit trail** with your username + timestamp.

### 7.4 Investigate via the SHAP widget

The detail page has a **"Why did this alert fire?"** panel with two
sections:

1. **Per‑detection SHAP** — the top 5 features that pushed the model
   toward "attack" for THIS specific window. Red bars = pushed toward
   attack; blue bars = pushed away.
2. **Global feature importance** — what features the model relies on
   overall (gain‑based). Helps you judge whether THIS feature normally
   matters or is an unusual driver.

### 7.5 Trace lateral movement on the attack graph

`Attack Graph` tab → live graph rendered from every detection in the
last window. Each detection contributes:

- a **host node** (severity‑coloured) for the source entity
- **directed edges** to inferred destinations (lateral_movement → distinct
  internal IPs from the related network events; dns_exfiltration → base
  domains, with the admin‑managed allowlist filtering benign ones)

Edges are labelled with the MITRE technique IDs and the top SHAP
feature.

### 7.6 Fleet inventory

`Fleet` tab → table of every enrolled agent (id, profile, last seen,
pending commands). The "Send command" expander on each row gives you a
quick form for the most common ops (see §8).

---

## 8. Fleet remote control

Every command is **HMAC‑signed**, **replay‑protected** (per‑agent
monotonic sequence + 10‑min expiry), and **whitelist‑bound** on the
endpoint side (the PowerShell handler refuses anything not in its
dispatch table).

### 8.1 Switch profile (Lean ↔ Balanced ↔ Full)

**Via dashboard:** Fleet tab → row → Send command → `set_profile`
→ pick profile → Enqueue.

**Via REST:**

```bash
curl -X POST http://localhost:8000/fleet/agents/LAPTOP-007/commands \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"command_type":"set_profile","params":{"profile":"Lean"}}'
```

### 8.2 Toggle a telemetry source

```bash
# Disable Sysmon temporarily on one laptop
curl -X POST http://localhost:8000/fleet/agents/LAPTOP-007/commands \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"command_type":"toggle_telemetry",
          "params":{"source":"sysmon","enabled":false}}'
```

Sources: `sysmon`, `dns_client`, `firewall`, `wmi`, `defender`,
`tasksched`, `powershell`.

### 8.3 Restart agent services

```bash
curl -X POST http://localhost:8000/fleet/agents/LAPTOP-007/commands \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"command_type":"restart_services","params":{"service":"wazuh"}}'
```

Services: `wazuh`, `sysmon`, `all`.

### 8.4 Get status

```bash
curl -X POST http://localhost:8000/fleet/agents/LAPTOP-007/commands \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -d '{"command_type":"get_status","params":{}}'

# After ~60 s, fetch the result:
curl -H "X-API-Key: $YOUR_ADMIN_KEY" \
     http://localhost:8000/fleet/commands/<command_id> | jq
```

### 8.5 Bulk: change every Lean laptop to Balanced

```bash
curl -X POST http://localhost:8000/fleet/commands/broadcast \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "command_type":"set_profile",
       "params":{"profile":"Balanced"},
       "target_filter":{"profile":"Lean"}
     }'
```

### 8.6 Verify the agent received it

On the target laptop:

```powershell
# Look at the handler's log
type C:\ProgramData\APTPlatform\handler.log -Tail 20
```

---

## 9. DNS allowlist management

Domains in the allowlist are **excluded from attack‑graph DNS exfil
edges**. Comes pre‑seeded with 14 well‑known benign domains
(`microsoft.com`, `windowsupdate.com`, `office365.com`, etc.).

### 9.1 List

```bash
curl -H "X-API-Key: $YOUR_ADMIN_KEY" \
     http://localhost:8000/allowlist/dns | jq
```

### 9.2 Add your corporate domain

```bash
curl -X POST http://localhost:8000/allowlist/dns \
     -H "X-API-Key: $YOUR_OPERATOR_KEY" \
     -H "Content-Type: application/json" \
     -d '{"domain":"corp.example.com","note":"corporate intranet"}'
```

### 9.3 Remove a domain (e.g., one that turned out to be malicious)

```bash
curl -X DELETE http://localhost:8000/allowlist/dns/github.com \
     -H "X-API-Key: $YOUR_OPERATOR_KEY"
```

Changes take effect **immediately** — graph builder reads from the live
table on every detection. Every mutation is audit‑logged.

---

## 10. Federated learning

Two distinct personas:

| Persona | Where | What they do |
|---|---|---|
| **Org admin** (`admin` role on the org's platform) | Org's own host | Generates org's keypair, configures coordinator URL, opts org into rounds |
| **FL coordinator operator** (`fl_admin` / `fl_operator` / `fl_viewer`) | **Separate host**, separate user roster | Enrols orgs, starts rounds, blocks misbehaving clients, monitors convergence |

These two personas **share nothing** — different JWT secrets, different
audit DBs, different REST surfaces.

### 10.1 As an FL coordinator operator: bootstrap

On the FL coordinator host (could be your server, but conceptually a
neutral consortium machine):

```bash
# 1. Generate the federation root CA (one‑time)
venv/bin/python -m federated.init_fl_ca \
    --ca-dir data/fl_coordinator/ca \
    --hostname fl.example.com

# 2. Create FL coordinator users in config/fl_users.yml
KEY=$(openssl rand -base64 32)
HASH=$(echo -n "$KEY" | sha256sum | cut -d' ' -f1)
cat > config/fl_users.yml <<EOF
users:
  - username: alice
    role: fl_admin
    api_key_hash: $HASH
EOF
echo "FL admin api_key (give to operator only): $KEY"

# 3. Start the coordinator with mTLS
export FL_JWT_SECRET="$(openssl rand -hex 32)"
export FL_DATA_DIR=data/fl_coordinator
export FL_CA_DIR=data/fl_coordinator/ca
export FL_USERS_FILE=config/fl_users.yml

venv/bin/python -m uvicorn federated.coordinator_app:app \
    --host 0.0.0.0 --port 8889 \
    --ssl-certfile $FL_CA_DIR/coordinator_cert.pem \
    --ssl-keyfile  $FL_CA_DIR/coordinator_key.pem \
    --ssl-ca-certs $FL_CA_DIR/ca_cert.pem \
    --ssl-cert-reqs 2

# 4. Distribute $FL_CA_DIR/ca_cert.pem to every participating org
#    (out-of-band — same channel you use to verify org legitimacy)
```

### 10.2 As an FL coordinator operator: enrol an org

```bash
# Wait for the org to send you their public key (from §10.3 step 2)
PUBKEY=$(cat udom_public_key.pem)

curl -X POST https://fl.example.com:8889/fl/orgs/enroll \
     -H "X-FL-API-Key: $FL_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d "{
       \"org_id\": \"udom\",
       \"display_name\": \"University of Dodoma\",
       \"public_key_pem\": $(echo "$PUBKEY" | jq -Rs .)
     }"
# → returns: api_key + client_cert_pem + ca_cert_pem + coordinator_pub_pem
#   Send ALL of these back to the org (out-of-band)
```

### 10.3 As an org admin: join a federation

On YOUR org's platform (NOT the coordinator):

```bash
ORG_ADMIN_TOKEN=...   # JWT obtained by logging into your org's dashboard

# 1. Generate the keypair LOCALLY (private key never leaves)
curl -X POST http://localhost:8000/fl/local/keypair/init \
     -H "Authorization: Bearer $ORG_ADMIN_TOKEN"
# → returns public_key_pem

# 2. Send public_key_pem out-of-band to the FL coordinator admin

# 3. Once they reply with the enrollment package, configure locally:
curl -X POST http://localhost:8000/fl/local/configure \
     -H "Authorization: Bearer $ORG_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d @enrollment_response.json

# 4. Opt in to the next round:
curl -X POST http://localhost:8000/fl/local/opt-in \
     -H "Authorization: Bearer $ORG_ADMIN_TOKEN" \
     -d '{"opted_in": true}'
```

### 10.4 As FL coordinator: start a round

```bash
curl -X POST https://fl.example.com:8889/fl/rounds/start \
     -H "X-FL-API-Key: $FL_OPERATOR_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "epsilon": 1.0,
       "num_boost_rounds": 10,
       "min_clients": 3
     }'

# Monitor progress:
curl -H "X-FL-API-Key: $FL_OPERATOR_KEY" \
     https://fl.example.com:8889/fl/rounds | jq

# Coordinator audit log (separate from org platforms!):
curl -H "X-FL-API-Key: $FL_OPERATOR_KEY" \
     https://fl.example.com:8889/fl/audit | jq
```

### 10.5 In‑process FL demo + convergence graph

For Chapter 7 of your dissertation:

```bash
venv/bin/python -m federated.run_demo \
    --num-rounds 10 --hours-per-org 12 \
    --poison-round 5 \
    --output-dir data/fl_demo

# Outputs:
#   data/fl_demo/convergence_<ts>.json   — round-by-round metrics
#   data/fl_demo/convergence_<ts>.png    — convergence + trust graph
```

The demo simulates 3 orgs (UDoM + hospital + bank), poisons one at
round 5, and shows the trust manager dropping its score from 1.0 → 0.25
over rounds 5–9, blocking it at round 10. **Global AUC stays at 1.0
throughout** (poison defended).

### 10.6 mTLS demo (security test transcript)

```bash
venv/bin/python -m federated.mtls_demo
# 5 adversarial scenarios run against a real uvicorn TLS server:
#   1. Valid cert + signature   → 202 accepted
#   2. No client cert           → TLS handshake aborts
#   3. Rogue CA cert            → TLS handshake aborts
#   4. Forged signature         → 403
#   5. Cross-org attestation    → 403
# 5/5 pass.
```

### 10.7 Block a misbehaving org

```bash
# Block (reversible — keeps cert valid, just refuses participation)
curl -X POST https://fl.example.com:8889/fl/orgs/bank-B/block \
     -H "X-FL-API-Key: $FL_OPERATOR_KEY"

# Revoke (permanent — admin only)
curl -X DELETE https://fl.example.com:8889/fl/orgs/bank-B \
     -H "X-FL-API-Key: $FL_ADMIN_KEY"
```

---

## 11. Model lifecycle: retrain, version, roll back

### 11.1 List models + versions

```bash
curl -H "X-API-Key: $YOUR_KEY" http://localhost:8000/models | jq
curl -H "X-API-Key: $YOUR_KEY" \
     http://localhost:8000/models/lateral_movement/versions | jq
```

### 11.2 Trigger a retrain (admin‑only background task)

```bash
curl -X POST http://localhost:8000/models/lateral_movement/retrain \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "hours": 48, "hosts": 10,
       "lateral_attacks": 8, "dns_attacks": 6,
       "num_boost_round": 200,
       "hot_reload": true
     }'
# → 202 Accepted; check audit + /models for the new version
```

If `hot_reload=true`, the running detector swaps to the new model
**without restarting the API**.

### 11.3 Roll back

```bash
curl -X POST http://localhost:8000/models/lateral_movement/rollback/v1715184000 \
     -H "X-API-Key: $YOUR_ADMIN_KEY"
```

The `latest` symlink is re‑pointed atomically + the running detector
hot‑reloads.

### 11.4 Drift monitoring

After ~100 predictions of normal traffic, snapshot the baseline:

```bash
curl -X POST http://localhost:8000/models/drift/baseline \
     -H "X-API-Key: $YOUR_OPERATOR_KEY"
```

From now on, when the rolling confidence distribution shifts > 0.15 OR
detection rate changes > 0.10 from baseline, a `MODEL_DRIFT_DETECTED`
event fires (debounced — only on transition, not every batch). Hook
this into your alerting / Slack / etc. by subscribing to the bus event.

### 11.5 Per‑prediction explainability (SHAP)

Per alert:
```bash
curl -H "X-API-Key: $YOUR_KEY" \
     http://localhost:8000/alerts/alert_abc123/explanation | jq
```

Or open the rendered HTML widget directly:
`http://localhost:8000/alerts/alert_abc123/explanation.html` — it's
embedded in the dashboard alert detail page automatically.

### 11.6 Global feature importance

```bash
curl -H "X-API-Key: $YOUR_KEY" \
     "http://localhost:8000/models/lateral_movement/importance?importance_type=gain&top_k=20" | jq
```

`importance_type` ∈ `weight | gain | cover | total_gain | total_cover`.

---

## 12. Maintenance & operations

### 12.1 Audit log inspection

The audit DB is hash‑chained — any tampering breaks the chain.

```bash
# Verify integrity
venv/bin/python -c "
from observability.audit import AuditTrail
a = AuditTrail(db_path='data/audit/audit.db')
ok, n = a.verify_integrity()
print(f'{n} entries, integrity={ok}')
"

# Query specific actions
venv/bin/python -c "
from observability.audit import AuditTrail
a = AuditTrail(db_path='data/audit/audit.db')
for row in a.query(action='alert.acknowledge', limit=20):
    print(row)
"
```

### 12.2 Backup what matters

| Path | Why |
|---|---|
| `data/audit/audit.db` | hash‑chained audit trail (legal evidence) |
| `data/alerts/alerts.db` | every alert ever fired |
| `data/fleet/fleet.db` | per‑agent secrets + command history |
| `detection/models/*/v*` | trained models + manifests |
| `data/anonymizer/salt.bin` | username pseudonymization salt (without it, you can't reverse hashes) |
| `data/fl_coordinator/coordinator.db` | (FL coordinator only) org registry + round history |
| `data/fl_coordinator/ca/ca_key.pem` | (FL coordinator only) federation root CA — **MOST sensitive file** |

A nightly tarball of these is enough for full recovery.

### 12.3 Rotate JWT secret

```bash
# Generate new secret
NEW=$(openssl rand -hex 32)
# Update .env + secrets/ + config/security.yml's ${JWT_SECRET}
docker compose restart api
# All existing sessions become invalid; users must re-login
```

### 12.4 Rotate an agent's HMAC secret

```bash
# Re-enroll the agent (rotates its secret + zeros sequence counter)
curl -X POST http://localhost:8000/fleet/agents/enroll \
     -H "X-Bootstrap-Token: $FLEET_BOOTSTRAP_TOKEN" \
     -d '{"agent_id":"LAPTOP-007","profile":"Balanced"}'
# Returns the new secret. Re-deploy to the laptop.
```

### 12.5 Update Sysmon configuration on every laptop

```bash
# Push a fleet-wide update
SYSMON_XML_B64=$(base64 -w 0 scripts/sysmon_config.xml)
curl -X POST http://localhost:8000/fleet/commands/broadcast \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d "{
       \"command_type\":\"update_sysmon\",
       \"params\":{\"config_b64\":\"$SYSMON_XML_B64\"}
     }"
```

---

## 13. Troubleshooting

### Agent enrolled but no events arriving

```bash
# Server side — is the agent connected at all?
docker exec wazuh-manager /var/ossec/bin/agent_control -l
# (should show your laptop in 'Active' state)

# Server side — are events being polled by AI Platform?
docker compose logs api | grep -i "events ingested"

# Endpoint side — check Wazuh + Sysmon
Get-Service WazuhSvc, Sysmon64
Get-EventLog -LogName "Microsoft-Windows-Sysmon/Operational" -Newest 10
```

### Dashboard returns 401 even after login

- The cookie is set as `HttpOnly` + `samesite=lax`. If your reverse
  proxy strips cookies, the API will reject every request.
- Check the cookie shows up in browser dev tools under the API host's
  cookies tab.
- JWT expires after 8 h. Login again.

### No alerts firing despite events

- Confirm models are loaded:
  `curl http://localhost:8000/models -H "X-API-Key: ..." | jq`
  → both should show `current_version` ≠ `null`.
- Confirm threshold isn't too high in `config/detectors.yml`
  (default 0.5).
- Check the model wasn't trained on synthetic data and is now seeing
  real data with very different distribution. Inspect a SHAP output to
  see if features are non‑zero.

### Drift fires constantly

- Re‑snapshot baseline AFTER you've fed real traffic for ~1 h:
  `POST /models/drift/baseline`
- Check if real attack scenarios are happening (drift may be correctly
  detecting model staleness).

### FL handshake fails: `unexpected eof while reading`

- The org's client cert is expired or signed by a different CA.
  Re‑enroll: `POST /fl/orgs/enroll` again with the same public key.
- The FL coordinator was started **without** `--ssl-cert-reqs 2` —
  check the uvicorn args.

### `MODEL INTEGRITY VIOLATION` on startup

- Someone modified a `model.json` file in `detection/models/.../latest/`.
  Either restore from backup or roll back to a prior version.
- Or `MODEL_SIGNING_KEY` was rotated without re‑signing models — the
  signed manifests no longer match. Re‑train or re‑sign.

### `Federation CA not initialised` when enrolling an org

```bash
venv/bin/python -m federated.init_fl_ca --ca-dir data/fl_coordinator/ca
# Then restart the coordinator process so it loads the CA into memory.
```

---

## 14. Production security checklist

Before exposing this platform beyond your lab:

- [ ] **All secrets** in `.env` are unique 32+ byte random values, NOT
      example/dev values
- [ ] **Docker secrets** (`secrets/`) used in production, not env vars
- [ ] **HTTPS** on the API (uvicorn + cert OR nginx in front)
- [ ] `samesite=lax` cookie + **`secure=True`** flag set in
      `api/routes/auth.py` (currently `False` for dev)
- [ ] Wazuh agent registration password is **strong** and rotated periodically
- [ ] `MODEL_SIGNING_KEY` stored on the same host as models OR in a vault
- [ ] `FLEET_BOOTSTRAP_TOKEN` rotated **after every batch deployment**
      (it shouldn't outlive the deployment campaign)
- [ ] FL coordinator's CA private key (`ca_key.pem`) on a **separate
      host** or HSM — production should never have it next to the
      coordinator's runtime
- [ ] `FL_DEV_ALLOW_HEADER_MTLS` env var **NOT set** (enables a dev‑only
      auth bypass)
- [ ] `APT_ANONYMIZE` is `1` (default) — never disable for production
      collection
- [ ] `data/anonymizer/salt.bin` mode 600 + backed up separately from
      alert data (separation of duty: one box decrypts; the other
      collects)
- [ ] Docker hardening audit passes: `python scripts/audit_compose_hardening.py`
- [ ] Audit log integrity verification scheduled in cron (daily)
- [ ] Backup tarball of `data/` + `detection/models/` to off‑site

---

## 15. Reference

### 15.1 Endpoints

#### Org platform (port 8000)

**Auth (cookie‑based for dashboard):**
| Method | Path | Auth |
|---|---|---|
| `GET`  | `/auth/login` | none |
| `POST` | `/auth/login` | none |
| `POST` | `/auth/logout` | cookie |

**Dashboard (HTML, cookie auth):**
| Method | Path | Permission |
|---|---|---|
| `GET`  | `/dashboard` | logged in |
| `GET`  | `/dashboard/alerts[?severity&status&entity&hours]` | `read_alerts` |
| `GET`  | `/dashboard/alerts/{id}` | `read_alerts` |
| `POST` | `/dashboard/alerts/{id}/ack` | `acknowledge_alerts` |
| `GET`  | `/dashboard/fleet` | `manage_fleet` |
| `POST` | `/dashboard/fleet/{agent_id}/command` | `manage_fleet` |
| `GET`  | `/dashboard/graph` | `view_graphs` |

**REST (Bearer JWT or X-API-Key header):**
| Method | Path | Permission |
|---|---|---|
| `GET`  | `/health` | none |
| `GET`  | `/alerts[?severity&status&entity&hours&limit]` | `read_alerts` |
| `GET`  | `/alerts/stats` | `read_alerts` |
| `GET`  | `/alerts/{id}` | `read_alerts` |
| `GET`  | `/alerts/{id}/explanation[?top_k]` | `read_detections` |
| `GET`  | `/alerts/{id}/explanation.html` | `read_detections` |
| `POST` | `/alerts/{id}/acknowledge` | `acknowledge_alerts` |
| `GET`  | `/models` | `read_detections` |
| `GET`  | `/models/{name}/versions` | `read_detections` |
| `GET`  | `/models/{name}/importance[?importance_type&top_k]` | `read_detections` |
| `POST` | `/models/{name}/retrain` | `retrain_models` |
| `POST` | `/models/{name}/rollback/{version}` | `retrain_models` |
| `POST` | `/models/drift/baseline` | `manage_detectors` |
| `GET`  | `/fleet/agents` | `manage_fleet` |
| `POST` | `/fleet/agents/enroll` | `enroll_agents` OR `X-Bootstrap-Token` |
| `POST` | `/fleet/agents/{id}/commands` | `manage_fleet` |
| `POST` | `/fleet/commands/broadcast` | `manage_fleet` |
| `GET`  | `/fleet/commands/{command_id}` | `manage_fleet` |
| `GET`  | `/allowlist/dns` | `read_detections` |
| `POST` | `/allowlist/dns` | `manage_detectors` |
| `DELETE` | `/allowlist/dns/{domain}` | `manage_detectors` |
| `POST` | `/fl/local/keypair/init` | `manage_fl_local` (admin) |
| `GET`  | `/fl/local/keypair/public` | `manage_fl_local` |
| `POST` | `/fl/local/configure` | `manage_fl_local` |
| `GET`  | `/fl/local/status` | `read_detections` |
| `POST` | `/fl/local/opt-in` | `manage_fl_local` |
| `GET`  | `/fl/local/contributions` | `manage_fl_local` |

**Agent (per‑agent HMAC, `Authorization: APT-HMAC ...` header):**
| Method | Path | Auth |
|---|---|---|
| `POST` | `/agents/{id}/poll` | HMAC |
| `POST` | `/agents/{id}/results` | HMAC + signed envelope |
| `POST` | `/agents/{id}/heartbeat` | HMAC |

#### FL coordinator (port 8889 — separate process, separate auth)

| Method | Path | Permission |
|---|---|---|
| `POST` | `/fl/orgs/enroll` | `fl_enroll_org` (FLAdmin) |
| `GET`  | `/fl/orgs` | `fl_view_orgs` |
| `POST` | `/fl/orgs/{id}/block` | `fl_block_org` |
| `POST` | `/fl/orgs/{id}/unblock` | `fl_unblock_org` |
| `DELETE` | `/fl/orgs/{id}` | `fl_revoke_org` (FLAdmin) |
| `POST` | `/fl/rounds/start` | `fl_start_round` |
| `GET`  | `/fl/rounds` | `fl_view_rounds` |
| `GET`  | `/fl/rounds/{id}` | `fl_view_rounds` |
| `GET`  | `/fl/rounds/{id}/challenge` | mTLS or X-FL-API-Key |
| `POST` | `/fl/rounds/{id}/contribute` | mTLS or X-FL-API-Key + signed attestation |
| `GET`  | `/fl/rounds/{id}/global-model` | mTLS or X-FL-API-Key |
| `GET`  | `/fl/audit` | `fl_view_audit` |

### 15.2 Environment variables

| Variable | Component | Default | Purpose |
|---|---|---|---|
| `JWT_SECRET` | API | (required) | Sign org‑platform JWTs |
| `MODEL_SIGNING_KEY` | API + training | "" | HMAC key for model manifests |
| `MODEL_STORE_DIR` | API | `detection/models` | ModelStore base directory |
| `FLEET_BOOTSTRAP_TOKEN` | API | (unset = bootstrap path closed) | Token for `/fleet/agents/enroll` without admin auth |
| `FL_LOCAL_FERNET_KEY` | API | (required to use FL local) | Encrypts org's FL API key + private key at rest |
| `APT_ANONYMIZE` | API | `1` | Set `0` to disable username pseudonymization (dev only) |
| `APT_ANONYMIZER_SALT_FILE` | API | `data/anonymizer/salt.bin` | Where the anonymizer salt lives |
| `MISP_ENABLED` | API | `1` | Enable MISP IoC enrichment |
| `MISP_MODE` | API | `file` | `file` or `live` |
| `MISP_FILE_PATH` | API | `threat_intel/iocs.json` | File‑mode IoC source |
| `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL`, `MISP_CACHE_TTL_SECONDS` | API | — | Live‑mode MISP config |
| `WAZUH_ALERT_FILE` | API | `data/alerts/wazuh_external.json` | Where Wazuh‑format alerts get appended |
| `GRAPH_DIR` | API | `data/graphs` | Where attack‑graph HTML files are written |
| `CONFIG_DIR`, `DATA_DIR`, `LOG_LEVEL`, `DETECTION_LOOP_ENABLED` | API | `config`, `data`, `INFO`, `true` | basics |
| `FL_JWT_SECRET` | FL coordinator | (required) | Sign FL coordinator JWTs (separate from JWT_SECRET) |
| `FL_DATA_DIR` | FL coordinator | `data/fl_coordinator` | Coordinator DB + audit + CA |
| `FL_CA_DIR` | FL coordinator | `<DATA_DIR>/ca` | Federation CA material |
| `FL_USERS_FILE` | FL coordinator | `config/fl_users.yml` | Coordinator's user roster |
| `FL_API_PORT` | FL coordinator | `8889` | REST + mTLS port |
| `FL_DEV_ALLOW_HEADER_MTLS` | FL coordinator | (unset) | Dev‑only: accept `X-Dev-Mtls-Org-Id` header instead of real cert. **NEVER set in production.** |

### 15.3 Ports

| Port | Service | From |
|---|---|---|
| 1514 | Wazuh agent ingestion | All endpoint laptops |
| 1515 | Wazuh agent registration | All endpoint laptops |
| 5601 | Wazuh dashboard | SOC analysts |
| 8000 | AI Platform API + dashboard | SOC analysts + IT admins |
| 8080 | Standalone attack graph viewer | SOC analysts (optional — embedded in dashboard) |
| 8888 | Flower FL gRPC server (legacy) | FL clients (org platforms) |
| 8889 | FL coordinator REST + mTLS | FL coordinator users + org FL clients |
| 55000 | Wazuh manager REST | AI Platform → Wazuh |

### 15.4 File layout

```
threat-hunting-platform/
├── api/                      ← FastAPI app (REST + dashboard HTML)
│   ├── main.py
│   ├── routes/               ← health, models, fleet, agent, alerts, allowlist,
│   │                            fl_local, auth, dashboard
│   └── templates/            ← Jinja2 dashboard pages
├── ingestion/                ← Wazuh connector + preprocessor + DLQ
├── features/                 ← 6 extractors + composable pipeline + cache
├── detection/
│   ├── detectors/            ← XGBoost detectors (lateral_movement, dns_exfiltration)
│   ├── model_store.py        ← signed model store
│   ├── drift_monitor.py
│   ├── explainer.py          ← SHAP via XGBoost TreeSHAP
│   ├── registry.py           ← detector plugin registry
│   ├── subscriber.py         ← bus subscriber that runs detection
│   └── models/               ← trained models live here (versioned dirs)
├── alert_manager/            ← AlertSubscriber, AlertStore, WazuhPublisher
├── threat_intel/
│   ├── enricher.py           ← MITRE + MISP + response actions
│   ├── misp_client.py        ← file/live IoC client
│   └── iocs.json             ← sample IoC file (file‑mode default)
├── visualization/
│   ├── graph_builder.py      ← MultiDiGraph + benign‑domain filter
│   ├── renderer.py           ← pyvis HTML renderer
│   ├── subscriber.py         ← bus subscriber → renders current.html
│   ├── explanation_widget.py ← SHAP HTML widget
│   └── web.py                ← standalone graph server (port 8080)
├── federated/
│   ├── attestation.py        ← Ed25519 sign/verify + canonical JSON
│   ├── ca.py                 ← federation CA + cert issuance + CRL
│   ├── coordinator_app.py    ← coordinator FastAPI entrypoint
│   ├── coordinator_api.py    ← coordinator REST routes
│   ├── coordinator_store.py  ← orgs + rounds + challenges + contributions
│   ├── fl_security.py        ← coordinator's separate AuthManager + FLRoles
│   ├── mtls_middleware.py    ← extracts mTLS peer cert → org_id
│   ├── local_state.py        ← org-side FL state
│   ├── server.py / client.py ← Flower gRPC implementations
│   ├── aggregation.py / privacy.py / trust.py
│   ├── init_fl_ca.py         ← CLI: bootstrap federation CA
│   ├── run_demo.py           ← in-process FL demo + convergence graph
│   └── mtls_demo.py          ← real TCP mTLS demo with adversarial scenarios
├── observability/
│   └── audit.py              ← hash‑chained audit DB
├── shared/
│   ├── schemas.py            ← Pydantic models (NormalizedEvent, FeatureVector, ...)
│   ├── interfaces.py         ← BaseDetector + BaseFeatureExtractor
│   ├── enums.py
│   ├── events.py             ← async pub/sub bus
│   ├── security.py           ← org platform AuthManager + Roles
│   ├── commands.py           ← fleet remote-control schemas + HMAC
│   ├── allowlist.py          ← admin-managed DNS allowlist
│   ├── anonymizer.py         ← PII pseudonymization
│   ├── config.py             ← YAML loader with env var resolution
│   ├── logging.py            ← structured JSON logging
│   └── health.py
├── training/
│   ├── synthetic.py          ← labelled event generator
│   ├── trainer.py            ← windowing + features + XGBoost fit + sign
│   ├── train_models.py       ← CLI
│   ├── tuning.py             ← GridSearchCV
│   ├── evaluate_models.py    ← NFR-02 grading
│   └── loaders/mordor.py     ← Mordor / Security-Datasets loader
├── scripts/
│   ├── deploy_endpoint.ps1   ← endpoint deploy + enrol + scheduled task
│   ├── agent_command_handler.ps1 ← command-execution daemon
│   ├── sysmon_config.xml     ← balanced profile
│   ├── sysmon_config_lean.xml
│   └── audit_compose_hardening.py
├── config/
│   ├── platform.yml
│   ├── wazuh.yml
│   ├── detectors.yml
│   ├── federated.yml
│   ├── security.yml          ← org users + JWT secret reference
│   └── fl_users.yml          ← FL coordinator users (if running FL)
├── data/                     ← runtime state (DBs, models, graphs, audit, CA)
└── docker-compose.yml        ← deployment topology
```

### 15.5 Permissions matrix (full)

| Permission | viewer | analyst | operator | admin |
|---|:--:|:--:|:--:|:--:|
| `read_alerts` | ✓ | ✓ | ✓ | ✓ |
| `read_detections` | ✓ | ✓ | ✓ | ✓ |
| `view_graphs` | ✓ | ✓ | ✓ | ✓ |
| `acknowledge_alerts` |  | ✓ | ✓ | ✓ |
| `add_notes` |  | ✓ | ✓ | ✓ |
| `export_data` |  | ✓ | ✓ | ✓ |
| `update_thresholds` |  |  | ✓ | ✓ |
| `manage_detectors` |  |  | ✓ | ✓ |
| `manage_fleet` |  |  | ✓ | ✓ |
| `enroll_agents` |  |  |  | ✓ |
| `retrain_models` |  |  |  | ✓ |
| `manage_users` |  |  |  | ✓ |
| `view_audit_log` |  |  |  | ✓ |
| `manage_fl_local` |  |  |  | ✓ |

**FL coordinator roles (separate roster — none of these overlap with org‑platform roles):**

| Permission | fl_viewer | fl_operator | fl_admin |
|---|:--:|:--:|:--:|
| `fl_view_orgs` | ✓ | ✓ | ✓ |
| `fl_view_rounds` | ✓ | ✓ | ✓ |
| `fl_view_audit` | ✓ | ✓ | ✓ |
| `fl_start_round` |  | ✓ | ✓ |
| `fl_block_org` |  | ✓ | ✓ |
| `fl_unblock_org` |  | ✓ | ✓ |
| `fl_enroll_org` |  |  | ✓ |
| `fl_revoke_org` |  |  | ✓ |
| `fl_configure_round` |  |  | ✓ |
| `fl_manage_users` |  |  | ✓ |

---

## Appendix A: Common task cookbook

Quick recipes for the most common operations.

### Add a new SOC analyst

```bash
KEY=$(openssl rand -base64 32)
HASH=$(echo -n "$KEY" | sha256sum | cut -d' ' -f1)
echo "API key for new analyst: $KEY"
# Paste $HASH into config/security.yml as a new users[] entry with role: analyst
docker compose restart api
```

### Bulk‑deploy collector to 50 laptops

See §6.2 — same script, just feed a longer list to `New-PSSession`.

### Rotate every model after major retraining

```bash
# Force every detector to use the new latest version
docker compose restart api
# Or hot-reload without restart:
curl -X POST http://localhost:8000/models/lateral_movement/retrain \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -d '{"hot_reload":true,"hours":48,"hosts":10,"num_boost_round":300}'
```

### Quarantine a suspicious laptop (turn off telemetry but keep cert)

```bash
# Toggle Sysmon off (collection stops, agent stays connected)
curl -X POST http://localhost:8000/fleet/agents/LAPTOP-007/commands \
     -H "X-API-Key: $YOUR_ADMIN_KEY" \
     -d '{"command_type":"toggle_telemetry",
          "params":{"source":"sysmon","enabled":false}}'
```

### Audit who acknowledged a specific alert

```bash
venv/bin/python -c "
from observability.audit import AuditTrail
a = AuditTrail(db_path='data/audit/audit.db')
for r in a.query(action='alert.acknowledge'):
    if r['target'] == 'alert_abc123def456':
        print(r['actor'], r['timestamp'])
"
```

---

## Appendix B: Mental model for examiners

If someone is reviewing this without operational context, give them
this paragraph:

> "This platform sits between a fleet of corporate Windows laptops and
> a SOC analyst. Each laptop runs Sysmon and a Wazuh agent that ship
> security telemetry to a central server. The server's AI Platform
> normalizes those events, computes 141 behavioural features across six
> categories, and runs them through two XGBoost classifiers — one
> trained to spot credential‑based lateral movement, the other to spot
> covert DNS exfiltration. Detections are explained per‑prediction with
> SHAP, enriched with MITRE ATT&CK techniques and MISP IoC matches,
> deduplicated, persisted, published to the existing Wazuh dashboard,
> and surfaced in a dedicated SOC dashboard with an interactive attack
> graph. A separate federated‑learning coordinator (with its own user
> roster and trust boundary) lets multiple organizations improve their
> models together without sharing raw security data, using
> differential‑privacy‑protected XGBoost tree contributions
> cryptographically signed per organization. Operators can remotely
> control the laptop fleet — switching profiles, toggling telemetry —
> through HMAC‑signed commands with a constrained whitelist of
> operations on the endpoint side."

---

*This document covers v1.0 of the platform. For implementation details
see the source code; for design rationale see Chapter 5 of the FYP
proposal.*
