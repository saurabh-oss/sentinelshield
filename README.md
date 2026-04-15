# SentinelShield — Anomaly & Threat Detection Framework

## Executive Summary

**SentinelShield** is an enterprise-grade anomaly detection and automated threat resolution framework designed for SaaS product companies. It continuously monitors application behaviour, infrastructure metrics, data ingestion patterns, release deployments, API usage, and security posture — then **detects**, **alerts**, and **auto-resolves** threats in real time.

This PoC demonstrates SentinelShield protecting **NexusCloud Commerce**, a simulated SaaS subscription commerce platform (think Adobe/Salesforce/Microsoft model).

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    SENTINEL DASHBOARD (React)                │
│          Real-time threat view · Alert management            │
│          Resolution audit trail · Risk scoring               │
└──────────────┬───────────────────────────┬───────────────────┘
               │ REST API                  │ WebSocket
┌──────────────▼───────────────────────────▼───────────────────┐
│                  SENTINEL ENGINE (Python)                     │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────────────┐    │
│  │  Collectors  │ │  Detectors   │ │    Resolvers       │    │
│  │─────────────│ │──────────────│ │────────────────────│    │
│  │ API Metrics  │ │ Isolation    │ │ Rate Limiter       │    │
│  │ Log Ingestor │ │  Forest      │ │ IP Blocker         │    │
│  │ Release Mon. │ │ Z-Score      │ │ Circuit Breaker    │    │
│  │ Data Flow    │ │ Rule Engine  │ │ Rollback Trigger   │    │
│  │ Auth Tracker │ │ Sequence     │ │ Credential Rotate  │    │
│  │ Patch Audit  │ │  Anomaly     │ │ Incident Escalator │    │
│  └─────────────┘ └──────────────┘ └────────────────────┘    │
└──────┬──────────────────┬────────────────────┬───────────────┘
       │                  │                    │
┌──────▼──────┐  ┌────────▼────────┐  ┌───────▼───────┐
│  Redis      │  │   PostgreSQL    │  │  Prometheus   │
│  Event Bus  │  │   Events/Logs   │  │  Metrics TS   │
└─────────────┘  └─────────────────┘  └───────┬───────┘
                                              │
                                      ┌───────▼───────┐
                                      │   Grafana     │
                                      │  Dashboards   │
                                      └───────────────┘
       │
┌──────▼──────────────────────────────────────────────────────┐
│              NEXUSCLOUD COMMERCE (Target Product)            │
│  FastAPI · Subscription Mgmt · Payments · Licensing · API   │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ Auth/SSO │ │ Billing   │ │ Catalog  │ │ Webhooks     │  │
│  │ Gateway  │ │ Engine    │ │ Service  │ │ & Events     │  │
│  └──────────┘ └───────────┘ └──────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Business Capabilities Addressed

| # | Capability | SentinelShield Feature |
|---|-----------|----------------------|
| 1 | **Continuous Behavioural Monitoring** | API call pattern analysis, user session profiling |
| 2 | **Release Risk Assessment** | Deployment diff analysis, canary metric comparison |
| 3 | **Data Ingestion Integrity** | Schema drift detection, volume anomaly alerts |
| 4 | **Patch & Upgrade Audit** | Dependency vulnerability scanning, change tracking |
| 5 | **Threat Detection** | Brute force, credential stuffing, injection attempts |
| 6 | **Automated Resolution** | Rate limiting, IP blocking, circuit breaking, rollback |
| 7 | **Compliance & Audit Trail** | Immutable event log, resolution chain-of-custody |
| 8 | **Risk Scoring** | Per-tenant, per-endpoint, per-release risk scores |

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Target Product | FastAPI (Python) | NexusCloud Commerce SaaS |
| Detection Engine | Python, scikit-learn, NumPy | ML anomaly detection |
| Event Bus | Redis Streams | Real-time event propagation |
| Persistent Store | PostgreSQL 16 | Events, alerts, audit trail |
| Time-Series Metrics | Prometheus | Infrastructure & app metrics |
| Visualization | Grafana | Pre-built ops dashboards |
| Dashboard | React 18 + Recharts | SentinelShield control plane |
| Reverse Proxy | Nginx | Dashboard + API routing |
| Orchestration | Docker Compose | Single-command deployment |
| AI Code Generation | Anthropic Claude API | Auto-synthesises new resolvers |

---

## Prerequisites

- **Docker** (Docker Desktop 4.x+ on macOS/Windows, or Docker Engine + Compose plugin on Linux)
- **Git**
- **8 GB RAM minimum** (16 GB recommended)
- **10 GB free disk space**
- **Anthropic API key** *(optional — only required for the AI Resolver Generator feature)*

> **Windows users:** Docker Desktop requires WSL2. Enable it via `wsl --install` before installing Docker Desktop.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/saurabh-oss/sentinelshield.git
cd sentinelshield
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Open `.env` and set your credentials. The only field needed for the full demo is the optional Anthropic API key:

```
ANTHROPIC_API_KEY=sk-ant-...
```

> Without an API key, SentinelShield still detects and resolves all threats using its built-in playbooks.
> The AI Resolver Generator feature (Phase 8 of the demo) is skipped with a log warning.

### 3. Launch Everything

```bash
docker compose up --build -d
```

First build takes ~5–8 minutes. Subsequent starts are < 30 seconds.

### 4. Access the Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **SentinelShield Dashboard** | http://localhost:3000 | — |
| **NexusCloud Commerce API** | http://localhost:8000/docs | — |
| **Grafana** | http://localhost:3001 | admin / sentinel *(or your .env value)* |
| **Prometheus** | http://localhost:9090 | — |
| **Sentinel Engine API** | http://localhost:8001/docs | — |

### 5. Run the Demo Simulator

This generates realistic traffic **and** injects threat scenarios:

```bash
docker compose exec sentinel-engine python -m scripts.demo_simulator
```

Or from the host (requires Python 3.10+):

```bash
pip install requests
python scripts/run_demo.py
```

### 6. Watch Detections Flow

- Open **SentinelShield Dashboard** → see threats appear in real time
- Open **Grafana** → pre-built dashboards show metric anomalies
- Check **Sentinel Engine API** → `/api/v1/alerts` for programmatic access

---

## AI Resolver Generator

SentinelShield can automatically write and deploy new resolver code when a threat
type is encountered that has no built-in playbook.

### How It Works

```
New threat detected
        │
        ▼
resolver_action not in RESOLVER_MAP?
        │  yes
        ▼
Claude API called with full threat context
  (alert type, severity, description, metadata)
        │
        ▼
Python class generated → exec() in safe namespace
  (only BaseResolver, ResolutionResult, stdlib available)
        │
        ▼
Resolver instantiated & added to RESOLVER_MAP
        │
        ├─► Resolution executed immediately for current alert
        │
        └─► Generated code persisted to generated_resolvers table
              (viewable at GET /api/v1/generated-resolvers)
```

### Demo: SQL Injection Probe (Phase 8)

The demo simulator injects SQL injection probes from a single attacker IP.
`SqlInjectionDetector` fires after 3 pattern-matched requests, raising a
`Detection` with `resolver_action="sql_injection_block"` — an action that has
**no built-in resolver**. The engine then:

1. Calls Claude with full threat context (attacker IP, matched patterns, affected endpoints)
2. Receives a complete `SqlInjectionBlockResolver` class definition
3. Instantiates and executes it — blocking the IP and quarantining the patterns
4. Stores the generated code for audit and future reuse

### Inspecting Generated Resolvers

```bash
curl http://localhost:8001/api/v1/generated-resolvers | python -m json.tool
```

---

## Demo Scenarios

The simulator runs these threat scenarios sequentially:

| # | Scenario | Detection Method | Auto-Resolution |
|---|----------|-----------------|-----------------|
| 1 | **Brute Force Login** | Rule: >10 failed auth in 60s | IP temporary block |
| 2 | **API Rate Abuse** | Z-Score on request volume | Dynamic rate limiting |
| 3 | **Data Exfiltration** | Isolation Forest on payload sizes | Circuit breaker |
| 4 | **Credential Stuffing** | Sequence anomaly on auth patterns | Account lockout + alert |
| 5 | **Suspicious Release** | Canary metric deviation post-deploy | Rollback trigger |
| 6 | **Schema Drift** | Data ingestion validator | Ingestion pause + alert |
| 7 | **Privilege Escalation** | Rule: role change without approval | Revert + escalate |
| 8 | **SQL Injection Probe** | Pattern matching on request paths | **AI-generated resolver** |

---

## Project Structure

```
sentinelshield/
├── docker-compose.yml          # Full orchestration
├── .env.example                # Environment variable template
├── README.md                   # This file
├── CONTRIBUTING.md             # Contributor guide
├── LICENSE                     # Apache 2.0
│
├── nexuscloud-api/             # TARGET PRODUCT
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py             # FastAPI app
│       ├── config.py           # Settings
│       ├── database.py         # DB connection
│       ├── models/             # SQLAlchemy models
│       ├── routers/            # API endpoints
│       ├── middleware/         # Event emission, Prometheus metrics
│       └── services/           # Business logic
│
├── sentinel-engine/            # DETECTION + RESOLUTION ENGINE
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # Engine entry point
│   ├── api.py                  # REST API for dashboard
│   ├── config.py
│   ├── database.py
│   ├── collectors/             # Redis Stream consumer
│   ├── detectors/              # Anomaly detection algorithms
│   │   └── sql_injection_detector.py  # Triggers AI resolver generation
│   ├── resolvers/              # Auto-resolution playbooks
│   │   └── ai_resolver_generator.py   # Claude-powered code synthesis
│   ├── rules/                  # Detection rules (YAML)
│   └── scripts/                # Demo simulator
│
├── sentinel-dashboard/         # REACT DASHBOARD
│   ├── Dockerfile
│   ├── nginx.conf              # SPA routing (served by Nginx)
│   ├── package.json
│   └── src/
│       ├── App.jsx             # Main dashboard component
│       ├── main.jsx
│       └── index.css
│
├── prometheus/                 # METRICS
│   └── prometheus.yml
│
├── grafana/                    # VISUALIZATION
│   └── provisioning/           # Auto-provisioned dashboards & data sources
│
└── scripts/                    # Host-side utilities
    ├── init-db.sql             # Database & schema initialisation
    └── run_demo.py             # Host-side demo launcher
```

---

## Production Deployment

The demo wires SentinelShield to NexusCloud Commerce out of the box. This section explains what to change when pointing SentinelShield at a **real application**.

### How SentinelShield Couples to Its Target

SentinelShield depends on the target application in three specific ways:

| Coupling point | Where it lives | What it does |
|----------------|---------------|--------------|
| **Event emission** | `nexuscloud-api/app/middleware/event_emitter.py` | Publishes every API request as a structured event to Redis Streams |
| **Event schema** | `sentinel-engine/detectors/` | Detectors expect fields like `method`, `path`, `status_code`, `ip`, `tenant_id`, `duration_ms` |
| **Resolver callbacks** | `sentinel-engine/resolvers/resolvers.py` | Some resolvers call back to the target app's management API to execute actions |

You cannot simply change an `.env` value to point at a different app — you need to connect the event pipeline. The engine and dashboard themselves are product-agnostic.

---

### Integration Options

#### Option A — Instrument the Target App *(fastest)*

Add the same middleware to your real application (~50 lines). Every inbound request is published to Redis Streams; SentinelShield consumes it from there.

```
Your Real App
    │
    ├── (existing code, unchanged)
    │
    └── EventEmitterMiddleware   ← add this
            │
            └── Redis Streams ──► SentinelShield Engine
```

**What to do:**
1. Copy/adapt `nexuscloud-api/app/middleware/event_emitter.py` into your app's middleware stack.
2. Normalise your app's request fields to the expected event schema.
3. Point both apps at the same Redis instance.
4. Update `SENTINEL_NEXUSCLOUD_URL` in `.env` to your real app's internal base URL.

**Pros:** Low latency, minimal infrastructure change  
**Cons:** Requires a code change in the target app

---

#### Option B — Log / Metric Ingestion *(no target app changes)*

Build a collector that reads from your app's existing logs or Prometheus metrics and normalises them into SentinelShield's event format. This is how agents like Datadog and Elastic APM work.

```
Your Real App
    │
    ├── Stdout / access logs
    │         │
    │    Log Collector (Fluent Bit, Vector, or custom)
    │         │
    └── Prometheus metrics ──► Custom SentinelShield Collector
                                          │
                                    Redis Streams ──► Engine
```

**What to do:**
1. Create a new collector in `sentinel-engine/collectors/` that reads from your log source.
2. Normalise events to the expected schema before pushing to Redis Streams.

**Pros:** Zero changes to the target app  
**Cons:** More upfront work; log-based detection has higher latency than inline middleware

---

#### Option C — Reverse Proxy / Sidecar *(production-grade, non-invasive)*

Run an Envoy or Nginx sidecar in front of your target app. The proxy intercepts every request, emits the event, and forwards the request onwards. Resolutions (IP blocks, rate limits) can also be enforced at the proxy layer.

```
Client ──► Envoy / Nginx sidecar ──► Your Real App
                    │
              Event emission
                    │
             Redis Streams ──► SentinelShield Engine
```

**Pros:** Completely non-invasive to the target app; proxy can enforce resolutions directly  
**Cons:** Adds a network hop; proxy configuration overhead

---

### Where to Run SentinelShield

**Do not run SentinelShield on the same server as the target application.** If the app server is compromised, a co-located detection layer is compromised too.

```
┌─────────────────────┐     Redis / Kafka      ┌──────────────────────┐
│  Target App Server  │ ──── event stream ───► │  SentinelShield      │
│  (your production)  │                         │  (dedicated server   │
│                     │ ◄─── resolver calls ─── │   or cluster)        │
└─────────────────────┘                         └──────────────────────┘
```

A dedicated host or Kubernetes namespace (with network policies) means:
- SentinelShield keeps operating even while the target is under attack
- Compromising the target app does not expose detection rules or the alert database
- Both sides scale independently

---

### Secrets Management

The `.env` file is suitable for Docker Compose on a single machine. For production, inject secrets through your orchestration platform instead of a file on disk:

| Platform | Recommended approach |
|----------|---------------------|
| **Kubernetes** | `Secret` objects injected as env vars; or the external-secrets operator pulling from Vault / AWS Secrets Manager |
| **AWS ECS** | Task definition env vars backed by Secrets Manager or Parameter Store |
| **Docker Compose on a server** | `.env` file with `chmod 600`, owned by root — never committed to version control (already excluded by `.gitignore`) |
| **Any platform** | Never bake secrets into Docker images |

---

### Step-by-Step: Pointing at a Real App

1. **Connect the event pipeline** using one of the options above. Option A (middleware) is the fastest path.

2. **Update `.env`**

   ```
   SENTINEL_NEXUSCLOUD_URL=https://your-real-app-internal-url
   SENTINEL_REDIS_URL=redis://your-shared-redis:6379/0
   ANTHROPIC_API_KEY=sk-ant-...   # optional — enables AI resolver generation
   ```

3. **Tune detection thresholds** — `sentinel-engine/rules/detection_rules.yml` is calibrated for demo traffic. Adjust threshold values to match your real application's baseline. The Z-score and Isolation Forest detectors learn baselines automatically; rule-based detectors need manual tuning.

4. **Adapt resolver callbacks** — any resolver that calls back into the target app (e.g. `PauseIngestionResolver`) needs its URL and auth headers updated to match your real app's admin API.

5. **Drop NexusCloud from Compose** — once your real app is connected, remove the `nexuscloud-api` service block from `docker-compose.yml`.

---

## Extending the Framework

### Add a New Detector

1. Create `sentinel-engine/detectors/my_detector.py`
2. Implement the `BaseDetector` interface
3. Register in `sentinel-engine/detectors/__init__.py`
4. Add rules in `sentinel-engine/rules/`

### Add a New Resolver

1. Create `sentinel-engine/resolvers/my_resolver.py`
2. Implement the `BaseResolver` interface
3. Map the threat type to the resolver in `sentinel-engine/config.py`

### Let AI Write a Resolver

Set a detector's `resolver_action` to any string **not** present in `RESOLVER_MAP`.
When that detection fires, the engine will automatically:

1. Call the Claude API with the full threat context
2. `exec()` the returned class in a safe namespace
3. Register it in `RESOLVER_MAP` and execute it immediately
4. Persist the code to `generated_resolvers` for audit

Set `ANTHROPIC_API_KEY` in `.env` to enable this.

### Monitor a New Product

1. Implement collectors for the product's APIs/logs
2. Configure endpoints in `.env`
3. The detection engine is product-agnostic by design

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add detectors, resolvers, or rules, and how to submit a pull request.

---

## License

[Apache 2.0](LICENSE) — Free for commercial and internal use.
