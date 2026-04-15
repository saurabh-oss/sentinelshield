# Contributing to SentinelShield

Thank you for your interest in contributing! This document covers how to get the project running locally, what kinds of contributions are welcome, and how to submit them.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Project Layout](#project-layout)
- [Adding a Detector](#adding-a-detector)
- [Adding a Resolver](#adding-a-resolver)
- [Adding Detection Rules](#adding-detection-rules)
- [Frontend Changes](#frontend-changes)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Code Style](#code-style)

---

## Getting Started

1. Fork and clone the repo.
2. Copy `.env.example` to `.env` and fill in the required values.
3. Start all services:
   ```bash
   docker compose up --build -d
   ```
4. Run the demo simulator to verify everything works end-to-end:
   ```bash
   docker compose exec sentinel-engine python -m scripts.demo_simulator
   ```

---

## Project Layout

```
sentinel-engine/
  detectors/          # Add new threat detectors here
  resolvers/          # Add new remediation resolvers here
  rules/              # YAML-based detection rules
  collectors/         # Event ingestion from external sources
  scripts/            # Demo & utility scripts

nexuscloud-api/       # Simulated target product (FastAPI)
sentinel-dashboard/   # React control-plane UI
```

---

## Adding a Detector

Detectors live in `sentinel-engine/detectors/`. Each detector must subclass `BaseDetector`:

```python
# sentinel-engine/detectors/my_detector.py
from detectors.base import BaseDetector, Detection

class MyDetector(BaseDetector):
    def __init__(self):
        super().__init__("my_detector")

    async def detect(self, event: dict) -> list[Detection]:
        # Return a list of Detection objects (empty list = no threat)
        ...
```

Register it in `sentinel-engine/detectors/__init__.py` and, if needed, add matching rules to `sentinel-engine/rules/detection_rules.yml`.

---

## Adding a Resolver

Resolvers live in `sentinel-engine/resolvers/resolvers.py`. Each resolver must subclass `BaseResolver`:

```python
class MyResolver(BaseResolver):
    def __init__(self):
        super().__init__("My Resolver")

    async def resolve(self, metadata: dict) -> ResolutionResult:
        ...
        return ResolutionResult(
            action_type="my_action",
            status="success",
            details={...},
            rollback_available=False,
            timestamp=datetime.now(timezone.utc),
        )
```

Map the resolver to a `resolver_action` string in `sentinel-engine/config.py` (`RESOLVER_MAP`).

---

## Adding Detection Rules

YAML rules are defined in `sentinel-engine/rules/detection_rules.yml`. A rule looks like:

```yaml
- id: my_rule
  name: My Rule
  description: Detects something suspicious
  conditions:
    field: path
    operator: contains
    value: "/suspicious"
  severity: high
  resolver_action: my_action
```

---

## Frontend Changes

The dashboard is a single React component at `sentinel-dashboard/src/App.jsx`. For local development without Docker:

```bash
cd sentinel-dashboard
npm install
npm run dev        # Vite dev server at http://localhost:5173
```

Ensure the Sentinel Engine API is reachable at `http://localhost:8001` (start it separately or via Docker Compose).

---

## Submitting a Pull Request

1. Create a branch from `main`: `git checkout -b feature/my-change`
2. Make your changes and test end-to-end with the demo simulator.
3. Open a pull request against `main` with a clear description of what it does and why.
4. Include any relevant demo output or screenshots.

---

## Code Style

- **Python**: Follow PEP 8. Keep functions focused and add docstrings to public methods.
- **JavaScript/JSX**: Consistent with the existing Tailwind + React patterns in `App.jsx`.
- **YAML**: 2-space indentation.
- Do not commit `.env` or any file containing real credentials or API keys.
