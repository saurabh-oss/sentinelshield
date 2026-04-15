import time
import logging
from typing import Dict, Optional
from collections import deque
from detectors.base import BaseDetector, Detection

logger = logging.getLogger("sentinel.detector.rules")

class RuleEngineDetector(BaseDetector):
    """Rule-based detector for privilege escalation, schema drift, and release anomalies."""

    def __init__(self):
        super().__init__("RuleEngineDetector", "Deterministic rule-based threat detection")
        self.release_error_rates: deque = deque(maxlen=100)
        self.pre_release_error_mean = 1.2  # baseline from seeded data
        self.cooldowns: Dict[str, float] = {}

    async def analyze(self, event: Dict) -> Optional[Detection]:
        self.events_analyzed += 1
        event_type = event.get("event_type", "")

        # ── Privilege Escalation ──
        if event_type == "role_change":
            has_approval = event.get("has_approval", "True") == "True"
            if not has_approval:
                self.detections_count += 1
                return Detection(
                    alert_type="privilege_escalation",
                    severity="critical",
                    title=f"Unauthorized Privilege Escalation: {event.get('user_email', 'unknown')}",
                    description=(
                        f"Role change from '{event.get('old_role')}' to '{event.get('new_role')}' "
                        f"for user {event.get('user_email')} was performed WITHOUT approval token. "
                        f"Source IP: {event.get('client_ip', 'unknown')}."
                    ),
                    detection_method="rule",
                    risk_score=95.0,
                    affected_resource={"type": "user", "id": event.get("user_email", "")},
                    source_events=[event],
                    resolver_action="revert_escalate",
                    metadata={"old_role": event.get("old_role"), "new_role": event.get("new_role"),
                              "email": event.get("user_email"), "ip": event.get("client_ip")}
                )

        # ── Schema Drift ──
        if event_type == "data_ingestion":
            drift_pct = float(event.get("schema_drift_pct", 0))
            if drift_pct > 5 and not self._in_cooldown("schema_drift"):
                self.cooldowns["schema_drift"] = time.time()
                self.detections_count += 1
                severity = "critical" if drift_pct > 30 else "high" if drift_pct > 15 else "medium"
                return Detection(
                    alert_type="schema_drift",
                    severity=severity,
                    title=f"Schema Drift Detected: {drift_pct:.1f}% unexpected fields",
                    description=(
                        f"Data ingestion from source '{event.get('source', 'unknown')}' contains "
                        f"{drift_pct:.1f}% unexpected fields: {event.get('unexpected_fields', '[]')}. "
                        f"This may indicate a data pipeline misconfiguration or injection attempt."
                    ),
                    detection_method="schema_validation",
                    risk_score=min(90.0, drift_pct * 2),
                    affected_resource={"type": "data_pipeline", "id": event.get("source", "api")},
                    source_events=[event],
                    resolver_action="pause_ingestion",
                    metadata={"drift_pct": drift_pct, "source": event.get("source")}
                )

        # ── Post-Release Error Spike ──
        if event_type == "api_request":
            status = int(event.get("status_code", 200))
            is_error = 1.0 if status >= 500 else 0.0
            self.release_error_rates.append(is_error)

        if event_type == "release_deployed":
            if len(self.release_error_rates) > 20 and not self._in_cooldown("release_canary"):
                import numpy as np
                recent = list(self.release_error_rates)[-50:]
                error_rate = np.mean(recent) * 100
                if error_rate > self.pre_release_error_mean * 2.5:
                    self.cooldowns["release_canary"] = time.time()
                    self.detections_count += 1
                    return Detection(
                        alert_type="release_regression",
                        severity="high",
                        title=f"Post-Release Error Spike: v{event.get('version', '?')}",
                        description=(
                            f"Error rate spiked to {error_rate:.1f}% after deploying "
                            f"v{event.get('version')}. Baseline: {self.pre_release_error_mean:.1f}%. "
                            f"Automatic rollback recommended."
                        ),
                        detection_method="canary",
                        risk_score=min(95.0, error_rate * 5),
                        affected_resource={"type": "release", "id": event.get("version", "")},
                        source_events=[event],
                        resolver_action="rollback",
                        metadata={"error_rate": error_rate, "version": event.get("version"),
                                  "baseline": self.pre_release_error_mean}
                    )

        return None

    def _in_cooldown(self, key: str, seconds: float = 300) -> bool:
        return (time.time() - self.cooldowns.get(key, 0)) < seconds

    async def reset(self):
        self.release_error_rates.clear()
        self.cooldowns.clear()
