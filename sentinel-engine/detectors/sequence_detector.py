import time
import logging
from typing import Dict, Optional, DefaultDict
from collections import defaultdict
from detectors.base import BaseDetector, Detection

logger = logging.getLogger("sentinel.detector.sequence")

class SequenceDetector(BaseDetector):
    """Detects suspicious sequential patterns — credential stuffing, enumeration attacks."""

    def __init__(self):
        super().__init__("SequenceDetector", "Sequential pattern anomaly detection")
        # Track unique emails per IP in time window
        self.ip_emails: DefaultDict[str, set] = defaultdict(set)
        self.ip_timestamps: DefaultDict[str, list] = defaultdict(list)
        self.cooldowns: Dict[str, float] = {}

    async def analyze(self, event: Dict) -> Optional[Detection]:
        self.events_analyzed += 1

        if event.get("event_type") != "auth_event":
            return None
        if event.get("action") != "login_failed":
            return None

        ip = event.get("client_ip", "unknown")
        email = event.get("email", "unknown")
        now = time.time()

        self.ip_emails[ip].add(email)
        self.ip_timestamps[ip].append(now)

        # Cleanup old entries (30s window)
        self.ip_timestamps[ip] = [t for t in self.ip_timestamps[ip] if now - t < 30]

        unique_emails = len(self.ip_emails[ip])
        attempts = len(self.ip_timestamps[ip])

        # Credential stuffing: many different emails from same IP quickly
        if unique_emails >= 5 and attempts >= 5 and not self._in_cooldown(ip):
            self.cooldowns[ip] = now
            self.detections_count += 1

            # Calculate attack velocity
            if len(self.ip_timestamps[ip]) >= 2:
                time_span = self.ip_timestamps[ip][-1] - self.ip_timestamps[ip][0]
                velocity = attempts / max(time_span, 0.1)
            else:
                velocity = 0

            return Detection(
                alert_type="credential_stuffing",
                severity="critical",
                title=f"Credential Stuffing Attack from {ip}",
                description=(
                    f"Detected {unique_emails} unique email addresses attempted from IP {ip} "
                    f"within 30 seconds ({attempts} total attempts). "
                    f"Attack velocity: {velocity:.1f} attempts/sec. "
                    f"This pattern strongly indicates automated credential stuffing."
                ),
                detection_method="sequence",
                risk_score=min(99.0, 70 + unique_emails * 3),
                affected_resource={"type": "ip_address", "id": ip},
                source_events=[event],
                resolver_action="account_lockout",
                metadata={"unique_emails": unique_emails, "attempts": attempts,
                          "velocity": velocity, "ip": ip}
            )

        return None

    def _in_cooldown(self, key: str, seconds: float = 180) -> bool:
        return (time.time() - self.cooldowns.get(key, 0)) < seconds

    async def reset(self):
        self.ip_emails.clear()
        self.ip_timestamps.clear()
        self.cooldowns.clear()
