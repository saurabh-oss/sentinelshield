import time
import logging
from typing import Dict, Optional, DefaultDict
from collections import defaultdict
from detectors.base import BaseDetector, Detection

logger = logging.getLogger("sentinel.detector.threshold")

class ThresholdDetector(BaseDetector):
    """Detects threshold breaches — brute force login, rate abuse, etc."""

    def __init__(self):
        super().__init__("ThresholdDetector", "Detects events exceeding count thresholds in time windows")
        # Sliding windows: key -> list of timestamps
        self.windows: DefaultDict[str, list] = defaultdict(list)
        self.triggered: Dict[str, float] = {}  # cooldown tracking

    async def analyze(self, event: Dict) -> Optional[Detection]:
        self.events_analyzed += 1
        event_type = event.get("event_type", "")

        # ── Brute Force Detection ──
        if event_type == "auth_event" and event.get("action") in ("login_failed", "login_locked"):
            ip = event.get("client_ip", "unknown")
            key = f"auth_fail:{ip}"
            now = time.time()

            self.windows[key].append(now)
            # Keep only last 60 seconds
            self.windows[key] = [t for t in self.windows[key] if now - t < 60]

            count = len(self.windows[key])
            if count >= 10 and not self._in_cooldown(key):
                self.triggered[key] = now
                self.detections_count += 1
                return Detection(
                    alert_type="brute_force",
                    severity="high",
                    title=f"Brute Force Attack Detected from {ip}",
                    description=f"{count} failed login attempts from {ip} in the last 60 seconds. "
                                f"Threshold: 10. This pattern is consistent with credential brute-forcing.",
                    detection_method="threshold",
                    risk_score=min(95.0, 50 + count * 3),
                    affected_resource={"type": "ip_address", "id": ip},
                    source_events=[event],
                    resolver_action="block_ip",
                    metadata={"count": count, "window_seconds": 60, "ip": ip}
                )

        # ── API Rate Abuse (simple threshold) ──
        if event_type == "api_request":
            ip = event.get("client_ip", "unknown")
            key = f"api_rate:{ip}"
            now = time.time()

            self.windows[key].append(now)
            self.windows[key] = [t for t in self.windows[key] if now - t < 60]

            count = len(self.windows[key])
            if count >= 200 and not self._in_cooldown(key):
                self.triggered[key] = now
                self.detections_count += 1
                return Detection(
                    alert_type="rate_abuse",
                    severity="high",
                    title=f"API Rate Abuse from {ip}",
                    description=f"{count} API requests from {ip} in 60 seconds, far exceeding normal patterns.",
                    detection_method="threshold",
                    risk_score=min(90.0, 40 + count * 0.2),
                    affected_resource={"type": "ip_address", "id": ip},
                    source_events=[event],
                    resolver_action="rate_limit",
                    metadata={"count": count, "window_seconds": 60}
                )

        return None

    def _in_cooldown(self, key: str, cooldown: float = 120) -> bool:
        last = self.triggered.get(key, 0)
        return (time.time() - last) < cooldown

    async def reset(self):
        self.windows.clear()
        self.triggered.clear()
