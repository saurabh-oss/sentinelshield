import time
import logging
import numpy as np
from typing import Dict, Optional, DefaultDict
from collections import defaultdict, deque
from detectors.base import BaseDetector, Detection

logger = logging.getLogger("sentinel.detector.zscore")

class ZScoreDetector(BaseDetector):
    """Detects anomalies using z-score deviation from rolling baselines."""

    def __init__(self, zscore_threshold: float = 3.0, window_size: int = 200):
        super().__init__("ZScoreDetector", "Statistical z-score anomaly detection on numeric metrics")
        self.zscore_threshold = zscore_threshold
        self.window_size = window_size
        self.metric_windows: DefaultDict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.cooldowns: Dict[str, float] = {}

    async def analyze(self, event: Dict) -> Optional[Detection]:
        self.events_analyzed += 1
        event_type = event.get("event_type", "")

        # Track response times
        if event_type == "api_request":
            duration = float(event.get("duration_ms", 0))
            if duration > 0:
                det = self._check_metric("response_time_ms", duration, event)
                if det: return det

            # Track response sizes for exfiltration
            content_len = int(event.get("content_length", 0))
            if content_len > 0:
                det = self._check_metric("response_bytes", content_len, event,
                                          alert_type="data_exfiltration",
                                          title_prefix="Abnormal Response Size",
                                          resolver="circuit_break")
                if det: return det

        # Track ingestion volumes
        if event_type == "data_ingestion":
            payload_bytes = float(event.get("payload_bytes", 0))
            if payload_bytes > 0:
                det = self._check_metric("ingestion_bytes", payload_bytes, event,
                                          alert_type="ingestion_anomaly",
                                          title_prefix="Data Ingestion Volume Anomaly",
                                          resolver="pause_ingestion")
                if det: return det

        return None

    def _check_metric(self, metric_name: str, value: float, event: Dict,
                      alert_type: str = "metric_anomaly",
                      title_prefix: str = "Metric Anomaly",
                      resolver: str = "rate_limit") -> Optional[Detection]:
        window = self.metric_windows[metric_name]
        window.append(value)

        if len(window) < 30:
            return None  # Need minimum samples

        arr = np.array(window)
        mean = np.mean(arr[:-1])  # Exclude current value
        std = np.std(arr[:-1])

        if std == 0:
            return None

        zscore = abs((value - mean) / std)

        if zscore >= self.zscore_threshold and not self._in_cooldown(metric_name):
            self.cooldowns[metric_name] = time.time()
            self.detections_count += 1
            severity = "critical" if zscore > 5 else "high" if zscore > 4 else "medium"
            return Detection(
                alert_type=alert_type,
                severity=severity,
                title=f"{title_prefix}: {metric_name} (z={zscore:.2f})",
                description=(
                    f"Metric '{metric_name}' value {value:.2f} deviates {zscore:.2f} standard deviations "
                    f"from the rolling mean ({mean:.2f} ± {std:.2f}). "
                    f"This exceeds the threshold of {self.zscore_threshold}σ."
                ),
                detection_method="zscore",
                risk_score=min(99.0, zscore * 15),
                affected_resource={"type": "metric", "id": metric_name},
                source_events=[event],
                resolver_action=resolver,
                metadata={"metric": metric_name, "value": value, "mean": float(mean),
                          "std": float(std), "zscore": float(zscore)}
            )
        return None

    def _in_cooldown(self, key: str, seconds: float = 120) -> bool:
        return (time.time() - self.cooldowns.get(key, 0)) < seconds

    async def reset(self):
        self.metric_windows.clear()
        self.cooldowns.clear()
