import time
import logging
import numpy as np
from typing import Dict, Optional, List
from collections import deque
from detectors.base import BaseDetector, Detection

logger = logging.getLogger("sentinel.detector.iforest")

class IsolationForestDetector(BaseDetector):
    """Multivariate anomaly detection using Isolation Forest on API request features."""

    def __init__(self, contamination: float = 0.05, min_samples: int = 100, retrain_interval: int = 500):
        super().__init__("IsolationForestDetector", "ML-based multivariate anomaly detection")
        self.contamination = contamination
        self.min_samples = min_samples
        self.retrain_interval = retrain_interval
        self.feature_buffer: deque = deque(maxlen=2000)
        self.event_buffer: deque = deque(maxlen=2000)
        self.model = None
        self.samples_since_train = 0
        self.cooldown_until = 0

    def _extract_features(self, event: Dict) -> Optional[List[float]]:
        """Extract numeric feature vector from event."""
        if event.get("event_type") != "api_request":
            return None
        try:
            return [
                float(event.get("duration_ms", 0)),
                float(event.get("content_length", 0)),
                float(event.get("status_code", 200)),
                len(event.get("path", "")),
                1.0 if event.get("method") == "POST" else 0.0,
            ]
        except (ValueError, TypeError):
            return None

    async def analyze(self, event: Dict) -> Optional[Detection]:
        self.events_analyzed += 1
        features = self._extract_features(event)
        if features is None:
            return None

        self.feature_buffer.append(features)
        self.event_buffer.append(event)
        self.samples_since_train += 1

        # Train/retrain model
        if self.model is None and len(self.feature_buffer) >= self.min_samples:
            self._train()
        elif self.model is not None and self.samples_since_train >= self.retrain_interval:
            self._train()

        if self.model is None:
            return None

        # Predict
        X = np.array([features])
        prediction = self.model.predict(X)[0]
        score = self.model.decision_function(X)[0]

        if prediction == -1 and time.time() > self.cooldown_until:
            self.cooldown_until = time.time() + 60
            self.detections_count += 1
            anomaly_score = abs(score)
            severity = "critical" if anomaly_score > 0.3 else "high" if anomaly_score > 0.15 else "medium"

            return Detection(
                alert_type="multivariate_anomaly",
                severity=severity,
                title=f"Isolation Forest: Anomalous Request Pattern (score={score:.3f})",
                description=(
                    f"A request pattern was flagged as anomalous by the Isolation Forest model. "
                    f"Features: duration={features[0]:.0f}ms, payload={features[1]:.0f}B, "
                    f"status={features[2]:.0f}. Decision score: {score:.4f}."
                ),
                detection_method="isolation_forest",
                risk_score=min(99.0, anomaly_score * 200),
                affected_resource={"type": "api_request", "id": event.get("path", "unknown")},
                source_events=[event],
                resolver_action="circuit_break",
                metadata={"features": features, "score": float(score),
                          "model_samples": len(self.feature_buffer)}
            )

        return None

    def _train(self):
        from sklearn.ensemble import IsolationForest
        X = np.array(list(self.feature_buffer))
        self.model = IsolationForest(contamination=self.contamination, random_state=42, n_estimators=100)
        self.model.fit(X)
        self.samples_since_train = 0
        logger.info(f"IsolationForest retrained on {len(X)} samples")

    async def reset(self):
        self.feature_buffer.clear()
        self.event_buffer.clear()
        self.model = None
        self.samples_since_train = 0
