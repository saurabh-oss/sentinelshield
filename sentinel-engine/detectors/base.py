from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Detection:
    alert_type: str
    severity: str  # low, medium, high, critical
    title: str
    description: str
    detection_method: str
    risk_score: float
    affected_resource: Dict = field(default_factory=dict)
    source_events: List[Dict] = field(default_factory=list)
    resolver_action: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

class BaseDetector(ABC):
    """Base class for all anomaly/threat detectors."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.detections_count = 0
        self.events_analyzed = 0

    @abstractmethod
    async def analyze(self, event: Dict) -> Optional[Detection]:
        """Analyze an event and return a Detection if anomaly found."""
        pass

    @abstractmethod
    async def reset(self):
        """Reset detector state."""
        pass

    @property
    def stats(self) -> Dict:
        return {
            "name": self.name,
            "detections": self.detections_count,
            "events_analyzed": self.events_analyzed,
        }
