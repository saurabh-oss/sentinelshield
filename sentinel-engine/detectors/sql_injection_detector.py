"""
SQL Injection Probe Detector
=============================
Watches incoming api_request events for SQL injection patterns in URL paths
and query parameters.  When probes from an IP accumulate past the threshold,
a Detection is raised with resolver_action="sql_injection_block" — a resolver
type that has no built-in implementation, intentionally triggering the
AI Resolver Generator to synthesise one on the fly.
"""

import re
import time
import logging
from collections import defaultdict
from typing import Dict, Optional

from detectors.base import BaseDetector, Detection

logger = logging.getLogger("sentinel.detector.sql_injection")

# Compiled patterns covering common SQL injection payloads
_SQL_PATTERNS: list[re.Pattern] = [
    re.compile(r"'[\s]*(?:OR|AND)[\s]+['\"0-9]", re.IGNORECASE),   # ' OR '1'='1
    re.compile(r"UNION[\s]+(?:ALL[\s]+)?SELECT", re.IGNORECASE),
    re.compile(r"(?:DROP|DELETE|TRUNCATE)[\s]+(?:TABLE|DATABASE|FROM)", re.IGNORECASE),
    re.compile(r"INSERT[\s]+INTO", re.IGNORECASE),
    re.compile(r"(?:EXEC|EXECUTE)\s*\(", re.IGNORECASE),
    re.compile(r"xp_cmdshell", re.IGNORECASE),
    re.compile(r"WAITFOR[\s]+DELAY", re.IGNORECASE),
    re.compile(r"--[\s]*$"),                                         # trailing comment
    re.compile(r"/\*.*?\*/"),                                        # block comment
    re.compile(r"%27|%22|%3D.*%3D"),                                 # URL-encoded ' " ==
    re.compile(r"';[\s]*--"),                                        # '; --
    re.compile(r"1[\s]*=[\s]*1|0[\s]*=[\s]*0"),                     # tautologies
]

_FIELDS_TO_SCAN = ("path", "query_string", "url", "body", "user_agent")

# Alert after this many distinct pattern matches from a single IP within the window
_THRESHOLD = 3
_WINDOW_SECONDS = 60
_COOLDOWN_SECONDS = 120


def _scan_event(event: Dict) -> Optional[str]:
    """Return the first matching SQL injection pattern string, or None."""
    for field in _FIELDS_TO_SCAN:
        value = str(event.get(field, ""))
        if not value:
            continue
        for pat in _SQL_PATTERNS:
            m = pat.search(value)
            if m:
                return m.group(0)
    return None


class SqlInjectionDetector(BaseDetector):
    """
    Detects SQL injection probes in API request events.

    Intentionally raises detections with resolver_action='sql_injection_block',
    which has no pre-built resolver, triggering the AI Resolver Generator.
    """

    def __init__(self):
        super().__init__(
            "SqlInjectionDetector",
            "Detects SQL injection probe patterns in API request paths and parameters",
        )
        # ip -> list of (timestamp, matched_pattern)
        self._hits: Dict[str, list] = defaultdict(list)
        self._cooldowns: Dict[str, float] = {}

    async def analyze(self, event: Dict) -> Optional[Detection]:
        self.events_analyzed += 1

        if event.get("event_type") != "api_request":
            return None

        matched_pattern = _scan_event(event)
        if matched_pattern is None:
            return None

        ip = event.get("client_ip", "unknown")
        now = time.time()

        # Record this hit
        self._hits[ip].append((now, matched_pattern))

        # Slide the window
        self._hits[ip] = [
            (ts, pat) for ts, pat in self._hits[ip]
            if now - ts <= _WINDOW_SECONDS
        ]

        if len(self._hits[ip]) < _THRESHOLD:
            return None

        # Respect cooldown
        if now - self._cooldowns.get(ip, 0) < _COOLDOWN_SECONDS:
            return None

        self._cooldowns[ip] = now
        self.detections_count += 1

        patterns_seen = list({pat for _, pat in self._hits[ip]})
        hit_count = len(self._hits[ip])
        path = event.get("path", "unknown")

        logger.warning(
            "SQL injection probe detected from %s — %d hits, patterns: %s",
            ip, hit_count, patterns_seen,
        )

        return Detection(
            alert_type="sql_injection_probe",
            severity="high",
            title=f"SQL Injection Probe Detected from {ip}",
            description=(
                f"IP {ip} sent {hit_count} requests containing SQL injection patterns "
                f"within {_WINDOW_SECONDS}s. "
                f"Patterns matched: {patterns_seen}. "
                f"Last affected path: {path}. "
                f"No built-in resolver exists — AI resolver synthesis required."
            ),
            detection_method="pattern_match",
            risk_score=min(95.0, 55.0 + hit_count * 4),
            affected_resource={"type": "api_endpoint", "id": path},
            source_events=[event],
            resolver_action="sql_injection_block",
            metadata={
                "ip": ip,
                "hit_count": hit_count,
                "injected_patterns": patterns_seen,
                "path": path,
                "window_seconds": _WINDOW_SECONDS,
            },
        )

    async def reset(self):
        self._hits.clear()
        self._cooldowns.clear()
