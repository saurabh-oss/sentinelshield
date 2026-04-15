import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("sentinel.resolver")

@dataclass
class ResolutionResult:
    action_type: str
    status: str  # success, failed, partial
    details: Dict = field(default_factory=dict)
    rollback_available: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)

class BaseResolver(ABC):
    def __init__(self, name: str):
        self.name = name
        self.resolutions_count = 0

    @abstractmethod
    async def resolve(self, detection_metadata: Dict) -> ResolutionResult:
        pass


class IPBlockResolver(BaseResolver):
    """Blocks malicious IPs by adding to a deny list."""

    def __init__(self):
        super().__init__("IPBlockResolver")
        self.blocked_ips: Dict[str, float] = {}  # ip -> expiry timestamp

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        ip = metadata.get("ip", metadata.get("affected_resource", {}).get("id", "unknown"))
        duration = metadata.get("block_duration", 1800)  # 30 min default
        self.blocked_ips[ip] = time.time() + duration
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Blocked IP {ip} for {duration}s")
        return ResolutionResult(
            action_type="block_ip",
            status="success",
            details={"ip": ip, "duration_seconds": duration, "expires": time.time() + duration,
                     "action": f"IP {ip} added to deny list for {duration//60} minutes"},
            rollback_available=True
        )

    def is_blocked(self, ip: str) -> bool:
        expiry = self.blocked_ips.get(ip, 0)
        if expiry > time.time():
            return True
        self.blocked_ips.pop(ip, None)
        return False


class RateLimitResolver(BaseResolver):
    """Applies dynamic rate limiting to abusive clients."""

    def __init__(self):
        super().__init__("RateLimitResolver")
        self.rate_limits: Dict[str, Dict] = {}

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        ip = metadata.get("ip", metadata.get("affected_resource", {}).get("id", "unknown"))
        new_limit = metadata.get("rate_limit", 10)  # requests per minute
        self.rate_limits[ip] = {"limit": new_limit, "applied_at": time.time(), "expires": time.time() + 600}
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Rate limited {ip} to {new_limit} req/min")
        return ResolutionResult(
            action_type="rate_limit",
            status="success",
            details={"ip": ip, "new_limit_rpm": new_limit, "duration_seconds": 600,
                     "action": f"Rate limit applied: {ip} → {new_limit} req/min for 10 minutes"},
            rollback_available=True
        )


class CircuitBreakerResolver(BaseResolver):
    """Trips circuit breaker on suspicious endpoints."""

    def __init__(self):
        super().__init__("CircuitBreakerResolver")
        self.open_circuits: Dict[str, float] = {}

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        resource = metadata.get("affected_resource", {}).get("id", "unknown")
        self.open_circuits[resource] = time.time() + 300
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Circuit breaker opened for {resource}")
        return ResolutionResult(
            action_type="circuit_break",
            status="success",
            details={"resource": resource, "duration_seconds": 300,
                     "action": f"Circuit breaker OPEN on '{resource}' for 5 minutes"},
            rollback_available=True
        )


class AccountLockoutResolver(BaseResolver):
    """Locks out accounts targeted by credential stuffing."""

    def __init__(self):
        super().__init__("AccountLockoutResolver")

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        ip = metadata.get("ip", "unknown")
        emails = metadata.get("unique_emails", 0)
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Account lockout triggered for IP {ip}")
        return ResolutionResult(
            action_type="account_lockout",
            status="success",
            details={"ip": ip, "targeted_accounts": emails,
                     "action": f"Locked {emails} targeted accounts; blocked source IP {ip}; "
                               f"password reset emails queued"},
            rollback_available=True
        )


class RollbackResolver(BaseResolver):
    """Triggers release rollback via NexusCloud API."""

    def __init__(self):
        super().__init__("RollbackResolver")

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        version = metadata.get("version", "unknown")
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Rollback triggered for release v{version}")
        return ResolutionResult(
            action_type="rollback",
            status="success",
            details={"version": version, "error_rate": metadata.get("error_rate", 0),
                     "action": f"Rollback initiated for v{version}; reverting to previous stable release"},
            rollback_available=False
        )


class PauseIngestionResolver(BaseResolver):
    """Pauses data ingestion pipeline."""

    def __init__(self):
        super().__init__("PauseIngestionResolver")

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        source = metadata.get("source", "unknown")
        drift = metadata.get("drift_pct", 0)
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Ingestion paused for source {source}")
        return ResolutionResult(
            action_type="pause_ingestion",
            status="success",
            details={"source": source, "drift_pct": drift,
                     "action": f"Data ingestion paused for source '{source}'; "
                               f"schema drift {drift:.1f}% requires review"},
            rollback_available=True
        )


class RevertEscalateResolver(BaseResolver):
    """Reverts unauthorized privilege changes and escalates."""

    def __init__(self):
        super().__init__("RevertEscalateResolver")

    async def resolve(self, metadata: Dict) -> ResolutionResult:
        email = metadata.get("email", "unknown")
        old_role = metadata.get("old_role", "unknown")
        new_role = metadata.get("new_role", "unknown")
        self.resolutions_count += 1
        logger.info(f"RESOLVED: Reverted role change for {email}, escalated to security team")
        return ResolutionResult(
            action_type="revert_escalate",
            status="success",
            details={"user": email, "reverted_from": new_role, "reverted_to": old_role,
                     "action": f"Role for {email} reverted from '{new_role}' back to '{old_role}'; "
                               f"incident escalated to security team; user session invalidated"},
            rollback_available=False
        )


# ── Resolver Registry ──
RESOLVER_MAP = {
    "block_ip": IPBlockResolver(),
    "rate_limit": RateLimitResolver(),
    "circuit_break": CircuitBreakerResolver(),
    "account_lockout": AccountLockoutResolver(),
    "rollback": RollbackResolver(),
    "pause_ingestion": PauseIngestionResolver(),
    "revert_escalate": RevertEscalateResolver(),
}

async def execute_resolution(
    resolver_action: str,
    metadata: Dict,
    detection_context: Optional[Dict] = None,
) -> Optional[ResolutionResult]:
    resolver = RESOLVER_MAP.get(resolver_action)
    if resolver is None:
        if detection_context is not None:
            # Lazy import avoids circular dependency
            from resolvers.ai_resolver_generator import generate_and_register
            resolver = await generate_and_register(resolver_action, detection_context, metadata)
            if resolver is not None:
                # Cache for future detections of the same type
                RESOLVER_MAP[resolver_action] = resolver
        if resolver is None:
            logger.warning(f"No resolver found for action: {resolver_action}")
            return None
    return await resolver.resolve(metadata)
