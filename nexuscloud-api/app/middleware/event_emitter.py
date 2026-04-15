import time
import json
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger("nexuscloud.events")

class EventEmitterMiddleware(BaseHTTPMiddleware):
    """Emits request events to Redis Stream for SentinelShield consumption."""

    def __init__(self, app):
        super().__init__(app)
        self.redis = None

    async def _get_redis(self):
        if self.redis is None:
            self.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        return self.redis

    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration_ms = (time.time() - start) * 1000

        event = {
            "event_type": "api_request",
            "method": request.method,
            "path": str(request.url.path),
            "status_code": str(response.status_code),
            "duration_ms": str(round(duration_ms, 2)),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", ""),
            "content_length": response.headers.get("content-length", "0"),
            "timestamp": str(time.time()),
        }

        # Extract tenant from header or path
        tenant = request.headers.get("X-Tenant-ID", "")
        if tenant:
            event["tenant_id"] = tenant

        try:
            r = await self._get_redis()
            await r.xadd("nexuscloud:events", event, maxlen=50000)
        except Exception as e:
            logger.warning(f"Failed to emit event: {e}")

        return response
