import asyncio
import json
import logging
import time
from typing import Callable, Dict, List
import redis.asyncio as aioredis
from config import settings

logger = logging.getLogger("sentinel.collector")

class RedisStreamCollector:
    """Consumes events from NexusCloud's Redis Streams and dispatches to detectors."""

    def __init__(self, stream_name: str = "nexuscloud:events"):
        self.stream_name = stream_name
        self.redis = None
        self.handlers: List[Callable] = []
        self.last_id = "0"
        self.running = False
        self.events_processed = 0

    def register_handler(self, handler: Callable):
        self.handlers.append(handler)

    async def connect(self):
        self.redis = aioredis.from_url(settings.sentinel_redis_url, decode_responses=True)
        logger.info(f"Collector connected to Redis, consuming '{self.stream_name}'")

    async def start(self):
        if not self.redis:
            await self.connect()
        self.running = True
        logger.info("Stream collector started")

        while self.running:
            try:
                results = await self.redis.xread(
                    {self.stream_name: self.last_id}, count=100, block=1000
                )
                for stream, messages in results:
                    for msg_id, data in messages:
                        self.last_id = msg_id
                        self.events_processed += 1
                        event = {
                            "id": msg_id,
                            "stream": stream,
                            **data
                        }
                        for handler in self.handlers:
                            try:
                                await handler(event)
                            except Exception as e:
                                logger.error(f"Handler error: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Collector error: {e}")
                await asyncio.sleep(2)

    async def stop(self):
        self.running = False
        if self.redis:
            await self.redis.close()

    @property
    def stats(self) -> Dict:
        return {
            "stream": self.stream_name,
            "events_processed": self.events_processed,
            "last_id": self.last_id,
            "running": self.running,
        }
