import asyncio
import logging
import uvicorn
from datetime import datetime
from typing import Dict, List
from contextlib import asynccontextmanager

from collectors.redis_stream import RedisStreamCollector
from detectors.base import Detection
from detectors.threshold_detector import ThresholdDetector
from detectors.zscore_detector import ZScoreDetector
from detectors.isolation_forest_detector import IsolationForestDetector
from detectors.sequence_detector import SequenceDetector
from detectors.rule_engine import RuleEngineDetector
from detectors.sql_injection_detector import SqlInjectionDetector
from resolvers.resolvers import execute_resolution, ResolutionResult
from database import SessionLocal, Event, Alert, Resolution, Base, engine, GeneratedResolver

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("sentinel.engine")

# ── Global state ──
collector = RedisStreamCollector()
detectors = [
    ThresholdDetector(),
    ZScoreDetector(),
    IsolationForestDetector(),
    SequenceDetector(),
    RuleEngineDetector(),
    SqlInjectionDetector(),
]

# Recent alerts/resolutions for dashboard (in-memory cache)
recent_alerts: List[Dict] = []
recent_resolutions: List[Dict] = []
MAX_RECENT = 200

async def handle_event(event: Dict):
    """Process an event through all detectors, then resolve if needed."""
    # Persist raw event
    try:
        db = SessionLocal()
        db_event = Event(
            event_type=event.get("event_type", "unknown"),
            source="nexuscloud",
            payload={k: v for k, v in event.items() if k not in ("id", "stream")},
        )
        db.add(db_event)
        db.commit()
        event_id = db_event.id
        db.close()
    except Exception as e:
        logger.error(f"DB event persist error: {e}")
        event_id = None

    # Run through detectors
    for detector in detectors:
        try:
            detection = await detector.analyze(event)
            if detection is not None:
                await process_detection(detection, event_id)
        except Exception as e:
            logger.error(f"Detector {detector.name} error: {e}")

async def process_detection(detection: Detection, event_id: int = None):
    """Persist alert, execute resolution, update dashboard cache."""
    logger.warning(f"🚨 DETECTION: [{detection.severity.upper()}] {detection.title}")

    # Persist alert
    db = SessionLocal()
    try:
        alert = Alert(
            alert_type=detection.alert_type,
            severity=detection.severity,
            status="open",
            title=detection.title,
            description=detection.description,
            source_event_ids=[event_id] if event_id else [],
            affected_resource=detection.affected_resource,
            risk_score=detection.risk_score,
            detection_method=detection.detection_method,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = str(alert.id)
    except Exception as e:
        logger.error(f"Alert persist error: {e}")
        alert_id = "unknown"
    finally:
        db.close()

    alert_dict = {
        "id": alert_id,
        "alert_type": detection.alert_type,
        "severity": detection.severity,
        "title": detection.title,
        "description": detection.description,
        "risk_score": detection.risk_score,
        "detection_method": detection.detection_method,
        "affected_resource": detection.affected_resource,
        "resolver_action": detection.resolver_action,
        "status": "open",
        "created_at": datetime.utcnow().isoformat(),
    }
    recent_alerts.insert(0, alert_dict)
    if len(recent_alerts) > MAX_RECENT:
        recent_alerts.pop()

    # Execute auto-resolution
    if detection.resolver_action:
        resolution_meta = {**detection.metadata, "affected_resource": detection.affected_resource}
        detection_context = {
            "alert_type": detection.alert_type,
            "severity": detection.severity,
            "title": detection.title,
            "description": detection.description,
            "detection_method": detection.detection_method,
            "risk_score": detection.risk_score,
            "affected_resource": detection.affected_resource,
        }
        result = await execute_resolution(detection.resolver_action, resolution_meta, detection_context)
        if result:
            logger.info(f"✅ RESOLVED: {result.action_type} → {result.status}")

            # Persist resolution
            db = SessionLocal()
            try:
                res = Resolution(
                    alert_id=alert_id,
                    action_type=result.action_type,
                    status=result.status,
                    details=result.details,
                    automated=True,
                    rollback_available=result.rollback_available,
                    completed_at=datetime.utcnow(),
                )
                db.add(res)
                # Update alert status
                db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
                if db_alert:
                    db_alert.status = "resolved"
                    db_alert.resolved_at = datetime.utcnow()
                db.commit()
                resolution_id = str(res.id)
            except Exception as e:
                logger.error(f"Resolution persist error: {e}")
                resolution_id = "unknown"
            finally:
                db.close()

            res_dict = {
                "id": resolution_id,
                "alert_id": alert_id,
                "action_type": result.action_type,
                "status": result.status,
                "details": result.details,
                "automated": True,
                "rollback_available": result.rollback_available,
                "executed_at": datetime.utcnow().isoformat(),
            }
            recent_resolutions.insert(0, res_dict)
            if len(recent_resolutions) > MAX_RECENT:
                recent_resolutions.pop()

            # Update cached alert status
            alert_dict["status"] = "resolved"
            alert_dict["resolution"] = res_dict

async def start_engine():
    """Start the collector loop."""
    # Ensure any new ORM models (e.g. generated_resolvers) exist in the DB
    Base.metadata.create_all(bind=engine)
    collector.register_handler(handle_event)
    logger.info("SentinelShield Engine starting...")
    logger.info(f"Detectors loaded: {[d.name for d in detectors]}")
    await collector.start()

if __name__ == "__main__":
    from api import app
    import threading

    async def run():
        config = uvicorn.Config(app, host="0.0.0.0", port=8001, log_level="info")
        server = uvicorn.Server(config)
        await asyncio.gather(
            server.serve(),
            start_engine(),
        )

    asyncio.run(run())
