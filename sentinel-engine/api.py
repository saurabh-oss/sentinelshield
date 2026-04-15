from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from datetime import datetime
from database import SessionLocal, Alert, Resolution, Event, Baseline, RiskScore, GeneratedResolver
from prometheus_client import make_asgi_app

app = FastAPI(
    title="SentinelShield Engine API",
    description="Anomaly detection & threat resolution engine — API for the SentinelShield Dashboard.",
    version="1.0.0",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# ── Health ──
@app.get("/health")
def health():
    return {"status": "healthy", "service": "sentinel-engine", "version": "1.0.0"}

# ── Alerts ──
@app.get("/api/v1/alerts")
def list_alerts(status: Optional[str] = None, severity: Optional[str] = None,
                limit: int = 50, offset: int = 0):
    db = SessionLocal()
    try:
        q = db.query(Alert).order_by(Alert.created_at.desc())
        if status: q = q.filter(Alert.status == status)
        if severity: q = q.filter(Alert.severity == severity)
        total = q.count()
        alerts = q.offset(offset).limit(limit).all()
        return {
            "total": total, "limit": limit, "offset": offset,
            "items": [{
                "id": str(a.id), "alert_type": a.alert_type, "severity": a.severity,
                "status": a.status, "title": a.title, "description": a.description,
                "risk_score": float(a.risk_score) if a.risk_score else 0,
                "detection_method": a.detection_method,
                "affected_resource": a.affected_resource,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            } for a in alerts]
        }
    finally:
        db.close()

@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: str):
    db = SessionLocal()
    try:
        a = db.query(Alert).filter(Alert.id == alert_id).first()
        if not a: return {"error": "Not found"}, 404
        resolutions = db.query(Resolution).filter(Resolution.alert_id == alert_id).all()
        return {
            "id": str(a.id), "alert_type": a.alert_type, "severity": a.severity,
            "status": a.status, "title": a.title, "description": a.description,
            "risk_score": float(a.risk_score) if a.risk_score else 0,
            "detection_method": a.detection_method,
            "affected_resource": a.affected_resource,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            "resolutions": [{
                "id": str(r.id), "action_type": r.action_type, "status": r.status,
                "details": r.details, "automated": r.automated,
                "rollback_available": r.rollback_available,
                "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            } for r in resolutions]
        }
    finally:
        db.close()

@app.post("/api/v1/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    db = SessionLocal()
    try:
        a = db.query(Alert).filter(Alert.id == alert_id).first()
        if not a: return {"error": "Not found"}, 404
        a.status = "acknowledged"
        a.acknowledged_at = datetime.utcnow()
        db.commit()
        return {"message": "Alert acknowledged", "id": alert_id}
    finally:
        db.close()

# ── Resolutions ──
@app.get("/api/v1/resolutions")
def list_resolutions(limit: int = 50):
    db = SessionLocal()
    try:
        items = db.query(Resolution).order_by(Resolution.executed_at.desc()).limit(limit).all()
        return {"items": [{
            "id": str(r.id), "alert_id": str(r.alert_id), "action_type": r.action_type,
            "status": r.status, "details": r.details, "automated": r.automated,
            "rollback_available": r.rollback_available,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        } for r in items]}
    finally:
        db.close()

# ── Events Stream ──
@app.get("/api/v1/events")
def list_events(event_type: Optional[str] = None, limit: int = 100):
    db = SessionLocal()
    try:
        q = db.query(Event).order_by(Event.created_at.desc())
        if event_type: q = q.filter(Event.event_type == event_type)
        items = q.limit(limit).all()
        return {"items": [{
            "id": e.id, "event_type": e.event_type, "source": e.source,
            "severity": e.severity, "payload": e.payload,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        } for e in items]}
    finally:
        db.close()

# ── Dashboard Stats ──
@app.get("/api/v1/stats")
def dashboard_stats():
    db = SessionLocal()
    try:
        total_alerts = db.query(Alert).count()
        open_alerts = db.query(Alert).filter(Alert.status == "open").count()
        resolved_alerts = db.query(Alert).filter(Alert.status == "resolved").count()
        critical = db.query(Alert).filter(Alert.severity == "critical").count()
        high = db.query(Alert).filter(Alert.severity == "high").count()
        total_events = db.query(Event).count()
        total_resolutions = db.query(Resolution).count()
        auto_resolutions = db.query(Resolution).filter(Resolution.automated == True).count()

        # Severity distribution
        from sqlalchemy import func
        severity_dist = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
        type_dist = dict(db.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).all())

        return {
            "total_alerts": total_alerts, "open_alerts": open_alerts,
            "resolved_alerts": resolved_alerts, "critical_count": critical,
            "high_count": high, "total_events": total_events,
            "total_resolutions": total_resolutions,
            "auto_resolution_rate": round(auto_resolutions / max(total_resolutions, 1) * 100, 1),
            "severity_distribution": severity_dist,
            "alert_type_distribution": type_dist,
            "mean_risk_score": 0,
        }
    finally:
        db.close()

# ── Live Feed (polling endpoint for dashboard) ──
@app.get("/api/v1/live/alerts")
def live_alerts():
    """Returns recent in-memory alerts for near-real-time dashboard updates."""
    from main import recent_alerts, recent_resolutions
    return {
        "alerts": recent_alerts[:50],
        "resolutions": recent_resolutions[:50],
        "timestamp": datetime.utcnow().isoformat(),
    }

# ── Baselines ──
@app.get("/api/v1/baselines")
def list_baselines():
    db = SessionLocal()
    try:
        items = db.query(Baseline).all()
        return {"items": [{
            "metric_name": b.metric_name, "dimension": b.dimension,
            "mean": float(b.mean) if b.mean else 0, "std_dev": float(b.std_dev) if b.std_dev else 0,
            "p95": float(b.p95) if b.p95 else 0, "p99": float(b.p99) if b.p99 else 0,
        } for b in items]}
    finally:
        db.close()

# ── AI-Generated Resolvers ──
@app.get("/api/v1/generated-resolvers")
def list_generated_resolvers():
    """Returns all resolver classes synthesised by the AI Resolver Generator."""
    db = SessionLocal()
    try:
        items = db.query(GeneratedResolver).order_by(GeneratedResolver.generated_at.desc()).all()
        return {"items": [{
            "id": str(r.id),
            "action_type": r.action_type,
            "threat_type": r.threat_type,
            "status": r.status,
            "code": r.code,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        } for r in items]}
    finally:
        db.close()

# ── Engine Status ──
@app.get("/api/v1/engine/status")
def engine_status():
    from main import collector, detectors
    return {
        "collector": collector.stats,
        "detectors": [d.stats for d in detectors],
        "uptime": "running",
    }
