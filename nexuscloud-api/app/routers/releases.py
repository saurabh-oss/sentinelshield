from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.database import get_db
from app.models.models import Release
import redis as sync_redis, time

router = APIRouter(prefix="/api/v1/releases", tags=["Release Management"])
redis_client = sync_redis.from_url("redis://redis:6379/0", decode_responses=True)

class ReleaseOut(BaseModel):
    id: str; version: str; release_type: str; status: str; changelog: Optional[str]; deployed_at: Optional[str]
    class Config: from_attributes = True

class ReleaseCreate(BaseModel):
    version: str; release_type: str; changelog: Optional[str] = None
    metrics_snapshot: Optional[Dict[str, Any]] = None

@router.get("/", response_model=List[ReleaseOut])
def list_releases(db: Session = Depends(get_db)):
    return [ReleaseOut(id=str(r.id), version=r.version, release_type=r.release_type,
                       status=r.status, changelog=r.changelog,
                       deployed_at=r.deployed_at.isoformat() if r.deployed_at else None)
            for r in db.query(Release).order_by(Release.deployed_at.desc()).all()]

@router.post("/", response_model=ReleaseOut, status_code=201)
def create_release(req: ReleaseCreate, db: Session = Depends(get_db)):
    rel = Release(version=req.version, release_type=req.release_type,
                  changelog=req.changelog, metrics_snapshot=req.metrics_snapshot or {})
    db.add(rel); db.commit(); db.refresh(rel)
    try:
        redis_client.xadd("nexuscloud:events", {
            "event_type": "release_deployed", "version": req.version,
            "release_type": req.release_type, "timestamp": str(time.time())
        }, maxlen=50000)
    except: pass
    return ReleaseOut(id=str(rel.id), version=rel.version, release_type=rel.release_type,
                      status=rel.status, changelog=rel.changelog,
                      deployed_at=rel.deployed_at.isoformat() if rel.deployed_at else None)

@router.post("/{release_id}/rollback")
def rollback_release(release_id: str, db: Session = Depends(get_db)):
    rel = db.query(Release).filter(Release.id == release_id).first()
    if not rel: raise HTTPException(404, "Release not found")
    rel.status = "rolled_back"
    rel.rolled_back_at = datetime.utcnow()
    db.commit()
    try:
        redis_client.xadd("nexuscloud:events", {
            "event_type": "release_rollback", "version": rel.version, "timestamp": str(time.time())
        }, maxlen=50000)
    except: pass
    return {"message": f"Release {rel.version} rolled back"}
