from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.database import get_db
from app.models.models import User, AuditLog
import redis as sync_redis, time

router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])
redis_client = sync_redis.from_url("redis://redis:6379/0", decode_responses=True)

class RoleChangeRequest(BaseModel):
    user_email: str; new_role: str; approval_token: Optional[str] = None

@router.post("/users/role")
def change_user_role(req: RoleChangeRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.user_email).first()
    if not user: raise HTTPException(404, "User not found")

    old_role = user.role
    has_approval = req.approval_token is not None and req.approval_token != ""

    # Emit event regardless - SentinelShield will evaluate
    try:
        redis_client.xadd("nexuscloud:events", {
            "event_type": "role_change",
            "user_email": req.user_email,
            "old_role": old_role, "new_role": req.new_role,
            "has_approval": str(has_approval),
            "client_ip": request.client.host if request.client else "unknown",
            "timestamp": str(time.time()),
        }, maxlen=50000)
    except: pass

    user.role = req.new_role
    audit = AuditLog(user_id=user.id, tenant_id=user.tenant_id, action="role_change",
                     resource_type="user", resource_id=str(user.id),
                     details={"old_role": old_role, "new_role": req.new_role, "approved": has_approval},
                     ip_address=request.client.host if request.client else None)
    db.add(audit); db.commit()
    return {"message": f"Role changed from {old_role} to {req.new_role}", "approved": has_approval}

@router.get("/audit-log")
def get_audit_log(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [{"id": l.id, "action": l.action, "resource_type": l.resource_type,
             "details": l.details, "ip_address": str(l.ip_address) if l.ip_address else None,
             "created_at": l.created_at.isoformat() if l.created_at else None} for l in logs]
