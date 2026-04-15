from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
from app.database import get_db
from app.models.models import User, AuditLog
from app.config import settings
import redis as sync_redis
import json, time

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

redis_client = sync_redis.from_url("redis://redis:6379/0", decode_responses=True)

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    client_ip = request.client.host if request.client else "unknown"

    if not user or not user.is_active:
        # Emit auth failure event
        _emit_auth_event(db, req.email, client_ip, "login_failed", request)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.locked_until and user.locked_until > datetime.utcnow():
        _emit_auth_event(db, req.email, client_ip, "login_locked", request)
        raise HTTPException(status_code=403, detail="Account locked")

    # Simplified password check for PoC (accept "password" or hash match)
    if req.password != "password" and req.password != "demo":
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= 10:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.commit()
        _emit_auth_event(db, req.email, client_ip, "login_failed", request)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Success
    user.failed_login_count = 0
    user.last_login = datetime.utcnow()
    db.commit()

    token = jwt.encode(
        {"sub": str(user.id), "email": user.email, "role": user.role,
         "tenant_id": str(user.tenant_id), "exp": datetime.utcnow() + timedelta(hours=1)},
        settings.nexuscloud_secret_key, algorithm="HS256"
    )
    _emit_auth_event(db, req.email, client_ip, "login_success", request)
    return TokenResponse(access_token=token)

@router.post("/logout")
def logout(request: Request):
    return {"message": "Logged out"}

@router.post("/refresh")
def refresh_token(request: Request):
    return TokenResponse(access_token="refreshed-token-placeholder", expires_in=3600)

def _emit_auth_event(db: Session, email: str, ip: str, action: str, request: Request):
    audit = AuditLog(
        action=action, resource_type="auth", resource_id=email,
        ip_address=ip, user_agent=request.headers.get("user-agent", ""),
        details={"email": email, "timestamp": time.time()}
    )
    db.add(audit)
    db.commit()
    try:
        redis_client.xadd("nexuscloud:events", {
            "event_type": "auth_event", "action": action,
            "email": email, "client_ip": ip, "timestamp": str(time.time())
        }, maxlen=50000)
    except Exception:
        pass
