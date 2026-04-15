from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from app.database import get_db
from app.models.models import Subscription, Invoice
import uuid, redis as sync_redis, time

router = APIRouter(prefix="/api/v1/subscriptions", tags=["Subscriptions"])
redis_client = sync_redis.from_url("redis://redis:6379/0", decode_responses=True)

class SubOut(BaseModel):
    id: str; tenant_id: str; product_sku: str; plan_tier: str; status: str; monthly_amount: float
    class Config: from_attributes = True

class SubCreate(BaseModel):
    tenant_id: str; product_sku: str; plan_tier: str; monthly_amount: float

@router.get("/", response_model=List[SubOut])
def list_subscriptions(tenant_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Subscription)
    if tenant_id: q = q.filter(Subscription.tenant_id == tenant_id)
    return [SubOut(id=str(s.id), tenant_id=str(s.tenant_id), product_sku=s.product_sku,
                   plan_tier=s.plan_tier, status=s.status, monthly_amount=float(s.monthly_amount))
            for s in q.all()]

@router.post("/", response_model=SubOut, status_code=201)
def create_subscription(req: SubCreate, db: Session = Depends(get_db)):
    sub = Subscription(tenant_id=req.tenant_id, product_sku=req.product_sku,
                       plan_tier=req.plan_tier, monthly_amount=req.monthly_amount)
    db.add(sub); db.commit(); db.refresh(sub)
    try:
        redis_client.xadd("nexuscloud:events", {"event_type": "subscription_created",
            "tenant_id": req.tenant_id, "product_sku": req.product_sku, "timestamp": str(time.time())}, maxlen=50000)
    except: pass
    return SubOut(id=str(sub.id), tenant_id=str(sub.tenant_id), product_sku=sub.product_sku,
                  plan_tier=sub.plan_tier, status=sub.status, monthly_amount=float(sub.monthly_amount))

@router.delete("/{sub_id}")
def cancel_subscription(sub_id: str, db: Session = Depends(get_db)):
    sub = db.query(Subscription).filter(Subscription.id == sub_id).first()
    if not sub: raise HTTPException(404, "Subscription not found")
    sub.status = "cancelled"
    db.commit()
    return {"message": "Subscription cancelled"}
