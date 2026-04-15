from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from app.database import get_db
from app.models.models import Tenant

router = APIRouter(prefix="/api/v1/tenants", tags=["Tenants"])

class TenantOut(BaseModel):
    id: str; name: str; slug: str; plan: str; status: str
    class Config: from_attributes = True

@router.get("/", response_model=List[TenantOut])
def list_tenants(db: Session = Depends(get_db)):
    return [TenantOut(id=str(t.id), name=t.name, slug=t.slug, plan=t.plan, status=t.status)
            for t in db.query(Tenant).all()]

@router.get("/{slug}", response_model=TenantOut)
def get_tenant(slug: str, db: Session = Depends(get_db)):
    t = db.query(Tenant).filter(Tenant.slug == slug).first()
    if not t: raise HTTPException(404, "Tenant not found")
    return TenantOut(id=str(t.id), name=t.name, slug=t.slug, plan=t.plan, status=t.status)
