from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from app.database import get_db
from app.models.models import Product

router = APIRouter(prefix="/api/v1/products", tags=["Product Catalog"])

class ProductOut(BaseModel):
    id: str; sku: str; name: str; category: str; base_price: float; is_active: bool
    class Config: from_attributes = True

@router.get("/", response_model=List[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return [ProductOut(id=str(p.id), sku=p.sku, name=p.name, category=p.category or "",
                       base_price=float(p.base_price), is_active=p.is_active)
            for p in db.query(Product).all()]

@router.get("/{sku}", response_model=ProductOut)
def get_product(sku: str, db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.sku == sku).first()
    if not p:
        from fastapi import HTTPException
        raise HTTPException(404, "Product not found")
    return ProductOut(id=str(p.id), sku=p.sku, name=p.name, category=p.category or "",
                      base_price=float(p.base_price), is_active=p.is_active)
