from sqlalchemy import create_engine, Column, String, Integer, Boolean, Numeric, DateTime, Text, ARRAY
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
from config import settings
import uuid

engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(100), nullable=False)
    source = Column(String(100), nullable=False)
    severity = Column(String(20), default="info")
    payload = Column(JSONB, default={})
    fingerprint = Column(String(255))
    created_at = Column(DateTime, server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(20), default="medium")
    status = Column(String(30), default="open")
    title = Column(String(500), nullable=False)
    description = Column(Text)
    source_event_ids = Column(ARRAY(Integer), default=[])
    affected_resource = Column(JSONB, default={})
    risk_score = Column(Numeric(5, 2), default=0)
    detection_method = Column(String(100))
    created_at = Column(DateTime, server_default=func.now())
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)

class Resolution(Base):
    __tablename__ = "resolutions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True))
    action_type = Column(String(100), nullable=False)
    status = Column(String(30), default="pending")
    details = Column(JSONB, default={})
    automated = Column(Boolean, default=True)
    executed_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime)
    rollback_available = Column(Boolean, default=False)

class ThreatRule(Base):
    __tablename__ = "threat_rules"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    rule_type = Column(String(50), nullable=False)
    conditions = Column(JSONB, nullable=False)
    severity = Column(String(20), default="medium")
    is_active = Column(Boolean, default=True)
    resolver_action = Column(String(100))
    created_at = Column(DateTime, server_default=func.now())

class Baseline(Base):
    __tablename__ = "baselines"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    metric_name = Column(String(255), nullable=False)
    dimension = Column(String(255))
    mean = Column(Numeric(20, 6))
    std_dev = Column(Numeric(20, 6))
    p95 = Column(Numeric(20, 6))
    p99 = Column(Numeric(20, 6))
    sample_count = Column(Integer)
    updated_at = Column(DateTime, server_default=func.now())

class RiskScore(Base):
    __tablename__ = "risk_scores"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(255), nullable=False)
    score = Column(Numeric(5, 2), default=0)
    factors = Column(JSONB, default={})
    updated_at = Column(DateTime, server_default=func.now())

class GeneratedResolver(Base):
    __tablename__ = "generated_resolvers"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_type = Column(String(100), nullable=False)
    threat_type = Column(String(100), nullable=False)
    code = Column(Text, nullable=False)
    status = Column(String(30), default="active")
    generation_prompt = Column(Text)
    generated_at = Column(DateTime, server_default=func.now())

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
