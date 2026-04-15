from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import redis as sync_redis, time, json

router = APIRouter(prefix="/api/v1/data", tags=["Data Ingestion"])
redis_client = sync_redis.from_url("redis://redis:6379/0", decode_responses=True)

EXPECTED_SCHEMA = {"customer_id", "event_name", "timestamp", "properties"}

class IngestPayload(BaseModel):
    records: List[Dict[str, Any]]
    source: str = "api"
    schema_version: Optional[str] = "1.0"

class IngestResponse(BaseModel):
    accepted: int; rejected: int; warnings: List[str]

@router.post("/ingest", response_model=IngestResponse)
def ingest_data(payload: IngestPayload, request: Request):
    accepted = 0; rejected = 0; warnings = []
    unexpected_fields = set()

    for record in payload.records:
        fields = set(record.keys())
        extra = fields - EXPECTED_SCHEMA
        if extra:
            unexpected_fields.update(extra)
        missing = EXPECTED_SCHEMA - fields
        if missing:
            rejected += 1
            warnings.append(f"Missing fields: {missing}")
        else:
            accepted += 1

    drift_pct = (len(unexpected_fields) / max(len(EXPECTED_SCHEMA), 1)) * 100 if unexpected_fields else 0

    try:
        redis_client.xadd("nexuscloud:events", {
            "event_type": "data_ingestion",
            "source": payload.source,
            "records_total": str(len(payload.records)),
            "accepted": str(accepted), "rejected": str(rejected),
            "schema_drift_pct": str(round(drift_pct, 2)),
            "unexpected_fields": json.dumps(list(unexpected_fields)),
            "payload_bytes": str(len(json.dumps(payload.records))),
            "timestamp": str(time.time()),
        }, maxlen=50000)
    except: pass

    if drift_pct > 20:
        warnings.append(f"Schema drift detected: {drift_pct:.1f}% unexpected fields")

    return IngestResponse(accepted=accepted, rejected=rejected, warnings=warnings)

@router.get("/schema")
def get_schema():
    return {"version": "1.0", "required_fields": list(EXPECTED_SCHEMA),
            "description": "NexusCloud event ingestion schema"}
