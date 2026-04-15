"""
SentinelShield Demo Simulator
==============================
Generates realistic NexusCloud traffic, then injects threat scenarios
to demonstrate detection and auto-resolution capabilities.

Run inside the sentinel-engine container:
    python -m scripts.demo_simulator
"""

import asyncio
import time
import random
import logging
import redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIMULATOR] %(message)s")
logger = logging.getLogger("simulator")

REDIS_URL = "redis://redis:6379/0"
STREAM = "nexuscloud:events"

PATHS = ["/api/v1/products", "/api/v1/subscriptions", "/api/v1/tenants",
         "/api/v1/auth/login", "/api/v1/data/ingest", "/api/v1/releases",
         "/api/v1/admin/audit-log", "/health"]
EMAILS = ["admin@acme.com", "user1@acme.com", "admin@techstart.io",
          "ops@globalretail.com", "root@megascale.dev"]
IPS = [f"10.0.{random.randint(1,5)}.{random.randint(10,200)}" for _ in range(20)]
ATTACKER_IP = "185.220.101.42"

def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)

def emit(r, event: dict):
    event["timestamp"] = str(time.time())
    r.xadd(STREAM, event, maxlen=50000)

# ════════════════════════════════════════════
#  Phase 1: Normal Traffic Baseline
# ════════════════════════════════════════════
def phase_normal_traffic(r, count=300):
    logger.info(f"═══ Phase 1: Generating {count} normal requests for baseline ═══")
    for i in range(count):
        path = random.choice(PATHS)
        emit(r, {
            "event_type": "api_request",
            "method": random.choice(["GET", "GET", "GET", "POST"]),
            "path": path,
            "status_code": str(random.choices([200, 201, 204, 400, 404], weights=[70, 10, 5, 10, 5])[0]),
            "duration_ms": str(round(random.gauss(120, 40), 2)),
            "client_ip": random.choice(IPS),
            "content_length": str(random.randint(200, 8000)),
            "user_agent": "NexusCloud-SDK/2.15.0",
        })
        if i % 50 == 0:
            logger.info(f"  Normal traffic: {i}/{count}")
        time.sleep(0.02)
    logger.info("  ✓ Baseline traffic complete\n")

# ════════════════════════════════════════════
#  Phase 2: Brute Force Attack
# ════════════════════════════════════════════
def phase_brute_force(r):
    logger.info("═══ Phase 2: Simulating BRUTE FORCE ATTACK ═══")
    target_email = "admin@acme.com"
    for i in range(15):
        emit(r, {
            "event_type": "auth_event",
            "action": "login_failed",
            "email": target_email,
            "client_ip": ATTACKER_IP,
        })
        time.sleep(0.1)
    logger.info(f"  → Sent 15 failed logins from {ATTACKER_IP} targeting {target_email}")
    time.sleep(3)
    logger.info("  ✓ Brute force scenario complete\n")

# ════════════════════════════════════════════
#  Phase 3: API Rate Abuse
# ════════════════════════════════════════════
def phase_rate_abuse(r):
    logger.info("═══ Phase 3: Simulating API RATE ABUSE ═══")
    abuser_ip = "203.0.113.99"
    for i in range(250):
        emit(r, {
            "event_type": "api_request",
            "method": "GET",
            "path": "/api/v1/products",
            "status_code": "200",
            "duration_ms": str(round(random.gauss(50, 10), 2)),
            "client_ip": abuser_ip,
            "content_length": str(random.randint(500, 2000)),
            "user_agent": "python-requests/2.31.0",
        })
        time.sleep(0.01)
    logger.info(f"  → Sent 250 rapid requests from {abuser_ip}")
    time.sleep(3)
    logger.info("  ✓ Rate abuse scenario complete\n")

# ════════════════════════════════════════════
#  Phase 4: Data Exfiltration (large payloads)
# ════════════════════════════════════════════
def phase_exfiltration(r):
    logger.info("═══ Phase 4: Simulating DATA EXFILTRATION ═══")
    for i in range(20):
        emit(r, {
            "event_type": "api_request",
            "method": "GET",
            "path": "/api/v1/subscriptions",
            "status_code": "200",
            "duration_ms": str(round(random.gauss(800, 200), 2)),
            "client_ip": ATTACKER_IP,
            "content_length": str(random.randint(500000, 2000000)),  # 500KB-2MB payloads
            "user_agent": "curl/7.88.1",
        })
        time.sleep(0.3)
    logger.info(f"  → Sent 20 requests with abnormally large responses (500KB-2MB)")
    time.sleep(3)
    logger.info("  ✓ Exfiltration scenario complete\n")

# ════════════════════════════════════════════
#  Phase 5: Credential Stuffing
# ════════════════════════════════════════════
def phase_credential_stuffing(r):
    logger.info("═══ Phase 5: Simulating CREDENTIAL STUFFING ═══")
    stuffer_ip = "45.33.32.156"
    fake_emails = [f"user{i}@leaked-dump.com" for i in range(20)]
    for email in fake_emails:
        emit(r, {
            "event_type": "auth_event",
            "action": "login_failed",
            "email": email,
            "client_ip": stuffer_ip,
        })
        time.sleep(0.05)
    logger.info(f"  → Sent 20 login attempts with unique emails from {stuffer_ip}")
    time.sleep(3)
    logger.info("  ✓ Credential stuffing scenario complete\n")

# ════════════════════════════════════════════
#  Phase 6: Suspicious Release + Error Spike
# ════════════════════════════════════════════
def phase_bad_release(r):
    logger.info("═══ Phase 6: Simulating BAD RELEASE DEPLOYMENT ═══")
    # Generate some error traffic first
    for i in range(60):
        emit(r, {
            "event_type": "api_request",
            "method": random.choice(["GET", "POST"]),
            "path": random.choice(PATHS),
            "status_code": str(random.choices([500, 502, 503, 200], weights=[40, 20, 20, 20])[0]),
            "duration_ms": str(round(random.gauss(500, 200), 2)),
            "client_ip": random.choice(IPS),
            "content_length": str(random.randint(100, 500)),
            "user_agent": "NexusCloud-SDK/2.16.0",
        })
        time.sleep(0.05)

    # Then deploy
    emit(r, {
        "event_type": "release_deployed",
        "version": "2.16.0",
        "release_type": "minor",
    })
    logger.info("  → Deployed v2.16.0 after error spike (60% error rate)")
    time.sleep(3)
    logger.info("  ✓ Bad release scenario complete\n")

# ════════════════════════════════════════════
#  Phase 7: Schema Drift
# ════════════════════════════════════════════
def phase_schema_drift(r):
    logger.info("═══ Phase 7: Simulating SCHEMA DRIFT ═══")
    import json
    emit(r, {
        "event_type": "data_ingestion",
        "source": "partner-feed-v2",
        "records_total": "500",
        "accepted": "350",
        "rejected": "150",
        "schema_drift_pct": "35.0",
        "unexpected_fields": json.dumps(["ssn", "credit_card", "raw_password", "internal_id"]),
        "payload_bytes": "1048576",
    })
    logger.info("  → Ingested data with 35% schema drift including sensitive fields")
    time.sleep(3)
    logger.info("  ✓ Schema drift scenario complete\n")

# ════════════════════════════════════════════
#  Phase 8: Privilege Escalation
# ════════════════════════════════════════════
def phase_privilege_escalation(r):
    logger.info("═══ Phase 8: Simulating UNAUTHORIZED PRIVILEGE ESCALATION ═══")
    emit(r, {
        "event_type": "role_change",
        "user_email": "user1@acme.com",
        "old_role": "user",
        "new_role": "superadmin",
        "has_approval": "False",
        "client_ip": "192.168.1.105",
    })
    logger.info("  → user1@acme.com escalated to superadmin WITHOUT approval")
    time.sleep(3)
    logger.info("  ✓ Privilege escalation scenario complete\n")

# ════════════════════════════════════════════
#  Phase 9: SQL Injection Probe
#  — triggers the AI Resolver Generator
# ════════════════════════════════════════════
def phase_sql_injection(r):
    logger.info("═══ Phase 9: Simulating SQL INJECTION PROBE ═══")
    logger.info("  (No built-in resolver exists — AI will synthesise one)")
    probe_ip = "91.195.240.117"

    probes = [
        # Path-based probes
        ("/api/v1/products?id=1' OR '1'='1",          "GET"),
        ("/api/v1/subscriptions?tenant=acme'--",       "GET"),
        ("/api/v1/tenants?name=x' UNION SELECT * FROM users--", "GET"),
        ("/api/v1/auth/login?user=admin'--",           "POST"),
        ("/api/v1/data?q=1; DROP TABLE subscriptions--", "GET"),
        ("/api/v1/admin/audit-log?filter=1 OR 1=1",   "GET"),
        ("/api/v1/products?sort=id WAITFOR DELAY '0:0:5'--", "GET"),
        ("/api/v1/releases?version=1' UNION ALL SELECT username,password FROM users--", "GET"),
        ("/api/v1/tenants?id=1; EXEC xp_cmdshell('whoami')--", "GET"),
        ("/api/v1/subscriptions?plan=starter%27+OR+%271%27%3D%271", "GET"),
    ]

    for path, method in probes:
        emit(r, {
            "event_type": "api_request",
            "method": method,
            "path": path,
            "status_code": str(random.choice([400, 422, 500])),
            "duration_ms": str(round(random.gauss(95, 15), 2)),
            "client_ip": probe_ip,
            "content_length": str(random.randint(100, 400)),
            "user_agent": "sqlmap/1.7.8#stable (https://sqlmap.org)",
        })
        time.sleep(0.15)

    logger.info(f"  → Sent {len(probes)} SQL injection probes from {probe_ip}")
    logger.info("  → Detector: SqlInjectionDetector")
    logger.info("  → Resolver: AI-generated SqlInjectionBlockResolver (synthesised by Claude)")
    time.sleep(4)
    logger.info("  ✓ SQL injection scenario complete\n")


# ════════════════════════════════════════════
#  Run All
# ════════════════════════════════════════════
def run_demo():
    r = get_redis()
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║    SentinelShield Demo Simulator v2.0           ║")
    logger.info("║    Generating traffic + 8 threat scenarios      ║")
    logger.info("║    Scenario 9 uses AI-generated resolver        ║")
    logger.info("╚══════════════════════════════════════════════════╝\n")

    phase_normal_traffic(r, count=300)
    time.sleep(2)
    phase_brute_force(r)
    phase_rate_abuse(r)
    phase_exfiltration(r)
    phase_credential_stuffing(r)
    phase_bad_release(r)
    phase_schema_drift(r)
    phase_privilege_escalation(r)
    phase_sql_injection(r)

    # Resume some normal traffic
    logger.info("═══ Resuming normal traffic ═══")
    phase_normal_traffic(r, count=100)

    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║    Demo simulation COMPLETE                     ║")
    logger.info("║                                                 ║")
    logger.info("║    Open the dashboard: http://localhost:3000    ║")
    logger.info("║    Grafana:            http://localhost:3001    ║")
    logger.info("║    Engine API:         http://localhost:8001/docs║")
    logger.info("║    Generated resolvers: GET /api/v1/generated-resolvers ║")
    logger.info("╚══════════════════════════════════════════════════╝")

if __name__ == "__main__":
    run_demo()
