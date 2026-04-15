-- Create NexusCloud database and user
CREATE USER nexus WITH PASSWORD 'nexus_secret_2024';
CREATE DATABASE nexuscloud OWNER nexus;

-- Create SentinelShield database and user
CREATE USER sentinel WITH PASSWORD 'sentinel_secret_2024';
CREATE DATABASE sentinel OWNER sentinel;

-- NexusCloud schema
\c nexuscloud nexus;

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'starter',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    failed_login_count INT DEFAULT 0,
    locked_until TIMESTAMP,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    product_sku VARCHAR(100) NOT NULL,
    plan_tier VARCHAR(50) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    monthly_amount DECIMAL(10,2) NOT NULL,
    billing_cycle_day INT DEFAULT 1,
    started_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    cancelled_at TIMESTAMP
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100),
    scopes TEXT[] DEFAULT '{}',
    rate_limit INT DEFAULT 1000,
    is_active BOOLEAN DEFAULT true,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sku VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    base_price DECIMAL(10,2) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}'
);

CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    subscription_id UUID REFERENCES subscriptions(id),
    amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(30) DEFAULT 'pending',
    issued_at TIMESTAMP DEFAULT NOW(),
    paid_at TIMESTAMP
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version VARCHAR(50) NOT NULL,
    release_type VARCHAR(30) NOT NULL,
    status VARCHAR(30) DEFAULT 'deployed',
    changelog TEXT,
    deployed_at TIMESTAMP DEFAULT NOW(),
    rolled_back_at TIMESTAMP,
    metrics_snapshot JSONB DEFAULT '{}'
);

-- Seed data
INSERT INTO tenants (name, slug, plan) VALUES
    ('Acme Corp', 'acme', 'enterprise'),
    ('TechStart Inc', 'techstart', 'professional'),
    ('GlobalRetail', 'globalretail', 'enterprise'),
    ('SmallBiz LLC', 'smallbiz', 'starter'),
    ('MegaScale', 'megascale', 'enterprise');

INSERT INTO products (sku, name, category, base_price) VALUES
    ('NXC-SUITE-ENT', 'NexusCloud Enterprise Suite', 'platform', 2499.00),
    ('NXC-SUITE-PRO', 'NexusCloud Professional', 'platform', 899.00),
    ('NXC-SUITE-STR', 'NexusCloud Starter', 'platform', 299.00),
    ('NXC-ADDON-AI', 'AI Insights Add-on', 'addon', 499.00),
    ('NXC-ADDON-API', 'API Premium Access', 'addon', 199.00),
    ('NXC-ADDON-SUPPORT', 'Priority Support', 'addon', 149.00);

INSERT INTO users (tenant_id, email, password_hash, role) VALUES
    ((SELECT id FROM tenants WHERE slug='acme'), 'admin@acme.com', '$2b$12$dummy_hash_admin', 'admin'),
    ((SELECT id FROM tenants WHERE slug='acme'), 'user1@acme.com', '$2b$12$dummy_hash_user1', 'user'),
    ((SELECT id FROM tenants WHERE slug='techstart'), 'admin@techstart.io', '$2b$12$dummy_hash_admin2', 'admin'),
    ((SELECT id FROM tenants WHERE slug='globalretail'), 'ops@globalretail.com', '$2b$12$dummy_hash_ops', 'admin'),
    ((SELECT id FROM tenants WHERE slug='megascale'), 'root@megascale.dev', '$2b$12$dummy_hash_root', 'superadmin');

INSERT INTO subscriptions (tenant_id, product_sku, plan_tier, status, monthly_amount) VALUES
    ((SELECT id FROM tenants WHERE slug='acme'), 'NXC-SUITE-ENT', 'enterprise', 'active', 2499.00),
    ((SELECT id FROM tenants WHERE slug='techstart'), 'NXC-SUITE-PRO', 'professional', 'active', 899.00),
    ((SELECT id FROM tenants WHERE slug='globalretail'), 'NXC-SUITE-ENT', 'enterprise', 'active', 2499.00),
    ((SELECT id FROM tenants WHERE slug='smallbiz'), 'NXC-SUITE-STR', 'starter', 'active', 299.00),
    ((SELECT id FROM tenants WHERE slug='megascale'), 'NXC-SUITE-ENT', 'enterprise', 'active', 2499.00);

INSERT INTO releases (version, release_type, status, changelog) VALUES
    ('2.14.0', 'minor', 'deployed', 'Performance improvements, new billing API'),
    ('2.14.1', 'patch', 'deployed', 'Fix: subscription renewal edge case'),
    ('2.15.0', 'minor', 'deployed', 'Feature: AI-powered usage analytics');

CREATE INDEX idx_audit_log_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_subscriptions_tenant ON subscriptions(tenant_id);

-- ════════════════════════════════════════════
--  SentinelShield Schema
-- ════════════════════════════════════════════

\c sentinel sentinel;

CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    source VARCHAR(100) NOT NULL,
    severity VARCHAR(20) DEFAULT 'info',
    payload JSONB NOT NULL DEFAULT '{}',
    fingerprint VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    source_event_ids BIGINT[] DEFAULT '{}',
    affected_resource JSONB DEFAULT '{}',
    risk_score DECIMAL(5,2) DEFAULT 0,
    detection_method VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE TABLE resolutions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES alerts(id),
    action_type VARCHAR(100) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    details JSONB DEFAULT '{}',
    automated BOOLEAN DEFAULT true,
    executed_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    rollback_available BOOLEAN DEFAULT false
);

CREATE TABLE threat_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL,
    conditions JSONB NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium',
    is_active BOOLEAN DEFAULT true,
    resolver_action VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name VARCHAR(255) NOT NULL,
    dimension VARCHAR(255),
    mean DECIMAL(20,6),
    std_dev DECIMAL(20,6),
    p95 DECIMAL(20,6),
    p99 DECIMAL(20,6),
    sample_count INT,
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,
    score DECIMAL(5,2) NOT NULL DEFAULT 0,
    factors JSONB DEFAULT '{}',
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Seed threat rules
INSERT INTO threat_rules (name, description, rule_type, conditions, severity, resolver_action) VALUES
    ('Brute Force Detection', 'Detect >10 failed logins from same IP in 60s', 'threshold', '{"metric": "failed_auth", "threshold": 10, "window_seconds": 60, "group_by": "ip_address"}', 'high', 'block_ip'),
    ('API Rate Abuse', 'Detect API call volume >3 std devs from baseline', 'zscore', '{"metric": "api_requests", "zscore_threshold": 3.0, "window_seconds": 300}', 'high', 'rate_limit'),
    ('Large Payload Exfiltration', 'Detect unusually large response payloads', 'isolation_forest', '{"metric": "response_bytes", "contamination": 0.05}', 'critical', 'circuit_break'),
    ('Credential Stuffing Pattern', 'Detect sequential auth attempts with varied credentials', 'sequence', '{"pattern": "multi_credential_single_source", "threshold": 5, "window_seconds": 30}', 'critical', 'account_lockout'),
    ('Post-Release Metric Deviation', 'Detect error rate spike after deployment', 'canary', '{"metric": "error_rate", "deviation_pct": 50, "window_seconds": 600}', 'high', 'rollback'),
    ('Schema Drift', 'Detect unexpected fields in data ingestion', 'schema', '{"allowed_drift_pct": 5}', 'medium', 'pause_ingestion'),
    ('Privilege Escalation', 'Detect role changes without approval workflow', 'rule', '{"action": "role_change", "requires": "approval_token"}', 'critical', 'revert_escalate');

-- Seed baselines
INSERT INTO baselines (metric_name, dimension, mean, std_dev, p95, p99, sample_count) VALUES
    ('api_requests_per_minute', 'global', 150.0, 35.0, 210.0, 260.0, 10000),
    ('response_time_ms', 'global', 120.0, 45.0, 200.0, 350.0, 10000),
    ('error_rate_pct', 'global', 1.2, 0.8, 2.5, 4.0, 10000),
    ('auth_failures_per_minute', 'global', 3.0, 2.0, 7.0, 12.0, 10000),
    ('response_bytes_avg', 'global', 4096.0, 2048.0, 8192.0, 16384.0, 10000),
    ('active_sessions', 'global', 500.0, 120.0, 700.0, 850.0, 10000);

CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_created ON events(created_at);
CREATE INDEX idx_events_fingerprint ON events(fingerprint);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created ON alerts(created_at);
CREATE INDEX idx_resolutions_alert ON resolutions(alert_id);
CREATE INDEX idx_risk_scores_entity ON risk_scores(entity_type, entity_id);
