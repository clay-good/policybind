"""
Database schema definitions for PolicyBind.

This module defines the SQLite database schema as SQL strings.
The schema includes tables for policies, model registry, tokens,
incidents, and audit logging.
"""

# Current schema version - increment when making schema changes
SCHEMA_VERSION = 1

# Schema version tracking table
SCHEMA_VERSION_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now')),
    description TEXT
);
"""

# Policies table - stores serialized PolicySet objects with versioning
POLICIES_SQL = """
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    description TEXT,
    content TEXT NOT NULL,  -- JSON serialized PolicySet
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT,
    metadata TEXT  -- JSON metadata
);

CREATE INDEX IF NOT EXISTS idx_policies_name ON policies(name);
CREATE INDEX IF NOT EXISTS idx_policies_is_active ON policies(is_active);
CREATE INDEX IF NOT EXISTS idx_policies_created_at ON policies(created_at);
"""

# Policy audit log - tracks all policy changes
POLICY_AUDIT_LOG_SQL = """
CREATE TABLE IF NOT EXISTS policy_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    action TEXT NOT NULL,  -- CREATE, UPDATE, DELETE, ACTIVATE, DEACTIVATE
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    user_id TEXT,
    old_value TEXT,  -- JSON of previous state
    new_value TEXT,  -- JSON of new state
    reason TEXT,
    metadata TEXT  -- JSON metadata
);

CREATE INDEX IF NOT EXISTS idx_policy_audit_policy_id ON policy_audit_log(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_timestamp ON policy_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_policy_audit_action ON policy_audit_log(action);
"""

# Model registry - stores ModelDeployment records
MODEL_REGISTRY_SQL = """
CREATE TABLE IF NOT EXISTS model_registry (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    model_provider TEXT NOT NULL,
    model_name TEXT NOT NULL,
    model_version TEXT,
    owner TEXT NOT NULL,
    owner_contact TEXT,
    data_categories TEXT,  -- JSON array
    risk_level TEXT NOT NULL DEFAULT 'MEDIUM',
    approval_status TEXT NOT NULL DEFAULT 'PENDING',
    approval_ticket TEXT,
    deployment_date TEXT,
    last_review_date TEXT,
    next_review_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    metadata TEXT  -- JSON metadata
);

CREATE INDEX IF NOT EXISTS idx_registry_deployment_id ON model_registry(deployment_id);
CREATE INDEX IF NOT EXISTS idx_registry_name ON model_registry(name);
CREATE INDEX IF NOT EXISTS idx_registry_owner ON model_registry(owner);
CREATE INDEX IF NOT EXISTS idx_registry_risk_level ON model_registry(risk_level);
CREATE INDEX IF NOT EXISTS idx_registry_approval_status ON model_registry(approval_status);
CREATE INDEX IF NOT EXISTS idx_registry_model_provider ON model_registry(model_provider);
"""

# Model usage statistics
MODEL_USAGE_SQL = """
CREATE TABLE IF NOT EXISTS model_usage (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    token_count INTEGER NOT NULL DEFAULT 0,
    estimated_cost REAL NOT NULL DEFAULT 0.0,
    error_count INTEGER NOT NULL DEFAULT 0,
    policy_violation_count INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms REAL,
    p95_latency_ms REAL,
    unique_users INTEGER,
    top_use_cases TEXT,  -- JSON dict
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    metadata TEXT,  -- JSON metadata
    FOREIGN KEY (deployment_id) REFERENCES model_registry(deployment_id)
);

CREATE INDEX IF NOT EXISTS idx_usage_deployment_id ON model_usage(deployment_id);
CREATE INDEX IF NOT EXISTS idx_usage_period_start ON model_usage(period_start);
CREATE INDEX IF NOT EXISTS idx_usage_period_end ON model_usage(period_end);
"""

# Enforcement log - stores AIRequest and AIResponse pairs
ENFORCEMENT_LOG_SQL = """
CREATE TABLE IF NOT EXISTS enforcement_log (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    provider TEXT,
    model TEXT,
    prompt_hash TEXT,
    estimated_tokens INTEGER,
    estimated_cost REAL,
    source_application TEXT,
    user_id TEXT,
    department TEXT,
    data_classification TEXT,  -- JSON array
    intended_use_case TEXT,
    decision TEXT NOT NULL,
    applied_rules TEXT,  -- JSON array
    modifications TEXT,  -- JSON dict
    enforcement_time_ms REAL,
    reason TEXT,
    warnings TEXT,  -- JSON array
    deployment_id TEXT,
    request_metadata TEXT,  -- JSON metadata from request
    response_metadata TEXT  -- JSON metadata from response
);

CREATE INDEX IF NOT EXISTS idx_enforcement_request_id ON enforcement_log(request_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_timestamp ON enforcement_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_enforcement_user_id ON enforcement_log(user_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_department ON enforcement_log(department);
CREATE INDEX IF NOT EXISTS idx_enforcement_decision ON enforcement_log(decision);
CREATE INDEX IF NOT EXISTS idx_enforcement_provider ON enforcement_log(provider);
CREATE INDEX IF NOT EXISTS idx_enforcement_deployment_id ON enforcement_log(deployment_id);
"""

# Tokens - stores issued access tokens
TOKENS_SQL = """
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,  -- SHA-256 hash, never store plaintext
    subject TEXT NOT NULL,
    issuer TEXT,
    issued_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT,
    revoked_reason TEXT,
    last_used_at TEXT,
    use_count INTEGER NOT NULL DEFAULT 0,
    permissions TEXT NOT NULL,  -- JSON serialized TokenPermissions
    metadata TEXT  -- JSON metadata
);

CREATE INDEX IF NOT EXISTS idx_tokens_token_id ON tokens(token_id);
CREATE INDEX IF NOT EXISTS idx_tokens_token_hash ON tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_subject ON tokens(subject);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_revoked_at ON tokens(revoked_at);
"""

# Token usage tracking
TOKEN_USAGE_SQL = """
CREATE TABLE IF NOT EXISTS token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    token_count INTEGER NOT NULL DEFAULT 0,
    estimated_cost REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (token_id) REFERENCES tokens(token_id)
);

CREATE INDEX IF NOT EXISTS idx_token_usage_token_id ON token_usage(token_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_period ON token_usage(period_start, period_end);
"""

# Incidents - stores policy violation incidents
INCIDENTS_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE,
    severity TEXT NOT NULL DEFAULT 'MEDIUM',
    status TEXT NOT NULL DEFAULT 'OPEN',
    incident_type TEXT NOT NULL,
    source_request_id TEXT,
    deployment_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,  -- JSON dict
    assignee TEXT,
    resolution TEXT,
    root_cause TEXT,
    tags TEXT,  -- JSON array
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT,
    metadata TEXT  -- JSON metadata
);

CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_incident_type ON incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_incidents_deployment_id ON incidents(deployment_id);
CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents(assignee);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
"""

# Incident comments/notes
INCIDENT_COMMENTS_SQL = """
CREATE TABLE IF NOT EXISTS incident_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    metadata TEXT,  -- JSON metadata
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_comments_incident_id ON incident_comments(incident_id);
"""

# Incident timeline/status changes
INCIDENT_TIMELINE_SQL = """
CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    event_type TEXT NOT NULL,  -- STATUS_CHANGE, ASSIGNMENT, COMMENT, etc.
    old_value TEXT,
    new_value TEXT,
    actor TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    metadata TEXT,  -- JSON metadata
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_timeline_incident_id ON incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_timeline_timestamp ON incident_timeline(timestamp);
"""

# Combined schema SQL for initialization
SCHEMA_SQL = f"""
-- PolicyBind Database Schema v{SCHEMA_VERSION}

{SCHEMA_VERSION_SQL}

{POLICIES_SQL}

{POLICY_AUDIT_LOG_SQL}

{MODEL_REGISTRY_SQL}

{MODEL_USAGE_SQL}

{ENFORCEMENT_LOG_SQL}

{TOKENS_SQL}

{TOKEN_USAGE_SQL}

{INCIDENTS_SQL}

{INCIDENT_COMMENTS_SQL}

{INCIDENT_TIMELINE_SQL}

-- Insert initial schema version if not exists
INSERT OR IGNORE INTO schema_version (version, description)
VALUES ({SCHEMA_VERSION}, 'Initial schema');
"""

# List of all tables for reference
TABLES = [
    "schema_version",
    "policies",
    "policy_audit_log",
    "model_registry",
    "model_usage",
    "enforcement_log",
    "tokens",
    "token_usage",
    "incidents",
    "incident_comments",
    "incident_timeline",
]
