# PolicyBind API Reference

This document provides a complete reference for the PolicyBind HTTP API.

## Overview

PolicyBind exposes a RESTful API over HTTP for managing AI policy enforcement, model deployments, access tokens, incidents, and audit logs. All endpoints use JSON for request and response bodies unless otherwise specified.

**Base URL**: `http://localhost:8080/v1`

**API Version**: 1.0.0

## Authentication

The API supports two authentication methods:

### API Key Authentication

Pass your API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" https://api.policybind.example/v1/policies
```

### Bearer Token Authentication

Pass a bearer token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer your-token" https://api.policybind.example/v1/policies
```

### Public Endpoints

The following endpoints do not require authentication:
- `GET /v1/health` - Health check
- `GET /v1/ready` - Readiness check
- `GET /v1/metrics` - Prometheus metrics

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": {
    "type": "ErrorType",
    "message": "Human-readable error description"
  }
}
```

### Common Error Types

| Error Type | HTTP Status | Description |
|------------|-------------|-------------|
| `ValidationError` | 400 | Invalid request parameters |
| `AuthenticationError` | 401 | Missing or invalid credentials |
| `AuthorizationError` | 403 | Insufficient permissions |
| `NotFound` | 404 | Resource not found |
| `PolicyViolation` | 403 | Request violates policy |
| `InternalError` | 500 | Server error |
| `ServiceUnavailable` | 503 | Service temporarily unavailable |

---

## Health & System Endpoints

### Health Check

Check if the server is running.

**Endpoint**: `GET /v1/health`

**Authentication**: None required

**Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Example**:
```bash
curl http://localhost:8080/v1/health
```

---

### Readiness Check

Check if the server is ready to accept requests.

**Endpoint**: `GET /v1/ready`

**Authentication**: None required

**Response**:
```json
{
  "ready": true,
  "checks": {
    "database": true,
    "policy_engine": true
  }
}
```

**Example**:
```bash
curl http://localhost:8080/v1/ready
```

---

### Prometheus Metrics

Get server metrics in Prometheus format.

**Endpoint**: `GET /v1/metrics`

**Authentication**: None required

**Response**: Prometheus text format

**Example**:
```bash
curl http://localhost:8080/v1/metrics
```

---

## Policy Enforcement

### Enforce Request

Submit a request for policy enforcement.

**Endpoint**: `POST /v1/enforce`

**Authentication**: Required

**Request Body**:
```json
{
  "deployment_id": "dep_abc123",
  "user_id": "user@example.com",
  "department": "engineering",
  "prompt": "Analyze this customer data...",
  "model": "gpt-4",
  "metadata": {
    "session_id": "sess_xyz",
    "client_ip": "192.168.1.1"
  }
}
```

**Request Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `deployment_id` | string | Yes | Registered deployment identifier |
| `user_id` | string | Yes | User making the request |
| `department` | string | No | User's department |
| `prompt` | string | Yes | The prompt to check |
| `model` | string | No | Target model name |
| `metadata` | object | No | Additional context metadata |

**Response** (ALLOW):
```json
{
  "decision": "ALLOW",
  "request_id": "req_abc123",
  "data_classification": ["INTERNAL"],
  "applied_rules": ["rule_001"],
  "warnings": []
}
```

**Response** (DENY):
```json
{
  "decision": "DENY",
  "request_id": "req_abc123",
  "reason": "Request contains PII data",
  "data_classification": ["PII", "CONFIDENTIAL"],
  "applied_rules": ["rule_pii_block"],
  "violations": [
    {
      "rule": "rule_pii_block",
      "message": "PII detected in prompt"
    }
  ]
}
```

**Response** (MODIFY):
```json
{
  "decision": "MODIFY",
  "request_id": "req_abc123",
  "modified_prompt": "Analyze this [REDACTED] data...",
  "modifications": [
    {
      "type": "redaction",
      "field": "prompt",
      "reason": "PII redacted"
    }
  ],
  "data_classification": ["INTERNAL"],
  "applied_rules": ["rule_pii_redact"]
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/v1/enforce \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "deployment_id": "dep_abc123",
    "user_id": "user@example.com",
    "prompt": "Summarize this report"
  }'
```

---

## Policies

### List Policies

Get all active policies.

**Endpoint**: `GET /v1/policies`

**Authentication**: Required

**Response**:
```json
{
  "policies": [
    {
      "id": "policy_001",
      "name": "PII Protection",
      "description": "Block requests containing PII",
      "enabled": true,
      "priority": 100
    }
  ],
  "total": 1
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/policies
```

---

### Get Policy Version

Get the current policy version and hash.

**Endpoint**: `GET /v1/policies/version`

**Authentication**: Required

**Response**:
```json
{
  "version": "2024-01-15T10:30:00Z",
  "hash": "sha256:abc123...",
  "policy_count": 10
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/policies/version
```

---

### Get Policy History

Get policy change history.

**Endpoint**: `GET /v1/policies/history`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum results |

**Response**:
```json
{
  "history": [
    {
      "version": "2024-01-15T10:30:00Z",
      "hash": "sha256:abc123...",
      "changed_by": "admin@example.com",
      "changes": ["Added PII rule"]
    }
  ]
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/policies/history?limit=10
```

---

### Reload Policies

Reload policies from the configuration source.

**Endpoint**: `POST /v1/policies/reload`

**Authentication**: Required (Admin)

**Response**:
```json
{
  "success": true,
  "version": "2024-01-15T10:35:00Z",
  "policy_count": 12
}
```

**Example**:
```bash
curl -X POST -H "X-API-Key: admin-key" http://localhost:8080/v1/policies/reload
```

---

### Test Policy

Test a request against policies without logging.

**Endpoint**: `POST /v1/policies/test`

**Authentication**: Required

**Request Body**: Same as `/v1/enforce`

**Response**: Same as `/v1/enforce` but with `"test_mode": true`

**Example**:
```bash
curl -X POST http://localhost:8080/v1/policies/test \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "deployment_id": "dep_abc123",
    "user_id": "user@example.com",
    "prompt": "Test prompt"
  }'
```

---

## Model Registry

### List Deployments

List all registered model deployments.

**Endpoint**: `GET /v1/registry`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status (pending, approved, rejected, suspended) |
| `department` | string | - | Filter by department |
| `limit` | integer | 100 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

**Response**:
```json
{
  "deployments": [
    {
      "deployment_id": "dep_abc123",
      "name": "Customer Service Bot",
      "model": "gpt-4",
      "status": "approved",
      "department": "support",
      "created_at": "2024-01-10T08:00:00Z"
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/registry?status=approved
```

---

### Create Deployment

Register a new model deployment.

**Endpoint**: `POST /v1/registry`

**Authentication**: Required

**Request Body**:
```json
{
  "name": "Customer Service Bot",
  "description": "AI assistant for customer support",
  "model": "gpt-4",
  "department": "support",
  "owner": "team-lead@example.com",
  "use_case": "customer_support",
  "data_classification": ["INTERNAL"],
  "metadata": {
    "team": "customer-experience"
  }
}
```

**Request Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Deployment name |
| `description` | string | No | Deployment description |
| `model` | string | Yes | Model identifier |
| `department` | string | Yes | Owning department |
| `owner` | string | Yes | Owner email |
| `use_case` | string | No | Use case category |
| `data_classification` | array | No | Data classification levels |
| `metadata` | object | No | Additional metadata |

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "status": "pending",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/v1/registry \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Customer Service Bot",
    "model": "gpt-4",
    "department": "support",
    "owner": "team@example.com"
  }'
```

---

### Get Deployment

Get deployment details.

**Endpoint**: `GET /v1/registry/{deployment_id}`

**Authentication**: Required

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `deployment_id` | string | Deployment identifier |

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "name": "Customer Service Bot",
  "description": "AI assistant for customer support",
  "model": "gpt-4",
  "status": "approved",
  "department": "support",
  "owner": "team-lead@example.com",
  "created_at": "2024-01-10T08:00:00Z",
  "approved_at": "2024-01-11T09:00:00Z",
  "approved_by": "admin@example.com"
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/registry/dep_abc123
```

---

### Update Deployment

Update deployment configuration.

**Endpoint**: `PUT /v1/registry/{deployment_id}`

**Authentication**: Required

**Request Body**: Same fields as create (all optional)

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "updated": true
}
```

**Example**:
```bash
curl -X PUT http://localhost:8080/v1/registry/dep_abc123 \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"description": "Updated description"}'
```

---

### Delete Deployment

Delete a deployment registration.

**Endpoint**: `DELETE /v1/registry/{deployment_id}`

**Authentication**: Required (Admin)

**Response**:
```json
{
  "deleted": true
}
```

**Example**:
```bash
curl -X DELETE -H "X-API-Key: admin-key" http://localhost:8080/v1/registry/dep_abc123
```

---

### Approve Deployment

Approve a pending deployment.

**Endpoint**: `POST /v1/registry/{deployment_id}/approve`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "comment": "Approved after security review"
}
```

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "status": "approved",
  "approved_at": "2024-01-15T10:30:00Z"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/v1/registry/dep_abc123/approve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-key" \
  -d '{"comment": "Looks good"}'
```

---

### Reject Deployment

Reject a pending deployment.

**Endpoint**: `POST /v1/registry/{deployment_id}/reject`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "reason": "Missing security documentation"
}
```

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "status": "rejected",
  "rejected_at": "2024-01-15T10:30:00Z"
}
```

---

### Suspend Deployment

Suspend an approved deployment.

**Endpoint**: `POST /v1/registry/{deployment_id}/suspend`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "reason": "Security incident investigation"
}
```

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "status": "suspended",
  "suspended_at": "2024-01-15T10:30:00Z"
}
```

---

### Reinstate Deployment

Reinstate a suspended deployment.

**Endpoint**: `POST /v1/registry/{deployment_id}/reinstate`

**Authentication**: Required (Admin)

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "status": "approved",
  "reinstated_at": "2024-01-15T10:30:00Z"
}
```

---

### Check Compliance

Check deployment compliance status.

**Endpoint**: `GET /v1/registry/{deployment_id}/compliance`

**Authentication**: Required

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "compliant": true,
  "checks": [
    {
      "name": "data_classification",
      "passed": true
    },
    {
      "name": "owner_verification",
      "passed": true
    }
  ]
}
```

---

### Get Deployment Stats

Get usage statistics for a deployment.

**Endpoint**: `GET /v1/registry/{deployment_id}/stats`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `start` | string | 7d | Start date (ISO or relative) |
| `end` | string | now | End date (ISO format) |

**Response**:
```json
{
  "deployment_id": "dep_abc123",
  "period": {
    "start": "2024-01-08T00:00:00Z",
    "end": "2024-01-15T23:59:59Z"
  },
  "total_requests": 1523,
  "decisions": {
    "ALLOW": 1450,
    "DENY": 50,
    "MODIFY": 23
  },
  "unique_users": 45
}
```

---

## Access Tokens

### List Tokens

List all access tokens.

**Endpoint**: `GET /v1/tokens`

**Authentication**: Required (Admin)

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status (active, suspended, revoked, expired) |
| `deployment_id` | string | - | Filter by deployment |
| `limit` | integer | 100 | Maximum results |

**Response**:
```json
{
  "tokens": [
    {
      "token_id": "tok_abc123",
      "name": "Production API",
      "deployment_id": "dep_xyz",
      "status": "active",
      "created_at": "2024-01-10T08:00:00Z",
      "expires_at": "2024-07-10T08:00:00Z"
    }
  ],
  "total": 1
}
```

**Example**:
```bash
curl -H "X-API-Key: admin-key" http://localhost:8080/v1/tokens
```

---

### Create Token

Create a new access token.

**Endpoint**: `POST /v1/tokens`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "name": "Production API Token",
  "deployment_id": "dep_abc123",
  "expires_in_days": 180,
  "constraints": {
    "allowed_models": ["gpt-4", "gpt-3.5-turbo"],
    "max_requests_per_day": 10000,
    "allowed_departments": ["engineering", "support"],
    "data_classification_max": "CONFIDENTIAL"
  },
  "metadata": {
    "environment": "production"
  }
}
```

**Request Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Token name |
| `deployment_id` | string | No | Associated deployment |
| `expires_in_days` | integer | No | Expiration in days |
| `constraints` | object | No | Access constraints |
| `metadata` | object | No | Additional metadata |

**Response**:
```json
{
  "token_id": "tok_abc123",
  "token": "pb_live_xxx...xxx",
  "expires_at": "2024-07-15T10:30:00Z"
}
```

**Note**: The full token is only returned once at creation time. Store it securely.

**Example**:
```bash
curl -X POST http://localhost:8080/v1/tokens \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-key" \
  -d '{
    "name": "Test Token",
    "expires_in_days": 30
  }'
```

---

### List Token Templates

Get available token templates.

**Endpoint**: `GET /v1/tokens/templates`

**Authentication**: Required

**Response**:
```json
{
  "templates": [
    {
      "name": "development",
      "description": "Development environment token",
      "constraints": {
        "max_requests_per_day": 1000,
        "data_classification_max": "INTERNAL"
      }
    },
    {
      "name": "production",
      "description": "Production environment token",
      "constraints": {
        "max_requests_per_day": 100000
      }
    }
  ]
}
```

---

### Create Token from Natural Language

Create a token using natural language description.

**Endpoint**: `POST /v1/tokens/from-natural-language`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "description": "Create a token for the engineering team with 5000 requests per day, only for internal data, valid for 90 days",
  "deployment_id": "dep_abc123"
}
```

**Response**:
```json
{
  "token_id": "tok_abc123",
  "token": "pb_live_xxx...xxx",
  "parsed_constraints": {
    "max_requests_per_day": 5000,
    "data_classification_max": "INTERNAL",
    "allowed_departments": ["engineering"]
  },
  "expires_at": "2024-04-15T10:30:00Z"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/v1/tokens/from-natural-language \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-key" \
  -d '{
    "description": "token for marketing with 1000 daily requests"
  }'
```

---

### Parse Natural Language

Parse natural language into token constraints without creating a token.

**Endpoint**: `POST /v1/tokens/parse-natural-language`

**Authentication**: Required

**Request Body**:
```json
{
  "description": "engineering team, 5000 requests per day, internal data only"
}
```

**Response**:
```json
{
  "constraints": {
    "allowed_departments": ["engineering"],
    "max_requests_per_day": 5000,
    "data_classification_max": "INTERNAL"
  },
  "confidence": 0.95,
  "interpretation": "Token for engineering department with 5000 daily request limit, restricted to internal data classification"
}
```

---

### Get Token

Get token details.

**Endpoint**: `GET /v1/tokens/{token_id}`

**Authentication**: Required (Admin)

**Response**:
```json
{
  "token_id": "tok_abc123",
  "name": "Production API",
  "status": "active",
  "deployment_id": "dep_xyz",
  "constraints": {
    "max_requests_per_day": 10000
  },
  "created_at": "2024-01-10T08:00:00Z",
  "expires_at": "2024-07-10T08:00:00Z",
  "last_used_at": "2024-01-15T09:30:00Z"
}
```

---

### Update Token

Update token configuration.

**Endpoint**: `PUT /v1/tokens/{token_id}`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "name": "Updated Token Name",
  "constraints": {
    "max_requests_per_day": 20000
  }
}
```

**Response**:
```json
{
  "token_id": "tok_abc123",
  "updated": true
}
```

---

### Revoke Token

Revoke an access token.

**Endpoint**: `DELETE /v1/tokens/{token_id}`

**Authentication**: Required (Admin)

**Response**:
```json
{
  "revoked": true
}
```

---

### Validate Token

Validate a token and check its permissions.

**Endpoint**: `POST /v1/tokens/validate`

**Authentication**: None (token in body)

**Request Body**:
```json
{
  "token": "pb_live_xxx...xxx",
  "deployment_id": "dep_abc123"
}
```

**Response**:
```json
{
  "valid": true,
  "token_id": "tok_abc123",
  "constraints": {
    "max_requests_per_day": 10000,
    "remaining_requests": 8500
  },
  "expires_at": "2024-07-10T08:00:00Z"
}
```

---

### Suspend Token

Temporarily suspend a token.

**Endpoint**: `POST /v1/tokens/{token_id}/suspend`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "reason": "Suspicious activity detected"
}
```

**Response**:
```json
{
  "token_id": "tok_abc123",
  "status": "suspended"
}
```

---

### Unsuspend Token

Reactivate a suspended token.

**Endpoint**: `POST /v1/tokens/{token_id}/unsuspend`

**Authentication**: Required (Admin)

**Response**:
```json
{
  "token_id": "tok_abc123",
  "status": "active"
}
```

---

### Renew Token

Extend a token's expiration.

**Endpoint**: `POST /v1/tokens/{token_id}/renew`

**Authentication**: Required (Admin)

**Request Body**:
```json
{
  "extend_days": 90
}
```

**Response**:
```json
{
  "token_id": "tok_abc123",
  "expires_at": "2024-10-15T10:30:00Z"
}
```

---

## Incidents

### List Incidents

List policy violation incidents.

**Endpoint**: `GET /v1/incidents`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status (open, investigating, resolved, closed) |
| `severity` | string | - | Filter by severity (low, medium, high, critical) |
| `type` | string | - | Filter by incident type |
| `deployment_id` | string | - | Filter by deployment |
| `start` | string | 30d | Start date |
| `end` | string | now | End date |
| `limit` | integer | 100 | Maximum results |

**Response**:
```json
{
  "incidents": [
    {
      "incident_id": "inc_abc123",
      "title": "PII Data Exposure Attempt",
      "type": "data_leak",
      "severity": "high",
      "status": "investigating",
      "deployment_id": "dep_xyz",
      "created_at": "2024-01-15T08:30:00Z"
    }
  ],
  "total": 1
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/incidents?severity=high
```

---

### Create Incident

Create a new incident manually.

**Endpoint**: `POST /v1/incidents`

**Authentication**: Required

**Request Body**:
```json
{
  "title": "Unauthorized Data Access Attempt",
  "description": "User attempted to access restricted customer data",
  "type": "unauthorized_access",
  "severity": "high",
  "deployment_id": "dep_abc123",
  "user_id": "user@example.com",
  "metadata": {
    "source_ip": "192.168.1.100"
  }
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "status": "open",
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

### Get Incident Statistics

Get incident statistics and trends.

**Endpoint**: `GET /v1/incidents/stats`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `start` | string | 30d | Start date |
| `end` | string | now | End date |

**Response**:
```json
{
  "total_count": 45,
  "open_count": 5,
  "investigating_count": 3,
  "resolved_count": 30,
  "closed_count": 7,
  "by_severity": {
    "low": 20,
    "medium": 15,
    "high": 8,
    "critical": 2
  },
  "by_type": {
    "data_leak": 12,
    "unauthorized_access": 18,
    "policy_violation": 15
  },
  "mean_time_to_resolve_hours": 4.5
}
```

---

### Generate Incident Report

Generate a formatted incident report.

**Endpoint**: `GET /v1/incidents/report`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | string | summary | Report type (incident, summary, trend) |
| `format` | string | markdown | Output format (markdown, json, text) |
| `incident_id` | string | - | Required for incident type |
| `start` | string | 30d | Start date for summary/trend |
| `end` | string | now | End date |

**Response** (Markdown format):
```
# Incident Summary Report

**Period**: 2024-01-01 to 2024-01-15

## Overview

- Total Incidents: 45
- Open: 5
- Resolved: 30

## By Severity

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 8 |
...
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8080/v1/incidents/report?type=summary&format=markdown"
```

---

### Get Incident

Get incident details.

**Endpoint**: `GET /v1/incidents/{incident_id}`

**Authentication**: Required

**Response**:
```json
{
  "incident": {
    "incident_id": "inc_abc123",
    "title": "PII Data Exposure Attempt",
    "description": "User attempted to include customer SSN in prompt",
    "type": "data_leak",
    "severity": "high",
    "status": "investigating",
    "deployment_id": "dep_xyz",
    "user_id": "user@example.com",
    "assigned_to": "security@example.com",
    "created_at": "2024-01-15T08:30:00Z",
    "comments": [
      {
        "author": "security@example.com",
        "text": "Investigating user activity logs",
        "created_at": "2024-01-15T09:00:00Z"
      }
    ],
    "timeline": [
      {
        "event": "created",
        "timestamp": "2024-01-15T08:30:00Z"
      },
      {
        "event": "assigned",
        "timestamp": "2024-01-15T08:35:00Z",
        "details": {"assigned_to": "security@example.com"}
      }
    ]
  }
}
```

---

### Update Incident

Update incident details.

**Endpoint**: `PUT /v1/incidents/{incident_id}`

**Authentication**: Required

**Request Body**:
```json
{
  "title": "Updated Title",
  "severity": "critical",
  "description": "Updated description with more details"
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "updated": true
}
```

---

### Assign Incident

Assign an incident to a user.

**Endpoint**: `POST /v1/incidents/{incident_id}/assign`

**Authentication**: Required

**Request Body**:
```json
{
  "assignee": "security-team@example.com"
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "assigned_to": "security-team@example.com"
}
```

---

### Add Comment

Add a comment to an incident.

**Endpoint**: `POST /v1/incidents/{incident_id}/comment`

**Authentication**: Required

**Request Body**:
```json
{
  "text": "Completed initial investigation. User was unaware of policy."
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "comment_id": "com_xyz789"
}
```

---

### Start Investigation

Mark incident as under investigation.

**Endpoint**: `POST /v1/incidents/{incident_id}/investigate`

**Authentication**: Required

**Request Body**:
```json
{
  "notes": "Beginning security review"
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "status": "investigating"
}
```

---

### Resolve Incident

Mark incident as resolved.

**Endpoint**: `POST /v1/incidents/{incident_id}/resolve`

**Authentication**: Required

**Request Body**:
```json
{
  "resolution": "User training completed. Policy updated for clarity.",
  "root_cause": "Unclear policy documentation"
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "status": "resolved",
  "resolved_at": "2024-01-15T14:30:00Z"
}
```

---

### Close Incident

Close a resolved incident.

**Endpoint**: `POST /v1/incidents/{incident_id}/close`

**Authentication**: Required

**Request Body**:
```json
{
  "summary": "Incident fully remediated and documented"
}
```

**Response**:
```json
{
  "incident_id": "inc_abc123",
  "status": "closed",
  "closed_at": "2024-01-15T16:00:00Z"
}
```

---

## Audit Logs

### Query Audit Logs

Query enforcement audit logs.

**Endpoint**: `GET /v1/audit/logs`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `user` | string | - | Filter by user ID |
| `department` | string | - | Filter by department |
| `decision` | string | - | Filter by decision (ALLOW, DENY, MODIFY) |
| `deployment` | string | - | Filter by deployment ID |
| `start` | string | 7d | Start date (ISO or relative like "7d") |
| `end` | string | now | End date |
| `limit` | integer | 100 | Maximum results |

**Response**:
```json
{
  "logs": [
    {
      "id": "log_abc123",
      "timestamp": "2024-01-15T10:30:00Z",
      "deployment_id": "dep_xyz",
      "user_id": "user@example.com",
      "department": "engineering",
      "decision": "ALLOW",
      "model": "gpt-4",
      "data_classification": ["INTERNAL"]
    }
  ],
  "total": 1,
  "limit": 100
}
```

**Example**:
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8080/v1/audit/logs?decision=DENY&start=7d"
```

---

### Get Audit Statistics

Get audit statistics for a time period.

**Endpoint**: `GET /v1/audit/stats`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `start` | string | 30d | Start date |
| `end` | string | now | End date |

**Response**:
```json
{
  "total_requests": 15230,
  "by_decision": {
    "ALLOW": 14500,
    "DENY": 500,
    "MODIFY": 230
  },
  "by_department": {
    "engineering": 8000,
    "support": 5000,
    "marketing": 2230
  },
  "by_model": {
    "gpt-4": 10000,
    "gpt-3.5-turbo": 5230
  }
}
```

---

### Export Audit Logs

Export audit logs in various formats.

**Endpoint**: `GET /v1/audit/export`

**Authentication**: Required

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | string | json | Export format (json, csv, ndjson) |
| `user` | string | - | Filter by user ID |
| `department` | string | - | Filter by department |
| `decision` | string | - | Filter by decision |
| `deployment` | string | - | Filter by deployment |
| `start` | string | 30d | Start date |
| `end` | string | now | End date |
| `limit` | integer | 10000 | Maximum results (max 100000) |

**Response**: File download with `Content-Disposition` header

**Example** (JSON export):
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8080/v1/audit/export?format=json&start=30d" \
  -o audit_logs.json
```

**Example** (CSV export):
```bash
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8080/v1/audit/export?format=csv&decision=DENY" \
  -o denied_requests.csv
```

---

### Get Log Entry

Get a specific audit log entry with full details.

**Endpoint**: `GET /v1/audit/logs/{log_id}`

**Authentication**: Required

**Response**:
```json
{
  "log": {
    "id": "log_abc123",
    "timestamp": "2024-01-15T10:30:00Z",
    "deployment_id": "dep_xyz",
    "user_id": "user@example.com",
    "department": "engineering",
    "decision": "MODIFY",
    "model": "gpt-4",
    "prompt_hash": "sha256:abc...",
    "data_classification": ["PII", "INTERNAL"],
    "applied_rules": ["rule_pii_redact"],
    "modifications": [
      {
        "type": "redaction",
        "field": "prompt",
        "pattern": "SSN"
      }
    ],
    "request_metadata": {
      "client_ip": "192.168.1.1",
      "user_agent": "MyApp/1.0"
    },
    "response_metadata": {
      "processing_time_ms": 45
    }
  }
}
```

---

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Default limit**: 1000 requests per minute per API key
- **Burst limit**: 100 requests per second

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1705319460
```

When rate limited, the API returns `429 Too Many Requests`:

```json
{
  "error": {
    "type": "RateLimitExceeded",
    "message": "Rate limit exceeded. Try again in 30 seconds.",
    "retry_after": 30
  }
}
```

---

## Pagination

List endpoints support pagination using `limit` and `offset` parameters:

```bash
# First page
curl "http://localhost:8080/v1/incidents?limit=50&offset=0"

# Second page
curl "http://localhost:8080/v1/incidents?limit=50&offset=50"
```

Response includes pagination metadata:

```json
{
  "incidents": [...],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

---

## Webhooks

PolicyBind can send webhook notifications for events. Configure webhooks via the server configuration file.

### Event Types

| Event | Description |
|-------|-------------|
| `enforcement.deny` | Request was denied |
| `enforcement.modify` | Request was modified |
| `incident.created` | New incident created |
| `incident.resolved` | Incident resolved |
| `deployment.approved` | Deployment approved |
| `deployment.suspended` | Deployment suspended |
| `token.revoked` | Token revoked |

### Webhook Payload

```json
{
  "event": "enforcement.deny",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "request_id": "req_abc123",
    "deployment_id": "dep_xyz",
    "user_id": "user@example.com",
    "reason": "PII detected"
  }
}
```

---

## SDK Examples

### Python

```python
import requests

class PolicyBindClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {"X-API-Key": api_key}

    def enforce(self, deployment_id, user_id, prompt):
        response = requests.post(
            f"{self.base_url}/v1/enforce",
            headers=self.headers,
            json={
                "deployment_id": deployment_id,
                "user_id": user_id,
                "prompt": prompt
            }
        )
        return response.json()

# Usage
client = PolicyBindClient("http://localhost:8080", "your-api-key")
result = client.enforce("dep_abc", "user@example.com", "Hello")
if result["decision"] == "ALLOW":
    print("Request allowed")
```

### JavaScript/TypeScript

```typescript
class PolicyBindClient {
  constructor(private baseUrl: string, private apiKey: string) {}

  async enforce(deploymentId: string, userId: string, prompt: string) {
    const response = await fetch(`${this.baseUrl}/v1/enforce`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey,
      },
      body: JSON.stringify({
        deployment_id: deploymentId,
        user_id: userId,
        prompt: prompt,
      }),
    });
    return response.json();
  }
}

// Usage
const client = new PolicyBindClient('http://localhost:8080', 'your-api-key');
const result = await client.enforce('dep_abc', 'user@example.com', 'Hello');
```

### cURL

```bash
# Enforce a request
curl -X POST http://localhost:8080/v1/enforce \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"deployment_id": "dep_abc", "user_id": "user@example.com", "prompt": "Hello"}'

# List incidents
curl -H "X-API-Key: your-api-key" http://localhost:8080/v1/incidents

# Export audit logs as CSV
curl -H "X-API-Key: your-api-key" \
  "http://localhost:8080/v1/audit/export?format=csv" \
  -o audit.csv
```

---

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:

- **JSON**: `GET /v1/openapi.json`
- **YAML**: `GET /v1/openapi.yaml`

You can import this specification into tools like Swagger UI, Postman, or use it to generate client SDKs.
