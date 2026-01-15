# PolicyBind Security Guide

This document describes the security model, authentication, authorization, and best practices for securing PolicyBind deployments.

## Security Model Overview

PolicyBind is designed with security as a core principle:

1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Minimal permissions by default
3. **Fail Secure**: Deny access when in doubt
4. **Audit Everything**: Complete audit trail of all operations
5. **Secure by Default**: Secure configuration out of the box

## Authentication

### API Key Authentication

For server-to-server communication, use API keys:

```yaml
# Configuration
server:
  require_auth: true
  api_key_header: X-API-Key
```

Using API keys:

```bash
curl -X POST https://policybind.example.com/v1/enforce \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "model": "gpt-4"}'
```

API key requirements:
- Minimum 32 characters
- Cryptographically random
- Stored as secure hashes (Argon2)
- Rotated regularly (90 days recommended)

### Token Authentication

For end-user or application authentication, use PolicyBind tokens:

```bash
curl -X POST https://policybind.example.com/v1/enforce \
  -H "Authorization: Bearer pb_live_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "model": "gpt-4"}'
```

Token security features:
- Cryptographically random generation
- Secure hash storage (plaintext never stored)
- Expiration enforcement
- Permission scoping
- Revocation support

### Token Hashing

Tokens are hashed before storage:

```python
# Tokens are never stored in plaintext
# Only the hash is stored in the database
token_hash = argon2.hash(token_value)
```

The plaintext token is only shown once at creation time. It cannot be recovered.

## Authorization

### Role-Based Access Control

The HTTP API uses role-based access control:

| Role | Permissions |
|------|-------------|
| `viewer` | Read policies, view status |
| `operator` | + Reload policies, manage tokens |
| `admin` | + Create/delete policies, manage registry |
| `superadmin` | + All operations, system configuration |

Configure roles per API key:

```yaml
api_keys:
  - key_hash: "..."
    name: monitoring-service
    roles: [viewer]

  - key_hash: "..."
    name: deployment-automation
    roles: [operator]

  - key_hash: "..."
    name: security-admin
    roles: [admin]
```

### Endpoint Permissions

| Endpoint | Required Role |
|----------|---------------|
| `GET /v1/health` | None (public) |
| `GET /v1/ready` | None (public) |
| `POST /v1/enforce` | Any authenticated |
| `GET /v1/policies` | viewer |
| `POST /v1/policies/reload` | operator |
| `POST /v1/registry` | admin |
| `DELETE /v1/registry/{id}` | admin |
| `POST /v1/tokens` | operator |
| `DELETE /v1/tokens/{id}` | operator |
| `GET /v1/audit/logs` | viewer |

### Token Permissions

Tokens can be scoped to specific permissions:

```yaml
permissions:
  # Model restrictions
  allowed_models:
    - gpt-3.5-turbo
    - gpt-4
  denied_models:
    - dall-e-*

  # Use case restrictions
  allowed_use_cases:
    - code-review
    - documentation

  # Data classification restrictions
  allowed_data_classifications:
    - public
    - internal

  # Budget limits
  budget_limit: 100.0
  budget_period: monthly

  # Rate limits
  rate_limit:
    requests_per_minute: 30

  # Time restrictions
  valid_hours: [9, 17]  # 9 AM - 5 PM only
```

## Secure Configuration

### Default Secure Settings

PolicyBind ships with secure defaults:

```yaml
# Enforcement defaults
enforcement:
  default_action: deny  # Deny unknown requests
  require_classification: true  # Require data classification
  log_all_requests: true  # Audit everything

# Server defaults
server:
  require_auth: true  # Require authentication
  tls_enabled: true  # Require TLS

# Token defaults
tokens:
  max_expiry_days: 365  # Maximum token lifetime
  require_expiry: true  # Tokens must expire
```

### TLS Configuration

Always use TLS in production:

```yaml
server:
  tls_enabled: true
  tls_cert_file: /etc/policybind/tls/cert.pem
  tls_key_file: /etc/policybind/tls/key.pem
  tls_min_version: "1.2"
  tls_cipher_suites:
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### Secret Management

Never store secrets in configuration files:

```yaml
# BAD - secret in file
database:
  password: mysecretpassword

# GOOD - environment variable reference
database:
  password_env: POLICYBIND_DB_PASSWORD

# GOOD - file reference
database:
  password_file: /run/secrets/db-password
```

Use secret management systems:
- Kubernetes Secrets
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault

## Audit Logging

### What is Logged

PolicyBind logs all security-relevant events:

| Event | Details Logged |
|-------|----------------|
| Enforcement decisions | Request, decision, rules, timing |
| Policy changes | Old/new values, who, when |
| Token operations | Create, validate, revoke |
| Registry changes | Deployment lifecycle |
| Incidents | Full incident lifecycle |
| Authentication | Success/failure, source |
| Authorization | Access granted/denied |

### Audit Log Format

Structured JSON logs for security analysis:

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "event_type": "enforcement",
  "request_id": "req-abc123",
  "user_id": "user-001",
  "source_ip": "10.0.1.50",
  "action": "enforce",
  "decision": "DENY",
  "reason": "Model not approved for department",
  "model": "gpt-4",
  "department": "marketing",
  "applied_rules": ["deny-marketing-gpt4"],
  "latency_ms": 0.5
}
```

### Log Retention

Configure log retention for compliance:

```yaml
audit:
  retention_days: 365  # 1 year minimum for compliance
  archive_enabled: true
  archive_path: /archive/policybind/
  archive_compression: gzip
```

### Log Integrity

Enable tamper-evident logging:

```yaml
audit:
  integrity_enabled: true
  hash_algorithm: sha256
  signature_key_file: /etc/policybind/audit-signing-key.pem
```

Each log entry includes a hash chain:

```json
{
  "entry_hash": "sha256:abc123...",
  "previous_hash": "sha256:xyz789...",
  "signature": "..."
}
```

## SQL Injection Prevention

PolicyBind uses parameterized queries exclusively:

```python
# SAFE - parameterized query
cursor.execute(
    "SELECT * FROM tokens WHERE subject = ?",
    (subject,)
)

# NEVER - string interpolation (would be rejected in code review)
# cursor.execute(f"SELECT * FROM tokens WHERE subject = '{subject}'")
```

All database operations go through the repository layer which enforces parameterization.

## Input Validation

All inputs are validated at system boundaries:

### Request Validation

```python
# Request fields are validated
class AIRequest:
    provider: str  # Must be non-empty
    model: str  # Must be non-empty
    user_id: str  # Must be non-empty
    # ... validated on construction
```

### Policy Validation

Policies are validated before loading:
- YAML syntax checking
- Schema validation
- Semantic validation
- No code execution from policies

### API Input Validation

All API inputs are validated:
- Type checking
- Length limits
- Pattern validation
- Sanitization

## Rate Limiting

Protect against abuse with rate limiting:

```yaml
server:
  rate_limit_enabled: true
  rate_limit_requests: 10000
  rate_limit_window_seconds: 60
  rate_limit_by: ip  # or api_key

  # Per-endpoint limits
  rate_limits:
    "/v1/enforce": 1000
    "/v1/tokens": 100
    "/v1/policies/reload": 10
```

## Denial of Service Protection

### Resource Limits

```yaml
server:
  max_request_size_bytes: 1048576  # 1 MB
  request_timeout_seconds: 30
  max_connections: 1000

database:
  max_query_time_seconds: 10
  max_result_rows: 10000
```

### Policy Limits

```yaml
policies:
  max_rules_per_policy: 1000
  max_policy_size_bytes: 1048576
  max_include_depth: 10
```

## Threat Model

### Threats Mitigated

| Threat | Mitigation |
|--------|------------|
| Unauthorized access | Authentication required, RBAC |
| Policy bypass | Server-side enforcement |
| Token theft | Short expiry, hashing, revocation |
| Data exfiltration | Audit logging, data classification |
| SQL injection | Parameterized queries |
| Privilege escalation | Least privilege, RBAC |
| Denial of service | Rate limiting, resource limits |
| Man-in-the-middle | TLS required |
| Log tampering | Hash chains, signatures |

### Threats Not Mitigated

PolicyBind does not protect against:

- **Insider threats with admin access**: Admins can change policies
- **Physical access to database**: Use disk encryption
- **Compromised AI providers**: PolicyBind controls access, not AI behavior
- **Side-channel attacks**: Standard cloud hardening required

### Security Assumptions

PolicyBind assumes:

1. The server infrastructure is secure
2. TLS is properly configured
3. Secrets are managed securely
4. Administrators are trusted
5. The operating system is hardened

## Incident Response

### Security Incident Types

| Type | Severity | Response |
|------|----------|----------|
| Token compromise | HIGH | Revoke immediately |
| Policy bypass attempt | MEDIUM | Investigate, update policy |
| Unauthorized access | HIGH | Revoke credentials, audit |
| Data leak detected | CRITICAL | Suspend deployment, investigate |
| DoS attack | HIGH | Enable stricter rate limits |

### Response Procedures

1. **Detection**: Automated alerts or manual discovery
2. **Containment**: Revoke tokens, suspend deployments
3. **Investigation**: Review audit logs
4. **Remediation**: Update policies, patch vulnerabilities
5. **Recovery**: Restore normal operations
6. **Lessons learned**: Update procedures

### Emergency Lockdown

For critical security events:

```bash
# Enable emergency lockdown
policybind emergency lockdown --reason "Security incident"

# This:
# - Denies all requests
# - Revokes all tokens
# - Suspends all deployments
# - Notifies administrators

# Disable lockdown
policybind emergency unlock --ticket SEC-2024-001
```

## Compliance

### Regulatory Frameworks

PolicyBind supports compliance with:

- **EU AI Act**: Risk classification, documentation, audit trails
- **NIST AI RMF**: Governance, mapping, measurement, management
- **SOC 2**: Security controls, availability, confidentiality
- **GDPR**: Data protection, right to explanation
- **HIPAA**: Healthcare data handling

### Compliance Features

| Requirement | PolicyBind Feature |
|-------------|-------------------|
| Access control | RBAC, tokens, policies |
| Audit trails | Complete audit logging |
| Data classification | Classification enforcement |
| Risk assessment | Registry risk scoring |
| Documentation | Policy as code, versioning |
| Incident response | Incident management |

### Evidence Export

Export compliance evidence:

```bash
# Generate compliance report
policybind report compliance \
  --framework eu-ai-act \
  --period 2024-Q1 \
  --output compliance-report.pdf

# Export audit evidence
policybind audit export \
  --since 2024-01-01 \
  --until 2024-03-31 \
  --format json \
  --signed \
  --output evidence-package.json
```

## Security Best Practices

### Deployment Checklist

- [ ] TLS enabled with strong ciphers
- [ ] Authentication required for all endpoints
- [ ] API keys rotated every 90 days
- [ ] Tokens have appropriate expiry
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Log retention configured
- [ ] Backups encrypted
- [ ] Secrets in secret manager
- [ ] Firewall rules configured
- [ ] Monitoring and alerting set up

### Operational Security

1. **Principle of least privilege**: Grant minimal permissions
2. **Defense in depth**: Multiple security layers
3. **Regular audits**: Review access and policies
4. **Incident readiness**: Have response procedures
5. **Security updates**: Keep dependencies updated
6. **Training**: Ensure team understands security model

### API Key Management

```bash
# Create API key
policybind api-key create \
  --name "ci-cd-pipeline" \
  --roles operator \
  --expires 90d

# Rotate API key
policybind api-key rotate \
  --name "ci-cd-pipeline"

# Revoke API key
policybind api-key revoke \
  --name "ci-cd-pipeline" \
  --reason "Employee departure"
```

### Token Management

```bash
# Create scoped token
policybind token create \
  --subject "data-science-team" \
  --expires 30d \
  --budget 500 \
  --models "gpt-4,gpt-3.5-turbo"

# Audit token usage
policybind token audit \
  --subject "data-science-team" \
  --since 2024-01-01

# Revoke compromised token
policybind token revoke \
  --id tok-abc123 \
  --reason "Potential compromise"
```

## Vulnerability Reporting

Report security vulnerabilities to: security@policybind.example.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge within 24 hours and provide updates on remediation.
