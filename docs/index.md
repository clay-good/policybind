# PolicyBind Documentation

Welcome to the PolicyBind documentation. PolicyBind is an AI Policy as Code enforcement platform for organizational AI governance.

## Overview

PolicyBind helps organizations:

- **Control AI Access**: Define who can use which AI models and for what purposes
- **Enforce Policies**: Evaluate every AI request against your organization's policies
- **Track Deployments**: Maintain a registry of all AI model deployments
- **Manage Tokens**: Issue scoped access tokens with budgets and rate limits
- **Monitor Compliance**: Generate reports for auditors and regulators
- **Respond to Incidents**: Track and resolve policy violations

## Quick Navigation

### Getting Started

- [Getting Started Guide](getting-started.md) - Installation, first policy, and basic usage
- [Core Concepts](concepts.md) - Understand the PolicyBind data model and philosophy

### Reference

- [Policy Reference](policy-reference.md) - Complete policy syntax documentation
- [API Reference](api-reference.md) - HTTP API endpoints and usage
- [CLI Reference](cli-reference.md) - Command-line interface documentation

### Guides

- [Architecture Overview](architecture.md) - System design and components
- [Deployment Guide](deployment.md) - Production deployment and scaling
- [Security Guide](security.md) - Security model and best practices
- [Integration Guide](integration-guide.md) - Integrating with your applications

### Additional Resources

- [Testing Guide](testing.md) - Running and writing tests
- [Examples](../examples/) - Example policies and scripts
- [Changelog](../CHANGELOG.md) - Version history

## Documentation Map

```
docs/
  index.md              <- You are here
  getting-started.md    <- Start here
  concepts.md           <- Core concepts
  policy-reference.md   <- Policy syntax
  api-reference.md      <- HTTP API
  architecture.md       <- System design
  deployment.md         <- Production deployment
  security.md           <- Security guide
  integration-guide.md  <- Integration patterns
  testing.md            <- Testing guide
```

## Feature Overview

### Policy Engine

Define AI usage policies in human-readable YAML:

```yaml
rules:
  - name: allow-engineering-gpt4
    match:
      department: engineering
      model: gpt-4
    action: ALLOW
```

Key features:
- Declarative policy definitions
- Complex matching conditions
- Multiple action types (ALLOW, DENY, MODIFY, etc.)
- Hot reloading without restarts
- Version control integration

[Learn more about policies](policy-reference.md)

### Model Registry

Track all AI deployments in your organization:

```bash
policybind registry add \
  --name "Customer Support Bot" \
  --model gpt-4-turbo \
  --owner support-team \
  --risk-level MEDIUM
```

Key features:
- Deployment tracking
- Risk assessment
- Approval workflows
- Compliance checking
- Usage statistics

[Learn more about the registry](concepts.md#model-registry-concepts)

### Token System

Issue scoped access tokens:

```bash
policybind token create \
  --subject "data-science-team" \
  --models "gpt-4,gpt-3.5-turbo" \
  --budget 500 --budget-period monthly \
  --expires 90d
```

Key features:
- Fine-grained permissions
- Budget enforcement
- Rate limiting
- Natural language creation
- Automatic expiration

[Learn more about tokens](concepts.md#token-system-concepts)

### Incident Management

Track and respond to policy violations:

```bash
policybind incident list --status OPEN --severity HIGH
policybind incident show INC-001
policybind incident update INC-001 --status INVESTIGATING --assignee security-team
```

Key features:
- Automatic detection
- Workflow management
- Root cause tracking
- Metrics and reporting

[Learn more about incidents](concepts.md#incident-management-concepts)

### Compliance Reporting

Generate reports for auditors:

```bash
policybind report compliance \
  --framework eu-ai-act \
  --period 2024-Q1 \
  --output report.pdf
```

Key features:
- EU AI Act mapping
- NIST AI RMF mapping
- SOC 2 controls
- Evidence export
- Audit trails

[Learn more about compliance](security.md#compliance)

## Deployment Options

| Mode | Description | Best For |
|------|-------------|----------|
| **Library** | Embed in your application | Low latency, simple setup |
| **Server** | Centralized HTTP service | Multiple applications, central control |
| **CLI** | Command-line operations | Administration, CI/CD |

[Learn more about deployment](deployment.md)

## Integration

PolicyBind integrates with your existing infrastructure:

```python
# Python SDK
from policybind import EnforcementPipeline, AIRequest

pipeline = EnforcementPipeline.from_config("policybind.yaml")
response = pipeline.enforce(AIRequest(
    provider="openai",
    model="gpt-4",
    user_id="user-001",
))
```

```bash
# HTTP API
curl -X POST https://policybind.example.com/v1/enforce \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"provider": "openai", "model": "gpt-4"}'
```

[Learn more about integration](integration-guide.md)

## Security

PolicyBind is designed with security in mind:

- Authentication via API keys or tokens
- Role-based access control
- Complete audit logging
- TLS encryption
- SQL injection prevention
- Rate limiting

[Learn more about security](security.md)

