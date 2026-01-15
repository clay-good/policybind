# Getting Started with PolicyBind

This guide will help you install PolicyBind and get your first policy enforcement running in minutes.

## Prerequisites

Before installing PolicyBind, ensure you have:

- Python 3.10 or higher
- pip (Python package installer)
- SQLite 3.x (included with Python)

## Installation

### From PyPI (Recommended)

```bash
pip install policybind
```

### From Source

```bash
git clone https://github.com/clay-good/policybind.git
cd policybind
pip install -e .
```

### With Server Support

If you plan to run PolicyBind as an HTTP server, install with the server extras:

```bash
pip install policybind[server]
```

### Development Installation

For development, install with all development dependencies:

```bash
pip install -e ".[dev]"
```

## Verify Installation

Verify that PolicyBind is installed correctly:

```bash
# Check version
policybind --version

# Or via Python
python -c "import policybind; print(policybind.__version__)"
```

## Quick Start Tutorial

### Step 1: Initialize PolicyBind

Create a new PolicyBind project with an initialized database and example configuration:

```bash
# Create a new directory for your project
mkdir my-ai-governance
cd my-ai-governance

# Initialize PolicyBind
policybind init

# This creates:
# - policybind.yaml (configuration file)
# - policybind.db (SQLite database)
# - policies/ (directory for policy files)
```

### Step 2: Create Your First Policy

Create a policy file at `policies/first-policy.yaml`:

```yaml
name: first-policy
version: "1.0.0"
description: My first PolicyBind policy

rules:
  # Allow engineering team to use GPT-4
  - name: allow-engineering-gpt4
    description: Engineering department can use GPT-4
    match:
      department: engineering
      model: gpt-4
    action: ALLOW
    priority: 100

  # Deny GPT-4 for other departments
  - name: deny-gpt4-others
    description: Other departments cannot use GPT-4
    match:
      model: gpt-4
    action: DENY
    priority: 50

  # Allow GPT-3.5 for everyone
  - name: allow-gpt35-all
    description: Everyone can use GPT-3.5
    match:
      model: gpt-3.5-turbo
    action: ALLOW
    priority: 10

  # Default deny
  - name: default-deny
    description: Deny all other requests
    action: DENY
    priority: 1
```

### Step 3: Validate and Load the Policy

```bash
# Validate the policy syntax
policybind policy validate policies/first-policy.yaml

# Load the policy
policybind policy load policies/first-policy.yaml

# View loaded policies
policybind policy show
```

### Step 4: Test Your Policy

Test how requests would be handled:

```bash
# Test an engineering request for GPT-4 (should be allowed)
policybind policy test policies/first-policy.yaml --request '{
  "provider": "openai",
  "model": "gpt-4",
  "department": "engineering",
  "user_id": "eng-user-001"
}'

# Test a marketing request for GPT-4 (should be denied)
policybind policy test policies/first-policy.yaml --request '{
  "provider": "openai",
  "model": "gpt-4",
  "department": "marketing",
  "user_id": "mkt-user-001"
}'
```

### Step 5: Check System Status

```bash
# View overall system status
policybind status

# View detailed status with metrics
policybind status --detailed
```

## Using PolicyBind as a Library

You can also use PolicyBind directly in your Python applications:

```python
from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline
from policybind.models.request import AIRequest
from policybind.storage import Database

# Initialize database
db = Database("policybind.db")
db.initialize()

# Load policies
parser = PolicyParser()
policy_set = parser.parse_file("policies/first-policy.yaml")

# Create enforcement pipeline
pipeline = EnforcementPipeline(policy_set=policy_set)

# Create a request
request = AIRequest(
    provider="openai",
    model="gpt-4",
    user_id="eng-user-001",
    department="engineering",
)

# Enforce the policy
response = pipeline.enforce(request)

print(f"Decision: {response.decision}")
print(f"Applied Rules: {response.applied_rules}")
print(f"Reason: {response.reason}")
```

## Running the HTTP Server

For production deployments, you can run PolicyBind as an HTTP server:

```bash
# Start the server (requires server extras)
policybind serve --host 0.0.0.0 --port 8080

# Or with a custom config
policybind serve --config policybind.yaml
```

The server exposes a REST API for enforcement:

```bash
# Health check
curl http://localhost:8080/v1/health

# Enforce a request
curl -X POST http://localhost:8080/v1/enforce \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "provider": "openai",
    "model": "gpt-4",
    "department": "engineering",
    "user_id": "eng-user-001"
  }'
```

## Configuration

PolicyBind is configured via a YAML file (`policybind.yaml`):

```yaml
# Database settings
database:
  path: policybind.db
  pool_size: 5
  timeout_seconds: 30

# Enforcement settings
enforcement:
  default_action: deny
  log_all_requests: true
  require_classification: false

# Server settings (when running as HTTP server)
server:
  host: 127.0.0.1
  port: 8080
  require_auth: true
  api_key_header: X-API-Key

# Logging settings
logging:
  level: INFO
  format: json
```

Environment variables override file configuration (prefix with `POLICYBIND_`):

```bash
export POLICYBIND_DATABASE_PATH=/var/lib/policybind/db.sqlite
export POLICYBIND_ENFORCEMENT_DEFAULT_ACTION=deny
export POLICYBIND_SERVER_PORT=9090
```

## Next Steps

Now that you have PolicyBind running, explore these topics:

- [Core Concepts](concepts.md) - Understand the PolicyBind data model
- [Policy Reference](policy-reference.md) - Complete policy syntax documentation
- [API Reference](api-reference.md) - HTTP API documentation
- [Architecture](architecture.md) - System design and components
- [Deployment Guide](deployment.md) - Production deployment best practices
- [Security Guide](security.md) - Security model and configuration

