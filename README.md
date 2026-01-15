# PolicyBind

**AI Policy as Code Enforcement Platform for Organizational AI Governance**

PolicyBind is a comprehensive framework for defining, managing, and enforcing policies that govern AI usage within organizations. It provides the infrastructure needed to implement responsible AI practices at scale.

## Why PolicyBind?

As organizations adopt AI systems, they face critical governance challenges:

| Challenge | Impact | PolicyBind Solution |
|-----------|--------|---------------------|
| **Lack of Visibility** | No centralized view of AI deployments | Model Registry with full inventory |
| **Inconsistent Controls** | Different teams apply different standards | Unified policy-as-code enforcement |
| **Reactive Security** | Violations discovered after the fact | Real-time policy enforcement |
| **Compliance Burden** | Manual effort for EU AI Act, NIST, SOC 2 | Automated compliance mapping and reporting |
| **Access Sprawl** | API credentials proliferate without control | Scoped tokens with automatic expiration |

## Features

### Policy Engine

Define AI usage policies in human-readable YAML:

```yaml
name: enterprise-ai-policy
version: "1.0.0"

rules:
  - name: block-pii-external
    description: PII data cannot go to external providers
    match:
      and:
        - provider: { not_in: [internal, on-premise] }
        - data_classification: { contains: pii }
    action: DENY
    priority: 800

  - name: allow-engineering
    match:
      department: engineering
    action: ALLOW
    priority: 500

  - name: default-deny
    action: DENY
    priority: 0
```

### SDK Integrations

PolicyBind provides transparent policy enforcement for 9 major AI providers. Wrap your existing SDK clients to automatically enforce policies without changing application code.

| Provider | Integration | Features |
|----------|-------------|----------|
| **OpenAI** | `openai_integration` | Chat, completions, embeddings, streaming |
| **Anthropic** | `anthropic_integration` | Messages, streaming, tool use |
| **Google** | `google_integration` | Gemini, Vertex AI, streaming |
| **Cohere** | `cohere_integration` | Chat, generate, embed, rerank |
| **Mistral AI** | `mistral_integration` | Chat, streaming, embeddings |
| **AWS Bedrock** | `bedrock_integration` | Converse, invoke model, streaming |
| **Ollama** | `ollama_integration` | Local models, chat, generate, embeddings |
| **Hugging Face** | `huggingface_integration` | Chat, text generation, embeddings |
| **LangChain** | `langchain_integration` | Callbacks and LLM wrappers |

#### Example: OpenAI Integration

```python
from openai import OpenAI
from policybind.integrations.openai_integration import create_policy_client

# Create a policy-enforced OpenAI client
client = create_policy_client(
    policy_set=policy_set,
    user_id="user@example.com",
    department="engineering",
)

# Use normally - policies are automatically enforced
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

#### Example: Anthropic Integration

```python
from policybind.integrations.anthropic_integration import create_policy_client

client = create_policy_client(
    policy_set=policy_set,
    user_id="user@example.com",
    department="engineering",
)

response = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}]
)
```

#### Example: LangChain Integration

```python
from langchain_openai import ChatOpenAI
from policybind.integrations.langchain_integration import wrap_llm

# Wrap any LangChain LLM
llm = wrap_llm(
    llm=ChatOpenAI(model="gpt-4"),
    policy_set=policy_set,
    user_id="user@example.com",
)

# Use normally - policies automatically enforced
response = llm.invoke("Hello!")
```

### Model Registry

Track and manage all AI deployments:

```bash
# Register a deployment
policybind registry register \
  --name "customer-support-bot" \
  --provider openai \
  --model gpt-4 \
  --owner "support-team" \
  --data-categories "customer-data,pii"

# Assess risk
policybind registry risk-assess dep_abc123

# Approve for production
policybind registry approve dep_abc123 --ticket JIRA-456
```

### Token-Based Access Control

Issue scoped tokens with fine-grained permissions:

```bash
# Create a token with natural language
policybind token create \
  --subject "marketing-analytics" \
  --permissions "Allow GPT-3.5 and Claude for content generation, \
                 max $50/day budget, no PII data"

# Or with explicit options
policybind token create \
  --subject "data-science-team" \
  --models "gpt-4,claude-3-*" \
  --budget 100 \
  --budget-period daily \
  --expires 30
```

### Incident Management

Track and resolve policy violations:

```bash
# View incidents
policybind incident list --status open --severity high

# Generate incident report
policybind incident report inc_xyz789 --format pdf
```

### Compliance Reporting

Generate evidence for auditors:

```bash
# Compliance status report
policybind report compliance --framework eu-ai-act

# Export audit trail
policybind audit export --start 2024-01-01 --end 2024-01-31 --format json
```

## Installation

### Requirements

- Python 3.10 or higher
- SQLite 3.x (included with Python)

### Install from PyPI

```bash
pip install policybind
```

### Install from Source

```bash
git clone https://github.com/clay-good/policybind.git
cd policybind
pip install -e .
```

### Install with Server Support

```bash
pip install policybind[server]
```

### Verify Installation

```bash
policybind --version
policybind --help
```

## Quick Start

### 1. Initialize PolicyBind

```bash
# Create a new project
mkdir my-ai-governance
cd my-ai-governance

# Initialize PolicyBind
policybind init

# Check status
policybind status
```

### 2. Create Your First Policy

Create `policies/main.yaml`:

```yaml
name: my-first-policy
version: "1.0.0"
description: Basic AI governance policy

rules:
  - name: allow-approved-models
    description: Allow access to approved models
    match:
      model:
        in:
          - gpt-4
          - gpt-3.5-turbo
          - claude-3-sonnet
    action: ALLOW
    priority: 100

  - name: default-deny
    description: Deny all other requests
    action: DENY
    priority: 0
```

### 3. Load the Policy

```bash
policybind policy load policies/main.yaml
policybind policy show
```

### 4. Test Enforcement

```bash
# Test a request that should be allowed
policybind policy test policies/main.yaml \
  --request '{"provider": "openai", "model": "gpt-4"}'

# Test a request that should be denied
policybind policy test policies/main.yaml \
  --request '{"provider": "openai", "model": "davinci"}'
```

### 5. Use as a Library

```python
from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline
from policybind.models.request import AIRequest

# Load policy
parser = PolicyParser()
result = parser.parse_file("policies/main.yaml")
policy_set = result.policy_set

# Create pipeline
pipeline = EnforcementPipeline(policy_set)

# Enforce a request
request = AIRequest(
    provider="openai",
    model="gpt-4",
    user_id="user-123",
    department="engineering",
)

response = pipeline.process(request)

if response.is_allowed():
    print("Request allowed")
else:
    print(f"Request denied: {response.reason}")
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first steps |
| [Concepts](docs/concepts.md) | Core concepts and philosophy |
| [Policy Reference](docs/policy-reference.md) | Complete policy syntax |
| [Architecture](docs/architecture.md) | System design and components |
| [Deployment](docs/deployment.md) | Production deployment guide |
| [Security](docs/security.md) | Security model and best practices |
| [Performance](docs/performance.md) | Performance tuning and benchmarks |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [API Reference](docs/api-reference.md) | HTTP API documentation |
| [Integration Guide](docs/integration-guide.md) | SDK integration details |

## CLI Commands

| Command | Description |
|---------|-------------|
| `policybind init` | Initialize a new PolicyBind project |
| `policybind status` | Show system status |
| `policybind policy load` | Load a policy file |
| `policybind policy show` | Display current policies |
| `policybind policy validate` | Validate policy syntax |
| `policybind policy test` | Test policy against a request |
| `policybind registry list` | List registered deployments |
| `policybind registry register` | Register a new deployment |
| `policybind token create` | Create an access token |
| `policybind token list` | List all tokens |
| `policybind incident list` | List incidents |
| `policybind audit query` | Query audit logs |
| `policybind serve` | Start the HTTP server |

Run `policybind <command> --help` for detailed usage.

## Performance

PolicyBind is designed for production workloads:

| Metric | Target | Typical |
|--------|--------|---------|
| Matcher latency (P99) | < 1ms | 0.1-0.5ms |
| Pipeline latency (P99) | < 10ms | 1-5ms |
| Throughput | > 10,000 req/s | 20,000+ req/s |

See the [Performance Guide](docs/performance.md) for tuning recommendations.

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/clay-good/policybind.git
cd policybind

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=policybind

# Run specific test file
pytest tests/test_engine.py

# Run tests in parallel
pytest -n auto
```

### Code Quality

```bash
# Run linter
ruff check policybind/

# Run type checker
mypy policybind/

# Format code
ruff format policybind/
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Applications                           │
│  (OpenAI, Anthropic, Google, LangChain, etc.)              │
└────────────────────┬────────────────────────────────────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
    v                v                v
┌─────────────┐ ┌──────────────┐ ┌─────────┐
│ Python SDK  │ │  HTTP API    │ │   CLI   │
│ (wrappers)  │ │  (aiohttp)   │ │(argparse)│
└────────────┬┘ └──────────┬───┘ └────┬────┘
             │             │          │
             └─────────────┼──────────┘
                           v
                 ┌──────────────────────────┐
                 │   PolicyBind Core        │
                 │  (Enforcement Engine)    │
                 └──────┬───────────────────┘
                        │
        ┌───────┬───────┼───────┬────────┬──────────┐
        │       │       │       │        │          │
        v       v       v       v        v          v
    ┌──────┬────────┬──────┬────────┬────────┬──────────┐
    │Policy│ Model  │Token │Incident│ Audit  │ Reports  │
    │Engine│Registry│Manager│Manager│ Logger │Generator │
    └──────┴────────┴──────┴────────┴────────┴──────────┘
                        │
                        v
                 ┌──────────────────┐
                 │   SQLite DB      │
                 │   (WAL mode)     │
                 └──────────────────┘
```

## Project Structure

```
policybind/
├── engine/          # Policy parsing, matching, and execution
├── integrations/    # SDK wrappers for AI providers
├── models/          # Data models (Policy, Request, Response)
├── server/          # HTTP API (aiohttp-based)
├── cli/             # Command-line interface
├── storage/         # SQLite database layer
├── registry/        # Model deployment registry
├── tokens/          # Access token management
├── incidents/       # Incident tracking and workflows
├── reports/         # Compliance and audit reports
└── config/          # Configuration management
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linter (`ruff check policybind/`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

Please ensure all tests pass and code follows the project style guidelines.

## Security

PolicyBind is designed with security in mind:

- **Deny-by-default**: Requests without matching policies are denied
- **Token hashing**: Tokens are stored as hashes, never in plaintext
- **Parameterized queries**: All database queries use parameterization
- **Input validation**: All inputs are validated before processing
- **Audit logging**: Complete audit trail of all decisions

For security concerns, please see [SECURITY.md](docs/security.md) or contact the maintainers.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/clay-good/policybind/issues)
- **Discussions**: [GitHub Discussions](https://github.com/clay-good/policybind/discussions)

## Acknowledgments

PolicyBind is built on these excellent open-source projects:

- [PyYAML](https://pyyaml.org/) - YAML parsing
- [aiohttp](https://docs.aiohttp.org/) - Async HTTP server
- [pytest](https://pytest.org/) - Testing framework
