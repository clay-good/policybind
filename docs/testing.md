# PolicyBind Testing Guide

This document describes how to run tests, the test organization, how to add new tests, and coverage requirements for the PolicyBind project.

## Table of Contents

- [Quick Start](#quick-start)
- [Test Organization](#test-organization)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [Writing Tests](#writing-tests)
- [Test Utilities](#test-utilities)
- [Fixtures](#fixtures)
- [Coverage Requirements](#coverage-requirements)
- [CI/CD Integration](#cicd-integration)

## Quick Start

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=policybind --cov-report=html

# Run specific test file
pytest tests/unit/test_models.py

# Run specific test class
pytest tests/unit/test_models.py::TestPolicyRule

# Run specific test
pytest tests/unit/test_models.py::TestPolicyRule::test_rule_creation

# Run tests matching a pattern
pytest -k "token"

# Run tests with markers
pytest -m "unit"
pytest -m "integration"
pytest -m "not slow"
```

## Test Organization

The test suite is organized into the following structure:

```
tests/
├── conftest.py              # Shared fixtures and pytest configuration
├── helpers.py               # Test utilities and factory functions
├── fixtures/                # Sample test data files
│   ├── __init__.py
│   ├── policies/           # Sample policy YAML files
│   ├── requests/           # Sample request JSON files
│   └── registry/           # Sample registry entries
├── unit/                    # Unit tests
│   ├── test_models.py
│   ├── test_parser.py
│   ├── test_pipeline.py
│   ├── test_tokens.py
│   ├── test_incidents.py
│   └── test_registry.py
└── integration/             # Integration tests
    ├── test_api_server.py
    ├── test_full_pipeline.py
    └── scenarios/           # Complex test scenarios
        ├── test_concurrent_access.py
        ├── test_high_volume.py
        └── test_multi_policy.py
```

### Unit Tests (`tests/unit/`)

Unit tests focus on testing individual components in isolation:

- **test_models.py**: Domain model tests (PolicyRule, PolicySet, AIRequest, etc.)
- **test_parser.py**: Policy YAML parser tests
- **test_pipeline.py**: Enforcement pipeline tests
- **test_tokens.py**: Token management tests
- **test_incidents.py**: Incident management tests
- **test_registry.py**: Model registry tests

### Integration Tests (`tests/integration/`)

Integration tests verify that components work together:

- **test_api_server.py**: HTTP API endpoint tests
- **test_full_pipeline.py**: End-to-end pipeline tests
- **scenarios/**: Complex multi-component test scenarios

## Running Tests

### Basic Commands

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with very verbose output (shows individual test names)
pytest -vv

# Stop on first failure
pytest -x

# Run last failed tests first
pytest --lf

# Run only failed tests from last run
pytest --ff
```

### Coverage

```bash
# Run with coverage report in terminal
pytest --cov=policybind

# Generate HTML coverage report
pytest --cov=policybind --cov-report=html

# Generate XML coverage report (for CI)
pytest --cov=policybind --cov-report=xml

# Fail if coverage is below threshold
pytest --cov=policybind --cov-fail-under=80
```

### Parallel Execution

```bash
# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Run with specific number of workers
pytest -n 4
```

### Filtering Tests

```bash
# Run tests matching keyword
pytest -k "token"
pytest -k "token and not revoke"

# Run tests with specific marker
pytest -m unit
pytest -m integration
pytest -m "not slow"

# Run tests in specific directory
pytest tests/unit/
pytest tests/integration/
```

## Test Categories

Tests are categorized using pytest markers:

| Marker | Description |
|--------|-------------|
| `@pytest.mark.unit` | Unit tests (fast, isolated) |
| `@pytest.mark.integration` | Integration tests |
| `@pytest.mark.api` | API/HTTP tests (require aiohttp) |
| `@pytest.mark.slow` | Slow tests (>1s) |
| `@pytest.mark.performance` | Performance/benchmark tests |
| `@pytest.mark.database` | Tests requiring database |

Example usage:

```python
import pytest

@pytest.mark.unit
def test_something_fast():
    pass

@pytest.mark.integration
@pytest.mark.slow
def test_full_workflow():
    pass
```

## Writing Tests

### Test Structure

Follow the Arrange-Act-Assert pattern:

```python
def test_something():
    # Arrange - Set up test data
    request = RequestFactory.create_request(model="gpt-4")

    # Act - Execute the code under test
    result = pipeline.process(request)

    # Assert - Verify the results
    assert result.decision == Decision.ALLOW
```

### Naming Conventions

- Test files: `test_<module>.py`
- Test classes: `Test<Component>`
- Test functions: `test_<behavior>` or `test_<scenario>_<expected_result>`

```python
# Good examples
def test_token_creation():
    pass

def test_expired_token_returns_invalid():
    pass

def test_concurrent_requests_thread_safe():
    pass
```

### Using Fixtures

```python
def test_with_database(temp_db):
    """Test using temporary database fixture."""
    # temp_db is automatically provided by conftest.py
    repo = AuditRepository(temp_db)
    # ...

def test_with_pipeline(enforcement_pipeline):
    """Test using pipeline fixture."""
    result = enforcement_pipeline.process(request)
    # ...
```

### Using Factory Functions

```python
from tests.helpers import RequestFactory, PolicyFactory, AssertHelpers

def test_enforcement():
    # Create test data with factories
    request = RequestFactory.create_request(
        provider="openai",
        model="gpt-4",
        department="engineering",
    )

    policy = PolicyFactory.create_allow_all_policy()
    pipeline = EnforcementPipeline(policy)

    result = pipeline.process(request)

    # Use assertion helpers
    AssertHelpers.assert_allowed(result)
```

### Async Tests

For testing async code (API handlers):

```python
import pytest

@pytest.mark.asyncio
async def test_api_endpoint(aiohttp_client, test_app):
    client = await aiohttp_client(test_app)
    resp = await client.get("/v1/health")
    assert resp.status == 200
```

## Test Utilities

### Factory Classes

Located in `tests/helpers.py`:

| Factory | Purpose |
|---------|---------|
| `PolicyFactory` | Create PolicyRule, PolicySet objects |
| `RequestFactory` | Create AIRequest, AIResponse objects |
| `RegistryFactory` | Create ModelDeployment objects |
| `TokenFactory` | Create Token, TokenPermissions objects |
| `IncidentFactory` | Create Incident, IncidentComment objects |

### Assertion Helpers

```python
from tests.helpers import AssertHelpers

# Decision assertions
AssertHelpers.assert_allowed(response)
AssertHelpers.assert_denied(response)
AssertHelpers.assert_decision(response, Decision.ALLOW)

# Rule assertions
AssertHelpers.assert_rule_applied(response, "allow-gpt4")
AssertHelpers.assert_no_rule_applied(response, "deny-all")

# Performance assertions
AssertHelpers.assert_enforcement_time_under(response, max_ms=10)

# Status assertions
AssertHelpers.assert_token_status(token, TokenStatus.ACTIVE)
AssertHelpers.assert_incident_status(incident, IncidentStatus.OPEN)
```

### Timing Utilities

```python
from tests.helpers import timer, time_function, benchmark

# Context manager
with timer() as t:
    result = expensive_operation()
print(f"Took {t['elapsed_ms']}ms")

# Function timing
result, timing = time_function(lambda: pipeline.process(request), iterations=100)
print(f"Average: {timing.avg_ms_per_iteration}ms")

# Benchmarking
timing = benchmark(
    func=lambda: pipeline.process(request),
    warmup_iterations=10,
    benchmark_iterations=1000,
)
print(timing)
```

### Mock Implementations

```python
from tests.helpers import MockNotificationChannel, MockEventHandler, MockDatabase

# Mock notification channel
channel = MockNotificationChannel()
channel.send("user@example.com", "Subject", "Body")
assert len(channel.notifications) == 1

# Mock event handler
handler = MockEventHandler()
manager.on_token_event(handler)
# ... create tokens ...
assert len(handler.events) > 0

# Mock database
db = MockDatabase()
db.initialize()
```

### Data Generators

```python
from tests.helpers import generate_test_requests, generate_test_tokens, generate_test_incidents

# Generate many requests
requests = generate_test_requests(
    count=100,
    providers=["openai", "anthropic"],
    models=["gpt-4", "claude-3"],
)

# Generate tokens
tokens = generate_test_tokens(count=50, status=TokenStatus.ACTIVE)

# Generate incidents with severity distribution
incidents = generate_test_incidents(
    count=20,
    severity_distribution={
        IncidentSeverity.LOW: 10,
        IncidentSeverity.MEDIUM: 6,
        IncidentSeverity.HIGH: 3,
        IncidentSeverity.CRITICAL: 1,
    }
)
```

## Fixtures

### Available Fixtures

Defined in `tests/conftest.py`:

| Fixture | Description |
|---------|-------------|
| `temp_db` | Fresh in-memory SQLite database |
| `seeded_db` | Database with sample test data |
| `default_config` | Default PolicyBindConfig |
| `simple_policy_yaml` | Simple policy YAML string |
| `complex_policy_yaml` | Complex policy YAML string |
| `simple_policy_set` | Parsed simple PolicySet |
| `complex_policy_set` | Parsed complex PolicySet |
| `pipeline_config` | Default PipelineConfig |
| `enforcement_pipeline` | Configured EnforcementPipeline |
| `token_manager` | TokenManager instance |
| `incident_manager` | IncidentManager with database |
| `registry_manager` | RegistryManager with database |

### Sample Data Files

Located in `tests/fixtures/`:

```python
from tests.fixtures import load_policy_yaml, load_sample_requests, load_registry_entries

# Load policy YAML
policy_yaml = load_policy_yaml("basic_policy.yaml")

# Load sample requests
requests = load_sample_requests("basic_requests.json")

# Load registry entries
deployments = load_registry_entries("sample_deployments.json")
```

## Coverage Requirements

### Minimum Coverage

The project requires minimum test coverage of **80%** overall:

| Category | Minimum Coverage |
|----------|-----------------|
| Overall | 80% |
| Critical paths | 90% |
| API handlers | 85% |
| Core models | 95% |

### Checking Coverage

```bash
# Check coverage with threshold
pytest --cov=policybind --cov-fail-under=80

# View detailed coverage report
pytest --cov=policybind --cov-report=html
open htmlcov/index.html
```

### Excluding from Coverage

Add to `pyproject.toml` or `.coveragerc`:

```ini
[coverage:run]
omit =
    tests/*
    */__init__.py

[coverage:report]
exclude_lines =
    pragma: no cover
    if TYPE_CHECKING:
    raise NotImplementedError
```

## CI/CD Integration

### GitHub Actions

Tests run automatically on:
- Push to `main` branch
- Pull requests to `main`
- Manual workflow dispatch

The CI pipeline:
1. Runs linting (ruff)
2. Runs type checking (mypy)
3. Runs tests on Python 3.10, 3.11, 3.12
4. Generates coverage report
5. Uploads coverage to Codecov (if configured)

### Running Locally Like CI

```bash
# Full CI-like run
ruff check .
mypy policybind
pytest --cov=policybind --cov-report=xml --cov-fail-under=80
```

### Pre-commit Hooks

Install pre-commit hooks to run tests before commits:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```
