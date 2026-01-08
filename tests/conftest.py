"""
Pytest configuration and shared fixtures for PolicyBind tests.

This module provides:
- Database fixtures (fresh database, seeded with data)
- Configuration fixtures
- Component fixtures (managers, pipelines)
- Server fixtures for API tests
"""

from __future__ import annotations

import pytest
from typing import Generator
from unittest.mock import MagicMock

from policybind.config.schema import PolicyBindConfig
from policybind.storage.database import Database
from policybind.storage.repositories import (
    AuditRepository,
    IncidentRepository,
    RegistryRepository,
)
from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.models.policy import PolicySet
from policybind.tokens.manager import TokenManager
from policybind.incidents.manager import IncidentManager
from policybind.registry.manager import RegistryManager


# =============================================================================
# Database Fixtures
# =============================================================================


@pytest.fixture
def temp_db() -> Generator[Database, None, None]:
    """Create a temporary in-memory database for testing.

    Yields:
        Initialized Database instance.
    """
    db = Database(":memory:")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def fresh_db() -> Generator[Database, None, None]:
    """Create a fresh in-memory database (alias for temp_db).

    Yields:
        Initialized Database instance.
    """
    db = Database(":memory:")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def seeded_db(temp_db: Database) -> Database:
    """Create a database seeded with test data.

    Args:
        temp_db: Base temporary database.

    Returns:
        Database with seeded test data.
    """
    # Seed with basic test data using managers
    registry_repo = RegistryRepository(temp_db)
    registry_manager = RegistryManager(repository=registry_repo)

    # Add some test deployments
    for i in range(3):
        registry_manager.register(
            name=f"test-deployment-{i}",
            model_provider="openai",
            model_name="gpt-4",
            owner=f"team-{i}",
            owner_contact=f"team-{i}@example.com",
        )

    # Add some test incidents
    incident_repo = IncidentRepository(temp_db)
    incident_manager = IncidentManager(repository=incident_repo)

    from policybind.incidents.models import IncidentSeverity, IncidentType

    for i in range(5):
        incident_manager.create(
            title=f"Test Incident {i}",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

    return temp_db


# =============================================================================
# Configuration Fixtures
# =============================================================================


@pytest.fixture
def default_config() -> PolicyBindConfig:
    """Create a default PolicyBindConfig for testing.

    Returns:
        PolicyBindConfig with default values.
    """
    return PolicyBindConfig()


@pytest.fixture
def test_config() -> PolicyBindConfig:
    """Create a PolicyBindConfig configured for testing.

    Returns:
        PolicyBindConfig with test-appropriate settings.
    """
    return PolicyBindConfig(
        debug=True,
        log_level="DEBUG",
    )


# =============================================================================
# Policy Fixtures
# =============================================================================


@pytest.fixture
def simple_policy_yaml() -> str:
    """Return a simple policy YAML string for testing.

    Returns:
        YAML string defining a simple policy set.
    """
    return """
name: test-policy
version: "1.0.0"
description: Simple test policy

rules:
  - name: allow-gpt-models
    description: Allow GPT model access
    action: ALLOW
    priority: 100
    match_conditions:
      model:
        in:
          - gpt-4
          - gpt-3.5-turbo

  - name: deny-dall-e
    description: Deny DALL-E access
    action: DENY
    priority: 100
    match_conditions:
      model: dall-e-3
"""


@pytest.fixture
def complex_policy_yaml() -> str:
    """Return a complex policy YAML string for testing.

    Returns:
        YAML string defining a complex policy set with multiple rules.
    """
    return """
name: complex-test-policy
version: "1.0.0"
description: Complex test policy

rules:
  - name: deny-blocked-users
    description: Deny blocked users
    action: DENY
    priority: 200
    match_conditions:
      user_id:
        in:
          - blocked-user-1
          - blocked-user-2

  - name: allow-engineering
    description: Allow engineering department
    action: ALLOW
    priority: 100
    match_conditions:
      department: engineering

  - name: allow-research
    description: Allow research department with GPT-4
    action: ALLOW
    priority: 100
    match_conditions:
      department: research
      model: gpt-4

  - name: deny-marketing-expensive
    description: Deny marketing from expensive models
    action: DENY
    priority: 90
    match_conditions:
      department: marketing
      model:
        in:
          - gpt-4
          - claude-3-opus

  - name: allow-openai-default
    description: Default allow for OpenAI
    action: ALLOW
    priority: 10
    match_conditions:
      provider: openai
"""


@pytest.fixture
def policy_parser() -> PolicyParser:
    """Create a PolicyParser instance.

    Returns:
        PolicyParser instance.
    """
    return PolicyParser()


@pytest.fixture
def simple_policy_set(policy_parser: PolicyParser, simple_policy_yaml: str) -> PolicySet:
    """Create a simple PolicySet for testing.

    Args:
        policy_parser: Parser instance.
        simple_policy_yaml: YAML string.

    Returns:
        Parsed PolicySet.
    """
    result = policy_parser.parse_string(simple_policy_yaml)
    assert result.success, f"Failed to parse policy: {result.errors}"
    return result.policy_set


@pytest.fixture
def complex_policy_set(
    policy_parser: PolicyParser, complex_policy_yaml: str
) -> PolicySet:
    """Create a complex PolicySet for testing.

    Args:
        policy_parser: Parser instance.
        complex_policy_yaml: YAML string.

    Returns:
        Parsed PolicySet.
    """
    result = policy_parser.parse_string(complex_policy_yaml)
    assert result.success, f"Failed to parse policy: {result.errors}"
    return result.policy_set


# =============================================================================
# Pipeline Fixtures
# =============================================================================


@pytest.fixture
def pipeline_config() -> PipelineConfig:
    """Create a default PipelineConfig for testing.

    Returns:
        PipelineConfig with default values.
    """
    return PipelineConfig(
        enable_cost_tracking=True,
        enable_audit_logging=True,
    )


@pytest.fixture
def enforcement_pipeline(
    simple_policy_set: PolicySet,
    pipeline_config: PipelineConfig,
) -> EnforcementPipeline:
    """Create an EnforcementPipeline for testing.

    Args:
        simple_policy_set: Policy set to use.
        pipeline_config: Pipeline configuration.

    Returns:
        Configured EnforcementPipeline.
    """
    return EnforcementPipeline(
        policy_set=simple_policy_set,
        config=pipeline_config,
    )


@pytest.fixture
def enforcement_pipeline_with_audit(
    simple_policy_set: PolicySet,
    pipeline_config: PipelineConfig,
    temp_db: Database,
) -> EnforcementPipeline:
    """Create an EnforcementPipeline with audit logging.

    Args:
        simple_policy_set: Policy set to use.
        pipeline_config: Pipeline configuration.
        temp_db: Database for audit logging.

    Returns:
        Configured EnforcementPipeline with audit repository.
    """
    audit_repo = AuditRepository(temp_db)
    return EnforcementPipeline(
        policy_set=simple_policy_set,
        config=pipeline_config,
        audit_repository=audit_repo,
    )


# =============================================================================
# Manager Fixtures
# =============================================================================


@pytest.fixture
def token_manager() -> TokenManager:
    """Create a TokenManager for testing.

    Returns:
        TokenManager instance (in-memory).
    """
    return TokenManager()


@pytest.fixture
def incident_manager(temp_db: Database) -> IncidentManager:
    """Create an IncidentManager for testing.

    Args:
        temp_db: Database for persistence.

    Returns:
        IncidentManager instance.
    """
    repo = IncidentRepository(temp_db)
    return IncidentManager(repository=repo)


@pytest.fixture
def registry_manager(temp_db: Database) -> RegistryManager:
    """Create a RegistryManager for testing.

    Args:
        temp_db: Database for persistence.

    Returns:
        RegistryManager instance.
    """
    repo = RegistryRepository(temp_db)
    return RegistryManager(repository=repo)


@pytest.fixture
def registry_manager_inmemory() -> RegistryManager:
    """Create an in-memory RegistryManager for testing.

    Returns:
        RegistryManager instance without database backing.
    """
    return RegistryManager()


# =============================================================================
# Repository Fixtures
# =============================================================================


@pytest.fixture
def audit_repository(temp_db: Database) -> AuditRepository:
    """Create an AuditRepository for testing.

    Args:
        temp_db: Database for persistence.

    Returns:
        AuditRepository instance.
    """
    return AuditRepository(temp_db)


@pytest.fixture
def incident_repository(temp_db: Database) -> IncidentRepository:
    """Create an IncidentRepository for testing.

    Args:
        temp_db: Database for persistence.

    Returns:
        IncidentRepository instance.
    """
    return IncidentRepository(temp_db)


@pytest.fixture
def registry_repository(temp_db: Database) -> RegistryRepository:
    """Create a RegistryRepository for testing.

    Args:
        temp_db: Database for persistence.

    Returns:
        RegistryRepository instance.
    """
    return RegistryRepository(temp_db)


# =============================================================================
# Server/API Fixtures (for aiohttp tests)
# =============================================================================


# Note: These fixtures require aiohttp to be installed
# They are defined conditionally to avoid import errors


try:
    import aiohttp
    from aiohttp import web

    @pytest.fixture
    def app_config(
        simple_policy_set: PolicySet,
        temp_db: Database,
    ) -> dict:
        """Create application configuration dict for API testing.

        Args:
            simple_policy_set: Policy set to use.
            temp_db: Database for persistence.

        Returns:
            Dict with all app components.
        """
        pipeline_config = PipelineConfig(
            enable_cost_tracking=True,
            enable_audit_logging=True,
        )
        audit_repo = AuditRepository(temp_db)
        pipeline = EnforcementPipeline(
            policy_set=simple_policy_set,
            config=pipeline_config,
            audit_repository=audit_repo,
        )

        registry_repo = RegistryRepository(temp_db)
        incident_repo = IncidentRepository(temp_db)

        return {
            "config": PolicyBindConfig(),
            "pipeline": pipeline,
            "policy_set": simple_policy_set,
            "database": temp_db,
            "registry_manager": RegistryManager(repository=registry_repo),
            "token_manager": TokenManager(),
            "incident_manager": IncidentManager(repository=incident_repo),
            "audit_repository": audit_repo,
        }

    @pytest.fixture
    def test_app(app_config: dict) -> web.Application:
        """Create a test aiohttp Application.

        Args:
            app_config: Application configuration dict.

        Returns:
            Configured web.Application.
        """
        from policybind.server.handlers import (
            enforce_handlers,
            health_handlers,
            policy_handlers,
        )
        from policybind.server.middleware import (
            create_error_handler_middleware,
            create_request_id_middleware,
        )

        app = web.Application(
            middlewares=[
                create_request_id_middleware(),
                create_error_handler_middleware(),
            ]
        )

        # Add routes
        app.router.add_get("/v1/health", health_handlers.health_check)
        app.router.add_get("/v1/ready", health_handlers.readiness_check)
        app.router.add_post("/v1/enforce", enforce_handlers.enforce)
        app.router.add_get("/v1/policies", policy_handlers.list_policies)

        # Add components from config
        for key, value in app_config.items():
            app[key] = value

        return app

except ImportError:
    # aiohttp not installed, skip these fixtures
    pass


# =============================================================================
# Mock Fixtures
# =============================================================================


@pytest.fixture
def mock_notification_channel():
    """Create a mock notification channel.

    Returns:
        MagicMock configured as a notification channel.
    """
    from tests.helpers import MockNotificationChannel

    return MockNotificationChannel()


@pytest.fixture
def mock_event_handler():
    """Create a mock event handler.

    Returns:
        MockEventHandler instance.
    """
    from tests.helpers import MockEventHandler

    return MockEventHandler()


@pytest.fixture
def mock_database():
    """Create a mock database.

    Returns:
        MockDatabase instance.
    """
    from tests.helpers import MockDatabase

    db = MockDatabase()
    db.initialize()
    return db


# =============================================================================
# Markers Configuration
# =============================================================================


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "api: marks tests as API tests requiring aiohttp"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )
    config.addinivalue_line(
        "markers", "database: marks tests that require database access"
    )
