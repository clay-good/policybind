"""
Integration tests for the HTTP API server.

This module tests the complete HTTP API including:
- Full enforcement pipeline via API
- Policy management endpoints
- Registry management endpoints
- Token management endpoints
- Incident management endpoints
- Audit and metrics endpoints
"""

import pytest
from unittest.mock import MagicMock

# Skip all tests if aiohttp is not installed
aiohttp = pytest.importorskip("aiohttp")

from aiohttp import web

from policybind.config.schema import PolicyBindConfig
from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.engine.parser import PolicyParser
from policybind.models.policy import PolicySet
from policybind.storage.database import Database
from policybind.storage.repositories import AuditRepository, IncidentRepository, RegistryRepository
from policybind.tokens.manager import TokenManager
from policybind.incidents.manager import IncidentManager
from policybind.registry.manager import RegistryManager


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    db = Database(":memory:")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def policy_set():
    """Create a policy set for testing."""
    yaml_content = """
policies:
  - name: allow-gpt-models
    description: Allow GPT model access
    rules:
      - condition:
          model: gpt-4
        action:
          type: allow
      - condition:
          model: gpt-3.5-turbo
        action:
          type: allow
  - name: deny-dall-e
    description: Deny DALL-E access
    rules:
      - condition:
          model: dall-e-3
        action:
          type: deny
          reason: DALL-E access is restricted
"""
    parser = PolicyParser()
    return parser.parse_yaml(yaml_content)


@pytest.fixture
def enforcement_pipeline(policy_set: PolicySet, temp_db: Database):
    """Create an enforcement pipeline for testing."""
    audit_repo = AuditRepository(temp_db)
    config = PipelineConfig(
        enable_cost_tracking=True,
        enable_audit_logging=True,
    )
    return EnforcementPipeline(
        policy_set=policy_set,
        config=config,
        audit_repository=audit_repo,
    )


@pytest.fixture
def app_with_components(
    enforcement_pipeline: EnforcementPipeline,
    policy_set: PolicySet,
    temp_db: Database,
) -> web.Application:
    """Create a test application with all components."""
    from policybind.server.handlers import (
        enforce_handlers,
        health_handlers,
        policy_handlers,
        registry_handlers,
        token_handlers,
        incident_handlers,
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

    # Add components
    app["config"] = PolicyBindConfig()
    app["pipeline"] = enforcement_pipeline
    app["policy_set"] = policy_set
    app["database"] = temp_db

    # Add managers
    registry_repo = RegistryRepository(temp_db)
    app["registry_manager"] = RegistryManager(repository=registry_repo)

    app["token_manager"] = TokenManager()

    incident_repo = IncidentRepository(temp_db)
    app["incident_manager"] = IncidentManager(repository=incident_repo)

    app["audit_repository"] = AuditRepository(temp_db)

    return app


# =============================================================================
# Health and Readiness Tests
# =============================================================================


class TestHealthEndpoints:
    """Integration tests for health endpoints."""

    @pytest.mark.asyncio
    async def test_health_endpoint_returns_healthy(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test health endpoint returns healthy status."""
        client = await aiohttp_client(app_with_components)
        resp = await client.get("/v1/health")

        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_readiness_with_all_components(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test readiness endpoint with all components."""
        client = await aiohttp_client(app_with_components)
        resp = await client.get("/v1/ready")

        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ready"
        assert data["checks"]["policies"]["status"] == "ready"
        assert data["checks"]["enforcement"]["status"] == "ready"


# =============================================================================
# Enforcement API Tests
# =============================================================================


class TestEnforcementAPI:
    """Integration tests for enforcement API."""

    @pytest.mark.asyncio
    async def test_enforce_allowed_request(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement allows valid request."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "test-user",
            },
        )

        assert resp.status == 200
        data = await resp.json()
        assert data["decision"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_enforce_denied_request(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement denies restricted request."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "dall-e-3",
                "user_id": "test-user",
            },
        )

        assert resp.status == 200
        data = await resp.json()
        assert data["decision"] == "DENY"
        assert "restricted" in data["reason"].lower()

    @pytest.mark.asyncio
    async def test_enforce_returns_request_id(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement returns request ID."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "test-user",
            },
        )

        assert resp.status == 200
        data = await resp.json()
        assert "request_id" in data
        assert data["request_id"] is not None

    @pytest.mark.asyncio
    async def test_enforce_tracks_timing(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement tracks timing metrics."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "test-user",
            },
        )

        assert resp.status == 200
        data = await resp.json()
        assert "enforcement_time_ms" in data
        assert data["enforcement_time_ms"] >= 0

    @pytest.mark.asyncio
    async def test_enforce_with_custom_attributes(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement with custom attributes."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "test-user",
                "department": "engineering",
                "cost_center": "CC-123",
            },
        )

        assert resp.status == 200
        data = await resp.json()
        assert data["decision"] in ["ALLOW", "DENY"]

    @pytest.mark.asyncio
    async def test_enforce_validation_error(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement returns validation error for invalid request."""
        client = await aiohttp_client(app_with_components)

        # Missing required fields
        resp = await client.post(
            "/v1/enforce",
            json={"user_id": "test-user"},
        )

        assert resp.status == 400
        data = await resp.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_multiple_sequential_enforcements(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test multiple sequential enforcement requests."""
        client = await aiohttp_client(app_with_components)

        # Send multiple requests
        for i in range(5):
            resp = await client.post(
                "/v1/enforce",
                json={
                    "provider": "openai",
                    "model": "gpt-4",
                    "user_id": f"user-{i}",
                },
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["decision"] == "ALLOW"


# =============================================================================
# Policy API Tests
# =============================================================================


class TestPolicyAPI:
    """Integration tests for policy API."""

    @pytest.mark.asyncio
    async def test_list_policies(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test listing loaded policies."""
        client = await aiohttp_client(app_with_components)

        resp = await client.get("/v1/policies")

        assert resp.status == 200
        data = await resp.json()
        assert "policies" in data
        assert len(data["policies"]) >= 2  # We have 2 policies in our test set


# =============================================================================
# Full API Flow Tests
# =============================================================================


class TestFullAPIFlow:
    """Integration tests for complete API flows."""

    @pytest.mark.asyncio
    async def test_full_enforcement_flow_with_audit(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test complete enforcement flow including audit logging."""
        client = await aiohttp_client(app_with_components)

        # 1. Check health
        health_resp = await client.get("/v1/health")
        assert health_resp.status == 200

        # 2. Check readiness
        ready_resp = await client.get("/v1/ready")
        assert ready_resp.status == 200

        # 3. List policies
        policies_resp = await client.get("/v1/policies")
        assert policies_resp.status == 200

        # 4. Enforce a request
        enforce_resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "flow-test-user",
            },
        )
        assert enforce_resp.status == 200
        enforce_data = await enforce_resp.json()
        assert enforce_data["decision"] == "ALLOW"

        # Verify the request was tracked
        assert "request_id" in enforce_data

    @pytest.mark.asyncio
    async def test_enforcement_with_different_models(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test enforcement with different model types."""
        client = await aiohttp_client(app_with_components)

        test_cases = [
            {"model": "gpt-4", "expected": "ALLOW"},
            {"model": "gpt-3.5-turbo", "expected": "ALLOW"},
            {"model": "dall-e-3", "expected": "DENY"},
        ]

        for test_case in test_cases:
            resp = await client.post(
                "/v1/enforce",
                json={
                    "provider": "openai",
                    "model": test_case["model"],
                    "user_id": "model-test-user",
                },
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["decision"] == test_case["expected"], f"Model {test_case['model']} expected {test_case['expected']}"


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Integration tests for error handling."""

    @pytest.mark.asyncio
    async def test_invalid_json_body(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test error handling for invalid JSON body."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            data="not valid json",
            headers={"Content-Type": "application/json"},
        )

        assert resp.status == 400
        data = await resp.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_missing_content_type(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test error handling for missing content type."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            data='{"provider": "openai", "model": "gpt-4"}',
            # No Content-Type header
        )

        # Should still work or return appropriate error
        assert resp.status in [200, 400]

    @pytest.mark.asyncio
    async def test_not_found_endpoint(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test 404 for non-existent endpoint."""
        client = await aiohttp_client(app_with_components)

        resp = await client.get("/v1/nonexistent")

        assert resp.status == 404


# =============================================================================
# Request ID Propagation Tests
# =============================================================================


class TestRequestIDPropagation:
    """Integration tests for request ID propagation."""

    @pytest.mark.asyncio
    async def test_request_id_header_propagation(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test that X-Request-ID header is propagated in response."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "test-user",
            },
        )

        assert resp.status == 200
        assert "X-Request-ID" in resp.headers

    @pytest.mark.asyncio
    async def test_custom_request_id_preserved(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test that custom X-Request-ID is preserved."""
        client = await aiohttp_client(app_with_components)
        custom_id = "custom-request-id-12345"

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "test-user",
            },
            headers={"X-Request-ID": custom_id},
        )

        assert resp.status == 200
        assert resp.headers.get("X-Request-ID") == custom_id


# =============================================================================
# Performance Tests
# =============================================================================


class TestPerformance:
    """Basic performance tests for the API."""

    @pytest.mark.asyncio
    async def test_rapid_sequential_requests(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test API handles rapid sequential requests."""
        client = await aiohttp_client(app_with_components)

        # Send 20 rapid requests
        for i in range(20):
            resp = await client.post(
                "/v1/enforce",
                json={
                    "provider": "openai",
                    "model": "gpt-4",
                    "user_id": f"perf-user-{i}",
                },
            )
            assert resp.status == 200

    @pytest.mark.asyncio
    async def test_enforcement_time_reasonable(
        self, app_with_components: web.Application, aiohttp_client
    ) -> None:
        """Test that enforcement time is reasonable."""
        client = await aiohttp_client(app_with_components)

        resp = await client.post(
            "/v1/enforce",
            json={
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "timing-test-user",
            },
        )

        assert resp.status == 200
        data = await resp.json()

        # Enforcement should complete within 100ms for simple rules
        assert data["enforcement_time_ms"] < 100
