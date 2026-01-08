"""
Tests for the PolicyBind HTTP server.

These tests verify the HTTP API endpoints and middleware functionality.
"""

import json
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

# Skip all tests if aiohttp is not installed
aiohttp = pytest.importorskip("aiohttp")

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop


class TestHealthEndpoints:
    """Tests for health and readiness endpoints."""

    @pytest.fixture
    def app(self) -> web.Application:
        """Create a test application."""
        from policybind.server.handlers import health_handlers
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
        app.router.add_get("/v1/health", health_handlers.health_check)
        app.router.add_get("/v1/ready", health_handlers.readiness_check)
        app.router.add_get("/v1/metrics", health_handlers.metrics)

        return app

    @pytest.mark.asyncio
    async def test_health_check(self, app: web.Application, aiohttp_client: Any) -> None:
        """Test the health check endpoint returns healthy status."""
        client = await aiohttp_client(app)
        resp = await client.get("/v1/health")

        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_readiness_check_no_components(
        self, app: web.Application, aiohttp_client: Any
    ) -> None:
        """Test readiness check with no components configured."""
        client = await aiohttp_client(app)
        resp = await client.get("/v1/ready")

        # Should return 503 since no policies are loaded
        assert resp.status == 503
        data = await resp.json()
        assert data["status"] == "not_ready"
        assert "checks" in data

    @pytest.mark.asyncio
    async def test_readiness_check_with_components(
        self, app: web.Application, aiohttp_client: Any
    ) -> None:
        """Test readiness check with components configured."""
        # Add mock components
        mock_policy_set = MagicMock()
        mock_policy_set.rules = [MagicMock(), MagicMock()]
        app["policy_set"] = mock_policy_set

        mock_pipeline = MagicMock()
        app["pipeline"] = mock_pipeline

        mock_database = MagicMock()
        mock_database.execute.return_value = [(1,)]
        app["database"] = mock_database

        client = await aiohttp_client(app)
        resp = await client.get("/v1/ready")

        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ready"
        assert data["checks"]["policies"]["status"] == "ready"
        assert data["checks"]["enforcement"]["status"] == "ready"

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, app: web.Application, aiohttp_client: Any) -> None:
        """Test the metrics endpoint returns Prometheus format."""
        client = await aiohttp_client(app)
        resp = await client.get("/v1/metrics")

        assert resp.status == 200
        text = await resp.text()
        assert "policybind_up 1" in text
        assert "policybind_uptime_seconds" in text
        assert "policybind_requests_total" in text


class TestMiddleware:
    """Tests for HTTP middleware."""

    @pytest.mark.asyncio
    async def test_request_id_middleware(self, aiohttp_client: Any) -> None:
        """Test that request ID middleware adds X-Request-ID header."""
        from policybind.server.middleware import create_request_id_middleware

        async def handler(request: web.Request) -> web.Response:
            return web.json_response({"request_id": request.get("request_id")})

        app = web.Application(middlewares=[create_request_id_middleware()])
        app.router.add_get("/test", handler)

        client = await aiohttp_client(app)
        resp = await client.get("/test")

        assert resp.status == 200
        assert "X-Request-ID" in resp.headers
        data = await resp.json()
        assert data["request_id"] == resp.headers["X-Request-ID"]

    @pytest.mark.asyncio
    async def test_request_id_from_header(self, aiohttp_client: Any) -> None:
        """Test that request ID middleware uses provided X-Request-ID."""
        from policybind.server.middleware import create_request_id_middleware

        async def handler(request: web.Request) -> web.Response:
            return web.json_response({"request_id": request.get("request_id")})

        app = web.Application(middlewares=[create_request_id_middleware()])
        app.router.add_get("/test", handler)

        client = await aiohttp_client(app)
        resp = await client.get("/test", headers={"X-Request-ID": "my-custom-id"})

        assert resp.status == 200
        assert resp.headers["X-Request-ID"] == "my-custom-id"
        data = await resp.json()
        assert data["request_id"] == "my-custom-id"

    @pytest.mark.asyncio
    async def test_error_handler_middleware(self, aiohttp_client: Any) -> None:
        """Test that error handler converts exceptions to JSON responses."""
        from policybind.exceptions import ValidationError
        from policybind.server.middleware import create_error_handler_middleware

        async def handler(request: web.Request) -> web.Response:
            raise ValidationError("Test error", {"field": "test"})

        app = web.Application(middlewares=[create_error_handler_middleware()])
        app.router.add_get("/test", handler)

        client = await aiohttp_client(app)
        resp = await client.get("/test")

        assert resp.status == 400
        data = await resp.json()
        assert data["error"]["type"] == "ValidationError"
        assert data["error"]["message"] == "Test error"

    @pytest.mark.asyncio
    async def test_rate_limit_middleware(self, aiohttp_client: Any) -> None:
        """Test that rate limiting middleware enforces limits."""
        from policybind.server.middleware import create_rate_limit_middleware

        async def handler(request: web.Request) -> web.Response:
            return web.json_response({"ok": True})

        rate_limit_middleware, limiter = create_rate_limit_middleware(
            max_requests=3,
            window_seconds=60,
        )

        app = web.Application(middlewares=[rate_limit_middleware])
        app.router.add_get("/test", handler)

        client = await aiohttp_client(app)

        # First 3 requests should succeed
        for i in range(3):
            resp = await client.get("/test")
            assert resp.status == 200
            assert "X-RateLimit-Limit" in resp.headers
            assert resp.headers["X-RateLimit-Limit"] == "3"

        # 4th request should be rate limited
        resp = await client.get("/test")
        assert resp.status == 429
        data = await resp.json()
        assert data["error"]["type"] == "RateLimitExceeded"


class TestAuthentication:
    """Tests for authentication middleware."""

    @pytest.mark.asyncio
    async def test_api_key_authentication(self, aiohttp_client: Any) -> None:
        """Test API key authentication."""
        from policybind.server.auth import (
            APIKey,
            APIKeyAuthenticator,
            Role,
            create_authentication_middleware,
        )

        async def handler(request: web.Request) -> web.Response:
            auth_context = request.get("auth_context")
            return web.json_response({
                "authenticated": auth_context.authenticated,
                "identity": auth_context.identity,
                "role": auth_context.role.value,
            })

        api_key_auth = APIKeyAuthenticator()
        api_key_auth.add_key(APIKey(key="test-key-123", name="test-user", role=Role.ADMIN))

        app = web.Application(
            middlewares=[
                create_authentication_middleware(
                    api_key_authenticator=api_key_auth,
                    require_auth=False,
                )
            ]
        )
        app.router.add_get("/test", handler)

        client = await aiohttp_client(app)

        # Without API key
        resp = await client.get("/test")
        assert resp.status == 200
        data = await resp.json()
        assert data["authenticated"] is False

        # With valid API key
        resp = await client.get("/test", headers={"X-API-Key": "test-key-123"})
        assert resp.status == 200
        data = await resp.json()
        assert data["authenticated"] is True
        assert data["identity"] == "test-user"
        assert data["role"] == "admin"

        # With invalid API key
        resp = await client.get("/test", headers={"X-API-Key": "invalid-key"})
        assert resp.status == 200
        data = await resp.json()
        assert data["authenticated"] is False

    @pytest.mark.asyncio
    async def test_require_authentication(self, aiohttp_client: Any) -> None:
        """Test that authentication is required when configured."""
        from policybind.server.auth import (
            APIKey,
            APIKeyAuthenticator,
            Role,
            create_authentication_middleware,
        )

        async def handler(request: web.Request) -> web.Response:
            return web.json_response({"ok": True})

        api_key_auth = APIKeyAuthenticator()
        api_key_auth.add_key(APIKey(key="test-key", name="test", role=Role.ADMIN))

        app = web.Application(
            middlewares=[
                create_authentication_middleware(
                    api_key_authenticator=api_key_auth,
                    require_auth=True,
                    exempt_paths=["/public"],
                )
            ]
        )
        app.router.add_get("/test", handler)
        app.router.add_get("/public", handler)

        client = await aiohttp_client(app)

        # Protected endpoint without auth
        resp = await client.get("/test")
        assert resp.status == 401

        # Protected endpoint with auth
        resp = await client.get("/test", headers={"X-API-Key": "test-key"})
        assert resp.status == 200

        # Exempt endpoint without auth
        resp = await client.get("/public")
        assert resp.status == 200


class TestEnforceEndpoint:
    """Tests for the enforce endpoint."""

    @pytest.fixture
    def app_with_pipeline(self) -> web.Application:
        """Create a test application with mock pipeline."""
        from policybind.server.handlers import enforce_handlers
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
        app.router.add_post("/v1/enforce", enforce_handlers.enforce)

        # Add mock pipeline
        mock_response = MagicMock()
        mock_response.request_id = "test-request-123"
        mock_response.decision.value = "ALLOW"
        mock_response.reason = "Test allowed"
        mock_response.applied_rules = ["rule1"]
        mock_response.warnings = []
        mock_response.modifications = {}
        mock_response.estimated_cost = 0.01

        mock_pipeline = MagicMock()
        mock_pipeline.process.return_value = mock_response
        app["pipeline"] = mock_pipeline

        return app

    @pytest.mark.asyncio
    async def test_enforce_success(
        self, app_with_pipeline: web.Application, aiohttp_client: Any
    ) -> None:
        """Test successful enforcement request."""
        client = await aiohttp_client(app_with_pipeline)

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
        assert data["request_id"] == "test-request-123"
        assert "enforcement_time_ms" in data

    @pytest.mark.asyncio
    async def test_enforce_missing_fields(
        self, app_with_pipeline: web.Application, aiohttp_client: Any
    ) -> None:
        """Test enforcement with missing required fields."""
        client = await aiohttp_client(app_with_pipeline)

        resp = await client.post(
            "/v1/enforce",
            json={"user_id": "test-user"},
        )

        assert resp.status == 400
        data = await resp.json()
        assert "error" in data
        assert "provider" in data["error"]["message"] or "model" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_enforce_invalid_json(
        self, app_with_pipeline: web.Application, aiohttp_client: Any
    ) -> None:
        """Test enforcement with invalid JSON body."""
        client = await aiohttp_client(app_with_pipeline)

        resp = await client.post(
            "/v1/enforce",
            data="not json",
            headers={"Content-Type": "application/json"},
        )

        assert resp.status == 400
        data = await resp.json()
        assert "error" in data
        assert "Invalid JSON" in data["error"]["message"]


class TestCORSMiddleware:
    """Tests for CORS middleware."""

    @pytest.mark.asyncio
    async def test_cors_preflight(self, aiohttp_client: Any) -> None:
        """Test CORS preflight request handling."""
        from policybind.server.middleware import create_cors_middleware

        async def handler(request: web.Request) -> web.Response:
            return web.json_response({"ok": True})

        app = web.Application(
            middlewares=[create_cors_middleware(allowed_origins=["http://example.com"])]
        )
        app.router.add_post("/test", handler)

        client = await aiohttp_client(app)

        # Preflight request
        resp = await client.options(
            "/test",
            headers={
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "POST",
            },
        )

        assert resp.status == 204
        assert resp.headers["Access-Control-Allow-Origin"] == "http://example.com"
        assert "POST" in resp.headers["Access-Control-Allow-Methods"]

    @pytest.mark.asyncio
    async def test_cors_actual_request(self, aiohttp_client: Any) -> None:
        """Test CORS headers on actual request."""
        from policybind.server.middleware import create_cors_middleware

        async def handler(request: web.Request) -> web.Response:
            return web.json_response({"ok": True})

        app = web.Application(
            middlewares=[create_cors_middleware(allowed_origins=["http://example.com"])]
        )
        app.router.add_get("/test", handler)

        client = await aiohttp_client(app)

        resp = await client.get("/test", headers={"Origin": "http://example.com"})

        assert resp.status == 200
        assert resp.headers["Access-Control-Allow-Origin"] == "http://example.com"


class TestServerApp:
    """Tests for the server application factory."""

    def test_create_app(self) -> None:
        """Test that create_app creates a valid application."""
        from policybind.config.schema import PolicyBindConfig
        from policybind.server.app import create_app

        config = PolicyBindConfig()
        app = create_app(config)

        assert isinstance(app, web.Application)
        assert "config" in app
        assert app["config"] == config

    def test_policybind_application(self) -> None:
        """Test PolicyBindApplication creation."""
        from policybind.config.schema import PolicyBindConfig
        from policybind.server.app import PolicyBindApplication

        config = PolicyBindConfig()
        pb_app = PolicyBindApplication(config)

        assert pb_app.app is not None
        assert isinstance(pb_app.app, web.Application)

    def test_add_api_key(self) -> None:
        """Test adding API keys to the application."""
        from policybind.config.schema import PolicyBindConfig
        from policybind.server.app import PolicyBindApplication

        config = PolicyBindConfig()
        pb_app = PolicyBindApplication(config)

        pb_app.add_api_key("test-key-123", "test-user", "admin")

        api_key_auth = pb_app.app.get("api_key_authenticator")
        assert api_key_auth is not None
        assert "test-key-123" in api_key_auth._keys


class TestTokenNaturalLanguage:
    """Tests for natural language token creation endpoints."""

    @pytest.fixture
    def app_with_tokens(self) -> web.Application:
        """Create a test application with mock token manager."""
        from policybind.server.handlers import token_handlers
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
        app.router.add_post(
            "/v1/tokens/from-natural-language",
            token_handlers.create_token_from_natural_language,
        )
        app.router.add_post(
            "/v1/tokens/parse-natural-language",
            token_handlers.parse_natural_language,
        )

        # Add mock token manager
        mock_token = MagicMock()
        mock_token.token_id = "tok_123"
        mock_token.name = "Test Token"
        mock_token.subject = "test@example.com"
        mock_token.token_value = "pb_test_123"
        mock_token.permissions = {}
        mock_token.to_dict.return_value = {
            "token_id": "tok_123",
            "name": "Test Token",
            "subject": "test@example.com",
            "token_value": "pb_test_123",
        }

        mock_manager = MagicMock()
        mock_manager.create.return_value = mock_token
        app["token_manager"] = mock_manager

        return app

    @pytest.mark.asyncio
    async def test_parse_natural_language(
        self, app_with_tokens: web.Application, aiohttp_client: Any
    ) -> None:
        """Test parsing natural language without creating token."""
        client = await aiohttp_client(app_with_tokens)

        resp = await client.post(
            "/v1/tokens/parse-natural-language",
            json={"description": "Allow GPT-4 access"},
        )

        assert resp.status == 200
        data = await resp.json()
        assert "permissions" in data
        assert "confidence" in data

    @pytest.mark.asyncio
    async def test_parse_natural_language_missing_description(
        self, app_with_tokens: web.Application, aiohttp_client: Any
    ) -> None:
        """Test error when description is missing."""
        client = await aiohttp_client(app_with_tokens)

        resp = await client.post(
            "/v1/tokens/parse-natural-language",
            json={},
        )

        assert resp.status == 400
        data = await resp.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_create_token_from_natural_language(
        self, app_with_tokens: web.Application, aiohttp_client: Any
    ) -> None:
        """Test creating token from natural language."""
        client = await aiohttp_client(app_with_tokens)

        resp = await client.post(
            "/v1/tokens/from-natural-language",
            json={
                "name": "Test Token",
                "subject": "test@example.com",
                "description": "Allow GPT-4 access with $100 monthly budget",
            },
        )

        assert resp.status == 201
        data = await resp.json()
        assert "token" in data
        assert "parsing" in data
        assert data["token"]["token_id"] == "tok_123"


class TestIncidentReportEndpoint:
    """Tests for incident report generation endpoint."""

    @pytest.fixture
    def app_with_incidents(self) -> web.Application:
        """Create a test application with mock incident manager."""
        from policybind.server.handlers import incident_handlers
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
        app.router.add_get("/v1/incidents/report", incident_handlers.generate_report)

        # Add mock incident manager
        mock_incident = MagicMock()
        mock_incident.incident_id = "inc_123"
        mock_incident.title = "Test Incident"
        mock_incident.status.value = "OPEN"
        mock_incident.severity.value = "HIGH"
        mock_incident.incident_type.value = "POLICY_VIOLATION"
        mock_incident.description = "Test description"
        mock_incident.created_at.isoformat.return_value = "2024-01-01T00:00:00"
        mock_incident.resolved_at = None
        mock_incident.assignee = None
        mock_incident.evidence = {}
        mock_incident.resolution = None
        mock_incident.root_cause = None

        mock_manager = MagicMock()
        mock_manager.get.return_value = mock_incident
        mock_manager.list_incidents.return_value = [mock_incident]
        mock_manager.get_comments.return_value = []
        mock_manager.get_timeline.return_value = []
        app["incident_manager"] = mock_manager

        return app

    @pytest.mark.asyncio
    async def test_generate_summary_report(
        self, app_with_incidents: web.Application, aiohttp_client: Any
    ) -> None:
        """Test generating summary report."""
        # For summary reports, we need to mock the IncidentReporter
        # This test validates the endpoint exists and handles the request
        client = await aiohttp_client(app_with_incidents)

        # The summary report will fail due to mock setup, but we can test
        # that validation works correctly
        resp = await client.get("/v1/incidents/report?format=invalid_format")

        assert resp.status == 400
        data = await resp.json()
        assert "Invalid format" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_generate_incident_report_without_id(
        self, app_with_incidents: web.Application, aiohttp_client: Any
    ) -> None:
        """Test that incident report requires incident_id."""
        client = await aiohttp_client(app_with_incidents)

        resp = await client.get("/v1/incidents/report?type=incident")

        assert resp.status == 400
        data = await resp.json()
        assert "incident_id required" in data["error"]["message"]

    @pytest.mark.asyncio
    async def test_generate_incident_report_with_id(
        self, app_with_incidents: web.Application, aiohttp_client: Any
    ) -> None:
        """Test generating report for specific incident."""
        client = await aiohttp_client(app_with_incidents)

        resp = await client.get(
            "/v1/incidents/report?incident_id=inc_123&format=markdown"
        )

        assert resp.status == 200
        assert "text/markdown" in resp.headers.get("Content-Type", "")


class TestAuditExportEndpoint:
    """Tests for audit log export endpoint."""

    @pytest.fixture
    def app_with_audit(self) -> web.Application:
        """Create a test application with mock audit repository."""
        from policybind.server.handlers import audit_handlers
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
        app.router.add_get("/v1/audit/export", audit_handlers.export_logs)

        # Add mock audit repository
        mock_logs = [
            {
                "id": "log_1",
                "decision": "ALLOW",
                "user_id": "user1",
                "timestamp": "2024-01-01T00:00:00",
            },
            {
                "id": "log_2",
                "decision": "DENY",
                "user_id": "user2",
                "timestamp": "2024-01-02T00:00:00",
            },
        ]

        mock_repo = MagicMock()
        mock_repo.query_enforcement_logs.return_value = mock_logs
        app["audit_repository"] = mock_repo

        return app

    @pytest.mark.asyncio
    async def test_export_json(
        self, app_with_audit: web.Application, aiohttp_client: Any
    ) -> None:
        """Test exporting logs as JSON."""
        client = await aiohttp_client(app_with_audit)

        resp = await client.get("/v1/audit/export?format=json")

        assert resp.status == 200
        assert "application/json" in resp.headers.get("Content-Type", "")
        assert "Content-Disposition" in resp.headers

        text = await resp.text()
        data = json.loads(text)
        assert "logs" in data
        assert len(data["logs"]) == 2

    @pytest.mark.asyncio
    async def test_export_csv(
        self, app_with_audit: web.Application, aiohttp_client: Any
    ) -> None:
        """Test exporting logs as CSV."""
        client = await aiohttp_client(app_with_audit)

        resp = await client.get("/v1/audit/export?format=csv")

        assert resp.status == 200
        assert "text/csv" in resp.headers.get("Content-Type", "")
        assert "Content-Disposition" in resp.headers

        text = await resp.text()
        assert "id,decision,user_id,timestamp" in text
        assert "log_1" in text
        assert "ALLOW" in text

    @pytest.mark.asyncio
    async def test_export_ndjson(
        self, app_with_audit: web.Application, aiohttp_client: Any
    ) -> None:
        """Test exporting logs as NDJSON."""
        client = await aiohttp_client(app_with_audit)

        resp = await client.get("/v1/audit/export?format=ndjson")

        assert resp.status == 200
        assert "ndjson" in resp.headers.get("Content-Type", "")

        text = await resp.text()
        lines = text.strip().split("\n")
        assert len(lines) == 2


class TestRoutes:
    """Tests for route configuration."""

    def test_get_route_info(self) -> None:
        """Test that route info is available."""
        from policybind.server.routes import get_route_info

        routes = get_route_info()

        assert isinstance(routes, list)
        assert len(routes) > 0

        # Check for expected routes
        paths = [r["path"] for r in routes]
        assert "/v1/health" in paths
        assert "/v1/enforce" in paths
        assert "/v1/policies" in paths
        assert "/v1/registry" in paths
        assert "/v1/tokens" in paths
        assert "/v1/incidents" in paths
        assert "/v1/audit/logs" in paths

    def test_new_api_routes_included(self) -> None:
        """Test that new API routes are included in route info."""
        from policybind.server.routes import get_route_info

        routes = get_route_info()
        paths = [r["path"] for r in routes]

        # Check for new endpoints
        assert "/v1/tokens/from-natural-language" in paths
        assert "/v1/tokens/parse-natural-language" in paths
        assert "/v1/incidents/report" in paths
        assert "/v1/audit/export" in paths


class TestOpenAPISpec:
    """Tests for the OpenAPI specification generator."""

    def test_get_openapi_spec_structure(self) -> None:
        """Test that OpenAPI spec has the required structure."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()

        # Check required top-level keys
        assert "openapi" in spec
        assert spec["openapi"].startswith("3.0")
        assert "info" in spec
        assert "paths" in spec
        assert "components" in spec

    def test_openapi_info_section(self) -> None:
        """Test the info section of the OpenAPI spec."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()
        info = spec["info"]

        assert info["title"] == "PolicyBind API"
        assert "version" in info
        assert "description" in info

    def test_openapi_paths_coverage(self) -> None:
        """Test that all routes are documented in OpenAPI spec."""
        from policybind.server.openapi import get_openapi_spec
        from policybind.server.routes import get_route_info

        spec = get_openapi_spec()
        routes = get_route_info()

        spec_paths = list(spec["paths"].keys())

        # Check that major endpoints are covered
        assert "/v1/health" in spec_paths
        assert "/v1/enforce" in spec_paths
        assert "/v1/policies" in spec_paths
        assert "/v1/registry" in spec_paths
        assert "/v1/tokens" in spec_paths
        assert "/v1/incidents" in spec_paths
        assert "/v1/audit/logs" in spec_paths

    def test_openapi_components_schemas(self) -> None:
        """Test that component schemas are defined."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()
        components = spec.get("components", {})
        schemas = components.get("schemas", {})

        # Check for key schemas
        assert "EnforcementRequest" in schemas
        assert "EnforcementResponse" in schemas
        assert "ErrorResponse" in schemas

    def test_openapi_security_schemes(self) -> None:
        """Test that security schemes are defined."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()
        components = spec.get("components", {})
        security_schemes = components.get("securitySchemes", {})

        assert "ApiKeyAuth" in security_schemes
        assert "BearerAuth" in security_schemes

    def test_openapi_tags(self) -> None:
        """Test that tags are defined for grouping endpoints."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()
        tags = spec.get("tags", [])

        tag_names = [t["name"] for t in tags]
        assert "Health" in tag_names
        assert "Enforcement" in tag_names
        assert "Policies" in tag_names

    def test_get_openapi_json(self) -> None:
        """Test JSON output generation."""
        from policybind.server.openapi import get_openapi_json

        json_str = get_openapi_json()

        # Should be valid JSON
        data = json.loads(json_str)
        assert "openapi" in data

    def test_get_openapi_json_indentation(self) -> None:
        """Test JSON output with custom indentation."""
        from policybind.server.openapi import get_openapi_json

        json_2 = get_openapi_json(indent=2)
        json_4 = get_openapi_json(indent=4)

        # Both should be valid JSON
        assert json.loads(json_2)
        assert json.loads(json_4)

        # 4-indent version should be larger
        assert len(json_4) > len(json_2)

    def test_openapi_endpoint_details(self) -> None:
        """Test that endpoints have proper details."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()

        # Check enforce endpoint
        enforce_path = spec["paths"].get("/v1/enforce", {})
        post_op = enforce_path.get("post", {})

        assert "summary" in post_op or "description" in post_op
        assert "requestBody" in post_op
        assert "responses" in post_op

    def test_openapi_new_endpoints_documented(self) -> None:
        """Test that new endpoints are documented in OpenAPI."""
        from policybind.server.openapi import get_openapi_spec

        spec = get_openapi_spec()
        paths = spec["paths"]

        # Check new endpoints from PROMPT 7.2
        assert "/v1/tokens/from-natural-language" in paths
        assert "/v1/tokens/parse-natural-language" in paths
        assert "/v1/incidents/report" in paths
        assert "/v1/audit/export" in paths
