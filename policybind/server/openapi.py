"""
OpenAPI 3.0 specification generator for PolicyBind API.

This module generates a complete OpenAPI 3.0 specification for the PolicyBind
HTTP API, including all endpoints, schemas, authentication requirements,
and example requests/responses.
"""

import json
from typing import Any


def get_openapi_spec() -> dict[str, Any]:
    """
    Generate the complete OpenAPI 3.0 specification.

    Returns:
        OpenAPI specification as a dictionary.
    """
    return {
        "openapi": "3.0.3",
        "info": _get_info(),
        "servers": _get_servers(),
        "tags": _get_tags(),
        "paths": _get_paths(),
        "components": _get_components(),
        "security": [{"ApiKeyAuth": []}, {"BearerAuth": []}],
    }


def get_openapi_json(indent: int = 2) -> str:
    """
    Generate the OpenAPI specification as JSON string.

    Args:
        indent: JSON indentation level.

    Returns:
        JSON string of OpenAPI specification.
    """
    return json.dumps(get_openapi_spec(), indent=indent)


def get_openapi_yaml() -> str:
    """
    Generate the OpenAPI specification as YAML string.

    Returns:
        YAML string of OpenAPI specification.
    """
    try:
        import yaml

        return yaml.dump(get_openapi_spec(), default_flow_style=False, sort_keys=False)
    except ImportError:
        raise ImportError("PyYAML is required for YAML output. Install with: pip install pyyaml")


def _get_info() -> dict[str, Any]:
    """Get API info section."""
    return {
        "title": "PolicyBind API",
        "description": """
PolicyBind is an AI Policy as Code enforcement platform that provides
centralized governance for AI/ML model deployments across your organization.

## Features

- **Policy Enforcement**: Define and enforce policies for AI model usage
- **Model Registry**: Track and manage AI model deployments
- **Access Tokens**: Fine-grained access control with natural language configuration
- **Incident Management**: Track and respond to policy violations
- **Audit Logging**: Complete audit trail for compliance

## Authentication

The API supports two authentication methods:

1. **API Key**: Pass via `X-API-Key` header
2. **Bearer Token**: Pass via `Authorization: Bearer <token>` header

Some endpoints (health, ready, metrics) are publicly accessible.
""",
        "version": "1.0.0",
        "contact": {
            "name": "PolicyBind Support",
            "url": "https://github.com/policybind/policybind",
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT",
        },
    }


def _get_servers() -> list[dict[str, Any]]:
    """Get servers section."""
    return [
        {
            "url": "http://localhost:8080",
            "description": "Local development server",
        },
        {
            "url": "https://api.policybind.example.com",
            "description": "Production server (example)",
        },
    ]


def _get_tags() -> list[dict[str, Any]]:
    """Get tags section."""
    return [
        {
            "name": "Health",
            "description": "Health check and monitoring endpoints",
        },
        {
            "name": "Enforcement",
            "description": "Policy enforcement endpoints",
        },
        {
            "name": "Policies",
            "description": "Policy management endpoints",
        },
        {
            "name": "Registry",
            "description": "Model deployment registry endpoints",
        },
        {
            "name": "Tokens",
            "description": "Access token management endpoints",
        },
        {
            "name": "Incidents",
            "description": "Incident management endpoints",
        },
        {
            "name": "Audit",
            "description": "Audit log and reporting endpoints",
        },
    ]


def _get_paths() -> dict[str, Any]:
    """Get all API paths."""
    paths: dict[str, Any] = {}

    # Health endpoints
    paths.update(_get_health_paths())

    # Enforcement endpoints
    paths.update(_get_enforcement_paths())

    # Policy endpoints
    paths.update(_get_policy_paths())

    # Registry endpoints
    paths.update(_get_registry_paths())

    # Token endpoints
    paths.update(_get_token_paths())

    # Incident endpoints
    paths.update(_get_incident_paths())

    # Audit endpoints
    paths.update(_get_audit_paths())

    return paths


def _get_health_paths() -> dict[str, Any]:
    """Get health endpoint paths."""
    return {
        "/v1/health": {
            "get": {
                "tags": ["Health"],
                "summary": "Health check",
                "description": "Returns the health status of the server. Use for load balancer health checks.",
                "operationId": "healthCheck",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Server is healthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthResponse"},
                                "example": {
                                    "status": "healthy",
                                    "timestamp": 1704067200.0,
                                },
                            }
                        },
                    }
                },
            }
        },
        "/v1/ready": {
            "get": {
                "tags": ["Health"],
                "summary": "Readiness check",
                "description": "Checks that all dependencies are available and the server is ready to accept requests.",
                "operationId": "readinessCheck",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Server is ready",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReadinessResponse"},
                                "example": {
                                    "status": "ready",
                                    "checks": {
                                        "database": {"status": "ready"},
                                        "policies": {"status": "ready", "rule_count": 10},
                                        "enforcement": {"status": "ready"},
                                    },
                                    "timestamp": 1704067200.0,
                                },
                            }
                        },
                    },
                    "503": {
                        "description": "Server is not ready",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReadinessResponse"},
                            }
                        },
                    },
                },
            }
        },
        "/v1/metrics": {
            "get": {
                "tags": ["Health"],
                "summary": "Prometheus metrics",
                "description": "Returns metrics in Prometheus text format for scraping.",
                "operationId": "getMetrics",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Metrics in Prometheus format",
                        "content": {
                            "text/plain": {
                                "schema": {"type": "string"},
                                "example": "# HELP policybind_up PolicyBind server is up\n# TYPE policybind_up gauge\npolicybind_up 1\n",
                            }
                        },
                    }
                },
            }
        },
    }


def _get_enforcement_paths() -> dict[str, Any]:
    """Get enforcement endpoint paths."""
    return {
        "/v1/enforce": {
            "post": {
                "tags": ["Enforcement"],
                "summary": "Submit request for enforcement",
                "description": "Submits an AI request for policy enforcement. Returns the enforcement decision.",
                "operationId": "enforce",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/EnforcementRequest"},
                            "example": {
                                "provider": "openai",
                                "model": "gpt-4",
                                "user_id": "user@example.com",
                                "department": "engineering",
                                "estimated_tokens": 1000,
                                "data_classification": ["internal"],
                                "intended_use_case": "code_review",
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Enforcement decision",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/EnforcementResponse"},
                                "example": {
                                    "request_id": "req_abc123",
                                    "decision": "ALLOW",
                                    "reason": "Request matches allowed policy",
                                    "applied_rules": ["allow-engineering-gpt4"],
                                    "warnings": [],
                                    "modifications": {},
                                    "enforcement_time_ms": 2.5,
                                },
                            }
                        },
                    },
                    "400": {
                        "description": "Invalid request",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                    "503": {
                        "description": "Service unavailable",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            }
        }
    }


def _get_policy_paths() -> dict[str, Any]:
    """Get policy endpoint paths."""
    return {
        "/v1/policies": {
            "get": {
                "tags": ["Policies"],
                "summary": "List current policies",
                "description": "Returns a summary of all currently loaded policies.",
                "operationId": "listPolicies",
                "responses": {
                    "200": {
                        "description": "Policy list",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PolicyListResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/policies/version": {
            "get": {
                "tags": ["Policies"],
                "summary": "Get policy version",
                "description": "Returns the current policy version and metadata.",
                "operationId": "getPolicyVersion",
                "responses": {
                    "200": {
                        "description": "Policy version info",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PolicyVersionResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/policies/history": {
            "get": {
                "tags": ["Policies"],
                "summary": "Get policy history",
                "description": "Returns the version history of policy changes.",
                "operationId": "getPolicyHistory",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "description": "Maximum number of entries to return",
                        "schema": {"type": "integer", "default": 10},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Policy history",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PolicyHistoryResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/policies/reload": {
            "post": {
                "tags": ["Policies"],
                "summary": "Reload policies",
                "description": "Triggers a reload of policies from the configured source. Requires admin role.",
                "operationId": "reloadPolicies",
                "responses": {
                    "200": {
                        "description": "Policies reloaded",
                        "content": {
                            "application/json": {
                                "example": {
                                    "message": "Policies reloaded",
                                    "rule_count": 15,
                                    "version": "v2",
                                },
                            }
                        },
                    },
                    "403": {
                        "description": "Forbidden - requires admin role",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            }
        },
        "/v1/policies/test": {
            "post": {
                "tags": ["Policies"],
                "summary": "Test request against policies",
                "description": "Tests a request against policies without recording it. Useful for debugging.",
                "operationId": "testPolicy",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/EnforcementRequest"},
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Test result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/EnforcementResponse"},
                            }
                        },
                    }
                },
            }
        },
    }


def _get_registry_paths() -> dict[str, Any]:
    """Get registry endpoint paths."""
    return {
        "/v1/registry": {
            "get": {
                "tags": ["Registry"],
                "summary": "List model deployments",
                "description": "Returns a list of all registered model deployments.",
                "operationId": "listDeployments",
                "parameters": [
                    {
                        "name": "status",
                        "in": "query",
                        "description": "Filter by status",
                        "schema": {
                            "type": "string",
                            "enum": ["PENDING", "APPROVED", "REJECTED", "SUSPENDED"],
                        },
                    },
                    {
                        "name": "provider",
                        "in": "query",
                        "description": "Filter by provider",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "owner",
                        "in": "query",
                        "description": "Filter by owner",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "description": "Maximum results",
                        "schema": {"type": "integer", "default": 100},
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "description": "Pagination offset",
                        "schema": {"type": "integer", "default": 0},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Deployment list",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentListResponse"},
                            }
                        },
                    }
                },
            },
            "post": {
                "tags": ["Registry"],
                "summary": "Register new deployment",
                "description": "Registers a new model deployment in the registry.",
                "operationId": "createDeployment",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CreateDeploymentRequest"},
                            "example": {
                                "name": "GPT-4 Production",
                                "provider": "openai",
                                "model": "gpt-4",
                                "owner": "engineering@example.com",
                                "department": "engineering",
                                "purpose": "Code review assistance",
                                "data_classification": ["internal"],
                            },
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Deployment created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    },
                    "400": {
                        "description": "Invalid request",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            },
        },
        "/v1/registry/{deployment_id}": {
            "get": {
                "tags": ["Registry"],
                "summary": "Get deployment details",
                "description": "Returns detailed information about a specific deployment.",
                "operationId": "getDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Deployment details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    },
                    "404": {
                        "description": "Deployment not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            },
            "put": {
                "tags": ["Registry"],
                "summary": "Update deployment",
                "description": "Updates an existing deployment.",
                "operationId": "updateDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UpdateDeploymentRequest"},
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Deployment updated",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    },
                    "404": {
                        "description": "Deployment not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            },
            "delete": {
                "tags": ["Registry"],
                "summary": "Delete deployment",
                "description": "Deletes a deployment from the registry.",
                "operationId": "deleteDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Deployment deleted",
                        "content": {
                            "application/json": {
                                "example": {"message": "Deployment deleted"},
                            }
                        },
                    },
                    "404": {
                        "description": "Deployment not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            },
        },
        "/v1/registry/{deployment_id}/approve": {
            "post": {
                "tags": ["Registry"],
                "summary": "Approve deployment",
                "description": "Approves a pending deployment.",
                "operationId": "approveDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "approver": {"type": "string"},
                                    "notes": {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Deployment approved",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/registry/{deployment_id}/reject": {
            "post": {
                "tags": ["Registry"],
                "summary": "Reject deployment",
                "description": "Rejects a pending deployment.",
                "operationId": "rejectDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["reason"],
                                "properties": {
                                    "reason": {"type": "string"},
                                    "rejector": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Deployment rejected",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/registry/{deployment_id}/suspend": {
            "post": {
                "tags": ["Registry"],
                "summary": "Suspend deployment",
                "description": "Suspends an active deployment.",
                "operationId": "suspendDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["reason"],
                                "properties": {
                                    "reason": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Deployment suspended",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/registry/{deployment_id}/reinstate": {
            "post": {
                "tags": ["Registry"],
                "summary": "Reinstate deployment",
                "description": "Reinstates a suspended deployment.",
                "operationId": "reinstateDeployment",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Deployment reinstated",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/registry/{deployment_id}/compliance": {
            "get": {
                "tags": ["Registry"],
                "summary": "Check compliance",
                "description": "Checks compliance status for a deployment.",
                "operationId": "checkCompliance",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Compliance check result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ComplianceResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/registry/{deployment_id}/stats": {
            "get": {
                "tags": ["Registry"],
                "summary": "Get deployment stats",
                "description": "Returns usage statistics for a deployment.",
                "operationId": "getDeploymentStats",
                "parameters": [
                    {
                        "name": "deployment_id",
                        "in": "path",
                        "required": True,
                        "description": "Deployment ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Deployment statistics",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DeploymentStatsResponse"},
                            }
                        },
                    }
                },
            }
        },
    }


def _get_token_paths() -> dict[str, Any]:
    """Get token endpoint paths."""
    return {
        "/v1/tokens": {
            "get": {
                "tags": ["Tokens"],
                "summary": "List access tokens",
                "description": "Returns a list of access tokens. Token values are not included.",
                "operationId": "listTokens",
                "parameters": [
                    {
                        "name": "subject",
                        "in": "query",
                        "description": "Filter by subject",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "status",
                        "in": "query",
                        "description": "Filter by status",
                        "schema": {
                            "type": "string",
                            "enum": ["active", "suspended", "revoked", "expired"],
                        },
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 100},
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "schema": {"type": "integer", "default": 0},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Token list",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenListResponse"},
                            }
                        },
                    }
                },
            },
            "post": {
                "tags": ["Tokens"],
                "summary": "Create access token",
                "description": "Creates a new access token. The token value is only returned once.",
                "operationId": "createToken",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CreateTokenRequest"},
                            "example": {
                                "name": "CI/CD Token",
                                "subject": "ci-system@example.com",
                                "permissions": {
                                    "allowed_models": ["gpt-3.5-turbo"],
                                    "budget": {"amount": 100, "period": "monthly"},
                                },
                                "expires_in_days": 90,
                            },
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Token created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenCreatedResponse"},
                            }
                        },
                    }
                },
            },
        },
        "/v1/tokens/templates": {
            "get": {
                "tags": ["Tokens"],
                "summary": "List token templates",
                "description": "Returns available token permission templates.",
                "operationId": "listTokenTemplates",
                "responses": {
                    "200": {
                        "description": "Template list",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenTemplateListResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/tokens/from-natural-language": {
            "post": {
                "tags": ["Tokens"],
                "summary": "Create token from natural language",
                "description": "Creates a token by parsing a natural language description of permissions.",
                "operationId": "createTokenFromNaturalLanguage",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/NaturalLanguageTokenRequest"},
                            "example": {
                                "name": "Developer Token",
                                "subject": "dev@example.com",
                                "description": "Allow GPT-4 with a budget of $100 per month during business hours",
                            },
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Token created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/NaturalLanguageTokenResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/tokens/parse-natural-language": {
            "post": {
                "tags": ["Tokens"],
                "summary": "Parse natural language permissions",
                "description": "Parses a natural language description without creating a token. Useful for previewing.",
                "operationId": "parseNaturalLanguage",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["description"],
                                "properties": {
                                    "description": {
                                        "type": "string",
                                        "description": "Natural language description of permissions",
                                    }
                                },
                            },
                            "example": {
                                "description": "Allow GPT-4 and Claude with $50 daily budget",
                            },
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Parse result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ParseNaturalLanguageResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/tokens/{token_id}": {
            "get": {
                "tags": ["Tokens"],
                "summary": "Get token details",
                "description": "Returns details of a specific token. Token value is not included.",
                "operationId": "getToken",
                "parameters": [
                    {
                        "name": "token_id",
                        "in": "path",
                        "required": True,
                        "description": "Token ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Token details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenResponse"},
                            }
                        },
                    },
                    "404": {
                        "description": "Token not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            },
            "put": {
                "tags": ["Tokens"],
                "summary": "Update token",
                "description": "Updates token permissions or metadata.",
                "operationId": "updateToken",
                "parameters": [
                    {
                        "name": "token_id",
                        "in": "path",
                        "required": True,
                        "description": "Token ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UpdateTokenRequest"},
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Token updated",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenResponse"},
                            }
                        },
                    }
                },
            },
            "delete": {
                "tags": ["Tokens"],
                "summary": "Revoke token",
                "description": "Permanently revokes a token. This action cannot be undone.",
                "operationId": "revokeToken",
                "parameters": [
                    {
                        "name": "token_id",
                        "in": "path",
                        "required": True,
                        "description": "Token ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Token revoked",
                        "content": {
                            "application/json": {
                                "example": {"message": "Token revoked"},
                            }
                        },
                    }
                },
            },
        },
        "/v1/tokens/validate": {
            "post": {
                "tags": ["Tokens"],
                "summary": "Validate token",
                "description": "Validates a token value and returns its permissions.",
                "operationId": "validateToken",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["token"],
                                "properties": {
                                    "token": {
                                        "type": "string",
                                        "description": "Token value to validate",
                                    }
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Token validation result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenValidationResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/tokens/{token_id}/suspend": {
            "post": {
                "tags": ["Tokens"],
                "summary": "Suspend token",
                "description": "Temporarily suspends a token.",
                "operationId": "suspendToken",
                "parameters": [
                    {
                        "name": "token_id",
                        "in": "path",
                        "required": True,
                        "description": "Token ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "reason": {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Token suspended",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/tokens/{token_id}/unsuspend": {
            "post": {
                "tags": ["Tokens"],
                "summary": "Unsuspend token",
                "description": "Reactivates a suspended token.",
                "operationId": "unsuspendToken",
                "parameters": [
                    {
                        "name": "token_id",
                        "in": "path",
                        "required": True,
                        "description": "Token ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Token unsuspended",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/tokens/{token_id}/renew": {
            "post": {
                "tags": ["Tokens"],
                "summary": "Renew token",
                "description": "Extends the expiration date of a token.",
                "operationId": "renewToken",
                "parameters": [
                    {
                        "name": "token_id",
                        "in": "path",
                        "required": True,
                        "description": "Token ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "extend_days": {
                                        "type": "integer",
                                        "description": "Number of days to extend",
                                        "default": 30,
                                    }
                                },
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Token renewed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/TokenResponse"},
                            }
                        },
                    }
                },
            }
        },
    }


def _get_incident_paths() -> dict[str, Any]:
    """Get incident endpoint paths."""
    return {
        "/v1/incidents": {
            "get": {
                "tags": ["Incidents"],
                "summary": "List incidents",
                "description": "Returns a list of incidents with optional filtering.",
                "operationId": "listIncidents",
                "parameters": [
                    {
                        "name": "status",
                        "in": "query",
                        "description": "Filter by status",
                        "schema": {
                            "type": "string",
                            "enum": ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"],
                        },
                    },
                    {
                        "name": "severity",
                        "in": "query",
                        "description": "Filter by severity",
                        "schema": {
                            "type": "string",
                            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        },
                    },
                    {
                        "name": "type",
                        "in": "query",
                        "description": "Filter by incident type",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "assignee",
                        "in": "query",
                        "description": "Filter by assignee",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 100},
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "schema": {"type": "integer", "default": 0},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Incident list",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentListResponse"},
                            }
                        },
                    }
                },
            },
            "post": {
                "tags": ["Incidents"],
                "summary": "Create incident",
                "description": "Creates a new incident.",
                "operationId": "createIncident",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CreateIncidentRequest"},
                            "example": {
                                "title": "Policy violation detected",
                                "incident_type": "POLICY_VIOLATION",
                                "severity": "HIGH",
                                "description": "Unauthorized access to GPT-4 detected",
                                "deployment_id": "dep_abc123",
                            },
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Incident created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentResponse"},
                            }
                        },
                    }
                },
            },
        },
        "/v1/incidents/stats": {
            "get": {
                "tags": ["Incidents"],
                "summary": "Get incident statistics",
                "description": "Returns aggregated incident statistics.",
                "operationId": "getIncidentStats",
                "responses": {
                    "200": {
                        "description": "Incident statistics",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentStatsResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/incidents/report": {
            "get": {
                "tags": ["Incidents"],
                "summary": "Generate incident report",
                "description": "Generates an incident report in the specified format.",
                "operationId": "generateIncidentReport",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "query",
                        "description": "Generate report for specific incident",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "type",
                        "in": "query",
                        "description": "Report type",
                        "schema": {
                            "type": "string",
                            "enum": ["incident", "summary", "trend"],
                            "default": "summary",
                        },
                    },
                    {
                        "name": "format",
                        "in": "query",
                        "description": "Output format",
                        "schema": {
                            "type": "string",
                            "enum": ["markdown", "json", "text"],
                            "default": "markdown",
                        },
                    },
                    {
                        "name": "period",
                        "in": "query",
                        "description": "Time period (e.g., 7d, 30d, 90d)",
                        "schema": {"type": "string", "default": "30d"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Generated report",
                        "content": {
                            "text/markdown": {"schema": {"type": "string"}},
                            "application/json": {"schema": {"type": "object"}},
                            "text/plain": {"schema": {"type": "string"}},
                        },
                    }
                },
            }
        },
        "/v1/incidents/{incident_id}": {
            "get": {
                "tags": ["Incidents"],
                "summary": "Get incident details",
                "description": "Returns detailed information about an incident including timeline and comments.",
                "operationId": "getIncident",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Incident details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentDetailResponse"},
                            }
                        },
                    },
                    "404": {
                        "description": "Incident not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            },
            "put": {
                "tags": ["Incidents"],
                "summary": "Update incident",
                "description": "Updates incident details.",
                "operationId": "updateIncident",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UpdateIncidentRequest"},
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Incident updated",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentResponse"},
                            }
                        },
                    }
                },
            },
        },
        "/v1/incidents/{incident_id}/assign": {
            "post": {
                "tags": ["Incidents"],
                "summary": "Assign incident",
                "description": "Assigns an incident to a user.",
                "operationId": "assignIncident",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["assignee"],
                                "properties": {
                                    "assignee": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Incident assigned",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/incidents/{incident_id}/comment": {
            "post": {
                "tags": ["Incidents"],
                "summary": "Add comment",
                "description": "Adds a comment to an incident.",
                "operationId": "addIncidentComment",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["content"],
                                "properties": {
                                    "author": {"type": "string"},
                                    "content": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Comment added",
                        "content": {
                            "application/json": {
                                "example": {
                                    "comment_id": "cmt_abc123",
                                    "message": "Comment added",
                                },
                            }
                        },
                    }
                },
            }
        },
        "/v1/incidents/{incident_id}/investigate": {
            "post": {
                "tags": ["Incidents"],
                "summary": "Start investigation",
                "description": "Transitions incident to INVESTIGATING status.",
                "operationId": "startInvestigation",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Investigation started",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/incidents/{incident_id}/resolve": {
            "post": {
                "tags": ["Incidents"],
                "summary": "Resolve incident",
                "description": "Resolves an incident with resolution details.",
                "operationId": "resolveIncident",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["resolution"],
                                "properties": {
                                    "resolution": {"type": "string"},
                                    "root_cause": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Incident resolved",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/incidents/{incident_id}/close": {
            "post": {
                "tags": ["Incidents"],
                "summary": "Close incident",
                "description": "Closes a resolved incident.",
                "operationId": "closeIncident",
                "parameters": [
                    {
                        "name": "incident_id",
                        "in": "path",
                        "required": True,
                        "description": "Incident ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Incident closed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentResponse"},
                            }
                        },
                    }
                },
            }
        },
    }


def _get_audit_paths() -> dict[str, Any]:
    """Get audit endpoint paths."""
    return {
        "/v1/audit/logs": {
            "get": {
                "tags": ["Audit"],
                "summary": "Query audit logs",
                "description": "Queries enforcement audit logs with optional filters.",
                "operationId": "queryAuditLogs",
                "parameters": [
                    {
                        "name": "user",
                        "in": "query",
                        "description": "Filter by user ID",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "department",
                        "in": "query",
                        "description": "Filter by department",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "decision",
                        "in": "query",
                        "description": "Filter by decision",
                        "schema": {
                            "type": "string",
                            "enum": ["ALLOW", "DENY", "MODIFY"],
                        },
                    },
                    {
                        "name": "deployment",
                        "in": "query",
                        "description": "Filter by deployment ID",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "start",
                        "in": "query",
                        "description": "Start date (ISO format or relative like '7d')",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "end",
                        "in": "query",
                        "description": "End date (ISO format)",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 100},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Audit logs",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AuditLogResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/audit/stats": {
            "get": {
                "tags": ["Audit"],
                "summary": "Get audit statistics",
                "description": "Returns aggregated audit statistics.",
                "operationId": "getAuditStats",
                "parameters": [
                    {
                        "name": "start",
                        "in": "query",
                        "description": "Start date",
                        "schema": {"type": "string", "default": "30d"},
                    },
                    {
                        "name": "end",
                        "in": "query",
                        "description": "End date",
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Audit statistics",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AuditStatsResponse"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/audit/export": {
            "get": {
                "tags": ["Audit"],
                "summary": "Export audit logs",
                "description": "Exports audit logs in the specified format.",
                "operationId": "exportAuditLogs",
                "parameters": [
                    {
                        "name": "format",
                        "in": "query",
                        "description": "Export format",
                        "schema": {
                            "type": "string",
                            "enum": ["json", "csv", "ndjson"],
                            "default": "json",
                        },
                    },
                    {
                        "name": "user",
                        "in": "query",
                        "description": "Filter by user ID",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "department",
                        "in": "query",
                        "description": "Filter by department",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "decision",
                        "in": "query",
                        "description": "Filter by decision",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "start",
                        "in": "query",
                        "description": "Start date",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "end",
                        "in": "query",
                        "description": "End date",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 10000},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Exported audit logs",
                        "content": {
                            "application/json": {"schema": {"type": "object"}},
                            "text/csv": {"schema": {"type": "string"}},
                            "application/x-ndjson": {"schema": {"type": "string"}},
                        },
                        "headers": {
                            "Content-Disposition": {
                                "description": "File download header",
                                "schema": {"type": "string"},
                            }
                        },
                    }
                },
            }
        },
        "/v1/audit/logs/{log_id}": {
            "get": {
                "tags": ["Audit"],
                "summary": "Get log entry details",
                "description": "Returns details of a specific audit log entry.",
                "operationId": "getAuditLogEntry",
                "parameters": [
                    {
                        "name": "log_id",
                        "in": "path",
                        "required": True,
                        "description": "Log entry ID",
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Log entry details",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AuditLogEntryResponse"},
                            }
                        },
                    },
                    "404": {
                        "description": "Log entry not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ErrorResponse"},
                            }
                        },
                    },
                },
            }
        },
    }


def _get_components() -> dict[str, Any]:
    """Get components section."""
    return {
        "securitySchemes": {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API key authentication",
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "Bearer token authentication",
            },
        },
        "schemas": _get_schemas(),
    }


def _get_schemas() -> dict[str, Any]:
    """Get all schema definitions."""
    return {
        # Common schemas
        "ErrorResponse": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "message": {"type": "string"},
                        "details": {"type": "object"},
                    },
                    "required": ["type", "message"],
                }
            },
            "required": ["error"],
        },
        # Health schemas
        "HealthResponse": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["healthy"]},
                "timestamp": {"type": "number"},
            },
        },
        "ReadinessResponse": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["ready", "not_ready"]},
                "checks": {"type": "object"},
                "timestamp": {"type": "number"},
            },
        },
        # Enforcement schemas
        "EnforcementRequest": {
            "type": "object",
            "required": ["provider", "model"],
            "properties": {
                "request_id": {"type": "string"},
                "provider": {"type": "string"},
                "model": {"type": "string"},
                "prompt_hash": {"type": "string"},
                "estimated_tokens": {"type": "integer"},
                "estimated_cost": {"type": "number"},
                "source_application": {"type": "string"},
                "user_id": {"type": "string"},
                "department": {"type": "string"},
                "data_classification": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "intended_use_case": {"type": "string"},
                "metadata": {"type": "object"},
            },
        },
        "EnforcementResponse": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string"},
                "decision": {
                    "type": "string",
                    "enum": ["ALLOW", "DENY", "MODIFY"],
                },
                "reason": {"type": "string"},
                "applied_rules": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "warnings": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "modifications": {"type": "object"},
                "enforcement_time_ms": {"type": "number"},
                "estimated_cost": {"type": "number"},
            },
        },
        # Policy schemas
        "PolicyListResponse": {
            "type": "object",
            "properties": {
                "policies": {"type": "array"},
                "total": {"type": "integer"},
            },
        },
        "PolicyVersionResponse": {
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "loaded_at": {"type": "string"},
                "rule_count": {"type": "integer"},
            },
        },
        "PolicyHistoryResponse": {
            "type": "object",
            "properties": {
                "history": {"type": "array"},
                "total": {"type": "integer"},
            },
        },
        # Deployment schemas
        "DeploymentListResponse": {
            "type": "object",
            "properties": {
                "deployments": {"type": "array"},
                "total": {"type": "integer"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
        },
        "CreateDeploymentRequest": {
            "type": "object",
            "required": ["name", "provider", "model", "owner"],
            "properties": {
                "name": {"type": "string"},
                "provider": {"type": "string"},
                "model": {"type": "string"},
                "owner": {"type": "string"},
                "department": {"type": "string"},
                "purpose": {"type": "string"},
                "data_classification": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "metadata": {"type": "object"},
            },
        },
        "UpdateDeploymentRequest": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "purpose": {"type": "string"},
                "data_classification": {"type": "array"},
                "metadata": {"type": "object"},
            },
        },
        "DeploymentResponse": {
            "type": "object",
            "properties": {
                "deployment": {"type": "object"},
                "message": {"type": "string"},
            },
        },
        "ComplianceResponse": {
            "type": "object",
            "properties": {
                "compliant": {"type": "boolean"},
                "checks": {"type": "array"},
                "overall_score": {"type": "number"},
            },
        },
        "DeploymentStatsResponse": {
            "type": "object",
            "properties": {
                "total_requests": {"type": "integer"},
                "decisions": {"type": "object"},
            },
        },
        # Token schemas
        "TokenListResponse": {
            "type": "object",
            "properties": {
                "tokens": {"type": "array"},
                "total": {"type": "integer"},
            },
        },
        "CreateTokenRequest": {
            "type": "object",
            "required": ["name", "subject"],
            "properties": {
                "name": {"type": "string"},
                "subject": {"type": "string"},
                "permissions": {"type": "object"},
                "expires_in_days": {"type": "integer"},
                "metadata": {"type": "object"},
            },
        },
        "TokenCreatedResponse": {
            "type": "object",
            "properties": {
                "token": {"type": "object"},
                "message": {"type": "string"},
            },
        },
        "TokenResponse": {
            "type": "object",
            "properties": {
                "token": {"type": "object"},
            },
        },
        "UpdateTokenRequest": {
            "type": "object",
            "properties": {
                "permissions": {"type": "object"},
                "metadata": {"type": "object"},
            },
        },
        "TokenValidationResponse": {
            "type": "object",
            "properties": {
                "valid": {"type": "boolean"},
                "token_id": {"type": "string"},
                "subject": {"type": "string"},
                "permissions": {"type": "object"},
            },
        },
        "TokenTemplateListResponse": {
            "type": "object",
            "properties": {
                "templates": {"type": "array"},
                "total": {"type": "integer"},
            },
        },
        "NaturalLanguageTokenRequest": {
            "type": "object",
            "required": ["name", "subject", "description"],
            "properties": {
                "name": {"type": "string"},
                "subject": {"type": "string"},
                "description": {"type": "string"},
                "expires_in_days": {"type": "integer"},
            },
        },
        "NaturalLanguageTokenResponse": {
            "type": "object",
            "properties": {
                "token": {"type": "object"},
                "parsing": {
                    "type": "object",
                    "properties": {
                        "constraints": {"type": "array"},
                        "confidence": {"type": "string"},
                        "warnings": {"type": "array"},
                        "suggestions": {"type": "array"},
                        "unrecognized_parts": {"type": "array"},
                    },
                },
                "message": {"type": "string"},
            },
        },
        "ParseNaturalLanguageResponse": {
            "type": "object",
            "properties": {
                "permissions": {"type": "object"},
                "constraints": {"type": "array"},
                "confidence": {"type": "string"},
                "warnings": {"type": "array"},
                "suggestions": {"type": "array"},
                "unrecognized_parts": {"type": "array"},
            },
        },
        # Incident schemas
        "IncidentListResponse": {
            "type": "object",
            "properties": {
                "incidents": {"type": "array"},
                "total": {"type": "integer"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
        },
        "CreateIncidentRequest": {
            "type": "object",
            "required": ["title", "incident_type"],
            "properties": {
                "title": {"type": "string"},
                "incident_type": {
                    "type": "string",
                    "enum": [
                        "POLICY_VIOLATION",
                        "BUDGET_EXCEEDED",
                        "RATE_LIMIT_EXCEEDED",
                        "UNAUTHORIZED_ACCESS",
                        "DATA_LEAK",
                        "SYSTEM_ERROR",
                        "OTHER",
                    ],
                },
                "severity": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "default": "MEDIUM",
                },
                "description": {"type": "string"},
                "deployment_id": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "metadata": {"type": "object"},
            },
        },
        "UpdateIncidentRequest": {
            "type": "object",
            "properties": {
                "severity": {"type": "string"},
                "description": {"type": "string"},
            },
        },
        "IncidentResponse": {
            "type": "object",
            "properties": {
                "incident": {"type": "object"},
                "message": {"type": "string"},
            },
        },
        "IncidentDetailResponse": {
            "type": "object",
            "properties": {
                "incident": {
                    "type": "object",
                    "properties": {
                        "incident_id": {"type": "string"},
                        "title": {"type": "string"},
                        "status": {"type": "string"},
                        "severity": {"type": "string"},
                        "comments": {"type": "array"},
                        "timeline": {"type": "array"},
                    },
                }
            },
        },
        "IncidentStatsResponse": {
            "type": "object",
            "properties": {
                "total_count": {"type": "integer"},
                "open_count": {"type": "integer"},
                "investigating_count": {"type": "integer"},
                "resolved_count": {"type": "integer"},
                "closed_count": {"type": "integer"},
                "by_severity": {"type": "object"},
                "by_type": {"type": "object"},
                "mean_time_to_resolve_hours": {"type": "number"},
            },
        },
        # Audit schemas
        "AuditLogResponse": {
            "type": "object",
            "properties": {
                "logs": {"type": "array"},
                "total": {"type": "integer"},
                "limit": {"type": "integer"},
            },
        },
        "AuditLogEntryResponse": {
            "type": "object",
            "properties": {
                "log": {"type": "object"},
            },
        },
        "AuditStatsResponse": {
            "type": "object",
            "properties": {
                "total_requests": {"type": "integer"},
                "by_decision": {"type": "object"},
                "by_department": {"type": "object"},
            },
        },
    }
