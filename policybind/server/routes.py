"""
API route definitions for PolicyBind server.

This module defines all API routes and their handlers. Routes are
organized by resource type (policies, registry, tokens, incidents, audit).
"""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Coroutine

if TYPE_CHECKING:
    from aiohttp import web

from policybind.server.auth import Role

logger = logging.getLogger("policybind.server.routes")


@dataclass
class Route:
    """
    API route definition.

    Attributes:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH).
        path: URL path pattern.
        handler: Async handler function.
        name: Route name for reverse URL lookup.
        description: Human-readable description.
        required_roles: Roles allowed to access this route.
    """

    method: str
    path: str
    handler: Callable[["web.Request"], Coroutine[Any, Any, "web.StreamResponse"]]
    name: str = ""
    description: str = ""
    required_roles: set[Role] | None = None


def setup_routes(app: "web.Application") -> None:
    """
    Set up all API routes on the application.

    Args:
        app: The aiohttp application instance.
    """
    from aiohttp import web

    # Import handlers
    from policybind.server.handlers import (
        audit_handlers,
        enforce_handlers,
        health_handlers,
        incident_handlers,
        policy_handlers,
        registry_handlers,
        token_handlers,
    )

    # Health and system routes
    app.router.add_get("/v1/health", health_handlers.health_check, name="health")
    app.router.add_get("/v1/ready", health_handlers.readiness_check, name="ready")
    app.router.add_get("/v1/metrics", health_handlers.metrics, name="metrics")

    # Enforcement routes
    app.router.add_post("/v1/enforce", enforce_handlers.enforce, name="enforce")

    # Policy routes
    app.router.add_get("/v1/policies", policy_handlers.list_policies, name="policies_list")
    app.router.add_get(
        "/v1/policies/version", policy_handlers.get_policy_version, name="policies_version"
    )
    app.router.add_get(
        "/v1/policies/history", policy_handlers.get_policy_history, name="policies_history"
    )
    app.router.add_post(
        "/v1/policies/reload", policy_handlers.reload_policies, name="policies_reload"
    )
    app.router.add_post("/v1/policies/test", policy_handlers.test_policy, name="policies_test")

    # Registry routes
    app.router.add_get("/v1/registry", registry_handlers.list_deployments, name="registry_list")
    app.router.add_post(
        "/v1/registry", registry_handlers.create_deployment, name="registry_create"
    )
    app.router.add_get(
        "/v1/registry/{deployment_id}", registry_handlers.get_deployment, name="registry_get"
    )
    app.router.add_put(
        "/v1/registry/{deployment_id}",
        registry_handlers.update_deployment,
        name="registry_update",
    )
    app.router.add_delete(
        "/v1/registry/{deployment_id}",
        registry_handlers.delete_deployment,
        name="registry_delete",
    )
    app.router.add_post(
        "/v1/registry/{deployment_id}/approve",
        registry_handlers.approve_deployment,
        name="registry_approve",
    )
    app.router.add_post(
        "/v1/registry/{deployment_id}/reject",
        registry_handlers.reject_deployment,
        name="registry_reject",
    )
    app.router.add_post(
        "/v1/registry/{deployment_id}/suspend",
        registry_handlers.suspend_deployment,
        name="registry_suspend",
    )
    app.router.add_post(
        "/v1/registry/{deployment_id}/reinstate",
        registry_handlers.reinstate_deployment,
        name="registry_reinstate",
    )
    app.router.add_get(
        "/v1/registry/{deployment_id}/compliance",
        registry_handlers.check_compliance,
        name="registry_compliance",
    )
    app.router.add_get(
        "/v1/registry/{deployment_id}/stats",
        registry_handlers.get_deployment_stats,
        name="registry_stats",
    )

    # Token routes
    app.router.add_get("/v1/tokens", token_handlers.list_tokens, name="tokens_list")
    app.router.add_post("/v1/tokens", token_handlers.create_token, name="tokens_create")
    app.router.add_get(
        "/v1/tokens/templates", token_handlers.list_templates, name="tokens_templates"
    )
    app.router.add_post(
        "/v1/tokens/from-natural-language",
        token_handlers.create_token_from_natural_language,
        name="tokens_from_natural_language",
    )
    app.router.add_post(
        "/v1/tokens/parse-natural-language",
        token_handlers.parse_natural_language,
        name="tokens_parse_natural_language",
    )
    app.router.add_get("/v1/tokens/{token_id}", token_handlers.get_token, name="tokens_get")
    app.router.add_put(
        "/v1/tokens/{token_id}", token_handlers.update_token, name="tokens_update"
    )
    app.router.add_delete(
        "/v1/tokens/{token_id}", token_handlers.revoke_token, name="tokens_revoke"
    )
    app.router.add_post(
        "/v1/tokens/validate", token_handlers.validate_token, name="tokens_validate"
    )
    app.router.add_post(
        "/v1/tokens/{token_id}/suspend",
        token_handlers.suspend_token,
        name="tokens_suspend",
    )
    app.router.add_post(
        "/v1/tokens/{token_id}/unsuspend",
        token_handlers.unsuspend_token,
        name="tokens_unsuspend",
    )
    app.router.add_post(
        "/v1/tokens/{token_id}/renew", token_handlers.renew_token, name="tokens_renew"
    )

    # Incident routes
    app.router.add_get("/v1/incidents", incident_handlers.list_incidents, name="incidents_list")
    app.router.add_post(
        "/v1/incidents", incident_handlers.create_incident, name="incidents_create"
    )
    app.router.add_get(
        "/v1/incidents/stats", incident_handlers.get_incident_stats, name="incidents_stats"
    )
    app.router.add_get(
        "/v1/incidents/report", incident_handlers.generate_report, name="incidents_report"
    )
    app.router.add_get(
        "/v1/incidents/{incident_id}",
        incident_handlers.get_incident,
        name="incidents_get",
    )
    app.router.add_put(
        "/v1/incidents/{incident_id}",
        incident_handlers.update_incident,
        name="incidents_update",
    )
    app.router.add_post(
        "/v1/incidents/{incident_id}/assign",
        incident_handlers.assign_incident,
        name="incidents_assign",
    )
    app.router.add_post(
        "/v1/incidents/{incident_id}/comment",
        incident_handlers.add_comment,
        name="incidents_comment",
    )
    app.router.add_post(
        "/v1/incidents/{incident_id}/investigate",
        incident_handlers.start_investigation,
        name="incidents_investigate",
    )
    app.router.add_post(
        "/v1/incidents/{incident_id}/resolve",
        incident_handlers.resolve_incident,
        name="incidents_resolve",
    )
    app.router.add_post(
        "/v1/incidents/{incident_id}/close",
        incident_handlers.close_incident,
        name="incidents_close",
    )

    # Audit routes
    app.router.add_get("/v1/audit/logs", audit_handlers.query_logs, name="audit_logs")
    app.router.add_get("/v1/audit/stats", audit_handlers.get_stats, name="audit_stats")
    app.router.add_get("/v1/audit/export", audit_handlers.export_logs, name="audit_export")
    app.router.add_get(
        "/v1/audit/logs/{log_id}", audit_handlers.get_log_entry, name="audit_log_entry"
    )

    logger.info("API routes configured")


def get_route_info() -> list[dict[str, Any]]:
    """
    Get information about all defined routes.

    Returns:
        List of route information dictionaries.
    """
    routes = [
        # Health
        {"method": "GET", "path": "/v1/health", "description": "Health check endpoint"},
        {"method": "GET", "path": "/v1/ready", "description": "Readiness check endpoint"},
        {"method": "GET", "path": "/v1/metrics", "description": "Prometheus metrics endpoint"},
        # Enforcement
        {"method": "POST", "path": "/v1/enforce", "description": "Submit request for enforcement"},
        # Policies
        {"method": "GET", "path": "/v1/policies", "description": "List current policies"},
        {"method": "GET", "path": "/v1/policies/version", "description": "Get policy version"},
        {"method": "GET", "path": "/v1/policies/history", "description": "Get policy history"},
        {"method": "POST", "path": "/v1/policies/reload", "description": "Reload policies"},
        {"method": "POST", "path": "/v1/policies/test", "description": "Test request against policies"},
        # Registry
        {"method": "GET", "path": "/v1/registry", "description": "List model deployments"},
        {"method": "POST", "path": "/v1/registry", "description": "Register new deployment"},
        {"method": "GET", "path": "/v1/registry/{id}", "description": "Get deployment details"},
        {"method": "PUT", "path": "/v1/registry/{id}", "description": "Update deployment"},
        {"method": "DELETE", "path": "/v1/registry/{id}", "description": "Delete deployment"},
        {"method": "POST", "path": "/v1/registry/{id}/approve", "description": "Approve deployment"},
        {"method": "POST", "path": "/v1/registry/{id}/reject", "description": "Reject deployment"},
        {"method": "POST", "path": "/v1/registry/{id}/suspend", "description": "Suspend deployment"},
        {"method": "POST", "path": "/v1/registry/{id}/reinstate", "description": "Reinstate deployment"},
        {"method": "GET", "path": "/v1/registry/{id}/compliance", "description": "Check compliance"},
        {"method": "GET", "path": "/v1/registry/{id}/stats", "description": "Get deployment stats"},
        # Tokens
        {"method": "GET", "path": "/v1/tokens", "description": "List access tokens"},
        {"method": "POST", "path": "/v1/tokens", "description": "Create access token"},
        {"method": "GET", "path": "/v1/tokens/templates", "description": "List token templates"},
        {"method": "POST", "path": "/v1/tokens/from-natural-language", "description": "Create token from natural language"},
        {"method": "POST", "path": "/v1/tokens/parse-natural-language", "description": "Parse natural language permissions"},
        {"method": "GET", "path": "/v1/tokens/{id}", "description": "Get token details"},
        {"method": "PUT", "path": "/v1/tokens/{id}", "description": "Update token"},
        {"method": "DELETE", "path": "/v1/tokens/{id}", "description": "Revoke token"},
        {"method": "POST", "path": "/v1/tokens/validate", "description": "Validate token"},
        {"method": "POST", "path": "/v1/tokens/{id}/suspend", "description": "Suspend token"},
        {"method": "POST", "path": "/v1/tokens/{id}/unsuspend", "description": "Unsuspend token"},
        {"method": "POST", "path": "/v1/tokens/{id}/renew", "description": "Renew token"},
        # Incidents
        {"method": "GET", "path": "/v1/incidents", "description": "List incidents"},
        {"method": "POST", "path": "/v1/incidents", "description": "Create incident"},
        {"method": "GET", "path": "/v1/incidents/stats", "description": "Get incident statistics"},
        {"method": "GET", "path": "/v1/incidents/report", "description": "Generate incident report"},
        {"method": "GET", "path": "/v1/incidents/{id}", "description": "Get incident details"},
        {"method": "PUT", "path": "/v1/incidents/{id}", "description": "Update incident"},
        {"method": "POST", "path": "/v1/incidents/{id}/assign", "description": "Assign incident"},
        {"method": "POST", "path": "/v1/incidents/{id}/comment", "description": "Add comment"},
        {"method": "POST", "path": "/v1/incidents/{id}/investigate", "description": "Start investigation"},
        {"method": "POST", "path": "/v1/incidents/{id}/resolve", "description": "Resolve incident"},
        {"method": "POST", "path": "/v1/incidents/{id}/close", "description": "Close incident"},
        # Audit
        {"method": "GET", "path": "/v1/audit/logs", "description": "Query audit logs"},
        {"method": "GET", "path": "/v1/audit/stats", "description": "Get audit statistics"},
        {"method": "GET", "path": "/v1/audit/export", "description": "Export audit logs"},
        {"method": "GET", "path": "/v1/audit/logs/{id}", "description": "Get log entry details"},
    ]
    return routes
