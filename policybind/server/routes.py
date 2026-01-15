"""
API route definitions for PolicyBind server.

This module defines all API routes and their handlers. Routes are
organized by resource type (policies, registry, tokens, incidents, audit).
"""

import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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

    # Import handlers
    from policybind.server.handlers import (
        audit_handlers,
        auth_handlers,
        dashboard_handlers,
        enforce_handlers,
        health_handlers,
        incident_handlers,
        policy_handlers,
        registry_handlers,
        simulation_handlers,
        tenant_handlers,
        token_handlers,
        webhook_handlers,
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

    # Dashboard routes
    app.router.add_get(
        "/v1/dashboard", dashboard_handlers.dashboard_summary, name="dashboard_summary"
    )
    app.router.add_get(
        "/v1/dashboard/realtime",
        dashboard_handlers.dashboard_realtime,
        name="dashboard_realtime",
    )
    app.router.add_get(
        "/v1/dashboard/trends", dashboard_handlers.dashboard_trends, name="dashboard_trends"
    )
    app.router.add_get(
        "/v1/dashboard/breakdown",
        dashboard_handlers.dashboard_breakdown,
        name="dashboard_breakdown",
    )
    app.router.add_get(
        "/v1/dashboard/latency",
        dashboard_handlers.dashboard_latency,
        name="dashboard_latency",
    )
    app.router.add_get(
        "/v1/dashboard/alerts", dashboard_handlers.dashboard_alerts, name="dashboard_alerts"
    )
    app.router.add_get(
        "/v1/dashboard/prometheus",
        dashboard_handlers.dashboard_prometheus,
        name="dashboard_prometheus",
    )

    # Webhook routes
    app.router.add_get("/v1/webhooks", webhook_handlers.list_webhooks, name="webhooks_list")
    app.router.add_post(
        "/v1/webhooks", webhook_handlers.create_webhook, name="webhooks_create"
    )
    app.router.add_get(
        "/v1/webhooks/deliveries",
        webhook_handlers.list_webhook_deliveries,
        name="webhooks_deliveries",
    )
    app.router.add_get(
        "/v1/webhooks/stats", webhook_handlers.get_webhook_stats, name="webhooks_stats"
    )
    app.router.add_post(
        "/v1/webhooks/retry",
        webhook_handlers.retry_failed_deliveries,
        name="webhooks_retry",
    )
    app.router.add_get(
        "/v1/webhooks/event-types",
        webhook_handlers.list_event_types,
        name="webhooks_event_types",
    )
    app.router.add_get(
        "/v1/webhooks/{webhook_id}",
        webhook_handlers.get_webhook,
        name="webhooks_get",
    )
    app.router.add_put(
        "/v1/webhooks/{webhook_id}",
        webhook_handlers.update_webhook,
        name="webhooks_update",
    )
    app.router.add_delete(
        "/v1/webhooks/{webhook_id}",
        webhook_handlers.delete_webhook,
        name="webhooks_delete",
    )
    app.router.add_post(
        "/v1/webhooks/{webhook_id}/enable",
        webhook_handlers.enable_webhook,
        name="webhooks_enable",
    )
    app.router.add_post(
        "/v1/webhooks/{webhook_id}/disable",
        webhook_handlers.disable_webhook,
        name="webhooks_disable",
    )
    app.router.add_post(
        "/v1/webhooks/{webhook_id}/test",
        webhook_handlers.test_webhook,
        name="webhooks_test",
    )

    # Authentication routes
    app.router.add_get("/v1/auth/status", auth_handlers.auth_status, name="auth_status")
    app.router.add_get(
        "/v1/auth/providers", auth_handlers.auth_providers, name="auth_providers"
    )
    app.router.add_get("/v1/auth/config", auth_handlers.auth_config, name="auth_config")
    app.router.add_post(
        "/v1/auth/cache/clear", auth_handlers.clear_auth_cache, name="auth_cache_clear"
    )

    # SAML routes
    app.router.add_get("/v1/auth/saml/login", auth_handlers.saml_login, name="saml_login")
    app.router.add_post("/v1/auth/saml/acs", auth_handlers.saml_acs, name="saml_acs")
    app.router.add_post(
        "/v1/auth/saml/logout", auth_handlers.saml_logout, name="saml_logout"
    )
    app.router.add_get(
        "/v1/auth/saml/metadata", auth_handlers.saml_metadata, name="saml_metadata"
    )
    app.router.add_get(
        "/v1/auth/saml/session", auth_handlers.saml_session, name="saml_session"
    )

    # LDAP routes
    app.router.add_post(
        "/v1/auth/ldap/login", auth_handlers.ldap_login, name="ldap_login"
    )
    app.router.add_get(
        "/v1/auth/ldap/status", auth_handlers.ldap_status, name="ldap_status"
    )

    # Tenant context route
    app.router.add_get("/v1/tenant", tenant_handlers.get_current_tenant, name="tenant_current")

    # Organization routes
    app.router.add_get("/v1/orgs", tenant_handlers.list_organizations, name="orgs_list")
    app.router.add_post("/v1/orgs", tenant_handlers.create_organization, name="orgs_create")
    app.router.add_get(
        "/v1/orgs/{org_id}", tenant_handlers.get_organization, name="orgs_get"
    )
    app.router.add_put(
        "/v1/orgs/{org_id}", tenant_handlers.update_organization, name="orgs_update"
    )
    app.router.add_delete(
        "/v1/orgs/{org_id}", tenant_handlers.delete_organization, name="orgs_delete"
    )
    app.router.add_post(
        "/v1/orgs/{org_id}/suspend",
        tenant_handlers.suspend_organization,
        name="orgs_suspend",
    )
    app.router.add_post(
        "/v1/orgs/{org_id}/activate",
        tenant_handlers.activate_organization,
        name="orgs_activate",
    )

    # Tenant routes
    app.router.add_get(
        "/v1/orgs/{org_id}/tenants", tenant_handlers.list_tenants, name="tenants_list"
    )
    app.router.add_post(
        "/v1/orgs/{org_id}/tenants", tenant_handlers.create_tenant, name="tenants_create"
    )
    app.router.add_get(
        "/v1/orgs/{org_id}/tenants/{tenant_id}",
        tenant_handlers.get_tenant,
        name="tenants_get",
    )
    app.router.add_put(
        "/v1/orgs/{org_id}/tenants/{tenant_id}",
        tenant_handlers.update_tenant,
        name="tenants_update",
    )
    app.router.add_delete(
        "/v1/orgs/{org_id}/tenants/{tenant_id}",
        tenant_handlers.delete_tenant,
        name="tenants_delete",
    )
    app.router.add_post(
        "/v1/orgs/{org_id}/tenants/{tenant_id}/suspend",
        tenant_handlers.suspend_tenant,
        name="tenants_suspend",
    )
    app.router.add_post(
        "/v1/orgs/{org_id}/tenants/{tenant_id}/activate",
        tenant_handlers.activate_tenant,
        name="tenants_activate",
    )
    app.router.add_get(
        "/v1/orgs/{org_id}/tenants/{tenant_id}/usage",
        tenant_handlers.get_tenant_usage,
        name="tenants_usage",
    )

    # Organization member routes
    app.router.add_get(
        "/v1/orgs/{org_id}/members", tenant_handlers.list_members, name="members_list"
    )
    app.router.add_post(
        "/v1/orgs/{org_id}/members", tenant_handlers.add_member, name="members_add"
    )
    app.router.add_put(
        "/v1/orgs/{org_id}/members/{user_id}",
        tenant_handlers.update_member,
        name="members_update",
    )
    app.router.add_delete(
        "/v1/orgs/{org_id}/members/{user_id}",
        tenant_handlers.remove_member,
        name="members_remove",
    )

    # Simulation routes
    app.router.add_post(
        "/v1/simulate", simulation_handlers.simulate_request, name="simulate"
    )
    app.router.add_post(
        "/v1/simulate/batch", simulation_handlers.simulate_batch, name="simulate_batch"
    )
    app.router.add_post(
        "/v1/simulate/explain",
        simulation_handlers.simulate_explain,
        name="simulate_explain",
    )
    app.router.add_post(
        "/v1/simulate/whatif",
        simulation_handlers.whatif_analyze,
        name="simulate_whatif",
    )
    app.router.add_post(
        "/v1/simulate/whatif/impact",
        simulation_handlers.whatif_impact,
        name="simulate_whatif_impact",
    )
    app.router.add_post(
        "/v1/simulate/whatif/compare",
        simulation_handlers.whatif_compare,
        name="simulate_whatif_compare",
    )
    app.router.add_post(
        "/v1/simulate/rule/analyze",
        simulation_handlers.analyze_rule,
        name="simulate_rule_analyze",
    )
    app.router.add_get(
        "/v1/simulate/status",
        simulation_handlers.get_simulation_status,
        name="simulate_status",
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
        # Dashboard
        {"method": "GET", "path": "/v1/dashboard", "description": "Get dashboard summary"},
        {"method": "GET", "path": "/v1/dashboard/realtime", "description": "Get real-time stats"},
        {"method": "GET", "path": "/v1/dashboard/trends", "description": "Get trend data"},
        {"method": "GET", "path": "/v1/dashboard/breakdown", "description": "Get request breakdown"},
        {"method": "GET", "path": "/v1/dashboard/latency", "description": "Get latency metrics"},
        {"method": "GET", "path": "/v1/dashboard/alerts", "description": "Get active alerts"},
        {"method": "GET", "path": "/v1/dashboard/prometheus", "description": "Prometheus metrics"},
        # Webhooks
        {"method": "GET", "path": "/v1/webhooks", "description": "List webhooks"},
        {"method": "POST", "path": "/v1/webhooks", "description": "Create webhook"},
        {"method": "GET", "path": "/v1/webhooks/deliveries", "description": "List deliveries"},
        {"method": "GET", "path": "/v1/webhooks/stats", "description": "Get delivery stats"},
        {"method": "POST", "path": "/v1/webhooks/retry", "description": "Retry failed deliveries"},
        {"method": "GET", "path": "/v1/webhooks/event-types", "description": "List event types"},
        {"method": "GET", "path": "/v1/webhooks/{id}", "description": "Get webhook details"},
        {"method": "PUT", "path": "/v1/webhooks/{id}", "description": "Update webhook"},
        {"method": "DELETE", "path": "/v1/webhooks/{id}", "description": "Delete webhook"},
        {"method": "POST", "path": "/v1/webhooks/{id}/enable", "description": "Enable webhook"},
        {"method": "POST", "path": "/v1/webhooks/{id}/disable", "description": "Disable webhook"},
        {"method": "POST", "path": "/v1/webhooks/{id}/test", "description": "Test webhook"},
        # Authentication
        {"method": "GET", "path": "/v1/auth/status", "description": "Get auth status"},
        {"method": "GET", "path": "/v1/auth/providers", "description": "List auth providers"},
        {"method": "GET", "path": "/v1/auth/config", "description": "Get auth config (admin)"},
        {"method": "POST", "path": "/v1/auth/cache/clear", "description": "Clear auth cache (admin)"},
        # SAML
        {"method": "GET", "path": "/v1/auth/saml/login", "description": "Initiate SAML login"},
        {"method": "POST", "path": "/v1/auth/saml/acs", "description": "SAML assertion consumer"},
        {"method": "POST", "path": "/v1/auth/saml/logout", "description": "SAML logout"},
        {"method": "GET", "path": "/v1/auth/saml/metadata", "description": "Get SP metadata"},
        {"method": "GET", "path": "/v1/auth/saml/session", "description": "Get SAML session"},
        # LDAP
        {"method": "POST", "path": "/v1/auth/ldap/login", "description": "LDAP login"},
        {"method": "GET", "path": "/v1/auth/ldap/status", "description": "Get LDAP status (admin)"},
        # Tenant context
        {"method": "GET", "path": "/v1/tenant", "description": "Get current tenant context"},
        # Organizations
        {"method": "GET", "path": "/v1/orgs", "description": "List organizations (admin)"},
        {"method": "POST", "path": "/v1/orgs", "description": "Create organization (admin)"},
        {"method": "GET", "path": "/v1/orgs/{id}", "description": "Get organization details"},
        {"method": "PUT", "path": "/v1/orgs/{id}", "description": "Update organization"},
        {"method": "DELETE", "path": "/v1/orgs/{id}", "description": "Delete organization"},
        {"method": "POST", "path": "/v1/orgs/{id}/suspend", "description": "Suspend organization"},
        {"method": "POST", "path": "/v1/orgs/{id}/activate", "description": "Activate organization"},
        # Tenants
        {"method": "GET", "path": "/v1/orgs/{id}/tenants", "description": "List tenants"},
        {"method": "POST", "path": "/v1/orgs/{id}/tenants", "description": "Create tenant"},
        {"method": "GET", "path": "/v1/orgs/{id}/tenants/{id}", "description": "Get tenant"},
        {"method": "PUT", "path": "/v1/orgs/{id}/tenants/{id}", "description": "Update tenant"},
        {"method": "DELETE", "path": "/v1/orgs/{id}/tenants/{id}", "description": "Delete tenant"},
        {"method": "POST", "path": "/v1/orgs/{id}/tenants/{id}/suspend", "description": "Suspend tenant"},
        {"method": "POST", "path": "/v1/orgs/{id}/tenants/{id}/activate", "description": "Activate tenant"},
        {"method": "GET", "path": "/v1/orgs/{id}/tenants/{id}/usage", "description": "Get tenant usage"},
        # Organization members
        {"method": "GET", "path": "/v1/orgs/{id}/members", "description": "List members"},
        {"method": "POST", "path": "/v1/orgs/{id}/members", "description": "Add member"},
        {"method": "PUT", "path": "/v1/orgs/{id}/members/{id}", "description": "Update member role"},
        {"method": "DELETE", "path": "/v1/orgs/{id}/members/{id}", "description": "Remove member"},
        # Simulation
        {"method": "POST", "path": "/v1/simulate", "description": "Simulate request enforcement"},
        {"method": "POST", "path": "/v1/simulate/batch", "description": "Batch simulate requests"},
        {"method": "POST", "path": "/v1/simulate/explain", "description": "Explain simulation result"},
        {"method": "POST", "path": "/v1/simulate/whatif", "description": "What-if scenario analysis"},
        {"method": "POST", "path": "/v1/simulate/whatif/impact", "description": "Impact analysis for changes"},
        {"method": "POST", "path": "/v1/simulate/whatif/compare", "description": "Compare policy sets"},
        {"method": "POST", "path": "/v1/simulate/rule/analyze", "description": "Analyze rule impact"},
        {"method": "GET", "path": "/v1/simulate/status", "description": "Get simulation status"},
    ]
    return routes
