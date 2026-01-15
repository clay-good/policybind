"""
API handlers for PolicyBind server.

This package contains handler modules for each API resource type.

Modules:
    health_handlers: Health and readiness checks
    enforce_handlers: Policy enforcement endpoint
    policy_handlers: Policy management endpoints
    registry_handlers: Model registry endpoints
    token_handlers: Access token endpoints
    incident_handlers: Incident management endpoints
    audit_handlers: Audit log endpoints
    dashboard_handlers: Dashboard and metrics endpoints
    webhook_handlers: Webhook configuration and management
    auth_handlers: Authentication and SSO endpoints
    tenant_handlers: Organization and tenant management endpoints
    simulation_handlers: Policy simulation and what-if analysis endpoints
"""

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

__all__ = [
    "health_handlers",
    "enforce_handlers",
    "policy_handlers",
    "registry_handlers",
    "token_handlers",
    "incident_handlers",
    "audit_handlers",
    "dashboard_handlers",
    "webhook_handlers",
    "auth_handlers",
    "tenant_handlers",
    "simulation_handlers",
]
