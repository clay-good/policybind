"""
Multi-tenant support for PolicyBind.

This package provides organization and tenant management for PolicyBind,
enabling data isolation, resource quotas, and organization-level administration.

Modules:
    models: Organization, Tenant, and TenantContext data models
    manager: TenantManager for organization lifecycle management
    middleware: Tenant context extraction and isolation middleware
"""

from policybind.tenants.manager import (
    MemberNotFoundError,
    OrganizationNotFoundError,
    QuotaExceededError,
    TenantError,
    TenantManager,
    TenantNotFoundError,
    ValidationError,
)
from policybind.tenants.middleware import (
    create_quota_enforcement_middleware,
    create_tenant_isolation_middleware,
    create_tenant_middleware,
    get_tenant_context,
    get_tenant_filter,
    require_organization_admin,
)
from policybind.tenants.models import (
    Organization,
    OrganizationMember,
    OrganizationRole,
    OrganizationStatus,
    Tenant,
    TenantContext,
    TenantQuota,
    TenantStatus,
    TenantUsage,
)

__all__ = [
    # Organization
    "Organization",
    "OrganizationMember",
    "OrganizationRole",
    "OrganizationStatus",
    # Tenant
    "Tenant",
    "TenantContext",
    "TenantQuota",
    "TenantStatus",
    "TenantUsage",
    # Manager
    "TenantManager",
    # Middleware
    "create_tenant_middleware",
    "create_tenant_isolation_middleware",
    "create_quota_enforcement_middleware",
    "get_tenant_context",
    "get_tenant_filter",
    "require_organization_admin",
    # Exceptions
    "TenantError",
    "OrganizationNotFoundError",
    "TenantNotFoundError",
    "MemberNotFoundError",
    "QuotaExceededError",
    "ValidationError",
]
