"""
Tenant middleware for PolicyBind.

This module provides middleware for extracting tenant context from requests
and enforcing tenant isolation across all operations.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from policybind.tenants.manager import TenantManager
from policybind.tenants.models import (
    OrganizationRole,
    OrganizationStatus,
    TenantContext,
    TenantStatus,
)

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.tenants.middleware")


# Type aliases
Handler = Callable[["web.Request"], Awaitable["web.StreamResponse"]]
Middleware = Callable[["web.Request", Handler], Awaitable["web.StreamResponse"]]


# Request attribute keys
TENANT_CONTEXT_KEY = "tenant_context"


def extract_tenant_context(
    request: "web.Request",
    tenant_manager: TenantManager,
) -> TenantContext:
    """
    Extract tenant context from request.

    Supports multiple methods for specifying the tenant:
    1. X-Tenant-ID header
    2. X-Organization-ID + X-Tenant-Slug headers
    3. URL path prefix: /orgs/{org_slug}/tenants/{tenant_slug}/...
    4. Query parameters: ?org=slug&tenant=slug

    Args:
        request: The HTTP request.
        tenant_manager: The tenant manager instance.

    Returns:
        TenantContext (may be empty if no tenant context found).
    """
    context = TenantContext()

    # Try X-Tenant-ID header first (most explicit)
    tenant_id = request.headers.get("X-Tenant-ID")
    if tenant_id:
        try:
            tenant = tenant_manager.get_tenant(tenant_id)
            org = tenant_manager.get_organization(tenant.organization_id)

            context = TenantContext(
                has_tenant=True,
                organization_id=org.organization_id,
                tenant_id=tenant.tenant_id,
                organization=org,
                tenant=tenant,
                quota=tenant.quota,
            )
            return context
        except Exception as e:
            logger.warning(f"Failed to resolve tenant from X-Tenant-ID: {e}")

    # Try X-Organization-ID + X-Tenant-Slug
    org_id = request.headers.get("X-Organization-ID")
    tenant_slug = request.headers.get("X-Tenant-Slug")
    if org_id and tenant_slug:
        try:
            org = tenant_manager.get_organization(org_id)
            tenant = tenant_manager.get_tenant_by_slug(org_id, tenant_slug)

            context = TenantContext(
                has_tenant=True,
                organization_id=org.organization_id,
                tenant_id=tenant.tenant_id,
                organization=org,
                tenant=tenant,
                quota=tenant.quota,
            )
            return context
        except Exception as e:
            logger.warning(f"Failed to resolve tenant from headers: {e}")

    # Try URL path prefix: /orgs/{org_slug}/tenants/{tenant_slug}/...
    path = request.path
    if path.startswith("/orgs/"):
        parts = path.split("/")
        if len(parts) >= 5 and parts[3] == "tenants":
            org_slug = parts[2]
            tenant_slug = parts[4]
            try:
                org = tenant_manager.get_organization_by_slug(org_slug)
                tenant = tenant_manager.get_tenant_by_slug(
                    org.organization_id, tenant_slug
                )

                context = TenantContext(
                    has_tenant=True,
                    organization_id=org.organization_id,
                    tenant_id=tenant.tenant_id,
                    organization=org,
                    tenant=tenant,
                    quota=tenant.quota,
                )
                return context
            except Exception as e:
                logger.warning(f"Failed to resolve tenant from URL path: {e}")

    # Try query parameters
    org_slug_param = request.query.get("org")
    tenant_slug_param = request.query.get("tenant")
    if org_slug_param and tenant_slug_param:
        try:
            org = tenant_manager.get_organization_by_slug(org_slug_param)
            tenant = tenant_manager.get_tenant_by_slug(
                org.organization_id, tenant_slug_param
            )

            context = TenantContext(
                has_tenant=True,
                organization_id=org.organization_id,
                tenant_id=tenant.tenant_id,
                organization=org,
                tenant=tenant,
                quota=tenant.quota,
            )
            return context
        except Exception as e:
            logger.warning(f"Failed to resolve tenant from query params: {e}")

    return context


def enrich_tenant_context(
    context: TenantContext,
    tenant_manager: TenantManager,
    user_id: str,
) -> TenantContext:
    """
    Enrich tenant context with user membership information.

    Args:
        context: The tenant context.
        tenant_manager: The tenant manager.
        user_id: The authenticated user's ID.

    Returns:
        Enriched tenant context.
    """
    if not context.has_tenant or not user_id:
        return context

    # Look up user's membership
    member = tenant_manager.get_member(context.organization_id, user_id)

    if member:
        context.is_admin = member.is_admin()
        context.member_role = member.role

    return context


def create_tenant_middleware(
    tenant_manager: TenantManager,
    require_tenant: bool = False,
    exempt_paths: list[str] | None = None,
) -> Middleware:
    """
    Create tenant context middleware.

    This middleware extracts tenant context from requests and stores it
    for use by handlers.

    Args:
        tenant_manager: The tenant manager instance.
        require_tenant: Whether to require tenant context on all requests.
        exempt_paths: Paths that don't require tenant context.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    exempt_paths = exempt_paths or [
        "/v1/health",
        "/v1/ready",
        "/v1/metrics",
        "/v1/auth",
    ]

    @web.middleware
    async def tenant_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Extract tenant context from requests."""
        # Check if path is exempt
        path = request.path
        is_exempt = any(
            path == exempt or path.startswith(f"{exempt}/")
            for exempt in exempt_paths
        )

        if is_exempt:
            request[TENANT_CONTEXT_KEY] = TenantContext()
            return await handler(request)

        # Extract tenant context
        context = extract_tenant_context(request, tenant_manager)

        # Enrich with user membership if authenticated
        auth_context = request.get("auth_context")
        if auth_context and auth_context.authenticated and auth_context.identity:
            context = enrich_tenant_context(
                context, tenant_manager, auth_context.identity
            )

        # Store context in request
        request[TENANT_CONTEXT_KEY] = context

        # Check if tenant is required
        if require_tenant and not context.has_tenant:
            request_id = request.get("request_id", "unknown")
            error_response = {
                "error": {
                    "type": "TenantRequired",
                    "message": "Tenant context is required for this request",
                    "request_id": request_id,
                }
            }
            return web.json_response(error_response, status=400)

        # Validate tenant status if context is present
        if context.has_tenant and not context.is_valid():
            request_id = request.get("request_id", "unknown")

            if context.organization and context.organization.status == OrganizationStatus.SUSPENDED:
                error_response = {
                    "error": {
                        "type": "OrganizationSuspended",
                        "message": "Organization is suspended",
                        "request_id": request_id,
                    }
                }
                return web.json_response(error_response, status=403)

            if context.tenant and context.tenant.status == TenantStatus.SUSPENDED:
                error_response = {
                    "error": {
                        "type": "TenantSuspended",
                        "message": "Tenant is suspended",
                        "request_id": request_id,
                    }
                }
                return web.json_response(error_response, status=403)

        return await handler(request)

    return tenant_middleware


def create_tenant_isolation_middleware(
    tenant_manager: TenantManager,
) -> Middleware:
    """
    Create tenant isolation middleware.

    This middleware enforces tenant isolation by checking that requests
    only access resources belonging to their tenant.

    Args:
        tenant_manager: The tenant manager instance.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    @web.middleware
    async def tenant_isolation_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Enforce tenant isolation."""
        context: TenantContext = request.get(TENANT_CONTEXT_KEY, TenantContext())

        # No enforcement if no tenant context
        if not context.has_tenant:
            return await handler(request)

        # Store tenant filter for handlers to use
        request["tenant_filter"] = {
            "organization_id": context.organization_id,
            "tenant_id": context.tenant_id,
        }

        # Execute handler
        response = await handler(request)

        return response

    return tenant_isolation_middleware


def create_quota_enforcement_middleware(
    tenant_manager: TenantManager,
    resource_paths: dict[str, str] | None = None,
) -> Middleware:
    """
    Create quota enforcement middleware.

    This middleware checks resource quotas before allowing operations
    that create new resources.

    Args:
        tenant_manager: The tenant manager instance.
        resource_paths: Map of path patterns to resource types.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    # Default resource paths
    resource_paths = resource_paths or {
        "POST /v1/policies": "policies",
        "POST /v1/registry": "deployments",
        "POST /v1/tokens": "tokens",
        "POST /v1/enforce": "requests",
    }

    @web.middleware
    async def quota_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Enforce resource quotas."""
        context: TenantContext = request.get(TENANT_CONTEXT_KEY, TenantContext())

        # No enforcement if no tenant context
        if not context.has_tenant:
            return await handler(request)

        # Check if this is a resource creation request
        resource = None

        for pattern, resource_type in resource_paths.items():
            method, path = pattern.split(" ", 1)
            if request.method == method and request.path.startswith(path):
                resource = resource_type
                break

        # If creating a resource, check quota
        if resource:
            if not tenant_manager.check_quota(context.tenant_id, resource):
                request_id = request.get("request_id", "unknown")
                error_response = {
                    "error": {
                        "type": "QuotaExceeded",
                        "message": f"Quota exceeded for {resource}",
                        "resource": resource,
                        "request_id": request_id,
                    }
                }
                return web.json_response(error_response, status=429)

        return await handler(request)

    return quota_middleware


def get_tenant_context(request: "web.Request") -> TenantContext:
    """
    Get tenant context from request.

    Helper function for handlers to retrieve the tenant context.

    Args:
        request: The HTTP request.

    Returns:
        TenantContext from the request.
    """
    return request.get(TENANT_CONTEXT_KEY, TenantContext())


def require_organization_admin(request: "web.Request") -> bool:
    """
    Check if the current user is an organization admin.

    Args:
        request: The HTTP request.

    Returns:
        True if the user is an organization admin.
    """
    context = get_tenant_context(request)
    return context.can_manage_organization()


def get_tenant_filter(request: "web.Request") -> dict[str, str]:
    """
    Get tenant filter from request.

    Helper function for handlers to retrieve tenant filter criteria.

    Args:
        request: The HTTP request.

    Returns:
        Dictionary with organization_id and tenant_id, or empty dict.
    """
    return request.get("tenant_filter", {})
