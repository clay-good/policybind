"""
Tenant management API handlers for PolicyBind.

This module provides HTTP handlers for organization and tenant management
endpoints including CRUD operations and member management.
"""

import json
import logging
from typing import TYPE_CHECKING, Any

from policybind.server.auth import AuthContext, Role
from policybind.tenants import (
    MemberNotFoundError,
    OrganizationNotFoundError,
    OrganizationRole,
    OrganizationStatus,
    QuotaExceededError,
    TenantManager,
    TenantNotFoundError,
    TenantQuota,
    TenantStatus,
    ValidationError,
    get_tenant_context,
)

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.tenant")

# Global tenant manager instance
_tenant_manager: TenantManager | None = None


def get_tenant_manager() -> TenantManager | None:
    """Get the global tenant manager."""
    return _tenant_manager


def set_tenant_manager(manager: TenantManager | None) -> None:
    """Set the global tenant manager."""
    global _tenant_manager
    _tenant_manager = manager


def _require_admin(request: "web.Request") -> AuthContext:
    """
    Require admin role for the request.

    Args:
        request: The HTTP request.

    Returns:
        The auth context.

    Raises:
        web.HTTPForbidden: If not an admin.
    """
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())
    if auth_context.role != Role.ADMIN:
        raise web.HTTPForbidden(
            text=json.dumps({"error": "Admin access required"}),
            content_type="application/json",
        )
    return auth_context


def _require_org_admin(request: "web.Request") -> None:
    """
    Require organization admin role.

    Args:
        request: The HTTP request.

    Raises:
        web.HTTPForbidden: If not an org admin.
    """
    from aiohttp import web

    tenant_context = get_tenant_context(request)
    if not tenant_context.can_manage_organization():
        auth_context: AuthContext = request.get("auth_context", AuthContext())
        if auth_context.role != Role.ADMIN:
            raise web.HTTPForbidden(
                text=json.dumps({"error": "Organization admin access required"}),
                content_type="application/json",
            )


# =============================================================================
# Organization Endpoints
# =============================================================================


async def list_organizations(request: "web.Request") -> "web.Response":
    """
    List organizations.

    GET /v1/orgs

    Query params:
        status: Filter by status (ACTIVE, SUSPENDED, PENDING, ARCHIVED)
        plan: Filter by plan
        limit: Maximum number to return (default 100)
        offset: Number to skip (default 0)

    Returns:
        JSON list of organizations.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    # Parse query parameters
    status_str = request.query.get("status")
    status = OrganizationStatus(status_str) if status_str else None
    plan = request.query.get("plan")
    limit = int(request.query.get("limit", 100))
    offset = int(request.query.get("offset", 0))

    orgs = _tenant_manager.list_organizations(
        status=status,
        plan=plan,
        limit=limit,
        offset=offset,
    )

    return web.json_response({
        "organizations": [org.to_dict() for org in orgs],
        "total": _tenant_manager.get_organization_count(),
        "limit": limit,
        "offset": offset,
    })


async def create_organization(request: "web.Request") -> "web.Response":
    """
    Create a new organization.

    POST /v1/orgs

    Body:
        {
            "name": "Acme Corp",
            "slug": "acme-corp",
            "billing_email": "billing@acme.com",
            "plan": "pro",
            "owner_user_id": "user-123",
            "owner_email": "admin@acme.com",
            "settings": {},
            "metadata": {}
        }

    Returns:
        Created organization.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    name = data.get("name", "")
    slug = data.get("slug", "")

    if not name or not slug:
        return web.json_response(
            {"error": "Name and slug are required"},
            status=400,
        )

    try:
        org = _tenant_manager.create_organization(
            name=name,
            slug=slug,
            billing_email=data.get("billing_email", ""),
            plan=data.get("plan", "free"),
            owner_user_id=data.get("owner_user_id", ""),
            owner_email=data.get("owner_email", ""),
            settings=data.get("settings"),
            metadata=data.get("metadata"),
        )

        logger.info(f"Created organization: {org.organization_id} ({name})")

        return web.json_response(org.to_dict(), status=201)

    except ValidationError as e:
        return web.json_response(
            {"error": str(e)},
            status=400,
        )


async def get_organization(request: "web.Request") -> "web.Response":
    """
    Get an organization by ID.

    GET /v1/orgs/{org_id}

    Returns:
        Organization details.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    try:
        org = _tenant_manager.get_organization(org_id)
        return web.json_response(org.to_dict())

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )


async def update_organization(request: "web.Request") -> "web.Response":
    """
    Update an organization.

    PUT /v1/orgs/{org_id}

    Body:
        {
            "name": "New Name",
            "billing_email": "new@email.com",
            "plan": "enterprise",
            "settings": {},
            "metadata": {}
        }

    Returns:
        Updated organization.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    try:
        org = _tenant_manager.update_organization(
            organization_id=org_id,
            name=data.get("name"),
            billing_email=data.get("billing_email"),
            plan=data.get("plan"),
            settings=data.get("settings"),
            metadata=data.get("metadata"),
        )

        logger.info(f"Updated organization: {org_id}")

        return web.json_response(org.to_dict())

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )


async def delete_organization(request: "web.Request") -> "web.Response":
    """
    Delete an organization.

    DELETE /v1/orgs/{org_id}

    Query params:
        hard: If "true", permanently delete (default: archive)

    Returns:
        Success message.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]
    hard_delete = request.query.get("hard", "").lower() == "true"

    try:
        _tenant_manager.delete_organization(org_id, hard_delete=hard_delete)

        action = "deleted" if hard_delete else "archived"
        logger.info(f"Organization {action}: {org_id}")

        return web.json_response({
            "message": f"Organization {action} successfully",
            "organization_id": org_id,
        })

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )


async def suspend_organization(request: "web.Request") -> "web.Response":
    """
    Suspend an organization.

    POST /v1/orgs/{org_id}/suspend

    Body:
        {
            "reason": "Payment overdue"
        }

    Returns:
        Updated organization.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    try:
        data = await request.json()
        reason = data.get("reason", "")
    except json.JSONDecodeError:
        reason = ""

    try:
        org = _tenant_manager.suspend_organization(org_id, reason=reason)

        logger.warning(f"Suspended organization: {org_id}")

        return web.json_response(org.to_dict())

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )


async def activate_organization(request: "web.Request") -> "web.Response":
    """
    Activate an organization.

    POST /v1/orgs/{org_id}/activate

    Returns:
        Updated organization.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    try:
        org = _tenant_manager.activate_organization(org_id)

        logger.info(f"Activated organization: {org_id}")

        return web.json_response(org.to_dict())

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )


# =============================================================================
# Tenant Endpoints
# =============================================================================


async def list_tenants(request: "web.Request") -> "web.Response":
    """
    List tenants for an organization.

    GET /v1/orgs/{org_id}/tenants

    Query params:
        status: Filter by status
        limit: Maximum number to return
        offset: Number to skip

    Returns:
        JSON list of tenants.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    # Parse query parameters
    status_str = request.query.get("status")
    status = TenantStatus(status_str) if status_str else None
    limit = int(request.query.get("limit", 100))
    offset = int(request.query.get("offset", 0))

    try:
        _tenant_manager.get_organization(org_id)  # Verify org exists
    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )

    tenants = _tenant_manager.list_tenants(
        organization_id=org_id,
        status=status,
        limit=limit,
        offset=offset,
    )

    return web.json_response({
        "tenants": [t.to_dict() for t in tenants],
        "total": _tenant_manager.get_tenant_count(org_id),
        "limit": limit,
        "offset": offset,
    })


async def create_tenant(request: "web.Request") -> "web.Response":
    """
    Create a new tenant.

    POST /v1/orgs/{org_id}/tenants

    Body:
        {
            "name": "Staging",
            "slug": "staging",
            "description": "Staging environment",
            "quota": {...},
            "settings": {},
            "metadata": {}
        }

    Returns:
        Created tenant.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    name = data.get("name", "")
    slug = data.get("slug", "")

    if not name or not slug:
        return web.json_response(
            {"error": "Name and slug are required"},
            status=400,
        )

    # Parse quota if provided
    quota = None
    if "quota" in data:
        quota = TenantQuota(**data["quota"])

    try:
        tenant = _tenant_manager.create_tenant(
            organization_id=org_id,
            name=name,
            slug=slug,
            description=data.get("description", ""),
            quota=quota,
            settings=data.get("settings"),
            metadata=data.get("metadata"),
        )

        logger.info(f"Created tenant: {tenant.tenant_id} ({name}) in org {org_id}")

        return web.json_response(tenant.to_dict(), status=201)

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )
    except ValidationError as e:
        return web.json_response(
            {"error": str(e)},
            status=400,
        )


async def get_tenant(request: "web.Request") -> "web.Response":
    """
    Get a tenant by ID.

    GET /v1/orgs/{org_id}/tenants/{tenant_id}

    Returns:
        Tenant details.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    tenant_id = request.match_info["tenant_id"]

    try:
        tenant = _tenant_manager.get_tenant(tenant_id)

        # Include usage information
        usage = _tenant_manager.get_usage(tenant_id)

        response_data = tenant.to_dict()
        response_data["usage"] = usage.to_dict()

        return web.json_response(response_data)

    except TenantNotFoundError:
        return web.json_response(
            {"error": f"Tenant not found: {tenant_id}"},
            status=404,
        )


async def update_tenant(request: "web.Request") -> "web.Response":
    """
    Update a tenant.

    PUT /v1/orgs/{org_id}/tenants/{tenant_id}

    Body:
        {
            "name": "New Name",
            "description": "New description",
            "quota": {...},
            "settings": {},
            "metadata": {}
        }

    Returns:
        Updated tenant.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    tenant_id = request.match_info["tenant_id"]

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse quota if provided
    quota = None
    if "quota" in data:
        quota = TenantQuota(**data["quota"])

    try:
        tenant = _tenant_manager.update_tenant(
            tenant_id=tenant_id,
            name=data.get("name"),
            description=data.get("description"),
            quota=quota,
            settings=data.get("settings"),
            metadata=data.get("metadata"),
        )

        logger.info(f"Updated tenant: {tenant_id}")

        return web.json_response(tenant.to_dict())

    except TenantNotFoundError:
        return web.json_response(
            {"error": f"Tenant not found: {tenant_id}"},
            status=404,
        )


async def delete_tenant(request: "web.Request") -> "web.Response":
    """
    Delete a tenant.

    DELETE /v1/orgs/{org_id}/tenants/{tenant_id}

    Query params:
        hard: If "true", permanently delete (default: archive)

    Returns:
        Success message.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    tenant_id = request.match_info["tenant_id"]
    hard_delete = request.query.get("hard", "").lower() == "true"

    try:
        _tenant_manager.delete_tenant(tenant_id, hard_delete=hard_delete)

        action = "deleted" if hard_delete else "archived"
        logger.info(f"Tenant {action}: {tenant_id}")

        return web.json_response({
            "message": f"Tenant {action} successfully",
            "tenant_id": tenant_id,
        })

    except TenantNotFoundError:
        return web.json_response(
            {"error": f"Tenant not found: {tenant_id}"},
            status=404,
        )


async def suspend_tenant(request: "web.Request") -> "web.Response":
    """
    Suspend a tenant.

    POST /v1/orgs/{org_id}/tenants/{tenant_id}/suspend

    Body:
        {
            "reason": "Quota exceeded"
        }

    Returns:
        Updated tenant.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    tenant_id = request.match_info["tenant_id"]

    try:
        data = await request.json()
        reason = data.get("reason", "")
    except json.JSONDecodeError:
        reason = ""

    try:
        tenant = _tenant_manager.suspend_tenant(tenant_id, reason=reason)

        logger.warning(f"Suspended tenant: {tenant_id}")

        return web.json_response(tenant.to_dict())

    except TenantNotFoundError:
        return web.json_response(
            {"error": f"Tenant not found: {tenant_id}"},
            status=404,
        )


async def activate_tenant(request: "web.Request") -> "web.Response":
    """
    Activate a tenant.

    POST /v1/orgs/{org_id}/tenants/{tenant_id}/activate

    Returns:
        Updated tenant.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    tenant_id = request.match_info["tenant_id"]

    try:
        tenant = _tenant_manager.activate_tenant(tenant_id)

        logger.info(f"Activated tenant: {tenant_id}")

        return web.json_response(tenant.to_dict())

    except TenantNotFoundError:
        return web.json_response(
            {"error": f"Tenant not found: {tenant_id}"},
            status=404,
        )


async def get_tenant_usage(request: "web.Request") -> "web.Response":
    """
    Get tenant usage and quota status.

    GET /v1/orgs/{org_id}/tenants/{tenant_id}/usage

    Returns:
        Usage and quota information.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    tenant_id = request.match_info["tenant_id"]

    try:
        tenant = _tenant_manager.get_tenant(tenant_id)
        usage = _tenant_manager.get_usage(tenant_id)

        return web.json_response({
            "tenant_id": tenant_id,
            "usage": usage.to_dict(),
            "quota": tenant.quota.to_dict(),
            "exceeded": usage.get_exceeded_quotas(tenant.quota),
        })

    except TenantNotFoundError:
        return web.json_response(
            {"error": f"Tenant not found: {tenant_id}"},
            status=404,
        )


# =============================================================================
# Member Endpoints
# =============================================================================


async def list_members(request: "web.Request") -> "web.Response":
    """
    List organization members.

    GET /v1/orgs/{org_id}/members

    Query params:
        role: Filter by role
        limit: Maximum number to return
        offset: Number to skip

    Returns:
        JSON list of members.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    # Parse query parameters
    role_str = request.query.get("role")
    role = OrganizationRole(role_str) if role_str else None
    limit = int(request.query.get("limit", 100))
    offset = int(request.query.get("offset", 0))

    try:
        _tenant_manager.get_organization(org_id)  # Verify org exists
    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )

    members = _tenant_manager.list_members(
        organization_id=org_id,
        role=role,
        limit=limit,
        offset=offset,
    )

    return web.json_response({
        "members": [m.to_dict() for m in members],
        "total": _tenant_manager.get_member_count(org_id),
        "limit": limit,
        "offset": offset,
    })


async def add_member(request: "web.Request") -> "web.Response":
    """
    Add a member to an organization.

    POST /v1/orgs/{org_id}/members

    Body:
        {
            "user_id": "user-123",
            "role": "MEMBER",
            "email": "user@example.com",
            "display_name": "John Doe"
        }

    Returns:
        Created member.
    """
    from aiohttp import web

    auth_context = _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    user_id = data.get("user_id", "")
    if not user_id:
        return web.json_response(
            {"error": "user_id is required"},
            status=400,
        )

    role_str = data.get("role", "MEMBER")
    try:
        role = OrganizationRole(role_str)
    except ValueError:
        return web.json_response(
            {"error": f"Invalid role: {role_str}"},
            status=400,
        )

    try:
        member = _tenant_manager.add_member(
            organization_id=org_id,
            user_id=user_id,
            role=role,
            email=data.get("email", ""),
            display_name=data.get("display_name", ""),
            invited_by=auth_context.identity,
            metadata=data.get("metadata"),
        )

        logger.info(f"Added member to organization: {user_id} -> {org_id}")

        return web.json_response(member.to_dict(), status=201)

    except OrganizationNotFoundError:
        return web.json_response(
            {"error": f"Organization not found: {org_id}"},
            status=404,
        )
    except ValidationError as e:
        return web.json_response(
            {"error": str(e)},
            status=400,
        )


async def update_member(request: "web.Request") -> "web.Response":
    """
    Update a member's role.

    PUT /v1/orgs/{org_id}/members/{user_id}

    Body:
        {
            "role": "ADMIN"
        }

    Returns:
        Updated member.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]
    user_id = request.match_info["user_id"]

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    role_str = data.get("role")
    if not role_str:
        return web.json_response(
            {"error": "role is required"},
            status=400,
        )

    try:
        role = OrganizationRole(role_str)
    except ValueError:
        return web.json_response(
            {"error": f"Invalid role: {role_str}"},
            status=400,
        )

    try:
        member = _tenant_manager.update_member_role(
            organization_id=org_id,
            user_id=user_id,
            new_role=role,
        )

        logger.info(f"Updated member role: {user_id} in {org_id} -> {role.value}")

        return web.json_response(member.to_dict())

    except MemberNotFoundError:
        return web.json_response(
            {"error": f"Member not found: {user_id}"},
            status=404,
        )


async def remove_member(request: "web.Request") -> "web.Response":
    """
    Remove a member from an organization.

    DELETE /v1/orgs/{org_id}/members/{user_id}

    Returns:
        Success message.
    """
    from aiohttp import web

    _require_admin(request)

    if not _tenant_manager:
        return web.json_response(
            {"error": "Tenant management is not enabled"},
            status=503,
        )

    org_id = request.match_info["org_id"]
    user_id = request.match_info["user_id"]

    try:
        _tenant_manager.remove_member(org_id, user_id)

        logger.info(f"Removed member from organization: {user_id} from {org_id}")

        return web.json_response({
            "message": "Member removed successfully",
            "user_id": user_id,
        })

    except MemberNotFoundError:
        return web.json_response(
            {"error": f"Member not found: {user_id}"},
            status=404,
        )
    except ValidationError as e:
        return web.json_response(
            {"error": str(e)},
            status=400,
        )


# =============================================================================
# Current Tenant Context Endpoint
# =============================================================================


async def get_current_tenant(request: "web.Request") -> "web.Response":
    """
    Get current tenant context.

    GET /v1/tenant

    Returns:
        Current tenant context information.
    """
    from aiohttp import web

    context = get_tenant_context(request)

    if not context.has_tenant:
        return web.json_response({
            "has_tenant": False,
            "message": "No tenant context",
        })

    return web.json_response(context.to_dict())
