"""
Tenant manager for PolicyBind.

This module provides the TenantManager class for managing organizations,
tenants, and members throughout their lifecycle.
"""

import logging
import re
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable

from policybind.tenants.models import (
    Organization,
    OrganizationMember,
    OrganizationRole,
    OrganizationStatus,
    Tenant,
    TenantQuota,
    TenantStatus,
    TenantUsage,
)

logger = logging.getLogger("policybind.tenants.manager")


class TenantError(Exception):
    """Base exception for tenant operations."""

    pass


class OrganizationNotFoundError(TenantError):
    """Organization not found."""

    pass


class TenantNotFoundError(TenantError):
    """Tenant not found."""

    pass


class MemberNotFoundError(TenantError):
    """Organization member not found."""

    pass


class QuotaExceededError(TenantError):
    """Resource quota exceeded."""

    def __init__(self, resource: str, limit: int, current: int) -> None:
        self.resource = resource
        self.limit = limit
        self.current = current
        super().__init__(f"Quota exceeded for {resource}: {current}/{limit}")


class ValidationError(TenantError):
    """Validation error."""

    pass


# Type alias for event callbacks
EventCallback = Callable[[str, dict[str, Any]], None]


class TenantManager:
    """
    Manages organizations and tenants for PolicyBind.

    Provides operations for creating, updating, and querying organizations
    and tenants, along with member management and quota enforcement.
    """

    # Slug pattern: lowercase letters, numbers, hyphens, 3-63 characters
    SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,62}$")

    def __init__(self) -> None:
        """Initialize the tenant manager."""
        # In-memory storage (to be replaced with repository pattern)
        self._organizations: dict[str, Organization] = {}
        self._tenants: dict[str, Tenant] = {}
        self._members: dict[str, list[OrganizationMember]] = {}
        self._usage: dict[str, TenantUsage] = {}

        # Event callbacks
        self._callbacks: list[EventCallback] = []

        # Indexes for fast lookups
        self._org_by_slug: dict[str, str] = {}
        self._tenant_by_slug: dict[str, dict[str, str]] = {}  # org_id -> slug -> tenant_id

    # =========================================================================
    # Event System
    # =========================================================================

    def on_event(self, callback: EventCallback) -> None:
        """
        Register a callback for tenant events.

        Args:
            callback: Function to call with (event_type, event_data).
        """
        self._callbacks.append(callback)

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event to all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                logger.error(f"Event callback error for {event_type}: {e}")

    # =========================================================================
    # Organization Management
    # =========================================================================

    def create_organization(
        self,
        name: str,
        slug: str,
        billing_email: str = "",
        plan: str = "free",
        owner_user_id: str = "",
        owner_email: str = "",
        settings: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Organization:
        """
        Create a new organization.

        Args:
            name: Human-readable name.
            slug: URL-friendly identifier.
            billing_email: Email for billing notifications.
            plan: Subscription plan.
            owner_user_id: User ID of the organization owner.
            owner_email: Email of the owner.
            settings: Organization settings.
            metadata: Additional metadata.

        Returns:
            The created organization.

        Raises:
            ValidationError: If validation fails.
        """
        # Validate slug
        if not self.SLUG_PATTERN.match(slug):
            raise ValidationError(
                "Slug must be 3-63 characters, start with a letter, "
                "and contain only lowercase letters, numbers, and hyphens"
            )

        # Check slug uniqueness
        if slug in self._org_by_slug:
            raise ValidationError(f"Organization slug already exists: {slug}")

        # Create organization
        org = Organization(
            name=name,
            slug=slug,
            status=OrganizationStatus.ACTIVE,
            billing_email=billing_email,
            plan=plan,
            settings=settings or {},
            metadata=metadata or {},
        )

        # Store organization
        self._organizations[org.organization_id] = org
        self._org_by_slug[slug] = org.organization_id
        self._members[org.organization_id] = []
        self._tenant_by_slug[org.organization_id] = {}

        logger.info(f"Created organization: {org.organization_id} ({name})")

        # Add owner if specified
        if owner_user_id:
            self.add_member(
                organization_id=org.organization_id,
                user_id=owner_user_id,
                role=OrganizationRole.OWNER,
                email=owner_email,
                display_name=name,
            )

        # Create default tenant
        self.create_tenant(
            organization_id=org.organization_id,
            name="Production",
            slug="production",
            description="Default production tenant",
        )

        # Emit event
        self._emit(
            "organization.created",
            {
                "organization_id": org.organization_id,
                "name": name,
                "slug": slug,
                "plan": plan,
            },
        )

        return org

    def get_organization(self, organization_id: str) -> Organization:
        """
        Get an organization by ID.

        Args:
            organization_id: The organization ID.

        Returns:
            The organization.

        Raises:
            OrganizationNotFoundError: If not found.
        """
        org = self._organizations.get(organization_id)
        if not org:
            raise OrganizationNotFoundError(f"Organization not found: {organization_id}")
        return org

    def get_organization_by_slug(self, slug: str) -> Organization:
        """
        Get an organization by slug.

        Args:
            slug: The organization slug.

        Returns:
            The organization.

        Raises:
            OrganizationNotFoundError: If not found.
        """
        org_id = self._org_by_slug.get(slug)
        if not org_id:
            raise OrganizationNotFoundError(f"Organization not found: {slug}")
        return self.get_organization(org_id)

    def list_organizations(
        self,
        status: OrganizationStatus | None = None,
        plan: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Organization]:
        """
        List organizations with optional filters.

        Args:
            status: Filter by status.
            plan: Filter by plan.
            limit: Maximum number to return.
            offset: Number to skip.

        Returns:
            List of organizations.
        """
        orgs = list(self._organizations.values())

        if status:
            orgs = [o for o in orgs if o.status == status]
        if plan:
            orgs = [o for o in orgs if o.plan == plan]

        # Sort by creation time (newest first)
        orgs.sort(key=lambda o: o.created_at, reverse=True)

        return orgs[offset : offset + limit]

    def update_organization(
        self,
        organization_id: str,
        name: str | None = None,
        billing_email: str | None = None,
        plan: str | None = None,
        settings: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Organization:
        """
        Update an organization.

        Args:
            organization_id: The organization ID.
            name: New name (optional).
            billing_email: New billing email (optional).
            plan: New plan (optional).
            settings: New settings (optional, merged).
            metadata: New metadata (optional, merged).

        Returns:
            The updated organization.

        Raises:
            OrganizationNotFoundError: If not found.
        """
        org = self.get_organization(organization_id)

        # Build updates
        updates: dict[str, Any] = {
            "updated_at": datetime.now(timezone.utc),
        }

        if name is not None:
            updates["name"] = name
        if billing_email is not None:
            updates["billing_email"] = billing_email
        if plan is not None:
            updates["plan"] = plan
        if settings is not None:
            updates["settings"] = {**org.settings, **settings}
        if metadata is not None:
            updates["metadata"] = {**org.metadata, **metadata}

        # Create updated organization
        updated = replace(org, **updates)
        self._organizations[organization_id] = updated

        logger.info(f"Updated organization: {organization_id}")

        # Emit event
        self._emit(
            "organization.updated",
            {
                "organization_id": organization_id,
                "updates": list(updates.keys()),
            },
        )

        return updated

    def suspend_organization(self, organization_id: str, reason: str = "") -> Organization:
        """
        Suspend an organization.

        Args:
            organization_id: The organization ID.
            reason: Reason for suspension.

        Returns:
            The updated organization.

        Raises:
            OrganizationNotFoundError: If not found.
        """
        org = self.get_organization(organization_id)

        if org.status == OrganizationStatus.SUSPENDED:
            return org

        updated = replace(
            org,
            status=OrganizationStatus.SUSPENDED,
            updated_at=datetime.now(timezone.utc),
            metadata={**org.metadata, "suspension_reason": reason},
        )
        self._organizations[organization_id] = updated

        logger.warning(f"Suspended organization: {organization_id}, reason: {reason}")

        # Emit event
        self._emit(
            "organization.suspended",
            {
                "organization_id": organization_id,
                "reason": reason,
            },
        )

        return updated

    def activate_organization(self, organization_id: str) -> Organization:
        """
        Activate an organization.

        Args:
            organization_id: The organization ID.

        Returns:
            The updated organization.

        Raises:
            OrganizationNotFoundError: If not found.
        """
        org = self.get_organization(organization_id)

        if org.status == OrganizationStatus.ACTIVE:
            return org

        metadata = dict(org.metadata)
        metadata.pop("suspension_reason", None)

        updated = replace(
            org,
            status=OrganizationStatus.ACTIVE,
            updated_at=datetime.now(timezone.utc),
            metadata=metadata,
        )
        self._organizations[organization_id] = updated

        logger.info(f"Activated organization: {organization_id}")

        # Emit event
        self._emit(
            "organization.activated",
            {"organization_id": organization_id},
        )

        return updated

    def delete_organization(self, organization_id: str, hard_delete: bool = False) -> None:
        """
        Delete an organization.

        By default, this archives the organization. Use hard_delete=True
        for permanent deletion.

        Args:
            organization_id: The organization ID.
            hard_delete: Whether to permanently delete.

        Raises:
            OrganizationNotFoundError: If not found.
        """
        org = self.get_organization(organization_id)

        if hard_delete:
            # Remove from storage
            del self._organizations[organization_id]
            del self._org_by_slug[org.slug]
            del self._members[organization_id]

            # Remove all tenants
            for tenant_id in list(self._tenants.keys()):
                if self._tenants[tenant_id].organization_id == organization_id:
                    del self._tenants[tenant_id]
                    self._usage.pop(tenant_id, None)

            del self._tenant_by_slug[organization_id]

            logger.warning(f"Hard deleted organization: {organization_id}")
        else:
            # Archive
            updated = replace(
                org,
                status=OrganizationStatus.ARCHIVED,
                updated_at=datetime.now(timezone.utc),
            )
            self._organizations[organization_id] = updated

            logger.info(f"Archived organization: {organization_id}")

        # Emit event
        self._emit(
            "organization.deleted",
            {
                "organization_id": organization_id,
                "hard_delete": hard_delete,
            },
        )

    # =========================================================================
    # Tenant Management
    # =========================================================================

    def create_tenant(
        self,
        organization_id: str,
        name: str,
        slug: str,
        description: str = "",
        quota: TenantQuota | None = None,
        settings: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Tenant:
        """
        Create a new tenant within an organization.

        Args:
            organization_id: The parent organization ID.
            name: Human-readable name.
            slug: URL-friendly identifier (unique within org).
            description: Description of the tenant.
            quota: Resource quotas (defaults to org's default).
            settings: Tenant settings.
            metadata: Additional metadata.

        Returns:
            The created tenant.

        Raises:
            OrganizationNotFoundError: If organization not found.
            ValidationError: If validation fails.
        """
        org = self.get_organization(organization_id)

        # Validate slug
        if not self.SLUG_PATTERN.match(slug):
            raise ValidationError(
                "Slug must be 3-63 characters, start with a letter, "
                "and contain only lowercase letters, numbers, and hyphens"
            )

        # Check slug uniqueness within organization
        if slug in self._tenant_by_slug.get(organization_id, {}):
            raise ValidationError(f"Tenant slug already exists in this organization: {slug}")

        # Use organization's default quota if not specified
        if quota is None:
            quota = org.default_tenant_quota

        # Create tenant
        tenant = Tenant(
            organization_id=organization_id,
            name=name,
            slug=slug,
            description=description,
            status=TenantStatus.ACTIVE,
            quota=quota,
            settings=settings or {},
            metadata=metadata or {},
        )

        # Store tenant
        self._tenants[tenant.tenant_id] = tenant
        if organization_id not in self._tenant_by_slug:
            self._tenant_by_slug[organization_id] = {}
        self._tenant_by_slug[organization_id][slug] = tenant.tenant_id

        # Initialize usage tracking
        self._usage[tenant.tenant_id] = TenantUsage(tenant_id=tenant.tenant_id)

        logger.info(
            f"Created tenant: {tenant.tenant_id} ({name}) in org {organization_id}"
        )

        # Emit event
        self._emit(
            "tenant.created",
            {
                "tenant_id": tenant.tenant_id,
                "organization_id": organization_id,
                "name": name,
                "slug": slug,
            },
        )

        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant:
        """
        Get a tenant by ID.

        Args:
            tenant_id: The tenant ID.

        Returns:
            The tenant.

        Raises:
            TenantNotFoundError: If not found.
        """
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            raise TenantNotFoundError(f"Tenant not found: {tenant_id}")
        return tenant

    def get_tenant_by_slug(self, organization_id: str, slug: str) -> Tenant:
        """
        Get a tenant by slug within an organization.

        Args:
            organization_id: The organization ID.
            slug: The tenant slug.

        Returns:
            The tenant.

        Raises:
            TenantNotFoundError: If not found.
        """
        org_tenants = self._tenant_by_slug.get(organization_id, {})
        tenant_id = org_tenants.get(slug)
        if not tenant_id:
            raise TenantNotFoundError(f"Tenant not found: {slug}")
        return self.get_tenant(tenant_id)

    def list_tenants(
        self,
        organization_id: str,
        status: TenantStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Tenant]:
        """
        List tenants for an organization.

        Args:
            organization_id: The organization ID.
            status: Filter by status.
            limit: Maximum number to return.
            offset: Number to skip.

        Returns:
            List of tenants.
        """
        tenants = [
            t for t in self._tenants.values()
            if t.organization_id == organization_id
        ]

        if status:
            tenants = [t for t in tenants if t.status == status]

        # Sort by creation time (newest first)
        tenants.sort(key=lambda t: t.created_at, reverse=True)

        return tenants[offset : offset + limit]

    def update_tenant(
        self,
        tenant_id: str,
        name: str | None = None,
        description: str | None = None,
        quota: TenantQuota | None = None,
        settings: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Tenant:
        """
        Update a tenant.

        Args:
            tenant_id: The tenant ID.
            name: New name (optional).
            description: New description (optional).
            quota: New quota (optional).
            settings: New settings (optional, merged).
            metadata: New metadata (optional, merged).

        Returns:
            The updated tenant.

        Raises:
            TenantNotFoundError: If not found.
        """
        tenant = self.get_tenant(tenant_id)

        # Build updates
        updates: dict[str, Any] = {
            "updated_at": datetime.now(timezone.utc),
        }

        if name is not None:
            updates["name"] = name
        if description is not None:
            updates["description"] = description
        if quota is not None:
            updates["quota"] = quota
        if settings is not None:
            updates["settings"] = {**tenant.settings, **settings}
        if metadata is not None:
            updates["metadata"] = {**tenant.metadata, **metadata}

        # Create updated tenant
        updated = replace(tenant, **updates)
        self._tenants[tenant_id] = updated

        logger.info(f"Updated tenant: {tenant_id}")

        # Emit event
        self._emit(
            "tenant.updated",
            {
                "tenant_id": tenant_id,
                "organization_id": tenant.organization_id,
                "updates": list(updates.keys()),
            },
        )

        return updated

    def suspend_tenant(self, tenant_id: str, reason: str = "") -> Tenant:
        """
        Suspend a tenant.

        Args:
            tenant_id: The tenant ID.
            reason: Reason for suspension.

        Returns:
            The updated tenant.

        Raises:
            TenantNotFoundError: If not found.
        """
        tenant = self.get_tenant(tenant_id)

        if tenant.status == TenantStatus.SUSPENDED:
            return tenant

        updated = replace(
            tenant,
            status=TenantStatus.SUSPENDED,
            updated_at=datetime.now(timezone.utc),
            metadata={**tenant.metadata, "suspension_reason": reason},
        )
        self._tenants[tenant_id] = updated

        logger.warning(f"Suspended tenant: {tenant_id}, reason: {reason}")

        # Emit event
        self._emit(
            "tenant.suspended",
            {
                "tenant_id": tenant_id,
                "organization_id": tenant.organization_id,
                "reason": reason,
            },
        )

        return updated

    def activate_tenant(self, tenant_id: str) -> Tenant:
        """
        Activate a tenant.

        Args:
            tenant_id: The tenant ID.

        Returns:
            The updated tenant.

        Raises:
            TenantNotFoundError: If not found.
        """
        tenant = self.get_tenant(tenant_id)

        if tenant.status == TenantStatus.ACTIVE:
            return tenant

        metadata = dict(tenant.metadata)
        metadata.pop("suspension_reason", None)

        updated = replace(
            tenant,
            status=TenantStatus.ACTIVE,
            updated_at=datetime.now(timezone.utc),
            metadata=metadata,
        )
        self._tenants[tenant_id] = updated

        logger.info(f"Activated tenant: {tenant_id}")

        # Emit event
        self._emit(
            "tenant.activated",
            {
                "tenant_id": tenant_id,
                "organization_id": tenant.organization_id,
            },
        )

        return updated

    def delete_tenant(self, tenant_id: str, hard_delete: bool = False) -> None:
        """
        Delete a tenant.

        By default, this archives the tenant. Use hard_delete=True
        for permanent deletion.

        Args:
            tenant_id: The tenant ID.
            hard_delete: Whether to permanently delete.

        Raises:
            TenantNotFoundError: If not found.
        """
        tenant = self.get_tenant(tenant_id)

        if hard_delete:
            # Remove from storage
            del self._tenants[tenant_id]
            org_tenants = self._tenant_by_slug.get(tenant.organization_id, {})
            if tenant.slug in org_tenants:
                del org_tenants[tenant.slug]
            self._usage.pop(tenant_id, None)

            logger.warning(f"Hard deleted tenant: {tenant_id}")
        else:
            # Archive
            updated = replace(
                tenant,
                status=TenantStatus.ARCHIVED,
                updated_at=datetime.now(timezone.utc),
            )
            self._tenants[tenant_id] = updated

            logger.info(f"Archived tenant: {tenant_id}")

        # Emit event
        self._emit(
            "tenant.deleted",
            {
                "tenant_id": tenant_id,
                "organization_id": tenant.organization_id,
                "hard_delete": hard_delete,
            },
        )

    # =========================================================================
    # Member Management
    # =========================================================================

    def add_member(
        self,
        organization_id: str,
        user_id: str,
        role: OrganizationRole = OrganizationRole.MEMBER,
        email: str = "",
        display_name: str = "",
        invited_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OrganizationMember:
        """
        Add a member to an organization.

        Args:
            organization_id: The organization ID.
            user_id: The user's ID.
            role: Role within the organization.
            email: User's email.
            display_name: User's display name.
            invited_by: ID of the inviting user.
            metadata: Additional metadata.

        Returns:
            The created member.

        Raises:
            OrganizationNotFoundError: If organization not found.
            ValidationError: If user is already a member.
        """
        self.get_organization(organization_id)  # Verify org exists

        # Check if already a member
        existing = self.get_member(organization_id, user_id)
        if existing:
            raise ValidationError(f"User is already a member: {user_id}")

        member = OrganizationMember(
            organization_id=organization_id,
            user_id=user_id,
            role=role,
            email=email,
            display_name=display_name,
            invited_by=invited_by,
            metadata=metadata or {},
        )

        self._members[organization_id].append(member)

        logger.info(
            f"Added member to organization: {user_id} -> {organization_id} ({role.value})"
        )

        # Emit event
        self._emit(
            "member.added",
            {
                "organization_id": organization_id,
                "user_id": user_id,
                "role": role.value,
            },
        )

        return member

    def get_member(
        self, organization_id: str, user_id: str
    ) -> OrganizationMember | None:
        """
        Get a member by user ID.

        Args:
            organization_id: The organization ID.
            user_id: The user ID.

        Returns:
            The member, or None if not found.
        """
        members = self._members.get(organization_id, [])
        for member in members:
            if member.user_id == user_id:
                return member
        return None

    def list_members(
        self,
        organization_id: str,
        role: OrganizationRole | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[OrganizationMember]:
        """
        List members of an organization.

        Args:
            organization_id: The organization ID.
            role: Filter by role.
            limit: Maximum number to return.
            offset: Number to skip.

        Returns:
            List of members.
        """
        members = self._members.get(organization_id, [])

        if role:
            members = [m for m in members if m.role == role]

        # Sort by join time (oldest first)
        members.sort(key=lambda m: m.joined_at)

        return members[offset : offset + limit]

    def update_member_role(
        self,
        organization_id: str,
        user_id: str,
        new_role: OrganizationRole,
    ) -> OrganizationMember:
        """
        Update a member's role.

        Args:
            organization_id: The organization ID.
            user_id: The user ID.
            new_role: The new role.

        Returns:
            The updated member.

        Raises:
            MemberNotFoundError: If member not found.
        """
        member = self.get_member(organization_id, user_id)
        if not member:
            raise MemberNotFoundError(f"Member not found: {user_id}")

        old_role = member.role

        # Create updated member
        updated = replace(member, role=new_role)

        # Update in list
        members = self._members[organization_id]
        self._members[organization_id] = [
            updated if m.user_id == user_id else m for m in members
        ]

        logger.info(
            f"Updated member role: {user_id} in {organization_id}: "
            f"{old_role.value} -> {new_role.value}"
        )

        # Emit event
        self._emit(
            "member.role_changed",
            {
                "organization_id": organization_id,
                "user_id": user_id,
                "old_role": old_role.value,
                "new_role": new_role.value,
            },
        )

        return updated

    def remove_member(self, organization_id: str, user_id: str) -> None:
        """
        Remove a member from an organization.

        Args:
            organization_id: The organization ID.
            user_id: The user ID.

        Raises:
            MemberNotFoundError: If member not found.
            ValidationError: If trying to remove the owner.
        """
        member = self.get_member(organization_id, user_id)
        if not member:
            raise MemberNotFoundError(f"Member not found: {user_id}")

        if member.role == OrganizationRole.OWNER:
            raise ValidationError("Cannot remove the organization owner")

        # Remove from list
        self._members[organization_id] = [
            m for m in self._members[organization_id] if m.user_id != user_id
        ]

        logger.info(f"Removed member from organization: {user_id} from {organization_id}")

        # Emit event
        self._emit(
            "member.removed",
            {
                "organization_id": organization_id,
                "user_id": user_id,
            },
        )

    # =========================================================================
    # Usage and Quota Management
    # =========================================================================

    def get_usage(self, tenant_id: str) -> TenantUsage:
        """
        Get current usage for a tenant.

        Args:
            tenant_id: The tenant ID.

        Returns:
            Current usage.

        Raises:
            TenantNotFoundError: If tenant not found.
        """
        self.get_tenant(tenant_id)  # Verify tenant exists

        usage = self._usage.get(tenant_id)
        if not usage:
            usage = TenantUsage(tenant_id=tenant_id)
            self._usage[tenant_id] = usage

        return usage

    def update_usage(
        self,
        tenant_id: str,
        policy_count: int | None = None,
        deployment_count: int | None = None,
        token_count: int | None = None,
        requests_today: int | None = None,
        storage_bytes: int | None = None,
        incident_count: int | None = None,
    ) -> TenantUsage:
        """
        Update usage counters for a tenant.

        Args:
            tenant_id: The tenant ID.
            policy_count: New policy count.
            deployment_count: New deployment count.
            token_count: New token count.
            requests_today: New requests today count.
            storage_bytes: New storage bytes.
            incident_count: New incident count.

        Returns:
            Updated usage.

        Raises:
            TenantNotFoundError: If tenant not found.
        """
        current = self.get_usage(tenant_id)

        updates = {
            "measured_at": datetime.now(timezone.utc),
        }

        if policy_count is not None:
            updates["policy_count"] = policy_count
        if deployment_count is not None:
            updates["deployment_count"] = deployment_count
        if token_count is not None:
            updates["token_count"] = token_count
        if requests_today is not None:
            updates["requests_today"] = requests_today
        if storage_bytes is not None:
            updates["storage_bytes"] = storage_bytes
        if incident_count is not None:
            updates["incident_count"] = incident_count

        updated = replace(current, **updates)
        self._usage[tenant_id] = updated

        return updated

    def check_quota(self, tenant_id: str, resource: str, increment: int = 1) -> bool:
        """
        Check if a quota would be exceeded.

        Args:
            tenant_id: The tenant ID.
            resource: Resource to check (policies, deployments, etc.).
            increment: Amount to add (default 1).

        Returns:
            True if the operation is allowed, False if it would exceed quota.
        """
        tenant = self.get_tenant(tenant_id)
        usage = self.get_usage(tenant_id)
        quota = tenant.quota

        resource_map = {
            "policies": (usage.policy_count, quota.max_policies),
            "deployments": (usage.deployment_count, quota.max_deployments),
            "tokens": (usage.token_count, quota.max_tokens),
            "requests": (usage.requests_today, quota.max_requests_per_day),
            "storage": (usage.storage_bytes, quota.max_storage_bytes),
        }

        if resource not in resource_map:
            return True

        current, limit = resource_map[resource]
        return (current + increment) <= limit

    def enforce_quota(self, tenant_id: str, resource: str, increment: int = 1) -> None:
        """
        Enforce a quota, raising an error if exceeded.

        Args:
            tenant_id: The tenant ID.
            resource: Resource to check.
            increment: Amount to add.

        Raises:
            QuotaExceededError: If quota would be exceeded.
        """
        if not self.check_quota(tenant_id, resource, increment):
            tenant = self.get_tenant(tenant_id)
            usage = self.get_usage(tenant_id)
            quota = tenant.quota

            resource_map = {
                "policies": (usage.policy_count, quota.max_policies),
                "deployments": (usage.deployment_count, quota.max_deployments),
                "tokens": (usage.token_count, quota.max_tokens),
                "requests": (usage.requests_today, quota.max_requests_per_day),
                "storage": (usage.storage_bytes, quota.max_storage_bytes),
            }

            current, limit = resource_map.get(resource, (0, 0))
            raise QuotaExceededError(resource, limit, current)

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_organization_count(self) -> int:
        """Get total number of organizations."""
        return len(self._organizations)

    def get_tenant_count(self, organization_id: str | None = None) -> int:
        """Get total number of tenants, optionally for an organization."""
        if organization_id:
            return len([t for t in self._tenants.values() if t.organization_id == organization_id])
        return len(self._tenants)

    def get_member_count(self, organization_id: str) -> int:
        """Get total number of members in an organization."""
        return len(self._members.get(organization_id, []))
