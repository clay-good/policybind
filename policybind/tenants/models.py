"""
Multi-tenant data models for PolicyBind.

This module defines the data structures for organization and tenant management,
enabling multi-tenant isolation and resource management.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, model_to_dict, model_to_json, utc_now


class OrganizationStatus(Enum):
    """
    Status of an organization.

    Controls whether the organization is active and can use PolicyBind.
    """

    ACTIVE = "ACTIVE"
    """Organization is fully operational."""

    SUSPENDED = "SUSPENDED"
    """Organization is suspended - all access denied."""

    PENDING = "PENDING"
    """Organization is pending activation."""

    ARCHIVED = "ARCHIVED"
    """Organization is archived and read-only."""


class OrganizationRole(Enum):
    """
    Roles within an organization.

    Defines permissions for organization members.
    """

    OWNER = "OWNER"
    """Organization owner with full administrative access."""

    ADMIN = "ADMIN"
    """Organization admin - can manage members and settings."""

    MEMBER = "MEMBER"
    """Regular member - inherits organization's PolicyBind role."""

    VIEWER = "VIEWER"
    """Read-only access to organization resources."""


class TenantStatus(Enum):
    """
    Status of a tenant within an organization.

    A tenant represents an isolated environment (e.g., production, staging).
    """

    ACTIVE = "ACTIVE"
    """Tenant is fully operational."""

    SUSPENDED = "SUSPENDED"
    """Tenant is suspended - all access denied."""

    PROVISIONING = "PROVISIONING"
    """Tenant is being set up."""

    ARCHIVED = "ARCHIVED"
    """Tenant is archived and read-only."""


@dataclass(frozen=True)
class TenantQuota:
    """
    Resource quotas for a tenant.

    Defines limits on resources a tenant can consume.

    Attributes:
        max_policies: Maximum number of policies.
        max_deployments: Maximum number of model deployments.
        max_tokens: Maximum number of access tokens.
        max_requests_per_minute: Rate limit for enforcement requests.
        max_requests_per_day: Daily limit for enforcement requests.
        max_storage_bytes: Maximum storage in bytes.
        max_incident_retention_days: Days to retain incidents.
        max_audit_retention_days: Days to retain audit logs.
    """

    max_policies: int = 100
    max_deployments: int = 50
    max_tokens: int = 100
    max_requests_per_minute: int = 1000
    max_requests_per_day: int = 100000
    max_storage_bytes: int = 1073741824  # 1 GB
    max_incident_retention_days: int = 90
    max_audit_retention_days: int = 365

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the quota to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the quota to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"TenantQuota(policies={self.max_policies}, "
            f"deployments={self.max_deployments}, "
            f"rpm={self.max_requests_per_minute})"
        )


@dataclass(frozen=True)
class Tenant:
    """
    Represents a tenant within an organization.

    A tenant is an isolated environment that contains its own policies,
    deployments, tokens, and incidents. Organizations can have multiple
    tenants (e.g., production, staging, development).

    This class is immutable (frozen) to ensure tenant records maintain
    their integrity. Updates should create new records with updated values.

    Attributes:
        id: Unique identifier for the database record.
        created_at: Timestamp when the tenant was created.
        updated_at: Timestamp when the tenant was last modified.
        tenant_id: Unique identifier for the tenant (used in API).
        organization_id: ID of the parent organization.
        name: Human-readable name for the tenant.
        slug: URL-friendly identifier (e.g., "production", "staging").
        description: Description of the tenant's purpose.
        status: Current status of the tenant.
        quota: Resource quotas for this tenant.
        settings: Tenant-specific settings.
        metadata: Additional key-value metadata.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    tenant_id: str = field(default_factory=generate_uuid)
    organization_id: str = ""
    name: str = ""
    slug: str = ""
    description: str = ""
    status: TenantStatus = TenantStatus.ACTIVE
    quota: TenantQuota = field(default_factory=TenantQuota)
    settings: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the tenant to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the tenant to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the tenant's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on tenant id."""
        if not isinstance(other, Tenant):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"Tenant(id={self.tenant_id!r}, name={self.name!r}, "
            f"org={self.organization_id!r}, status={self.status.value})"
        )

    def is_active(self) -> bool:
        """Check if the tenant is active."""
        return self.status == TenantStatus.ACTIVE

    def is_suspended(self) -> bool:
        """Check if the tenant is suspended."""
        return self.status == TenantStatus.SUSPENDED


@dataclass(frozen=True)
class OrganizationMember:
    """
    Represents a member of an organization.

    Links users to organizations with specific roles.

    Attributes:
        id: Unique identifier for the database record.
        organization_id: ID of the organization.
        user_id: ID or identifier of the user.
        role: Role within the organization.
        email: User's email address.
        display_name: User's display name.
        joined_at: When the user joined the organization.
        invited_by: ID of the user who invited this member.
        last_active_at: Last activity timestamp.
        metadata: Additional key-value metadata.
    """

    id: str = field(default_factory=generate_uuid)
    organization_id: str = ""
    user_id: str = ""
    role: OrganizationRole = OrganizationRole.MEMBER
    email: str = ""
    display_name: str = ""
    joined_at: datetime = field(default_factory=utc_now)
    invited_by: str | None = None
    last_active_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the member to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the member to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the member's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on member id."""
        if not isinstance(other, OrganizationMember):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"OrganizationMember(user={self.user_id!r}, org={self.organization_id!r}, "
            f"role={self.role.value})"
        )

    def is_admin(self) -> bool:
        """Check if the member has admin privileges."""
        return self.role in (OrganizationRole.OWNER, OrganizationRole.ADMIN)

    def is_owner(self) -> bool:
        """Check if the member is the owner."""
        return self.role == OrganizationRole.OWNER


@dataclass(frozen=True)
class Organization:
    """
    Represents an organization in PolicyBind.

    An organization is the top-level entity that contains tenants, members,
    and billing information. Each organization is isolated from others.

    This class is immutable (frozen) to ensure organization records maintain
    their integrity. Updates should create new records with updated values.

    Attributes:
        id: Unique identifier for the database record.
        created_at: Timestamp when the organization was created.
        updated_at: Timestamp when the organization was last modified.
        organization_id: Unique identifier for the organization (used in API).
        name: Human-readable name for the organization.
        slug: URL-friendly identifier (e.g., "acme-corp").
        status: Current status of the organization.
        billing_email: Email for billing notifications.
        plan: Subscription plan (free, pro, enterprise, etc.).
        default_tenant_quota: Default quotas for new tenants.
        settings: Organization-wide settings.
        metadata: Additional key-value metadata.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    organization_id: str = field(default_factory=generate_uuid)
    name: str = ""
    slug: str = ""
    status: OrganizationStatus = OrganizationStatus.PENDING
    billing_email: str = ""
    plan: str = "free"
    default_tenant_quota: TenantQuota = field(default_factory=TenantQuota)
    settings: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the organization to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the organization to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the organization's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on organization id."""
        if not isinstance(other, Organization):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"Organization(id={self.organization_id!r}, name={self.name!r}, "
            f"status={self.status.value}, plan={self.plan!r})"
        )

    def is_active(self) -> bool:
        """Check if the organization is active."""
        return self.status == OrganizationStatus.ACTIVE

    def is_suspended(self) -> bool:
        """Check if the organization is suspended."""
        return self.status == OrganizationStatus.SUSPENDED

    def is_enterprise(self) -> bool:
        """Check if the organization is on an enterprise plan."""
        return self.plan == "enterprise"


@dataclass
class TenantContext:
    """
    Tenant context for a request.

    Contains information about the current tenant context for request
    processing, including organization and tenant identifiers and quotas.

    This class is mutable to allow updates during request processing.

    Attributes:
        has_tenant: Whether a tenant context is present.
        organization_id: ID of the current organization.
        tenant_id: ID of the current tenant.
        organization: Full organization object (optional).
        tenant: Full tenant object (optional).
        quota: Current tenant quota.
        is_admin: Whether the user is an organization admin.
        member_role: User's role in the organization.
    """

    has_tenant: bool = False
    organization_id: str = ""
    tenant_id: str = ""
    organization: Organization | None = None
    tenant: Tenant | None = None
    quota: TenantQuota | None = None
    is_admin: bool = False
    member_role: OrganizationRole | None = None

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the context to a dictionary."""
        result = {
            "has_tenant": self.has_tenant,
            "organization_id": self.organization_id,
            "tenant_id": self.tenant_id,
            "is_admin": self.is_admin,
        }

        if self.organization:
            result["organization_name"] = self.organization.name
            result["organization_status"] = self.organization.status.value

        if self.tenant:
            result["tenant_name"] = self.tenant.name
            result["tenant_status"] = self.tenant.status.value

        if self.quota:
            result["quota"] = self.quota.to_dict()

        if self.member_role:
            result["member_role"] = self.member_role.value

        if exclude_none:
            result = {k: v for k, v in result.items() if v is not None}

        return result

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        if not self.has_tenant:
            return "TenantContext(has_tenant=False)"
        return (
            f"TenantContext(org={self.organization_id!r}, "
            f"tenant={self.tenant_id!r}, admin={self.is_admin})"
        )

    def is_valid(self) -> bool:
        """Check if the context is valid for request processing."""
        if not self.has_tenant:
            return False
        if not self.organization_id or not self.tenant_id:
            return False
        if self.organization and not self.organization.is_active():
            return False
        if self.tenant and not self.tenant.is_active():
            return False
        return True

    def can_manage_organization(self) -> bool:
        """Check if the user can manage the organization."""
        return self.is_admin or self.member_role in (
            OrganizationRole.OWNER,
            OrganizationRole.ADMIN,
        )

    def get_quota(self) -> TenantQuota:
        """Get the effective quota for this context."""
        if self.quota:
            return self.quota
        if self.tenant:
            return self.tenant.quota
        return TenantQuota()


@dataclass(frozen=True)
class TenantUsage:
    """
    Current resource usage for a tenant.

    Tracks how much of a tenant's quota has been consumed.

    Attributes:
        tenant_id: ID of the tenant.
        policy_count: Current number of policies.
        deployment_count: Current number of deployments.
        token_count: Current number of access tokens.
        requests_today: Requests made today.
        storage_bytes: Storage used in bytes.
        incident_count: Active incident count.
        measured_at: When the usage was measured.
    """

    tenant_id: str = ""
    policy_count: int = 0
    deployment_count: int = 0
    token_count: int = 0
    requests_today: int = 0
    storage_bytes: int = 0
    incident_count: int = 0
    measured_at: datetime = field(default_factory=utc_now)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the usage to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the usage to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"TenantUsage(tenant={self.tenant_id!r}, "
            f"policies={self.policy_count}, "
            f"requests_today={self.requests_today})"
        )

    def check_quota(self, quota: TenantQuota) -> dict[str, bool]:
        """
        Check which quotas have been exceeded.

        Args:
            quota: The quota to check against.

        Returns:
            Dictionary with resource names and whether they're exceeded.
        """
        return {
            "policies": self.policy_count >= quota.max_policies,
            "deployments": self.deployment_count >= quota.max_deployments,
            "tokens": self.token_count >= quota.max_tokens,
            "requests_today": self.requests_today >= quota.max_requests_per_day,
            "storage": self.storage_bytes >= quota.max_storage_bytes,
        }

    def get_exceeded_quotas(self, quota: TenantQuota) -> list[str]:
        """
        Get list of exceeded quota names.

        Args:
            quota: The quota to check against.

        Returns:
            List of exceeded resource names.
        """
        check = self.check_quota(quota)
        return [name for name, exceeded in check.items() if exceeded]
