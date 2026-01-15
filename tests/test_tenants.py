"""
Tests for multi-tenant support in PolicyBind.

Tests cover organization and tenant models, manager, middleware, and API handlers.
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone

from policybind.tenants import (
    MemberNotFoundError,
    Organization,
    OrganizationMember,
    OrganizationNotFoundError,
    OrganizationRole,
    OrganizationStatus,
    QuotaExceededError,
    Tenant,
    TenantContext,
    TenantManager,
    TenantNotFoundError,
    TenantQuota,
    TenantStatus,
    TenantUsage,
    ValidationError,
)


# =============================================================================
# Model Tests
# =============================================================================


class TestTenantQuota:
    """Tests for TenantQuota model."""

    def test_default_values(self) -> None:
        """Test default quota values."""
        quota = TenantQuota()
        assert quota.max_policies == 100
        assert quota.max_deployments == 50
        assert quota.max_tokens == 100
        assert quota.max_requests_per_minute == 1000
        assert quota.max_requests_per_day == 100000
        assert quota.max_storage_bytes == 1073741824  # 1 GB

    def test_custom_values(self) -> None:
        """Test custom quota values."""
        quota = TenantQuota(max_policies=500, max_deployments=200)
        assert quota.max_policies == 500
        assert quota.max_deployments == 200

    def test_to_dict(self) -> None:
        """Test serialization."""
        quota = TenantQuota(max_policies=50)
        data = quota.to_dict()
        assert data["max_policies"] == 50
        assert "max_deployments" in data


class TestTenant:
    """Tests for Tenant model."""

    def test_create_tenant(self) -> None:
        """Test tenant creation."""
        tenant = Tenant(
            organization_id="org-123",
            name="Production",
            slug="production",
        )
        assert tenant.tenant_id
        assert tenant.organization_id == "org-123"
        assert tenant.name == "Production"
        assert tenant.slug == "production"
        assert tenant.status == TenantStatus.ACTIVE

    def test_is_active(self) -> None:
        """Test active status check."""
        tenant = Tenant(status=TenantStatus.ACTIVE)
        assert tenant.is_active()
        assert not tenant.is_suspended()

    def test_is_suspended(self) -> None:
        """Test suspended status check."""
        tenant = Tenant(status=TenantStatus.SUSPENDED)
        assert tenant.is_suspended()
        assert not tenant.is_active()

    def test_to_dict(self) -> None:
        """Test serialization."""
        tenant = Tenant(name="Test", slug="test")
        data = tenant.to_dict()
        assert data["name"] == "Test"
        assert data["slug"] == "test"
        assert "quota" in data


class TestOrganization:
    """Tests for Organization model."""

    def test_create_organization(self) -> None:
        """Test organization creation."""
        org = Organization(
            name="Acme Corp",
            slug="acme-corp",
            billing_email="billing@acme.com",
            plan="pro",
        )
        assert org.organization_id
        assert org.name == "Acme Corp"
        assert org.slug == "acme-corp"
        assert org.plan == "pro"
        assert org.status == OrganizationStatus.PENDING

    def test_is_active(self) -> None:
        """Test active status check."""
        org = Organization(status=OrganizationStatus.ACTIVE)
        assert org.is_active()

    def test_is_enterprise(self) -> None:
        """Test enterprise plan check."""
        org = Organization(plan="enterprise")
        assert org.is_enterprise()

        org2 = Organization(plan="pro")
        assert not org2.is_enterprise()


class TestOrganizationMember:
    """Tests for OrganizationMember model."""

    def test_create_member(self) -> None:
        """Test member creation."""
        member = OrganizationMember(
            organization_id="org-123",
            user_id="user-456",
            role=OrganizationRole.ADMIN,
            email="admin@example.com",
        )
        assert member.organization_id == "org-123"
        assert member.user_id == "user-456"
        assert member.role == OrganizationRole.ADMIN

    def test_is_admin(self) -> None:
        """Test admin check."""
        admin = OrganizationMember(role=OrganizationRole.ADMIN)
        owner = OrganizationMember(role=OrganizationRole.OWNER)
        member = OrganizationMember(role=OrganizationRole.MEMBER)

        assert admin.is_admin()
        assert owner.is_admin()
        assert not member.is_admin()

    def test_is_owner(self) -> None:
        """Test owner check."""
        owner = OrganizationMember(role=OrganizationRole.OWNER)
        admin = OrganizationMember(role=OrganizationRole.ADMIN)

        assert owner.is_owner()
        assert not admin.is_owner()


class TestTenantContext:
    """Tests for TenantContext model."""

    def test_empty_context(self) -> None:
        """Test empty context."""
        context = TenantContext()
        assert not context.has_tenant
        assert context.organization_id == ""
        assert context.tenant_id == ""
        assert not context.is_valid()

    def test_valid_context(self) -> None:
        """Test valid context."""
        org = Organization(status=OrganizationStatus.ACTIVE)
        tenant = Tenant(status=TenantStatus.ACTIVE)
        context = TenantContext(
            has_tenant=True,
            organization_id=org.organization_id,
            tenant_id=tenant.tenant_id,
            organization=org,
            tenant=tenant,
        )
        assert context.has_tenant
        assert context.is_valid()

    def test_can_manage_organization(self) -> None:
        """Test organization management check."""
        context = TenantContext(
            has_tenant=True,
            is_admin=True,
        )
        assert context.can_manage_organization()

        context2 = TenantContext(
            has_tenant=True,
            member_role=OrganizationRole.OWNER,
        )
        assert context2.can_manage_organization()


class TestTenantUsage:
    """Tests for TenantUsage model."""

    def test_check_quota(self) -> None:
        """Test quota check."""
        usage = TenantUsage(
            tenant_id="t-123",
            policy_count=100,
            deployment_count=30,
        )
        quota = TenantQuota(max_policies=100, max_deployments=50)

        check = usage.check_quota(quota)
        assert check["policies"]  # At limit
        assert not check["deployments"]  # Under limit

    def test_get_exceeded_quotas(self) -> None:
        """Test exceeded quota list."""
        usage = TenantUsage(
            policy_count=150,
            requests_today=200000,
        )
        quota = TenantQuota(max_policies=100, max_requests_per_day=100000)

        exceeded = usage.get_exceeded_quotas(quota)
        assert "policies" in exceeded
        assert "requests_today" in exceeded
        assert "deployments" not in exceeded


# =============================================================================
# Manager Tests
# =============================================================================


class TestTenantManager:
    """Tests for TenantManager."""

    @pytest.fixture
    def manager(self) -> TenantManager:
        """Create a tenant manager."""
        return TenantManager()

    def test_create_organization(self, manager: TenantManager) -> None:
        """Test organization creation."""
        org = manager.create_organization(
            name="Acme Corp",
            slug="acme-corp",
            billing_email="billing@acme.com",
            plan="pro",
        )
        assert org.name == "Acme Corp"
        assert org.slug == "acme-corp"
        assert org.status == OrganizationStatus.ACTIVE

        # Should create a default tenant
        tenants = manager.list_tenants(org.organization_id)
        assert len(tenants) == 1
        assert tenants[0].slug == "production"

    def test_create_organization_with_owner(self, manager: TenantManager) -> None:
        """Test organization creation with owner."""
        org = manager.create_organization(
            name="Test Org",
            slug="test-org",
            owner_user_id="user-123",
            owner_email="owner@test.org",
        )

        members = manager.list_members(org.organization_id)
        assert len(members) == 1
        assert members[0].role == OrganizationRole.OWNER

    def test_create_organization_invalid_slug(self, manager: TenantManager) -> None:
        """Test organization creation with invalid slug."""
        with pytest.raises(ValidationError):
            manager.create_organization(name="Test", slug="AB")  # Too short

        with pytest.raises(ValidationError):
            manager.create_organization(name="Test", slug="UPPER")  # Uppercase

        with pytest.raises(ValidationError):
            manager.create_organization(name="Test", slug="123abc")  # Starts with number

    def test_create_organization_duplicate_slug(self, manager: TenantManager) -> None:
        """Test organization creation with duplicate slug."""
        manager.create_organization(name="First", slug="test-org")

        with pytest.raises(ValidationError):
            manager.create_organization(name="Second", slug="test-org")

    def test_get_organization(self, manager: TenantManager) -> None:
        """Test getting organization."""
        org = manager.create_organization(name="Test", slug="test-org")

        fetched = manager.get_organization(org.organization_id)
        assert fetched.name == "Test"

        with pytest.raises(OrganizationNotFoundError):
            manager.get_organization("nonexistent")

    def test_get_organization_by_slug(self, manager: TenantManager) -> None:
        """Test getting organization by slug."""
        org = manager.create_organization(name="Test", slug="test-org")

        fetched = manager.get_organization_by_slug("test-org")
        assert fetched.organization_id == org.organization_id

    def test_list_organizations(self, manager: TenantManager) -> None:
        """Test listing organizations."""
        manager.create_organization(name="Org 1", slug="org-one", plan="free")
        manager.create_organization(name="Org 2", slug="org-two", plan="pro")
        manager.create_organization(name="Org 3", slug="org-three", plan="pro")

        # All organizations
        all_orgs = manager.list_organizations()
        assert len(all_orgs) == 3

        # Filter by plan
        pro_orgs = manager.list_organizations(plan="pro")
        assert len(pro_orgs) == 2

    def test_update_organization(self, manager: TenantManager) -> None:
        """Test updating organization."""
        org = manager.create_organization(name="Old Name", slug="test-org")

        updated = manager.update_organization(
            org.organization_id,
            name="New Name",
            plan="enterprise",
        )
        assert updated.name == "New Name"
        assert updated.plan == "enterprise"

    def test_suspend_organization(self, manager: TenantManager) -> None:
        """Test suspending organization."""
        org = manager.create_organization(name="Test", slug="test-org")

        suspended = manager.suspend_organization(org.organization_id, reason="Payment")
        assert suspended.status == OrganizationStatus.SUSPENDED
        assert suspended.metadata.get("suspension_reason") == "Payment"

    def test_activate_organization(self, manager: TenantManager) -> None:
        """Test activating organization."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.suspend_organization(org.organization_id)

        activated = manager.activate_organization(org.organization_id)
        assert activated.status == OrganizationStatus.ACTIVE

    def test_delete_organization(self, manager: TenantManager) -> None:
        """Test deleting organization."""
        org = manager.create_organization(name="Test", slug="test-org")

        # Archive (soft delete)
        manager.delete_organization(org.organization_id)
        archived = manager.get_organization(org.organization_id)
        assert archived.status == OrganizationStatus.ARCHIVED

        # Hard delete
        org2 = manager.create_organization(name="Test 2", slug="test-org-two")
        manager.delete_organization(org2.organization_id, hard_delete=True)

        with pytest.raises(OrganizationNotFoundError):
            manager.get_organization(org2.organization_id)

    def test_create_tenant(self, manager: TenantManager) -> None:
        """Test tenant creation."""
        org = manager.create_organization(name="Test", slug="test-org")

        tenant = manager.create_tenant(
            organization_id=org.organization_id,
            name="Staging",
            slug="staging",
            description="Staging environment",
        )
        assert tenant.name == "Staging"
        assert tenant.organization_id == org.organization_id

    def test_create_tenant_invalid_slug(self, manager: TenantManager) -> None:
        """Test tenant creation with invalid slug."""
        org = manager.create_organization(name="Test", slug="test-org")

        with pytest.raises(ValidationError):
            manager.create_tenant(
                organization_id=org.organization_id,
                name="Test",
                slug="AB",  # Too short
            )

    def test_create_tenant_duplicate_slug(self, manager: TenantManager) -> None:
        """Test tenant creation with duplicate slug within org."""
        org = manager.create_organization(name="Test", slug="test-org")

        manager.create_tenant(
            organization_id=org.organization_id,
            name="First",
            slug="staging",
        )

        with pytest.raises(ValidationError):
            manager.create_tenant(
                organization_id=org.organization_id,
                name="Second",
                slug="staging",  # Duplicate
            )

    def test_get_tenant(self, manager: TenantManager) -> None:
        """Test getting tenant."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(
            organization_id=org.organization_id,
            name="Staging",
            slug="staging",
        )

        fetched = manager.get_tenant(tenant.tenant_id)
        assert fetched.name == "Staging"

        with pytest.raises(TenantNotFoundError):
            manager.get_tenant("nonexistent")

    def test_get_tenant_by_slug(self, manager: TenantManager) -> None:
        """Test getting tenant by slug."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(
            organization_id=org.organization_id,
            name="Staging",
            slug="staging",
        )

        fetched = manager.get_tenant_by_slug(org.organization_id, "staging")
        assert fetched.tenant_id == tenant.tenant_id

    def test_list_tenants(self, manager: TenantManager) -> None:
        """Test listing tenants."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.create_tenant(org.organization_id, "Dev", "development")
        manager.create_tenant(org.organization_id, "Staging", "staging")

        # Default tenant + 2 created
        tenants = manager.list_tenants(org.organization_id)
        assert len(tenants) == 3

    def test_update_tenant(self, manager: TenantManager) -> None:
        """Test updating tenant."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(org.organization_id, "Old", "staging")

        updated = manager.update_tenant(tenant.tenant_id, name="New Name")
        assert updated.name == "New Name"

    def test_suspend_activate_tenant(self, manager: TenantManager) -> None:
        """Test suspending and activating tenant."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(org.organization_id, "Test", "staging")

        suspended = manager.suspend_tenant(tenant.tenant_id, "Quota exceeded")
        assert suspended.status == TenantStatus.SUSPENDED

        activated = manager.activate_tenant(tenant.tenant_id)
        assert activated.status == TenantStatus.ACTIVE

    def test_delete_tenant(self, manager: TenantManager) -> None:
        """Test deleting tenant."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(org.organization_id, "Test", "staging")

        manager.delete_tenant(tenant.tenant_id, hard_delete=True)

        with pytest.raises(TenantNotFoundError):
            manager.get_tenant(tenant.tenant_id)

    def test_add_member(self, manager: TenantManager) -> None:
        """Test adding member."""
        org = manager.create_organization(name="Test", slug="test-org")

        member = manager.add_member(
            organization_id=org.organization_id,
            user_id="user-123",
            role=OrganizationRole.MEMBER,
            email="user@test.org",
        )
        assert member.user_id == "user-123"
        assert member.role == OrganizationRole.MEMBER

    def test_add_member_duplicate(self, manager: TenantManager) -> None:
        """Test adding duplicate member."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.add_member(org.organization_id, "user-123", OrganizationRole.MEMBER)

        with pytest.raises(ValidationError):
            manager.add_member(org.organization_id, "user-123", OrganizationRole.ADMIN)

    def test_get_member(self, manager: TenantManager) -> None:
        """Test getting member."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.add_member(org.organization_id, "user-123", OrganizationRole.MEMBER)

        member = manager.get_member(org.organization_id, "user-123")
        assert member is not None
        assert member.user_id == "user-123"

        # Non-existent member
        assert manager.get_member(org.organization_id, "user-999") is None

    def test_list_members(self, manager: TenantManager) -> None:
        """Test listing members."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.add_member(org.organization_id, "user-1", OrganizationRole.ADMIN)
        manager.add_member(org.organization_id, "user-2", OrganizationRole.MEMBER)
        manager.add_member(org.organization_id, "user-3", OrganizationRole.MEMBER)

        # All members
        all_members = manager.list_members(org.organization_id)
        assert len(all_members) == 3

        # Filter by role
        members = manager.list_members(org.organization_id, role=OrganizationRole.MEMBER)
        assert len(members) == 2

    def test_update_member_role(self, manager: TenantManager) -> None:
        """Test updating member role."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.add_member(org.organization_id, "user-123", OrganizationRole.MEMBER)

        updated = manager.update_member_role(
            org.organization_id, "user-123", OrganizationRole.ADMIN
        )
        assert updated.role == OrganizationRole.ADMIN

    def test_remove_member(self, manager: TenantManager) -> None:
        """Test removing member."""
        org = manager.create_organization(name="Test", slug="test-org")
        manager.add_member(org.organization_id, "user-123", OrganizationRole.MEMBER)

        manager.remove_member(org.organization_id, "user-123")
        assert manager.get_member(org.organization_id, "user-123") is None

    def test_remove_owner_fails(self, manager: TenantManager) -> None:
        """Test that removing owner fails."""
        org = manager.create_organization(
            name="Test",
            slug="test-org",
            owner_user_id="owner-123",
        )

        with pytest.raises(ValidationError):
            manager.remove_member(org.organization_id, "owner-123")

    def test_get_usage(self, manager: TenantManager) -> None:
        """Test getting usage."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenants = manager.list_tenants(org.organization_id)
        tenant = tenants[0]

        usage = manager.get_usage(tenant.tenant_id)
        assert usage.tenant_id == tenant.tenant_id
        assert usage.policy_count == 0

    def test_update_usage(self, manager: TenantManager) -> None:
        """Test updating usage."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenants = manager.list_tenants(org.organization_id)
        tenant = tenants[0]

        updated = manager.update_usage(
            tenant.tenant_id,
            policy_count=50,
            requests_today=1000,
        )
        assert updated.policy_count == 50
        assert updated.requests_today == 1000

    def test_check_quota(self, manager: TenantManager) -> None:
        """Test quota checking."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(
            org.organization_id,
            "Test",
            "test-env",
            quota=TenantQuota(max_policies=10),
        )

        # Initially allowed
        assert manager.check_quota(tenant.tenant_id, "policies")

        # Update to limit
        manager.update_usage(tenant.tenant_id, policy_count=10)

        # Now at limit
        assert not manager.check_quota(tenant.tenant_id, "policies")

    def test_enforce_quota(self, manager: TenantManager) -> None:
        """Test quota enforcement."""
        org = manager.create_organization(name="Test", slug="test-org")
        tenant = manager.create_tenant(
            org.organization_id,
            "Test",
            "test-env",
            quota=TenantQuota(max_policies=5),
        )
        manager.update_usage(tenant.tenant_id, policy_count=5)

        with pytest.raises(QuotaExceededError) as exc_info:
            manager.enforce_quota(tenant.tenant_id, "policies")

        assert exc_info.value.resource == "policies"
        assert exc_info.value.limit == 5
        assert exc_info.value.current == 5

    def test_event_callbacks(self, manager: TenantManager) -> None:
        """Test event callback system."""
        events = []

        def callback(event_type: str, data: dict) -> None:
            events.append((event_type, data))

        manager.on_event(callback)

        org = manager.create_organization(name="Test", slug="test-org")
        manager.suspend_organization(org.organization_id)

        assert len(events) >= 2
        event_types = [e[0] for e in events]
        assert "organization.created" in event_types
        assert "organization.suspended" in event_types


# =============================================================================
# Middleware Tests (Unit Tests)
# =============================================================================


class TestMiddlewareHelpers:
    """Tests for middleware helper functions."""

    def test_get_tenant_filter_no_context(self) -> None:
        """Test get_tenant_filter with no context."""
        from policybind.tenants.middleware import get_tenant_filter

        class MockRequest(dict):
            pass

        request = MockRequest()
        filter_data = get_tenant_filter(request)
        assert filter_data == {}

    def test_get_tenant_context_no_context(self) -> None:
        """Test get_tenant_context with no context."""
        from policybind.tenants.middleware import get_tenant_context

        class MockRequest(dict):
            pass

        request = MockRequest()
        context = get_tenant_context(request)
        assert not context.has_tenant


# =============================================================================
# API Handler Tests
# =============================================================================


class TestTenantHandlers:
    """Tests for tenant API handlers."""

    @pytest.fixture
    def setup_handlers(self) -> TenantManager:
        """Set up handlers with a tenant manager."""
        from policybind.server.handlers import tenant_handlers

        manager = TenantManager()
        tenant_handlers.set_tenant_manager(manager)
        return manager

    def test_handler_manager_lifecycle(self, setup_handlers: TenantManager) -> None:
        """Test handler manager getter/setter."""
        from policybind.server.handlers import tenant_handlers

        manager = tenant_handlers.get_tenant_manager()
        assert manager is not None

        tenant_handlers.set_tenant_manager(None)
        assert tenant_handlers.get_tenant_manager() is None

        # Restore for other tests
        tenant_handlers.set_tenant_manager(setup_handlers)


# =============================================================================
# Integration Tests with aiohttp
# =============================================================================


@pytest.fixture
def aiohttp_available():
    """Check if aiohttp is available."""
    return pytest.importorskip("aiohttp")


class TestTenantAPIIntegration:
    """Integration tests for tenant API with aiohttp."""

    @pytest.fixture
    def app(self, aiohttp_available):
        """Create test application."""
        from aiohttp import web
        from policybind.server.handlers import tenant_handlers
        from policybind.server.auth import AuthContext, Role

        manager = TenantManager()
        tenant_handlers.set_tenant_manager(manager)

        app = web.Application()

        # Add mock auth middleware
        @web.middleware
        async def mock_auth(request, handler):
            request["auth_context"] = AuthContext(
                authenticated=True,
                role=Role.ADMIN,
                identity="test-admin",
            )
            return await handler(request)

        app.middlewares.append(mock_auth)

        # Add routes
        app.router.add_get("/v1/orgs", tenant_handlers.list_organizations)
        app.router.add_post("/v1/orgs", tenant_handlers.create_organization)
        app.router.add_get("/v1/orgs/{org_id}", tenant_handlers.get_organization)
        app.router.add_put("/v1/orgs/{org_id}", tenant_handlers.update_organization)
        app.router.add_delete("/v1/orgs/{org_id}", tenant_handlers.delete_organization)
        app.router.add_post(
            "/v1/orgs/{org_id}/suspend", tenant_handlers.suspend_organization
        )
        app.router.add_post(
            "/v1/orgs/{org_id}/activate", tenant_handlers.activate_organization
        )
        app.router.add_get(
            "/v1/orgs/{org_id}/tenants", tenant_handlers.list_tenants
        )
        app.router.add_post(
            "/v1/orgs/{org_id}/tenants", tenant_handlers.create_tenant
        )
        app.router.add_get(
            "/v1/orgs/{org_id}/tenants/{tenant_id}", tenant_handlers.get_tenant
        )
        app.router.add_get(
            "/v1/orgs/{org_id}/members", tenant_handlers.list_members
        )
        app.router.add_post(
            "/v1/orgs/{org_id}/members", tenant_handlers.add_member
        )

        return app

    @pytest_asyncio.fixture
    async def client(self, app, aiohttp_available):
        """Create test client."""
        from aiohttp.test_utils import TestClient, TestServer

        server = TestServer(app)
        client = TestClient(server)
        await client.start_server()
        yield client
        await client.close()

    @pytest.mark.asyncio
    async def test_list_organizations_empty(self, client) -> None:
        """Test listing organizations when empty."""
        resp = await client.get("/v1/orgs")
        assert resp.status == 200

        data = await resp.json()
        assert data["organizations"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_create_organization(self, client) -> None:
        """Test creating an organization."""
        resp = await client.post("/v1/orgs", json={
            "name": "Acme Corp",
            "slug": "acme-corp",
            "billing_email": "billing@acme.com",
            "plan": "pro",
        })
        assert resp.status == 201

        data = await resp.json()
        assert data["name"] == "Acme Corp"
        assert data["slug"] == "acme-corp"
        assert data["plan"] == "pro"

    @pytest.mark.asyncio
    async def test_create_organization_invalid_slug(self, client) -> None:
        """Test creating organization with invalid slug."""
        resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "AB",  # Too short
        })
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_get_organization(self, client) -> None:
        """Test getting an organization."""
        # Create first
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test Org",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Get
        resp = await client.get(f"/v1/orgs/{org_id}")
        assert resp.status == 200

        data = await resp.json()
        assert data["name"] == "Test Org"

    @pytest.mark.asyncio
    async def test_get_organization_not_found(self, client) -> None:
        """Test getting non-existent organization."""
        resp = await client.get("/v1/orgs/nonexistent")
        assert resp.status == 404

    @pytest.mark.asyncio
    async def test_update_organization(self, client) -> None:
        """Test updating an organization."""
        # Create first
        create_resp = await client.post("/v1/orgs", json={
            "name": "Old Name",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Update
        resp = await client.put(f"/v1/orgs/{org_id}", json={
            "name": "New Name",
            "plan": "enterprise",
        })
        assert resp.status == 200

        data = await resp.json()
        assert data["name"] == "New Name"
        assert data["plan"] == "enterprise"

    @pytest.mark.asyncio
    async def test_suspend_organization(self, client) -> None:
        """Test suspending an organization."""
        # Create first
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Suspend
        resp = await client.post(f"/v1/orgs/{org_id}/suspend", json={
            "reason": "Payment overdue",
        })
        assert resp.status == 200

        data = await resp.json()
        assert data["status"] == "SUSPENDED"

    @pytest.mark.asyncio
    async def test_activate_organization(self, client) -> None:
        """Test activating an organization."""
        # Create and suspend
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        await client.post(f"/v1/orgs/{org_id}/suspend", json={})

        # Activate
        resp = await client.post(f"/v1/orgs/{org_id}/activate")
        assert resp.status == 200

        data = await resp.json()
        assert data["status"] == "ACTIVE"

    @pytest.mark.asyncio
    async def test_delete_organization(self, client) -> None:
        """Test deleting an organization."""
        # Create first
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Archive (soft delete)
        resp = await client.delete(f"/v1/orgs/{org_id}")
        assert resp.status == 200

        # Verify archived
        get_resp = await client.get(f"/v1/orgs/{org_id}")
        get_data = await get_resp.json()
        assert get_data["status"] == "ARCHIVED"

    @pytest.mark.asyncio
    async def test_list_tenants(self, client) -> None:
        """Test listing tenants."""
        # Create org
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # List tenants (should have default)
        resp = await client.get(f"/v1/orgs/{org_id}/tenants")
        assert resp.status == 200

        data = await resp.json()
        assert len(data["tenants"]) == 1  # Default production tenant

    @pytest.mark.asyncio
    async def test_create_tenant(self, client) -> None:
        """Test creating a tenant."""
        # Create org
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Create tenant
        resp = await client.post(f"/v1/orgs/{org_id}/tenants", json={
            "name": "Staging",
            "slug": "staging",
            "description": "Staging environment",
        })
        assert resp.status == 201

        data = await resp.json()
        assert data["name"] == "Staging"
        assert data["slug"] == "staging"

    @pytest.mark.asyncio
    async def test_get_tenant(self, client) -> None:
        """Test getting a tenant."""
        # Create org
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Create tenant
        tenant_resp = await client.post(f"/v1/orgs/{org_id}/tenants", json={
            "name": "Staging",
            "slug": "staging",
        })
        tenant_data = await tenant_resp.json()
        tenant_id = tenant_data["tenant_id"]

        # Get tenant
        resp = await client.get(f"/v1/orgs/{org_id}/tenants/{tenant_id}")
        assert resp.status == 200

        data = await resp.json()
        assert data["name"] == "Staging"
        assert "usage" in data

    @pytest.mark.asyncio
    async def test_list_members(self, client) -> None:
        """Test listing members."""
        # Create org
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # List members (should be empty for this test)
        resp = await client.get(f"/v1/orgs/{org_id}/members")
        assert resp.status == 200

        data = await resp.json()
        assert "members" in data

    @pytest.mark.asyncio
    async def test_add_member(self, client) -> None:
        """Test adding a member."""
        # Create org
        create_resp = await client.post("/v1/orgs", json={
            "name": "Test",
            "slug": "test-org",
        })
        create_data = await create_resp.json()
        org_id = create_data["organization_id"]

        # Add member
        resp = await client.post(f"/v1/orgs/{org_id}/members", json={
            "user_id": "user-123",
            "role": "MEMBER",
            "email": "user@test.org",
        })
        assert resp.status == 201

        data = await resp.json()
        assert data["user_id"] == "user-123"
        assert data["role"] == "MEMBER"
