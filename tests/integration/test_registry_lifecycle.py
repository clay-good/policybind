"""
Integration tests for model registry lifecycle.

This module tests the complete deployment lifecycle including:
- Registration
- Approval workflows
- Usage tracking
- Suspension and reinstatement
"""

import pytest

from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel
from policybind.registry.manager import DeploymentEventType, RegistryManager
from policybind.registry.risk import RiskAssessor
from policybind.registry.validator import DeploymentValidator
from policybind.registry.compliance import ComplianceChecker
from policybind.storage.database import Database
from policybind.storage.repositories import RegistryRepository


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    db = Database(":memory:")
    db.initialize()
    yield db
    db.close()


@pytest.fixture
def registry_repo(temp_db: Database) -> RegistryRepository:
    """Create a registry repository."""
    return RegistryRepository(temp_db)


@pytest.fixture
def registry_manager(registry_repo: RegistryRepository) -> RegistryManager:
    """Create a registry manager."""
    return RegistryManager(repository=registry_repo)


@pytest.fixture
def inmemory_registry_manager() -> RegistryManager:
    """Create a registry manager without database persistence (in-memory only)."""
    return RegistryManager()


# =============================================================================
# Registration Tests
# =============================================================================


class TestDeploymentRegistration:
    """Tests for deployment registration."""

    def test_register_new_deployment(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test registering a new deployment."""
        deployment = inmemory_registry_manager.register(
            name="Test GPT-4 Deployment",
            description="A test deployment for GPT-4",
            model_provider="openai",
            model_name="gpt-4",
            owner="engineering-team",
            owner_contact="eng@example.com",
            risk_level=RiskLevel.MEDIUM,
        )

        assert deployment is not None
        assert deployment.deployment_id is not None

        # Verify deployment exists
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved is not None
        assert retrieved.name == "Test GPT-4 Deployment"
        assert retrieved.model_provider == "openai"
        assert retrieved.approval_status == ApprovalStatus.PENDING

    def test_register_with_data_categories(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test registering a deployment with data categories."""
        deployment = inmemory_registry_manager.register(
            name="PII Handler",
            description="Handles PII data",
            model_provider="anthropic",
            model_name="claude-3-opus",
            owner="compliance-team",
            owner_contact="compliance@example.com",
            data_categories=["pii", "internal"],
            risk_level=RiskLevel.HIGH,
        )

        assert deployment is not None
        assert "pii" in deployment.data_categories
        assert "internal" in deployment.data_categories

    def test_register_with_metadata(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test registering a deployment with custom metadata."""
        deployment = inmemory_registry_manager.register(
            name="Custom Deployment",
            description="Deployment with metadata",
            model_provider="openai",
            model_name="gpt-4",
            owner="data-team",
            owner_contact="data@example.com",
            metadata={
                "environment": "production",
                "cost_center": "CC-1234",
                "project": "alpha",
            },
        )

        assert deployment is not None
        assert deployment.metadata.get("environment") == "production"
        assert deployment.metadata.get("cost_center") == "CC-1234"

    def test_register_generates_event(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test that registration generates an event."""
        events = []

        def capture_event(event):
            events.append(event)

        inmemory_registry_manager.on_event(capture_event)

        inmemory_registry_manager.register(
            name="Event Test",
            description="Test events",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        assert len(events) >= 1
        assert any(e.event_type == DeploymentEventType.REGISTERED for e in events)


# =============================================================================
# Approval Workflow Tests
# =============================================================================


class TestApprovalWorkflow:
    """Tests for deployment approval workflow."""

    def test_approve_deployment(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test approving a deployment."""
        deployment = inmemory_registry_manager.register(
            name="Pending Approval",
            description="Awaiting approval",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        # Verify initially pending
        assert deployment.approval_status == ApprovalStatus.PENDING

        # Approve
        approved = inmemory_registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
            approval_ticket="TICKET-123",
        )
        assert approved is not None

        # Verify approved
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.APPROVED

    def test_reject_deployment(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test rejecting a deployment."""
        deployment = inmemory_registry_manager.register(
            name="To Be Rejected",
            description="Will be rejected",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        # Reject
        rejected = inmemory_registry_manager.reject(
            deployment_id=deployment.deployment_id,
            rejected_by="admin@example.com",
            reason="Does not meet compliance requirements",
        )
        assert rejected is not None

        # Verify rejected
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.REJECTED

    def test_high_risk_requires_approval(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test that high risk deployments start as pending."""
        deployment = inmemory_registry_manager.register(
            name="High Risk Deployment",
            description="A high risk deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=["pii"],  # Required for high risk
            risk_level=RiskLevel.HIGH,
        )

        assert deployment.approval_status == ApprovalStatus.PENDING
        assert deployment.risk_level == RiskLevel.HIGH

    def test_approval_generates_event(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test that approval generates an event."""
        deployment = inmemory_registry_manager.register(
            name="Event Test",
            description="Test events",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        events = []
        inmemory_registry_manager.on_event(lambda e: events.append(e))

        inmemory_registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
        )

        assert any(e.event_type == DeploymentEventType.APPROVED for e in events)


# =============================================================================
# Suspension and Reinstatement Tests
# =============================================================================


class TestSuspensionWorkflow:
    """Tests for deployment suspension and reinstatement."""

    def test_suspend_deployment(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test suspending a deployment."""
        deployment = inmemory_registry_manager.register(
            name="To Be Suspended",
            description="Will be suspended",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        # First approve
        inmemory_registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
        )

        # Then suspend
        suspended = inmemory_registry_manager.suspend(
            deployment_id=deployment.deployment_id,
            suspended_by="security@example.com",
            reason="Security concern identified",
        )
        assert suspended is not None

        # Verify suspended
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.SUSPENDED

    def test_reinstate_deployment(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test reinstating a suspended deployment."""
        deployment = inmemory_registry_manager.register(
            name="To Be Reinstated",
            description="Will be reinstated",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        # Approve and suspend
        inmemory_registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
        )
        inmemory_registry_manager.suspend(
            deployment_id=deployment.deployment_id,
            suspended_by="security@example.com",
            reason="Temporary suspension",
        )

        # Reinstate
        reinstated = inmemory_registry_manager.reinstate(
            deployment_id=deployment.deployment_id,
            reinstated_by="admin@example.com",
            notes="Investigation complete - cleared",
        )
        assert reinstated is not None

        # Verify reinstated (back to approved)
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.APPROVED

    def test_suspension_generates_event(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test that suspension generates an event."""
        deployment = inmemory_registry_manager.register(
            name="Event Test",
            description="Test events",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        inmemory_registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
        )

        events = []
        inmemory_registry_manager.on_event(lambda e: events.append(e))

        inmemory_registry_manager.suspend(
            deployment_id=deployment.deployment_id,
            suspended_by="security@example.com",
            reason="Test",
        )

        assert any(e.event_type == DeploymentEventType.SUSPENDED for e in events)


# =============================================================================
# Listing and Query Tests
# =============================================================================


class TestListingAndQueries:
    """Tests for listing and querying deployments."""

    def test_list_all_deployments(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test listing all deployments."""
        # Create multiple deployments
        inmemory_registry_manager.register(
            name="Deployment 1",
            description="First",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-a",
            owner_contact="a@example.com",
        )
        inmemory_registry_manager.register(
            name="Deployment 2",
            description="Second",
            model_provider="anthropic",
            model_name="claude-3",
            owner="team-b",
            owner_contact="b@example.com",
        )

        deployments = inmemory_registry_manager.list_all()
        assert len(deployments) >= 2

    def test_list_by_status(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test listing deployments by status."""
        # Create deployments with different statuses
        d1 = inmemory_registry_manager.register(
            name="Pending",
            description="Pending deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
        )
        d2 = inmemory_registry_manager.register(
            name="Approved",
            description="Approved deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
        )
        inmemory_registry_manager.approve(
            deployment_id=d2.deployment_id,
            approved_by="admin@example.com",
        )

        # List pending only
        pending = inmemory_registry_manager.find_pending()
        assert any(d.deployment_id == d1.deployment_id for d in pending)

        # List approved only
        approved = inmemory_registry_manager.find_active()
        assert any(d.deployment_id == d2.deployment_id for d in approved)

    def test_list_by_risk_level(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test listing deployments by risk level."""
        inmemory_registry_manager.register(
            name="Low Risk",
            description="Low risk deployment",
            model_provider="openai",
            model_name="gpt-3.5-turbo",
            owner="team",
            owner_contact="team@example.com",
            risk_level=RiskLevel.LOW,
        )
        inmemory_registry_manager.register(
            name="High Risk",
            description="High risk deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
            data_categories=["pii"],  # Required for high risk
            risk_level=RiskLevel.HIGH,
        )

        high_risk = inmemory_registry_manager.find_by_risk_level(RiskLevel.HIGH)
        assert any(d.name == "High Risk" for d in high_risk)

    def test_list_by_owner(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test listing deployments by owner."""
        inmemory_registry_manager.register(
            name="Team A Deployment",
            description="Owned by Team A",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-a",
            owner_contact="a@example.com",
        )
        inmemory_registry_manager.register(
            name="Team B Deployment",
            description="Owned by Team B",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-b",
            owner_contact="b@example.com",
        )

        team_a_deployments = inmemory_registry_manager.find_by_owner("team-a")
        assert all(d.owner == "team-a" for d in team_a_deployments)


# =============================================================================
# Update Tests
# =============================================================================


class TestDeploymentUpdate:
    """Tests for updating deployments."""

    def test_update_description(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test updating deployment description."""
        deployment = inmemory_registry_manager.register(
            name="Updatable",
            description="Original description",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
        )

        updated = inmemory_registry_manager.update(
            deployment_id=deployment.deployment_id,
            description="Updated description",
        )
        assert updated is not None

        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.description == "Updated description"

    def test_update_metadata(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test updating deployment metadata."""
        deployment = inmemory_registry_manager.register(
            name="Metadata Test",
            description="Testing metadata",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
            metadata={"key": "original"},
        )

        updated = inmemory_registry_manager.update(
            deployment_id=deployment.deployment_id,
            metadata={"key": "updated", "new_key": "new_value"},
        )
        assert updated is not None

        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.metadata.get("key") == "updated"
        assert retrieved.metadata.get("new_key") == "new_value"

    def test_update_generates_event(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test that updates generate events."""
        deployment = inmemory_registry_manager.register(
            name="Event Test",
            description="Test events",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        events = []
        inmemory_registry_manager.on_event(lambda e: events.append(e))

        inmemory_registry_manager.update(
            deployment_id=deployment.deployment_id,
            description="New description",
        )

        assert any(e.event_type == DeploymentEventType.UPDATED for e in events)


# =============================================================================
# Risk Assessment Tests
# =============================================================================


class TestRiskAssessment:
    """Tests for risk assessment integration."""

    def test_risk_assessment_on_registration(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test that risk assessment is performed on registration."""
        # Don't specify risk_level to let the system assess it
        deployment = inmemory_registry_manager.register(
            name="Risk Assessment Test",
            description="Testing risk assessment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
            data_categories=["pii", "financial"],
        )

        # PII and financial data should result in higher risk
        assert deployment.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


# =============================================================================
# Database Persistence Tests
# =============================================================================


class TestDatabasePersistence:
    """Tests for database persistence."""

    def test_deployment_persists_in_database(
        self, registry_manager: RegistryManager, registry_repo: RegistryRepository
    ) -> None:
        """Test that deployments are persisted to database."""
        deployment = registry_manager.register(
            name="Persistent",
            description="Should persist",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
        )

        # Query directly from repository using deployment name
        db_record = registry_repo.get_by_name("Persistent")
        assert db_record is not None
        assert db_record["name"] == "Persistent"

    def test_status_changes_persist(
        self, registry_manager: RegistryManager, registry_repo: RegistryRepository
    ) -> None:
        """Test that status changes persist to database."""
        registry_manager.register(
            name="Status Test",
            description="Testing status persistence",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            owner_contact="team@example.com",
        )

        # Get the deployment by name since the repository assigns its own ID
        deployment = registry_manager.get_by_name("Status Test")
        assert deployment is not None

        registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
        )

        # Query directly from repository
        db_record = registry_repo.get_by_name("Status Test")
        assert db_record["approval_status"] == "APPROVED"


# =============================================================================
# Full Lifecycle Tests
# =============================================================================


class TestFullLifecycle:
    """Tests for complete deployment lifecycle."""

    def test_full_deployment_lifecycle(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test complete deployment lifecycle from registration to deletion."""
        # 1. Register
        deployment = inmemory_registry_manager.register(
            name="Full Lifecycle Test",
            description="Testing full lifecycle",
            model_provider="openai",
            model_name="gpt-4",
            owner="lifecycle-team",
            owner_contact="lifecycle@example.com",
            risk_level=RiskLevel.MEDIUM,
        )
        assert deployment.approval_status == ApprovalStatus.PENDING

        # 2. Approve
        inmemory_registry_manager.approve(
            deployment_id=deployment.deployment_id,
            approved_by="admin@example.com",
            approval_ticket="TICKET-001",
        )
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.APPROVED

        # 3. Update metadata
        inmemory_registry_manager.update(
            deployment_id=deployment.deployment_id,
            metadata={"phase": "production"},
        )
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.metadata.get("phase") == "production"

        # 4. Suspend (due to incident)
        inmemory_registry_manager.suspend(
            deployment_id=deployment.deployment_id,
            suspended_by="security@example.com",
            reason="Security incident investigation",
        )
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.SUSPENDED

        # 5. Reinstate after investigation
        inmemory_registry_manager.reinstate(
            deployment_id=deployment.deployment_id,
            reinstated_by="admin@example.com",
            notes="Investigation complete - cleared",
        )
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved.approval_status == ApprovalStatus.APPROVED

        # 6. Delete
        success = inmemory_registry_manager.delete(
            deployment_id=deployment.deployment_id,
            deleted_by="admin@example.com",
        )
        assert success is True

        # Verify deleted
        retrieved = inmemory_registry_manager.get(deployment.deployment_id)
        assert retrieved is None

    def test_multiple_deployments_same_owner(
        self, inmemory_registry_manager: RegistryManager
    ) -> None:
        """Test managing multiple deployments from same owner."""
        owner = "multi-deploy-team"
        contact = "multi@example.com"

        # Register multiple deployments
        deployments = []
        for i in range(3):
            deployment = inmemory_registry_manager.register(
                name=f"Deployment {i}",
                description=f"Deployment number {i}",
                model_provider="openai",
                model_name="gpt-4",
                owner=owner,
                owner_contact=contact,
            )
            deployments.append(deployment)

        # Verify all exist
        owner_deployments = inmemory_registry_manager.find_by_owner(owner)
        assert len(owner_deployments) == 3

        # Approve all
        for deployment in deployments:
            inmemory_registry_manager.approve(
                deployment_id=deployment.deployment_id,
                approved_by="admin@example.com",
            )

        # Verify all approved
        approved = inmemory_registry_manager.find_active()
        approved_ids = [d.deployment_id for d in approved]
        assert all(d.deployment_id in approved_ids for d in deployments)
