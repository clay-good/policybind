"""
Integration tests for incident workflow.

This module tests the complete incident management workflow including:
- Incident creation
- Investigation workflow
- Resolution and closure
- Comments and timeline
- Metrics and trends
"""

import pytest

from policybind.incidents.manager import IncidentManager, IncidentEvent
from policybind.incidents.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    TimelineEventType,
)
from policybind.storage.database import Database
from policybind.storage.repositories import IncidentRepository


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
def incident_repo(temp_db: Database) -> IncidentRepository:
    """Create an incident repository."""
    return IncidentRepository(temp_db)


@pytest.fixture
def incident_manager(incident_repo: IncidentRepository) -> IncidentManager:
    """Create an incident manager."""
    return IncidentManager(repository=incident_repo)


# =============================================================================
# Incident Creation Tests
# =============================================================================


class TestIncidentCreation:
    """Tests for incident creation."""

    def test_create_basic_incident(self, incident_manager: IncidentManager) -> None:
        """Test creating a basic incident."""
        incident = incident_manager.create(
            title="Test Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
            description="A test incident for integration testing",
        )

        assert incident is not None
        assert incident.incident_id is not None
        assert incident.title == "Test Incident"
        assert incident.incident_type == IncidentType.POLICY_VIOLATION
        assert incident.severity == IncidentSeverity.MEDIUM
        assert incident.status == IncidentStatus.OPEN

    def test_create_incident_from_violation(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test creating an incident from a policy violation."""
        incident = incident_manager.create_from_violation(
            request_id="req-123",
            policy_rule="deny-pii-access",
            description="Request attempted to access PII data without authorization",
            severity=IncidentSeverity.HIGH,
            deployment_id="deploy-001",
            user_id="user-456",
        )

        assert incident is not None
        assert "policy-violation" in incident.tags
        assert "deny-pii-access" in incident.tags
        assert incident.incident_type == IncidentType.POLICY_VIOLATION
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.evidence.get("request_id") == "req-123"
        assert incident.evidence.get("policy_rule") == "deny-pii-access"
        assert incident.evidence.get("user_id") == "user-456"

    def test_create_incident_from_detection(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test creating an incident from automated detection."""
        incident = incident_manager.create_from_detection(
            detection_rule="anomaly-high-volume",
            incident_type=IncidentType.ANOMALY,
            severity=IncidentSeverity.MEDIUM,
            description="Unusual volume of requests detected",
            evidence={
                "request_count": 1000,
                "normal_count": 100,
                "period": "1h",
            },
            auto_assign="security-team",
        )

        assert incident is not None
        assert "auto-detected" in incident.tags
        assert "rule:anomaly-high-volume" in incident.tags
        assert incident.incident_type == IncidentType.ANOMALY
        assert incident.evidence.get("detection_rule") == "anomaly-high-volume"
        assert incident.assignee == "security-team"

    def test_create_incident_with_metadata(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test creating an incident with metadata and tags."""
        incident = incident_manager.create(
            title="Tagged Incident",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
            tags=["test", "low-priority"],
            metadata={
                "source": "integration-test",
                "environment": "testing",
            },
        )

        assert incident is not None
        assert "test" in incident.tags
        assert "low-priority" in incident.tags
        assert incident.metadata.get("source") == "integration-test"

    def test_create_incident_generates_event(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test that incident creation generates an event."""
        events = []
        incident_manager.on_event(lambda e: events.append(e))

        incident_manager.create(
            title="Event Test",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
        )

        assert len(events) >= 1
        assert any(e.event_type == TimelineEventType.CREATED for e in events)


# =============================================================================
# Investigation Workflow Tests
# =============================================================================


class TestInvestigationWorkflow:
    """Tests for investigation workflow."""

    def test_start_investigation(self, incident_manager: IncidentManager) -> None:
        """Test starting an investigation."""
        incident = incident_manager.create(
            title="To Investigate",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        assert incident.status == IncidentStatus.OPEN

        updated = incident_manager.start_investigation(
            incident.incident_id,
            actor="analyst@example.com",
        )

        assert updated.status == IncidentStatus.INVESTIGATING

    def test_assign_incident(self, incident_manager: IncidentManager) -> None:
        """Test assigning an incident."""
        incident = incident_manager.create(
            title="To Assign",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        assert incident.assignee is None

        updated = incident_manager.assign(
            incident.incident_id,
            assignee="analyst@example.com",
            actor="manager@example.com",
        )

        assert updated.assignee == "analyst@example.com"

    def test_unassign_incident(self, incident_manager: IncidentManager) -> None:
        """Test unassigning an incident."""
        incident = incident_manager.create(
            title="To Unassign",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        # First assign
        incident_manager.assign(incident.incident_id, "analyst@example.com")

        # Then unassign
        updated = incident_manager.unassign(
            incident.incident_id,
            actor="manager@example.com",
        )

        assert updated.assignee is None

    def test_investigation_generates_event(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test that investigation start generates an event."""
        incident = incident_manager.create(
            title="Event Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        events = []
        incident_manager.on_event(lambda e: events.append(e))

        incident_manager.start_investigation(incident.incident_id)

        assert any(e.event_type == TimelineEventType.STATUS_CHANGE for e in events)


# =============================================================================
# Resolution Workflow Tests
# =============================================================================


class TestResolutionWorkflow:
    """Tests for resolution workflow."""

    def test_resolve_incident(self, incident_manager: IncidentManager) -> None:
        """Test resolving an incident."""
        incident = incident_manager.create(
            title="To Resolve",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        # Start investigation first
        incident_manager.start_investigation(incident.incident_id)

        # Then resolve
        resolved = incident_manager.resolve(
            incident.incident_id,
            resolution="Revoked the offending token and updated policy rules",
            root_cause="Token had excessive permissions due to config error",
            actor="analyst@example.com",
        )

        assert resolved.status == IncidentStatus.RESOLVED
        assert resolved.resolution == "Revoked the offending token and updated policy rules"
        assert resolved.root_cause == "Token had excessive permissions due to config error"

    def test_close_incident(self, incident_manager: IncidentManager) -> None:
        """Test closing an incident."""
        incident = incident_manager.create(
            title="To Close",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.LOW,
        )

        # Resolve first
        incident_manager.resolve(
            incident.incident_id,
            resolution="Issue addressed",
            actor="analyst@example.com",
        )

        # Then close
        closed = incident_manager.close(
            incident.incident_id,
            actor="manager@example.com",
        )

        assert closed.status == IncidentStatus.CLOSED

    def test_reopen_incident(self, incident_manager: IncidentManager) -> None:
        """Test reopening a closed incident."""
        incident = incident_manager.create(
            title="To Reopen",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        # Resolve and close
        incident_manager.resolve(
            incident.incident_id,
            resolution="Initial resolution",
            actor="analyst@example.com",
        )
        incident_manager.close(incident.incident_id)

        # Reopen
        reopened = incident_manager.reopen(
            incident.incident_id,
            reason="Issue recurred after fix",
            actor="analyst@example.com",
        )

        assert reopened.status == IncidentStatus.OPEN


# =============================================================================
# Severity Management Tests
# =============================================================================


class TestSeverityManagement:
    """Tests for severity management."""

    def test_update_severity(self, incident_manager: IncidentManager) -> None:
        """Test updating incident severity."""
        incident = incident_manager.create(
            title="Severity Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.LOW,
        )

        updated = incident_manager.update_severity(
            incident.incident_id,
            severity=IncidentSeverity.HIGH,
            reason="Impact is greater than initially assessed",
            actor="analyst@example.com",
        )

        assert updated.severity == IncidentSeverity.HIGH

    def test_escalate_incident(self, incident_manager: IncidentManager) -> None:
        """Test escalating an incident."""
        incident = incident_manager.create(
            title="To Escalate",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        escalated = incident_manager.escalate(
            incident.incident_id,
            reason="Multiple similar incidents discovered",
            actor="analyst@example.com",
        )

        assert escalated.severity == IncidentSeverity.HIGH

    def test_escalate_generates_event(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test that escalation generates events."""
        incident = incident_manager.create(
            title="Escalate Event Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.LOW,
        )

        events = []
        incident_manager.on_event(lambda e: events.append(e))

        incident_manager.escalate(
            incident.incident_id,
            reason="Test escalation",
        )

        assert any(e.event_type == TimelineEventType.ESCALATION for e in events)


# =============================================================================
# Comments Tests
# =============================================================================


class TestComments:
    """Tests for incident comments."""

    def test_add_comment(self, incident_manager: IncidentManager) -> None:
        """Test adding a comment to an incident."""
        incident = incident_manager.create(
            title="Comment Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        comment_id = incident_manager.add_comment(
            incident.incident_id,
            author="analyst@example.com",
            content="Initial investigation started. Reviewing logs.",
        )

        assert comment_id is not None

        comments = incident_manager.get_comments(incident.incident_id)
        assert len(comments) >= 1
        assert any(c.content == "Initial investigation started. Reviewing logs." for c in comments)

    def test_multiple_comments(self, incident_manager: IncidentManager) -> None:
        """Test adding multiple comments."""
        incident = incident_manager.create(
            title="Multi-Comment Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        # Add multiple comments
        incident_manager.add_comment(
            incident.incident_id,
            author="analyst1@example.com",
            content="First observation",
        )
        incident_manager.add_comment(
            incident.incident_id,
            author="analyst2@example.com",
            content="Second observation",
        )
        incident_manager.add_comment(
            incident.incident_id,
            author="analyst1@example.com",
            content="Follow-up note",
        )

        comments = incident_manager.get_comments(incident.incident_id)
        assert len(comments) >= 3


# =============================================================================
# Timeline Tests
# =============================================================================


class TestTimeline:
    """Tests for incident timeline."""

    def test_timeline_tracks_changes(self, incident_manager: IncidentManager) -> None:
        """Test that timeline tracks incident changes."""
        incident = incident_manager.create(
            title="Timeline Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        # Make changes
        incident_manager.assign(
            incident.incident_id,
            assignee="analyst@example.com",
        )
        incident_manager.start_investigation(incident.incident_id)
        incident_manager.resolve(
            incident.incident_id,
            resolution="Issue fixed",
        )

        timeline = incident_manager.get_timeline(incident.incident_id)
        event_types = [entry.event_type for entry in timeline]

        # Should have CREATED, ASSIGNMENT, STATUS_CHANGE (investigating), STATUS_CHANGE (resolved)
        assert TimelineEventType.CREATED in event_types or len(timeline) >= 3


# =============================================================================
# Related Incidents Tests
# =============================================================================


class TestRelatedIncidents:
    """Tests for related incidents."""

    def test_link_incidents(self, incident_manager: IncidentManager) -> None:
        """Test linking related incidents."""
        incident1 = incident_manager.create(
            title="Primary Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )
        incident2 = incident_manager.create(
            title="Related Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        incident_manager.link_incidents(
            incident1.incident_id,
            incident2.incident_id,
            actor="analyst@example.com",
        )

        related = incident_manager.get_related_incidents(incident1.incident_id)
        assert len(related) >= 1
        assert any(r.incident_id == incident2.incident_id for r in related)

    def test_find_similar_incidents(self, incident_manager: IncidentManager) -> None:
        """Test finding similar incidents."""
        # Create incidents for same deployment
        deployment_id = "deploy-test-001"

        for i in range(3):
            incident_manager.create(
                title=f"Deployment Incident {i}",
                incident_type=IncidentType.POLICY_VIOLATION,
                severity=IncidentSeverity.MEDIUM,
                deployment_id=deployment_id,
            )

        # Create one more incident to find similar ones
        target = incident_manager.create(
            title="Target Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.HIGH,
            deployment_id=deployment_id,
        )

        similar = incident_manager.find_similar_incidents(target.incident_id)
        # Should find at least some similar incidents
        assert len(similar) >= 1


# =============================================================================
# Listing and Filtering Tests
# =============================================================================


class TestListingAndFiltering:
    """Tests for listing and filtering incidents."""

    def test_list_all_incidents(self, incident_manager: IncidentManager) -> None:
        """Test listing all incidents."""
        # Create multiple incidents
        for i in range(3):
            incident_manager.create(
                title=f"List Test {i}",
                incident_type=IncidentType.OTHER,
                severity=IncidentSeverity.LOW,
            )

        incidents = incident_manager.list_incidents()
        assert len(incidents) >= 3

    def test_filter_by_status(self, incident_manager: IncidentManager) -> None:
        """Test filtering incidents by status."""
        # Create open incident
        open_incident = incident_manager.create(
            title="Open Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )

        # Create and resolve another
        resolved_incident = incident_manager.create(
            title="Resolved Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.LOW,
        )
        incident_manager.resolve(
            resolved_incident.incident_id,
            resolution="Fixed",
        )

        # Filter by status
        open_incidents = incident_manager.list_incidents(status=IncidentStatus.OPEN)
        assert any(i.incident_id == open_incident.incident_id for i in open_incidents)
        assert not any(i.incident_id == resolved_incident.incident_id for i in open_incidents)

    def test_filter_by_severity(self, incident_manager: IncidentManager) -> None:
        """Test filtering incidents by severity."""
        incident_manager.create(
            title="Low Severity",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
        )
        high_incident = incident_manager.create(
            title="High Severity",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.HIGH,
        )

        high_incidents = incident_manager.list_incidents(severity=IncidentSeverity.HIGH)
        assert any(i.incident_id == high_incident.incident_id for i in high_incidents)

    def test_filter_by_type(self, incident_manager: IncidentManager) -> None:
        """Test filtering incidents by type."""
        violation = incident_manager.create(
            title="Policy Violation",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )
        incident_manager.create(
            title="Anomaly",
            incident_type=IncidentType.ANOMALY,
            severity=IncidentSeverity.MEDIUM,
        )

        violations = incident_manager.list_incidents(incident_type=IncidentType.POLICY_VIOLATION)
        assert any(i.incident_id == violation.incident_id for i in violations)

    def test_filter_by_deployment(self, incident_manager: IncidentManager) -> None:
        """Test filtering incidents by deployment."""
        incident = incident_manager.create(
            title="Deployment Specific",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
            deployment_id="deploy-filter-test",
        )

        deployment_incidents = incident_manager.list_incidents(
            deployment_id="deploy-filter-test"
        )
        assert any(i.incident_id == incident.incident_id for i in deployment_incidents)

    def test_filter_by_assignee(self, incident_manager: IncidentManager) -> None:
        """Test filtering incidents by assignee."""
        incident = incident_manager.create(
            title="Assigned Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )
        incident_manager.assign(incident.incident_id, "specific-analyst@example.com")

        assigned_incidents = incident_manager.list_incidents(
            assignee="specific-analyst@example.com"
        )
        assert any(i.incident_id == incident.incident_id for i in assigned_incidents)

    def test_get_open_incidents(self, incident_manager: IncidentManager) -> None:
        """Test getting open incidents."""
        # Create open and closed incidents
        open_incident = incident_manager.create(
            title="Open",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
        )
        closed_incident = incident_manager.create(
            title="Closed",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
        )
        incident_manager.resolve(closed_incident.incident_id, resolution="Done")
        incident_manager.close(closed_incident.incident_id)

        open_incidents = incident_manager.get_open_incidents()
        open_ids = [i.incident_id for i in open_incidents]
        assert open_incident.incident_id in open_ids
        assert closed_incident.incident_id not in open_ids


# =============================================================================
# Metrics Tests
# =============================================================================


class TestMetrics:
    """Tests for incident metrics."""

    def test_get_metrics(self, incident_manager: IncidentManager) -> None:
        """Test getting incident metrics."""
        # Create incidents with various statuses
        incident_manager.create(
            title="Open 1",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )
        incident_manager.create(
            title="Open 2",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.HIGH,
        )
        resolved = incident_manager.create(
            title="Resolved",
            incident_type=IncidentType.ANOMALY,
            severity=IncidentSeverity.LOW,
        )
        incident_manager.resolve(resolved.incident_id, resolution="Fixed")

        metrics = incident_manager.get_metrics()

        assert metrics.total_count >= 3
        assert metrics.open_count >= 2
        assert metrics.resolved_count >= 1

    def test_metrics_by_deployment(self, incident_manager: IncidentManager) -> None:
        """Test getting metrics filtered by deployment."""
        deployment_id = "metrics-deploy-test"

        for i in range(3):
            incident_manager.create(
                title=f"Deploy Incident {i}",
                incident_type=IncidentType.POLICY_VIOLATION,
                severity=IncidentSeverity.MEDIUM,
                deployment_id=deployment_id,
            )

        # Create incident for different deployment
        incident_manager.create(
            title="Other Deployment",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
            deployment_id="other-deploy",
        )

        metrics = incident_manager.get_metrics(deployment_id=deployment_id)
        assert metrics.total_count >= 3


# =============================================================================
# Full Workflow Tests
# =============================================================================


class TestFullWorkflow:
    """Tests for complete incident workflow."""

    def test_full_incident_workflow(self, incident_manager: IncidentManager) -> None:
        """Test complete incident workflow from creation to closure."""
        # 1. Create incident from violation
        incident = incident_manager.create_from_violation(
            request_id="req-workflow-001",
            policy_rule="deny-sensitive-data",
            description="Attempt to access sensitive data detected",
            severity=IncidentSeverity.HIGH,
            deployment_id="deploy-workflow-001",
            user_id="user-workflow-001",
        )
        assert incident.status == IncidentStatus.OPEN

        # 2. Assign to analyst
        incident = incident_manager.assign(
            incident.incident_id,
            assignee="analyst@example.com",
            actor="manager@example.com",
        )
        assert incident.assignee == "analyst@example.com"

        # 3. Start investigation
        incident = incident_manager.start_investigation(
            incident.incident_id,
            actor="analyst@example.com",
        )
        assert incident.status == IncidentStatus.INVESTIGATING

        # 4. Add investigation comments
        incident_manager.add_comment(
            incident.incident_id,
            author="analyst@example.com",
            content="Started reviewing logs. Request came from internal network.",
        )
        incident_manager.add_comment(
            incident.incident_id,
            author="analyst@example.com",
            content="Identified token with excessive permissions.",
        )

        # 5. Escalate due to severity findings
        incident = incident_manager.escalate(
            incident.incident_id,
            reason="Found additional affected users",
            actor="analyst@example.com",
        )
        assert incident.severity == IncidentSeverity.CRITICAL

        # 6. Create related incident
        related = incident_manager.create(
            title="Related: Token misconfiguration",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.MEDIUM,
            description="Root cause of the violation",
        )
        incident_manager.link_incidents(
            incident.incident_id,
            related.incident_id,
            actor="analyst@example.com",
        )

        # 7. Resolve the incident
        incident = incident_manager.resolve(
            incident.incident_id,
            resolution="Revoked affected tokens and updated policy configuration",
            root_cause="Token permissions were not properly scoped during provisioning",
            actor="analyst@example.com",
        )
        assert incident.status == IncidentStatus.RESOLVED
        assert incident.resolution is not None
        assert incident.root_cause is not None

        # 8. Add post-resolution comment
        incident_manager.add_comment(
            incident.incident_id,
            author="manager@example.com",
            content="Verified fix with security team. Approved for closure.",
        )

        # 9. Close the incident
        incident = incident_manager.close(
            incident.incident_id,
            actor="manager@example.com",
        )
        assert incident.status == IncidentStatus.CLOSED

        # 10. Verify timeline
        timeline = incident_manager.get_timeline(incident.incident_id)
        assert len(timeline) >= 1  # At least created

        # 11. Verify comments
        comments = incident_manager.get_comments(incident.incident_id)
        assert len(comments) >= 3  # At least our 3 comments

    def test_incident_reopen_workflow(self, incident_manager: IncidentManager) -> None:
        """Test reopening and re-resolving an incident."""
        # Create and resolve incident
        incident = incident_manager.create(
            title="Reopen Test",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
        )
        incident_manager.resolve(
            incident.incident_id,
            resolution="Initial fix applied",
            actor="analyst@example.com",
        )
        incident_manager.close(incident.incident_id)

        # Reopen due to recurrence
        incident = incident_manager.reopen(
            incident.incident_id,
            reason="Issue recurred after initial fix",
            actor="analyst@example.com",
        )
        assert incident.status == IncidentStatus.OPEN

        # Re-investigate
        incident = incident_manager.start_investigation(
            incident.incident_id,
            actor="analyst@example.com",
        )

        # Re-resolve with updated fix
        incident = incident_manager.resolve(
            incident.incident_id,
            resolution="Applied comprehensive fix addressing root cause",
            root_cause="Initial fix was incomplete",
            actor="analyst@example.com",
        )
        assert incident.status == IncidentStatus.RESOLVED

    def test_multiple_deployments_incident_tracking(
        self, incident_manager: IncidentManager
    ) -> None:
        """Test tracking incidents across multiple deployments."""
        deployments = ["deploy-a", "deploy-b", "deploy-c"]

        # Create incidents for each deployment
        for deployment_id in deployments:
            for i in range(2):
                incident_manager.create(
                    title=f"Incident {i} for {deployment_id}",
                    incident_type=IncidentType.POLICY_VIOLATION,
                    severity=IncidentSeverity.MEDIUM,
                    deployment_id=deployment_id,
                )

        # Verify we can retrieve incidents per deployment
        for deployment_id in deployments:
            deployment_incidents = incident_manager.get_incidents_by_deployment(
                deployment_id,
                include_closed=True,
            )
            assert len(deployment_incidents) >= 2

        # Get overall metrics
        metrics = incident_manager.get_metrics()
        assert metrics.total_count >= 6  # 3 deployments * 2 incidents
