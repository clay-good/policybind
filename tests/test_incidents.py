"""
Tests for incident management.

This module tests the IncidentManager, IncidentDetector, and related
incident tracking functionality.
"""

from datetime import datetime, timedelta

import pytest

from policybind.incidents import (
    DetectionMatch,
    DetectionRule,
    Incident,
    IncidentComment,
    IncidentDetector,
    IncidentEvent,
    IncidentManager,
    IncidentMetrics,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    IncidentType,
    TimelineEventType,
)
from policybind.models.base import utc_now
from policybind.storage import Database, IncidentRepository


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def db() -> Database:
    """Create a test database."""
    database = Database(":memory:")
    database.initialize()
    return database


@pytest.fixture
def repository(db: Database) -> IncidentRepository:
    """Create an incident repository."""
    return IncidentRepository(db)


@pytest.fixture
def manager(repository: IncidentRepository) -> IncidentManager:
    """Create an incident manager."""
    return IncidentManager(repository)


@pytest.fixture
def detector(manager: IncidentManager) -> IncidentDetector:
    """Create an incident detector."""
    return IncidentDetector(manager, include_builtins=True)


# =============================================================================
# Model Tests
# =============================================================================


class TestIncidentModels:
    """Tests for incident data models."""

    def test_incident_creation(self) -> None:
        """Test creating an incident."""
        incident = Incident(
            title="Test incident",
            description="Test description",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.HIGH,
        )

        assert incident.title == "Test incident"
        assert incident.incident_type == IncidentType.POLICY_VIOLATION
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.status == IncidentStatus.OPEN
        assert incident.incident_id != ""

    def test_incident_is_open(self) -> None:
        """Test is_open method."""
        open_incident = Incident(status=IncidentStatus.OPEN)
        investigating_incident = Incident(status=IncidentStatus.INVESTIGATING)
        resolved_incident = Incident(status=IncidentStatus.RESOLVED)
        closed_incident = Incident(status=IncidentStatus.CLOSED)

        assert open_incident.is_open() is True
        assert investigating_incident.is_open() is True
        assert resolved_incident.is_open() is False
        assert closed_incident.is_open() is False

    def test_incident_is_high_priority(self) -> None:
        """Test is_high_priority method."""
        low = Incident(severity=IncidentSeverity.LOW)
        medium = Incident(severity=IncidentSeverity.MEDIUM)
        high = Incident(severity=IncidentSeverity.HIGH)
        critical = Incident(severity=IncidentSeverity.CRITICAL)

        assert low.is_high_priority() is False
        assert medium.is_high_priority() is False
        assert high.is_high_priority() is True
        assert critical.is_high_priority() is True

    def test_incident_to_dict(self) -> None:
        """Test converting incident to dict."""
        incident = Incident(
            title="Test incident",
            incident_type=IncidentType.DATA_LEAK,
            tags=("security", "critical"),
        )

        data = incident.to_dict()

        assert data["title"] == "Test incident"
        assert data["incident_type"] == "DATA_LEAK"
        assert data["tags"] == ["security", "critical"]

    def test_incident_comment(self) -> None:
        """Test IncidentComment model."""
        comment = IncidentComment(
            incident_id="inc-123",
            author="analyst",
            content="This is a test comment",
        )

        assert comment.incident_id == "inc-123"
        assert comment.author == "analyst"
        assert comment.content == "This is a test comment"

    def test_incident_timeline_entry(self) -> None:
        """Test IncidentTimelineEntry model."""
        entry = IncidentTimelineEntry(
            incident_id="inc-123",
            event_type=TimelineEventType.STATUS_CHANGE,
            old_value="OPEN",
            new_value="INVESTIGATING",
            actor="analyst",
        )

        assert entry.event_type == TimelineEventType.STATUS_CHANGE
        assert entry.old_value == "OPEN"
        assert entry.new_value == "INVESTIGATING"

    def test_incident_metrics(self) -> None:
        """Test IncidentMetrics model."""
        metrics = IncidentMetrics(
            total_count=100,
            open_count=20,
            investigating_count=10,
            resolved_count=50,
            closed_count=20,
        )

        assert metrics.resolution_rate == 70.0  # (50 + 20) / 100 * 100

    def test_incident_metrics_zero_total(self) -> None:
        """Test resolution_rate with zero total."""
        metrics = IncidentMetrics(total_count=0)
        assert metrics.resolution_rate == 0.0

    def test_detection_rule(self) -> None:
        """Test DetectionRule model."""
        rule = DetectionRule(
            name="test-rule",
            description="Test detection rule",
            severity=IncidentSeverity.HIGH,
            incident_type=IncidentType.ABUSE,
            condition={"decision": "DENY"},
            threshold=5,
            window_minutes=30,
        )

        assert rule.name == "test-rule"
        assert rule.threshold == 5
        assert rule.enabled is True


# =============================================================================
# Manager Tests
# =============================================================================


class TestIncidentManager:
    """Tests for IncidentManager."""

    def test_create_incident(self, manager: IncidentManager) -> None:
        """Test creating an incident."""
        incident = manager.create(
            title="Test incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.MEDIUM,
            description="Test description",
        )

        assert incident.title == "Test incident"
        assert incident.status == IncidentStatus.OPEN
        assert incident.incident_id != ""

    def test_create_from_violation(self, manager: IncidentManager) -> None:
        """Test creating incident from violation."""
        incident = manager.create_from_violation(
            request_id="req-123",
            policy_rule="deny-pii",
            description="PII data detected",
            severity=IncidentSeverity.HIGH,
        )

        assert incident.incident_type == IncidentType.POLICY_VIOLATION
        assert "deny-pii" in incident.title
        assert incident.source_request_id == "req-123"
        assert incident.evidence.get("policy_rule") == "deny-pii"

    def test_create_from_detection(self, manager: IncidentManager) -> None:
        """Test creating incident from detection."""
        incident = manager.create_from_detection(
            detection_rule="repeated-denials",
            incident_type=IncidentType.ABUSE,
            severity=IncidentSeverity.MEDIUM,
            description="Multiple denials detected",
            evidence={"count": 5},
            auto_assign="security-team",
        )

        assert "auto-detected" in incident.tags
        assert incident.assignee == "security-team"
        assert incident.evidence.get("detection_rule") == "repeated-denials"

    def test_get_incident(self, manager: IncidentManager) -> None:
        """Test getting an incident by ID."""
        created = manager.create(
            title="Test",
            incident_type=IncidentType.OTHER,
        )

        retrieved = manager.get(created.incident_id)

        assert retrieved is not None
        assert retrieved.incident_id == created.incident_id

    def test_get_nonexistent_incident(self, manager: IncidentManager) -> None:
        """Test getting a non-existent incident."""
        result = manager.get("nonexistent-id")
        assert result is None

    def test_get_or_raise(self, manager: IncidentManager) -> None:
        """Test get_or_raise raises for non-existent incident."""
        from policybind.exceptions import IncidentError

        with pytest.raises(IncidentError):
            manager.get_or_raise("nonexistent-id")

    def test_list_incidents(self, manager: IncidentManager) -> None:
        """Test listing incidents."""
        manager.create(title="Incident 1", incident_type=IncidentType.POLICY_VIOLATION)
        manager.create(title="Incident 2", incident_type=IncidentType.ABUSE)
        manager.create(title="Incident 3", incident_type=IncidentType.POLICY_VIOLATION)

        # List all
        all_incidents = manager.list_incidents()
        assert len(all_incidents) == 3

        # Filter by type
        violations = manager.list_incidents(incident_type=IncidentType.POLICY_VIOLATION)
        assert len(violations) == 2

    def test_get_open_incidents(self, manager: IncidentManager) -> None:
        """Test getting open incidents."""
        inc1 = manager.create(title="Open 1", incident_type=IncidentType.OTHER)
        inc2 = manager.create(title="Open 2", incident_type=IncidentType.OTHER)
        manager.resolve(inc2.incident_id, "Resolved", actor="admin")

        open_incidents = manager.get_open_incidents()
        assert len(open_incidents) == 1
        assert open_incidents[0].incident_id == inc1.incident_id

    def test_update_status(self, manager: IncidentManager) -> None:
        """Test updating incident status."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)

        updated = manager.update_status(
            incident.incident_id,
            IncidentStatus.INVESTIGATING,
            actor="analyst",
        )

        assert updated.status == IncidentStatus.INVESTIGATING

    def test_invalid_status_transition(self, manager: IncidentManager) -> None:
        """Test invalid status transition raises error."""
        from policybind.exceptions import IncidentError

        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)
        manager.resolve(incident.incident_id, "Resolved")

        # Can't go from RESOLVED to INVESTIGATING directly
        with pytest.raises(IncidentError):
            manager.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)

    def test_start_investigation(self, manager: IncidentManager) -> None:
        """Test starting investigation."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)

        updated = manager.start_investigation(incident.incident_id, actor="analyst")

        assert updated.status == IncidentStatus.INVESTIGATING

    def test_resolve_incident(self, manager: IncidentManager) -> None:
        """Test resolving an incident."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)

        updated = manager.resolve(
            incident.incident_id,
            resolution="Fixed the issue",
            root_cause="Misconfiguration",
            actor="admin",
        )

        assert updated.status == IncidentStatus.RESOLVED

    def test_close_incident(self, manager: IncidentManager) -> None:
        """Test closing an incident."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)
        manager.resolve(incident.incident_id, "Resolved")

        updated = manager.close(incident.incident_id, actor="admin")

        assert updated.status == IncidentStatus.CLOSED

    def test_reopen_incident(self, manager: IncidentManager) -> None:
        """Test reopening an incident."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)
        manager.resolve(incident.incident_id, "Resolved")
        manager.close(incident.incident_id)

        updated = manager.reopen(
            incident.incident_id,
            reason="Issue recurred",
            actor="analyst",
        )

        assert updated.status == IncidentStatus.OPEN

    def test_assign_incident(self, manager: IncidentManager) -> None:
        """Test assigning an incident."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)

        updated = manager.assign(incident.incident_id, "security-team", actor="admin")

        assert updated.assignee == "security-team"

    def test_unassign_incident(self, manager: IncidentManager) -> None:
        """Test unassigning an incident."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)
        manager.assign(incident.incident_id, "security-team")

        updated = manager.unassign(incident.incident_id, actor="admin")

        assert updated.assignee is None

    def test_update_severity(self, manager: IncidentManager) -> None:
        """Test updating severity."""
        incident = manager.create(
            title="Test",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
        )

        updated = manager.update_severity(
            incident.incident_id,
            IncidentSeverity.HIGH,
            reason="New evidence",
            actor="analyst",
        )

        assert updated.severity == IncidentSeverity.HIGH

    def test_escalate(self, manager: IncidentManager) -> None:
        """Test escalating an incident."""
        incident = manager.create(
            title="Test",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.LOW,
        )

        updated = manager.escalate(
            incident.incident_id,
            reason="Critical impact discovered",
            actor="analyst",
        )

        assert updated.severity == IncidentSeverity.MEDIUM

    def test_escalate_already_critical(self, manager: IncidentManager) -> None:
        """Test escalating already critical incident raises error."""
        from policybind.exceptions import IncidentError

        incident = manager.create(
            title="Test",
            incident_type=IncidentType.OTHER,
            severity=IncidentSeverity.CRITICAL,
        )

        with pytest.raises(IncidentError):
            manager.escalate(incident.incident_id, "Try to escalate")

    def test_add_comment(self, manager: IncidentManager) -> None:
        """Test adding a comment."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)

        comment_id = manager.add_comment(
            incident.incident_id,
            author="analyst",
            content="Investigation notes",
        )

        assert comment_id > 0

        comments = manager.get_comments(incident.incident_id)
        assert len(comments) == 1
        assert comments[0].author == "analyst"

    def test_get_timeline(self, manager: IncidentManager) -> None:
        """Test getting incident timeline."""
        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)
        manager.assign(incident.incident_id, "analyst")
        manager.update_status(incident.incident_id, IncidentStatus.INVESTIGATING)

        timeline = manager.get_timeline(incident.incident_id)

        # Should have at least: created, assignment, status change
        assert len(timeline) >= 3

    def test_link_incidents(self, manager: IncidentManager) -> None:
        """Test linking incidents."""
        inc1 = manager.create(title="Incident 1", incident_type=IncidentType.OTHER)
        inc2 = manager.create(title="Incident 2", incident_type=IncidentType.OTHER)

        manager.link_incidents(inc1.incident_id, inc2.incident_id, actor="analyst")

        related = manager.get_related_incidents(inc1.incident_id)
        assert len(related) == 1
        assert related[0].incident_id == inc2.incident_id

        # Bidirectional link
        related2 = manager.get_related_incidents(inc2.incident_id)
        assert len(related2) == 1
        assert related2[0].incident_id == inc1.incident_id

    def test_find_similar_incidents(self, manager: IncidentManager) -> None:
        """Test finding similar incidents."""
        inc1 = manager.create(
            title="Incident 1",
            incident_type=IncidentType.POLICY_VIOLATION,
            deployment_id="deploy-123",
        )
        inc2 = manager.create(
            title="Incident 2",
            incident_type=IncidentType.POLICY_VIOLATION,
            deployment_id="deploy-123",
        )
        inc3 = manager.create(
            title="Incident 3",
            incident_type=IncidentType.OTHER,
            deployment_id="deploy-456",
        )

        similar = manager.find_similar_incidents(inc1.incident_id)

        # Should find inc2 (same deployment and type)
        similar_ids = [i.incident_id for i in similar]
        assert inc2.incident_id in similar_ids
        assert inc1.incident_id not in similar_ids  # Exclude self

    def test_get_metrics(self, manager: IncidentManager) -> None:
        """Test getting incident metrics."""
        manager.create(
            title="Low",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.LOW,
        )
        inc2 = manager.create(
            title="High",
            incident_type=IncidentType.DATA_LEAK,
            severity=IncidentSeverity.HIGH,
        )
        manager.resolve(inc2.incident_id, "Resolved")

        metrics = manager.get_metrics()

        assert metrics.total_count == 2
        assert metrics.open_count == 1
        assert metrics.resolved_count == 1
        assert "LOW" in metrics.by_severity
        assert "POLICY_VIOLATION" in metrics.by_type

    def test_event_callback(self, manager: IncidentManager) -> None:
        """Test event callbacks."""
        events: list[IncidentEvent] = []

        def callback(event: IncidentEvent) -> None:
            events.append(event)

        manager.on_event(callback)

        incident = manager.create(title="Test", incident_type=IncidentType.OTHER)
        manager.assign(incident.incident_id, "analyst")

        assert len(events) >= 2  # Created and assigned
        assert events[0].event_type == TimelineEventType.CREATED

    def test_remove_callback(self, manager: IncidentManager) -> None:
        """Test removing a callback."""
        events: list[IncidentEvent] = []

        def callback(event: IncidentEvent) -> None:
            events.append(event)

        manager.on_event(callback)
        manager.create(title="Test 1", incident_type=IncidentType.OTHER)

        assert len(events) == 1

        result = manager.remove_callback(callback)
        assert result is True

        manager.create(title="Test 2", incident_type=IncidentType.OTHER)
        assert len(events) == 1  # No new events


# =============================================================================
# Detector Tests
# =============================================================================


class TestIncidentDetector:
    """Tests for IncidentDetector."""

    def test_detector_initialization(self) -> None:
        """Test detector initializes with builtin rules."""
        detector = IncidentDetector(include_builtins=True)

        rules = detector.list_rules()
        assert len(rules) > 0

    def test_register_rule(self) -> None:
        """Test registering a custom rule."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="custom-rule",
            name="Custom Rule",
            description="A custom detection rule",
            severity=IncidentSeverity.MEDIUM,
            incident_type=IncidentType.ANOMALY,
            condition={"type": "test"},
            threshold=3,
        )

        detector.register_rule(rule)

        assert detector.get_rule("custom-rule") is not None
        assert len(detector.list_rules()) == 1

    def test_unregister_rule(self) -> None:
        """Test unregistering a rule."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(rule_id="test-rule", name="Test")
        detector.register_rule(rule)

        result = detector.unregister_rule("test-rule")
        assert result is True
        assert detector.get_rule("test-rule") is None

        # Unregistering non-existent rule
        result = detector.unregister_rule("nonexistent")
        assert result is False

    def test_enable_disable_rule(self) -> None:
        """Test enabling and disabling rules."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(rule_id="test-rule", name="Test", enabled=True)
        detector.register_rule(rule)

        detector.disable_rule("test-rule")
        assert detector.get_rule("test-rule").enabled is False

        detector.enable_rule("test-rule")
        assert detector.get_rule("test-rule").enabled is True

    def test_process_event_no_match(self) -> None:
        """Test processing event that doesn't match any rule."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"decision": "DENY"},
            threshold=3,
        )
        detector.register_rule(rule)

        matches = detector.process_event({"decision": "ALLOW"})
        assert len(matches) == 0

    def test_process_event_below_threshold(self) -> None:
        """Test processing events below threshold."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"decision": "DENY"},
            threshold=3,
            window_minutes=60,
        )
        detector.register_rule(rule)

        # Process 2 events (below threshold of 3)
        detector.process_event({"decision": "DENY", "user_id": "user-1"})
        matches = detector.process_event({"decision": "DENY", "user_id": "user-1"})

        assert len(matches) == 0

    def test_process_event_exceeds_threshold(self) -> None:
        """Test processing events that exceed threshold."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"decision": "DENY"},
            threshold=3,
            window_minutes=60,
            cooldown_minutes=0,  # No cooldown for testing
        )
        detector.register_rule(rule)

        # Process 3 events (meets threshold)
        detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )
        detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )
        matches = detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )

        assert len(matches) == 1
        assert matches[0].rule.rule_id == "test-rule"
        assert matches[0].occurrences == 3

    def test_process_event_with_cooldown(self) -> None:
        """Test cooldown prevents repeated incidents."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"decision": "DENY"},
            threshold=2,
            window_minutes=60,
            cooldown_minutes=60,
        )
        detector.register_rule(rule)

        # Trigger once
        detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )
        matches1 = detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )
        assert len(matches1) == 1

        # Try to trigger again (should be in cooldown)
        detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )
        matches2 = detector.process_event(
            {"decision": "DENY", "user_id": "user-1"},
            auto_create_incident=False,
        )
        assert len(matches2) == 0

    def test_process_event_list_condition(self) -> None:
        """Test condition with list values."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"data_classification": ["pii", "phi"]},
            threshold=1,
            cooldown_minutes=0,
        )
        detector.register_rule(rule)

        matches = detector.process_event(
            {"data_classification": ["pii"], "user_id": "u1"},
            auto_create_incident=False,
        )
        assert len(matches) == 1

    def test_process_event_operator_condition(self) -> None:
        """Test condition with operators."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"cost": {"$gt": 10.0}},
            threshold=1,
            cooldown_minutes=0,
        )
        detector.register_rule(rule)

        # Below threshold
        matches1 = detector.process_event(
            {"cost": 5.0, "user_id": "u1"},
            auto_create_incident=False,
        )
        assert len(matches1) == 0

        # Above threshold
        matches2 = detector.process_event(
            {"cost": 15.0, "user_id": "u2"},
            auto_create_incident=False,
        )
        assert len(matches2) == 1

    def test_process_events_batch(self) -> None:
        """Test processing multiple events."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"decision": "DENY"},
            threshold=2,
            cooldown_minutes=0,
        )
        detector.register_rule(rule)

        events = [
            {"decision": "DENY", "user_id": "user-1"},
            {"decision": "DENY", "user_id": "user-1"},
            {"decision": "ALLOW", "user_id": "user-1"},
        ]

        matches = detector.process_events(events, auto_create_incident=False)
        assert len(matches) == 1

    def test_analyze_patterns(self) -> None:
        """Test pattern analysis."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"decision": "DENY"},
            threshold=5,
        )
        detector.register_rule(rule)

        events = [
            {"decision": "DENY", "user_id": "user-1"},
            {"decision": "DENY", "user_id": "user-1"},
            {"decision": "DENY", "user_id": "user-2"},
            {"decision": "ALLOW", "user_id": "user-1"},
        ]

        analysis = detector.analyze_patterns(events)

        assert analysis["total_events"] == 4
        assert analysis["by_decision"]["DENY"] == 3
        assert analysis["by_decision"]["ALLOW"] == 1
        assert "Test" in analysis["rule_matches"]
        assert analysis["rule_matches"]["Test"]["count"] == 3
        assert analysis["rule_matches"]["Test"]["would_trigger"] is False

    def test_get_risk_score(self) -> None:
        """Test risk score calculation."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="high-rule",
            name="High Risk",
            condition={"decision": "DENY"},
            threshold=2,
            severity=IncidentSeverity.HIGH,
        )
        detector.register_rule(rule)

        events = [
            {"decision": "DENY"},
            {"decision": "DENY"},
        ]

        score = detector.get_risk_score(events)
        assert score > 0
        assert score <= 1.0

    def test_get_risk_score_empty(self) -> None:
        """Test risk score with no events."""
        detector = IncidentDetector(include_builtins=False)
        score = detector.get_risk_score([])
        assert score == 0.0

    def test_get_recent_matches(self) -> None:
        """Test getting recent matches."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"type": "test"},
            threshold=1,
            cooldown_minutes=0,
        )
        detector.register_rule(rule)

        detector.process_event({"type": "test", "user_id": "u1"}, auto_create_incident=False)
        detector.process_event({"type": "test", "user_id": "u2"}, auto_create_incident=False)

        matches = detector.get_recent_matches()
        assert len(matches) == 2

    def test_clear_matches(self) -> None:
        """Test clearing match history."""
        detector = IncidentDetector(include_builtins=False)

        rule = DetectionRule(
            rule_id="test-rule",
            name="Test",
            condition={"type": "test"},
            threshold=1,
            cooldown_minutes=0,
        )
        detector.register_rule(rule)

        detector.process_event({"type": "test", "user_id": "u1"}, auto_create_incident=False)
        assert len(detector.get_recent_matches()) == 1

        detector.clear_matches()
        assert len(detector.get_recent_matches()) == 0

    def test_auto_create_incident(
        self, manager: IncidentManager, detector: IncidentDetector
    ) -> None:
        """Test auto-creation of incidents."""
        # Register a simple rule that triggers easily
        rule = DetectionRule(
            rule_id="auto-test",
            name="Auto Test",
            description="Auto-create test",
            condition={"test": True},
            threshold=1,
            cooldown_minutes=0,
            severity=IncidentSeverity.MEDIUM,
            incident_type=IncidentType.ANOMALY,
        )
        detector.register_rule(rule)

        detector.process_event(
            {"test": True, "user_id": "user-1", "request_id": "req-123"},
            auto_create_incident=True,
        )

        incidents = manager.list_incidents()
        assert len(incidents) >= 1

        # Find the auto-created incident
        auto_incidents = [i for i in incidents if "auto-detected" in i.tags]
        assert len(auto_incidents) >= 1


# =============================================================================
# Integration Tests
# =============================================================================


class TestIncidentIntegration:
    """Integration tests for incident management."""

    def test_full_incident_lifecycle(
        self, manager: IncidentManager
    ) -> None:
        """Test complete incident lifecycle."""
        # Create
        incident = manager.create(
            title="Security incident",
            incident_type=IncidentType.DATA_LEAK,
            severity=IncidentSeverity.HIGH,
            description="Potential data leak detected",
        )
        assert incident.status == IncidentStatus.OPEN

        # Assign
        incident = manager.assign(incident.incident_id, "security-team")
        assert incident.assignee == "security-team"

        # Start investigation
        incident = manager.start_investigation(incident.incident_id)
        assert incident.status == IncidentStatus.INVESTIGATING

        # Add comments
        manager.add_comment(
            incident.incident_id,
            author="analyst",
            content="Started analyzing logs",
        )
        manager.add_comment(
            incident.incident_id,
            author="analyst",
            content="Found root cause",
        )

        comments = manager.get_comments(incident.incident_id)
        assert len(comments) == 2

        # Resolve
        incident = manager.resolve(
            incident.incident_id,
            resolution="Revoked compromised token",
            root_cause="Token was leaked in logs",
        )
        assert incident.status == IncidentStatus.RESOLVED

        # Close
        incident = manager.close(incident.incident_id)
        assert incident.status == IncidentStatus.CLOSED

        # Verify timeline
        timeline = manager.get_timeline(incident.incident_id)
        event_types = [e.event_type for e in timeline]
        assert TimelineEventType.CREATED in event_types
        assert TimelineEventType.ASSIGNMENT in event_types
        assert TimelineEventType.STATUS_CHANGE in event_types

    def test_detection_to_incident_flow(
        self, manager: IncidentManager, detector: IncidentDetector
    ) -> None:
        """Test detection triggering incident creation."""
        # Create a sensitive rule
        rule = DetectionRule(
            rule_id="jailbreak-test",
            name="Jailbreak Test",
            description="Test jailbreak detection",
            condition={"policy_rule": "jailbreak-detection"},
            threshold=1,
            cooldown_minutes=0,
            severity=IncidentSeverity.HIGH,
            incident_type=IncidentType.JAILBREAK,
            auto_assign="security-team",
        )
        detector.register_rule(rule)

        # Trigger detection
        detector.process_event({
            "policy_rule": "jailbreak-detection",
            "request_id": "req-evil",
            "user_id": "suspicious-user",
            "deployment_id": "deploy-123",
        })

        # Verify incident was created
        incidents = manager.list_incidents(incident_type=IncidentType.JAILBREAK)
        assert len(incidents) >= 1

        incident = incidents[0]
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.assignee == "security-team"
        assert "auto-detected" in incident.tags
