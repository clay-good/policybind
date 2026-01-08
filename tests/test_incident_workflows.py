"""
Tests for incident workflows and reporting.

This module tests the IncidentTriageWorkflow, IncidentInvestigationWorkflow,
IncidentRemediationWorkflow, and IncidentReporter classes.
"""

from datetime import datetime, timedelta

import pytest

from policybind.incidents import (
    Incident,
    IncidentInvestigationWorkflow,
    IncidentManager,
    IncidentRemediationWorkflow,
    IncidentReporter,
    IncidentSeverity,
    IncidentStatus,
    IncidentTriageWorkflow,
    IncidentType,
    RemediationAction,
    RemediationStep,
    ReportFormat,
    TriageDecision,
    TriageRule,
    WorkflowStep,
    WorkflowStepStatus,
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
def triage() -> IncidentTriageWorkflow:
    """Create a triage workflow."""
    return IncidentTriageWorkflow()


@pytest.fixture
def investigation() -> IncidentInvestigationWorkflow:
    """Create an investigation workflow."""
    return IncidentInvestigationWorkflow()


@pytest.fixture
def remediation() -> IncidentRemediationWorkflow:
    """Create a remediation workflow."""
    return IncidentRemediationWorkflow()


@pytest.fixture
def reporter(manager: IncidentManager) -> IncidentReporter:
    """Create an incident reporter."""
    return IncidentReporter(manager)


@pytest.fixture
def sample_incident() -> Incident:
    """Create a sample incident for testing."""
    return Incident(
        title="Test Incident",
        description="Test description",
        incident_type=IncidentType.POLICY_VIOLATION,
        severity=IncidentSeverity.MEDIUM,
        deployment_id="deploy-123",
        evidence={"policy_rule": "deny-pii", "user_id": "user-123"},
    )


# =============================================================================
# Triage Workflow Tests
# =============================================================================


class TestIncidentTriageWorkflow:
    """Tests for IncidentTriageWorkflow."""

    def test_triage_default_decision(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test default triage decision is INVESTIGATE."""
        result = triage.triage(sample_incident)

        assert result["decision"] == TriageDecision.INVESTIGATE
        assert result["sla_deadline"] is not None

    def test_triage_with_rule(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test triage with matching rule."""
        rule = TriageRule(
            name="dismiss-low-violations",
            condition={"incident_type": "POLICY_VIOLATION", "severity": "MEDIUM"},
            decision=TriageDecision.DISMISS,
        )
        triage.add_rule(rule)

        result = triage.triage(sample_incident)

        assert result["decision"] == TriageDecision.DISMISS
        assert result["matched_rule"] == "dismiss-low-violations"

    def test_triage_rule_auto_assign(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test rule with auto-assignment."""
        rule = TriageRule(
            name="assign-violations",
            condition={"incident_type": "POLICY_VIOLATION"},
            decision=TriageDecision.INVESTIGATE,
            auto_assign="security-team",
        )
        triage.add_rule(rule)

        result = triage.triage(sample_incident)

        assert result["assignee"] == "security-team"

    def test_triage_rule_severity_override(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test rule with severity override."""
        rule = TriageRule(
            name="escalate-violations",
            condition={"incident_type": "POLICY_VIOLATION"},
            decision=TriageDecision.ESCALATE,
            severity_override=IncidentSeverity.HIGH,
        )
        triage.add_rule(rule)

        result = triage.triage(sample_incident)

        assert result["severity"] == IncidentSeverity.HIGH

    def test_triage_rule_priority(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test rules are applied in priority order."""
        rule1 = TriageRule(
            name="low-priority",
            condition={"incident_type": "POLICY_VIOLATION"},
            decision=TriageDecision.DISMISS,
            priority=100,
        )
        rule2 = TriageRule(
            name="high-priority",
            condition={"incident_type": "POLICY_VIOLATION"},
            decision=TriageDecision.ESCALATE,
            priority=10,
        )
        triage.add_rule(rule1)
        triage.add_rule(rule2)

        result = triage.triage(sample_incident)

        # Higher priority (lower number) should match first
        assert result["matched_rule"] == "high-priority"
        assert result["decision"] == TriageDecision.ESCALATE

    def test_triage_rule_tags_to_add(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test rule adds tags."""
        rule = TriageRule(
            name="tag-violations",
            condition={"incident_type": "POLICY_VIOLATION"},
            decision=TriageDecision.INVESTIGATE,
            tags_to_add=["reviewed", "needs-attention"],
        )
        triage.add_rule(rule)

        result = triage.triage(sample_incident)

        assert "reviewed" in result["tags_added"]
        assert "needs-attention" in result["tags_added"]

    def test_remove_rule(self, triage: IncidentTriageWorkflow) -> None:
        """Test removing a rule."""
        rule = TriageRule(rule_id="test-rule", name="Test")
        triage.add_rule(rule)

        assert triage.remove_rule("test-rule") is True
        assert triage.remove_rule("nonexistent") is False
        assert len(triage.list_rules()) == 0

    def test_check_sla_breach(
        self, triage: IncidentTriageWorkflow
    ) -> None:
        """Test SLA breach checking."""
        incident = Incident(
            severity=IncidentSeverity.CRITICAL,
            created_at=utc_now() - timedelta(hours=2),  # 2 hours ago
        )

        result = triage.check_sla_breach(incident)

        # Critical has 0.5 hour SLA, so should be breached
        assert result["is_breached"] is True
        assert result["time_overdue"] is not None

    def test_check_sla_not_breached(
        self, triage: IncidentTriageWorkflow
    ) -> None:
        """Test SLA not breached."""
        incident = Incident(
            severity=IncidentSeverity.LOW,
            created_at=utc_now() - timedelta(hours=1),  # 1 hour ago
        )

        result = triage.check_sla_breach(incident)

        # Low has 24 hour SLA, so should not be breached
        assert result["is_breached"] is False
        assert result["time_remaining"] is not None

    def test_get_escalation_target(
        self, triage: IncidentTriageWorkflow
    ) -> None:
        """Test getting escalation target."""
        incident = Incident(severity=IncidentSeverity.CRITICAL)
        target = triage.get_escalation_target(incident)
        assert target == "security-director"

        incident_low = Incident(severity=IncidentSeverity.LOW)
        target_low = triage.get_escalation_target(incident_low)
        assert target_low == "incident-team"

    def test_triage_callback(
        self, triage: IncidentTriageWorkflow, sample_incident: Incident
    ) -> None:
        """Test triage callbacks."""
        decisions = []

        def callback(incident: Incident, decision: TriageDecision) -> None:
            decisions.append((incident.incident_id, decision))

        triage.on_decision(callback)
        triage.triage(sample_incident)

        assert len(decisions) == 1
        assert decisions[0][1] == TriageDecision.INVESTIGATE


# =============================================================================
# Investigation Workflow Tests
# =============================================================================


class TestIncidentInvestigationWorkflow:
    """Tests for IncidentInvestigationWorkflow."""

    def test_start_investigation(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test starting an investigation."""
        steps = investigation.start(sample_incident, investigator="analyst")

        assert len(steps) > 0
        assert steps[0].status == WorkflowStepStatus.IN_PROGRESS
        assert steps[0].assignee == "analyst"

    def test_start_with_custom_steps(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test starting with custom steps."""
        custom_steps = [
            WorkflowStep(name="Step 1", description="First step"),
            WorkflowStep(name="Step 2", description="Second step"),
        ]

        steps = investigation.start(
            sample_incident, investigator="analyst", custom_steps=custom_steps
        )

        assert len(steps) == 2
        assert steps[0].name == "Step 1"
        assert steps[1].name == "Step 2"

    def test_add_investigator(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test adding an investigator."""
        investigation.start(sample_incident, investigator="analyst1")
        investigation.add_investigator(sample_incident.incident_id, "analyst2")

        investigators = investigation.get_investigators(sample_incident.incident_id)

        assert "analyst1" in investigators
        assert "analyst2" in investigators

    def test_remove_investigator(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test removing an investigator."""
        investigation.start(sample_incident, investigator="analyst1")
        investigation.add_investigator(sample_incident.incident_id, "analyst2")

        result = investigation.remove_investigator(
            sample_incident.incident_id, "analyst2"
        )

        assert result is True
        assert "analyst2" not in investigation.get_investigators(
            sample_incident.incident_id
        )

    def test_add_step(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test adding a step."""
        investigation.start(sample_incident, investigator="analyst")

        new_step = WorkflowStep(name="Extra Step", description="Additional work")
        investigation.add_step(sample_incident.incident_id, new_step)

        steps = investigation.get_steps(sample_incident.incident_id)
        step_names = [s.name for s in steps]

        assert "Extra Step" in step_names

    def test_complete_step(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test completing a step."""
        steps = investigation.start(sample_incident, investigator="analyst")
        step_id = steps[0].step_id

        next_step = investigation.complete_step(
            sample_incident.incident_id,
            step_id,
            notes="Completed analysis",
            findings={"anomalies": 5},
        )

        completed_step = investigation.get_step(sample_incident.incident_id, step_id)

        assert completed_step.status == WorkflowStepStatus.COMPLETED
        assert completed_step.notes == "Completed analysis"
        assert completed_step.findings["anomalies"] == 5
        assert next_step is not None  # Next step should have started

    def test_skip_step(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test skipping a step."""
        steps = investigation.start(sample_incident, investigator="analyst")
        step_id = steps[0].step_id

        investigation.skip_step(
            sample_incident.incident_id, step_id, reason="Not applicable"
        )

        step = investigation.get_step(sample_incident.incident_id, step_id)

        assert step.status == WorkflowStepStatus.SKIPPED
        assert step.notes == "Not applicable"

    def test_get_progress(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test getting investigation progress."""
        steps = investigation.start(sample_incident, investigator="analyst")

        # Complete first step
        investigation.complete_step(sample_incident.incident_id, steps[0].step_id)

        progress = investigation.get_progress(sample_incident.incident_id)

        assert progress["completed"] == 1
        assert progress["in_progress"] == 1  # Next step started
        assert progress["progress_percent"] > 0

    def test_get_findings(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test aggregating findings."""
        steps = investigation.start(sample_incident, investigator="analyst")

        investigation.complete_step(
            sample_incident.incident_id,
            steps[0].step_id,
            findings={"finding1": "value1"},
        )

        findings = investigation.get_findings(sample_incident.incident_id)

        assert steps[0].name in findings
        assert findings[steps[0].name]["finding1"] == "value1"

    def test_get_current_step(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test getting current active step."""
        steps = investigation.start(sample_incident, investigator="analyst")

        current = investigation.get_current_step(sample_incident.incident_id)

        assert current is not None
        assert current.step_id == steps[0].step_id

    def test_overdue_steps(
        self, investigation: IncidentInvestigationWorkflow, sample_incident: Incident
    ) -> None:
        """Test detecting overdue steps."""
        steps = investigation.start(sample_incident, investigator="analyst")

        # Set a step as overdue
        steps[0].due_at = utc_now() - timedelta(hours=1)

        overdue = investigation.get_overdue_steps(sample_incident.incident_id)

        assert len(overdue) == 1


# =============================================================================
# Remediation Workflow Tests
# =============================================================================


class TestIncidentRemediationWorkflow:
    """Tests for IncidentRemediationWorkflow."""

    def test_add_action(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test adding a remediation action."""
        action = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-123",
            target_type="token",
            description="Revoke compromised token",
        )
        remediation.add_action("inc-123", action)

        actions = remediation.get_actions("inc-123")

        assert len(actions) == 1
        assert actions[0].action == RemediationAction.REVOKE_TOKEN

    def test_execute_action(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test executing a remediation action."""
        action = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-123",
            target_type="token",
        )
        remediation.add_action("inc-123", action)

        executed = remediation.execute_action(
            "inc-123", action.step_id, executed_by="admin"
        )

        assert executed is not None
        assert executed.executed_at is not None
        assert executed.executed_by == "admin"
        assert executed.status == WorkflowStepStatus.COMPLETED

    def test_verify_action(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test verifying a remediation action."""
        action = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-123",
            target_type="token",
        )
        remediation.add_action("inc-123", action)
        remediation.execute_action("inc-123", action.step_id, executed_by="admin")

        verified = remediation.verify_action(
            "inc-123", action.step_id, verified_by="analyst", effective=True
        )

        assert verified is not None
        assert verified.verified is True
        assert verified.verified_by == "analyst"

    def test_link_policy_change(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test linking a policy change."""
        remediation.link_policy_change("inc-123", "policy-456")

        policies = remediation.get_linked_policies("inc-123")

        assert "policy-456" in policies

    def test_link_suspension(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test linking a deployment suspension."""
        remediation.link_suspension("inc-123", "deploy-456")

        suspensions = remediation.get_linked_suspensions("inc-123")

        assert "deploy-456" in suspensions

    def test_get_status(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test getting remediation status."""
        action1 = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-1",
            target_type="token",
        )
        action2 = RemediationStep(
            action=RemediationAction.NOTIFY_OWNER,
            target_id="deploy-1",
            target_type="deployment",
        )
        remediation.add_action("inc-123", action1)
        remediation.add_action("inc-123", action2)

        remediation.execute_action("inc-123", action1.step_id, executed_by="admin")

        status = remediation.get_status("inc-123")

        assert status["total_actions"] == 2
        assert status["executed"] == 1
        assert status["pending"] == 1
        assert status["all_executed"] is False

    def test_get_pending_actions(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test getting pending actions."""
        action1 = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN, target_id="token-1", target_type="token"
        )
        action2 = RemediationStep(
            action=RemediationAction.NOTIFY_OWNER, target_id="deploy-1", target_type="deployment"
        )
        remediation.add_action("inc-123", action1)
        remediation.add_action("inc-123", action2)

        remediation.execute_action("inc-123", action1.step_id, executed_by="admin")

        pending = remediation.get_pending_actions("inc-123")

        assert len(pending) == 1
        assert pending[0].action == RemediationAction.NOTIFY_OWNER

    def test_get_unverified_actions(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test getting unverified actions."""
        action = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN, target_id="token-1", target_type="token"
        )
        remediation.add_action("inc-123", action)
        remediation.execute_action("inc-123", action.step_id, executed_by="admin")

        unverified = remediation.get_unverified_actions("inc-123")

        assert len(unverified) == 1

    def test_suggest_remediations_data_leak(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test suggesting remediations for data leak."""
        incident = Incident(
            incident_type=IncidentType.DATA_LEAK,
            severity=IncidentSeverity.HIGH,
            deployment_id="deploy-123",
            evidence={"token_id": "token-456"},
        )

        suggestions = remediation.suggest_remediations(incident)

        actions = [s.action for s in suggestions]
        assert RemediationAction.REVOKE_TOKEN in actions
        assert RemediationAction.AUDIT_ACCESS in actions

    def test_suggest_remediations_jailbreak(
        self, remediation: IncidentRemediationWorkflow
    ) -> None:
        """Test suggesting remediations for jailbreak."""
        incident = Incident(
            incident_type=IncidentType.JAILBREAK,
            severity=IncidentSeverity.HIGH,
            evidence={"user_id": "user-123"},
        )

        suggestions = remediation.suggest_remediations(incident)

        actions = [s.action for s in suggestions]
        assert RemediationAction.BLOCK_USER in actions
        assert RemediationAction.UPDATE_POLICY in actions


# =============================================================================
# Reporter Tests
# =============================================================================


class TestIncidentReporter:
    """Tests for IncidentReporter."""

    def test_generate_incident_report_markdown(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating individual incident report in Markdown."""
        incident = manager.create(
            title="Test Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.HIGH,
            description="Test description",
        )

        report = reporter.generate_incident_report(
            incident, format=ReportFormat.MARKDOWN
        )

        assert "# Incident Report:" in report
        assert "Test Incident" in report
        assert "HIGH" in report

    def test_generate_incident_report_json(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating individual incident report in JSON."""
        incident = manager.create(
            title="Test Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
        )

        report = reporter.generate_incident_report(
            incident, format=ReportFormat.JSON
        )

        import json
        data = json.loads(report)

        assert "incident" in data
        assert data["incident"]["title"] == "Test Incident"

    def test_generate_incident_report_text(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating individual incident report in plain text."""
        incident = manager.create(
            title="Test Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
        )

        report = reporter.generate_incident_report(
            incident, format=ReportFormat.TEXT
        )

        assert "INCIDENT REPORT:" in report
        assert "Test Incident" in report

    def test_generate_summary_report_markdown(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating summary report in Markdown."""
        manager.create(
            title="Incident 1",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.LOW,
        )
        manager.create(
            title="Incident 2",
            incident_type=IncidentType.DATA_LEAK,
            severity=IncidentSeverity.HIGH,
        )

        report = reporter.generate_summary_report(format=ReportFormat.MARKDOWN)

        assert "# Incident Summary Report" in report
        assert "Total Incidents" in report

    def test_generate_summary_report_json(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating summary report in JSON."""
        manager.create(
            title="Incident 1",
            incident_type=IncidentType.POLICY_VIOLATION,
        )

        report = reporter.generate_summary_report(format=ReportFormat.JSON)

        import json
        data = json.loads(report)

        assert data["report_type"] == "summary"
        assert "metrics" in data

    def test_generate_trend_report(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating trend report."""
        manager.create(
            title="Incident 1",
            incident_type=IncidentType.POLICY_VIOLATION,
        )

        report = reporter.generate_trend_report(days=7, format=ReportFormat.MARKDOWN)

        assert "# Incident Trend Analysis" in report
        assert "Last 7 days" in report

    def test_generate_deployment_report(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating deployment report."""
        manager.create(
            title="Incident 1",
            incident_type=IncidentType.POLICY_VIOLATION,
            deployment_id="deploy-123",
        )
        manager.create(
            title="Incident 2",
            incident_type=IncidentType.DATA_LEAK,
            deployment_id="deploy-123",
        )

        report = reporter.generate_deployment_report(
            "deploy-123", format=ReportFormat.MARKDOWN
        )

        assert "deploy-123" in report
        assert "Total Incidents" in report

    def test_generate_compliance_report(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test generating compliance report."""
        manager.create(
            title="Incident 1",
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=IncidentSeverity.CRITICAL,
        )
        inc2 = manager.create(
            title="Incident 2",
            incident_type=IncidentType.DATA_LEAK,
            severity=IncidentSeverity.HIGH,
        )
        manager.resolve(inc2.incident_id, "Resolved")

        report = reporter.generate_compliance_report(format=ReportFormat.MARKDOWN)

        assert "AI Governance Compliance Report" in report
        assert "Executive Summary" in report
        assert "Key Metrics" in report

    def test_generate_compliance_report_with_unresolved(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test compliance report includes unresolved incidents."""
        manager.create(
            title="Critical Unresolved",
            incident_type=IncidentType.DATA_LEAK,
            severity=IncidentSeverity.CRITICAL,
        )

        report = reporter.generate_compliance_report(
            include_unresolved=True, format=ReportFormat.MARKDOWN
        )

        assert "Outstanding Incidents" in report
        assert "Critical Priority" in report

    def test_report_with_timeline(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test incident report includes timeline."""
        incident = manager.create(
            title="Test Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
        )
        manager.assign(incident.incident_id, "analyst")
        manager.start_investigation(incident.incident_id)

        report = reporter.generate_incident_report(
            manager.get(incident.incident_id),
            include_timeline=True,
            format=ReportFormat.MARKDOWN,
        )

        assert "Activity Timeline" in report

    def test_report_with_comments(
        self, manager: IncidentManager, reporter: IncidentReporter
    ) -> None:
        """Test incident report includes comments."""
        incident = manager.create(
            title="Test Incident",
            incident_type=IncidentType.POLICY_VIOLATION,
        )
        manager.add_comment(incident.incident_id, "analyst", "Investigation notes")

        report = reporter.generate_incident_report(
            manager.get(incident.incident_id),
            include_comments=True,
            format=ReportFormat.MARKDOWN,
        )

        assert "Comments" in report
        assert "Investigation notes" in report


# =============================================================================
# Workflow Step Tests
# =============================================================================


class TestWorkflowStep:
    """Tests for WorkflowStep model."""

    def test_step_start(self) -> None:
        """Test starting a step."""
        step = WorkflowStep(name="Test Step")
        step.start("analyst")

        assert step.status == WorkflowStepStatus.IN_PROGRESS
        assert step.started_at is not None
        assert step.assignee == "analyst"

    def test_step_complete(self) -> None:
        """Test completing a step."""
        step = WorkflowStep(name="Test Step")
        step.start("analyst")
        step.complete(notes="Done", findings={"result": "success"})

        assert step.status == WorkflowStepStatus.COMPLETED
        assert step.completed_at is not None
        assert step.notes == "Done"
        assert step.findings["result"] == "success"

    def test_step_skip(self) -> None:
        """Test skipping a step."""
        step = WorkflowStep(name="Test Step")
        step.skip("Not needed")

        assert step.status == WorkflowStepStatus.SKIPPED
        assert step.notes == "Not needed"

    def test_step_fail(self) -> None:
        """Test failing a step."""
        step = WorkflowStep(name="Test Step")
        step.fail("Error occurred")

        assert step.status == WorkflowStepStatus.FAILED
        assert step.notes == "Error occurred"

    def test_step_is_overdue(self) -> None:
        """Test overdue detection."""
        step = WorkflowStep(
            name="Test Step",
            due_at=utc_now() - timedelta(hours=1),
        )
        step.start("analyst")

        assert step.is_overdue() is True

    def test_step_not_overdue(self) -> None:
        """Test not overdue."""
        step = WorkflowStep(
            name="Test Step",
            due_at=utc_now() + timedelta(hours=1),
        )
        step.start("analyst")

        assert step.is_overdue() is False

    def test_step_to_dict(self) -> None:
        """Test converting step to dict."""
        step = WorkflowStep(name="Test Step", description="Description")
        data = step.to_dict()

        assert data["name"] == "Test Step"
        assert data["description"] == "Description"
        assert data["status"] == "PENDING"


class TestRemediationStep:
    """Tests for RemediationStep model."""

    def test_execute(self) -> None:
        """Test executing a remediation step."""
        step = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-123",
        )
        step.execute("admin")

        assert step.executed_at is not None
        assert step.executed_by == "admin"
        assert step.status == WorkflowStepStatus.COMPLETED

    def test_verify(self) -> None:
        """Test verifying a remediation step."""
        step = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-123",
        )
        step.execute("admin")
        step.verify("analyst", effective=True, notes="Verified working")

        assert step.verified is True
        assert step.verified_by == "analyst"
        assert step.notes == "Verified working"

    def test_to_dict(self) -> None:
        """Test converting to dict."""
        step = RemediationStep(
            action=RemediationAction.REVOKE_TOKEN,
            target_id="token-123",
            target_type="token",
        )
        data = step.to_dict()

        assert data["action"] == "REVOKE_TOKEN"
        assert data["target_id"] == "token-123"
