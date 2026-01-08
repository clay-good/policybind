"""
Tests for PolicyBind registry workflows.

This module tests the ApprovalWorkflow, ReviewWorkflow, and SuspensionWorkflow
classes for managing deployment lifecycles.
"""

from datetime import timedelta

import pytest

from policybind.models.base import utc_now
from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel
from policybind.registry.workflows import (
    ApprovalStage,
    ApprovalWorkflow,
    ReviewWorkflow,
    SuspensionWorkflow,
    WorkflowInstance,
    WorkflowStatus,
    WorkflowStep,
)


# Fixtures


@pytest.fixture
def low_risk_deployment() -> ModelDeployment:
    """Create a low-risk test deployment."""
    return ModelDeployment(
        deployment_id="deploy-low-001",
        name="Test Bot Low",
        model_provider="openai",
        model_name="gpt-3.5-turbo",
        owner="test-team",
        owner_contact="test@example.com",
        risk_level=RiskLevel.LOW,
        approval_status=ApprovalStatus.PENDING,
    )


@pytest.fixture
def high_risk_deployment() -> ModelDeployment:
    """Create a high-risk test deployment."""
    return ModelDeployment(
        deployment_id="deploy-high-001",
        name="Critical System",
        model_provider="anthropic",
        model_name="claude-3-opus",
        owner="security-team",
        owner_contact="security@example.com",
        risk_level=RiskLevel.HIGH,
        data_categories=("pii", "financial"),
        approval_status=ApprovalStatus.PENDING,
    )


@pytest.fixture
def critical_risk_deployment() -> ModelDeployment:
    """Create a critical-risk test deployment."""
    return ModelDeployment(
        deployment_id="deploy-critical-001",
        name="Autonomous Decision System",
        model_provider="anthropic",
        model_name="claude-3-opus",
        owner="executive-team",
        owner_contact="cto@example.com",
        risk_level=RiskLevel.CRITICAL,
        data_categories=("pii", "financial", "healthcare"),
        approval_status=ApprovalStatus.PENDING,
    )


@pytest.fixture
def approved_deployment() -> ModelDeployment:
    """Create an approved deployment for review/suspension tests."""
    return ModelDeployment(
        deployment_id="deploy-approved-001",
        name="Production Bot",
        model_provider="openai",
        model_name="gpt-4",
        owner="prod-team",
        owner_contact="prod@example.com",
        risk_level=RiskLevel.MEDIUM,
        approval_status=ApprovalStatus.APPROVED,
    )


# ApprovalWorkflow Tests


class TestApprovalWorkflow:
    """Tests for the ApprovalWorkflow class."""

    def test_create_workflow_low_risk(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test creating a workflow for a low-risk deployment."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment, "admin")

        assert instance.workflow_type == "approval"
        assert instance.deployment_id == low_risk_deployment.deployment_id
        assert instance.status == WorkflowStatus.PENDING
        assert len(instance.steps) == 1  # Low risk has 1 stage
        assert instance.steps[0].stage == ApprovalStage.INITIAL_REVIEW

    def test_create_workflow_high_risk(
        self,
        high_risk_deployment: ModelDeployment,
    ) -> None:
        """Test creating a workflow for a high-risk deployment."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(high_risk_deployment, "admin")

        assert len(instance.steps) == 3  # High risk has 3 stages
        stages = [s.stage for s in instance.steps]
        assert ApprovalStage.INITIAL_REVIEW in stages
        assert ApprovalStage.SECURITY_REVIEW in stages
        assert ApprovalStage.COMPLIANCE_REVIEW in stages

    def test_create_workflow_critical_risk(
        self,
        critical_risk_deployment: ModelDeployment,
    ) -> None:
        """Test creating a workflow for a critical-risk deployment."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(critical_risk_deployment, "admin")

        assert len(instance.steps) == 4  # Critical has 4 stages
        stages = [s.stage for s in instance.steps]
        assert ApprovalStage.EXECUTIVE_APPROVAL in stages

    def test_start_workflow(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test starting a workflow."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)

        started = workflow.start_workflow(instance.workflow_id, "manager")

        assert started.status == WorkflowStatus.IN_PROGRESS
        assert started.started_at is not None
        assert started.steps[0].status == WorkflowStatus.AWAITING_ACTION
        assert started.steps[0].started_at is not None
        assert started.steps[0].due_at is not None

    def test_start_workflow_not_found(self) -> None:
        """Test starting a non-existent workflow raises error."""
        workflow = ApprovalWorkflow()

        with pytest.raises(ValueError, match="not found"):
            workflow.start_workflow("invalid-id")

    def test_start_workflow_already_started(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test starting an already-started workflow raises error."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        with pytest.raises(ValueError, match="already started"):
            workflow.start_workflow(instance.workflow_id)

    def test_complete_step_approved(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test completing a step with approval."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        completed = workflow.complete_step(
            instance.workflow_id,
            completed_by="reviewer@example.com",
            decision="approved",
            notes="Looks good",
        )

        # Low risk has only 1 step, so workflow should be complete
        assert completed.status == WorkflowStatus.COMPLETED
        assert completed.completed_at is not None
        assert completed.steps[0].decision == "approved"
        assert completed.steps[0].assignee == "reviewer@example.com"

    def test_complete_step_rejected(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test completing a step with rejection."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        rejected = workflow.complete_step(
            instance.workflow_id,
            completed_by="reviewer@example.com",
            decision="rejected",
            notes="Needs more documentation",
        )

        assert rejected.status == WorkflowStatus.FAILED
        assert rejected.completed_at is not None
        assert rejected.steps[0].decision == "rejected"

    def test_complete_multi_step_workflow(
        self,
        high_risk_deployment: ModelDeployment,
    ) -> None:
        """Test completing a multi-step workflow."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(high_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        # Complete first step
        after_step_1 = workflow.complete_step(
            instance.workflow_id,
            completed_by="manager",
            decision="approved",
        )
        assert after_step_1.current_step_index == 1
        assert after_step_1.steps[1].status == WorkflowStatus.AWAITING_ACTION

        # Complete second step
        after_step_2 = workflow.complete_step(
            instance.workflow_id,
            completed_by="security",
            decision="approved",
        )
        assert after_step_2.current_step_index == 2

        # Complete final step
        final = workflow.complete_step(
            instance.workflow_id,
            completed_by="compliance",
            decision="approved",
        )
        assert final.status == WorkflowStatus.COMPLETED

    def test_delegate_step(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test delegating a workflow step."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        delegated = workflow.delegate_step(
            instance.workflow_id,
            new_assignee="backup-reviewer@example.com",
            delegated_by="original@example.com",
            reason="Out of office",
        )

        current = delegated.current_step
        assert current is not None
        assert current.assignee == "backup-reviewer@example.com"
        assert current.metadata["delegated_from"] == ""  # Was empty
        assert current.metadata["delegated_by"] == "original@example.com"

    def test_escalate_workflow(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test escalating a workflow."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        escalated = workflow.escalate_workflow(
            instance.workflow_id,
            escalated_by="system",
            reason="SLA breach",
        )

        assert escalated.status == WorkflowStatus.ESCALATED
        assert escalated.metadata["escalation_reason"] == "SLA breach"

    def test_cancel_workflow(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test cancelling a workflow."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        cancelled = workflow.cancel_workflow(
            instance.workflow_id,
            cancelled_by="admin",
            reason="Deployment no longer needed",
        )

        assert cancelled.status == WorkflowStatus.CANCELLED
        assert cancelled.completed_at is not None

    def test_cancel_completed_workflow_fails(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test that cancelling a completed workflow fails."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)
        workflow.complete_step(instance.workflow_id, decision="approved")

        with pytest.raises(ValueError, match="already complete"):
            workflow.cancel_workflow(instance.workflow_id)

    def test_get_workflow(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test getting a workflow by ID."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)

        retrieved = workflow.get_workflow(instance.workflow_id)
        assert retrieved is not None
        assert retrieved.workflow_id == instance.workflow_id

    def test_get_workflows_for_deployment(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test getting workflows for a deployment."""
        workflow = ApprovalWorkflow()
        workflow.create_workflow(low_risk_deployment)
        workflow.create_workflow(low_risk_deployment)

        workflows = workflow.get_workflows_for_deployment(
            low_risk_deployment.deployment_id
        )
        assert len(workflows) == 2

    def test_get_pending_workflows(
        self,
        low_risk_deployment: ModelDeployment,
        high_risk_deployment: ModelDeployment,
    ) -> None:
        """Test getting pending workflows."""
        workflow = ApprovalWorkflow()

        w1 = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(w1.workflow_id)

        w2 = workflow.create_workflow(high_risk_deployment)
        # Don't start w2

        pending = workflow.get_pending_workflows()
        assert len(pending) == 2  # Both are pending (not completed)

    def test_get_overdue_workflows(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test getting overdue workflows."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        # Manually set the due date to past
        instance.steps[0].due_at = utc_now() - timedelta(hours=1)

        overdue = workflow.get_overdue_workflows()
        assert len(overdue) == 1
        assert overdue[0].workflow_id == instance.workflow_id

    def test_check_sla_breaches(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test checking and escalating SLA breaches."""
        workflow = ApprovalWorkflow()
        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)

        # Set due date to past
        instance.steps[0].due_at = utc_now() - timedelta(hours=1)

        escalated = workflow.check_sla_breaches()
        assert len(escalated) == 1

        updated = workflow.get_workflow(instance.workflow_id)
        assert updated is not None
        assert updated.status == WorkflowStatus.ESCALATED

    def test_workflow_callback(
        self,
        low_risk_deployment: ModelDeployment,
    ) -> None:
        """Test workflow event callbacks."""
        events: list[tuple[WorkflowInstance, str]] = []

        def callback(instance: WorkflowInstance, event_type: str) -> None:
            events.append((instance, event_type))

        workflow = ApprovalWorkflow()
        workflow.on_workflow_event(callback)

        instance = workflow.create_workflow(low_risk_deployment)
        workflow.start_workflow(instance.workflow_id)
        workflow.complete_step(instance.workflow_id, decision="approved")

        assert len(events) == 3
        assert events[0][1] == "created"
        assert events[1][1] == "started"
        assert events[2][1] == "completed"


# ReviewWorkflow Tests


class TestReviewWorkflow:
    """Tests for the ReviewWorkflow class."""

    def test_create_review(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test creating a review workflow."""
        workflow = ReviewWorkflow()
        instance = workflow.create_review(approved_deployment, "system")

        assert instance.workflow_type == "review"
        assert instance.deployment_id == approved_deployment.deployment_id
        assert instance.status == WorkflowStatus.IN_PROGRESS
        assert len(instance.steps) == 1
        assert instance.steps[0].due_at is not None

    def test_create_review_custom_due_date(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test creating a review with a custom due date."""
        due_date = utc_now() + timedelta(days=30)
        workflow = ReviewWorkflow()
        instance = workflow.create_review(
            approved_deployment,
            due_date=due_date,
        )

        assert instance.steps[0].due_at == due_date

    def test_complete_review(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test completing a review."""
        workflow = ReviewWorkflow()
        instance = workflow.create_review(approved_deployment)

        completed = workflow.complete_review(
            instance.workflow_id,
            reviewed_by="reviewer@example.com",
            findings="All systems operating normally",
            recommend_changes=False,
        )

        assert completed.status == WorkflowStatus.COMPLETED
        assert completed.completed_at is not None
        assert completed.metadata["reviewed_by"] == "reviewer@example.com"
        assert not completed.metadata["recommend_changes"]

    def test_complete_review_with_changes(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test completing a review with change recommendations."""
        workflow = ReviewWorkflow()
        instance = workflow.create_review(approved_deployment)

        completed = workflow.complete_review(
            instance.workflow_id,
            reviewed_by="reviewer@example.com",
            findings="Need to update model version",
            recommend_changes=True,
        )

        assert completed.metadata["recommend_changes"] is True
        assert completed.steps[0].decision == "changes_recommended"

    def test_get_reviews_due(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test getting reviews due within a time period."""
        workflow = ReviewWorkflow()

        # Create review due in 3 days
        due_soon = utc_now() + timedelta(days=3)
        r1 = workflow.create_review(approved_deployment, due_date=due_soon)

        # Create review due in 14 days
        due_later = utc_now() + timedelta(days=14)
        workflow.create_review(approved_deployment, due_date=due_later)

        due = workflow.get_reviews_due(within_days=7)
        assert len(due) == 1
        assert due[0].workflow_id == r1.workflow_id

    def test_get_overdue_reviews(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test getting overdue reviews."""
        workflow = ReviewWorkflow()

        past_due = utc_now() - timedelta(days=1)
        instance = workflow.create_review(approved_deployment, due_date=past_due)

        overdue = workflow.get_overdue_reviews()
        assert len(overdue) == 1
        assert overdue[0].workflow_id == instance.workflow_id

    def test_get_reviews_requiring_suspension(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test getting reviews past their grace period."""
        workflow = ReviewWorkflow(grace_period_days=7)

        # Past due by 10 days (past 7-day grace period)
        past_grace = utc_now() - timedelta(days=10)
        instance = workflow.create_review(approved_deployment, due_date=past_grace)

        requiring_suspension = workflow.get_reviews_requiring_suspension()
        assert len(requiring_suspension) == 1
        assert requiring_suspension[0].workflow_id == instance.workflow_id

    def test_get_active_review_for_deployment(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test getting the active review for a deployment."""
        workflow = ReviewWorkflow()
        instance = workflow.create_review(approved_deployment)

        active = workflow.get_active_review_for_deployment(
            approved_deployment.deployment_id
        )
        assert active is not None
        assert active.workflow_id == instance.workflow_id

        # Complete the review
        workflow.complete_review(
            instance.workflow_id,
            reviewed_by="reviewer",
        )

        # Should return None now
        active = workflow.get_active_review_for_deployment(
            approved_deployment.deployment_id
        )
        assert active is None


# SuspensionWorkflow Tests


class TestSuspensionWorkflow:
    """Tests for the SuspensionWorkflow class."""

    def test_create_suspension(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test creating a suspension workflow."""
        workflow = SuspensionWorkflow()
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Policy violations exceeded threshold",
            suspended_by="system",
            suspension_type="violation",
        )

        assert instance.workflow_type == "suspension"
        assert instance.deployment_id == approved_deployment.deployment_id
        assert instance.status == WorkflowStatus.IN_PROGRESS
        assert instance.metadata["reason"] == "Policy violations exceeded threshold"
        assert instance.metadata["suspension_type"] == "violation"

    def test_create_suspension_with_reinstatement_step(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test suspension includes reinstatement step when required."""
        workflow = SuspensionWorkflow(require_approval_for_reinstatement=True)
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Manual suspension",
        )

        # Should have 2 steps: suspension and reinstatement
        assert len(instance.steps) == 2
        assert instance.steps[0].name == "Suspension"
        assert instance.steps[1].name == "Reinstatement Approval"

    def test_create_suspension_without_reinstatement_step(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test suspension without reinstatement step."""
        workflow = SuspensionWorkflow(require_approval_for_reinstatement=False)
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Manual suspension",
        )

        # Should only have suspension step
        assert len(instance.steps) == 1

    def test_request_reinstatement(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test requesting reinstatement."""
        workflow = SuspensionWorkflow()
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Policy violation",
        )

        requested = workflow.request_reinstatement(
            instance.workflow_id,
            requested_by="owner@example.com",
            justification="Issue has been resolved",
        )

        assert requested.status == WorkflowStatus.AWAITING_ACTION
        assert requested.current_step_index == 1
        assert requested.steps[1].status == WorkflowStatus.AWAITING_ACTION
        assert requested.steps[1].metadata["requested_by"] == "owner@example.com"

    def test_complete_reinstatement_approved(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test approving reinstatement."""
        workflow = SuspensionWorkflow()
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Policy violation",
        )
        workflow.request_reinstatement(
            instance.workflow_id,
            requested_by="owner@example.com",
        )

        reinstated = workflow.complete_reinstatement(
            instance.workflow_id,
            reinstated_by="admin@example.com",
            approved=True,
            notes="Issue verified as fixed",
        )

        assert reinstated.status == WorkflowStatus.COMPLETED
        assert reinstated.metadata["reinstated_by"] == "admin@example.com"

    def test_complete_reinstatement_denied(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test denying reinstatement."""
        workflow = SuspensionWorkflow()
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Serious violation",
        )
        workflow.request_reinstatement(
            instance.workflow_id,
            requested_by="owner@example.com",
        )

        denied = workflow.complete_reinstatement(
            instance.workflow_id,
            reinstated_by="security@example.com",
            approved=False,
            notes="Violation not adequately addressed",
        )

        assert denied.status == WorkflowStatus.FAILED
        assert "reinstatement_denied_by" in denied.metadata

    def test_get_active_suspension(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test getting the active suspension for a deployment."""
        workflow = SuspensionWorkflow()
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Test",
        )

        active = workflow.get_active_suspension(approved_deployment.deployment_id)
        assert active is not None
        assert active.workflow_id == instance.workflow_id

    def test_get_pending_reinstatements(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test getting pending reinstatement requests."""
        workflow = SuspensionWorkflow()
        instance = workflow.create_suspension(
            approved_deployment,
            reason="Violation",
        )
        workflow.request_reinstatement(
            instance.workflow_id,
            requested_by="owner@example.com",
        )

        pending = workflow.get_pending_reinstatements()
        assert len(pending) == 1
        assert pending[0].workflow_id == instance.workflow_id

    def test_suspension_callback(
        self,
        approved_deployment: ModelDeployment,
    ) -> None:
        """Test suspension workflow event callbacks."""
        events: list[tuple[WorkflowInstance, str]] = []

        def callback(instance: WorkflowInstance, event_type: str) -> None:
            events.append((instance, event_type))

        workflow = SuspensionWorkflow()
        workflow.on_workflow_event(callback)

        instance = workflow.create_suspension(
            approved_deployment,
            reason="Test",
        )
        workflow.request_reinstatement(
            instance.workflow_id,
            requested_by="owner",
        )
        workflow.complete_reinstatement(
            instance.workflow_id,
            reinstated_by="admin",
            approved=True,
        )

        assert len(events) == 3
        assert events[0][1] == "suspension_created"
        assert events[1][1] == "reinstatement_requested"
        assert events[2][1] == "reinstated"


# WorkflowStep and WorkflowInstance Tests


class TestWorkflowStep:
    """Tests for the WorkflowStep dataclass."""

    def test_step_to_dict(self) -> None:
        """Test converting a step to dictionary."""
        step = WorkflowStep(
            name="Test Step",
            stage=ApprovalStage.INITIAL_REVIEW,
            status=WorkflowStatus.PENDING,
            assignee="test@example.com",
        )

        data = step.to_dict()
        assert data["name"] == "Test Step"
        assert data["stage"] == "initial_review"
        assert data["status"] == "pending"
        assert data["assignee"] == "test@example.com"


class TestWorkflowInstance:
    """Tests for the WorkflowInstance dataclass."""

    def test_instance_to_dict(self) -> None:
        """Test converting an instance to dictionary."""
        step = WorkflowStep(name="Step 1")
        instance = WorkflowInstance(
            workflow_type="approval",
            deployment_id="deploy-001",
            steps=[step],
        )

        data = instance.to_dict()
        assert data["workflow_type"] == "approval"
        assert data["deployment_id"] == "deploy-001"
        assert len(data["steps"]) == 1

    def test_current_step(self) -> None:
        """Test getting the current step."""
        steps = [
            WorkflowStep(name="Step 1"),
            WorkflowStep(name="Step 2"),
        ]
        instance = WorkflowInstance(steps=steps, current_step_index=1)

        current = instance.current_step
        assert current is not None
        assert current.name == "Step 2"

    def test_current_step_empty(self) -> None:
        """Test getting current step when no steps."""
        instance = WorkflowInstance()
        assert instance.current_step is None

    def test_is_complete(self) -> None:
        """Test checking if workflow is complete."""
        instance = WorkflowInstance(status=WorkflowStatus.PENDING)
        assert not instance.is_complete()

        instance.status = WorkflowStatus.IN_PROGRESS
        assert not instance.is_complete()

        instance.status = WorkflowStatus.COMPLETED
        assert instance.is_complete()

        instance.status = WorkflowStatus.CANCELLED
        assert instance.is_complete()

        instance.status = WorkflowStatus.FAILED
        assert instance.is_complete()
