"""
Workflow implementations for PolicyBind registry.

This module provides workflow classes for managing the lifecycle of
model deployments, including approval, review, and suspension processes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from policybind.models.base import generate_uuid, utc_now
from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel


class ApprovalStage(Enum):
    """Stages in the approval workflow."""

    INITIAL_REVIEW = "initial_review"
    """Initial review by deployment owner's manager."""

    SECURITY_REVIEW = "security_review"
    """Security team review for risk assessment."""

    COMPLIANCE_REVIEW = "compliance_review"
    """Compliance team review for regulatory requirements."""

    EXECUTIVE_APPROVAL = "executive_approval"
    """Executive approval for high-risk deployments."""

    FINAL_APPROVAL = "final_approval"
    """Final approval and activation."""


class WorkflowStatus(Enum):
    """Status of a workflow instance."""

    PENDING = "pending"
    """Workflow is waiting to be started."""

    IN_PROGRESS = "in_progress"
    """Workflow is actively being processed."""

    AWAITING_ACTION = "awaiting_action"
    """Workflow is waiting for someone to take action."""

    COMPLETED = "completed"
    """Workflow has been completed successfully."""

    CANCELLED = "cancelled"
    """Workflow was cancelled."""

    ESCALATED = "escalated"
    """Workflow has been escalated due to SLA breach."""

    FAILED = "failed"
    """Workflow failed to complete."""


@dataclass
class WorkflowStep:
    """
    A single step in a workflow.

    Attributes:
        step_id: Unique identifier for this step.
        name: Name of the step.
        stage: The approval stage this step belongs to.
        status: Current status of the step.
        assignee: Who is responsible for this step.
        started_at: When the step was started.
        completed_at: When the step was completed.
        due_at: Deadline for completing this step.
        notes: Notes added during the step.
        decision: The decision made (approved, rejected, etc.).
        metadata: Additional step metadata.
    """

    step_id: str = field(default_factory=generate_uuid)
    name: str = ""
    stage: ApprovalStage = ApprovalStage.INITIAL_REVIEW
    status: WorkflowStatus = WorkflowStatus.PENDING
    assignee: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    due_at: datetime | None = None
    notes: str = ""
    decision: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step_id": self.step_id,
            "name": self.name,
            "stage": self.stage.value,
            "status": self.status.value,
            "assignee": self.assignee,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "notes": self.notes,
            "decision": self.decision,
            "metadata": self.metadata,
        }


@dataclass
class WorkflowInstance:
    """
    An instance of a workflow for a specific deployment.

    Attributes:
        workflow_id: Unique identifier for this workflow instance.
        workflow_type: Type of workflow (approval, review, suspension).
        deployment_id: The deployment this workflow is for.
        status: Current status of the workflow.
        steps: List of steps in this workflow.
        created_at: When the workflow was created.
        updated_at: When the workflow was last updated.
        started_at: When the workflow was started.
        completed_at: When the workflow was completed.
        created_by: Who created this workflow.
        current_step_index: Index of the current step.
        metadata: Additional workflow metadata.
    """

    workflow_id: str = field(default_factory=generate_uuid)
    workflow_type: str = ""
    deployment_id: str = ""
    status: WorkflowStatus = WorkflowStatus.PENDING
    steps: list[WorkflowStep] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_by: str = ""
    current_step_index: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "workflow_id": self.workflow_id,
            "workflow_type": self.workflow_type,
            "deployment_id": self.deployment_id,
            "status": self.status.value,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "current_step_index": self.current_step_index,
            "metadata": self.metadata,
        }

    @property
    def current_step(self) -> WorkflowStep | None:
        """Get the current step."""
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    def is_complete(self) -> bool:
        """Check if the workflow is complete."""
        return self.status in (
            WorkflowStatus.COMPLETED,
            WorkflowStatus.CANCELLED,
            WorkflowStatus.FAILED,
        )


# Type alias for workflow callbacks
WorkflowCallback = Callable[[WorkflowInstance, str], None]


class ApprovalWorkflow:
    """
    Manages the approval process for new deployments.

    The ApprovalWorkflow handles:
    - Multiple approval stages based on risk level
    - Tracking approval status and approver information
    - Delegation and escalation
    - SLA enforcement for approval decisions
    - Notification triggers

    Example:
        Creating an approval workflow::

            workflow = ApprovalWorkflow()
            instance = workflow.create_workflow(deployment)

            # Start the workflow
            workflow.start_workflow(instance.workflow_id)

            # Complete a step
            workflow.complete_step(
                instance.workflow_id,
                approved_by="manager@example.com",
                decision="approved",
            )
    """

    # Default SLA hours for each risk level
    DEFAULT_SLA_HOURS = {
        RiskLevel.LOW: 24,
        RiskLevel.MEDIUM: 48,
        RiskLevel.HIGH: 72,
        RiskLevel.CRITICAL: 96,
    }

    # Required stages for each risk level
    REQUIRED_STAGES = {
        RiskLevel.LOW: [ApprovalStage.INITIAL_REVIEW],
        RiskLevel.MEDIUM: [
            ApprovalStage.INITIAL_REVIEW,
            ApprovalStage.SECURITY_REVIEW,
        ],
        RiskLevel.HIGH: [
            ApprovalStage.INITIAL_REVIEW,
            ApprovalStage.SECURITY_REVIEW,
            ApprovalStage.COMPLIANCE_REVIEW,
        ],
        RiskLevel.CRITICAL: [
            ApprovalStage.INITIAL_REVIEW,
            ApprovalStage.SECURITY_REVIEW,
            ApprovalStage.COMPLIANCE_REVIEW,
            ApprovalStage.EXECUTIVE_APPROVAL,
        ],
    }

    def __init__(
        self,
        sla_hours: dict[RiskLevel, int] | None = None,
        required_stages: dict[RiskLevel, list[ApprovalStage]] | None = None,
        default_assignees: dict[ApprovalStage, str] | None = None,
    ) -> None:
        """
        Initialize the approval workflow.

        Args:
            sla_hours: SLA hours for each risk level.
            required_stages: Required stages for each risk level.
            default_assignees: Default assignees for each stage.
        """
        self._sla_hours = sla_hours or self.DEFAULT_SLA_HOURS
        self._required_stages = required_stages or self.REQUIRED_STAGES
        self._default_assignees = default_assignees or {}
        self._workflows: dict[str, WorkflowInstance] = {}
        self._callbacks: list[WorkflowCallback] = []

    def on_workflow_event(self, callback: WorkflowCallback) -> None:
        """Register a callback for workflow events."""
        self._callbacks.append(callback)

    def create_workflow(
        self,
        deployment: ModelDeployment,
        created_by: str = "",
    ) -> WorkflowInstance:
        """
        Create an approval workflow for a deployment.

        Args:
            deployment: The deployment needing approval.
            created_by: Who is creating the workflow.

        Returns:
            The created workflow instance.
        """
        stages = self._required_stages.get(
            deployment.risk_level, [ApprovalStage.INITIAL_REVIEW]
        )

        steps = []
        for i, stage in enumerate(stages):
            assignee = self._default_assignees.get(stage, "")
            step = WorkflowStep(
                name=f"Step {i + 1}: {stage.value}",
                stage=stage,
                assignee=assignee,
            )
            steps.append(step)

        instance = WorkflowInstance(
            workflow_type="approval",
            deployment_id=deployment.deployment_id,
            status=WorkflowStatus.PENDING,
            steps=steps,
            created_by=created_by,
            metadata={
                "deployment_name": deployment.name,
                "risk_level": deployment.risk_level.value,
            },
        )

        self._workflows[instance.workflow_id] = instance
        self._emit_event(instance, "created")

        return instance

    def start_workflow(
        self,
        workflow_id: str,
        started_by: str = "",
    ) -> WorkflowInstance:
        """
        Start a pending workflow.

        Args:
            workflow_id: The workflow to start.
            started_by: Who is starting the workflow.

        Returns:
            The updated workflow instance.

        Raises:
            ValueError: If workflow not found or already started.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        if instance.status != WorkflowStatus.PENDING:
            raise ValueError(f"Workflow {workflow_id} is already started")

        now = utc_now()
        instance.status = WorkflowStatus.IN_PROGRESS
        instance.started_at = now
        instance.updated_at = now

        # Start the first step
        if instance.steps:
            first_step = instance.steps[0]
            first_step.status = WorkflowStatus.AWAITING_ACTION
            first_step.started_at = now

            # Calculate SLA
            risk_level = RiskLevel(
                instance.metadata.get("risk_level", RiskLevel.MEDIUM.value)
            )
            sla_hours = self._sla_hours.get(risk_level, 48)
            first_step.due_at = now + timedelta(hours=sla_hours)

        self._emit_event(instance, "started")

        return instance

    def complete_step(
        self,
        workflow_id: str,
        completed_by: str = "",
        decision: str = "approved",
        notes: str = "",
    ) -> WorkflowInstance:
        """
        Complete the current step in a workflow.

        Args:
            workflow_id: The workflow ID.
            completed_by: Who is completing the step.
            decision: The decision (approved, rejected).
            notes: Notes for the decision.

        Returns:
            The updated workflow instance.

        Raises:
            ValueError: If workflow not found or not in progress.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        if instance.status not in (
            WorkflowStatus.IN_PROGRESS,
            WorkflowStatus.AWAITING_ACTION,
        ):
            raise ValueError(f"Workflow {workflow_id} is not in progress")

        current = instance.current_step
        if not current:
            raise ValueError(f"Workflow {workflow_id} has no current step")

        now = utc_now()

        # Complete current step
        current.status = WorkflowStatus.COMPLETED
        current.completed_at = now
        current.decision = decision
        current.notes = notes
        if completed_by:
            current.assignee = completed_by

        instance.updated_at = now

        # Handle rejection
        if decision.lower() == "rejected":
            instance.status = WorkflowStatus.FAILED
            instance.completed_at = now
            self._emit_event(instance, "rejected")
            return instance

        # Move to next step or complete
        if instance.current_step_index < len(instance.steps) - 1:
            instance.current_step_index += 1
            next_step = instance.current_step
            if next_step:
                next_step.status = WorkflowStatus.AWAITING_ACTION
                next_step.started_at = now

                # Calculate SLA for next step
                risk_level = RiskLevel(
                    instance.metadata.get("risk_level", RiskLevel.MEDIUM.value)
                )
                sla_hours = self._sla_hours.get(risk_level, 48)
                next_step.due_at = now + timedelta(hours=sla_hours)

            self._emit_event(instance, "step_completed")
        else:
            # All steps complete
            instance.status = WorkflowStatus.COMPLETED
            instance.completed_at = now
            self._emit_event(instance, "completed")

        return instance

    def delegate_step(
        self,
        workflow_id: str,
        new_assignee: str,
        delegated_by: str = "",
        reason: str = "",
    ) -> WorkflowInstance:
        """
        Delegate the current step to another person.

        Args:
            workflow_id: The workflow ID.
            new_assignee: Who to delegate to.
            delegated_by: Who is delegating.
            reason: Reason for delegation.

        Returns:
            The updated workflow instance.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        current = instance.current_step
        if not current:
            raise ValueError(f"Workflow {workflow_id} has no current step")

        old_assignee = current.assignee
        current.assignee = new_assignee
        current.metadata["delegated_from"] = old_assignee
        current.metadata["delegated_by"] = delegated_by
        current.metadata["delegation_reason"] = reason
        instance.updated_at = utc_now()

        self._emit_event(instance, "delegated")

        return instance

    def escalate_workflow(
        self,
        workflow_id: str,
        escalated_by: str = "",
        reason: str = "",
    ) -> WorkflowInstance:
        """
        Escalate a workflow due to SLA breach or other reasons.

        Args:
            workflow_id: The workflow ID.
            escalated_by: Who is escalating.
            reason: Reason for escalation.

        Returns:
            The updated workflow instance.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        instance.status = WorkflowStatus.ESCALATED
        instance.updated_at = utc_now()
        instance.metadata["escalated_by"] = escalated_by
        instance.metadata["escalation_reason"] = reason

        self._emit_event(instance, "escalated")

        return instance

    def cancel_workflow(
        self,
        workflow_id: str,
        cancelled_by: str = "",
        reason: str = "",
    ) -> WorkflowInstance:
        """
        Cancel a workflow.

        Args:
            workflow_id: The workflow ID.
            cancelled_by: Who is cancelling.
            reason: Reason for cancellation.

        Returns:
            The updated workflow instance.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        if instance.is_complete():
            raise ValueError(f"Workflow {workflow_id} is already complete")

        instance.status = WorkflowStatus.CANCELLED
        instance.completed_at = utc_now()
        instance.updated_at = utc_now()
        instance.metadata["cancelled_by"] = cancelled_by
        instance.metadata["cancellation_reason"] = reason

        self._emit_event(instance, "cancelled")

        return instance

    def get_workflow(self, workflow_id: str) -> WorkflowInstance | None:
        """Get a workflow by ID."""
        return self._workflows.get(workflow_id)

    def get_workflows_for_deployment(
        self,
        deployment_id: str,
    ) -> list[WorkflowInstance]:
        """Get all workflows for a deployment."""
        return [
            w for w in self._workflows.values()
            if w.deployment_id == deployment_id
        ]

    def get_pending_workflows(self) -> list[WorkflowInstance]:
        """Get all pending workflows."""
        return [
            w for w in self._workflows.values()
            if w.status in (
                WorkflowStatus.PENDING,
                WorkflowStatus.IN_PROGRESS,
                WorkflowStatus.AWAITING_ACTION,
            )
        ]

    def get_overdue_workflows(self) -> list[WorkflowInstance]:
        """Get workflows that have exceeded their SLA."""
        now = utc_now()
        overdue = []
        for instance in self._workflows.values():
            if instance.is_complete():
                continue
            current = instance.current_step
            if current and current.due_at and now > current.due_at:
                overdue.append(instance)
        return overdue

    def check_sla_breaches(self) -> list[WorkflowInstance]:
        """
        Check for SLA breaches and escalate if needed.

        Returns:
            List of workflows that were escalated.
        """
        overdue = self.get_overdue_workflows()
        escalated = []

        for instance in overdue:
            if instance.status != WorkflowStatus.ESCALATED:
                self.escalate_workflow(
                    instance.workflow_id,
                    escalated_by="system",
                    reason="SLA breach",
                )
                escalated.append(instance)

        return escalated

    def _emit_event(self, instance: WorkflowInstance, event_type: str) -> None:
        """Emit a workflow event."""
        for callback in self._callbacks:
            try:
                callback(instance, event_type)
            except Exception:
                pass


class ReviewWorkflow:
    """
    Manages periodic review of deployed models.

    The ReviewWorkflow handles:
    - Scheduling reviews based on risk level and deployment age
    - Tracking review completion and findings
    - Triggering suspension if review is overdue
    - Generating review reminder notifications

    Example:
        Creating a review workflow::

            workflow = ReviewWorkflow()
            instance = workflow.create_review(deployment)

            # Complete the review
            workflow.complete_review(
                instance.workflow_id,
                reviewed_by="reviewer@example.com",
                findings="All systems operating normally",
            )
    """

    # Default review intervals in days for each risk level
    DEFAULT_REVIEW_INTERVALS = {
        RiskLevel.LOW: 180,  # 6 months
        RiskLevel.MEDIUM: 90,  # 3 months
        RiskLevel.HIGH: 30,  # 1 month
        RiskLevel.CRITICAL: 14,  # 2 weeks
    }

    # Grace period before suspension (days)
    DEFAULT_GRACE_PERIOD = 7

    def __init__(
        self,
        review_intervals: dict[RiskLevel, int] | None = None,
        grace_period_days: int = DEFAULT_GRACE_PERIOD,
        auto_suspend_on_overdue: bool = True,
    ) -> None:
        """
        Initialize the review workflow.

        Args:
            review_intervals: Review intervals in days for each risk level.
            grace_period_days: Days after due date before suspension.
            auto_suspend_on_overdue: Whether to auto-suspend overdue reviews.
        """
        self._review_intervals = review_intervals or self.DEFAULT_REVIEW_INTERVALS
        self._grace_period_days = grace_period_days
        self._auto_suspend_on_overdue = auto_suspend_on_overdue
        self._workflows: dict[str, WorkflowInstance] = {}
        self._callbacks: list[WorkflowCallback] = []

    def on_workflow_event(self, callback: WorkflowCallback) -> None:
        """Register a callback for workflow events."""
        self._callbacks.append(callback)

    def create_review(
        self,
        deployment: ModelDeployment,
        created_by: str = "",
        due_date: datetime | None = None,
    ) -> WorkflowInstance:
        """
        Create a review workflow for a deployment.

        Args:
            deployment: The deployment to review.
            created_by: Who is creating the review.
            due_date: When the review is due (calculated if not provided).

        Returns:
            The created workflow instance.
        """
        now = utc_now()

        if due_date is None:
            interval = self._review_intervals.get(
                deployment.risk_level, 90
            )
            due_date = now + timedelta(days=interval)

        step = WorkflowStep(
            name="Periodic Review",
            stage=ApprovalStage.INITIAL_REVIEW,
            status=WorkflowStatus.AWAITING_ACTION,
            started_at=now,
            due_at=due_date,
        )

        instance = WorkflowInstance(
            workflow_type="review",
            deployment_id=deployment.deployment_id,
            status=WorkflowStatus.IN_PROGRESS,
            steps=[step],
            started_at=now,
            created_by=created_by,
            metadata={
                "deployment_name": deployment.name,
                "risk_level": deployment.risk_level.value,
                "owner": deployment.owner,
                "owner_contact": deployment.owner_contact,
            },
        )

        self._workflows[instance.workflow_id] = instance
        self._emit_event(instance, "created")

        return instance

    def complete_review(
        self,
        workflow_id: str,
        reviewed_by: str,
        findings: str = "",
        recommend_changes: bool = False,
        next_review_days: int | None = None,
    ) -> WorkflowInstance:
        """
        Complete a review.

        Args:
            workflow_id: The workflow ID.
            reviewed_by: Who performed the review.
            findings: Review findings and notes.
            recommend_changes: Whether changes are recommended.
            next_review_days: Days until next review.

        Returns:
            The updated workflow instance.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        if instance.status not in (
            WorkflowStatus.IN_PROGRESS,
            WorkflowStatus.AWAITING_ACTION,
        ):
            raise ValueError(f"Workflow {workflow_id} is not in progress")

        now = utc_now()

        # Complete the step
        current = instance.current_step
        if current:
            current.status = WorkflowStatus.COMPLETED
            current.completed_at = now
            current.assignee = reviewed_by
            current.notes = findings
            current.decision = "changes_recommended" if recommend_changes else "approved"

        instance.status = WorkflowStatus.COMPLETED
        instance.completed_at = now
        instance.updated_at = now
        instance.metadata["reviewed_by"] = reviewed_by
        instance.metadata["recommend_changes"] = recommend_changes
        if next_review_days:
            instance.metadata["next_review_days"] = next_review_days

        self._emit_event(instance, "completed")

        return instance

    def get_reviews_due(
        self,
        within_days: int = 7,
    ) -> list[WorkflowInstance]:
        """
        Get reviews that are due within a certain number of days.

        Args:
            within_days: Number of days to look ahead.

        Returns:
            List of workflows due within the specified period.
        """
        now = utc_now()
        cutoff = now + timedelta(days=within_days)
        due = []

        for instance in self._workflows.values():
            if instance.is_complete():
                continue
            current = instance.current_step
            if current and current.due_at and current.due_at <= cutoff:
                due.append(instance)

        return due

    def get_overdue_reviews(self) -> list[WorkflowInstance]:
        """Get reviews that are past their due date."""
        now = utc_now()
        overdue = []

        for instance in self._workflows.values():
            if instance.is_complete():
                continue
            current = instance.current_step
            if current and current.due_at and now > current.due_at:
                overdue.append(instance)

        return overdue

    def get_reviews_requiring_suspension(self) -> list[WorkflowInstance]:
        """
        Get reviews that are past their grace period.

        Returns:
            List of workflows that should trigger suspension.
        """
        now = utc_now()
        grace = timedelta(days=self._grace_period_days)
        requiring_suspension = []

        for instance in self._workflows.values():
            if instance.is_complete():
                continue
            current = instance.current_step
            if current and current.due_at:
                suspension_date = current.due_at + grace
                if now > suspension_date:
                    requiring_suspension.append(instance)

        return requiring_suspension

    def get_workflow(self, workflow_id: str) -> WorkflowInstance | None:
        """Get a workflow by ID."""
        return self._workflows.get(workflow_id)

    def get_active_review_for_deployment(
        self,
        deployment_id: str,
    ) -> WorkflowInstance | None:
        """Get the active review for a deployment."""
        for instance in self._workflows.values():
            if instance.deployment_id == deployment_id and not instance.is_complete():
                return instance
        return None

    def _emit_event(self, instance: WorkflowInstance, event_type: str) -> None:
        """Emit a workflow event."""
        for callback in self._callbacks:
            try:
                callback(instance, event_type)
            except Exception:
                pass


class SuspensionWorkflow:
    """
    Handles model suspension and reinstatement.

    The SuspensionWorkflow manages:
    - Manual and automatic suspension triggers
    - Notification to affected parties
    - Blocking requests to suspended deployments
    - Reinstatement with approval

    Example:
        Suspending a deployment::

            workflow = SuspensionWorkflow()
            instance = workflow.create_suspension(
                deployment,
                reason="Policy violations exceeded threshold",
            )

            # Later, reinstate
            workflow.complete_reinstatement(
                instance.workflow_id,
                reinstated_by="admin@example.com",
            )
    """

    def __init__(
        self,
        require_approval_for_reinstatement: bool = True,
        reinstatement_approval_roles: list[str] | None = None,
    ) -> None:
        """
        Initialize the suspension workflow.

        Args:
            require_approval_for_reinstatement: Whether reinstatement needs approval.
            reinstatement_approval_roles: Roles that can approve reinstatement.
        """
        self._require_approval = require_approval_for_reinstatement
        self._approval_roles = reinstatement_approval_roles or ["admin", "security"]
        self._workflows: dict[str, WorkflowInstance] = {}
        self._callbacks: list[WorkflowCallback] = []

    def on_workflow_event(self, callback: WorkflowCallback) -> None:
        """Register a callback for workflow events."""
        self._callbacks.append(callback)

    def create_suspension(
        self,
        deployment: ModelDeployment,
        reason: str,
        suspended_by: str = "",
        suspension_type: str = "manual",
    ) -> WorkflowInstance:
        """
        Create a suspension workflow.

        Args:
            deployment: The deployment to suspend.
            reason: Reason for suspension.
            suspended_by: Who or what triggered the suspension.
            suspension_type: Type of suspension (manual, violation, review_overdue).

        Returns:
            The created workflow instance.
        """
        now = utc_now()

        steps = [
            WorkflowStep(
                name="Suspension",
                stage=ApprovalStage.INITIAL_REVIEW,
                status=WorkflowStatus.COMPLETED,
                started_at=now,
                completed_at=now,
                assignee=suspended_by,
                notes=reason,
                decision="suspended",
            ),
        ]

        if self._require_approval:
            steps.append(
                WorkflowStep(
                    name="Reinstatement Approval",
                    stage=ApprovalStage.SECURITY_REVIEW,
                    status=WorkflowStatus.PENDING,
                )
            )

        instance = WorkflowInstance(
            workflow_type="suspension",
            deployment_id=deployment.deployment_id,
            status=WorkflowStatus.IN_PROGRESS,
            steps=steps,
            started_at=now,
            current_step_index=0,
            created_by=suspended_by,
            metadata={
                "deployment_name": deployment.name,
                "owner": deployment.owner,
                "owner_contact": deployment.owner_contact,
                "reason": reason,
                "suspension_type": suspension_type,
            },
        )

        self._workflows[instance.workflow_id] = instance
        self._emit_event(instance, "suspension_created")

        return instance

    def request_reinstatement(
        self,
        workflow_id: str,
        requested_by: str,
        justification: str = "",
    ) -> WorkflowInstance:
        """
        Request reinstatement of a suspended deployment.

        Args:
            workflow_id: The suspension workflow ID.
            requested_by: Who is requesting reinstatement.
            justification: Why reinstatement should be granted.

        Returns:
            The updated workflow instance.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        if instance.workflow_type != "suspension":
            raise ValueError(f"Workflow {workflow_id} is not a suspension workflow")

        now = utc_now()

        # Move to reinstatement step
        if len(instance.steps) > 1:
            instance.current_step_index = 1
            reinstate_step = instance.steps[1]
            reinstate_step.status = WorkflowStatus.AWAITING_ACTION
            reinstate_step.started_at = now
            reinstate_step.metadata["requested_by"] = requested_by
            reinstate_step.metadata["justification"] = justification

        instance.updated_at = now
        instance.status = WorkflowStatus.AWAITING_ACTION

        self._emit_event(instance, "reinstatement_requested")

        return instance

    def complete_reinstatement(
        self,
        workflow_id: str,
        reinstated_by: str,
        approved: bool = True,
        notes: str = "",
    ) -> WorkflowInstance:
        """
        Complete the reinstatement process.

        Args:
            workflow_id: The suspension workflow ID.
            reinstated_by: Who is approving/denying reinstatement.
            approved: Whether reinstatement is approved.
            notes: Notes for the decision.

        Returns:
            The updated workflow instance.
        """
        instance = self._workflows.get(workflow_id)
        if not instance:
            raise ValueError(f"Workflow {workflow_id} not found")

        now = utc_now()

        # Complete current step
        current = instance.current_step
        if current:
            current.status = WorkflowStatus.COMPLETED
            current.completed_at = now
            current.assignee = reinstated_by
            current.notes = notes
            current.decision = "reinstated" if approved else "denied"

        instance.updated_at = now
        instance.completed_at = now

        if approved:
            instance.status = WorkflowStatus.COMPLETED
            instance.metadata["reinstated_by"] = reinstated_by
            instance.metadata["reinstated_at"] = now.isoformat()
            self._emit_event(instance, "reinstated")
        else:
            instance.status = WorkflowStatus.FAILED
            instance.metadata["reinstatement_denied_by"] = reinstated_by
            self._emit_event(instance, "reinstatement_denied")

        return instance

    def get_workflow(self, workflow_id: str) -> WorkflowInstance | None:
        """Get a workflow by ID."""
        return self._workflows.get(workflow_id)

    def get_active_suspension(
        self,
        deployment_id: str,
    ) -> WorkflowInstance | None:
        """Get the active suspension workflow for a deployment."""
        for instance in self._workflows.values():
            if (
                instance.deployment_id == deployment_id
                and instance.workflow_type == "suspension"
                and not instance.is_complete()
            ):
                return instance
        return None

    def get_pending_reinstatements(self) -> list[WorkflowInstance]:
        """Get all workflows awaiting reinstatement approval."""
        return [
            w for w in self._workflows.values()
            if w.status == WorkflowStatus.AWAITING_ACTION
            and w.workflow_type == "suspension"
        ]

    def _emit_event(self, instance: WorkflowInstance, event_type: str) -> None:
        """Emit a workflow event."""
        for callback in self._callbacks:
            try:
                callback(instance, event_type)
            except Exception:
                pass
