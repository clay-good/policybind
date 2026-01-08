"""
Incident workflow implementations for PolicyBind.

This module provides workflow classes for managing the lifecycle of
incidents, including triage, investigation, and remediation processes.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from policybind.exceptions import IncidentError
from policybind.incidents.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
)
from policybind.models.base import generate_uuid, utc_now


class TriageDecision(Enum):
    """Decisions that can be made during triage."""

    INVESTIGATE = "INVESTIGATE"
    """Incident requires investigation."""

    DISMISS = "DISMISS"
    """Incident is dismissed as false positive or duplicate."""

    ESCALATE = "ESCALATE"
    """Incident is escalated to higher severity."""

    AUTO_RESOLVE = "AUTO_RESOLVE"
    """Incident can be auto-resolved based on rules."""


class RemediationAction(Enum):
    """Types of remediation actions that can be taken."""

    REVOKE_TOKEN = "REVOKE_TOKEN"
    """Revoke an access token."""

    SUSPEND_DEPLOYMENT = "SUSPEND_DEPLOYMENT"
    """Suspend a model deployment."""

    UPDATE_POLICY = "UPDATE_POLICY"
    """Update a policy rule."""

    BLOCK_USER = "BLOCK_USER"
    """Block a user from accessing the system."""

    NOTIFY_OWNER = "NOTIFY_OWNER"
    """Notify the deployment or token owner."""

    AUDIT_ACCESS = "AUDIT_ACCESS"
    """Trigger an access audit."""

    CUSTOM = "CUSTOM"
    """Custom remediation action."""


class WorkflowStepStatus(Enum):
    """Status of a workflow step."""

    PENDING = "PENDING"
    """Step has not started."""

    IN_PROGRESS = "IN_PROGRESS"
    """Step is being worked on."""

    COMPLETED = "COMPLETED"
    """Step is complete."""

    SKIPPED = "SKIPPED"
    """Step was skipped."""

    FAILED = "FAILED"
    """Step failed."""


@dataclass
class TriageRule:
    """
    A rule for automatic triage decisions.

    Attributes:
        rule_id: Unique identifier for the rule.
        name: Name of the rule.
        description: Description of what the rule does.
        condition: Condition to match incidents.
        decision: Decision to make if condition matches.
        severity_override: Optionally override severity.
        auto_assign: Username to auto-assign to.
        tags_to_add: Tags to add to matching incidents.
        enabled: Whether the rule is active.
        priority: Priority for rule ordering (lower = higher priority).
    """

    rule_id: str = field(default_factory=generate_uuid)
    name: str = ""
    description: str = ""
    condition: dict[str, Any] = field(default_factory=dict)
    decision: TriageDecision = TriageDecision.INVESTIGATE
    severity_override: IncidentSeverity | None = None
    auto_assign: str | None = None
    tags_to_add: list[str] = field(default_factory=list)
    enabled: bool = True
    priority: int = 100


@dataclass
class WorkflowStep:
    """
    A step in an incident workflow.

    Attributes:
        step_id: Unique identifier for this step.
        name: Name of the step.
        description: Description of what needs to be done.
        status: Current status of the step.
        assignee: Who is responsible for this step.
        started_at: When the step was started.
        completed_at: When the step was completed.
        due_at: Deadline for completing this step.
        notes: Notes added during the step.
        findings: Findings from this step.
        metadata: Additional step metadata.
    """

    step_id: str = field(default_factory=generate_uuid)
    name: str = ""
    description: str = ""
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    assignee: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    due_at: datetime | None = None
    notes: str = ""
    findings: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "assignee": self.assignee,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "notes": self.notes,
            "findings": self.findings,
            "metadata": self.metadata,
        }

    def start(self, assignee: str | None = None) -> None:
        """Start the step."""
        self.status = WorkflowStepStatus.IN_PROGRESS
        self.started_at = utc_now()
        if assignee:
            self.assignee = assignee

    def complete(self, notes: str = "", findings: dict[str, Any] | None = None) -> None:
        """Complete the step."""
        self.status = WorkflowStepStatus.COMPLETED
        self.completed_at = utc_now()
        if notes:
            self.notes = notes
        if findings:
            self.findings = findings

    def skip(self, reason: str = "") -> None:
        """Skip the step."""
        self.status = WorkflowStepStatus.SKIPPED
        self.completed_at = utc_now()
        self.notes = reason

    def fail(self, reason: str = "") -> None:
        """Mark the step as failed."""
        self.status = WorkflowStepStatus.FAILED
        self.completed_at = utc_now()
        self.notes = reason

    def is_overdue(self) -> bool:
        """Check if the step is overdue."""
        if self.due_at is None:
            return False
        if self.status in (WorkflowStepStatus.COMPLETED, WorkflowStepStatus.SKIPPED):
            return False
        return utc_now() > self.due_at


@dataclass
class RemediationStep:
    """
    A remediation action to be taken.

    Attributes:
        step_id: Unique identifier for this step.
        action: Type of remediation action.
        target_id: ID of the target (token, deployment, user, etc.).
        target_type: Type of target.
        description: Description of the action.
        status: Current status.
        executed_at: When the action was executed.
        executed_by: Who executed the action.
        verified: Whether the action was verified effective.
        verified_at: When verification occurred.
        verified_by: Who verified.
        notes: Notes about the action.
        metadata: Additional metadata.
    """

    step_id: str = field(default_factory=generate_uuid)
    action: RemediationAction = RemediationAction.CUSTOM
    target_id: str = ""
    target_type: str = ""
    description: str = ""
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    executed_at: datetime | None = None
    executed_by: str | None = None
    verified: bool = False
    verified_at: datetime | None = None
    verified_by: str | None = None
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step_id": self.step_id,
            "action": self.action.value,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "description": self.description,
            "status": self.status.value,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "executed_by": self.executed_by,
            "verified": self.verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "verified_by": self.verified_by,
            "notes": self.notes,
            "metadata": self.metadata,
        }

    def execute(self, executed_by: str) -> None:
        """Mark the action as executed."""
        self.status = WorkflowStepStatus.COMPLETED
        self.executed_at = utc_now()
        self.executed_by = executed_by

    def verify(self, verified_by: str, effective: bool = True, notes: str = "") -> None:
        """Verify the action was effective."""
        self.verified = effective
        self.verified_at = utc_now()
        self.verified_by = verified_by
        if notes:
            self.notes = notes


# Type aliases for callbacks
TriageCallback = Callable[[Incident, TriageDecision], None]
InvestigationCallback = Callable[[Incident, WorkflowStep], None]
RemediationCallback = Callable[[Incident, RemediationStep], None]


class IncidentTriageWorkflow:
    """
    Workflow for initial incident triage.

    Handles initial assessment and routing of incidents, including
    auto-assignment, severity adjustment, and escalation.

    Example:
        Using the triage workflow::

            triage = IncidentTriageWorkflow()

            # Add triage rules
            triage.add_rule(TriageRule(
                name="auto-dismiss-low-budget",
                condition={"incident_type": "BUDGET_EXCEEDED", "severity": "LOW"},
                decision=TriageDecision.AUTO_RESOLVE,
            ))

            # Register callback
            triage.on_decision(lambda inc, dec: print(f"Triaged: {dec}"))

            # Triage an incident
            result = triage.triage(incident)
    """

    # Default SLA times by severity (in hours)
    DEFAULT_SLA_HOURS = {
        IncidentSeverity.LOW: 24,
        IncidentSeverity.MEDIUM: 8,
        IncidentSeverity.HIGH: 2,
        IncidentSeverity.CRITICAL: 0.5,
    }

    # Default assignees by incident type
    DEFAULT_ASSIGNEES: dict[IncidentType, str] = {}

    def __init__(
        self,
        sla_hours: dict[IncidentSeverity, float] | None = None,
        default_assignees: dict[IncidentType, str] | None = None,
    ) -> None:
        """
        Initialize the triage workflow.

        Args:
            sla_hours: SLA hours by severity (overrides defaults).
            default_assignees: Default assignees by incident type.
        """
        self._rules: list[TriageRule] = []
        self._callbacks: list[TriageCallback] = []
        self._sla_hours = sla_hours or dict(self.DEFAULT_SLA_HOURS)
        self._default_assignees = default_assignees or dict(self.DEFAULT_ASSIGNEES)

    def add_rule(self, rule: TriageRule) -> None:
        """Add a triage rule."""
        self._rules.append(rule)
        # Keep rules sorted by priority
        self._rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a triage rule by ID."""
        for i, rule in enumerate(self._rules):
            if rule.rule_id == rule_id:
                self._rules.pop(i)
                return True
        return False

    def list_rules(self, enabled_only: bool = False) -> list[TriageRule]:
        """List all triage rules."""
        if enabled_only:
            return [r for r in self._rules if r.enabled]
        return list(self._rules)

    def on_decision(self, callback: TriageCallback) -> None:
        """Register a callback for triage decisions."""
        self._callbacks.append(callback)

    def triage(self, incident: Incident) -> dict[str, Any]:
        """
        Perform triage on an incident.

        Args:
            incident: The incident to triage.

        Returns:
            Dictionary with triage results including decision, assignee,
            severity, and SLA deadline.
        """
        result: dict[str, Any] = {
            "incident_id": incident.incident_id,
            "decision": TriageDecision.INVESTIGATE,
            "assignee": None,
            "severity": incident.severity,
            "sla_deadline": None,
            "tags_added": [],
            "matched_rule": None,
        }

        # Check rules in priority order
        for rule in self._rules:
            if not rule.enabled:
                continue

            if self._matches_condition(incident, rule.condition):
                result["decision"] = rule.decision
                result["matched_rule"] = rule.name

                if rule.severity_override:
                    result["severity"] = rule.severity_override

                if rule.auto_assign:
                    result["assignee"] = rule.auto_assign

                if rule.tags_to_add:
                    result["tags_added"] = list(rule.tags_to_add)

                break

        # Apply default assignee if not set
        if result["assignee"] is None:
            result["assignee"] = self._default_assignees.get(incident.incident_type)

        # Calculate SLA deadline
        severity = result["severity"]
        sla_hours = self._sla_hours.get(severity, 24)
        result["sla_deadline"] = utc_now() + timedelta(hours=sla_hours)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(incident, result["decision"])
            except Exception:
                pass

        return result

    def check_sla_breach(
        self,
        incident: Incident,
        acknowledged_at: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Check if an incident has breached its SLA.

        Args:
            incident: The incident to check.
            acknowledged_at: When the incident was acknowledged.

        Returns:
            Dictionary with SLA status and breach information.
        """
        sla_hours = self._sla_hours.get(incident.severity, 24)
        deadline = incident.created_at + timedelta(hours=sla_hours)
        now = utc_now()

        result = {
            "incident_id": incident.incident_id,
            "sla_hours": sla_hours,
            "deadline": deadline,
            "is_breached": False,
            "time_remaining": None,
            "time_overdue": None,
            "acknowledged": acknowledged_at is not None,
            "acknowledged_in_time": False,
        }

        if acknowledged_at:
            result["acknowledged_in_time"] = acknowledged_at <= deadline

        if now > deadline:
            result["is_breached"] = True
            result["time_overdue"] = (now - deadline).total_seconds() / 3600
        else:
            result["time_remaining"] = (deadline - now).total_seconds() / 3600

        return result

    def get_escalation_target(self, incident: Incident) -> str | None:
        """
        Get the escalation target for an incident.

        Args:
            incident: The incident to escalate.

        Returns:
            Username or team to escalate to, or None.
        """
        # Default escalation path based on severity
        escalation_map = {
            IncidentSeverity.LOW: "incident-team",
            IncidentSeverity.MEDIUM: "incident-lead",
            IncidentSeverity.HIGH: "security-team",
            IncidentSeverity.CRITICAL: "security-director",
        }
        return escalation_map.get(incident.severity)

    def _matches_condition(
        self,
        incident: Incident,
        condition: dict[str, Any],
    ) -> bool:
        """Check if an incident matches a triage condition."""
        for key, expected in condition.items():
            # Get value from incident
            if key == "incident_type":
                actual = incident.incident_type.value
            elif key == "severity":
                actual = incident.severity.value
            elif key == "status":
                actual = incident.status.value
            elif key == "deployment_id":
                actual = incident.deployment_id
            elif key == "has_deployment":
                actual = incident.deployment_id is not None
                expected = bool(expected)
            elif key == "has_evidence":
                actual = bool(incident.evidence)
                expected = bool(expected)
            elif key == "tags":
                # Check if any tag matches
                if isinstance(expected, list):
                    if not any(t in incident.tags for t in expected):
                        return False
                    continue
                actual = expected in incident.tags
                expected = True
            else:
                # Check in evidence or metadata
                actual = incident.evidence.get(key) or incident.metadata.get(key)

            # Handle list expected values
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        return True


class IncidentInvestigationWorkflow:
    """
    Workflow for managing incident investigation.

    Tracks investigation steps, findings, and collaboration
    between investigators.

    Example:
        Using the investigation workflow::

            investigation = IncidentInvestigationWorkflow()

            # Start investigation
            investigation.start(incident, investigator="analyst")

            # Add investigation steps
            investigation.add_step(incident.incident_id, WorkflowStep(
                name="Review logs",
                description="Review enforcement logs for the time period",
            ))

            # Complete a step with findings
            investigation.complete_step(
                incident.incident_id,
                step_id,
                findings={"log_entries": 150, "anomalies": 3},
            )
    """

    # Default investigation steps by incident type
    DEFAULT_STEPS: dict[IncidentType, list[dict[str, str]]] = {
        IncidentType.POLICY_VIOLATION: [
            {"name": "Review Request", "description": "Review the violating request details"},
            {"name": "Analyze Policy Match", "description": "Understand why the policy triggered"},
            {"name": "Assess Impact", "description": "Determine the impact of the violation"},
            {"name": "Identify Root Cause", "description": "Identify why the violation occurred"},
        ],
        IncidentType.DATA_LEAK: [
            {"name": "Contain Exposure", "description": "Immediately contain any ongoing exposure"},
            {"name": "Identify Data Scope", "description": "Determine what data was exposed"},
            {"name": "Trace Access Path", "description": "Trace how the data was accessed"},
            {"name": "Assess Regulatory Impact", "description": "Determine regulatory notification requirements"},
            {"name": "Document Evidence", "description": "Preserve all relevant evidence"},
        ],
        IncidentType.JAILBREAK: [
            {"name": "Analyze Attempt", "description": "Analyze the jailbreak attempt technique"},
            {"name": "Check Success", "description": "Determine if the attempt was successful"},
            {"name": "Review Related Requests", "description": "Look for related attempts"},
            {"name": "Assess Model Vulnerability", "description": "Evaluate if model needs hardening"},
        ],
    }

    def __init__(self) -> None:
        """Initialize the investigation workflow."""
        self._investigations: dict[str, list[WorkflowStep]] = {}
        self._investigators: dict[str, list[str]] = {}
        self._callbacks: list[InvestigationCallback] = []

    def start(
        self,
        incident: Incident,
        investigator: str,
        custom_steps: list[WorkflowStep] | None = None,
    ) -> list[WorkflowStep]:
        """
        Start an investigation for an incident.

        Args:
            incident: The incident to investigate.
            investigator: Primary investigator username.
            custom_steps: Custom investigation steps (overrides defaults).

        Returns:
            List of investigation steps.
        """
        incident_id = incident.incident_id

        # Create steps
        if custom_steps:
            steps = custom_steps
        else:
            # Use default steps for this incident type
            default_step_defs = self.DEFAULT_STEPS.get(
                incident.incident_type,
                [{"name": "Initial Assessment", "description": "Perform initial assessment"}]
            )
            steps = [
                WorkflowStep(
                    name=step_def["name"],
                    description=step_def["description"],
                    assignee=investigator,
                )
                for step_def in default_step_defs
            ]

        self._investigations[incident_id] = steps
        self._investigators[incident_id] = [investigator]

        # Start first step
        if steps:
            steps[0].start(investigator)

        return steps

    def add_investigator(self, incident_id: str, investigator: str) -> None:
        """Add an investigator to the incident."""
        if incident_id not in self._investigators:
            self._investigators[incident_id] = []
        if investigator not in self._investigators[incident_id]:
            self._investigators[incident_id].append(investigator)

    def remove_investigator(self, incident_id: str, investigator: str) -> bool:
        """Remove an investigator from the incident."""
        if incident_id in self._investigators:
            try:
                self._investigators[incident_id].remove(investigator)
                return True
            except ValueError:
                pass
        return False

    def get_investigators(self, incident_id: str) -> list[str]:
        """Get all investigators for an incident."""
        return list(self._investigators.get(incident_id, []))

    def add_step(
        self,
        incident_id: str,
        step: WorkflowStep,
        after_step_id: str | None = None,
    ) -> None:
        """
        Add a step to the investigation.

        Args:
            incident_id: The incident ID.
            step: The step to add.
            after_step_id: Insert after this step (appends if None).
        """
        if incident_id not in self._investigations:
            self._investigations[incident_id] = []

        steps = self._investigations[incident_id]

        if after_step_id:
            for i, s in enumerate(steps):
                if s.step_id == after_step_id:
                    steps.insert(i + 1, step)
                    return

        steps.append(step)

    def get_steps(self, incident_id: str) -> list[WorkflowStep]:
        """Get all steps for an investigation."""
        return list(self._investigations.get(incident_id, []))

    def get_step(self, incident_id: str, step_id: str) -> WorkflowStep | None:
        """Get a specific step."""
        for step in self._investigations.get(incident_id, []):
            if step.step_id == step_id:
                return step
        return None

    def get_current_step(self, incident_id: str) -> WorkflowStep | None:
        """Get the current active step."""
        for step in self._investigations.get(incident_id, []):
            if step.status == WorkflowStepStatus.IN_PROGRESS:
                return step
        return None

    def start_step(
        self,
        incident_id: str,
        step_id: str,
        assignee: str | None = None,
    ) -> WorkflowStep | None:
        """Start a specific step."""
        step = self.get_step(incident_id, step_id)
        if step:
            step.start(assignee)
        return step

    def complete_step(
        self,
        incident_id: str,
        step_id: str,
        notes: str = "",
        findings: dict[str, Any] | None = None,
        auto_start_next: bool = True,
    ) -> WorkflowStep | None:
        """
        Complete a step and optionally start the next one.

        Args:
            incident_id: The incident ID.
            step_id: The step to complete.
            notes: Notes about the completion.
            findings: Findings from this step.
            auto_start_next: Whether to auto-start the next step.

        Returns:
            The next step if started, or None.
        """
        step = self.get_step(incident_id, step_id)
        if step:
            step.complete(notes, findings)

            # Notify callbacks
            # Note: We'd need the incident here, but we just have the ID
            # Callbacks would need to look up the incident

        if auto_start_next:
            return self._start_next_step(incident_id)

        return None

    def skip_step(
        self,
        incident_id: str,
        step_id: str,
        reason: str = "",
        auto_start_next: bool = True,
    ) -> WorkflowStep | None:
        """Skip a step."""
        step = self.get_step(incident_id, step_id)
        if step:
            step.skip(reason)

        if auto_start_next:
            return self._start_next_step(incident_id)

        return None

    def fail_step(self, incident_id: str, step_id: str, reason: str = "") -> None:
        """Mark a step as failed."""
        step = self.get_step(incident_id, step_id)
        if step:
            step.fail(reason)

    def get_progress(self, incident_id: str) -> dict[str, Any]:
        """
        Get investigation progress.

        Returns:
            Dictionary with progress information.
        """
        steps = self._investigations.get(incident_id, [])

        completed = sum(1 for s in steps if s.status == WorkflowStepStatus.COMPLETED)
        skipped = sum(1 for s in steps if s.status == WorkflowStepStatus.SKIPPED)
        in_progress = sum(1 for s in steps if s.status == WorkflowStepStatus.IN_PROGRESS)
        pending = sum(1 for s in steps if s.status == WorkflowStepStatus.PENDING)
        failed = sum(1 for s in steps if s.status == WorkflowStepStatus.FAILED)

        total = len(steps)
        done = completed + skipped

        return {
            "incident_id": incident_id,
            "total_steps": total,
            "completed": completed,
            "skipped": skipped,
            "in_progress": in_progress,
            "pending": pending,
            "failed": failed,
            "progress_percent": (done / total * 100) if total > 0 else 0,
            "is_complete": pending == 0 and in_progress == 0 and failed == 0,
            "investigators": self.get_investigators(incident_id),
        }

    def get_findings(self, incident_id: str) -> dict[str, Any]:
        """
        Aggregate all findings from completed steps.

        Returns:
            Dictionary with all findings.
        """
        findings: dict[str, Any] = {}

        for step in self._investigations.get(incident_id, []):
            if step.status == WorkflowStepStatus.COMPLETED and step.findings:
                findings[step.name] = step.findings

        return findings

    def get_overdue_steps(self, incident_id: str) -> list[WorkflowStep]:
        """Get all overdue steps for an incident."""
        return [
            step for step in self._investigations.get(incident_id, [])
            if step.is_overdue()
        ]

    def on_step_complete(self, callback: InvestigationCallback) -> None:
        """Register a callback for step completion."""
        self._callbacks.append(callback)

    def _start_next_step(self, incident_id: str) -> WorkflowStep | None:
        """Start the next pending step."""
        for step in self._investigations.get(incident_id, []):
            if step.status == WorkflowStepStatus.PENDING:
                step.start()
                return step
        return None


class IncidentRemediationWorkflow:
    """
    Workflow for tracking remediation actions.

    Manages the remediation steps taken in response to an incident,
    including tracking execution and verification.

    Example:
        Using the remediation workflow::

            remediation = IncidentRemediationWorkflow()

            # Add remediation actions
            remediation.add_action(incident_id, RemediationStep(
                action=RemediationAction.REVOKE_TOKEN,
                target_id="token-123",
                target_type="token",
                description="Revoke compromised token",
            ))

            # Execute action
            remediation.execute_action(incident_id, step_id, executed_by="admin")

            # Verify effectiveness
            remediation.verify_action(incident_id, step_id, verified_by="analyst")
    """

    def __init__(self) -> None:
        """Initialize the remediation workflow."""
        self._remediations: dict[str, list[RemediationStep]] = {}
        self._callbacks: list[RemediationCallback] = []
        self._linked_policies: dict[str, list[str]] = {}  # incident_id -> policy_ids
        self._linked_suspensions: dict[str, list[str]] = {}  # incident_id -> deployment_ids

    def add_action(self, incident_id: str, action: RemediationStep) -> None:
        """Add a remediation action."""
        if incident_id not in self._remediations:
            self._remediations[incident_id] = []
        self._remediations[incident_id].append(action)

    def get_actions(self, incident_id: str) -> list[RemediationStep]:
        """Get all remediation actions for an incident."""
        return list(self._remediations.get(incident_id, []))

    def get_action(self, incident_id: str, step_id: str) -> RemediationStep | None:
        """Get a specific remediation action."""
        for action in self._remediations.get(incident_id, []):
            if action.step_id == step_id:
                return action
        return None

    def execute_action(
        self,
        incident_id: str,
        step_id: str,
        executed_by: str,
        notes: str = "",
    ) -> RemediationStep | None:
        """
        Mark a remediation action as executed.

        Args:
            incident_id: The incident ID.
            step_id: The action to execute.
            executed_by: Who executed the action.
            notes: Notes about the execution.

        Returns:
            The updated action, or None if not found.
        """
        action = self.get_action(incident_id, step_id)
        if action:
            action.execute(executed_by)
            if notes:
                action.notes = notes

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    # Would need incident, but just have ID
                    pass
                except Exception:
                    pass

        return action

    def verify_action(
        self,
        incident_id: str,
        step_id: str,
        verified_by: str,
        effective: bool = True,
        notes: str = "",
    ) -> RemediationStep | None:
        """
        Verify a remediation action was effective.

        Args:
            incident_id: The incident ID.
            step_id: The action to verify.
            verified_by: Who verified the action.
            effective: Whether the action was effective.
            notes: Notes about the verification.

        Returns:
            The updated action, or None if not found.
        """
        action = self.get_action(incident_id, step_id)
        if action:
            action.verify(verified_by, effective, notes)
        return action

    def link_policy_change(self, incident_id: str, policy_id: str) -> None:
        """Link a policy change to the incident remediation."""
        if incident_id not in self._linked_policies:
            self._linked_policies[incident_id] = []
        if policy_id not in self._linked_policies[incident_id]:
            self._linked_policies[incident_id].append(policy_id)

    def link_suspension(self, incident_id: str, deployment_id: str) -> None:
        """Link a deployment suspension to the incident remediation."""
        if incident_id not in self._linked_suspensions:
            self._linked_suspensions[incident_id] = []
        if deployment_id not in self._linked_suspensions[incident_id]:
            self._linked_suspensions[incident_id].append(deployment_id)

    def get_linked_policies(self, incident_id: str) -> list[str]:
        """Get policy changes linked to the incident."""
        return list(self._linked_policies.get(incident_id, []))

    def get_linked_suspensions(self, incident_id: str) -> list[str]:
        """Get deployment suspensions linked to the incident."""
        return list(self._linked_suspensions.get(incident_id, []))

    def get_status(self, incident_id: str) -> dict[str, Any]:
        """
        Get remediation status for an incident.

        Returns:
            Dictionary with remediation status.
        """
        actions = self._remediations.get(incident_id, [])

        total = len(actions)
        executed = sum(1 for a in actions if a.executed_at is not None)
        verified = sum(1 for a in actions if a.verified)
        pending = sum(1 for a in actions if a.status == WorkflowStepStatus.PENDING)

        return {
            "incident_id": incident_id,
            "total_actions": total,
            "executed": executed,
            "verified": verified,
            "pending": pending,
            "all_executed": total > 0 and pending == 0,
            "all_verified": total > 0 and verified == total,
            "linked_policies": len(self._linked_policies.get(incident_id, [])),
            "linked_suspensions": len(self._linked_suspensions.get(incident_id, [])),
        }

    def get_pending_actions(self, incident_id: str) -> list[RemediationStep]:
        """Get pending remediation actions."""
        return [
            a for a in self._remediations.get(incident_id, [])
            if a.status == WorkflowStepStatus.PENDING
        ]

    def get_unverified_actions(self, incident_id: str) -> list[RemediationStep]:
        """Get executed but unverified actions."""
        return [
            a for a in self._remediations.get(incident_id, [])
            if a.executed_at is not None and not a.verified
        ]

    def suggest_remediations(self, incident: Incident) -> list[RemediationStep]:
        """
        Suggest remediation actions based on incident type.

        Args:
            incident: The incident to suggest remediations for.

        Returns:
            List of suggested remediation actions.
        """
        suggestions = []

        # Common suggestions by incident type
        if incident.incident_type == IncidentType.DATA_LEAK:
            if incident.evidence.get("token_id"):
                suggestions.append(RemediationStep(
                    action=RemediationAction.REVOKE_TOKEN,
                    target_id=incident.evidence["token_id"],
                    target_type="token",
                    description="Revoke the token involved in the data leak",
                ))

            suggestions.append(RemediationStep(
                action=RemediationAction.AUDIT_ACCESS,
                target_id=incident.deployment_id or "",
                target_type="deployment",
                description="Audit all access to affected resources",
            ))

        elif incident.incident_type == IncidentType.JAILBREAK:
            if incident.evidence.get("user_id"):
                suggestions.append(RemediationStep(
                    action=RemediationAction.BLOCK_USER,
                    target_id=incident.evidence["user_id"],
                    target_type="user",
                    description="Block user who attempted jailbreak",
                ))

            suggestions.append(RemediationStep(
                action=RemediationAction.UPDATE_POLICY,
                target_id="",
                target_type="policy",
                description="Update policy to prevent similar attempts",
            ))

        elif incident.incident_type == IncidentType.ABUSE:
            if incident.evidence.get("token_id"):
                suggestions.append(RemediationStep(
                    action=RemediationAction.REVOKE_TOKEN,
                    target_id=incident.evidence["token_id"],
                    target_type="token",
                    description="Revoke the abused token",
                ))

            if incident.deployment_id:
                suggestions.append(RemediationStep(
                    action=RemediationAction.SUSPEND_DEPLOYMENT,
                    target_id=incident.deployment_id,
                    target_type="deployment",
                    description="Suspend the affected deployment",
                ))

        elif incident.incident_type == IncidentType.POLICY_VIOLATION:
            suggestions.append(RemediationStep(
                action=RemediationAction.NOTIFY_OWNER,
                target_id=incident.deployment_id or "",
                target_type="deployment",
                description="Notify deployment owner of violation",
            ))

        # Always suggest owner notification for high/critical
        if incident.severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL):
            if incident.deployment_id and not any(
                s.action == RemediationAction.NOTIFY_OWNER for s in suggestions
            ):
                suggestions.append(RemediationStep(
                    action=RemediationAction.NOTIFY_OWNER,
                    target_id=incident.deployment_id,
                    target_type="deployment",
                    description="Notify deployment owner of critical incident",
                ))

        return suggestions

    def on_action_complete(self, callback: RemediationCallback) -> None:
        """Register a callback for action completion."""
        self._callbacks.append(callback)
