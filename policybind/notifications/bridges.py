"""
Notification bridges for PolicyBind.

This module provides bridge classes that connect system events
(incidents, workflows) to the webhook notification system.
"""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from policybind.notifications.webhooks import (
    WebhookEvent,
    WebhookEventType,
    WebhookManager,
)

if TYPE_CHECKING:
    from policybind.incidents.manager import IncidentEvent
    from policybind.incidents.models import Incident
    from policybind.registry.workflows import WorkflowInstance

logger = logging.getLogger("policybind.notifications.bridges")


@dataclass
class NotificationBridgeStats:
    """Statistics for a notification bridge."""

    events_received: int = 0
    events_dispatched: int = 0
    events_filtered: int = 0
    last_event_at: str | None = None


class IncidentNotificationBridge:
    """
    Bridge between incident events and webhook notifications.

    This class listens for incident events from the IncidentManager
    and dispatches them as webhook events.

    Example:
        Setting up the bridge::

            from policybind.incidents import IncidentManager
            from policybind.notifications import WebhookManager, IncidentNotificationBridge

            incident_manager = IncidentManager(repository)
            webhook_manager = WebhookManager()

            bridge = IncidentNotificationBridge(webhook_manager)
            bridge.connect(incident_manager)

            # Now incident events will trigger webhooks
    """

    # Mapping from incident timeline event types to webhook event types
    EVENT_TYPE_MAPPING = {
        "created": WebhookEventType.INCIDENT_CREATED,
        "status_change": WebhookEventType.INCIDENT_UPDATED,
        "assignment": WebhookEventType.INCIDENT_ASSIGNED,
        "escalation": WebhookEventType.INCIDENT_ESCALATED,
        "severity_change": WebhookEventType.INCIDENT_UPDATED,
        "evidence_added": WebhookEventType.INCIDENT_UPDATED,
        "comment": WebhookEventType.INCIDENT_UPDATED,
        "related_incident": WebhookEventType.INCIDENT_UPDATED,
        "remediation": WebhookEventType.INCIDENT_UPDATED,
        "notification": None,  # Don't create webhook for notification events
    }

    def __init__(
        self,
        webhook_manager: WebhookManager,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the incident notification bridge.

        Args:
            webhook_manager: The webhook manager to dispatch events to.
            enabled: Whether the bridge is enabled.
        """
        self._webhook_manager = webhook_manager
        self._enabled = enabled
        self._stats = NotificationBridgeStats()

    @property
    def enabled(self) -> bool:
        """Check if the bridge is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable the bridge."""
        self._enabled = value

    def get_stats(self) -> NotificationBridgeStats:
        """Get bridge statistics."""
        return self._stats

    def connect(self, incident_manager: Any) -> None:
        """
        Connect to an incident manager.

        Args:
            incident_manager: The IncidentManager to listen to.
        """
        incident_manager.on_event(self._handle_incident_event)
        logger.info("IncidentNotificationBridge connected to IncidentManager")

    def _handle_incident_event(self, event: "IncidentEvent") -> None:
        """Handle an incident event."""
        self._stats.events_received += 1

        if not self._enabled:
            self._stats.events_filtered += 1
            return

        # Map event type
        event_type_name = event.event_type.value.lower()
        webhook_event_type = self.EVENT_TYPE_MAPPING.get(event_type_name)

        if webhook_event_type is None:
            self._stats.events_filtered += 1
            return

        # Check for resolved/closed status
        if event_type_name == "status_change":
            if event.new_value == "resolved":
                webhook_event_type = WebhookEventType.INCIDENT_RESOLVED
            elif event.new_value == "closed":
                webhook_event_type = WebhookEventType.INCIDENT_CLOSED

        # Build webhook event
        webhook_event = WebhookEvent(
            event_type=webhook_event_type,
            payload=self._build_incident_payload(event),
            source="incident_manager",
        )

        # Dispatch
        self._webhook_manager.dispatch(webhook_event)
        self._stats.events_dispatched += 1
        self._stats.last_event_at = (
            event.timestamp.isoformat() if event.timestamp else None
        )

        logger.debug(
            f"Dispatched incident webhook: {webhook_event_type.value} "
            f"incident={event.incident_id}"
        )

    def _build_incident_payload(self, event: "IncidentEvent") -> dict[str, Any]:
        """Build the webhook payload for an incident event."""
        incident = event.incident
        return {
            "incident_id": incident.incident_id,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "incident_type": incident.incident_type.value,
            "description": incident.description,
            "source_request_id": incident.source_request_id,
            "deployment_id": incident.deployment_id,
            "assignee": incident.assignee,
            "tags": list(incident.tags) if incident.tags else [],
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
            "event": {
                "type": event.event_type.value,
                "actor": event.actor,
                "old_value": event.old_value,
                "new_value": event.new_value,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            },
        }


class WorkflowNotificationBridge:
    """
    Bridge between workflow events and webhook notifications.

    This class listens for workflow events from ApprovalWorkflow,
    ReviewWorkflow, and SuspensionWorkflow and dispatches them
    as webhook events.

    Example:
        Setting up the bridge::

            from policybind.registry.workflows import ApprovalWorkflow
            from policybind.notifications import WebhookManager, WorkflowNotificationBridge

            approval_workflow = ApprovalWorkflow()
            webhook_manager = WebhookManager()

            bridge = WorkflowNotificationBridge(webhook_manager)
            bridge.connect_approval_workflow(approval_workflow)

            # Now approval events will trigger webhooks
    """

    # Mapping from approval workflow event types to webhook event types
    APPROVAL_EVENT_MAPPING = {
        "created": WebhookEventType.APPROVAL_REQUESTED,
        "started": WebhookEventType.APPROVAL_REQUESTED,
        "step_completed": WebhookEventType.APPROVAL_STEP_COMPLETED,
        "rejected": WebhookEventType.APPROVAL_REJECTED,
        "completed": WebhookEventType.APPROVAL_GRANTED,
        "delegated": WebhookEventType.APPROVAL_DELEGATED,
        "escalated": WebhookEventType.APPROVAL_ESCALATED,
        "cancelled": None,  # Don't notify on cancel
    }

    # Mapping from review workflow event types to webhook event types
    REVIEW_EVENT_MAPPING = {
        "created": WebhookEventType.REVIEW_DUE,
        "completed": WebhookEventType.REVIEW_COMPLETED,
        "overdue": WebhookEventType.REVIEW_OVERDUE,
    }

    # Mapping from suspension workflow event types to webhook event types
    SUSPENSION_EVENT_MAPPING = {
        "suspension_created": WebhookEventType.DEPLOYMENT_SUSPENDED,
        "reinstatement_requested": WebhookEventType.REINSTATEMENT_REQUESTED,
        "reinstated": WebhookEventType.DEPLOYMENT_REINSTATED,
        "reinstatement_denied": WebhookEventType.REINSTATEMENT_DENIED,
    }

    def __init__(
        self,
        webhook_manager: WebhookManager,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the workflow notification bridge.

        Args:
            webhook_manager: The webhook manager to dispatch events to.
            enabled: Whether the bridge is enabled.
        """
        self._webhook_manager = webhook_manager
        self._enabled = enabled
        self._stats = NotificationBridgeStats()

    @property
    def enabled(self) -> bool:
        """Check if the bridge is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable the bridge."""
        self._enabled = value

    def get_stats(self) -> NotificationBridgeStats:
        """Get bridge statistics."""
        return self._stats

    def connect_approval_workflow(self, workflow: Any) -> None:
        """
        Connect to an approval workflow.

        Args:
            workflow: The ApprovalWorkflow to listen to.
        """
        workflow.on_workflow_event(self._handle_approval_event)
        logger.info("WorkflowNotificationBridge connected to ApprovalWorkflow")

    def connect_review_workflow(self, workflow: Any) -> None:
        """
        Connect to a review workflow.

        Args:
            workflow: The ReviewWorkflow to listen to.
        """
        workflow.on_workflow_event(self._handle_review_event)
        logger.info("WorkflowNotificationBridge connected to ReviewWorkflow")

    def connect_suspension_workflow(self, workflow: Any) -> None:
        """
        Connect to a suspension workflow.

        Args:
            workflow: The SuspensionWorkflow to listen to.
        """
        workflow.on_workflow_event(self._handle_suspension_event)
        logger.info("WorkflowNotificationBridge connected to SuspensionWorkflow")

    def connect_all(
        self,
        approval_workflow: Any | None = None,
        review_workflow: Any | None = None,
        suspension_workflow: Any | None = None,
    ) -> None:
        """
        Connect to multiple workflows at once.

        Args:
            approval_workflow: Optional ApprovalWorkflow.
            review_workflow: Optional ReviewWorkflow.
            suspension_workflow: Optional SuspensionWorkflow.
        """
        if approval_workflow:
            self.connect_approval_workflow(approval_workflow)
        if review_workflow:
            self.connect_review_workflow(review_workflow)
        if suspension_workflow:
            self.connect_suspension_workflow(suspension_workflow)

    def _handle_approval_event(
        self,
        instance: "WorkflowInstance",
        event_type: str,
    ) -> None:
        """Handle an approval workflow event."""
        self._stats.events_received += 1

        if not self._enabled:
            self._stats.events_filtered += 1
            return

        webhook_event_type = self.APPROVAL_EVENT_MAPPING.get(event_type)
        if webhook_event_type is None:
            self._stats.events_filtered += 1
            return

        webhook_event = WebhookEvent(
            event_type=webhook_event_type,
            payload=self._build_workflow_payload(instance, event_type, "approval"),
            source="approval_workflow",
        )

        self._webhook_manager.dispatch(webhook_event)
        self._stats.events_dispatched += 1
        self._stats.last_event_at = instance.updated_at.isoformat() if instance.updated_at else None

        logger.debug(
            f"Dispatched approval webhook: {webhook_event_type.value} "
            f"workflow={instance.workflow_id}"
        )

    def _handle_review_event(
        self,
        instance: "WorkflowInstance",
        event_type: str,
    ) -> None:
        """Handle a review workflow event."""
        self._stats.events_received += 1

        if not self._enabled:
            self._stats.events_filtered += 1
            return

        webhook_event_type = self.REVIEW_EVENT_MAPPING.get(event_type)
        if webhook_event_type is None:
            self._stats.events_filtered += 1
            return

        webhook_event = WebhookEvent(
            event_type=webhook_event_type,
            payload=self._build_workflow_payload(instance, event_type, "review"),
            source="review_workflow",
        )

        self._webhook_manager.dispatch(webhook_event)
        self._stats.events_dispatched += 1
        self._stats.last_event_at = instance.updated_at.isoformat() if instance.updated_at else None

        logger.debug(
            f"Dispatched review webhook: {webhook_event_type.value} "
            f"workflow={instance.workflow_id}"
        )

    def _handle_suspension_event(
        self,
        instance: "WorkflowInstance",
        event_type: str,
    ) -> None:
        """Handle a suspension workflow event."""
        self._stats.events_received += 1

        if not self._enabled:
            self._stats.events_filtered += 1
            return

        webhook_event_type = self.SUSPENSION_EVENT_MAPPING.get(event_type)
        if webhook_event_type is None:
            self._stats.events_filtered += 1
            return

        webhook_event = WebhookEvent(
            event_type=webhook_event_type,
            payload=self._build_workflow_payload(instance, event_type, "suspension"),
            source="suspension_workflow",
        )

        self._webhook_manager.dispatch(webhook_event)
        self._stats.events_dispatched += 1
        self._stats.last_event_at = instance.updated_at.isoformat() if instance.updated_at else None

        logger.debug(
            f"Dispatched suspension webhook: {webhook_event_type.value} "
            f"workflow={instance.workflow_id}"
        )

    def _build_workflow_payload(
        self,
        instance: "WorkflowInstance",
        event_type: str,
        workflow_type: str,
    ) -> dict[str, Any]:
        """Build the webhook payload for a workflow event."""
        payload: dict[str, Any] = {
            "workflow_id": instance.workflow_id,
            "workflow_type": workflow_type,
            "deployment_id": instance.deployment_id,
            "status": instance.status.value,
            "event_type": event_type,
            "created_at": instance.created_at.isoformat(),
            "updated_at": instance.updated_at.isoformat() if instance.updated_at else None,
            "metadata": instance.metadata,
        }

        # Add current step info if available
        if hasattr(instance, "current_step") and instance.current_step:
            payload["current_step"] = {
                "stage": instance.current_step.stage.value if hasattr(instance.current_step.stage, "value") else str(instance.current_step.stage),
                "assignee": instance.current_step.assignee,
                "status": instance.current_step.status.value if hasattr(instance.current_step.status, "value") else str(instance.current_step.status),
            }

        # Add completed steps summary
        if hasattr(instance, "completed_steps"):
            payload["completed_steps"] = len(instance.completed_steps)

        # Add due date if available
        if hasattr(instance, "due_date") and instance.due_date:
            payload["due_date"] = instance.due_date.isoformat()

        return payload


class PolicyViolationBridge:
    """
    Bridge for policy violation events.

    This class can be used to dispatch webhook events when policy
    violations are detected during enforcement.
    """

    def __init__(
        self,
        webhook_manager: WebhookManager,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the policy violation bridge.

        Args:
            webhook_manager: The webhook manager to dispatch events to.
            enabled: Whether the bridge is enabled.
        """
        self._webhook_manager = webhook_manager
        self._enabled = enabled
        self._stats = NotificationBridgeStats()

    @property
    def enabled(self) -> bool:
        """Check if the bridge is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable the bridge."""
        self._enabled = value

    def get_stats(self) -> NotificationBridgeStats:
        """Get bridge statistics."""
        return self._stats

    def notify_violation(
        self,
        request_id: str,
        rule_name: str,
        deployment_id: str | None = None,
        reason: str = "",
        severity: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Dispatch a policy violation notification.

        Args:
            request_id: ID of the request that violated policy.
            rule_name: Name of the policy rule that was violated.
            deployment_id: Optional deployment ID.
            reason: Reason for the violation.
            severity: Severity level (low, medium, high, critical).
            metadata: Additional metadata.
        """
        self._stats.events_received += 1

        if not self._enabled:
            self._stats.events_filtered += 1
            return

        webhook_event = WebhookEvent(
            event_type=WebhookEventType.POLICY_VIOLATION,
            payload={
                "request_id": request_id,
                "rule_name": rule_name,
                "deployment_id": deployment_id,
                "reason": reason,
                "severity": severity,
                "metadata": metadata or {},
            },
            source="enforcement_pipeline",
        )

        self._webhook_manager.dispatch(webhook_event)
        self._stats.events_dispatched += 1

        logger.debug(
            f"Dispatched violation webhook: rule={rule_name} request={request_id}"
        )
