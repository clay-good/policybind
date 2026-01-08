"""
Notification management for PolicyBind registry.

This module provides the NotificationManager class for sending notifications
about workflow events, review reminders, and other registry activities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable
import smtplib
import urllib.request
import urllib.error
import json

from policybind.models.base import generate_uuid, utc_now


class NotificationChannel(Enum):
    """Available notification channels."""

    EMAIL = "email"
    """Send notification via email."""

    WEBHOOK = "webhook"
    """Send notification via HTTP webhook."""

    LOG = "log"
    """Log notification (useful for testing)."""


class NotificationPriority(Enum):
    """Priority levels for notifications."""

    LOW = "low"
    """Low priority - can be batched or delayed."""

    NORMAL = "normal"
    """Normal priority - deliver in reasonable time."""

    HIGH = "high"
    """High priority - deliver immediately."""

    URGENT = "urgent"
    """Urgent - requires immediate attention."""


class NotificationStatus(Enum):
    """Status of a notification."""

    PENDING = "pending"
    """Notification is queued for delivery."""

    SENT = "sent"
    """Notification was sent successfully."""

    FAILED = "failed"
    """Notification delivery failed."""

    SKIPPED = "skipped"
    """Notification was skipped (e.g., preferences)."""


class NotificationType(Enum):
    """Types of notifications."""

    APPROVAL_PENDING = "approval_pending"
    """A deployment is awaiting approval."""

    APPROVAL_GRANTED = "approval_granted"
    """A deployment was approved."""

    APPROVAL_REJECTED = "approval_rejected"
    """A deployment was rejected."""

    REVIEW_REMINDER = "review_reminder"
    """A deployment review is due soon."""

    REVIEW_OVERDUE = "review_overdue"
    """A deployment review is overdue."""

    SUSPENSION_NOTICE = "suspension_notice"
    """A deployment has been suspended."""

    REINSTATEMENT_REQUEST = "reinstatement_request"
    """A reinstatement has been requested."""

    REINSTATEMENT_APPROVED = "reinstatement_approved"
    """A reinstatement was approved."""

    VIOLATION_ALERT = "violation_alert"
    """A policy violation occurred."""

    SLA_BREACH = "sla_breach"
    """A workflow SLA was breached."""

    DELEGATION_NOTICE = "delegation_notice"
    """A workflow step was delegated."""

    ESCALATION_NOTICE = "escalation_notice"
    """A workflow was escalated."""


@dataclass
class NotificationTemplate:
    """
    A template for generating notification content.

    Attributes:
        template_id: Unique identifier for the template.
        notification_type: Type of notification this template is for.
        subject_template: Template for the notification subject.
        body_template: Template for the notification body.
        html_template: Optional HTML template for rich emails.
        metadata: Additional template metadata.
    """

    template_id: str = field(default_factory=generate_uuid)
    notification_type: NotificationType = NotificationType.APPROVAL_PENDING
    subject_template: str = ""
    body_template: str = ""
    html_template: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def render_subject(self, context: dict[str, Any]) -> str:
        """Render the subject with the given context."""
        return self._render(self.subject_template, context)

    def render_body(self, context: dict[str, Any]) -> str:
        """Render the body with the given context."""
        return self._render(self.body_template, context)

    def render_html(self, context: dict[str, Any]) -> str:
        """Render the HTML body with the given context."""
        if not self.html_template:
            return ""
        return self._render(self.html_template, context)

    def _render(self, template: str, context: dict[str, Any]) -> str:
        """Simple template rendering using format-style substitution."""
        try:
            return template.format(**context)
        except KeyError:
            # Fall back to partial substitution
            result = template
            for key, value in context.items():
                result = result.replace(f"{{{key}}}", str(value))
            return result


@dataclass
class Notification:
    """
    A notification to be sent.

    Attributes:
        notification_id: Unique identifier for the notification.
        notification_type: Type of notification.
        priority: Priority level.
        status: Current status.
        channel: Delivery channel.
        recipient: Who should receive this notification.
        subject: Notification subject.
        body: Notification body.
        html_body: Optional HTML body.
        created_at: When the notification was created.
        sent_at: When the notification was sent.
        error: Error message if delivery failed.
        context: Additional context data.
        metadata: Additional notification metadata.
    """

    notification_id: str = field(default_factory=generate_uuid)
    notification_type: NotificationType = NotificationType.APPROVAL_PENDING
    priority: NotificationPriority = NotificationPriority.NORMAL
    status: NotificationStatus = NotificationStatus.PENDING
    channel: NotificationChannel = NotificationChannel.LOG
    recipient: str = ""
    subject: str = ""
    body: str = ""
    html_body: str = ""
    created_at: datetime = field(default_factory=utc_now)
    sent_at: datetime | None = None
    error: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "notification_id": self.notification_id,
            "notification_type": self.notification_type.value,
            "priority": self.priority.value,
            "status": self.status.value,
            "channel": self.channel.value,
            "recipient": self.recipient,
            "subject": self.subject,
            "body": self.body,
            "html_body": self.html_body,
            "created_at": self.created_at.isoformat(),
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "error": self.error,
            "context": self.context,
            "metadata": self.metadata,
        }


@dataclass
class NotificationPreferences:
    """
    Notification preferences for a recipient.

    Attributes:
        recipient: The recipient identifier.
        enabled_types: Set of notification types that are enabled.
        preferred_channel: Preferred notification channel.
        email: Email address for email notifications.
        webhook_url: Webhook URL for webhook notifications.
        quiet_hours_start: Start of quiet hours (0-23, or None).
        quiet_hours_end: End of quiet hours (0-23, or None).
        metadata: Additional preference metadata.
    """

    recipient: str = ""
    enabled_types: set[NotificationType] = field(
        default_factory=lambda: set(NotificationType)
    )
    preferred_channel: NotificationChannel = NotificationChannel.EMAIL
    email: str = ""
    webhook_url: str = ""
    quiet_hours_start: int | None = None
    quiet_hours_end: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_type_enabled(self, notification_type: NotificationType) -> bool:
        """Check if a notification type is enabled."""
        return notification_type in self.enabled_types

    def is_quiet_hours(self, now: datetime | None = None) -> bool:
        """Check if it's currently quiet hours."""
        if self.quiet_hours_start is None or self.quiet_hours_end is None:
            return False

        current = now or utc_now()
        hour = current.hour

        if self.quiet_hours_start <= self.quiet_hours_end:
            return self.quiet_hours_start <= hour < self.quiet_hours_end
        else:
            # Quiet hours span midnight
            return hour >= self.quiet_hours_start or hour < self.quiet_hours_end


@dataclass
class SMTPConfig:
    """SMTP configuration for email delivery."""

    host: str = "localhost"
    port: int = 25
    username: str = ""
    password: str = ""
    use_tls: bool = False
    use_ssl: bool = False
    from_address: str = "policybind@example.com"
    from_name: str = "PolicyBind"


# Type alias for notification callbacks
NotificationCallback = Callable[[Notification], None]


class NotificationManager:
    """
    Manages notification delivery for the registry.

    The NotificationManager handles:
    - Sending notifications via multiple channels
    - Template-based notification content
    - Notification preferences per recipient
    - Delivery tracking and status

    Example:
        Sending a notification::

            manager = NotificationManager()

            # Set up templates
            manager.set_template(
                NotificationType.APPROVAL_PENDING,
                subject="Approval Required: {deployment_name}",
                body="Deployment {deployment_name} requires approval.",
            )

            # Send notification
            manager.notify(
                notification_type=NotificationType.APPROVAL_PENDING,
                recipient="admin@example.com",
                context={"deployment_name": "Customer Bot"},
            )
    """

    # Default templates for each notification type
    DEFAULT_TEMPLATES = {
        NotificationType.APPROVAL_PENDING: NotificationTemplate(
            notification_type=NotificationType.APPROVAL_PENDING,
            subject_template="[PolicyBind] Approval Required: {deployment_name}",
            body_template=(
                "A new deployment requires your approval.\n\n"
                "Deployment: {deployment_name}\n"
                "Owner: {owner}\n"
                "Risk Level: {risk_level}\n\n"
                "Please review and approve or reject this deployment."
            ),
        ),
        NotificationType.APPROVAL_GRANTED: NotificationTemplate(
            notification_type=NotificationType.APPROVAL_GRANTED,
            subject_template="[PolicyBind] Deployment Approved: {deployment_name}",
            body_template=(
                "Your deployment has been approved.\n\n"
                "Deployment: {deployment_name}\n"
                "Approved by: {approved_by}\n\n"
                "The deployment is now active."
            ),
        ),
        NotificationType.APPROVAL_REJECTED: NotificationTemplate(
            notification_type=NotificationType.APPROVAL_REJECTED,
            subject_template="[PolicyBind] Deployment Rejected: {deployment_name}",
            body_template=(
                "Your deployment has been rejected.\n\n"
                "Deployment: {deployment_name}\n"
                "Rejected by: {rejected_by}\n"
                "Reason: {reason}\n\n"
                "Please address the concerns and resubmit."
            ),
        ),
        NotificationType.REVIEW_REMINDER: NotificationTemplate(
            notification_type=NotificationType.REVIEW_REMINDER,
            subject_template="[PolicyBind] Review Due: {deployment_name}",
            body_template=(
                "A deployment review is due soon.\n\n"
                "Deployment: {deployment_name}\n"
                "Review Due: {due_date}\n\n"
                "Please complete the review before the due date."
            ),
        ),
        NotificationType.REVIEW_OVERDUE: NotificationTemplate(
            notification_type=NotificationType.REVIEW_OVERDUE,
            subject_template="[PolicyBind] OVERDUE Review: {deployment_name}",
            body_template=(
                "A deployment review is OVERDUE.\n\n"
                "Deployment: {deployment_name}\n"
                "Was Due: {due_date}\n\n"
                "The deployment may be suspended if not reviewed promptly."
            ),
        ),
        NotificationType.SUSPENSION_NOTICE: NotificationTemplate(
            notification_type=NotificationType.SUSPENSION_NOTICE,
            subject_template="[PolicyBind] Deployment Suspended: {deployment_name}",
            body_template=(
                "A deployment has been suspended.\n\n"
                "Deployment: {deployment_name}\n"
                "Reason: {reason}\n"
                "Suspended by: {suspended_by}\n\n"
                "The deployment will not process requests until reinstated."
            ),
        ),
        NotificationType.REINSTATEMENT_REQUEST: NotificationTemplate(
            notification_type=NotificationType.REINSTATEMENT_REQUEST,
            subject_template=(
                "[PolicyBind] Reinstatement Requested: {deployment_name}"
            ),
            body_template=(
                "A reinstatement has been requested.\n\n"
                "Deployment: {deployment_name}\n"
                "Requested by: {requested_by}\n"
                "Justification: {justification}\n\n"
                "Please review and approve or deny the request."
            ),
        ),
        NotificationType.REINSTATEMENT_APPROVED: NotificationTemplate(
            notification_type=NotificationType.REINSTATEMENT_APPROVED,
            subject_template="[PolicyBind] Reinstatement Approved: {deployment_name}",
            body_template=(
                "A deployment has been reinstated.\n\n"
                "Deployment: {deployment_name}\n"
                "Approved by: {approved_by}\n\n"
                "The deployment is now active again."
            ),
        ),
        NotificationType.VIOLATION_ALERT: NotificationTemplate(
            notification_type=NotificationType.VIOLATION_ALERT,
            subject_template="[PolicyBind] Policy Violation: {deployment_name}",
            body_template=(
                "A policy violation has been detected.\n\n"
                "Deployment: {deployment_name}\n"
                "Violation: {violation_reason}\n"
                "Total Violations: {violation_count}\n\n"
                "Please investigate and take corrective action."
            ),
        ),
        NotificationType.SLA_BREACH: NotificationTemplate(
            notification_type=NotificationType.SLA_BREACH,
            subject_template="[PolicyBind] SLA Breach: {workflow_type}",
            body_template=(
                "A workflow SLA has been breached.\n\n"
                "Workflow: {workflow_type}\n"
                "Deployment: {deployment_name}\n"
                "Was Due: {due_date}\n\n"
                "The workflow has been escalated."
            ),
        ),
        NotificationType.DELEGATION_NOTICE: NotificationTemplate(
            notification_type=NotificationType.DELEGATION_NOTICE,
            subject_template="[PolicyBind] Task Delegated: {step_name}",
            body_template=(
                "A workflow task has been delegated to you.\n\n"
                "Task: {step_name}\n"
                "Deployment: {deployment_name}\n"
                "Delegated by: {delegated_by}\n"
                "Reason: {reason}\n\n"
                "Please review and take action."
            ),
        ),
        NotificationType.ESCALATION_NOTICE: NotificationTemplate(
            notification_type=NotificationType.ESCALATION_NOTICE,
            subject_template="[PolicyBind] ESCALATION: {deployment_name}",
            body_template=(
                "A workflow has been escalated.\n\n"
                "Deployment: {deployment_name}\n"
                "Reason: {reason}\n\n"
                "Immediate attention is required."
            ),
        ),
    }

    def __init__(
        self,
        smtp_config: SMTPConfig | None = None,
        default_channel: NotificationChannel = NotificationChannel.LOG,
    ) -> None:
        """
        Initialize the notification manager.

        Args:
            smtp_config: SMTP configuration for email delivery.
            default_channel: Default channel for notifications.
        """
        self._smtp_config = smtp_config or SMTPConfig()
        self._default_channel = default_channel
        self._templates: dict[NotificationType, NotificationTemplate] = (
            dict(self.DEFAULT_TEMPLATES)
        )
        self._preferences: dict[str, NotificationPreferences] = {}
        self._notifications: list[Notification] = []
        self._callbacks: list[NotificationCallback] = []
        self._log_handler: Callable[[Notification], None] | None = None

    def on_notification(self, callback: NotificationCallback) -> None:
        """Register a callback for sent notifications."""
        self._callbacks.append(callback)

    def set_log_handler(
        self, handler: Callable[[Notification], None]
    ) -> None:
        """Set a custom log handler for LOG channel notifications."""
        self._log_handler = handler

    def set_template(
        self,
        notification_type: NotificationType,
        subject: str,
        body: str,
        html: str = "",
    ) -> None:
        """
        Set a custom template for a notification type.

        Args:
            notification_type: The notification type.
            subject: Subject template.
            body: Body template.
            html: Optional HTML template.
        """
        self._templates[notification_type] = NotificationTemplate(
            notification_type=notification_type,
            subject_template=subject,
            body_template=body,
            html_template=html,
        )

    def set_preferences(
        self,
        recipient: str,
        preferences: NotificationPreferences,
    ) -> None:
        """
        Set notification preferences for a recipient.

        Args:
            recipient: The recipient identifier.
            preferences: The preferences to set.
        """
        preferences.recipient = recipient
        self._preferences[recipient] = preferences

    def get_preferences(self, recipient: str) -> NotificationPreferences:
        """
        Get notification preferences for a recipient.

        Args:
            recipient: The recipient identifier.

        Returns:
            The preferences, or default preferences if not set.
        """
        return self._preferences.get(
            recipient, NotificationPreferences(recipient=recipient)
        )

    def notify(
        self,
        notification_type: NotificationType,
        recipient: str,
        context: dict[str, Any] | None = None,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        channel: NotificationChannel | None = None,
    ) -> Notification:
        """
        Send a notification.

        Args:
            notification_type: Type of notification.
            recipient: Who should receive the notification.
            context: Context data for template rendering.
            priority: Notification priority.
            channel: Delivery channel (uses preference or default if None).

        Returns:
            The notification object.
        """
        context = context or {}
        prefs = self.get_preferences(recipient)

        # Check if type is enabled
        if not prefs.is_type_enabled(notification_type):
            notification = Notification(
                notification_type=notification_type,
                priority=priority,
                status=NotificationStatus.SKIPPED,
                recipient=recipient,
                context=context,
                metadata={"reason": "Type disabled in preferences"},
            )
            self._notifications.append(notification)
            return notification

        # Determine channel
        if channel is None:
            channel = prefs.preferred_channel or self._default_channel

        # Get template
        template = self._templates.get(notification_type)
        if not template:
            template = NotificationTemplate(
                notification_type=notification_type,
                subject_template=f"[PolicyBind] {notification_type.value}",
                body_template=str(context),
            )

        # Render content
        subject = template.render_subject(context)
        body = template.render_body(context)
        html_body = template.render_html(context)

        # Create notification
        notification = Notification(
            notification_type=notification_type,
            priority=priority,
            status=NotificationStatus.PENDING,
            channel=channel,
            recipient=recipient,
            subject=subject,
            body=body,
            html_body=html_body,
            context=context,
        )

        # Check quiet hours for non-urgent notifications
        if (
            priority != NotificationPriority.URGENT
            and prefs.is_quiet_hours()
        ):
            notification.status = NotificationStatus.PENDING
            notification.metadata["queued_for_quiet_hours"] = True
            self._notifications.append(notification)
            return notification

        # Send notification
        self._send_notification(notification, prefs)

        self._notifications.append(notification)

        # Call callbacks
        for callback in self._callbacks:
            try:
                callback(notification)
            except Exception:
                pass

        return notification

    def notify_many(
        self,
        notification_type: NotificationType,
        recipients: list[str],
        context: dict[str, Any] | None = None,
        priority: NotificationPriority = NotificationPriority.NORMAL,
    ) -> list[Notification]:
        """
        Send a notification to multiple recipients.

        Args:
            notification_type: Type of notification.
            recipients: List of recipients.
            context: Context data for template rendering.
            priority: Notification priority.

        Returns:
            List of notification objects.
        """
        return [
            self.notify(
                notification_type=notification_type,
                recipient=recipient,
                context=context,
                priority=priority,
            )
            for recipient in recipients
        ]

    def get_notifications(
        self,
        recipient: str | None = None,
        status: NotificationStatus | None = None,
        notification_type: NotificationType | None = None,
        limit: int = 100,
    ) -> list[Notification]:
        """
        Get notifications with optional filtering.

        Args:
            recipient: Filter by recipient.
            status: Filter by status.
            notification_type: Filter by type.
            limit: Maximum number to return.

        Returns:
            List of matching notifications.
        """
        results = []
        for notification in reversed(self._notifications):
            if recipient and notification.recipient != recipient:
                continue
            if status and notification.status != status:
                continue
            if notification_type and notification.notification_type != notification_type:
                continue
            results.append(notification)
            if len(results) >= limit:
                break
        return results

    def get_pending_notifications(self) -> list[Notification]:
        """Get all pending notifications."""
        return [
            n for n in self._notifications
            if n.status == NotificationStatus.PENDING
        ]

    def retry_failed(self) -> list[Notification]:
        """
        Retry sending failed notifications.

        Returns:
            List of notifications that were retried.
        """
        retried = []
        for notification in self._notifications:
            if notification.status == NotificationStatus.FAILED:
                prefs = self.get_preferences(notification.recipient)
                self._send_notification(notification, prefs)
                retried.append(notification)
        return retried

    def get_statistics(self) -> dict[str, Any]:
        """Get notification statistics."""
        by_status: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_channel: dict[str, int] = {}

        for notification in self._notifications:
            status = notification.status.value
            by_status[status] = by_status.get(status, 0) + 1

            ntype = notification.notification_type.value
            by_type[ntype] = by_type.get(ntype, 0) + 1

            channel = notification.channel.value
            by_channel[channel] = by_channel.get(channel, 0) + 1

        return {
            "total": len(self._notifications),
            "by_status": by_status,
            "by_type": by_type,
            "by_channel": by_channel,
        }

    def _send_notification(
        self,
        notification: Notification,
        prefs: NotificationPreferences,
    ) -> None:
        """Send a notification using the appropriate channel."""
        try:
            if notification.channel == NotificationChannel.EMAIL:
                self._send_email(notification, prefs)
            elif notification.channel == NotificationChannel.WEBHOOK:
                self._send_webhook(notification, prefs)
            elif notification.channel == NotificationChannel.LOG:
                self._send_log(notification)

            notification.status = NotificationStatus.SENT
            notification.sent_at = utc_now()

        except Exception as e:
            notification.status = NotificationStatus.FAILED
            notification.error = str(e)

    def _send_email(
        self,
        notification: Notification,
        prefs: NotificationPreferences,
    ) -> None:
        """Send notification via email."""
        email_address = prefs.email or notification.recipient

        if not email_address:
            raise ValueError("No email address available")

        # Build email message
        from_addr = f"{self._smtp_config.from_name} <{self._smtp_config.from_address}>"

        headers = [
            f"From: {from_addr}",
            f"To: {email_address}",
            f"Subject: {notification.subject}",
        ]

        if notification.html_body:
            headers.append("Content-Type: text/html; charset=utf-8")
            body = notification.html_body
        else:
            headers.append("Content-Type: text/plain; charset=utf-8")
            body = notification.body

        message = "\r\n".join(headers) + "\r\n\r\n" + body

        # Send email
        if self._smtp_config.use_ssl:
            server = smtplib.SMTP_SSL(
                self._smtp_config.host,
                self._smtp_config.port,
            )
        else:
            server = smtplib.SMTP(
                self._smtp_config.host,
                self._smtp_config.port,
            )

        try:
            if self._smtp_config.use_tls:
                server.starttls()

            if self._smtp_config.username and self._smtp_config.password:
                server.login(
                    self._smtp_config.username,
                    self._smtp_config.password,
                )

            server.sendmail(
                self._smtp_config.from_address,
                [email_address],
                message.encode("utf-8"),
            )
        finally:
            server.quit()

    def _send_webhook(
        self,
        notification: Notification,
        prefs: NotificationPreferences,
    ) -> None:
        """Send notification via webhook."""
        webhook_url = prefs.webhook_url
        if not webhook_url:
            raise ValueError("No webhook URL available")

        payload = {
            "type": notification.notification_type.value,
            "priority": notification.priority.value,
            "recipient": notification.recipient,
            "subject": notification.subject,
            "body": notification.body,
            "context": notification.context,
            "timestamp": notification.created_at.isoformat(),
        }

        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "PolicyBind/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status >= 400:
                raise ValueError(f"Webhook returned status {response.status}")

    def _send_log(self, notification: Notification) -> None:
        """Send notification via log handler."""
        if self._log_handler:
            self._log_handler(notification)
        # If no handler, notification is just recorded
