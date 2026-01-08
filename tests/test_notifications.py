"""
Tests for PolicyBind registry notifications.

This module tests the NotificationManager class and related notification
functionality.
"""

from datetime import timedelta

import pytest

from policybind.models.base import utc_now
from policybind.registry.notifications import (
    Notification,
    NotificationChannel,
    NotificationManager,
    NotificationPreferences,
    NotificationPriority,
    NotificationStatus,
    NotificationTemplate,
    NotificationType,
    SMTPConfig,
)


# Fixtures


@pytest.fixture
def notification_manager() -> NotificationManager:
    """Create a notification manager for testing."""
    manager = NotificationManager(default_channel=NotificationChannel.LOG)
    # Set default preferences to use LOG channel
    default_prefs = NotificationPreferences(
        preferred_channel=NotificationChannel.LOG,
    )
    # We'll set this for each recipient when needed
    return manager


@pytest.fixture
def smtp_config() -> SMTPConfig:
    """Create an SMTP configuration for testing."""
    return SMTPConfig(
        host="smtp.example.com",
        port=587,
        username="test",
        password="secret",
        use_tls=True,
        from_address="policybind@example.com",
        from_name="PolicyBind Test",
    )


# NotificationTemplate Tests


class TestNotificationTemplate:
    """Tests for the NotificationTemplate class."""

    def test_render_subject(self) -> None:
        """Test rendering a subject template."""
        template = NotificationTemplate(
            subject_template="[PolicyBind] {action}: {deployment_name}",
            body_template="",
        )

        subject = template.render_subject({
            "action": "Approval Required",
            "deployment_name": "Test Bot",
        })

        assert subject == "[PolicyBind] Approval Required: Test Bot"

    def test_render_body(self) -> None:
        """Test rendering a body template."""
        template = NotificationTemplate(
            subject_template="",
            body_template="Deployment: {name}\nOwner: {owner}\nRisk: {risk_level}",
        )

        body = template.render_body({
            "name": "Test Bot",
            "owner": "test-team",
            "risk_level": "HIGH",
        })

        assert "Deployment: Test Bot" in body
        assert "Owner: test-team" in body
        assert "Risk: HIGH" in body

    def test_render_html(self) -> None:
        """Test rendering an HTML template."""
        template = NotificationTemplate(
            subject_template="",
            body_template="",
            html_template="<h1>{title}</h1><p>{message}</p>",
        )

        html = template.render_html({
            "title": "Alert",
            "message": "Something happened",
        })

        assert html == "<h1>Alert</h1><p>Something happened</p>"

    def test_render_html_empty(self) -> None:
        """Test rendering empty HTML template."""
        template = NotificationTemplate(
            subject_template="",
            body_template="",
        )

        html = template.render_html({"key": "value"})
        assert html == ""

    def test_render_partial_substitution(self) -> None:
        """Test rendering with missing keys does partial substitution."""
        template = NotificationTemplate(
            subject_template="{known} and {unknown}",
            body_template="",
        )

        subject = template.render_subject({"known": "value"})
        assert "value" in subject
        assert "{unknown}" in subject


# NotificationPreferences Tests


class TestNotificationPreferences:
    """Tests for the NotificationPreferences class."""

    def test_is_type_enabled(self) -> None:
        """Test checking if a notification type is enabled."""
        prefs = NotificationPreferences(
            enabled_types={
                NotificationType.APPROVAL_PENDING,
                NotificationType.REVIEW_REMINDER,
            }
        )

        assert prefs.is_type_enabled(NotificationType.APPROVAL_PENDING)
        assert prefs.is_type_enabled(NotificationType.REVIEW_REMINDER)
        assert not prefs.is_type_enabled(NotificationType.SUSPENSION_NOTICE)

    def test_is_type_enabled_default_all(self) -> None:
        """Test that all types are enabled by default."""
        prefs = NotificationPreferences()

        for ntype in NotificationType:
            assert prefs.is_type_enabled(ntype)

    def test_is_quiet_hours_not_set(self) -> None:
        """Test quiet hours when not configured."""
        prefs = NotificationPreferences()
        assert not prefs.is_quiet_hours()

    def test_is_quiet_hours_within_range(self) -> None:
        """Test quiet hours within normal range."""
        prefs = NotificationPreferences(
            quiet_hours_start=22,
            quiet_hours_end=6,
        )

        # Create a time at 23:00
        from datetime import datetime, timezone
        late_night = datetime(2024, 1, 1, 23, 0, tzinfo=timezone.utc)
        assert prefs.is_quiet_hours(late_night)

        # Create a time at 3:00
        early_morning = datetime(2024, 1, 1, 3, 0, tzinfo=timezone.utc)
        assert prefs.is_quiet_hours(early_morning)

        # Create a time at 12:00
        midday = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        assert not prefs.is_quiet_hours(midday)

    def test_is_quiet_hours_normal_range(self) -> None:
        """Test quiet hours with normal range (not spanning midnight)."""
        prefs = NotificationPreferences(
            quiet_hours_start=12,
            quiet_hours_end=14,
        )

        from datetime import datetime, timezone
        during = datetime(2024, 1, 1, 13, 0, tzinfo=timezone.utc)
        assert prefs.is_quiet_hours(during)

        before = datetime(2024, 1, 1, 11, 0, tzinfo=timezone.utc)
        assert not prefs.is_quiet_hours(before)


# Notification Tests


class TestNotification:
    """Tests for the Notification dataclass."""

    def test_notification_to_dict(self) -> None:
        """Test converting a notification to dictionary."""
        notification = Notification(
            notification_type=NotificationType.APPROVAL_PENDING,
            priority=NotificationPriority.HIGH,
            status=NotificationStatus.SENT,
            channel=NotificationChannel.EMAIL,
            recipient="test@example.com",
            subject="Test Subject",
            body="Test Body",
        )

        data = notification.to_dict()

        assert data["notification_type"] == "approval_pending"
        assert data["priority"] == "high"
        assert data["status"] == "sent"
        assert data["channel"] == "email"
        assert data["recipient"] == "test@example.com"
        assert data["subject"] == "Test Subject"

    def test_notification_sent_at(self) -> None:
        """Test notification sent_at timestamp."""
        notification = Notification(sent_at=utc_now())
        data = notification.to_dict()
        assert data["sent_at"] is not None

        notification2 = Notification()
        data2 = notification2.to_dict()
        assert data2["sent_at"] is None


# NotificationManager Tests


class TestNotificationManager:
    """Tests for the NotificationManager class."""

    def test_notify_basic(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test sending a basic notification."""
        notification = notification_manager.notify(
            notification_type=NotificationType.APPROVAL_PENDING,
            recipient="admin@example.com",
            context={
                "deployment_name": "Test Bot",
                "owner": "test-team",
                "risk_level": "HIGH",
            },
            channel=NotificationChannel.LOG,  # Use LOG channel for testing
        )

        assert notification.status == NotificationStatus.SENT
        assert notification.recipient == "admin@example.com"
        assert "Test Bot" in notification.subject
        assert notification.sent_at is not None

    def test_notify_with_priority(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test notification with priority."""
        notification = notification_manager.notify(
            notification_type=NotificationType.SUSPENSION_NOTICE,
            recipient="owner@example.com",
            priority=NotificationPriority.URGENT,
            context={"deployment_name": "Critical System", "reason": "Violations", "suspended_by": "admin"},
            channel=NotificationChannel.LOG,
        )

        assert notification.priority == NotificationPriority.URGENT

    def test_notify_disabled_type(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test notification when type is disabled in preferences."""
        prefs = NotificationPreferences(
            enabled_types={NotificationType.APPROVAL_PENDING},  # Only this enabled
            preferred_channel=NotificationChannel.LOG,
        )
        notification_manager.set_preferences("user@example.com", prefs)

        notification = notification_manager.notify(
            notification_type=NotificationType.REVIEW_REMINDER,
            recipient="user@example.com",
        )

        assert notification.status == NotificationStatus.SKIPPED

    def test_notify_quiet_hours_non_urgent(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test non-urgent notification during quiet hours is queued."""
        from datetime import datetime, timezone

        prefs = NotificationPreferences(
            quiet_hours_start=0,
            quiet_hours_end=23,  # Always quiet
            preferred_channel=NotificationChannel.LOG,
        )
        notification_manager.set_preferences("user@example.com", prefs)

        notification = notification_manager.notify(
            notification_type=NotificationType.REVIEW_REMINDER,
            recipient="user@example.com",
            priority=NotificationPriority.NORMAL,
            context={"deployment_name": "Test", "due_date": "2024-01-01"},
        )

        assert notification.status == NotificationStatus.PENDING
        assert notification.metadata.get("queued_for_quiet_hours") is True

    def test_notify_urgent_bypasses_quiet_hours(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test urgent notification bypasses quiet hours."""
        prefs = NotificationPreferences(
            quiet_hours_start=0,
            quiet_hours_end=23,  # Always quiet
            preferred_channel=NotificationChannel.LOG,
        )
        notification_manager.set_preferences("user@example.com", prefs)

        notification = notification_manager.notify(
            notification_type=NotificationType.SLA_BREACH,
            recipient="user@example.com",
            priority=NotificationPriority.URGENT,
            context={
                "workflow_type": "approval",
                "deployment_name": "Test",
                "due_date": "2024-01-01",
            },
        )

        assert notification.status == NotificationStatus.SENT

    def test_notify_many(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test sending notification to multiple recipients."""
        recipients = ["user1@example.com", "user2@example.com", "user3@example.com"]

        # Set LOG channel for all recipients
        for r in recipients:
            prefs = NotificationPreferences(preferred_channel=NotificationChannel.LOG)
            notification_manager.set_preferences(r, prefs)

        notifications = notification_manager.notify_many(
            notification_type=NotificationType.ESCALATION_NOTICE,
            recipients=recipients,
            context={
                "deployment_name": "Critical System",
                "reason": "SLA breach",
            },
        )

        assert len(notifications) == 3
        assert all(n.status == NotificationStatus.SENT for n in notifications)

    def test_set_template(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test setting a custom template."""
        notification_manager.set_template(
            NotificationType.APPROVAL_PENDING,
            subject="CUSTOM: {deployment_name}",
            body="Custom body for {deployment_name}",
        )

        notification = notification_manager.notify(
            notification_type=NotificationType.APPROVAL_PENDING,
            recipient="admin@example.com",
            context={"deployment_name": "Test Bot"},
            channel=NotificationChannel.LOG,
        )

        assert notification.subject == "CUSTOM: Test Bot"
        assert "Custom body for Test Bot" in notification.body

    def test_set_and_get_preferences(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test setting and getting preferences."""
        prefs = NotificationPreferences(
            email="custom@example.com",
            preferred_channel=NotificationChannel.WEBHOOK,
            webhook_url="https://hooks.example.com/notify",
        )
        notification_manager.set_preferences("user@example.com", prefs)

        retrieved = notification_manager.get_preferences("user@example.com")
        assert retrieved.email == "custom@example.com"
        assert retrieved.preferred_channel == NotificationChannel.WEBHOOK

    def test_get_preferences_default(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test getting default preferences for unknown user."""
        prefs = notification_manager.get_preferences("unknown@example.com")
        assert prefs.recipient == "unknown@example.com"
        assert prefs.preferred_channel == NotificationChannel.EMAIL

    def test_get_notifications_all(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test getting all notifications."""
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user1@example.com",
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.REVIEW_REMINDER,
            "user2@example.com",
            context={"deployment_name": "Test", "due_date": "2024-01-01"},
            channel=NotificationChannel.LOG,
        )

        notifications = notification_manager.get_notifications()
        assert len(notifications) == 2

    def test_get_notifications_by_recipient(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test filtering notifications by recipient."""
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user1@example.com",
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.REVIEW_REMINDER,
            "user2@example.com",
            context={"deployment_name": "Test", "due_date": "2024-01-01"},
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.SUSPENSION_NOTICE,
            "user1@example.com",
            context={"deployment_name": "Test", "reason": "Violation", "suspended_by": "admin"},
            channel=NotificationChannel.LOG,
        )

        notifications = notification_manager.get_notifications(
            recipient="user1@example.com"
        )
        assert len(notifications) == 2

    def test_get_notifications_by_status(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test filtering notifications by status."""
        # Normal notification (will be SENT)
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user@example.com",
            channel=NotificationChannel.LOG,
        )

        # Skipped notification
        prefs = NotificationPreferences(
            enabled_types=set(),  # Nothing enabled
            preferred_channel=NotificationChannel.LOG,
        )
        notification_manager.set_preferences("disabled@example.com", prefs)
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "disabled@example.com",
        )

        sent = notification_manager.get_notifications(status=NotificationStatus.SENT)
        assert len(sent) == 1

        skipped = notification_manager.get_notifications(status=NotificationStatus.SKIPPED)
        assert len(skipped) == 1

    def test_get_notifications_by_type(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test filtering notifications by type."""
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user@example.com",
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.REVIEW_REMINDER,
            "user@example.com",
            context={"deployment_name": "Test", "due_date": "2024-01-01"},
            channel=NotificationChannel.LOG,
        )

        approvals = notification_manager.get_notifications(
            notification_type=NotificationType.APPROVAL_PENDING
        )
        assert len(approvals) == 1

    def test_get_pending_notifications(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test getting pending notifications."""
        # Set up quiet hours for all users
        prefs = NotificationPreferences(
            quiet_hours_start=0,
            quiet_hours_end=23,
        )
        notification_manager.set_preferences("user@example.com", prefs)

        # Non-urgent during quiet hours will be pending
        notification_manager.notify(
            NotificationType.REVIEW_REMINDER,
            "user@example.com",
            priority=NotificationPriority.LOW,
            context={"deployment_name": "Test", "due_date": "2024-01-01"},
        )

        pending = notification_manager.get_pending_notifications()
        assert len(pending) == 1

    def test_get_statistics(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test getting notification statistics."""
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user1@example.com",
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.APPROVAL_GRANTED,
            "user2@example.com",
            context={"deployment_name": "Test", "approved_by": "admin"},
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user3@example.com",
            channel=NotificationChannel.LOG,
        )

        stats = notification_manager.get_statistics()

        assert stats["total"] == 3
        assert stats["by_type"]["approval_pending"] == 2
        assert stats["by_type"]["approval_granted"] == 1
        assert stats["by_status"]["sent"] == 3
        assert stats["by_channel"]["log"] == 3

    def test_notification_callback(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test notification callbacks."""
        received: list[Notification] = []

        def callback(notification: Notification) -> None:
            received.append(notification)

        notification_manager.on_notification(callback)

        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user@example.com",
            channel=NotificationChannel.LOG,
        )
        notification_manager.notify(
            NotificationType.REVIEW_REMINDER,
            "user@example.com",
            context={"deployment_name": "Test", "due_date": "2024-01-01"},
            channel=NotificationChannel.LOG,
        )

        assert len(received) == 2

    def test_log_handler(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test custom log handler."""
        logged: list[Notification] = []

        def handler(notification: Notification) -> None:
            logged.append(notification)

        notification_manager.set_log_handler(handler)

        notification_manager.notify(
            NotificationType.APPROVAL_PENDING,
            "user@example.com",
            channel=NotificationChannel.LOG,
        )

        assert len(logged) == 1
        assert logged[0].notification_type == NotificationType.APPROVAL_PENDING

    def test_default_templates_exist(
        self,
        notification_manager: NotificationManager,
    ) -> None:
        """Test that default templates exist for all types."""
        for ntype in NotificationType:
            notification = notification_manager.notify(
                notification_type=ntype,
                recipient="test@example.com",
                context={
                    "deployment_name": "Test",
                    "owner": "owner",
                    "risk_level": "HIGH",
                    "approved_by": "admin",
                    "rejected_by": "admin",
                    "reason": "test reason",
                    "due_date": "2024-01-01",
                    "suspended_by": "admin",
                    "requested_by": "owner",
                    "justification": "test",
                    "violation_reason": "test",
                    "violation_count": 5,
                    "workflow_type": "approval",
                    "step_name": "Review",
                    "delegated_by": "manager",
                },
                channel=NotificationChannel.LOG,
            )
            assert notification.subject != ""
            assert notification.body != ""


# SMTPConfig Tests


class TestSMTPConfig:
    """Tests for the SMTPConfig dataclass."""

    def test_smtp_config_defaults(self) -> None:
        """Test SMTP config default values."""
        config = SMTPConfig()

        assert config.host == "localhost"
        assert config.port == 25
        assert config.use_tls is False
        assert config.use_ssl is False

    def test_smtp_config_custom(
        self,
        smtp_config: SMTPConfig,
    ) -> None:
        """Test SMTP config with custom values."""
        assert smtp_config.host == "smtp.example.com"
        assert smtp_config.port == 587
        assert smtp_config.use_tls is True
        assert smtp_config.username == "test"
