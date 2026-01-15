"""
Tests for PolicyBind webhook notification system.
"""

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from policybind.notifications.webhooks import (
    WebhookConfig,
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookEvent,
    WebhookEventType,
    WebhookManager,
)
from policybind.notifications.bridges import (
    IncidentNotificationBridge,
    WorkflowNotificationBridge,
    PolicyViolationBridge,
)
from policybind.models.base import utc_now


class TestWebhookEventType:
    """Tests for WebhookEventType enum."""

    def test_incident_events(self):
        """Test incident event types exist."""
        assert WebhookEventType.INCIDENT_CREATED.value == "incident.created"
        assert WebhookEventType.INCIDENT_UPDATED.value == "incident.updated"
        assert WebhookEventType.INCIDENT_ASSIGNED.value == "incident.assigned"
        assert WebhookEventType.INCIDENT_ESCALATED.value == "incident.escalated"
        assert WebhookEventType.INCIDENT_RESOLVED.value == "incident.resolved"
        assert WebhookEventType.INCIDENT_CLOSED.value == "incident.closed"

    def test_approval_events(self):
        """Test approval event types exist."""
        assert WebhookEventType.APPROVAL_REQUESTED.value == "approval.requested"
        assert WebhookEventType.APPROVAL_GRANTED.value == "approval.granted"
        assert WebhookEventType.APPROVAL_REJECTED.value == "approval.rejected"
        assert WebhookEventType.APPROVAL_ESCALATED.value == "approval.escalated"
        assert WebhookEventType.APPROVAL_DELEGATED.value == "approval.delegated"

    def test_deployment_events(self):
        """Test deployment event types exist."""
        assert WebhookEventType.DEPLOYMENT_SUSPENDED.value == "deployment.suspended"
        assert WebhookEventType.DEPLOYMENT_REINSTATED.value == "deployment.reinstated"
        assert WebhookEventType.DEPLOYMENT_REGISTERED.value == "deployment.registered"


class TestWebhookConfig:
    """Tests for WebhookConfig dataclass."""

    def test_create_config(self):
        """Test creating a webhook config."""
        config = WebhookConfig(
            name="Test Webhook",
            url="https://example.com/webhook",
            secret="my-secret",
            event_types={WebhookEventType.INCIDENT_CREATED},
        )

        assert config.name == "Test Webhook"
        assert config.url == "https://example.com/webhook"
        assert config.secret == "my-secret"
        assert config.enabled is True
        assert WebhookEventType.INCIDENT_CREATED in config.event_types

    def test_should_receive_enabled(self):
        """Test should_receive when enabled."""
        config = WebhookConfig(
            name="Test",
            url="https://example.com",
            enabled=True,
            event_types={WebhookEventType.INCIDENT_CREATED},
        )

        assert config.should_receive(WebhookEventType.INCIDENT_CREATED) is True
        assert config.should_receive(WebhookEventType.INCIDENT_UPDATED) is False

    def test_should_receive_all_events(self):
        """Test should_receive with empty event_types (all events)."""
        config = WebhookConfig(
            name="Test",
            url="https://example.com",
            enabled=True,
            event_types=set(),  # Empty = all events
        )

        assert config.should_receive(WebhookEventType.INCIDENT_CREATED) is True
        assert config.should_receive(WebhookEventType.APPROVAL_GRANTED) is True

    def test_should_receive_disabled(self):
        """Test should_receive when disabled."""
        config = WebhookConfig(
            name="Test",
            url="https://example.com",
            enabled=False,
            event_types={WebhookEventType.INCIDENT_CREATED},
        )

        assert config.should_receive(WebhookEventType.INCIDENT_CREATED) is False

    def test_to_dict(self):
        """Test converting to dictionary."""
        config = WebhookConfig(
            name="Test Webhook",
            url="https://example.com/webhook",
            event_types={WebhookEventType.INCIDENT_CREATED},
        )

        result = config.to_dict()
        assert result["name"] == "Test Webhook"
        assert result["url"] == "https://example.com/webhook"
        assert "secret" not in result  # Secret should not be in dict
        assert "incident.created" in result["event_types"]

    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "name": "Test Webhook",
            "url": "https://example.com/webhook",
            "secret": "my-secret",
            "event_types": ["incident.created", "approval.granted"],
            "enabled": True,
        }

        config = WebhookConfig.from_dict(data)
        assert config.name == "Test Webhook"
        assert config.url == "https://example.com/webhook"
        assert config.secret == "my-secret"
        assert WebhookEventType.INCIDENT_CREATED in config.event_types
        assert WebhookEventType.APPROVAL_GRANTED in config.event_types


class TestWebhookEvent:
    """Tests for WebhookEvent dataclass."""

    def test_create_event(self):
        """Test creating a webhook event."""
        event = WebhookEvent(
            event_type=WebhookEventType.INCIDENT_CREATED,
            payload={"incident_id": "inc-123"},
            source="test",
        )

        assert event.event_type == WebhookEventType.INCIDENT_CREATED
        assert event.payload["incident_id"] == "inc-123"
        assert event.source == "test"
        assert event.event_id is not None

    def test_to_dict(self):
        """Test converting to dictionary."""
        event = WebhookEvent(
            event_type=WebhookEventType.INCIDENT_CREATED,
            payload={"incident_id": "inc-123"},
            source="test",
        )

        result = event.to_dict()
        assert result["event_type"] == "incident.created"
        assert result["payload"]["incident_id"] == "inc-123"
        assert result["source"] == "test"
        assert "event_id" in result
        assert "created_at" in result


class TestWebhookDelivery:
    """Tests for WebhookDelivery dataclass."""

    def test_create_delivery(self):
        """Test creating a delivery record."""
        delivery = WebhookDelivery(
            webhook_id="wh-123",
            event_id="evt-456",
        )

        assert delivery.webhook_id == "wh-123"
        assert delivery.event_id == "evt-456"
        assert delivery.status == WebhookDeliveryStatus.PENDING
        assert delivery.attempt_count == 0

    def test_to_dict(self):
        """Test converting to dictionary."""
        delivery = WebhookDelivery(
            webhook_id="wh-123",
            event_id="evt-456",
            status=WebhookDeliveryStatus.DELIVERED,
            attempt_count=1,
            response_status=200,
        )

        result = delivery.to_dict()
        assert result["webhook_id"] == "wh-123"
        assert result["event_id"] == "evt-456"
        assert result["status"] == "delivered"
        assert result["attempt_count"] == 1
        assert result["response_status"] == 200


class TestWebhookManager:
    """Tests for WebhookManager class."""

    @pytest.fixture
    def manager(self):
        """Create a fresh webhook manager."""
        return WebhookManager()

    @pytest.fixture
    def config(self):
        """Create a test webhook config."""
        return WebhookConfig(
            name="Test Webhook",
            url="https://example.com/webhook",
            event_types={WebhookEventType.INCIDENT_CREATED},
        )

    def test_register_webhook(self, manager, config):
        """Test registering a webhook."""
        manager.register_webhook(config)

        assert manager.get_webhook(config.webhook_id) is not None
        assert len(manager.list_webhooks()) == 1

    def test_unregister_webhook(self, manager, config):
        """Test unregistering a webhook."""
        manager.register_webhook(config)
        assert manager.unregister_webhook(config.webhook_id) is True
        assert manager.get_webhook(config.webhook_id) is None
        assert manager.unregister_webhook("nonexistent") is False

    def test_update_webhook(self, manager, config):
        """Test updating a webhook."""
        manager.register_webhook(config)

        updated = manager.update_webhook(config.webhook_id, {"name": "Updated Name"})
        assert updated is not None
        assert updated.name == "Updated Name"

        # Test updating nonexistent
        assert manager.update_webhook("nonexistent", {}) is None

    def test_enable_disable_webhook(self, manager, config):
        """Test enabling and disabling webhooks."""
        manager.register_webhook(config)

        assert manager.disable_webhook(config.webhook_id) is True
        assert manager.get_webhook(config.webhook_id).enabled is False

        assert manager.enable_webhook(config.webhook_id) is True
        assert manager.get_webhook(config.webhook_id).enabled is True

    def test_compute_signature(self, manager):
        """Test HMAC signature computation."""
        secret = "my-secret"
        data = b'{"test": "data"}'

        signature = manager._compute_signature(secret, data)
        expected = hmac.new(
            secret.encode("utf-8"),
            data,
            hashlib.sha256,
        ).hexdigest()

        assert signature == expected

    def test_verify_signature(self, manager):
        """Test signature verification."""
        secret = "my-secret"
        data = b'{"test": "data"}'

        signature = manager._compute_signature(secret, data)

        assert manager.verify_signature(secret, data, signature) is True
        assert manager.verify_signature(secret, data, f"sha256={signature}") is True
        assert manager.verify_signature(secret, data, "invalid") is False
        assert manager.verify_signature("wrong-secret", data, signature) is False

    def test_get_deliveries(self, manager):
        """Test getting delivery history."""
        # Create some mock deliveries
        for i in range(5):
            delivery = WebhookDelivery(
                webhook_id=f"wh-{i % 2}",
                event_id=f"evt-{i}",
                status=(
                    WebhookDeliveryStatus.DELIVERED
                    if i % 2 == 0
                    else WebhookDeliveryStatus.FAILED
                ),
            )
            manager._deliveries.append(delivery)

        # Test filtering
        all_deliveries = manager.get_deliveries()
        assert len(all_deliveries) == 5

        webhook_deliveries = manager.get_deliveries(webhook_id="wh-0")
        assert len(webhook_deliveries) == 3

        failed_deliveries = manager.get_deliveries(
            status=WebhookDeliveryStatus.FAILED
        )
        assert len(failed_deliveries) == 2

        limited = manager.get_deliveries(limit=2)
        assert len(limited) == 2

    def test_get_delivery_stats(self, manager):
        """Test getting delivery statistics."""
        # Create some deliveries
        for i in range(10):
            delivery = WebhookDelivery(
                webhook_id=f"wh-{i % 2}",
                event_id=f"evt-{i}",
                status=(
                    WebhookDeliveryStatus.DELIVERED
                    if i % 3 != 0
                    else WebhookDeliveryStatus.FAILED
                ),
            )
            manager._deliveries.append(delivery)

        stats = manager.get_delivery_stats()
        assert stats["total_deliveries"] == 10
        assert "by_status" in stats
        assert "by_webhook" in stats

    @patch("urllib.request.urlopen")
    def test_dispatch(self, mock_urlopen, manager, config):
        """Test dispatching an event."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        manager.register_webhook(config)

        event = WebhookEvent(
            event_type=WebhookEventType.INCIDENT_CREATED,
            payload={"incident_id": "inc-123"},
        )

        deliveries = manager.dispatch(event)

        assert len(deliveries) == 1
        assert deliveries[0].status == WebhookDeliveryStatus.DELIVERED

    @patch("urllib.request.urlopen")
    def test_dispatch_no_matching_webhooks(self, mock_urlopen, manager, config):
        """Test dispatching when no webhooks match."""
        manager.register_webhook(config)

        event = WebhookEvent(
            event_type=WebhookEventType.APPROVAL_GRANTED,  # Not in config's event_types
            payload={},
        )

        deliveries = manager.dispatch(event)
        assert len(deliveries) == 0
        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_dispatch_failure_and_retry(self, mock_urlopen, manager):
        """Test dispatch failure and retry logic."""
        # Mock failed response
        mock_urlopen.side_effect = Exception("Connection failed")

        config = WebhookConfig(
            name="Test",
            url="https://example.com/webhook",
            max_retries=2,
            retry_delay_seconds=0,  # No delay for test
        )
        manager.register_webhook(config)

        event = WebhookEvent(
            event_type=WebhookEventType.INCIDENT_CREATED,
            payload={},
        )

        deliveries = manager.dispatch(event)

        assert len(deliveries) == 1
        assert deliveries[0].status == WebhookDeliveryStatus.FAILED
        assert deliveries[0].attempt_count == 2  # 2 retries

    @patch("urllib.request.urlopen")
    def test_test_webhook(self, mock_urlopen, manager, config):
        """Test sending a test event."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        manager.register_webhook(config)

        delivery = manager.test_webhook(config.webhook_id)
        assert delivery is not None
        assert delivery.status == WebhookDeliveryStatus.DELIVERED

        # Test nonexistent webhook
        assert manager.test_webhook("nonexistent") is None


class TestIncidentNotificationBridge:
    """Tests for IncidentNotificationBridge class."""

    @pytest.fixture
    def webhook_manager(self):
        """Create a webhook manager."""
        return WebhookManager()

    @pytest.fixture
    def bridge(self, webhook_manager):
        """Create an incident notification bridge."""
        return IncidentNotificationBridge(webhook_manager)

    def test_create_bridge(self, bridge, webhook_manager):
        """Test creating a bridge."""
        assert bridge.enabled is True
        assert bridge._webhook_manager is webhook_manager

    def test_enable_disable(self, bridge):
        """Test enabling and disabling the bridge."""
        bridge.enabled = False
        assert bridge.enabled is False

        bridge.enabled = True
        assert bridge.enabled is True

    def test_get_stats(self, bridge):
        """Test getting bridge statistics."""
        stats = bridge.get_stats()
        assert stats.events_received == 0
        assert stats.events_dispatched == 0
        assert stats.events_filtered == 0

    def test_event_type_mapping(self, bridge):
        """Test event type mappings exist."""
        assert "created" in bridge.EVENT_TYPE_MAPPING
        assert "status_change" in bridge.EVENT_TYPE_MAPPING
        assert "assignment" in bridge.EVENT_TYPE_MAPPING
        assert "escalation" in bridge.EVENT_TYPE_MAPPING


class TestWorkflowNotificationBridge:
    """Tests for WorkflowNotificationBridge class."""

    @pytest.fixture
    def webhook_manager(self):
        """Create a webhook manager."""
        return WebhookManager()

    @pytest.fixture
    def bridge(self, webhook_manager):
        """Create a workflow notification bridge."""
        return WorkflowNotificationBridge(webhook_manager)

    def test_create_bridge(self, bridge, webhook_manager):
        """Test creating a bridge."""
        assert bridge.enabled is True
        assert bridge._webhook_manager is webhook_manager

    def test_enable_disable(self, bridge):
        """Test enabling and disabling the bridge."""
        bridge.enabled = False
        assert bridge.enabled is False

        bridge.enabled = True
        assert bridge.enabled is True

    def test_approval_event_mapping(self, bridge):
        """Test approval event type mappings."""
        assert "created" in bridge.APPROVAL_EVENT_MAPPING
        assert "completed" in bridge.APPROVAL_EVENT_MAPPING
        assert "rejected" in bridge.APPROVAL_EVENT_MAPPING
        assert "delegated" in bridge.APPROVAL_EVENT_MAPPING
        assert "escalated" in bridge.APPROVAL_EVENT_MAPPING

    def test_review_event_mapping(self, bridge):
        """Test review event type mappings."""
        assert "created" in bridge.REVIEW_EVENT_MAPPING
        assert "completed" in bridge.REVIEW_EVENT_MAPPING

    def test_suspension_event_mapping(self, bridge):
        """Test suspension event type mappings."""
        assert "suspension_created" in bridge.SUSPENSION_EVENT_MAPPING
        assert "reinstated" in bridge.SUSPENSION_EVENT_MAPPING
        assert "reinstatement_requested" in bridge.SUSPENSION_EVENT_MAPPING
        assert "reinstatement_denied" in bridge.SUSPENSION_EVENT_MAPPING


class TestPolicyViolationBridge:
    """Tests for PolicyViolationBridge class."""

    @pytest.fixture
    def webhook_manager(self):
        """Create a webhook manager."""
        return WebhookManager()

    @pytest.fixture
    def bridge(self, webhook_manager):
        """Create a policy violation bridge."""
        return PolicyViolationBridge(webhook_manager)

    def test_create_bridge(self, bridge, webhook_manager):
        """Test creating a bridge."""
        assert bridge.enabled is True
        assert bridge._webhook_manager is webhook_manager

    @patch("urllib.request.urlopen")
    def test_notify_violation(self, mock_urlopen, bridge, webhook_manager):
        """Test notifying about a policy violation."""
        # Set up mock
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        # Register webhook that accepts all events
        config = WebhookConfig(
            name="Test",
            url="https://example.com/webhook",
        )
        webhook_manager.register_webhook(config)

        # Notify
        bridge.notify_violation(
            request_id="req-123",
            rule_name="deny-pii",
            deployment_id="dep-456",
            reason="PII detected",
            severity="high",
        )

        stats = bridge.get_stats()
        assert stats.events_received == 1
        assert stats.events_dispatched == 1

    def test_notify_violation_disabled(self, bridge):
        """Test notification when bridge is disabled."""
        bridge.enabled = False

        bridge.notify_violation(
            request_id="req-123",
            rule_name="deny-pii",
        )

        stats = bridge.get_stats()
        assert stats.events_received == 1
        assert stats.events_filtered == 1
        assert stats.events_dispatched == 0


class TestWebhookIntegration:
    """Integration tests for the webhook system."""

    @pytest.fixture
    def webhook_manager(self):
        """Create a webhook manager with test webhook."""
        manager = WebhookManager()
        config = WebhookConfig(
            name="Test Webhook",
            url="https://example.com/webhook",
            secret="test-secret",
            event_types=set(),  # All events
        )
        manager.register_webhook(config)
        return manager

    @patch("urllib.request.urlopen")
    def test_full_incident_flow(self, mock_urlopen, webhook_manager):
        """Test full incident notification flow."""
        # Set up mock
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        # Create bridge
        bridge = IncidentNotificationBridge(webhook_manager)

        # Create mock incident manager
        incident_manager = MagicMock()
        callbacks = []
        incident_manager.on_event = lambda cb: callbacks.append(cb)

        # Connect bridge
        bridge.connect(incident_manager)
        assert len(callbacks) == 1

        # Simulate incident event
        from policybind.incidents.models import (
            Incident,
            IncidentSeverity,
            IncidentStatus,
            IncidentType,
            TimelineEventType,
        )

        incident = Incident(
            incident_id="inc-123",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            incident_type=IncidentType.POLICY_VIOLATION,
            description="Test incident",
        )

        # Create mock event
        mock_event = MagicMock()
        mock_event.event_type = TimelineEventType.CREATED
        mock_event.incident_id = "inc-123"
        mock_event.incident = incident
        mock_event.actor = "test-user"
        mock_event.old_value = None
        mock_event.new_value = None
        mock_event.timestamp = utc_now()

        # Trigger callback
        callbacks[0](mock_event)

        # Verify webhook was called
        assert mock_urlopen.called
        stats = bridge.get_stats()
        assert stats.events_dispatched == 1

    @patch("urllib.request.urlopen")
    def test_full_workflow_flow(self, mock_urlopen, webhook_manager):
        """Test full workflow notification flow."""
        # Set up mock
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        # Create bridge
        bridge = WorkflowNotificationBridge(webhook_manager)

        # Create mock approval workflow
        approval_workflow = MagicMock()
        callbacks = []
        approval_workflow.on_workflow_event = lambda cb: callbacks.append(cb)

        # Connect bridge
        bridge.connect_approval_workflow(approval_workflow)
        assert len(callbacks) == 1

        # Create mock workflow instance
        mock_instance = MagicMock()
        mock_instance.workflow_id = "wf-123"
        mock_instance.deployment_id = "dep-456"
        mock_instance.status.value = "in_progress"
        mock_instance.created_at = utc_now()
        mock_instance.updated_at = utc_now()
        mock_instance.metadata = {}

        # Trigger callback
        callbacks[0](mock_instance, "created")

        # Verify webhook was called
        assert mock_urlopen.called
        stats = bridge.get_stats()
        assert stats.events_dispatched == 1
