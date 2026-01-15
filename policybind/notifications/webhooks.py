"""
Webhook delivery system for PolicyBind.

This module provides a robust webhook delivery system with:
- Configurable webhook endpoints
- Retry logic with exponential backoff
- HMAC signature verification
- Delivery tracking and history
- Event filtering by type
"""

import hashlib
import hmac
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, utc_now

logger = logging.getLogger("policybind.notifications.webhooks")


class WebhookEventType(Enum):
    """Types of webhook events."""

    # Incident events
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_ASSIGNED = "incident.assigned"
    INCIDENT_ESCALATED = "incident.escalated"
    INCIDENT_RESOLVED = "incident.resolved"
    INCIDENT_CLOSED = "incident.closed"

    # Approval workflow events
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_STEP_COMPLETED = "approval.step_completed"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_ESCALATED = "approval.escalated"
    APPROVAL_DELEGATED = "approval.delegated"

    # Review workflow events
    REVIEW_DUE = "review.due"
    REVIEW_OVERDUE = "review.overdue"
    REVIEW_COMPLETED = "review.completed"

    # Suspension events
    DEPLOYMENT_SUSPENDED = "deployment.suspended"
    DEPLOYMENT_REINSTATED = "deployment.reinstated"
    REINSTATEMENT_REQUESTED = "reinstatement.requested"
    REINSTATEMENT_DENIED = "reinstatement.denied"

    # Registry events
    DEPLOYMENT_REGISTERED = "deployment.registered"
    DEPLOYMENT_UPDATED = "deployment.updated"
    DEPLOYMENT_DELETED = "deployment.deleted"

    # Policy events
    POLICY_VIOLATION = "policy.violation"
    POLICY_RELOADED = "policy.reloaded"

    # Token events
    TOKEN_CREATED = "token.created"
    TOKEN_REVOKED = "token.revoked"
    TOKEN_EXPIRED = "token.expired"

    # System events
    SLA_BREACH = "sla.breach"
    SYSTEM_ALERT = "system.alert"


class WebhookDeliveryStatus(Enum):
    """Status of a webhook delivery attempt."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class WebhookConfig:
    """
    Configuration for a webhook endpoint.

    Attributes:
        webhook_id: Unique identifier for this webhook.
        name: Human-readable name.
        url: The endpoint URL to send events to.
        secret: Secret key for HMAC signature (optional).
        enabled: Whether this webhook is active.
        event_types: Set of event types to send (empty = all).
        headers: Additional headers to include.
        timeout_seconds: Request timeout.
        max_retries: Maximum retry attempts.
        retry_delay_seconds: Initial retry delay (exponential backoff).
        created_at: When the webhook was configured.
        metadata: Additional configuration metadata.
    """

    webhook_id: str = field(default_factory=generate_uuid)
    name: str = ""
    url: str = ""
    secret: str = ""
    enabled: bool = True
    event_types: set[WebhookEventType] = field(default_factory=set)
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay_seconds: int = 5
    created_at: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def should_receive(self, event_type: WebhookEventType) -> bool:
        """Check if this webhook should receive the given event type."""
        if not self.enabled:
            return False
        if not self.event_types:
            # Empty set means all events
            return True
        return event_type in self.event_types

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes secret)."""
        return {
            "webhook_id": self.webhook_id,
            "name": self.name,
            "url": self.url,
            "enabled": self.enabled,
            "event_types": [e.value for e in self.event_types],
            "headers": {k: v for k, v in self.headers.items() if not k.lower().startswith("authorization")},
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "retry_delay_seconds": self.retry_delay_seconds,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WebhookConfig":
        """Create from dictionary."""
        event_types = set()
        for et in data.get("event_types", []):
            try:
                event_types.add(WebhookEventType(et))
            except ValueError:
                pass

        return cls(
            webhook_id=data.get("webhook_id", generate_uuid()),
            name=data.get("name", ""),
            url=data.get("url", ""),
            secret=data.get("secret", ""),
            enabled=data.get("enabled", True),
            event_types=event_types,
            headers=data.get("headers", {}),
            timeout_seconds=data.get("timeout_seconds", 30),
            max_retries=data.get("max_retries", 3),
            retry_delay_seconds=data.get("retry_delay_seconds", 5),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else utc_now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class WebhookEvent:
    """
    A webhook event to be delivered.

    Attributes:
        event_id: Unique identifier for this event.
        event_type: Type of event.
        payload: Event data payload.
        created_at: When the event was created.
        source: Source of the event (e.g., "incident_manager").
    """

    event_id: str = field(default_factory=generate_uuid)
    event_type: WebhookEventType = WebhookEventType.SYSTEM_ALERT
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
            "source": self.source,
        }


@dataclass
class WebhookDelivery:
    """
    Record of a webhook delivery attempt.

    Attributes:
        delivery_id: Unique identifier.
        webhook_id: ID of the target webhook.
        event_id: ID of the event being delivered.
        status: Current delivery status.
        attempt_count: Number of delivery attempts.
        last_attempt_at: When the last attempt was made.
        next_retry_at: When the next retry is scheduled.
        response_status: HTTP status code from last attempt.
        response_body: Response body from last attempt.
        error: Error message if failed.
        created_at: When the delivery was created.
    """

    delivery_id: str = field(default_factory=generate_uuid)
    webhook_id: str = ""
    event_id: str = ""
    status: WebhookDeliveryStatus = WebhookDeliveryStatus.PENDING
    attempt_count: int = 0
    last_attempt_at: datetime | None = None
    next_retry_at: datetime | None = None
    response_status: int | None = None
    response_body: str = ""
    error: str = ""
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "delivery_id": self.delivery_id,
            "webhook_id": self.webhook_id,
            "event_id": self.event_id,
            "status": self.status.value,
            "attempt_count": self.attempt_count,
            "last_attempt_at": self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            "next_retry_at": self.next_retry_at.isoformat() if self.next_retry_at else None,
            "response_status": self.response_status,
            "response_body": self.response_body[:500] if self.response_body else "",
            "error": self.error,
            "created_at": self.created_at.isoformat(),
        }


class WebhookManager:
    """
    Manages webhook configurations and event delivery.

    The WebhookManager handles:
    - Webhook endpoint configuration
    - Event dispatching to matching webhooks
    - Delivery with retry logic
    - HMAC signature generation
    - Delivery history tracking

    Example:
        Setting up webhooks::

            manager = WebhookManager()

            # Register a webhook
            config = WebhookConfig(
                name="Slack Alerts",
                url="https://hooks.slack.com/services/...",
                event_types={WebhookEventType.INCIDENT_CREATED},
            )
            manager.register_webhook(config)

            # Dispatch an event
            event = WebhookEvent(
                event_type=WebhookEventType.INCIDENT_CREATED,
                payload={"incident_id": "inc-123", "severity": "high"},
            )
            manager.dispatch(event)
    """

    # Maximum number of deliveries to keep in history
    MAX_DELIVERY_HISTORY = 1000

    def __init__(self) -> None:
        """Initialize the webhook manager."""
        self._webhooks: dict[str, WebhookConfig] = {}
        self._deliveries: deque[WebhookDelivery] = deque(maxlen=self.MAX_DELIVERY_HISTORY)
        self._events: dict[str, WebhookEvent] = {}
        self._lock = threading.RLock()

    def register_webhook(self, config: WebhookConfig) -> None:
        """
        Register a webhook configuration.

        Args:
            config: The webhook configuration.
        """
        with self._lock:
            self._webhooks[config.webhook_id] = config
            logger.info(f"Registered webhook: {config.name} ({config.webhook_id})")

    def unregister_webhook(self, webhook_id: str) -> bool:
        """
        Unregister a webhook.

        Args:
            webhook_id: ID of the webhook to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if webhook_id in self._webhooks:
                del self._webhooks[webhook_id]
                logger.info(f"Unregistered webhook: {webhook_id}")
                return True
            return False

    def get_webhook(self, webhook_id: str) -> WebhookConfig | None:
        """Get a webhook configuration by ID."""
        return self._webhooks.get(webhook_id)

    def list_webhooks(self) -> list[WebhookConfig]:
        """List all registered webhooks."""
        return list(self._webhooks.values())

    def update_webhook(self, webhook_id: str, updates: dict[str, Any]) -> WebhookConfig | None:
        """
        Update a webhook configuration.

        Args:
            webhook_id: ID of the webhook to update.
            updates: Dictionary of fields to update.

        Returns:
            Updated config or None if not found.
        """
        with self._lock:
            config = self._webhooks.get(webhook_id)
            if not config:
                return None

            # Apply updates
            if "name" in updates:
                config.name = updates["name"]
            if "url" in updates:
                config.url = updates["url"]
            if "secret" in updates:
                config.secret = updates["secret"]
            if "enabled" in updates:
                config.enabled = updates["enabled"]
            if "event_types" in updates:
                config.event_types = {
                    WebhookEventType(et) for et in updates["event_types"]
                }
            if "headers" in updates:
                config.headers = updates["headers"]
            if "timeout_seconds" in updates:
                config.timeout_seconds = updates["timeout_seconds"]
            if "max_retries" in updates:
                config.max_retries = updates["max_retries"]
            if "retry_delay_seconds" in updates:
                config.retry_delay_seconds = updates["retry_delay_seconds"]

            logger.info(f"Updated webhook: {webhook_id}")
            return config

    def enable_webhook(self, webhook_id: str) -> bool:
        """Enable a webhook."""
        config = self._webhooks.get(webhook_id)
        if config:
            config.enabled = True
            return True
        return False

    def disable_webhook(self, webhook_id: str) -> bool:
        """Disable a webhook."""
        config = self._webhooks.get(webhook_id)
        if config:
            config.enabled = False
            return True
        return False

    def dispatch(self, event: WebhookEvent) -> list[WebhookDelivery]:
        """
        Dispatch an event to all matching webhooks.

        Args:
            event: The event to dispatch.

        Returns:
            List of delivery records.
        """
        with self._lock:
            self._events[event.event_id] = event

        deliveries = []
        for config in self._webhooks.values():
            if config.should_receive(event.event_type):
                delivery = self._deliver(config, event)
                deliveries.append(delivery)

        return deliveries

    def dispatch_to_webhook(
        self,
        webhook_id: str,
        event: WebhookEvent,
    ) -> WebhookDelivery | None:
        """
        Dispatch an event to a specific webhook.

        Args:
            webhook_id: ID of the webhook.
            event: The event to dispatch.

        Returns:
            Delivery record or None if webhook not found.
        """
        config = self._webhooks.get(webhook_id)
        if not config:
            return None

        with self._lock:
            self._events[event.event_id] = event

        return self._deliver(config, event)

    def _deliver(self, config: WebhookConfig, event: WebhookEvent) -> WebhookDelivery:
        """Attempt to deliver an event to a webhook."""
        delivery = WebhookDelivery(
            webhook_id=config.webhook_id,
            event_id=event.event_id,
        )

        with self._lock:
            self._deliveries.append(delivery)

        self._attempt_delivery(config, event, delivery)
        return delivery

    def _attempt_delivery(
        self,
        config: WebhookConfig,
        event: WebhookEvent,
        delivery: WebhookDelivery,
    ) -> None:
        """Make a delivery attempt with retry logic."""
        while delivery.attempt_count < config.max_retries:
            delivery.attempt_count += 1
            delivery.last_attempt_at = utc_now()

            try:
                response_status, response_body = self._send_request(config, event)
                delivery.response_status = response_status
                delivery.response_body = response_body

                if 200 <= response_status < 300:
                    delivery.status = WebhookDeliveryStatus.DELIVERED
                    logger.info(
                        f"Webhook delivered: {config.name} event={event.event_type.value}"
                    )
                    return
                else:
                    delivery.error = f"HTTP {response_status}"
                    logger.warning(
                        f"Webhook failed: {config.name} status={response_status}"
                    )

            except urllib.error.URLError as e:
                delivery.error = str(e.reason)
                logger.warning(f"Webhook error: {config.name} error={e.reason}")

            except Exception as e:
                delivery.error = str(e)
                logger.warning(f"Webhook error: {config.name} error={e}")

            # Check if we should retry
            if delivery.attempt_count < config.max_retries:
                delivery.status = WebhookDeliveryStatus.RETRYING
                delay = config.retry_delay_seconds * (2 ** (delivery.attempt_count - 1))
                delivery.next_retry_at = utc_now() + timedelta(seconds=delay)
                time.sleep(delay)
            else:
                delivery.status = WebhookDeliveryStatus.FAILED
                logger.error(
                    f"Webhook delivery failed after {delivery.attempt_count} attempts: "
                    f"{config.name} event={event.event_type.value}"
                )

    def _send_request(
        self,
        config: WebhookConfig,
        event: WebhookEvent,
    ) -> tuple[int, str]:
        """Send the HTTP request to the webhook endpoint."""
        payload = event.to_dict()
        data = json.dumps(payload, default=str).encode("utf-8")

        # Build headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PolicyBind-Webhook/1.0",
            "X-PolicyBind-Event": event.event_type.value,
            "X-PolicyBind-Event-ID": event.event_id,
            "X-PolicyBind-Timestamp": event.created_at.isoformat(),
        }

        # Add HMAC signature if secret is configured
        if config.secret:
            signature = self._compute_signature(config.secret, data)
            headers["X-PolicyBind-Signature"] = f"sha256={signature}"

        # Add custom headers
        headers.update(config.headers)

        request = urllib.request.Request(
            config.url,
            data=data,
            headers=headers,
            method="POST",
        )

        with urllib.request.urlopen(
            request, timeout=config.timeout_seconds
        ) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return response.status, response_body

    def _compute_signature(self, secret: str, data: bytes) -> str:
        """Compute HMAC-SHA256 signature for the payload."""
        return hmac.new(
            secret.encode("utf-8"),
            data,
            hashlib.sha256,
        ).hexdigest()

    def verify_signature(
        self,
        secret: str,
        payload: bytes,
        signature: str,
    ) -> bool:
        """
        Verify a webhook signature.

        This can be used by receiving applications to verify
        that a webhook payload was sent by PolicyBind.

        Args:
            secret: The shared secret.
            payload: The raw request body.
            signature: The signature from X-PolicyBind-Signature header.

        Returns:
            True if signature is valid.
        """
        if signature.startswith("sha256="):
            signature = signature[7:]

        expected = self._compute_signature(secret, payload)
        return hmac.compare_digest(expected, signature)

    def get_deliveries(
        self,
        webhook_id: str | None = None,
        event_id: str | None = None,
        status: WebhookDeliveryStatus | None = None,
        limit: int = 100,
    ) -> list[WebhookDelivery]:
        """
        Get delivery history with optional filtering.

        Args:
            webhook_id: Filter by webhook ID.
            event_id: Filter by event ID.
            status: Filter by status.
            limit: Maximum number to return.

        Returns:
            List of matching deliveries.
        """
        results = []
        for delivery in reversed(self._deliveries):
            if webhook_id and delivery.webhook_id != webhook_id:
                continue
            if event_id and delivery.event_id != event_id:
                continue
            if status and delivery.status != status:
                continue
            results.append(delivery)
            if len(results) >= limit:
                break
        return results

    def get_delivery_stats(self) -> dict[str, Any]:
        """Get delivery statistics."""
        by_status: dict[str, int] = {}
        by_webhook: dict[str, dict[str, int]] = {}

        for delivery in self._deliveries:
            status = delivery.status.value
            by_status[status] = by_status.get(status, 0) + 1

            if delivery.webhook_id not in by_webhook:
                by_webhook[delivery.webhook_id] = {}
            by_webhook[delivery.webhook_id][status] = (
                by_webhook[delivery.webhook_id].get(status, 0) + 1
            )

        return {
            "total_deliveries": len(self._deliveries),
            "by_status": by_status,
            "by_webhook": by_webhook,
        }

    def retry_failed(self, webhook_id: str | None = None) -> list[WebhookDelivery]:
        """
        Retry failed deliveries.

        Args:
            webhook_id: Optionally filter to a specific webhook.

        Returns:
            List of retried deliveries.
        """
        retried = []
        for delivery in list(self._deliveries):
            if delivery.status != WebhookDeliveryStatus.FAILED:
                continue
            if webhook_id and delivery.webhook_id != webhook_id:
                continue

            config = self._webhooks.get(delivery.webhook_id)
            event = self._events.get(delivery.event_id)

            if config and event:
                # Reset for retry
                delivery.attempt_count = 0
                delivery.status = WebhookDeliveryStatus.PENDING
                delivery.error = ""

                self._attempt_delivery(config, event, delivery)
                retried.append(delivery)

        return retried

    def test_webhook(self, webhook_id: str) -> WebhookDelivery | None:
        """
        Send a test event to a webhook.

        Args:
            webhook_id: ID of the webhook to test.

        Returns:
            Delivery record or None if webhook not found.
        """
        config = self._webhooks.get(webhook_id)
        if not config:
            return None

        event = WebhookEvent(
            event_type=WebhookEventType.SYSTEM_ALERT,
            payload={
                "message": "This is a test webhook from PolicyBind",
                "webhook_id": webhook_id,
                "webhook_name": config.name,
            },
            source="webhook_test",
        )

        return self._deliver(config, event)
