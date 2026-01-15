"""
Webhook API handlers for PolicyBind.

This module provides HTTP handlers for webhook configuration
and management endpoints.
"""

import json
import logging
from typing import TYPE_CHECKING, Any

from policybind.notifications.webhooks import (
    WebhookConfig,
    WebhookDeliveryStatus,
    WebhookEventType,
    WebhookManager,
)

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.webhook")

# Global webhook manager instance
_webhook_manager: WebhookManager | None = None


def get_webhook_manager() -> WebhookManager:
    """Get or create the global webhook manager."""
    global _webhook_manager
    if _webhook_manager is None:
        _webhook_manager = WebhookManager()
    return _webhook_manager


def set_webhook_manager(manager: WebhookManager) -> None:
    """Set the global webhook manager (for testing)."""
    global _webhook_manager
    _webhook_manager = manager


async def list_webhooks(request: "web.Request") -> "web.Response":
    """
    List all configured webhooks.

    GET /v1/webhooks

    Returns:
        JSON array of webhook configurations.
    """
    from aiohttp import web

    manager = get_webhook_manager()
    webhooks = manager.list_webhooks()

    return web.json_response({
        "webhooks": [w.to_dict() for w in webhooks],
        "total": len(webhooks),
    })


async def create_webhook(request: "web.Request") -> "web.Response":
    """
    Create a new webhook configuration.

    POST /v1/webhooks

    Body:
        {
            "name": "My Webhook",
            "url": "https://example.com/webhook",
            "secret": "optional-secret",
            "event_types": ["incident.created", "approval.granted"],
            "headers": {"Authorization": "Bearer token"},
            "enabled": true
        }

    Returns:
        Created webhook configuration.
    """
    from aiohttp import web

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Validate required fields
    if not data.get("name"):
        return web.json_response(
            {"error": "name is required"},
            status=400,
        )
    if not data.get("url"):
        return web.json_response(
            {"error": "url is required"},
            status=400,
        )

    # Validate URL format
    url = data["url"]
    if not url.startswith(("http://", "https://")):
        return web.json_response(
            {"error": "url must be an HTTP or HTTPS URL"},
            status=400,
        )

    # Parse event types
    event_types: set[WebhookEventType] = set()
    for et in data.get("event_types", []):
        try:
            event_types.add(WebhookEventType(et))
        except ValueError:
            return web.json_response(
                {"error": f"Invalid event type: {et}"},
                status=400,
            )

    config = WebhookConfig(
        name=data["name"],
        url=url,
        secret=data.get("secret", ""),
        enabled=data.get("enabled", True),
        event_types=event_types,
        headers=data.get("headers", {}),
        timeout_seconds=data.get("timeout_seconds", 30),
        max_retries=data.get("max_retries", 3),
        retry_delay_seconds=data.get("retry_delay_seconds", 5),
        metadata=data.get("metadata", {}),
    )

    manager = get_webhook_manager()
    manager.register_webhook(config)

    logger.info(f"Created webhook: {config.name} ({config.webhook_id})")

    return web.json_response(
        {"webhook": config.to_dict()},
        status=201,
    )


async def get_webhook(request: "web.Request") -> "web.Response":
    """
    Get a webhook configuration by ID.

    GET /v1/webhooks/{webhook_id}

    Returns:
        Webhook configuration.
    """
    from aiohttp import web

    webhook_id = request.match_info["webhook_id"]
    manager = get_webhook_manager()
    config = manager.get_webhook(webhook_id)

    if not config:
        return web.json_response(
            {"error": f"Webhook not found: {webhook_id}"},
            status=404,
        )

    return web.json_response({"webhook": config.to_dict()})


async def update_webhook(request: "web.Request") -> "web.Response":
    """
    Update a webhook configuration.

    PUT /v1/webhooks/{webhook_id}

    Body:
        Partial webhook configuration to update.

    Returns:
        Updated webhook configuration.
    """
    from aiohttp import web

    webhook_id = request.match_info["webhook_id"]

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    manager = get_webhook_manager()

    # Validate event types if provided
    if "event_types" in data:
        event_types = []
        for et in data["event_types"]:
            try:
                event_types.append(WebhookEventType(et).value)
            except ValueError:
                return web.json_response(
                    {"error": f"Invalid event type: {et}"},
                    status=400,
                )
        data["event_types"] = event_types

    config = manager.update_webhook(webhook_id, data)

    if not config:
        return web.json_response(
            {"error": f"Webhook not found: {webhook_id}"},
            status=404,
        )

    logger.info(f"Updated webhook: {webhook_id}")

    return web.json_response({"webhook": config.to_dict()})


async def delete_webhook(request: "web.Request") -> "web.Response":
    """
    Delete a webhook configuration.

    DELETE /v1/webhooks/{webhook_id}

    Returns:
        Success message.
    """
    from aiohttp import web

    webhook_id = request.match_info["webhook_id"]
    manager = get_webhook_manager()

    if manager.unregister_webhook(webhook_id):
        logger.info(f"Deleted webhook: {webhook_id}")
        return web.json_response({"message": "Webhook deleted"})
    else:
        return web.json_response(
            {"error": f"Webhook not found: {webhook_id}"},
            status=404,
        )


async def enable_webhook(request: "web.Request") -> "web.Response":
    """
    Enable a webhook.

    POST /v1/webhooks/{webhook_id}/enable

    Returns:
        Success message.
    """
    from aiohttp import web

    webhook_id = request.match_info["webhook_id"]
    manager = get_webhook_manager()

    if manager.enable_webhook(webhook_id):
        logger.info(f"Enabled webhook: {webhook_id}")
        return web.json_response({"message": "Webhook enabled"})
    else:
        return web.json_response(
            {"error": f"Webhook not found: {webhook_id}"},
            status=404,
        )


async def disable_webhook(request: "web.Request") -> "web.Response":
    """
    Disable a webhook.

    POST /v1/webhooks/{webhook_id}/disable

    Returns:
        Success message.
    """
    from aiohttp import web

    webhook_id = request.match_info["webhook_id"]
    manager = get_webhook_manager()

    if manager.disable_webhook(webhook_id):
        logger.info(f"Disabled webhook: {webhook_id}")
        return web.json_response({"message": "Webhook disabled"})
    else:
        return web.json_response(
            {"error": f"Webhook not found: {webhook_id}"},
            status=404,
        )


async def test_webhook(request: "web.Request") -> "web.Response":
    """
    Send a test event to a webhook.

    POST /v1/webhooks/{webhook_id}/test

    Returns:
        Delivery result.
    """
    from aiohttp import web

    webhook_id = request.match_info["webhook_id"]
    manager = get_webhook_manager()

    delivery = manager.test_webhook(webhook_id)

    if not delivery:
        return web.json_response(
            {"error": f"Webhook not found: {webhook_id}"},
            status=404,
        )

    return web.json_response({
        "delivery": delivery.to_dict(),
        "success": delivery.status == WebhookDeliveryStatus.DELIVERED,
    })


async def list_webhook_deliveries(request: "web.Request") -> "web.Response":
    """
    List webhook deliveries.

    GET /v1/webhooks/deliveries

    Query params:
        webhook_id: Filter by webhook ID
        status: Filter by status (pending, delivered, failed, retrying)
        limit: Maximum number to return (default 100)

    Returns:
        JSON array of delivery records.
    """
    from aiohttp import web

    manager = get_webhook_manager()

    webhook_id = request.query.get("webhook_id")
    status_str = request.query.get("status")
    limit = int(request.query.get("limit", "100"))

    status = None
    if status_str:
        try:
            status = WebhookDeliveryStatus(status_str)
        except ValueError:
            return web.json_response(
                {"error": f"Invalid status: {status_str}"},
                status=400,
            )

    deliveries = manager.get_deliveries(
        webhook_id=webhook_id,
        status=status,
        limit=limit,
    )

    return web.json_response({
        "deliveries": [d.to_dict() for d in deliveries],
        "total": len(deliveries),
    })


async def get_webhook_stats(request: "web.Request") -> "web.Response":
    """
    Get webhook delivery statistics.

    GET /v1/webhooks/stats

    Returns:
        Delivery statistics.
    """
    from aiohttp import web

    manager = get_webhook_manager()
    stats = manager.get_delivery_stats()

    return web.json_response({"stats": stats})


async def retry_failed_deliveries(request: "web.Request") -> "web.Response":
    """
    Retry failed webhook deliveries.

    POST /v1/webhooks/retry

    Query params:
        webhook_id: Optionally filter to a specific webhook

    Returns:
        List of retried deliveries.
    """
    from aiohttp import web

    manager = get_webhook_manager()
    webhook_id = request.query.get("webhook_id")

    retried = manager.retry_failed(webhook_id=webhook_id)

    return web.json_response({
        "retried": [d.to_dict() for d in retried],
        "count": len(retried),
    })


async def list_event_types(request: "web.Request") -> "web.Response":
    """
    List all available webhook event types.

    GET /v1/webhooks/event-types

    Returns:
        JSON array of event type names and descriptions.
    """
    from aiohttp import web

    event_types = []
    for et in WebhookEventType:
        # Parse category from event type value
        parts = et.value.split(".")
        category = parts[0] if parts else "unknown"

        event_types.append({
            "type": et.value,
            "category": category,
            "name": et.name,
        })

    return web.json_response({
        "event_types": event_types,
        "total": len(event_types),
    })
