"""
Enforcement handlers for PolicyBind server.

This module provides the main enforcement endpoint handler.
"""

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import ValidationError
from policybind.models.request import AIRequest
from policybind.server.handlers.health_handlers import record_enforcement

logger = logging.getLogger("policybind.server.handlers.enforce")


async def enforce(request: "web.Request") -> "web.Response":
    """
    Submit a request for policy enforcement.

    Accepts an AIRequest as JSON and runs it through the enforcement
    pipeline, returning the enforcement decision.

    Request body:
        {
            "provider": "openai",
            "model": "gpt-4",
            "prompt_hash": "abc123...",
            "estimated_tokens": 1000,
            "user_id": "user@example.com",
            "department": "engineering",
            "data_classification": ["internal"],
            "intended_use_case": "code_review",
            ...
        }

    Returns:
        JSON response with enforcement decision:
        {
            "request_id": "...",
            "decision": "ALLOW|DENY|MODIFY",
            "reason": "...",
            "applied_rules": [...],
            "warnings": [...],
            "modifications": {...},
            "enforcement_time_ms": 5.2
        }
    """
    from aiohttp import web

    start_time = time.perf_counter()

    # Get the enforcement pipeline
    pipeline = request.app.get("pipeline")
    if not pipeline:
        return web.json_response(
            {
                "error": {
                    "type": "ServiceUnavailable",
                    "message": "Enforcement pipeline not configured",
                }
            },
            status=503,
        )

    try:
        # Parse request body
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {
                "error": {
                    "type": "InvalidRequest",
                    "message": f"Invalid JSON body: {e}",
                }
            },
            status=400,
        )

    try:
        # Create AIRequest from body
        ai_request = _parse_ai_request(body)
    except ValidationError as e:
        return web.json_response(
            {
                "error": {
                    "type": "ValidationError",
                    "message": e.message,
                    "details": e.details,
                }
            },
            status=400,
        )
    except Exception as e:
        return web.json_response(
            {
                "error": {
                    "type": "InvalidRequest",
                    "message": f"Failed to parse request: {e}",
                }
            },
            status=400,
        )

    try:
        # Process through enforcement pipeline
        response = pipeline.process(ai_request)

        enforcement_time_ms = (time.perf_counter() - start_time) * 1000
        record_enforcement(enforcement_time_ms)

        # Build response
        result = {
            "request_id": response.request_id,
            "decision": response.decision.value,
            "reason": response.reason,
            "applied_rules": list(response.applied_rules),
            "warnings": list(response.warnings),
            "modifications": response.modifications,
            "enforcement_time_ms": round(enforcement_time_ms, 2),
        }

        # Add estimated cost if available
        if response.estimated_cost is not None:
            result["estimated_cost"] = response.estimated_cost

        return web.json_response(result)

    except Exception as e:
        logger.exception(f"Enforcement error: {e}")
        return web.json_response(
            {
                "error": {
                    "type": "EnforcementError",
                    "message": f"Enforcement failed: {e}",
                }
            },
            status=500,
        )


def _parse_ai_request(body: dict[str, Any]) -> AIRequest:
    """
    Parse an AIRequest from a JSON body.

    Args:
        body: The parsed JSON request body.

    Returns:
        AIRequest instance.

    Raises:
        ValidationError: If required fields are missing or invalid.
    """
    # Check required fields
    required_fields = ["provider", "model"]
    missing = [f for f in required_fields if f not in body]
    if missing:
        raise ValidationError(
            f"Missing required fields: {', '.join(missing)}",
            {"missing_fields": missing},
        )

    # Build AIRequest
    return AIRequest(
        request_id=body.get("request_id"),
        provider=body["provider"],
        model=body["model"],
        prompt_hash=body.get("prompt_hash", ""),
        estimated_tokens=body.get("estimated_tokens", 0),
        estimated_cost=body.get("estimated_cost"),
        source_application=body.get("source_application", ""),
        user_id=body.get("user_id", ""),
        department=body.get("department", ""),
        data_classification=tuple(body.get("data_classification", [])),
        intended_use_case=body.get("intended_use_case", ""),
        metadata=body.get("metadata", {}),
    )
