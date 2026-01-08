"""
Token handlers for PolicyBind server.

This module provides handlers for access token management endpoints.
"""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import TokenError, ValidationError

logger = logging.getLogger("policybind.server.handlers.token")


async def list_tokens(request: "web.Request") -> "web.Response":
    """
    List access tokens.

    Query parameters:
        subject: Filter by subject
        status: Filter by status (active, suspended, revoked, expired)
        limit: Maximum results (default: 100)

    Returns:
        JSON response with token list.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    subject = request.query.get("subject")
    status = request.query.get("status")

    try:
        limit = int(request.query.get("limit", "100"))
    except ValueError:
        limit = 100

    try:
        tokens = token_manager.list_tokens(subject=subject, limit=limit)

        # Filter by status if specified
        if status:
            tokens = [t for t in tokens if _get_token_status(t) == status]

        results = [_token_to_summary(t) for t in tokens]

        return web.json_response({
            "tokens": results,
            "total": len(results),
        })

    except Exception as e:
        logger.exception(f"List tokens error: {e}")
        return web.json_response(
            {"error": {"type": "TokenError", "message": str(e)}},
            status=500,
        )


async def create_token(request: "web.Request") -> "web.Response":
    """
    Create a new access token.

    Request body:
        {
            "name": "My API Token",
            "subject": "user@example.com",
            "permissions": {...},
            "expires_in_days": 30,
            "metadata": {...}
        }

    Returns:
        JSON response with created token (including the token value).
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    # Validate required fields
    required = ["name", "subject"]
    missing = [f for f in required if f not in body]
    if missing:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": f"Missing fields: {missing}"}},
            status=400,
        )

    try:
        token = token_manager.create(
            name=body["name"],
            subject=body["subject"],
            permissions=body.get("permissions", {}),
            expires_in_days=body.get("expires_in_days"),
            metadata=body.get("metadata", {}),
        )

        return web.json_response({
            "token": _token_to_dict(token, include_value=True),
            "message": "Token created",
        }, status=201)

    except ValidationError as e:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": e.message, "details": e.details}},
            status=400,
        )
    except TokenError as e:
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Create token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def get_token(request: "web.Request") -> "web.Response":
    """
    Get token details.

    Path parameters:
        token_id: The token ID

    Returns:
        JSON response with token details (excluding the token value).
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    token_id = request.match_info["token_id"]

    try:
        token = token_manager.get(token_id)
        if not token:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Token not found: {token_id}"}},
                status=404,
            )

        return web.json_response({"token": _token_to_dict(token, include_value=False)})

    except Exception as e:
        logger.exception(f"Get token error: {e}")
        return web.json_response(
            {"error": {"type": "TokenError", "message": str(e)}},
            status=500,
        )


async def update_token(request: "web.Request") -> "web.Response":
    """
    Update a token.

    Path parameters:
        token_id: The token ID

    Request body:
        Fields to update (name, permissions, metadata)

    Returns:
        JSON response with updated token.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    token_id = request.match_info["token_id"]

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    try:
        # Update permissions if provided
        if "permissions" in body:
            token_manager.update_permissions(token_id, body["permissions"])

        token = token_manager.get(token_id)
        if not token:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Token not found: {token_id}"}},
                status=404,
            )

        return web.json_response({
            "token": _token_to_dict(token, include_value=False),
            "message": "Token updated",
        })

    except TokenError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Update token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def revoke_token(request: "web.Request") -> "web.Response":
    """
    Revoke a token.

    Path parameters:
        token_id: The token ID

    Returns:
        JSON response confirming revocation.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    token_id = request.match_info["token_id"]

    try:
        success = token_manager.revoke(token_id)
        if not success:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Token not found: {token_id}"}},
                status=404,
            )

        return web.json_response({"message": "Token revoked", "token_id": token_id})

    except TokenError as e:
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Revoke token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def validate_token(request: "web.Request") -> "web.Response":
    """
    Validate a token.

    Request body:
        {
            "token": "pb_..."
        }

    Returns:
        JSON response with validation result.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    token_value = body.get("token")
    if not token_value:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": "Token value required"}},
            status=400,
        )

    try:
        result = token_manager.validate(token_value)

        if result is None:
            return web.json_response({
                "valid": False,
                "reason": "Invalid or expired token",
            })

        return web.json_response({
            "valid": True,
            "token_id": result.get("token_id"),
            "subject": result.get("subject"),
            "permissions": result.get("permissions", {}),
            "expires_at": result.get("expires_at"),
        })

    except TokenError as e:
        return web.json_response({
            "valid": False,
            "reason": e.message,
        })
    except Exception as e:
        logger.exception(f"Validate token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def suspend_token(request: "web.Request") -> "web.Response":
    """
    Suspend a token.

    Path parameters:
        token_id: The token ID

    Returns:
        JSON response confirming suspension.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    token_id = request.match_info["token_id"]

    try:
        success = token_manager.suspend(token_id)
        if not success:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Token not found: {token_id}"}},
                status=404,
            )

        return web.json_response({"message": "Token suspended", "token_id": token_id})

    except TokenError as e:
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Suspend token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def unsuspend_token(request: "web.Request") -> "web.Response":
    """
    Unsuspend a token.

    Path parameters:
        token_id: The token ID

    Returns:
        JSON response confirming unsuspension.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    token_id = request.match_info["token_id"]

    try:
        success = token_manager.unsuspend(token_id)
        if not success:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Token not found: {token_id}"}},
                status=404,
            )

        return web.json_response({"message": "Token unsuspended", "token_id": token_id})

    except TokenError as e:
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Unsuspend token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def renew_token(request: "web.Request") -> "web.Response":
    """
    Renew a token's expiry.

    Path parameters:
        token_id: The token ID

    Request body:
        {
            "expires_in_days": 30
        }

    Returns:
        JSON response with renewed token.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    token_id = request.match_info["token_id"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    expires_in_days = body.get("expires_in_days", 30)

    try:
        token = token_manager.renew(token_id, expires_in_days=expires_in_days)
        if not token:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Token not found: {token_id}"}},
                status=404,
            )

        return web.json_response({
            "token": _token_to_dict(token, include_value=False),
            "message": "Token renewed",
        })

    except TokenError as e:
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Renew token error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def create_token_from_natural_language(request: "web.Request") -> "web.Response":
    """
    Create a token from a natural language description.

    This endpoint parses a natural language description of permissions
    and creates a token with the parsed constraints.

    Request body:
        {
            "name": "My API Token",
            "subject": "user@example.com",
            "description": "Allow GPT-4 with a budget of $100 per month"
        }

    Returns:
        JSON response with created token and parsing details.
    """
    from aiohttp import web

    token_manager = request.app.get("token_manager")
    if not token_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Token manager not configured"}},
            status=503,
        )

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    # Validate required fields
    required = ["name", "subject", "description"]
    missing = [f for f in required if f not in body]
    if missing:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": f"Missing fields: {missing}"}},
            status=400,
        )

    try:
        from policybind.tokens.natural_language import NaturalLanguageTokenParser

        # Parse the natural language description
        parser = NaturalLanguageTokenParser()
        parse_result = parser.parse(body["description"])

        # Create the token with parsed permissions
        token = token_manager.create(
            name=body["name"],
            subject=body["subject"],
            permissions=parse_result.permissions.to_dict() if parse_result.permissions else {},
            expires_in_days=body.get("expires_in_days"),
            metadata={
                "created_from": "natural_language",
                "original_description": body["description"],
                "parse_confidence": parse_result.overall_confidence.value,
            },
        )

        return web.json_response({
            "token": _token_to_dict(token, include_value=True),
            "parsing": {
                "constraints": [_serialize_constraint(c) for c in parse_result.constraints],
                "confidence": parse_result.overall_confidence.value,
                "warnings": parse_result.warnings,
                "suggestions": parse_result.suggestions,
                "unrecognized_parts": parse_result.unrecognized_parts,
            },
            "message": "Token created from natural language",
        }, status=201)

    except ValidationError as e:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": e.message, "details": e.details}},
            status=400,
        )
    except TokenError as e:
        return web.json_response(
            {"error": {"type": "TokenError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Create token from natural language error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def parse_natural_language(request: "web.Request") -> "web.Response":
    """
    Parse a natural language description without creating a token.

    This endpoint allows previewing how a description would be parsed
    before actually creating a token.

    Request body:
        {
            "description": "Allow GPT-4 with a budget of $100 per month"
        }

    Returns:
        JSON response with parsing result.
    """
    from aiohttp import web

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    description = body.get("description")
    if not description:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": "Description required"}},
            status=400,
        )

    try:
        from policybind.tokens.natural_language import NaturalLanguageTokenParser

        parser = NaturalLanguageTokenParser()
        parse_result = parser.parse(description)

        return web.json_response({
            "permissions": parse_result.permissions.to_dict() if parse_result.permissions else {},
            "constraints": [_serialize_constraint(c) for c in parse_result.constraints],
            "confidence": parse_result.overall_confidence.value,
            "warnings": parse_result.warnings,
            "suggestions": parse_result.suggestions,
            "unrecognized_parts": parse_result.unrecognized_parts,
        })

    except Exception as e:
        logger.exception(f"Parse natural language error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def list_templates(request: "web.Request") -> "web.Response":
    """
    List available token permission templates.

    Returns:
        JSON response with template list.
    """
    from aiohttp import web

    try:
        from policybind.tokens.templates import get_all_templates

        templates = get_all_templates()
        results = []
        for name, template in templates.items():
            results.append({
                "name": name,
                "description": template.description,
                "permissions": template.permissions,
            })

        return web.json_response({"templates": results, "total": len(results)})

    except Exception as e:
        logger.exception(f"List templates error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


def _token_to_dict(token: Any, include_value: bool = False) -> dict[str, Any]:
    """Convert a token to a dictionary."""
    result = {}

    if hasattr(token, "to_dict"):
        result = token.to_dict()
    else:
        result = {
            "token_id": getattr(token, "token_id", None),
            "name": getattr(token, "name", None),
            "subject": getattr(token, "subject", None),
            "permissions": getattr(token, "permissions", {}),
            "created_at": getattr(token, "created_at", None),
            "expires_at": getattr(token, "expires_at", None),
            "is_revoked": getattr(token, "is_revoked", False),
            "is_suspended": getattr(token, "is_suspended", False),
        }

    # Include token value only when explicitly requested (on creation)
    if include_value and hasattr(token, "token_value"):
        result["token_value"] = token.token_value

    # Remove token value if not requested
    if not include_value and "token_value" in result:
        del result["token_value"]

    return result


def _token_to_summary(token: Any) -> dict[str, Any]:
    """Convert a token to a summary dictionary."""
    return {
        "token_id": getattr(token, "token_id", None),
        "name": getattr(token, "name", None),
        "subject": getattr(token, "subject", None),
        "status": _get_token_status(token),
        "created_at": getattr(token, "created_at", None),
        "expires_at": getattr(token, "expires_at", None),
    }


def _get_token_status(token: Any) -> str:
    """Get the current status of a token."""
    if getattr(token, "is_revoked", False):
        return "revoked"
    if getattr(token, "is_suspended", False):
        return "suspended"
    if hasattr(token, "is_expired") and token.is_expired():
        return "expired"
    return "active"


def _serialize_constraint(constraint: Any) -> dict[str, Any]:
    """Serialize a constraint to JSON-safe dictionary."""
    from enum import Enum

    def _serialize_value(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {k: _serialize_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_serialize_value(v) for v in value]
        if hasattr(value, "to_dict"):
            return _serialize_value(value.to_dict())
        return value

    base_dict = constraint.to_dict() if hasattr(constraint, "to_dict") else dict(constraint)
    return {k: _serialize_value(v) for k, v in base_dict.items()}
