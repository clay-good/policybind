"""
Policy handlers for PolicyBind server.

This module provides handlers for policy management endpoints.
"""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import ValidationError
from policybind.models.request import AIRequest

logger = logging.getLogger("policybind.server.handlers.policy")


async def list_policies(request: "web.Request") -> "web.Response":
    """
    List current policies.

    Returns a summary of all loaded policies including rule counts
    and metadata.

    Returns:
        JSON response with policy summary.
    """
    from aiohttp import web

    policy_set = request.app.get("policy_set")
    if not policy_set:
        return web.json_response(
            {"policies": [], "total": 0, "version": None},
        )

    # Build policy summary
    rules_summary = []
    for rule in policy_set.rules:
        rules_summary.append({
            "name": rule.name,
            "description": rule.description,
            "action": rule.action,
            "priority": rule.priority,
            "enabled": rule.enabled,
            "tags": list(rule.tags),
        })

    return web.json_response({
        "policies": rules_summary,
        "total": len(rules_summary),
        "version": policy_set.version,
        "name": policy_set.name,
        "metadata": policy_set.metadata,
    })


async def get_policy_version(request: "web.Request") -> "web.Response":
    """
    Get current policy version information.

    Returns:
        JSON response with version details.
    """
    from aiohttp import web

    policy_set = request.app.get("policy_set")
    versioning = request.app.get("versioning")

    result: dict[str, Any] = {
        "version": None,
        "loaded_at": None,
        "rule_count": 0,
    }

    if policy_set:
        result["version"] = policy_set.version
        result["rule_count"] = len(policy_set.rules)
        result["name"] = policy_set.name

    if versioning:
        current = versioning.get_current_version()
        if current:
            result["version_id"] = current.version_id
            result["loaded_at"] = current.timestamp.isoformat()
            result["checksum"] = current.checksum

    return web.json_response(result)


async def get_policy_history(request: "web.Request") -> "web.Response":
    """
    Get policy version history.

    Query parameters:
        limit: Maximum number of versions to return (default: 20)

    Returns:
        JSON response with version history.
    """
    from aiohttp import web

    versioning = request.app.get("versioning")
    if not versioning:
        return web.json_response({"versions": [], "total": 0})

    # Get limit from query params
    try:
        limit = int(request.query.get("limit", "20"))
    except ValueError:
        limit = 20

    history = versioning.get_history(limit=limit)

    versions = []
    for version in history:
        versions.append({
            "version_id": version.version_id,
            "version": version.version,
            "timestamp": version.timestamp.isoformat(),
            "checksum": version.checksum,
            "rule_count": version.rule_count,
            "source": version.source,
            "metadata": version.metadata,
        })

    return web.json_response({
        "versions": versions,
        "total": len(versions),
    })


async def reload_policies(request: "web.Request") -> "web.Response":
    """
    Trigger policy reload.

    This endpoint triggers an immediate reload of policies from
    the configured source. Requires admin role.

    Returns:
        JSON response with reload result.
    """
    from aiohttp import web

    reloader = request.app.get("reloader")
    if not reloader:
        return web.json_response(
            {
                "error": {
                    "type": "ServiceUnavailable",
                    "message": "Policy reloader not configured",
                }
            },
            status=503,
        )

    try:
        # Trigger reload
        success = reloader.reload()

        if success:
            # Update app's policy set reference
            policy_set = reloader.get_current_policy_set()
            if policy_set:
                request.app["policy_set"] = policy_set

                # Update pipeline if it exists
                pipeline = request.app.get("pipeline")
                if pipeline:
                    pipeline.update_policy_set(policy_set)

            return web.json_response({
                "status": "success",
                "message": "Policies reloaded successfully",
                "version": policy_set.version if policy_set else None,
                "rule_count": len(policy_set.rules) if policy_set else 0,
            })
        else:
            return web.json_response(
                {
                    "status": "failed",
                    "message": "Policy reload failed",
                },
                status=500,
            )

    except Exception as e:
        logger.exception(f"Policy reload error: {e}")
        return web.json_response(
            {
                "error": {
                    "type": "ReloadError",
                    "message": f"Failed to reload policies: {e}",
                }
            },
            status=500,
        )


async def test_policy(request: "web.Request") -> "web.Response":
    """
    Test a request against policies without logging.

    This endpoint allows testing how a request would be evaluated
    without actually logging the enforcement or affecting quotas.

    Request body:
        {
            "provider": "openai",
            "model": "gpt-4",
            ...
        }

    Returns:
        JSON response with test result.
    """
    from aiohttp import web

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
        # Create test request
        ai_request = _parse_test_request(body)

        # Get policy matches without full enforcement
        matcher = request.app.get("matcher")
        policy_set = request.app.get("policy_set")

        if not matcher or not policy_set:
            return web.json_response(
                {
                    "error": {
                        "type": "ServiceUnavailable",
                        "message": "Policy matcher not configured",
                    }
                },
                status=503,
            )

        # Find matching rules
        matches = matcher.match(ai_request, policy_set)

        # Build response
        matched_rules = []
        for match in matches:
            matched_rules.append({
                "rule_name": match.rule.name if match.rule else None,
                "action": match.rule.action if match.rule else None,
                "score": match.score,
                "matched_conditions": match.matched_conditions,
            })

        # Determine what the decision would be
        if matches and matches[0].rule:
            top_rule = matches[0].rule
            decision = top_rule.action
            reason = f"Matched rule: {top_rule.name}"
        else:
            # Use default action from config
            config = request.app.get("config")
            default_action = "DENY"
            if config:
                default_action = config.enforcement.default_action.upper()
            decision = default_action
            reason = "No matching rules, using default action"

        return web.json_response({
            "test_mode": True,
            "decision": decision,
            "reason": reason,
            "matched_rules": matched_rules,
            "total_matches": len(matches),
        })

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
        logger.exception(f"Policy test error: {e}")
        return web.json_response(
            {
                "error": {
                    "type": "TestError",
                    "message": f"Policy test failed: {e}",
                }
            },
            status=500,
        )


def _parse_test_request(body: dict[str, Any]) -> AIRequest:
    """
    Parse a test AIRequest from a JSON body.

    Args:
        body: The parsed JSON request body.

    Returns:
        AIRequest instance.

    Raises:
        ValidationError: If required fields are missing.
    """
    required_fields = ["provider", "model"]
    missing = [f for f in required_fields if f not in body]
    if missing:
        raise ValidationError(
            f"Missing required fields: {', '.join(missing)}",
            {"missing_fields": missing},
        )

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
