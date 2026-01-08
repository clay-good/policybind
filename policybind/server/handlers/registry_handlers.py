"""
Registry handlers for PolicyBind server.

This module provides handlers for model registry management endpoints.
"""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import RegistryError, ValidationError

logger = logging.getLogger("policybind.server.handlers.registry")


async def list_deployments(request: "web.Request") -> "web.Response":
    """
    List model deployments.

    Query parameters:
        status: Filter by approval status
        risk_level: Filter by risk level
        provider: Filter by provider
        limit: Maximum results (default: 100)
        offset: Pagination offset (default: 0)

    Returns:
        JSON response with deployment list.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    # Parse query parameters
    status = request.query.get("status")
    risk_level = request.query.get("risk_level")
    provider = request.query.get("provider")

    try:
        limit = int(request.query.get("limit", "100"))
        offset = int(request.query.get("offset", "0"))
    except ValueError:
        limit, offset = 100, 0

    try:
        deployments = registry.list_deployments(
            status=status,
            risk_level=risk_level,
            provider=provider,
            limit=limit,
            offset=offset,
        )

        results = [_deployment_to_dict(d) for d in deployments]

        return web.json_response({
            "deployments": results,
            "total": len(results),
            "limit": limit,
            "offset": offset,
        })

    except Exception as e:
        logger.exception(f"List deployments error: {e}")
        return web.json_response(
            {"error": {"type": "RegistryError", "message": str(e)}},
            status=500,
        )


async def create_deployment(request: "web.Request") -> "web.Response":
    """
    Register a new model deployment.

    Request body:
        {
            "provider": "openai",
            "model": "gpt-4",
            "owner": "user@example.com",
            "purpose": "Code review assistance",
            "risk_level": "MEDIUM",
            "data_categories": ["internal"],
            ...
        }

    Returns:
        JSON response with created deployment.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
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
    required = ["provider", "model", "owner", "purpose"]
    missing = [f for f in required if f not in body]
    if missing:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": f"Missing fields: {missing}"}},
            status=400,
        )

    try:
        deployment = registry.register(
            provider=body["provider"],
            model=body["model"],
            owner=body["owner"],
            purpose=body["purpose"],
            risk_level=body.get("risk_level", "MEDIUM"),
            data_categories=body.get("data_categories", []),
            description=body.get("description", ""),
            metadata=body.get("metadata", {}),
        )

        return web.json_response(
            {"deployment": _deployment_to_dict(deployment), "message": "Deployment created"},
            status=201,
        )

    except ValidationError as e:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": e.message, "details": e.details}},
            status=400,
        )
    except RegistryError as e:
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Create deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def get_deployment(request: "web.Request") -> "web.Response":
    """
    Get deployment details.

    Path parameters:
        deployment_id: The deployment ID

    Returns:
        JSON response with deployment details.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        deployment = registry.get(deployment_id)
        if not deployment:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Deployment not found: {deployment_id}"}},
                status=404,
            )

        return web.json_response({"deployment": _deployment_to_dict(deployment)})

    except Exception as e:
        logger.exception(f"Get deployment error: {e}")
        return web.json_response(
            {"error": {"type": "RegistryError", "message": str(e)}},
            status=500,
        )


async def update_deployment(request: "web.Request") -> "web.Response":
    """
    Update a deployment.

    Path parameters:
        deployment_id: The deployment ID

    Request body:
        Fields to update (owner, purpose, risk_level, etc.)

    Returns:
        JSON response with updated deployment.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    try:
        deployment = registry.update(deployment_id, **body)
        return web.json_response({
            "deployment": _deployment_to_dict(deployment),
            "message": "Deployment updated",
        })

    except RegistryError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Update deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def delete_deployment(request: "web.Request") -> "web.Response":
    """
    Delete a deployment.

    Path parameters:
        deployment_id: The deployment ID

    Returns:
        JSON response confirming deletion.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        success = registry.delete(deployment_id)
        if not success:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Deployment not found: {deployment_id}"}},
                status=404,
            )

        return web.json_response({"message": "Deployment deleted", "deployment_id": deployment_id})

    except RegistryError as e:
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Delete deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def approve_deployment(request: "web.Request") -> "web.Response":
    """
    Approve a deployment.

    Path parameters:
        deployment_id: The deployment ID

    Request body:
        {
            "approver": "admin@example.com",
            "notes": "Approved for production use"
        }

    Returns:
        JSON response with approved deployment.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    approver = body.get("approver", "api")
    notes = body.get("notes", "")

    try:
        deployment = registry.approve(deployment_id, approver=approver, notes=notes)
        return web.json_response({
            "deployment": _deployment_to_dict(deployment),
            "message": "Deployment approved",
        })

    except RegistryError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Approve deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def reject_deployment(request: "web.Request") -> "web.Response":
    """
    Reject a deployment.

    Path parameters:
        deployment_id: The deployment ID

    Request body:
        {
            "rejector": "admin@example.com",
            "reason": "Does not meet compliance requirements"
        }

    Returns:
        JSON response with rejected deployment.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    rejector = body.get("rejector", "api")
    reason = body.get("reason", "")

    try:
        deployment = registry.reject(deployment_id, rejector=rejector, reason=reason)
        return web.json_response({
            "deployment": _deployment_to_dict(deployment),
            "message": "Deployment rejected",
        })

    except RegistryError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Reject deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def suspend_deployment(request: "web.Request") -> "web.Response":
    """
    Suspend a deployment.

    Path parameters:
        deployment_id: The deployment ID

    Request body:
        {
            "reason": "Security review required",
            "suspended_by": "security@example.com"
        }

    Returns:
        JSON response with suspended deployment.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    reason = body.get("reason", "")
    suspended_by = body.get("suspended_by", "api")

    try:
        deployment = registry.suspend(deployment_id, reason=reason, suspended_by=suspended_by)
        return web.json_response({
            "deployment": _deployment_to_dict(deployment),
            "message": "Deployment suspended",
        })

    except RegistryError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Suspend deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def reinstate_deployment(request: "web.Request") -> "web.Response":
    """
    Reinstate a suspended deployment.

    Path parameters:
        deployment_id: The deployment ID

    Request body:
        {
            "reinstated_by": "admin@example.com",
            "notes": "Security review passed"
        }

    Returns:
        JSON response with reinstated deployment.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    reinstated_by = body.get("reinstated_by", "api")
    notes = body.get("notes", "")

    try:
        deployment = registry.reinstate(deployment_id, reinstated_by=reinstated_by, notes=notes)
        return web.json_response({
            "deployment": _deployment_to_dict(deployment),
            "message": "Deployment reinstated",
        })

    except RegistryError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "RegistryError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Reinstate deployment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def check_compliance(request: "web.Request") -> "web.Response":
    """
    Check deployment compliance.

    Path parameters:
        deployment_id: The deployment ID

    Returns:
        JSON response with compliance status.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    compliance_checker = request.app.get("compliance_checker")

    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        deployment = registry.get(deployment_id)
        if not deployment:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Deployment not found: {deployment_id}"}},
                status=404,
            )

        if compliance_checker:
            result = compliance_checker.check_deployment(deployment)
            return web.json_response({
                "deployment_id": deployment_id,
                "compliant": result.is_compliant,
                "findings": [f.to_dict() for f in result.findings],
                "checked_at": result.checked_at.isoformat() if result.checked_at else None,
            })
        else:
            return web.json_response({
                "deployment_id": deployment_id,
                "compliant": True,
                "findings": [],
                "message": "Compliance checker not configured",
            })

    except Exception as e:
        logger.exception(f"Compliance check error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def get_deployment_stats(request: "web.Request") -> "web.Response":
    """
    Get deployment usage statistics.

    Path parameters:
        deployment_id: The deployment ID

    Returns:
        JSON response with usage stats.
    """
    from aiohttp import web

    registry = request.app.get("registry_manager")
    if not registry:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Registry not configured"}},
            status=503,
        )

    deployment_id = request.match_info["deployment_id"]

    try:
        deployment = registry.get(deployment_id)
        if not deployment:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Deployment not found: {deployment_id}"}},
                status=404,
            )

        stats = registry.get_usage_stats(deployment_id)

        return web.json_response({
            "deployment_id": deployment_id,
            "stats": stats.to_dict() if hasattr(stats, "to_dict") else stats,
        })

    except Exception as e:
        logger.exception(f"Get stats error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


def _deployment_to_dict(deployment: Any) -> dict[str, Any]:
    """Convert a deployment to a dictionary."""
    if hasattr(deployment, "to_dict"):
        return deployment.to_dict()

    return {
        "deployment_id": getattr(deployment, "deployment_id", None),
        "provider": getattr(deployment, "provider", None),
        "model": getattr(deployment, "model", None),
        "owner": getattr(deployment, "owner", None),
        "purpose": getattr(deployment, "purpose", None),
        "risk_level": getattr(deployment, "risk_level", None),
        "status": getattr(deployment, "status", None),
        "created_at": getattr(deployment, "created_at", None),
    }
