"""
Incident handlers for PolicyBind server.

This module provides handlers for incident management endpoints.
"""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import IncidentError, ValidationError

logger = logging.getLogger("policybind.server.handlers.incident")


async def list_incidents(request: "web.Request") -> "web.Response":
    """
    List incidents.

    Query parameters:
        status: Filter by status (OPEN, INVESTIGATING, RESOLVED, CLOSED)
        severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
        type: Filter by incident type
        assignee: Filter by assignee
        limit: Maximum results (default: 100)
        offset: Pagination offset (default: 0)

    Returns:
        JSON response with incident list.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    # Parse query parameters
    status = request.query.get("status")
    severity = request.query.get("severity")
    incident_type = request.query.get("type")
    assignee = request.query.get("assignee")

    try:
        limit = int(request.query.get("limit", "100"))
        offset = int(request.query.get("offset", "0"))
    except ValueError:
        limit, offset = 100, 0

    try:
        from policybind.incidents.models import (
            IncidentSeverity,
            IncidentStatus,
            IncidentType,
        )

        # Parse enum filters
        status_enum = IncidentStatus(status) if status else None
        severity_enum = IncidentSeverity(severity) if severity else None
        type_enum = IncidentType(incident_type) if incident_type else None

        incidents = incident_manager.list_incidents(
            status=status_enum,
            severity=severity_enum,
            incident_type=type_enum,
            assignee=assignee,
            limit=limit,
            offset=offset,
        )

        results = [_incident_to_summary(i) for i in incidents]

        return web.json_response({
            "incidents": results,
            "total": len(results),
            "limit": limit,
            "offset": offset,
        })

    except ValueError as e:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": f"Invalid filter value: {e}"}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"List incidents error: {e}")
        return web.json_response(
            {"error": {"type": "IncidentError", "message": str(e)}},
            status=500,
        )


async def create_incident(request: "web.Request") -> "web.Response":
    """
    Create a new incident.

    Request body:
        {
            "title": "Policy violation detected",
            "incident_type": "POLICY_VIOLATION",
            "severity": "HIGH",
            "description": "...",
            "deployment_id": "...",
            "tags": [...]
        }

    Returns:
        JSON response with created incident.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
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
    required = ["title", "incident_type"]
    missing = [f for f in required if f not in body]
    if missing:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": f"Missing fields: {missing}"}},
            status=400,
        )

    try:
        from policybind.incidents.models import IncidentSeverity, IncidentType

        incident = incident_manager.create(
            title=body["title"],
            incident_type=IncidentType(body["incident_type"]),
            severity=IncidentSeverity(body.get("severity", "MEDIUM")),
            description=body.get("description", ""),
            deployment_id=body.get("deployment_id"),
            tags=body.get("tags", []),
            metadata=body.get("metadata", {}),
        )

        return web.json_response({
            "incident": _incident_to_dict(incident),
            "message": "Incident created",
        }, status=201)

    except ValueError as e:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": f"Invalid value: {e}"}},
            status=400,
        )
    except IncidentError as e:
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=400,
        )
    except Exception as e:
        logger.exception(f"Create incident error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def get_incident(request: "web.Request") -> "web.Response":
    """
    Get incident details.

    Path parameters:
        incident_id: The incident ID

    Returns:
        JSON response with incident details.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        incident = incident_manager.get(incident_id)
        if not incident:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Incident not found: {incident_id}"}},
                status=404,
            )

        # Get comments and timeline
        comments = incident_manager.get_comments(incident_id)
        timeline = incident_manager.get_timeline(incident_id)

        result = _incident_to_dict(incident)
        result["comments"] = [_comment_to_dict(c) for c in comments]
        result["timeline"] = [_timeline_to_dict(t) for t in timeline]

        return web.json_response({"incident": result})

    except Exception as e:
        logger.exception(f"Get incident error: {e}")
        return web.json_response(
            {"error": {"type": "IncidentError", "message": str(e)}},
            status=500,
        )


async def update_incident(request: "web.Request") -> "web.Response":
    """
    Update an incident.

    Path parameters:
        incident_id: The incident ID

    Request body:
        Fields to update

    Returns:
        JSON response with updated incident.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    try:
        # Update severity if provided
        if "severity" in body:
            from policybind.incidents.models import IncidentSeverity

            incident_manager.update_severity(
                incident_id,
                IncidentSeverity(body["severity"]),
                actor="api",
            )

        incident = incident_manager.get(incident_id)
        if not incident:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Incident not found: {incident_id}"}},
                status=404,
            )

        return web.json_response({
            "incident": _incident_to_dict(incident),
            "message": "Incident updated",
        })

    except IncidentError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Update incident error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def assign_incident(request: "web.Request") -> "web.Response":
    """
    Assign an incident.

    Path parameters:
        incident_id: The incident ID

    Request body:
        {
            "assignee": "user@example.com"
        }

    Returns:
        JSON response with assigned incident.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    assignee = body.get("assignee")
    if not assignee:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": "Assignee required"}},
            status=400,
        )

    try:
        incident = incident_manager.assign(incident_id, assignee, actor="api")
        return web.json_response({
            "incident": _incident_to_dict(incident),
            "message": f"Incident assigned to {assignee}",
        })

    except IncidentError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Assign incident error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def add_comment(request: "web.Request") -> "web.Response":
    """
    Add a comment to an incident.

    Path parameters:
        incident_id: The incident ID

    Request body:
        {
            "author": "user@example.com",
            "content": "Investigation notes..."
        }

    Returns:
        JSON response confirming comment added.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    content = body.get("content")
    if not content:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": "Comment content required"}},
            status=400,
        )

    author = body.get("author", "api")

    try:
        comment_id = incident_manager.add_comment(incident_id, author=author, content=content)
        return web.json_response({
            "comment_id": comment_id,
            "message": "Comment added",
        }, status=201)

    except IncidentError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Add comment error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def start_investigation(request: "web.Request") -> "web.Response":
    """
    Start investigation on an incident.

    Path parameters:
        incident_id: The incident ID

    Returns:
        JSON response with updated incident.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        incident = incident_manager.start_investigation(incident_id, actor="api")
        return web.json_response({
            "incident": _incident_to_dict(incident),
            "message": "Investigation started",
        })

    except IncidentError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Start investigation error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def resolve_incident(request: "web.Request") -> "web.Response":
    """
    Resolve an incident.

    Path parameters:
        incident_id: The incident ID

    Request body:
        {
            "resolution": "Description of how it was resolved",
            "root_cause": "Identified root cause"
        }

    Returns:
        JSON response with resolved incident.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        body = await request.json()
    except Exception as e:
        return web.json_response(
            {"error": {"type": "InvalidRequest", "message": f"Invalid JSON: {e}"}},
            status=400,
        )

    resolution = body.get("resolution")
    if not resolution:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": "Resolution required"}},
            status=400,
        )

    root_cause = body.get("root_cause")

    try:
        incident = incident_manager.resolve(
            incident_id,
            resolution=resolution,
            root_cause=root_cause,
            actor="api",
        )
        return web.json_response({
            "incident": _incident_to_dict(incident),
            "message": "Incident resolved",
        })

    except IncidentError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Resolve incident error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def close_incident(request: "web.Request") -> "web.Response":
    """
    Close an incident.

    Path parameters:
        incident_id: The incident ID

    Returns:
        JSON response with closed incident.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    incident_id = request.match_info["incident_id"]

    try:
        incident = incident_manager.close(incident_id, actor="api")
        return web.json_response({
            "incident": _incident_to_dict(incident),
            "message": "Incident closed",
        })

    except IncidentError as e:
        status = 404 if "not found" in str(e).lower() else 400
        return web.json_response(
            {"error": {"type": "IncidentError", "message": e.message}},
            status=status,
        )
    except Exception as e:
        logger.exception(f"Close incident error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def get_incident_stats(request: "web.Request") -> "web.Response":
    """
    Get incident statistics.

    Returns:
        JSON response with incident statistics.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    try:
        metrics = incident_manager.get_metrics()

        return web.json_response({
            "total_count": metrics.total_count,
            "open_count": metrics.open_count,
            "investigating_count": metrics.investigating_count,
            "resolved_count": metrics.resolved_count,
            "closed_count": metrics.closed_count,
            "by_severity": metrics.by_severity,
            "by_type": metrics.by_type,
            "mean_time_to_resolve_hours": metrics.mean_time_to_resolve_hours,
        })

    except Exception as e:
        logger.exception(f"Get incident stats error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


async def generate_report(request: "web.Request") -> "web.Response":
    """
    Generate an incident report.

    Query parameters:
        incident_id: Generate report for specific incident (optional)
        format: Report format (markdown, json, text) - default: markdown
        period: For summary reports: 7d, 30d, 90d - default: 30d
        type: Report type (incident, summary, trend) - default: summary

    Returns:
        Report content in the requested format.
    """
    from aiohttp import web

    incident_manager = request.app.get("incident_manager")
    if not incident_manager:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Incident manager not configured"}},
            status=503,
        )

    # Parse query parameters
    incident_id = request.query.get("incident_id")
    format_str = request.query.get("format", "markdown")
    period_str = request.query.get("period", "30d")
    report_type = request.query.get("type", "summary")

    try:
        from datetime import timedelta

        from policybind.incidents.reports import IncidentReporter, ReportFormat

        # Parse format
        try:
            report_format = ReportFormat(format_str)
        except ValueError:
            return web.json_response(
                {"error": {"type": "ValidationError", "message": f"Invalid format: {format_str}"}},
                status=400,
            )

        # Parse period
        period_days = 30
        if period_str.endswith("d") and period_str[:-1].isdigit():
            period_days = int(period_str[:-1])

        reporter = IncidentReporter(incident_manager)

        # Generate appropriate report
        if incident_id or report_type == "incident":
            if not incident_id:
                return web.json_response(
                    {"error": {"type": "ValidationError", "message": "incident_id required for incident report"}},
                    status=400,
                )

            incident = incident_manager.get(incident_id)
            if not incident:
                return web.json_response(
                    {"error": {"type": "NotFound", "message": f"Incident not found: {incident_id}"}},
                    status=404,
                )

            report = reporter.generate_incident_report(incident, format=report_format)

        elif report_type == "trend":
            from policybind.models.base import utc_now

            since = utc_now() - timedelta(days=period_days)
            report = reporter.generate_trend_report(since=since, format=report_format)

        else:  # summary
            from policybind.models.base import utc_now

            since = utc_now() - timedelta(days=period_days)
            report = reporter.generate_summary_report(since=since, format=report_format)

        # Return with appropriate content type
        if report_format == ReportFormat.JSON:
            # For JSON format, parse and return as JSON response
            import json as json_module

            try:
                return web.json_response(json_module.loads(report))
            except json_module.JSONDecodeError:
                return web.json_response({"report": report})
        elif report_format == ReportFormat.MARKDOWN:
            return web.Response(
                text=report,
                content_type="text/markdown",
            )
        else:  # text
            return web.Response(
                text=report,
                content_type="text/plain",
            )

    except Exception as e:
        logger.exception(f"Generate report error: {e}")
        return web.json_response(
            {"error": {"type": "InternalError", "message": str(e)}},
            status=500,
        )


def _incident_to_dict(incident: Any) -> dict[str, Any]:
    """Convert an incident to a dictionary."""
    if hasattr(incident, "to_dict"):
        return incident.to_dict()

    return {
        "incident_id": getattr(incident, "incident_id", None),
        "title": getattr(incident, "title", None),
        "description": getattr(incident, "description", None),
        "severity": getattr(incident, "severity", None).value if hasattr(incident, "severity") else None,
        "status": getattr(incident, "status", None).value if hasattr(incident, "status") else None,
        "incident_type": getattr(incident, "incident_type", None).value if hasattr(incident, "incident_type") else None,
        "assignee": getattr(incident, "assignee", None),
        "created_at": getattr(incident, "created_at", None),
        "resolved_at": getattr(incident, "resolved_at", None),
        "resolution": getattr(incident, "resolution", None),
        "root_cause": getattr(incident, "root_cause", None),
    }


def _incident_to_summary(incident: Any) -> dict[str, Any]:
    """Convert an incident to a summary dictionary."""
    return {
        "incident_id": getattr(incident, "incident_id", None),
        "title": getattr(incident, "title", None),
        "severity": getattr(incident, "severity", None).value if hasattr(incident, "severity") else None,
        "status": getattr(incident, "status", None).value if hasattr(incident, "status") else None,
        "assignee": getattr(incident, "assignee", None),
        "created_at": getattr(incident, "created_at", None),
    }


def _comment_to_dict(comment: Any) -> dict[str, Any]:
    """Convert a comment to a dictionary."""
    if hasattr(comment, "to_dict"):
        return comment.to_dict()

    return {
        "id": getattr(comment, "id", None),
        "author": getattr(comment, "author", None),
        "content": getattr(comment, "content", None),
        "created_at": getattr(comment, "created_at", None),
    }


def _timeline_to_dict(entry: Any) -> dict[str, Any]:
    """Convert a timeline entry to a dictionary."""
    if hasattr(entry, "to_dict"):
        return entry.to_dict()

    return {
        "id": getattr(entry, "id", None),
        "event_type": getattr(entry, "event_type", None).value if hasattr(entry, "event_type") else None,
        "old_value": getattr(entry, "old_value", None),
        "new_value": getattr(entry, "new_value", None),
        "actor": getattr(entry, "actor", None),
        "timestamp": getattr(entry, "timestamp", None),
    }
