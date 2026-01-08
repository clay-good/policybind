"""
Audit handlers for PolicyBind server.

This module provides handlers for audit log query endpoints.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.audit")


async def query_logs(request: "web.Request") -> "web.Response":
    """
    Query audit logs.

    Query parameters:
        user: Filter by user ID
        department: Filter by department
        decision: Filter by decision (ALLOW, DENY, MODIFY)
        deployment: Filter by deployment ID
        start: Start date (ISO format or relative like "7d")
        end: End date (ISO format)
        limit: Maximum results (default: 100)

    Returns:
        JSON response with audit logs.
    """
    from aiohttp import web

    audit_repository = request.app.get("audit_repository")
    if not audit_repository:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Audit repository not configured"}},
            status=503,
        )

    # Parse query parameters
    user_id = request.query.get("user")
    department = request.query.get("department")
    decision = request.query.get("decision")
    deployment_id = request.query.get("deployment")
    start_str = request.query.get("start")
    end_str = request.query.get("end")

    try:
        limit = int(request.query.get("limit", "100"))
    except ValueError:
        limit = 100

    # Parse dates
    start_date = _parse_date(start_str, default_days_ago=7)
    end_date = _parse_date(end_str)

    try:
        logs = audit_repository.query_enforcement_logs(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            department=department,
            decision=decision,
            deployment_id=deployment_id,
            limit=limit,
        )

        return web.json_response({
            "logs": logs,
            "total": len(logs),
            "limit": limit,
        })

    except Exception as e:
        logger.exception(f"Query logs error: {e}")
        return web.json_response(
            {"error": {"type": "AuditError", "message": str(e)}},
            status=500,
        )


async def get_stats(request: "web.Request") -> "web.Response":
    """
    Get audit statistics.

    Query parameters:
        start: Start date (ISO format or relative like "30d")
        end: End date (ISO format)

    Returns:
        JSON response with audit statistics.
    """
    from aiohttp import web

    audit_repository = request.app.get("audit_repository")
    if not audit_repository:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Audit repository not configured"}},
            status=503,
        )

    # Parse dates
    start_str = request.query.get("start", "30d")
    end_str = request.query.get("end")

    start_date = _parse_date(start_str, default_days_ago=30)
    end_date = _parse_date(end_str) or datetime.now(UTC)

    if start_date is None:
        return web.json_response(
            {"error": {"type": "ValidationError", "message": "Invalid start date"}},
            status=400,
        )

    try:
        stats = audit_repository.get_enforcement_stats(start_date, end_date)

        return web.json_response(stats)

    except Exception as e:
        logger.exception(f"Get stats error: {e}")
        return web.json_response(
            {"error": {"type": "AuditError", "message": str(e)}},
            status=500,
        )


async def get_log_entry(request: "web.Request") -> "web.Response":
    """
    Get a specific log entry.

    Path parameters:
        log_id: The log entry ID

    Returns:
        JSON response with log entry details.
    """
    from aiohttp import web

    database = request.app.get("database")
    if not database:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Database not configured"}},
            status=503,
        )

    log_id = request.match_info["log_id"]

    try:
        # Query directly from database
        logs = database.execute(
            "SELECT * FROM enforcement_log WHERE id = ?",
            (log_id,),
        )

        if not logs:
            return web.json_response(
                {"error": {"type": "NotFound", "message": f"Log entry not found: {log_id}"}},
                status=404,
            )

        log = logs[0]

        # Deserialize JSON fields
        import json

        for field in ["data_classification", "applied_rules", "modifications", "warnings", "request_metadata", "response_metadata"]:
            if log.get(field) and isinstance(log[field], str):
                try:
                    log[field] = json.loads(log[field])
                except json.JSONDecodeError:
                    pass

        return web.json_response({"log": log})

    except Exception as e:
        logger.exception(f"Get log entry error: {e}")
        return web.json_response(
            {"error": {"type": "AuditError", "message": str(e)}},
            status=500,
        )


async def export_logs(request: "web.Request") -> "web.Response":
    """
    Export audit logs in various formats.

    Query parameters:
        format: Export format (json, csv, ndjson) - default: json
        user: Filter by user ID
        department: Filter by department
        decision: Filter by decision (ALLOW, DENY, MODIFY)
        deployment: Filter by deployment ID
        start: Start date (ISO format or relative like "7d")
        end: End date (ISO format)
        limit: Maximum results (default: 10000)

    Returns:
        File download with audit logs in requested format.
    """
    from aiohttp import web

    audit_repository = request.app.get("audit_repository")
    if not audit_repository:
        return web.json_response(
            {"error": {"type": "ServiceUnavailable", "message": "Audit repository not configured"}},
            status=503,
        )

    # Parse query parameters
    export_format = request.query.get("format", "json")
    user_id = request.query.get("user")
    department = request.query.get("department")
    decision = request.query.get("decision")
    deployment_id = request.query.get("deployment")
    start_str = request.query.get("start")
    end_str = request.query.get("end")

    try:
        limit = int(request.query.get("limit", "10000"))
        limit = min(limit, 100000)  # Cap at 100k records
    except ValueError:
        limit = 10000

    # Parse dates
    start_date = _parse_date(start_str, default_days_ago=30)
    end_date = _parse_date(end_str)

    try:
        logs = audit_repository.query_enforcement_logs(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            department=department,
            decision=decision,
            deployment_id=deployment_id,
            limit=limit,
        )

        # Generate filename
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"audit_logs_{timestamp}"

        if export_format == "csv":
            # CSV export
            import csv
            import io

            output = io.StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                for log in logs:
                    # Flatten nested objects for CSV
                    flat_log = {}
                    for k, v in log.items():
                        if isinstance(v, (list, dict)):
                            import json
                            flat_log[k] = json.dumps(v)
                        else:
                            flat_log[k] = v
                    writer.writerow(flat_log)

            return web.Response(
                text=output.getvalue(),
                content_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}.csv"',
                },
            )

        elif export_format == "ndjson":
            # Newline-delimited JSON export
            import json

            lines = [json.dumps(log, default=str) for log in logs]
            content = "\n".join(lines)

            return web.Response(
                text=content,
                content_type="application/x-ndjson",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}.ndjson"',
                },
            )

        else:  # json
            # Standard JSON export
            import json

            content = json.dumps({
                "logs": logs,
                "total": len(logs),
                "exported_at": datetime.now(UTC).isoformat(),
                "filters": {
                    "user": user_id,
                    "department": department,
                    "decision": decision,
                    "deployment": deployment_id,
                    "start": start_date.isoformat() if start_date else None,
                    "end": end_date.isoformat() if end_date else None,
                },
            }, indent=2, default=str)

            return web.Response(
                text=content,
                content_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}.json"',
                },
            )

    except Exception as e:
        logger.exception(f"Export logs error: {e}")
        return web.json_response(
            {"error": {"type": "AuditError", "message": str(e)}},
            status=500,
        )


def _parse_date(date_str: str | None, default_days_ago: int = 0) -> datetime | None:
    """
    Parse a date string that can be ISO format or relative (e.g., '7d').

    Args:
        date_str: Date string or None.
        default_days_ago: Default number of days ago if None.

    Returns:
        Parsed datetime or None.
    """
    if date_str is None:
        if default_days_ago > 0:
            return datetime.now(UTC) - timedelta(days=default_days_ago)
        return None

    # Check for relative format (e.g., '7d', '30d')
    if date_str.endswith("d") and date_str[:-1].isdigit():
        days = int(date_str[:-1])
        return datetime.now(UTC) - timedelta(days=days)

    # Try ISO format
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None
