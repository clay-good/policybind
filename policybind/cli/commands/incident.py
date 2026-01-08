"""
Incident commands for PolicyBind CLI.

This module implements the 'policybind incident' commands for managing
policy violations and AI safety incidents.

Usage:
    policybind incident list [--status STATUS] [--severity SEVERITY]
    policybind incident show INCIDENT_ID
    policybind incident create --title TITLE --type TYPE [--severity SEVERITY]
    policybind incident assign INCIDENT_ID --assignee ASSIGNEE
    policybind incident comment INCIDENT_ID --message MESSAGE
    policybind incident resolve INCIDENT_ID --resolution RESOLUTION
    policybind incident close INCIDENT_ID
"""

import argparse
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the incident command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "incident",
        help="Manage incidents",
        description=(
            "Manage incidents for policy violations and AI safety events. "
            "Create, investigate, and resolve incidents."
        ),
    )

    incident_subparsers = parser.add_subparsers(
        dest="incident_command",
        help="Incident command to execute",
    )

    # incident list
    list_parser = incident_subparsers.add_parser(
        "list",
        help="List incidents",
        description="List all incidents with optional filters.",
    )
    list_parser.add_argument(
        "--status",
        choices=["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"],
        help="Filter by status",
    )
    list_parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter by severity",
    )
    list_parser.add_argument(
        "--type",
        choices=[
            "POLICY_VIOLATION", "HARMFUL_OUTPUT", "JAILBREAK",
            "DATA_LEAK", "PROMPT_INJECTION", "ABUSE",
            "BUDGET_EXCEEDED", "COMPLIANCE_FAILURE", "OTHER",
        ],
        dest="incident_type",
        help="Filter by incident type",
    )
    list_parser.add_argument(
        "--assignee",
        help="Filter by assignee",
    )
    list_parser.add_argument(
        "--deployment",
        help="Filter by deployment ID",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of results (default: 50)",
    )
    list_parser.set_defaults(func=run_incident_list)

    # incident show
    show_parser = incident_subparsers.add_parser(
        "show",
        help="Show incident details",
        description="Display detailed information about an incident.",
    )
    show_parser.add_argument(
        "incident_id",
        help="Incident ID",
    )
    show_parser.add_argument(
        "--include-timeline",
        action="store_true",
        help="Include full timeline",
    )
    show_parser.add_argument(
        "--include-comments",
        action="store_true",
        help="Include all comments",
    )
    show_parser.set_defaults(func=run_incident_show)

    # incident create
    create_parser = incident_subparsers.add_parser(
        "create",
        help="Create a new incident",
        description="Manually create an incident.",
    )
    create_parser.add_argument(
        "--title",
        required=True,
        help="Incident title",
    )
    create_parser.add_argument(
        "--type",
        required=True,
        choices=[
            "POLICY_VIOLATION", "HARMFUL_OUTPUT", "JAILBREAK",
            "DATA_LEAK", "PROMPT_INJECTION", "ABUSE",
            "BUDGET_EXCEEDED", "COMPLIANCE_FAILURE", "OTHER",
        ],
        dest="incident_type",
        help="Incident type",
    )
    create_parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="MEDIUM",
        help="Severity level (default: MEDIUM)",
    )
    create_parser.add_argument(
        "--description",
        default="",
        help="Detailed description",
    )
    create_parser.add_argument(
        "--deployment",
        help="Related deployment ID",
    )
    create_parser.add_argument(
        "--tags",
        nargs="+",
        help="Tags for categorization",
    )
    create_parser.set_defaults(func=run_incident_create)

    # incident assign
    assign_parser = incident_subparsers.add_parser(
        "assign",
        help="Assign an incident",
        description="Assign an incident to a user or team.",
    )
    assign_parser.add_argument(
        "incident_id",
        help="Incident ID",
    )
    assign_parser.add_argument(
        "--assignee",
        required=True,
        help="Assignee (user or team)",
    )
    assign_parser.set_defaults(func=run_incident_assign)

    # incident comment
    comment_parser = incident_subparsers.add_parser(
        "comment",
        help="Add a comment to an incident",
        description="Add a comment or note to an incident.",
    )
    comment_parser.add_argument(
        "incident_id",
        help="Incident ID",
    )
    comment_parser.add_argument(
        "--message",
        "-m",
        required=True,
        help="Comment message",
    )
    comment_parser.add_argument(
        "--internal",
        action="store_true",
        help="Mark as internal comment",
    )
    comment_parser.set_defaults(func=run_incident_comment)

    # incident investigate
    investigate_parser = incident_subparsers.add_parser(
        "investigate",
        help="Start investigation",
        description="Mark an incident as under investigation.",
    )
    investigate_parser.add_argument(
        "incident_id",
        help="Incident ID",
    )
    investigate_parser.set_defaults(func=run_incident_investigate)

    # incident resolve
    resolve_parser = incident_subparsers.add_parser(
        "resolve",
        help="Resolve an incident",
        description="Mark an incident as resolved.",
    )
    resolve_parser.add_argument(
        "incident_id",
        help="Incident ID",
    )
    resolve_parser.add_argument(
        "--resolution",
        required=True,
        help="Resolution description",
    )
    resolve_parser.add_argument(
        "--root-cause",
        help="Root cause analysis",
    )
    resolve_parser.set_defaults(func=run_incident_resolve)

    # incident close
    close_parser = incident_subparsers.add_parser(
        "close",
        help="Close an incident",
        description="Close an incident (no further action needed).",
    )
    close_parser.add_argument(
        "incident_id",
        help="Incident ID",
    )
    close_parser.add_argument(
        "--reason",
        default="",
        help="Closure reason",
    )
    close_parser.set_defaults(func=run_incident_close)

    # incident stats
    stats_parser = incident_subparsers.add_parser(
        "stats",
        help="Show incident statistics",
        description="Display incident statistics and metrics.",
    )
    stats_parser.set_defaults(func=run_incident_stats)

    # incident export
    export_parser = incident_subparsers.add_parser(
        "export",
        help="Export incidents",
        description="Export incidents to JSON for reporting.",
    )
    export_parser.add_argument(
        "--status",
        choices=["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"],
        help="Filter by status",
    )
    export_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (stdout if not specified)",
    )
    export_parser.set_defaults(func=run_incident_export)

    parser.set_defaults(func=run_incident)


def run_incident(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute incident command (shows help if no subcommand)."""
    from policybind.cli.main import EXIT_ERROR

    if not args.incident_command:
        ctx.print_error("No incident command specified. Use --help for usage.")
        return EXIT_ERROR

    return EXIT_ERROR


def _get_incident_manager(ctx: "CLIContext") -> Any:
    """Get an IncidentManager instance."""
    from policybind.incidents.manager import IncidentManager
    from policybind.storage.repositories import IncidentRepository

    repository = IncidentRepository(ctx.database)
    return IncidentManager(repository)


def run_incident_list(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident list command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.incidents.models import IncidentSeverity, IncidentStatus, IncidentType

    try:
        manager = _get_incident_manager(ctx)

        # Parse filters
        status = IncidentStatus(args.status) if args.status else None
        severity = IncidentSeverity(args.severity) if args.severity else None
        incident_type = IncidentType(args.incident_type) if args.incident_type else None

        # List incidents
        incidents = manager.list_incidents(
            status=status,
            severity=severity,
            incident_type=incident_type,
            deployment_id=args.deployment,
            assignee=args.assignee,
            limit=args.limit,
        )

        results = []
        for inc in incidents:
            results.append({
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity.value,
                "status": inc.status.value,
                "incident_type": inc.incident_type.value,
                "assignee": inc.assignee or "(unassigned)",
                "created_at": inc.created_at.isoformat(),
            })

        if ctx.output_format == "table":
            if not results:
                ctx.print("No incidents found.")
            else:
                ctx.print("Incidents")
                ctx.print("=" * 80)
                ctx.print("")
                for r in results:
                    status_marker = _get_status_marker(r["status"])
                    severity_marker = _get_severity_marker(r["severity"])
                    ctx.print(f"{status_marker}{severity_marker} {r['title']}")
                    ctx.print(f"    ID: {r['incident_id']}")
                    ctx.print(f"    Type: {r['incident_type']}, Assignee: {r['assignee']}")
                    ctx.print(f"    Created: {r['created_at'][:10]}")
                    ctx.print("")
                ctx.print(f"Total: {len(results)} incident(s)")
        else:
            output = format_output(results, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to list incidents: {e}")
        return EXIT_ERROR


def run_incident_show(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident show command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        incident = manager.get(args.incident_id)

        if not incident:
            ctx.print_error(f"Incident not found: {args.incident_id}")
            return EXIT_ERROR

        result = _incident_to_dict(incident)

        # Fetch timeline and comments if requested
        timeline = None
        comments = None
        if args.include_timeline:
            timeline = manager.get_timeline(args.incident_id)
        if args.include_comments:
            comments = manager.get_comments(args.incident_id)

        if ctx.output_format == "table":
            _print_incident_table(incident, ctx, timeline, comments)
        else:
            # Add timeline and comments to result if requested
            if timeline:
                result["timeline"] = [
                    {
                        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                        "event_type": e.event_type.value,
                        "old_value": e.old_value,
                        "new_value": e.new_value,
                        "actor": e.actor,
                    }
                    for e in timeline
                ]
            if comments:
                result["comments"] = [
                    {
                        "id": c.id,
                        "author": c.author,
                        "content": c.content,
                        "created_at": c.created_at.isoformat() if c.created_at else None,
                    }
                    for c in comments
                ]
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to show incident: {e}")
        return EXIT_ERROR


def run_incident_create(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident create command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.incidents.models import IncidentSeverity, IncidentType

    try:
        manager = _get_incident_manager(ctx)

        incident = manager.create(
            title=args.title,
            incident_type=IncidentType(args.incident_type),
            severity=IncidentSeverity(args.severity),
            description=args.description,
            deployment_id=args.deployment,
            tags=args.tags,
        )

        result = {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "message": "Incident created successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Created incident: {incident.title}")
            ctx.print(f"  ID: {incident.incident_id}")
            ctx.print(f"  Severity: {incident.severity.value}")
            ctx.print(f"  Status: {incident.status.value}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to create incident: {e}")
        return EXIT_ERROR


def run_incident_assign(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident assign command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        incident = manager.assign(
            args.incident_id,
            args.assignee,
            actor="cli",
        )

        result = {
            "incident_id": incident.incident_id,
            "assignee": incident.assignee,
            "message": f"Incident assigned to {args.assignee}",
        }

        if ctx.output_format == "table":
            ctx.print(f"Assigned incident to: {args.assignee}")
            ctx.print(f"  ID: {args.incident_id}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to assign incident: {e}")
        return EXIT_ERROR


def run_incident_comment(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident comment command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        # add_comment returns the comment ID (int), not a Comment object
        # If internal flag is set, include it in metadata
        metadata = {"internal": True} if args.internal else None
        comment_id = manager.add_comment(
            args.incident_id,
            author="cli",
            content=args.message,
            metadata=metadata,
        )

        result = {
            "incident_id": args.incident_id,
            "comment_id": comment_id,
            "message": "Comment added successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Added comment to incident: {args.incident_id}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to add comment: {e}")
        return EXIT_ERROR


def run_incident_investigate(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident investigate command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        incident = manager.start_investigation(
            args.incident_id,
            actor="cli",
        )

        result = {
            "incident_id": incident.incident_id,
            "status": incident.status.value,
            "message": "Investigation started",
        }

        if ctx.output_format == "table":
            ctx.print(f"Started investigation: {args.incident_id}")
            ctx.print(f"  Status: {incident.status.value}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to start investigation: {e}")
        return EXIT_ERROR


def run_incident_resolve(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident resolve command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        incident = manager.resolve(
            args.incident_id,
            resolution=args.resolution,
            root_cause=args.root_cause or "",
            actor="cli",
        )

        result = {
            "incident_id": incident.incident_id,
            "status": incident.status.value,
            "resolution": args.resolution,
            "message": "Incident resolved",
        }

        if ctx.output_format == "table":
            ctx.print(f"Resolved incident: {args.incident_id}")
            ctx.print(f"  Resolution: {args.resolution}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to resolve incident: {e}")
        return EXIT_ERROR


def run_incident_close(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident close command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        # If a reason is provided, add it as a comment before closing
        if args.reason:
            manager.add_comment(
                args.incident_id,
                author="cli",
                content=f"Closure reason: {args.reason}",
            )
        incident = manager.close(
            args.incident_id,
            actor="cli",
        )

        result = {
            "incident_id": incident.incident_id,
            "status": incident.status.value,
            "message": "Incident closed",
        }

        if ctx.output_format == "table":
            ctx.print(f"Closed incident: {args.incident_id}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to close incident: {e}")
        return EXIT_ERROR


def run_incident_stats(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident stats command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        manager = _get_incident_manager(ctx)
        metrics = manager.get_metrics()

        # Get critical/high counts from by_severity dict
        critical_open = metrics.by_severity.get("CRITICAL", 0)
        high_open = metrics.by_severity.get("HIGH", 0)

        result = {
            "total_count": metrics.total_count,
            "open_count": metrics.open_count,
            "investigating_count": metrics.investigating_count,
            "resolved_count": metrics.resolved_count,
            "closed_count": metrics.closed_count,
            "by_severity": metrics.by_severity,
            "by_type": metrics.by_type,
            "mean_time_to_resolve_hours": metrics.mean_time_to_resolve_hours,
        }

        if ctx.output_format == "table":
            ctx.print("Incident Statistics")
            ctx.print("=" * 50)
            ctx.print("")
            ctx.print(f"Total Incidents: {metrics.total_count}")
            ctx.print(f"  Open: {metrics.open_count}")
            ctx.print(f"  Investigating: {metrics.investigating_count}")
            ctx.print(f"  Resolved: {metrics.resolved_count}")
            ctx.print(f"  Closed: {metrics.closed_count}")
            ctx.print("")
            ctx.print("By Severity:")
            for sev, count in metrics.by_severity.items():
                ctx.print(f"  {sev}: {count}")
            ctx.print("")
            ctx.print("By Type:")
            for inc_type, count in metrics.by_type.items():
                ctx.print(f"  {inc_type}: {count}")
            ctx.print("")
            if metrics.mean_time_to_resolve_hours:
                ctx.print(f"Avg Resolution Time: {metrics.mean_time_to_resolve_hours:.1f} hours")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to get statistics: {e}")
        return EXIT_ERROR


def run_incident_export(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the incident export command."""
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.incidents.models import IncidentStatus

    try:
        manager = _get_incident_manager(ctx)

        # Parse filters
        status = IncidentStatus(args.status) if args.status else None

        # Get incidents
        incidents = manager.list_incidents(status=status, limit=10000)

        # Convert to export format
        export_data = [_incident_to_dict(inc) for inc in incidents]

        output_text = json.dumps(export_data, indent=2, default=str)

        # Write output
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_text)
            ctx.print(f"Exported {len(export_data)} incidents to {args.output}")
        else:
            ctx.print(output_text)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to export incidents: {e}")
        return EXIT_ERROR


def _incident_to_dict(incident: Any) -> dict[str, Any]:
    """Convert an incident to a dictionary for output."""
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "incident_type": incident.incident_type.value,
        "assignee": incident.assignee,
        "deployment_id": incident.deployment_id,
        "source_request_id": incident.source_request_id,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "resolution": incident.resolution,
        "root_cause": incident.root_cause,
        "tags": list(incident.tags) if incident.tags else [],
        "evidence": incident.evidence,
    }


def _get_status_marker(status: str) -> str:
    """Get status marker for display."""
    return {
        "OPEN": "[OPEN]",
        "INVESTIGATING": "[INVESTIGATING]",
        "RESOLVED": "[RESOLVED]",
        "CLOSED": "[CLOSED]",
    }.get(status, "[?]")


def _get_severity_marker(severity: str) -> str:
    """Get severity marker for display."""
    return {
        "CRITICAL": "[!!!]",
        "HIGH": "[!!]",
        "MEDIUM": "[!]",
        "LOW": "[ ]",
    }.get(severity, "")


def _print_incident_table(
    incident: Any,
    ctx: "CLIContext",
    timeline: list[Any] | None = None,
    comments: list[Any] | None = None,
) -> None:
    """Print incident details in table format."""
    status_marker = _get_status_marker(incident.status.value)
    severity_marker = _get_severity_marker(incident.severity.value)

    ctx.print("Incident Details")
    ctx.print("=" * 60)
    ctx.print("")
    ctx.print(f"Title: {incident.title} {status_marker}{severity_marker}")
    ctx.print(f"ID: {incident.incident_id}")
    ctx.print("")

    ctx.print("Classification:")
    ctx.print(f"  Type: {incident.incident_type.value}")
    ctx.print(f"  Severity: {incident.severity.value}")
    ctx.print(f"  Status: {incident.status.value}")
    ctx.print("")

    ctx.print("Assignment:")
    ctx.print(f"  Assignee: {incident.assignee or '(unassigned)'}")
    if incident.deployment_id:
        ctx.print(f"  Deployment: {incident.deployment_id}")
    ctx.print("")

    if incident.description:
        ctx.print("Description:")
        ctx.print(f"  {incident.description}")
        ctx.print("")

    ctx.print("Dates:")
    ctx.print(f"  Created: {incident.created_at.isoformat() if incident.created_at else 'N/A'}")
    ctx.print(f"  Updated: {incident.updated_at.isoformat() if incident.updated_at else 'N/A'}")
    if incident.resolved_at:
        ctx.print(f"  Resolved: {incident.resolved_at.isoformat()}")
    ctx.print("")

    if incident.resolution:
        ctx.print("Resolution:")
        ctx.print(f"  {incident.resolution}")
        if incident.root_cause:
            ctx.print(f"  Root Cause: {incident.root_cause}")
        ctx.print("")

    if incident.tags:
        ctx.print(f"Tags: {', '.join(incident.tags)}")
        ctx.print("")

    if incident.evidence:
        ctx.print("Evidence:")
        for key, value in incident.evidence.items():
            ctx.print(f"  {key}: {value}")
        ctx.print("")

    if timeline:
        ctx.print("Timeline:")
        for entry in timeline:
            ctx.print(f"  [{entry.timestamp.isoformat()[:16]}] {entry.event_type.value}")
            if entry.new_value:
                ctx.print(f"      {entry.new_value}")
        ctx.print("")

    if comments:
        ctx.print("Comments:")
        for comment in comments:
            ctx.print(f"  [{comment.created_at.isoformat()[:16]}] {comment.author}:")
            ctx.print(f"      {comment.content}")
        ctx.print("")
