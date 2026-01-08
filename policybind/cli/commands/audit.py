"""
Audit commands for PolicyBind CLI.

This module implements the 'policybind audit' commands for querying
and exporting enforcement logs and audit trails.

Usage:
    policybind audit query [--user USER] [--decision DECISION] [--start DATE]
    policybind audit stats [--start DATE] [--end DATE]
    policybind audit export [--format json|csv] [--output FILE]
"""

import argparse
import csv
import io
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the audit command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "audit",
        help="Query and export audit logs",
        description=(
            "Query and export enforcement logs and audit trails. "
            "View request decisions, policy enforcement, and usage patterns."
        ),
    )

    audit_subparsers = parser.add_subparsers(
        dest="audit_command",
        help="Audit command to execute",
    )

    # audit query
    query_parser = audit_subparsers.add_parser(
        "query",
        help="Query enforcement logs",
        description="Search and filter enforcement log entries.",
    )
    query_parser.add_argument(
        "--user",
        help="Filter by user ID",
    )
    query_parser.add_argument(
        "--department",
        help="Filter by department",
    )
    query_parser.add_argument(
        "--decision",
        choices=["ALLOW", "DENY", "MODIFY"],
        help="Filter by decision",
    )
    query_parser.add_argument(
        "--deployment",
        help="Filter by deployment ID",
    )
    query_parser.add_argument(
        "--start",
        help="Start date (ISO format or days ago, e.g., '7d')",
    )
    query_parser.add_argument(
        "--end",
        help="End date (ISO format or days ago)",
    )
    query_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of results (default: 50)",
    )
    query_parser.set_defaults(func=run_audit_query)

    # audit stats
    stats_parser = audit_subparsers.add_parser(
        "stats",
        help="Show enforcement statistics",
        description="Display statistics on enforcement decisions.",
    )
    stats_parser.add_argument(
        "--start",
        help="Start date (ISO format or days ago, e.g., '30d')",
        default="30d",
    )
    stats_parser.add_argument(
        "--end",
        help="End date (ISO format)",
    )
    stats_parser.set_defaults(func=run_audit_stats)

    # audit export
    export_parser = audit_subparsers.add_parser(
        "export",
        help="Export audit logs",
        description="Export enforcement logs to JSON or CSV for reporting.",
    )
    export_parser.add_argument(
        "--export-format",
        choices=["json", "csv"],
        default="json",
        help="Export format (default: json)",
    )
    export_parser.add_argument(
        "--start",
        help="Start date (ISO format or days ago)",
        default="7d",
    )
    export_parser.add_argument(
        "--end",
        help="End date (ISO format)",
    )
    export_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (stdout if not specified)",
    )
    export_parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum number of records (default: 1000)",
    )
    export_parser.set_defaults(func=run_audit_export)

    # audit show
    show_parser = audit_subparsers.add_parser(
        "show",
        help="Show a specific log entry",
        description="Display details of a specific enforcement log entry.",
    )
    show_parser.add_argument(
        "log_id",
        help="Log entry ID",
    )
    show_parser.set_defaults(func=run_audit_show)

    parser.set_defaults(func=run_audit)


def run_audit(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute audit command (shows help if no subcommand)."""
    from policybind.cli.main import EXIT_ERROR

    if not args.audit_command:
        ctx.print_error("No audit command specified. Use --help for usage.")
        return EXIT_ERROR

    return EXIT_ERROR


def _parse_date(date_str: str | None, default_days_ago: int = 0) -> datetime | None:
    """
    Parse a date string that can be ISO format or relative (e.g., '7d').

    Args:
        date_str: Date string or None.
        default_days_ago: Default number of days ago if None.

    Returns:
        Parsed datetime or None.
    """
    from policybind.models.base import utc_now

    if date_str is None:
        if default_days_ago > 0:
            return utc_now() - timedelta(days=default_days_ago)
        return None

    # Check for relative format (e.g., '7d', '30d')
    if date_str.endswith("d") and date_str[:-1].isdigit():
        days = int(date_str[:-1])
        return utc_now() - timedelta(days=days)

    # Try ISO format
    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        return None


def run_audit_query(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the audit query command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.storage.repositories import AuditRepository

    try:
        repository = AuditRepository(ctx.database)

        # Parse dates
        start_date = _parse_date(args.start, default_days_ago=7)
        end_date = _parse_date(args.end)

        # Query logs
        logs = repository.query_enforcement_logs(
            start_date=start_date,
            end_date=end_date,
            user_id=args.user,
            department=args.department,
            decision=args.decision,
            deployment_id=args.deployment,
            limit=args.limit,
        )

        if ctx.output_format == "table":
            if not logs:
                ctx.print("No enforcement logs found matching criteria.")
            else:
                ctx.print("Enforcement Logs")
                ctx.print("=" * 80)
                ctx.print("")
                for log in logs:
                    decision_marker = (
                        "[ALLOW]" if log["decision"] == "ALLOW" else
                        "[DENY]" if log["decision"] == "DENY" else "[MODIFY]"
                    )
                    ctx.print(f"{decision_marker} {log['request_id']}")
                    ctx.print(f"    Time: {log['timestamp']}")
                    ctx.print(f"    User: {log['user_id']} ({log['department']})")
                    ctx.print(f"    Model: {log['provider']}/{log['model']}")
                    if log.get("applied_rules"):
                        ctx.print(f"    Rules: {', '.join(log['applied_rules'])}")
                    ctx.print("")
                ctx.print(f"Total: {len(logs)} log(s)")
        else:
            output = format_output(logs, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to query audit logs: {e}")
        return EXIT_ERROR


def run_audit_stats(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the audit stats command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.base import utc_now
    from policybind.storage.repositories import AuditRepository

    try:
        repository = AuditRepository(ctx.database)

        # Parse dates
        start_date = _parse_date(args.start, default_days_ago=30)
        end_date = _parse_date(args.end) or utc_now()

        if start_date is None:
            ctx.print_error("Invalid start date")
            return EXIT_ERROR

        # Get statistics
        stats = repository.get_enforcement_stats(start_date, end_date)

        if ctx.output_format == "table":
            ctx.print("Enforcement Statistics")
            ctx.print("=" * 50)
            ctx.print("")
            ctx.print(f"Period: {stats['period_start'][:10]} to {stats['period_end'][:10]}")
            ctx.print("")
            ctx.print(f"Total Requests: {stats['total_requests']}")
            ctx.print("")
            ctx.print("By Decision:")
            for decision, count in stats.get("by_decision", {}).items():
                percentage = (count / stats["total_requests"] * 100) if stats["total_requests"] > 0 else 0
                ctx.print(f"  {decision}: {count} ({percentage:.1f}%)")
        else:
            output = format_output(stats, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to get statistics: {e}")
        return EXIT_ERROR


def run_audit_export(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the audit export command."""
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.base import utc_now
    from policybind.storage.repositories import AuditRepository

    try:
        repository = AuditRepository(ctx.database)

        # Parse dates
        start_date = _parse_date(args.start, default_days_ago=7)
        end_date = _parse_date(args.end) or utc_now()

        # Query logs
        logs = repository.query_enforcement_logs(
            start_date=start_date,
            end_date=end_date,
            limit=args.limit,
        )

        # Format output
        if args.export_format == "json":
            output_text = json.dumps(logs, indent=2, default=str)
        else:  # csv
            output_buffer = io.StringIO()
            if logs:
                # Flatten for CSV
                fieldnames = [
                    "id", "request_id", "timestamp", "provider", "model",
                    "user_id", "department", "decision", "reason",
                    "applied_rules", "enforcement_time_ms",
                ]
                writer = csv.DictWriter(output_buffer, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for log in logs:
                    # Flatten applied_rules to string
                    row = dict(log)
                    if row.get("applied_rules"):
                        row["applied_rules"] = ",".join(row["applied_rules"])
                    writer.writerow(row)
            output_text = output_buffer.getvalue()

        # Write output
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_text)
            ctx.print(f"Exported {len(logs)} log entries to {args.output}")
        else:
            ctx.print(output_text)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to export audit logs: {e}")
        return EXIT_ERROR


def run_audit_show(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the audit show command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    try:
        # Query by ID
        logs = ctx.database.execute(
            "SELECT * FROM enforcement_log WHERE id = ?",
            (args.log_id,),
        )

        if not logs:
            ctx.print_error(f"Log entry not found: {args.log_id}")
            return EXIT_ERROR

        log = logs[0]

        # Deserialize JSON fields
        import json as json_module
        for field in ["data_classification", "applied_rules", "modifications", "warnings", "request_metadata", "response_metadata"]:
            if log.get(field) and isinstance(log[field], str):
                try:
                    log[field] = json_module.loads(log[field])
                except json_module.JSONDecodeError:
                    pass

        if ctx.output_format == "table":
            ctx.print("Enforcement Log Entry")
            ctx.print("=" * 60)
            ctx.print("")
            ctx.print(f"ID: {log['id']}")
            ctx.print(f"Request ID: {log['request_id']}")
            ctx.print(f"Timestamp: {log['timestamp']}")
            ctx.print("")
            ctx.print("Request:")
            ctx.print(f"  Provider: {log['provider']}")
            ctx.print(f"  Model: {log['model']}")
            ctx.print(f"  User: {log['user_id']}")
            ctx.print(f"  Department: {log['department']}")
            ctx.print(f"  Source App: {log.get('source_application', 'N/A')}")
            ctx.print(f"  Use Case: {log.get('intended_use_case', 'N/A')}")
            ctx.print("")
            ctx.print("Decision:")
            ctx.print(f"  Result: {log['decision']}")
            ctx.print(f"  Reason: {log['reason']}")
            if log.get("applied_rules"):
                ctx.print(f"  Applied Rules: {', '.join(log['applied_rules'])}")
            if log.get("warnings"):
                ctx.print(f"  Warnings: {', '.join(log['warnings'])}")
            ctx.print("")
            ctx.print("Metrics:")
            ctx.print(f"  Estimated Tokens: {log.get('estimated_tokens', 0)}")
            ctx.print(f"  Estimated Cost: ${log.get('estimated_cost', 0):.4f}")
            ctx.print(f"  Enforcement Time: {log.get('enforcement_time_ms', 0):.2f}ms")
        else:
            output = format_output(log, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to show log entry: {e}")
        return EXIT_ERROR
