"""
Status command for PolicyBind CLI.

This module implements the 'policybind status' command which displays
system status, health checks, and statistics.

Usage:
    policybind status
    policybind status --detailed
"""

import argparse
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the status command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "status",
        help="Show system status",
        description=(
            "Display PolicyBind system status including database health, "
            "policy version, and statistics."
        ),
    )
    parser.add_argument(
        "--detailed",
        "-d",
        action="store_true",
        help="Show detailed status including statistics",
    )
    parser.add_argument(
        "--check",
        "-c",
        action="store_true",
        help="Perform health checks and exit with non-zero on failure",
    )
    parser.set_defaults(func=run_status)


def run_status(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the status command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    status_data: dict[str, Any] = {}
    all_healthy = True

    # Check configuration
    config_status = _check_config(ctx)
    status_data["configuration"] = config_status
    if not config_status.get("healthy", False):
        all_healthy = False

    # Check database
    db_status = _check_database(ctx)
    status_data["database"] = db_status
    if not db_status.get("healthy", False):
        all_healthy = False

    # Check policies
    policy_status = _check_policies(ctx)
    status_data["policies"] = policy_status
    if not policy_status.get("healthy", False):
        all_healthy = False

    # Add detailed statistics if requested
    if args.detailed:
        stats = _get_statistics(ctx)
        status_data["statistics"] = stats

    # Format and display output
    if ctx.output_format == "table":
        _print_status_table(status_data, ctx, args.detailed)
    else:
        output = format_output(status_data, ctx.output_format, title="Status")
        ctx.print(output)

    # Return appropriate exit code for health check mode
    if args.check:
        return EXIT_SUCCESS if all_healthy else EXIT_ERROR

    return EXIT_SUCCESS


def _check_config(ctx: "CLIContext") -> dict[str, Any]:
    """
    Check configuration status.

    Args:
        ctx: CLI context.

    Returns:
        Configuration status dictionary.
    """
    try:
        config = ctx.config
        return {
            "healthy": True,
            "environment": config.environment,
            "path": ctx.config_path or "(default)",
            "policies_path": config.policies_path,
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e),
        }


def _check_database(ctx: "CLIContext") -> dict[str, Any]:
    """
    Check database status.

    Args:
        ctx: CLI context.

    Returns:
        Database status dictionary.
    """
    try:
        db = ctx.database

        # Check basic health
        if not db.health_check():
            return {
                "healthy": False,
                "error": "Database health check failed",
            }

        # Get detailed validation info
        validation = db.validate_connection()

        return {
            "healthy": True,
            "path": validation.get("path", "unknown"),
            "schema_version": validation.get("schema_version", 0),
            "wal_mode": validation.get("wal_mode", "unknown"),
            "table_count": validation.get("table_count", 0),
            "pool_size": validation.get("pool_size", 0),
            "pool_available": validation.get("pool_available", 0),
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e),
        }


def _check_policies(ctx: "CLIContext") -> dict[str, Any]:
    """
    Check policies status.

    Args:
        ctx: CLI context.

    Returns:
        Policies status dictionary.
    """
    try:
        config = ctx.config
        policies_path = Path(config.policies_path)

        if not policies_path.exists():
            return {
                "healthy": False,
                "error": f"Policies directory not found: {policies_path}",
            }

        # Count policy files
        yaml_files = list(policies_path.glob("**/*.yaml")) + list(
            policies_path.glob("**/*.yml")
        )

        return {
            "healthy": True,
            "path": str(policies_path),
            "file_count": len(yaml_files),
        }
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e),
        }


def _get_statistics(ctx: "CLIContext") -> dict[str, Any]:
    """
    Get system statistics.

    Args:
        ctx: CLI context.

    Returns:
        Statistics dictionary.
    """
    stats: dict[str, Any] = {}

    try:
        db = ctx.database

        # Get deployment count
        deployments = db.execute("SELECT COUNT(*) as count FROM model_registry")
        stats["deployments"] = deployments[0]["count"] if deployments else 0

        # Get token count
        tokens = db.execute(
            "SELECT COUNT(*) as count FROM tokens WHERE expires_at > ?",
            (datetime.now().isoformat(),),
        )
        stats["active_tokens"] = tokens[0]["count"] if tokens else 0

        # Get incident counts
        incidents_open = db.execute(
            "SELECT COUNT(*) as count FROM incidents WHERE status IN ('open', 'investigating')"
        )
        stats["open_incidents"] = incidents_open[0]["count"] if incidents_open else 0

        # Get recent enforcement counts
        one_day_ago = datetime.now().isoformat()
        enforcement = db.execute(
            "SELECT COUNT(*) as count FROM enforcement_log WHERE timestamp > datetime('now', '-1 day')"
        )
        stats["requests_24h"] = enforcement[0]["count"] if enforcement else 0

    except Exception as e:
        stats["error"] = str(e)

    return stats


def _print_status_table(
    status_data: dict[str, Any],
    ctx: "CLIContext",
    detailed: bool,
) -> None:
    """
    Print status in table format.

    Args:
        status_data: Status data dictionary.
        ctx: CLI context.
        detailed: Whether to show detailed output.
    """
    ctx.print("PolicyBind Status")
    ctx.print("=" * 50)
    ctx.print("")

    # Configuration section
    config = status_data.get("configuration", {})
    health_icon = "[OK]" if config.get("healthy") else "[FAIL]"
    ctx.print(f"Configuration: {health_icon}")
    if config.get("healthy"):
        ctx.print(f"  Environment: {config.get('environment', 'unknown')}")
        ctx.print(f"  Config path: {config.get('path', 'unknown')}")
        ctx.print(f"  Policies path: {config.get('policies_path', 'unknown')}")
    else:
        ctx.print(f"  Error: {config.get('error', 'Unknown error')}")
    ctx.print("")

    # Database section
    db = status_data.get("database", {})
    health_icon = "[OK]" if db.get("healthy") else "[FAIL]"
    ctx.print(f"Database: {health_icon}")
    if db.get("healthy"):
        ctx.print(f"  Path: {db.get('path', 'unknown')}")
        ctx.print(f"  Schema version: {db.get('schema_version', 0)}")
        ctx.print(f"  WAL mode: {db.get('wal_mode', 'unknown')}")
        ctx.print(f"  Tables: {db.get('table_count', 0)}")
    else:
        ctx.print(f"  Error: {db.get('error', 'Unknown error')}")
    ctx.print("")

    # Policies section
    policies = status_data.get("policies", {})
    health_icon = "[OK]" if policies.get("healthy") else "[FAIL]"
    ctx.print(f"Policies: {health_icon}")
    if policies.get("healthy"):
        ctx.print(f"  Path: {policies.get('path', 'unknown')}")
        ctx.print(f"  Policy files: {policies.get('file_count', 0)}")
    else:
        ctx.print(f"  Error: {policies.get('error', 'Unknown error')}")

    # Statistics section (detailed only)
    if detailed and "statistics" in status_data:
        ctx.print("")
        ctx.print("Statistics:")
        stats = status_data["statistics"]
        if "error" in stats:
            ctx.print(f"  Error: {stats['error']}")
        else:
            ctx.print(f"  Registered deployments: {stats.get('deployments', 0)}")
            ctx.print(f"  Active tokens: {stats.get('active_tokens', 0)}")
            ctx.print(f"  Open incidents: {stats.get('open_incidents', 0)}")
            ctx.print(f"  Requests (24h): {stats.get('requests_24h', 0)}")

    ctx.print("")
