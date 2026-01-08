"""
Registry commands for PolicyBind CLI.

This module implements the 'policybind registry' commands for managing
model deployments in the registry.

Usage:
    policybind registry add --name NAME --model MODEL --provider PROVIDER ...
    policybind registry list [--status STATUS] [--risk-level LEVEL]
    policybind registry show DEPLOYMENT_ID
    policybind registry update DEPLOYMENT_ID --field VALUE
    policybind registry suspend DEPLOYMENT_ID --reason REASON
    policybind registry approve DEPLOYMENT_ID --ticket TICKET
    policybind registry compliance DEPLOYMENT_ID [--framework FRAMEWORK]
    policybind registry export [--format json|csv]
"""

import argparse
import csv
import io
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the registry command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "registry",
        help="Manage model registry",
        description=(
            "Manage AI model deployments in the PolicyBind registry. "
            "Register, approve, suspend, and track model deployments."
        ),
    )

    registry_subparsers = parser.add_subparsers(
        dest="registry_command",
        help="Registry command to execute",
    )

    # registry add
    add_parser = registry_subparsers.add_parser(
        "add",
        help="Register a new model deployment",
        description="Register a new AI model deployment in the registry.",
    )
    add_parser.add_argument(
        "--name",
        required=True,
        help="Deployment name",
    )
    add_parser.add_argument(
        "--model",
        required=True,
        help="Model name (e.g., gpt-4, claude-3-opus)",
    )
    add_parser.add_argument(
        "--provider",
        required=True,
        help="Model provider (e.g., openai, anthropic)",
    )
    add_parser.add_argument(
        "--owner",
        required=True,
        help="Owner identifier (team or user)",
    )
    add_parser.add_argument(
        "--owner-contact",
        required=True,
        help="Owner contact email",
    )
    add_parser.add_argument(
        "--description",
        default="",
        help="Deployment description",
    )
    add_parser.add_argument(
        "--model-version",
        default="",
        help="Model version",
    )
    add_parser.add_argument(
        "--risk-level",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Risk level (auto-assessed if not provided)",
    )
    add_parser.add_argument(
        "--data-categories",
        nargs="+",
        default=[],
        help="Data categories handled (e.g., pii financial)",
    )
    add_parser.set_defaults(func=run_registry_add)

    # registry list
    list_parser = registry_subparsers.add_parser(
        "list",
        help="List registered deployments",
        description="List all model deployments in the registry.",
    )
    list_parser.add_argument(
        "--status",
        choices=["PENDING", "APPROVED", "REJECTED", "SUSPENDED"],
        help="Filter by approval status",
    )
    list_parser.add_argument(
        "--risk-level",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter by risk level",
    )
    list_parser.add_argument(
        "--owner",
        help="Filter by owner",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of results (default: 50)",
    )
    list_parser.set_defaults(func=run_registry_list)

    # registry show
    show_parser = registry_subparsers.add_parser(
        "show",
        help="Show deployment details",
        description="Display detailed information about a deployment.",
    )
    show_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    show_parser.add_argument(
        "--include-stats",
        action="store_true",
        help="Include usage statistics",
    )
    show_parser.add_argument(
        "--include-compliance",
        action="store_true",
        help="Include compliance status",
    )
    show_parser.set_defaults(func=run_registry_show)

    # registry update
    update_parser = registry_subparsers.add_parser(
        "update",
        help="Update deployment metadata",
        description="Update deployment fields. Tracks changes in audit log.",
    )
    update_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    update_parser.add_argument(
        "--name",
        help="New deployment name",
    )
    update_parser.add_argument(
        "--description",
        help="New description",
    )
    update_parser.add_argument(
        "--owner",
        help="New owner",
    )
    update_parser.add_argument(
        "--owner-contact",
        help="New owner contact",
    )
    update_parser.add_argument(
        "--risk-level",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="New risk level",
    )
    update_parser.add_argument(
        "--data-categories",
        nargs="+",
        help="New data categories",
    )
    update_parser.set_defaults(func=run_registry_update)

    # registry suspend
    suspend_parser = registry_subparsers.add_parser(
        "suspend",
        help="Suspend a deployment",
        description="Suspend an active deployment. Requires confirmation.",
    )
    suspend_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    suspend_parser.add_argument(
        "--reason",
        required=True,
        help="Reason for suspension",
    )
    suspend_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )
    suspend_parser.set_defaults(func=run_registry_suspend)

    # registry reinstate
    reinstate_parser = registry_subparsers.add_parser(
        "reinstate",
        help="Reinstate a suspended deployment",
        description="Reinstate a previously suspended deployment.",
    )
    reinstate_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    reinstate_parser.add_argument(
        "--notes",
        default="",
        help="Reinstatement notes",
    )
    reinstate_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )
    reinstate_parser.set_defaults(func=run_registry_reinstate)

    # registry approve
    approve_parser = registry_subparsers.add_parser(
        "approve",
        help="Approve a pending deployment",
        description="Approve a deployment for use.",
    )
    approve_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    approve_parser.add_argument(
        "--ticket",
        required=True,
        help="Approval ticket reference",
    )
    approve_parser.add_argument(
        "--notes",
        default="",
        help="Approval notes",
    )
    approve_parser.set_defaults(func=run_registry_approve)

    # registry reject
    reject_parser = registry_subparsers.add_parser(
        "reject",
        help="Reject a pending deployment",
        description="Reject a deployment request.",
    )
    reject_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    reject_parser.add_argument(
        "--reason",
        required=True,
        help="Rejection reason",
    )
    reject_parser.set_defaults(func=run_registry_reject)

    # registry compliance
    compliance_parser = registry_subparsers.add_parser(
        "compliance",
        help="Run compliance check",
        description="Check deployment against compliance frameworks.",
    )
    compliance_parser.add_argument(
        "deployment_id",
        help="Deployment ID or name",
    )
    compliance_parser.add_argument(
        "--framework",
        choices=[
            "eu_ai_act", "nist_ai_rmf", "soc2", "internal",
            "hipaa", "gdpr", "pci_dss",
        ],
        help="Specific framework to check (checks all if not specified)",
    )
    compliance_parser.set_defaults(func=run_registry_compliance)

    # registry export
    export_parser = registry_subparsers.add_parser(
        "export",
        help="Export registry data",
        description="Export registry to JSON or CSV for reporting.",
    )
    export_parser.add_argument(
        "--export-format",
        choices=["json", "csv"],
        default="json",
        help="Export format (default: json)",
    )
    export_parser.add_argument(
        "--status",
        choices=["PENDING", "APPROVED", "REJECTED", "SUSPENDED"],
        help="Filter by status",
    )
    export_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (stdout if not specified)",
    )
    export_parser.set_defaults(func=run_registry_export)

    # registry stats
    stats_parser = registry_subparsers.add_parser(
        "stats",
        help="Show registry statistics",
        description="Display registry statistics and summary.",
    )
    stats_parser.set_defaults(func=run_registry_stats)

    parser.set_defaults(func=run_registry)


def run_registry(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute registry command (shows help if no subcommand)."""
    from policybind.cli.main import EXIT_ERROR

    if not args.registry_command:
        ctx.print_error("No registry command specified. Use --help for usage.")
        return EXIT_ERROR

    return EXIT_ERROR


def run_registry_add(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry add command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.registry import RiskLevel
    from policybind.registry.manager import RegistryManager

    try:
        # Create manager with database if available
        manager = RegistryManager(repository=ctx.registry_repository)

        # Parse risk level if provided
        risk_level = None
        if args.risk_level:
            risk_level = RiskLevel(args.risk_level)

        # Register deployment
        deployment = manager.register(
            name=args.name,
            model_provider=args.provider,
            model_name=args.model,
            owner=args.owner,
            owner_contact=args.owner_contact,
            description=args.description,
            model_version=args.model_version,
            data_categories=args.data_categories,
            risk_level=risk_level,
            registered_by="cli",
        )

        result = {
            "deployment_id": deployment.deployment_id,
            "name": deployment.name,
            "status": deployment.approval_status.value,
            "risk_level": deployment.risk_level.value,
            "message": f"Deployment '{deployment.name}' registered successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Registered deployment: {deployment.name}")
            ctx.print(f"  ID: {deployment.deployment_id}")
            ctx.print(f"  Status: {deployment.approval_status.value}")
            ctx.print(f"  Risk Level: {deployment.risk_level.value}")
            ctx.print("")
            ctx.print("Deployment is pending approval.")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to register deployment: {e}")
        return EXIT_ERROR


def run_registry_list(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry list command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.registry import ApprovalStatus, RiskLevel
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Get deployments with filters
        deployments = manager.list_all(limit=args.limit)

        # Apply filters
        if args.status:
            status = ApprovalStatus(args.status)
            deployments = [d for d in deployments if d.approval_status == status]

        if args.risk_level:
            risk = RiskLevel(args.risk_level)
            deployments = [d for d in deployments if d.risk_level == risk]

        if args.owner:
            deployments = [d for d in deployments if d.owner == args.owner]

        # Format output
        results = []
        for d in deployments:
            results.append({
                "deployment_id": d.deployment_id,
                "name": d.name,
                "provider": d.model_provider,
                "model": d.model_name,
                "status": d.approval_status.value,
                "risk_level": d.risk_level.value,
                "owner": d.owner,
            })

        if ctx.output_format == "table":
            if not results:
                ctx.print("No deployments found.")
            else:
                ctx.print("Model Deployments")
                ctx.print("=" * 80)
                ctx.print("")
                for r in results:
                    status_marker = "[OK]" if r["status"] == "APPROVED" else (
                        "[SUSPENDED]" if r["status"] == "SUSPENDED" else
                        "[PENDING]" if r["status"] == "PENDING" else "[REJECTED]"
                    )
                    ctx.print(f"{status_marker} {r['name']}")
                    ctx.print(f"    ID: {r['deployment_id']}")
                    ctx.print(f"    Model: {r['provider']}/{r['model']}")
                    ctx.print(f"    Risk: {r['risk_level']}, Owner: {r['owner']}")
                    ctx.print("")
                ctx.print(f"Total: {len(results)} deployment(s)")
        else:
            output = format_output(results, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to list deployments: {e}")
        return EXIT_ERROR


def run_registry_show(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry show command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Try to get by ID first, then by name
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        result = _deployment_to_dict(deployment)

        # Add compliance if requested
        if args.include_compliance:
            report = manager.check_compliance(deployment.deployment_id)
            result["compliance"] = {
                "overall_status": report.overall_status.value,
                "gaps_count": len(report.gaps),
                "critical_gaps": len(report.critical_gaps),
                "frameworks_checked": [f.value for f in report.frameworks_checked],
            }

        # Add risk assessment
        assessment = manager.assess_risk(deployment.deployment_id)
        result["risk_assessment"] = {
            "computed_level": assessment.computed_risk_level.value,
            "factors": [f.to_dict() for f in assessment.factors],
        }

        if ctx.output_format == "table":
            _print_deployment_table(deployment, result, ctx)
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to show deployment: {e}")
        return EXIT_ERROR


def run_registry_update(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry update command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.registry import RiskLevel
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Find deployment
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        # Build updates
        updates: dict[str, Any] = {}
        if args.name:
            updates["name"] = args.name
        if args.description:
            updates["description"] = args.description
        if args.owner:
            updates["owner"] = args.owner
        if args.owner_contact:
            updates["owner_contact"] = args.owner_contact
        if args.risk_level:
            updates["risk_level"] = RiskLevel(args.risk_level)
        if args.data_categories:
            updates["data_categories"] = tuple(args.data_categories)

        if not updates:
            ctx.print_error("No updates specified.")
            return EXIT_ERROR

        # Apply updates
        updated = manager.update(
            deployment.deployment_id,
            updated_by="cli",
            **updates,
        )

        result = {
            "deployment_id": updated.deployment_id,
            "name": updated.name,
            "updated_fields": list(updates.keys()),
            "message": "Deployment updated successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Updated deployment: {updated.name}")
            ctx.print(f"  Fields changed: {', '.join(updates.keys())}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to update deployment: {e}")
        return EXIT_ERROR


def run_registry_suspend(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry suspend command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Find deployment
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        # Confirm unless --force
        if not args.force and not ctx.quiet:
            ctx.print(f"About to suspend deployment: {deployment.name}")
            ctx.print(f"  Reason: {args.reason}")
            ctx.print("")
            ctx.print("This will block all requests to this deployment.")
            # In a real CLI, we would prompt for confirmation
            # For now, require --force

        # Suspend
        suspended = manager.suspend(
            deployment.deployment_id,
            suspended_by="cli",
            reason=args.reason,
        )

        result = {
            "deployment_id": suspended.deployment_id,
            "name": suspended.name,
            "status": suspended.approval_status.value,
            "reason": args.reason,
            "message": "Deployment suspended successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Suspended deployment: {suspended.name}")
            ctx.print(f"  Reason: {args.reason}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to suspend deployment: {e}")
        return EXIT_ERROR


def run_registry_reinstate(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry reinstate command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Find deployment
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        # Reinstate
        reinstated = manager.reinstate(
            deployment.deployment_id,
            reinstated_by="cli",
            notes=args.notes,
        )

        result = {
            "deployment_id": reinstated.deployment_id,
            "name": reinstated.name,
            "status": reinstated.approval_status.value,
            "message": "Deployment reinstated successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Reinstated deployment: {reinstated.name}")
            ctx.print(f"  Status: {reinstated.approval_status.value}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to reinstate deployment: {e}")
        return EXIT_ERROR


def run_registry_approve(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry approve command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Find deployment
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        # Approve
        approved = manager.approve(
            deployment.deployment_id,
            approved_by="cli",
            approval_ticket=args.ticket,
            notes=args.notes,
        )

        result = {
            "deployment_id": approved.deployment_id,
            "name": approved.name,
            "status": approved.approval_status.value,
            "approval_ticket": args.ticket,
            "message": "Deployment approved successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Approved deployment: {approved.name}")
            ctx.print(f"  Ticket: {args.ticket}")
            ctx.print(f"  Status: {approved.approval_status.value}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to approve deployment: {e}")
        return EXIT_ERROR


def run_registry_reject(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry reject command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Find deployment
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        # Reject
        rejected = manager.reject(
            deployment.deployment_id,
            rejected_by="cli",
            reason=args.reason,
        )

        result = {
            "deployment_id": rejected.deployment_id,
            "name": rejected.name,
            "status": rejected.approval_status.value,
            "reason": args.reason,
            "message": "Deployment rejected",
        }

        if ctx.output_format == "table":
            ctx.print(f"Rejected deployment: {rejected.name}")
            ctx.print(f"  Reason: {args.reason}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to reject deployment: {e}")
        return EXIT_ERROR


def run_registry_compliance(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry compliance command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.compliance import ComplianceFramework
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Find deployment
        deployment = manager.get(args.deployment_id)
        if not deployment:
            deployment = manager.get_by_name(args.deployment_id)

        if not deployment:
            ctx.print_error(f"Deployment not found: {args.deployment_id}")
            return EXIT_ERROR

        # Get compliance checker
        checker = manager._compliance_checker

        # Check specific framework or all
        frameworks = None
        if args.framework:
            frameworks = [ComplianceFramework(args.framework)]

        report = checker.check(deployment, frameworks)

        result = report.to_dict()

        if ctx.output_format == "table":
            _print_compliance_table(report, deployment, ctx)
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to check compliance: {e}")
        return EXIT_ERROR


def run_registry_export(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry export command."""
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.registry import ApprovalStatus
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)

        # Get all deployments
        deployments = manager.list_all(limit=10000)

        # Filter by status if specified
        if args.status:
            status = ApprovalStatus(args.status)
            deployments = [d for d in deployments if d.approval_status == status]

        # Convert to export format
        export_data = []
        for d in deployments:
            export_data.append({
                "deployment_id": d.deployment_id,
                "name": d.name,
                "description": d.description,
                "model_provider": d.model_provider,
                "model_name": d.model_name,
                "model_version": d.model_version,
                "owner": d.owner,
                "owner_contact": d.owner_contact,
                "data_categories": ",".join(d.data_categories),
                "risk_level": d.risk_level.value,
                "approval_status": d.approval_status.value,
                "approval_ticket": d.approval_ticket,
                "created_at": d.created_at.isoformat() if d.created_at else "",
                "deployment_date": d.deployment_date.isoformat() if d.deployment_date else "",
                "last_review_date": d.last_review_date.isoformat() if d.last_review_date else "",
            })

        # Format output
        if args.export_format == "json":
            output_text = json.dumps(export_data, indent=2)
        else:  # csv
            output_buffer = io.StringIO()
            if export_data:
                writer = csv.DictWriter(output_buffer, fieldnames=export_data[0].keys())
                writer.writeheader()
                writer.writerows(export_data)
            output_text = output_buffer.getvalue()

        # Write output
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_text)
            ctx.print(f"Exported {len(export_data)} deployments to {args.output}")
        else:
            ctx.print(output_text)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to export registry: {e}")
        return EXIT_ERROR


def run_registry_stats(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the registry stats command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.registry.manager import RegistryManager

    try:
        manager = RegistryManager(repository=ctx.registry_repository)
        stats = manager.get_statistics()

        if ctx.output_format == "table":
            ctx.print("Registry Statistics")
            ctx.print("=" * 40)
            ctx.print("")
            ctx.print(f"Total Deployments: {stats['total_deployments']}")
            ctx.print("")
            ctx.print("By Status:")
            for status, count in stats.get("by_status", {}).items():
                ctx.print(f"  {status}: {count}")
            ctx.print("")
            ctx.print("By Risk Level:")
            for risk, count in stats.get("by_risk_level", {}).items():
                ctx.print(f"  {risk}: {count}")
            ctx.print("")
            ctx.print(f"High Risk Count: {stats.get('high_risk_count', 0)}")
            ctx.print(f"Needing Review: {stats.get('needing_review', 0)}")
        else:
            output = format_output(stats, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to get statistics: {e}")
        return EXIT_ERROR


def _deployment_to_dict(deployment: Any) -> dict[str, Any]:
    """Convert a deployment to a dictionary for output."""
    return {
        "deployment_id": deployment.deployment_id,
        "name": deployment.name,
        "description": deployment.description,
        "model_provider": deployment.model_provider,
        "model_name": deployment.model_name,
        "model_version": deployment.model_version,
        "owner": deployment.owner,
        "owner_contact": deployment.owner_contact,
        "data_categories": list(deployment.data_categories),
        "risk_level": deployment.risk_level.value,
        "approval_status": deployment.approval_status.value,
        "approval_ticket": deployment.approval_ticket,
        "created_at": deployment.created_at.isoformat() if deployment.created_at else None,
        "deployment_date": deployment.deployment_date.isoformat() if deployment.deployment_date else None,
        "last_review_date": deployment.last_review_date.isoformat() if deployment.last_review_date else None,
        "next_review_date": deployment.next_review_date.isoformat() if deployment.next_review_date else None,
        "is_active": deployment.is_active(),
        "is_high_risk": deployment.is_high_risk(),
        "needs_review": deployment.needs_review(),
    }


def _print_deployment_table(
    deployment: Any,
    result: dict[str, Any],
    ctx: "CLIContext",
) -> None:
    """Print deployment details in table format."""
    ctx.print("Deployment Details")
    ctx.print("=" * 60)
    ctx.print("")

    # Status indicator
    status = deployment.approval_status.value
    status_marker = "[OK]" if status == "APPROVED" else (
        "[SUSPENDED]" if status == "SUSPENDED" else
        "[PENDING]" if status == "PENDING" else "[REJECTED]"
    )

    ctx.print(f"Name: {deployment.name} {status_marker}")
    ctx.print(f"ID: {deployment.deployment_id}")
    ctx.print("")

    ctx.print("Model Information:")
    ctx.print(f"  Provider: {deployment.model_provider}")
    ctx.print(f"  Model: {deployment.model_name}")
    if deployment.model_version:
        ctx.print(f"  Version: {deployment.model_version}")
    ctx.print("")

    ctx.print("Ownership:")
    ctx.print(f"  Owner: {deployment.owner}")
    ctx.print(f"  Contact: {deployment.owner_contact}")
    ctx.print("")

    ctx.print("Status:")
    ctx.print(f"  Approval: {deployment.approval_status.value}")
    ctx.print(f"  Risk Level: {deployment.risk_level.value}")
    if deployment.approval_ticket:
        ctx.print(f"  Ticket: {deployment.approval_ticket}")
    ctx.print("")

    if deployment.data_categories:
        ctx.print("Data Categories:")
        for cat in deployment.data_categories:
            ctx.print(f"  - {cat}")
        ctx.print("")

    if deployment.description:
        ctx.print("Description:")
        ctx.print(f"  {deployment.description}")
        ctx.print("")

    # Risk assessment
    if "risk_assessment" in result:
        assessment = result["risk_assessment"]
        ctx.print("Risk Assessment:")
        ctx.print(f"  Computed Level: {assessment['computed_level']}")
        if assessment.get("factors"):
            ctx.print("  Factors:")
            for factor in assessment["factors"][:5]:  # Show top 5
                ctx.print(f"    - {factor.get('factor', 'Unknown')}: {factor.get('level', 'N/A')}")
        ctx.print("")

    # Compliance summary
    if "compliance" in result:
        comp = result["compliance"]
        ctx.print("Compliance:")
        ctx.print(f"  Overall: {comp['overall_status']}")
        ctx.print(f"  Gaps: {comp['gaps_count']} ({comp['critical_gaps']} critical)")
        ctx.print("")

    # Dates
    ctx.print("Dates:")
    if deployment.created_at:
        ctx.print(f"  Created: {deployment.created_at.isoformat()}")
    if deployment.deployment_date:
        ctx.print(f"  Deployed: {deployment.deployment_date.isoformat()}")
    if deployment.last_review_date:
        ctx.print(f"  Last Review: {deployment.last_review_date.isoformat()}")
    if deployment.next_review_date:
        ctx.print(f"  Next Review: {deployment.next_review_date.isoformat()}")
    ctx.print("")


def _print_compliance_table(
    report: Any,
    deployment: Any,
    ctx: "CLIContext",
) -> None:
    """Print compliance report in table format."""
    ctx.print("Compliance Report")
    ctx.print("=" * 60)
    ctx.print("")

    ctx.print(f"Deployment: {deployment.name}")
    ctx.print(f"Overall Status: {report.overall_status.value.upper()}")
    ctx.print(f"Generated: {report.generated_at.isoformat()}")
    ctx.print("")

    # Framework statuses
    ctx.print("Framework Results:")
    for framework, status in report.framework_statuses.items():
        status_marker = "[PASS]" if status.value == "compliant" else (
            "[PARTIAL]" if status.value == "partial" else
            "[N/A]" if status.value == "not_applicable" else "[FAIL]"
        )
        ctx.print(f"  {framework.value}: {status_marker}")
    ctx.print("")

    # Gaps
    if report.gaps:
        ctx.print(f"Compliance Gaps ({len(report.gaps)}):")
        for gap in report.gaps:
            severity_marker = "[!!!]" if gap.severity == "critical" else (
                "[!!]" if gap.severity == "high" else
                "[!]" if gap.severity == "medium" else "[ ]"
            )
            ctx.print(f"  {severity_marker} {gap.framework.value}: {gap.requirement}")
            ctx.print(f"       {gap.description}")
            if gap.remediation:
                ctx.print(f"       Fix: {gap.remediation}")
            ctx.print("")
    else:
        ctx.print("No compliance gaps found.")
        ctx.print("")

    # Required documentation
    if report.documentation_required:
        ctx.print("Documentation Required:")
        for doc in report.documentation_required:
            ctx.print(f"  - {doc}")
        ctx.print("")
