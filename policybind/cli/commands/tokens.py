"""
Token commands for PolicyBind CLI.

This module implements the 'policybind token' commands for managing
access tokens for AI API authorization.

Usage:
    policybind token create --name NAME --subject SUBJECT ...
    policybind token list [--subject SUBJECT] [--expired]
    policybind token show TOKEN_ID
    policybind token revoke TOKEN_ID --reason REASON
    policybind token validate TOKEN_VALUE
    policybind token templates [show TEMPLATE]
"""

import argparse
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the token command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "token",
        help="Manage access tokens",
        description=(
            "Manage access tokens for AI API authorization. "
            "Create, validate, and revoke tokens with specific permissions."
        ),
    )

    token_subparsers = parser.add_subparsers(
        dest="token_command",
        help="Token command to execute",
    )

    # token create
    create_parser = token_subparsers.add_parser(
        "create",
        help="Create a new access token",
        description="Create a new access token with specified permissions.",
    )
    create_parser.add_argument(
        "--name",
        required=True,
        help="Token name",
    )
    create_parser.add_argument(
        "--subject",
        required=True,
        help="Who/what this token is for (user, service)",
    )
    create_parser.add_argument(
        "--expires",
        type=int,
        default=30,
        help="Expiration in days (default: 30)",
    )
    create_parser.add_argument(
        "--template",
        help="Use a predefined permission template",
    )
    create_parser.add_argument(
        "--description",
        default="",
        help="Token description",
    )
    create_parser.add_argument(
        "--budget",
        type=float,
        help="Budget limit in USD",
    )
    create_parser.add_argument(
        "--budget-period",
        choices=["hourly", "daily", "weekly", "monthly", "yearly"],
        default="monthly",
        help="Budget period (default: monthly)",
    )
    create_parser.add_argument(
        "--allowed-models",
        nargs="+",
        help="Allowed model patterns",
    )
    create_parser.add_argument(
        "--allowed-providers",
        nargs="+",
        help="Allowed provider patterns",
    )
    create_parser.add_argument(
        "--tags",
        nargs="+",
        help="Tags for categorization",
    )
    create_parser.set_defaults(func=run_token_create)

    # token list
    list_parser = token_subparsers.add_parser(
        "list",
        help="List tokens",
        description="List all access tokens.",
    )
    list_parser.add_argument(
        "--subject",
        help="Filter by subject",
    )
    list_parser.add_argument(
        "--status",
        choices=["active", "expired", "revoked", "suspended"],
        help="Filter by status",
    )
    list_parser.add_argument(
        "--expired",
        action="store_true",
        help="Include expired tokens",
    )
    list_parser.add_argument(
        "--issuer",
        help="Filter by issuer",
    )
    list_parser.set_defaults(func=run_token_list)

    # token show
    show_parser = token_subparsers.add_parser(
        "show",
        help="Show token details",
        description="Display detailed information about a token (not the token value).",
    )
    show_parser.add_argument(
        "token_id",
        help="Token ID",
    )
    show_parser.add_argument(
        "--include-usage",
        action="store_true",
        help="Include usage statistics",
    )
    show_parser.set_defaults(func=run_token_show)

    # token revoke
    revoke_parser = token_subparsers.add_parser(
        "revoke",
        help="Revoke a token",
        description="Revoke an access token, preventing further use.",
    )
    revoke_parser.add_argument(
        "token_id",
        help="Token ID",
    )
    revoke_parser.add_argument(
        "--reason",
        required=True,
        help="Reason for revocation",
    )
    revoke_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt",
    )
    revoke_parser.set_defaults(func=run_token_revoke)

    # token validate
    validate_parser = token_subparsers.add_parser(
        "validate",
        help="Validate a token",
        description="Validate a token value and show its permissions.",
    )
    validate_parser.add_argument(
        "token_value",
        help="Token value to validate",
    )
    validate_parser.set_defaults(func=run_token_validate)

    # token renew
    renew_parser = token_subparsers.add_parser(
        "renew",
        help="Renew a token",
        description="Extend token expiration.",
    )
    renew_parser.add_argument(
        "token_id",
        help="Token ID",
    )
    renew_parser.add_argument(
        "--expires",
        type=int,
        default=30,
        help="New expiration in days from now (default: 30)",
    )
    renew_parser.set_defaults(func=run_token_renew)

    # token suspend
    suspend_parser = token_subparsers.add_parser(
        "suspend",
        help="Suspend a token",
        description="Temporarily suspend a token.",
    )
    suspend_parser.add_argument(
        "token_id",
        help="Token ID",
    )
    suspend_parser.add_argument(
        "--reason",
        required=True,
        help="Reason for suspension",
    )
    suspend_parser.set_defaults(func=run_token_suspend)

    # token unsuspend
    unsuspend_parser = token_subparsers.add_parser(
        "unsuspend",
        help="Unsuspend a token",
        description="Remove suspension from a token.",
    )
    unsuspend_parser.add_argument(
        "token_id",
        help="Token ID",
    )
    unsuspend_parser.set_defaults(func=run_token_unsuspend)

    # token templates
    templates_parser = token_subparsers.add_parser(
        "templates",
        help="List permission templates",
        description="List available permission templates.",
    )
    templates_parser.add_argument(
        "template_name",
        nargs="?",
        help="Show details of a specific template",
    )
    templates_parser.set_defaults(func=run_token_templates)

    # token stats
    stats_parser = token_subparsers.add_parser(
        "stats",
        help="Show token statistics",
        description="Display overall token statistics.",
    )
    stats_parser.set_defaults(func=run_token_stats)

    parser.set_defaults(func=run_token)


def run_token(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute token command (shows help if no subcommand)."""
    from policybind.cli.main import EXIT_ERROR

    if not args.token_command:
        ctx.print_error("No token command specified. Use --help for usage.")
        return EXIT_ERROR

    return EXIT_ERROR


def run_token_create(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token create command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager
    from policybind.tokens.models import BudgetPeriod, TokenPermissions
    from policybind.tokens.templates import get_default_registry

    try:
        manager = TokenManager()

        # Build permissions
        permissions = TokenPermissions()

        # Use template if specified
        if args.template:
            registry = get_default_registry()
            template = registry.get(args.template)
            if not template:
                ctx.print_error(f"Template not found: {args.template}")
                return EXIT_ERROR
            permissions = template.create_permissions()

        # Apply overrides from arguments
        if args.budget is not None:
            permissions.budget_limit = args.budget
        if args.budget_period:
            permissions.budget_period = BudgetPeriod(args.budget_period)
        if args.allowed_models:
            permissions.allowed_models = args.allowed_models
        if args.allowed_providers:
            permissions.allowed_providers = args.allowed_providers

        # Create token
        result = manager.create_token(
            name=args.name,
            subject=args.subject,
            permissions=permissions,
            expires_in_days=args.expires,
            description=args.description,
            tags=args.tags or [],
            issuer="cli",
        )

        output_data = {
            "token_id": result.token.token_id,
            "name": result.token.name,
            "subject": result.token.subject,
            "status": result.token.status.value,
            "expires_at": result.token.expires_at.isoformat() if result.token.expires_at else None,
            "plaintext_token": result.plaintext_token,
            "message": "Token created successfully. Store the token value securely - it will not be shown again.",
        }

        if ctx.output_format == "table":
            ctx.print("Token Created Successfully")
            ctx.print("=" * 60)
            ctx.print("")
            ctx.print(f"Token ID: {result.token.token_id}")
            ctx.print(f"Name: {result.token.name}")
            ctx.print(f"Subject: {result.token.subject}")
            ctx.print(f"Expires: {result.token.expires_at.isoformat() if result.token.expires_at else 'Never'}")
            ctx.print("")
            ctx.print("Token Value (store securely - only shown once):")
            ctx.print(f"  {result.plaintext_token}")
            ctx.print("")
            if permissions.budget_limit:
                ctx.print(f"Budget: ${permissions.budget_limit:.2f}/{permissions.budget_period.value}")
            if permissions.allowed_models:
                ctx.print(f"Allowed Models: {', '.join(permissions.allowed_models)}")
        else:
            output = format_output(output_data, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to create token: {e}")
        return EXIT_ERROR


def run_token_list(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token list command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager
    from policybind.tokens.models import TokenStatus

    try:
        manager = TokenManager()

        # Parse status filter
        status = None
        if args.status:
            status = TokenStatus(args.status)

        # List tokens
        tokens = manager.list_tokens(
            subject=args.subject,
            status=status,
            issuer=args.issuer,
            include_expired=args.expired,
        )

        results = []
        for token in tokens:
            results.append({
                "token_id": token.token_id,
                "name": token.name,
                "subject": token.subject,
                "status": token.status.value,
                "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                "issued_at": token.issued_at.isoformat(),
                "issuer": token.issuer,
            })

        if ctx.output_format == "table":
            if not results:
                ctx.print("No tokens found.")
            else:
                ctx.print("Access Tokens")
                ctx.print("=" * 70)
                ctx.print("")
                for r in results:
                    status_marker = "[ACTIVE]" if r["status"] == "active" else (
                        "[REVOKED]" if r["status"] == "revoked" else
                        "[EXPIRED]" if r["status"] == "expired" else "[SUSPENDED]"
                    )
                    ctx.print(f"{status_marker} {r['name']}")
                    ctx.print(f"    ID: {r['token_id']}")
                    ctx.print(f"    Subject: {r['subject']}")
                    ctx.print(f"    Expires: {r['expires_at'] or 'Never'}")
                    ctx.print("")
                ctx.print(f"Total: {len(results)} token(s)")
        else:
            output = format_output(results, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to list tokens: {e}")
        return EXIT_ERROR


def run_token_show(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token show command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        token = manager.get_token(args.token_id)

        if not token:
            ctx.print_error(f"Token not found: {args.token_id}")
            return EXIT_ERROR

        result = token.to_dict(exclude_hash=True)

        # Add usage stats if requested
        if args.include_usage:
            stats = manager.get_usage_stats(args.token_id)
            if stats:
                result["usage"] = stats.to_dict()

            remaining = manager.get_remaining_budget(args.token_id)
            if remaining is not None:
                result["remaining_budget"] = remaining

        if ctx.output_format == "table":
            _print_token_table(token, result, ctx)
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to show token: {e}")
        return EXIT_ERROR


def run_token_revoke(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token revoke command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        token = manager.get_token(args.token_id)

        if not token:
            ctx.print_error(f"Token not found: {args.token_id}")
            return EXIT_ERROR

        success = manager.revoke_token(
            args.token_id,
            revoked_by="cli",
            reason=args.reason,
        )

        if not success:
            ctx.print_error("Failed to revoke token.")
            return EXIT_ERROR

        result = {
            "token_id": args.token_id,
            "name": token.name,
            "status": "revoked",
            "reason": args.reason,
            "message": "Token revoked successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Revoked token: {token.name}")
            ctx.print(f"  ID: {args.token_id}")
            ctx.print(f"  Reason: {args.reason}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to revoke token: {e}")
        return EXIT_ERROR


def run_token_validate(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token validate command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        token = manager.validate_token(args.token_value)

        if not token:
            result = {
                "valid": False,
                "message": "Token is invalid, expired, or revoked",
            }

            if ctx.output_format == "table":
                ctx.print("Token Validation: INVALID")
                ctx.print("  The token is invalid, expired, or has been revoked.")
            else:
                output = format_output(result, ctx.output_format)
                ctx.print(output)

            return EXIT_ERROR

        result = {
            "valid": True,
            "token_id": token.token_id,
            "name": token.name,
            "subject": token.subject,
            "status": token.status.value,
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "permissions": token.permissions.to_dict(),
        }

        if ctx.output_format == "table":
            ctx.print("Token Validation: VALID")
            ctx.print("")
            ctx.print(f"Name: {token.name}")
            ctx.print(f"Subject: {token.subject}")
            ctx.print(f"Expires: {token.expires_at.isoformat() if token.expires_at else 'Never'}")
            ctx.print("")
            ctx.print("Permissions:")
            if token.permissions.allowed_models:
                ctx.print(f"  Allowed Models: {', '.join(token.permissions.allowed_models)}")
            if token.permissions.budget_limit:
                ctx.print(f"  Budget: ${token.permissions.budget_limit:.2f}/{token.permissions.budget_period.value}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to validate token: {e}")
        return EXIT_ERROR


def run_token_renew(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token renew command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        token = manager.renew_token(
            args.token_id,
            renewed_by="cli",
            expires_in_days=args.expires,
        )

        if not token:
            ctx.print_error(f"Token not found or cannot be renewed: {args.token_id}")
            return EXIT_ERROR

        result = {
            "token_id": token.token_id,
            "name": token.name,
            "new_expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "message": "Token renewed successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Renewed token: {token.name}")
            ctx.print(f"  New expiration: {token.expires_at.isoformat() if token.expires_at else 'Never'}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to renew token: {e}")
        return EXIT_ERROR


def run_token_suspend(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token suspend command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        success = manager.suspend_token(
            args.token_id,
            suspended_by="cli",
            reason=args.reason,
        )

        if not success:
            ctx.print_error(f"Token not found or cannot be suspended: {args.token_id}")
            return EXIT_ERROR

        token = manager.get_token(args.token_id)
        result = {
            "token_id": args.token_id,
            "name": token.name if token else "",
            "status": "suspended",
            "reason": args.reason,
            "message": "Token suspended successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Suspended token: {token.name if token else args.token_id}")
            ctx.print(f"  Reason: {args.reason}")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to suspend token: {e}")
        return EXIT_ERROR


def run_token_unsuspend(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token unsuspend command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        success = manager.unsuspend_token(
            args.token_id,
            unsuspended_by="cli",
        )

        if not success:
            ctx.print_error(f"Token not found or not suspended: {args.token_id}")
            return EXIT_ERROR

        token = manager.get_token(args.token_id)
        result = {
            "token_id": args.token_id,
            "name": token.name if token else "",
            "status": "active",
            "message": "Token unsuspended successfully",
        }

        if ctx.output_format == "table":
            ctx.print(f"Unsuspended token: {token.name if token else args.token_id}")
            ctx.print("  Status: active")
        else:
            output = format_output(result, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to unsuspend token: {e}")
        return EXIT_ERROR


def run_token_templates(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token templates command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.templates import get_default_registry

    try:
        registry = get_default_registry()

        if args.template_name:
            # Show specific template
            template = registry.get(args.template_name)
            if not template:
                ctx.print_error(f"Template not found: {args.template_name}")
                return EXIT_ERROR

            result = template.to_dict()

            if ctx.output_format == "table":
                ctx.print(f"Template: {template.display_name}")
                ctx.print("=" * 60)
                ctx.print("")
                ctx.print(f"Name: {template.name}")
                ctx.print(f"Category: {template.category.value}")
                ctx.print(f"Description: {template.description}")
                ctx.print("")
                ctx.print("Permissions:")
                perms = template.permissions
                if perms.allowed_models:
                    ctx.print(f"  Allowed Models: {', '.join(perms.allowed_models)}")
                if perms.denied_models:
                    ctx.print(f"  Denied Models: {', '.join(perms.denied_models)}")
                if perms.allowed_providers:
                    ctx.print(f"  Allowed Providers: {', '.join(perms.allowed_providers)}")
                if perms.allowed_use_cases:
                    ctx.print(f"  Allowed Use Cases: {', '.join(perms.allowed_use_cases)}")
                if perms.denied_use_cases:
                    ctx.print(f"  Denied Use Cases: {', '.join(perms.denied_use_cases)}")
                if perms.budget_limit:
                    ctx.print(f"  Budget: ${perms.budget_limit:.2f}/{perms.budget_period.value}")
                if perms.rate_limit:
                    ctx.print(f"  Rate Limit: {perms.rate_limit.max_requests} requests/{perms.rate_limit.period_seconds}s")
                ctx.print("")
                if template.tags:
                    ctx.print(f"Tags: {', '.join(template.tags)}")
            else:
                output = format_output(result, ctx.output_format)
                ctx.print(output)
        else:
            # List all templates
            templates = registry.list_all()
            results = []
            for t in templates:
                results.append({
                    "name": t.name,
                    "display_name": t.display_name,
                    "category": t.category.value,
                    "description": t.description[:50] + "..." if len(t.description) > 50 else t.description,
                    "tags": t.tags,
                })

            if ctx.output_format == "table":
                ctx.print("Permission Templates")
                ctx.print("=" * 70)
                ctx.print("")
                for r in results:
                    ctx.print(f"{r['name']}")
                    ctx.print(f"    {r['display_name']} [{r['category']}]")
                    ctx.print(f"    {r['description']}")
                    ctx.print("")
                ctx.print(f"Total: {len(results)} template(s)")
                ctx.print("")
                ctx.print("Use 'policybind token templates TEMPLATE_NAME' to see details")
            else:
                output = format_output(results, ctx.output_format)
                ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to list templates: {e}")
        return EXIT_ERROR


def run_token_stats(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """Execute the token stats command."""
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.tokens.manager import TokenManager

    try:
        manager = TokenManager()
        stats = manager.get_statistics()

        if ctx.output_format == "table":
            ctx.print("Token Statistics")
            ctx.print("=" * 40)
            ctx.print("")
            ctx.print(f"Total Tokens: {stats['total_tokens']}")
            ctx.print(f"  Active: {stats['active_tokens']}")
            ctx.print(f"  Expired: {stats['expired_tokens']}")
            ctx.print(f"  Revoked: {stats['revoked_tokens']}")
            ctx.print(f"  Suspended: {stats['suspended_tokens']}")
            ctx.print("")
            ctx.print(f"Total Requests: {stats['total_requests']}")
            ctx.print(f"Total Cost: ${stats['total_cost']:.2f}")
            ctx.print(f"Denied Requests: {stats['total_denied_requests']}")
        else:
            output = format_output(stats, ctx.output_format)
            ctx.print(output)

        return EXIT_SUCCESS

    except Exception as e:
        ctx.print_error(f"Failed to get statistics: {e}")
        return EXIT_ERROR


def _print_token_table(
    token: Any,
    result: dict[str, Any],
    ctx: "CLIContext",
) -> None:
    """Print token details in table format."""
    ctx.print("Token Details")
    ctx.print("=" * 60)
    ctx.print("")

    status_marker = "[ACTIVE]" if token.status.value == "active" else (
        "[REVOKED]" if token.status.value == "revoked" else
        "[EXPIRED]" if token.status.value == "expired" else "[SUSPENDED]"
    )

    ctx.print(f"Name: {token.name} {status_marker}")
    ctx.print(f"ID: {token.token_id}")
    ctx.print("")

    ctx.print("Subject:")
    ctx.print(f"  {token.subject} ({token.subject_type})")
    ctx.print("")

    ctx.print("Status:")
    ctx.print(f"  Status: {token.status.value}")
    ctx.print(f"  Issued: {token.issued_at.isoformat()}")
    ctx.print(f"  Expires: {token.expires_at.isoformat() if token.expires_at else 'Never'}")
    if token.last_used_at:
        ctx.print(f"  Last Used: {token.last_used_at.isoformat()}")
    ctx.print("")

    if token.description:
        ctx.print(f"Description: {token.description}")
        ctx.print("")

    # Permissions summary
    perms = token.permissions
    ctx.print("Permissions:")
    if perms.allowed_models:
        ctx.print(f"  Allowed Models: {', '.join(perms.allowed_models)}")
    else:
        ctx.print("  Allowed Models: All")
    if perms.budget_limit:
        ctx.print(f"  Budget: ${perms.budget_limit:.2f}/{perms.budget_period.value}")
    if perms.rate_limit:
        ctx.print(f"  Rate Limit: {perms.rate_limit.max_requests}/{perms.rate_limit.period_seconds}s")
    ctx.print("")

    # Usage stats if available
    if "usage" in result:
        usage = result["usage"]
        ctx.print("Usage Statistics:")
        ctx.print(f"  Total Requests: {usage['total_requests']}")
        ctx.print(f"  Total Cost: ${usage['total_cost']:.2f}")
        ctx.print(f"  Period Requests: {usage['period_requests']}")
        ctx.print(f"  Period Cost: ${usage['period_cost']:.2f}")
        if "remaining_budget" in result:
            ctx.print(f"  Remaining Budget: ${result['remaining_budget']:.2f}")
        ctx.print("")

    # Revocation info if applicable
    if token.revoked_at:
        ctx.print("Revocation:")
        ctx.print(f"  Revoked At: {token.revoked_at.isoformat()}")
        ctx.print(f"  Revoked By: {token.revoked_by}")
        ctx.print(f"  Reason: {token.revocation_reason}")
        ctx.print("")
