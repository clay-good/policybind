"""
Policy commands for PolicyBind CLI.

This module implements the 'policybind policy' commands for
policy management including loading, validating, diffing, and testing.

Usage:
    policybind policy load PATH
    policybind policy show [--version VERSION] [--rule NAME]
    policybind policy validate PATH
    policybind policy diff VERSION1 VERSION2
    policybind policy history [--limit N]
    policybind policy rollback VERSION [--force]
    policybind policy test PATH --request REQUEST_JSON
"""

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the policy command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "policy",
        help="Policy management",
        description="Load, validate, and manage policies.",
    )

    policy_subparsers = parser.add_subparsers(
        title="policy commands",
        dest="policy_command",
        metavar="<subcommand>",
    )

    # policy load
    load_parser = policy_subparsers.add_parser(
        "load",
        help="Load policies from a YAML file",
        description="Load and activate policies from a YAML file or directory.",
    )
    load_parser.add_argument(
        "path",
        metavar="PATH",
        help="Path to policy file or directory",
    )
    load_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate without applying changes",
    )
    load_parser.add_argument(
        "--message",
        "-m",
        metavar="MSG",
        default="",
        help="Commit message for this version",
    )
    load_parser.set_defaults(func=run_policy_load)

    # policy show
    show_parser = policy_subparsers.add_parser(
        "show",
        help="Display current active policies",
        description="Display the current active policy set or a specific version.",
    )
    show_parser.add_argument(
        "--name",
        "-n",
        metavar="NAME",
        help="Show a specific policy by name",
    )
    show_parser.add_argument(
        "--rule",
        "-r",
        metavar="RULE",
        help="Show details of a specific rule",
    )
    show_parser.set_defaults(func=run_policy_show)

    # policy validate
    validate_parser = policy_subparsers.add_parser(
        "validate",
        help="Validate a policy file",
        description="Validate a policy file without loading it.",
    )
    validate_parser.add_argument(
        "path",
        metavar="PATH",
        help="Path to policy file to validate",
    )
    validate_parser.set_defaults(func=run_policy_validate)

    # policy diff
    diff_parser = policy_subparsers.add_parser(
        "diff",
        help="Show differences between policy versions",
        description="Compare two policy versions and show the differences.",
    )
    diff_parser.add_argument(
        "policy_name",
        metavar="POLICY_NAME",
        help="Name of the policy to compare versions",
    )
    diff_parser.set_defaults(func=run_policy_diff)

    # policy history
    history_parser = policy_subparsers.add_parser(
        "history",
        help="Show policy version history",
        description="Display the history of policy versions.",
    )
    history_parser.add_argument(
        "--name",
        "-n",
        metavar="NAME",
        help="Policy name to show history for",
    )
    history_parser.add_argument(
        "--limit",
        "-l",
        metavar="N",
        type=int,
        default=10,
        help="Maximum number of entries to show (default: 10)",
    )
    history_parser.set_defaults(func=run_policy_history)

    # policy rollback
    rollback_parser = policy_subparsers.add_parser(
        "rollback",
        help="Rollback to a previous policy version",
        description="Restore policies from a previous version.",
    )
    rollback_parser.add_argument(
        "policy_id",
        metavar="POLICY_ID",
        help="ID of the policy to rollback",
    )
    rollback_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Skip confirmation prompt",
    )
    rollback_parser.set_defaults(func=run_policy_rollback)

    # policy test
    test_parser = policy_subparsers.add_parser(
        "test",
        help="Test a policy against a sample request",
        description="Test which rules would match a sample request.",
    )
    test_parser.add_argument(
        "path",
        metavar="PATH",
        help="Path to policy file to test",
    )
    test_parser.add_argument(
        "--request",
        "-r",
        metavar="JSON",
        required=True,
        help="Request data as JSON string or @file path",
    )
    test_parser.set_defaults(func=run_policy_test)

    # Default to show help
    parser.set_defaults(func=lambda args, ctx: run_policy_help(parser, args, ctx))


def run_policy_help(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    ctx: "CLIContext",
) -> int:
    """Show help when no subcommand is specified."""
    parser.print_help()
    return 0


def _parse_policy_files(policy_path: Path, ctx: "CLIContext") -> Any:
    """
    Parse policy file(s) from a path.

    Args:
        policy_path: Path to policy file or directory.
        ctx: CLI context.

    Returns:
        Tuple of (result, policy_set) or (None, None) on error.
    """
    from policybind.engine.parser import PolicyParser

    parser = PolicyParser()

    if policy_path.is_dir():
        # Load all YAML files in directory and combine
        all_rules = []
        name = policy_path.name
        version = "1.0.0"
        description = ""
        errors = []
        warnings = []

        yaml_files = list(policy_path.glob("*.yaml")) + list(policy_path.glob("*.yml"))
        if not yaml_files:
            return None, None, ["No YAML files found in directory"]

        for yaml_file in yaml_files:
            result = parser.parse_file(str(yaml_file))
            if not result.success:
                errors.extend(result.errors)
                continue
            warnings.extend(result.warnings)
            if result.policy_set:
                all_rules.extend(result.policy_set.rules)
                if result.policy_set.name:
                    name = result.policy_set.name
                if result.policy_set.version:
                    version = result.policy_set.version
                if result.policy_set.description:
                    description = result.policy_set.description

        if errors:
            return None, None, [str(e) for e in errors]

        from policybind.models.policy import PolicySet
        policy_set = PolicySet(
            name=name,
            version=version,
            description=description,
            rules=all_rules,
        )
        return policy_set, warnings, []
    else:
        result = parser.parse_file(str(policy_path))
        if not result.success:
            return None, None, [str(e) for e in result.errors]
        return result.policy_set, result.warnings, []


def run_policy_load(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy load command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS, EXIT_VALIDATION_ERROR
    from policybind.engine.validator import PolicyValidator
    from policybind.storage.repositories import PolicyRepository

    policy_path = Path(args.path)

    if not policy_path.exists():
        ctx.print_error(f"Path not found: {policy_path}")
        return EXIT_ERROR

    ctx.print(f"Loading policies from: {policy_path}")

    # Parse policies
    policy_set, warnings, errors = _parse_policy_files(policy_path, ctx)

    if errors:
        ctx.print_error("Policy parsing failed:")
        for error in errors:
            ctx.print_error(f"  {error}")
        return EXIT_VALIDATION_ERROR

    if warnings:
        ctx.print("Warnings:")
        for warning in warnings:
            ctx.print(f"  {warning}")

    if policy_set is None:
        ctx.print_error("No policies parsed")
        return EXIT_VALIDATION_ERROR

    ctx.print(f"  Parsed {len(policy_set.rules)} rules")

    # Validate policies
    validator = PolicyValidator()
    validation = validator.validate(policy_set)

    if not validation.valid:
        ctx.print_error("Policy validation failed:")
        for error in validation.errors:
            ctx.print_error(f"  {error}")
        return EXIT_VALIDATION_ERROR

    if validation.warnings:
        ctx.print("Validation warnings:")
        for warning in validation.warnings:
            ctx.print(f"  {warning}")

    if validation.info:
        for info in validation.info:
            ctx.print(f"  Info: {info}")

    # Stop here if dry-run
    if args.dry_run:
        ctx.print("")
        ctx.print("Dry run completed. No changes made.")
        return EXIT_SUCCESS

    # Save to database
    try:
        db = ctx.database
        db.initialize()
        repo = PolicyRepository(db)

        # Check if policy already exists
        existing = repo.get_by_name(policy_set.name)
        if existing:
            # Update existing policy
            repo.update(
                policy_id=existing["id"],
                content=policy_set.to_dict(),
                version=policy_set.version,
                description=policy_set.description,
                updated_by="cli",
            )
            ctx.print("")
            ctx.print(f"Policy '{policy_set.name}' updated successfully.")
        else:
            # Create new policy
            policy_id = repo.create(
                name=policy_set.name,
                version=policy_set.version,
                content=policy_set.to_dict(),
                description=policy_set.description,
                created_by="cli",
            )
            ctx.print("")
            ctx.print(f"Policy '{policy_set.name}' created with ID: {policy_id}")

        ctx.print(f"  Name: {policy_set.name}")
        ctx.print(f"  Version: {policy_set.version}")
        ctx.print(f"  Rules: {len(policy_set.rules)}")

    except Exception as e:
        ctx.print_error(f"Failed to save policies: {e}")
        if ctx.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR

    return EXIT_SUCCESS


def run_policy_show(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy show command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.policy import PolicySet
    from policybind.storage.repositories import PolicyRepository

    try:
        db = ctx.database
        db.initialize()
        repo = PolicyRepository(db)

        if args.name:
            # Get specific policy by name
            policy_data = repo.get_by_name(args.name)
            if not policy_data:
                ctx.print_error(f"Policy '{args.name}' not found")
                return EXIT_ERROR
            policies = [policy_data]
        else:
            # Get all active policies
            policies = repo.get_active()
            if not policies:
                ctx.print("No policies loaded.")
                ctx.print("Use 'policybind policy load PATH' to load policies.")
                return EXIT_SUCCESS

        for policy_data in policies:
            # Parse policy data - content is already a dict from deserialization
            content = policy_data["content"]
            if isinstance(content, str):
                content = json.loads(content)

            # Convert nested rules to PolicyRule objects
            from policybind.models.policy import PolicyRule
            rules = []
            for rule_data in content.get("rules", []):
                if isinstance(rule_data, dict):
                    rules.append(PolicyRule(**rule_data))
                else:
                    rules.append(rule_data)

            policy_set = PolicySet(
                name=content.get("name", ""),
                version=content.get("version", "1.0.0"),
                description=content.get("description", ""),
                metadata=content.get("metadata", {}),
                rules=rules,
            )

            # Show specific rule if requested
            if args.rule:
                rule = policy_set.get_rule(args.rule)
                if not rule:
                    ctx.print_error(f"Rule '{args.rule}' not found in policy '{policy_set.name}'")
                    ctx.print_error("Available rules:")
                    for r in policy_set.rules:
                        ctx.print_error(f"  - {r.name}")
                    return EXIT_ERROR

                rule_data = {
                    "name": rule.name,
                    "description": rule.description,
                    "action": rule.action,
                    "priority": rule.priority,
                    "enabled": rule.enabled,
                    "match_conditions": rule.match_conditions,
                    "action_params": rule.action_params,
                    "tags": rule.tags,
                }
                output = format_output(rule_data, ctx.output_format, title=f"Rule: {rule.name}")
                ctx.print(output)
            else:
                # Show policy summary
                policy_info = {
                    "id": policy_data.get("id", "unknown"),
                    "name": policy_set.name,
                    "version": policy_set.version,
                    "description": policy_set.description,
                    "rule_count": len(policy_set.rules),
                    "is_active": policy_data.get("is_active", False),
                    "created_at": policy_data.get("created_at", "unknown"),
                    "created_by": policy_data.get("created_by", "unknown"),
                    "rules": [
                        {
                            "name": r.name,
                            "action": r.action,
                            "priority": r.priority,
                            "enabled": r.enabled,
                        }
                        for r in policy_set.rules
                    ],
                }
                output = format_output(policy_info, ctx.output_format, title=f"Policy: {policy_set.name}")
                ctx.print(output)

    except Exception as e:
        ctx.print_error(f"Failed to load policies: {e}")
        if ctx.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR

    return EXIT_SUCCESS


def run_policy_validate(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy validate command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_SUCCESS, EXIT_VALIDATION_ERROR
    from policybind.engine.validator import PolicyValidator

    policy_path = Path(args.path)

    if not policy_path.exists():
        ctx.print_error(f"Path not found: {policy_path}")
        return EXIT_VALIDATION_ERROR

    ctx.print(f"Validating: {policy_path}")

    # Parse
    policy_set, warnings, errors = _parse_policy_files(policy_path, ctx)

    has_issues = False

    # Report parse errors
    if errors:
        has_issues = True
        ctx.print("")
        ctx.print("Parse Errors:")
        for error in errors:
            ctx.print_error(f"  {error}")
        return EXIT_VALIDATION_ERROR

    # Report parse warnings
    if warnings:
        ctx.print("")
        ctx.print("Parse Warnings:")
        for warning in warnings:
            ctx.print(f"  {warning}")

    if policy_set is None:
        return EXIT_VALIDATION_ERROR

    # Validate semantically
    validator = PolicyValidator()
    validation = validator.validate(policy_set)

    # Report validation errors
    if validation.errors:
        has_issues = True
        ctx.print("")
        ctx.print("Validation Errors:")
        for error in validation.errors:
            ctx.print_error(f"  {error}")

    # Report validation warnings
    if validation.warnings:
        ctx.print("")
        ctx.print("Validation Warnings:")
        for warning in validation.warnings:
            ctx.print(f"  {warning}")

    # Report info messages
    if validation.info:
        ctx.print("")
        ctx.print("Info:")
        for info in validation.info:
            ctx.print(f"  {info}")

    # Summary
    ctx.print("")
    if validation.valid and not has_issues:
        ctx.print("Policy is valid.")
        ctx.print(f"  Name: {policy_set.name}")
        ctx.print(f"  Version: {policy_set.version}")
        ctx.print(f"  Rules: {len(policy_set.rules)}")
        return EXIT_SUCCESS
    else:
        ctx.print_error("Policy validation failed.")
        return EXIT_VALIDATION_ERROR


def run_policy_diff(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy diff command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.storage.repositories import PolicyRepository

    try:
        db = ctx.database
        db.initialize()
        repo = PolicyRepository(db)

        # Get version history for the policy
        versions = repo.get_versions(args.policy_name)

        if len(versions) < 2:
            ctx.print(f"Policy '{args.policy_name}' has fewer than 2 versions.")
            ctx.print("No diff available.")
            return EXIT_SUCCESS

        ctx.print(f"Version history for policy: {args.policy_name}")
        ctx.print("=" * 50)

        for i, version in enumerate(versions[:10]):
            ctx.print(f"\n[{i+1}] {version.get('timestamp', 'unknown')}")
            ctx.print(f"    Action: {version.get('action', 'unknown')}")
            ctx.print(f"    User: {version.get('user_id', 'unknown')}")

    except Exception as e:
        ctx.print_error(f"Failed to get diff: {e}")
        if ctx.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR

    return EXIT_SUCCESS


def run_policy_history(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy history command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.formatters import TableFormatter, format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.storage.repositories import PolicyRepository

    try:
        db = ctx.database
        db.initialize()
        repo = PolicyRepository(db)

        if args.name:
            # Get history for specific policy
            history = repo.get_versions(args.name)
            if not history:
                ctx.print(f"No history found for policy '{args.name}'.")
                return EXIT_SUCCESS

            if ctx.output_format in ("json", "yaml"):
                ctx.print(format_output(history, ctx.output_format))
            else:
                ctx.print(f"Policy History: {args.name}")
                ctx.print("=" * 60)
                ctx.print("")

                headers = ["Timestamp", "Action", "User"]
                rows = []
                for h in history[:args.limit]:
                    rows.append([
                        h.get("timestamp", "unknown")[:19],
                        h.get("action", "unknown"),
                        h.get("user_id", "unknown") or "system",
                    ])

                ctx.print(TableFormatter.format_table(headers, rows))
        else:
            # List all policies
            policies = repo.list_all(include_inactive=True, limit=args.limit)
            if not policies:
                ctx.print("No policies found.")
                return EXIT_SUCCESS

            if ctx.output_format in ("json", "yaml"):
                ctx.print(format_output(policies, ctx.output_format))
            else:
                ctx.print("All Policies")
                ctx.print("=" * 60)
                ctx.print("")

                headers = ["ID", "Name", "Version", "Active", "Created"]
                rows = []
                for p in policies:
                    rows.append([
                        p.get("id", "unknown")[:8] + "...",
                        p.get("name", "unknown"),
                        p.get("version", "unknown"),
                        "Yes" if p.get("is_active") else "No",
                        p.get("created_at", "unknown")[:19],
                    ])

                ctx.print(TableFormatter.format_table(headers, rows))

    except Exception as e:
        ctx.print_error(f"Failed to get history: {e}")
        if ctx.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR

    return EXIT_SUCCESS


def run_policy_rollback(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy rollback command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.models.policy import PolicySet
    from policybind.storage.repositories import PolicyRepository

    try:
        db = ctx.database
        db.initialize()
        repo = PolicyRepository(db)

        # Get the policy by ID
        policy_data = repo.get_by_id(args.policy_id)
        if not policy_data:
            ctx.print_error(f"Policy with ID '{args.policy_id}' not found")
            return EXIT_ERROR

        # Parse policy
        policy_set = PolicySet.from_dict(policy_data["content"])

        ctx.print(f"Policy to restore:")
        ctx.print(f"  ID: {policy_data['id']}")
        ctx.print(f"  Name: {policy_set.name}")
        ctx.print(f"  Version: {policy_set.version}")
        ctx.print(f"  Rules: {len(policy_set.rules)}")
        ctx.print(f"  Active: {'Yes' if policy_data.get('is_active') else 'No'}")

        # If already active, nothing to do
        if policy_data.get("is_active"):
            ctx.print("")
            ctx.print("This policy is already active.")
            return EXIT_SUCCESS

        # Confirm unless --force
        if not args.force:
            try:
                response = input("\nActivate this policy? [y/N] ")
                if response.lower() not in ("y", "yes"):
                    ctx.print("Operation cancelled.")
                    return EXIT_SUCCESS
            except EOFError:
                ctx.print("Operation cancelled.")
                return EXIT_SUCCESS

        # Activate the policy
        repo.activate(args.policy_id, activated_by="cli")

        ctx.print("")
        ctx.print(f"Successfully activated policy '{policy_set.name}'")

    except Exception as e:
        ctx.print_error(f"Rollback failed: {e}")
        if ctx.verbose:
            import traceback
            traceback.print_exc()
        return EXIT_ERROR

    return EXIT_SUCCESS


def run_policy_test(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the policy test command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS, EXIT_VALIDATION_ERROR
    from policybind.engine.matcher import PolicyMatcher
    from policybind.models.request import AIRequest

    policy_path = Path(args.path)

    if not policy_path.exists():
        ctx.print_error(f"Policy path not found: {policy_path}")
        return EXIT_ERROR

    # Parse request JSON
    request_json = args.request
    if request_json.startswith("@"):
        # Load from file
        request_file = Path(request_json[1:])
        if not request_file.exists():
            ctx.print_error(f"Request file not found: {request_file}")
            return EXIT_ERROR
        request_json = request_file.read_text()

    try:
        request_data = json.loads(request_json)
    except json.JSONDecodeError as e:
        ctx.print_error(f"Invalid JSON: {e}")
        return EXIT_ERROR

    # Create AIRequest from data
    try:
        request = AIRequest(
            request_id=request_data.get("request_id", "test-request"),
            provider=request_data.get("provider", "unknown"),
            model=request_data.get("model", "unknown"),
            prompt_hash=request_data.get("prompt_hash", ""),
            estimated_tokens=request_data.get("estimated_tokens", 0),
            estimated_cost=request_data.get("estimated_cost", 0.0),
            source_application=request_data.get("source_application", "cli-test"),
            user_id=request_data.get("user_id", "test-user"),
            department=request_data.get("department", ""),
            data_classification=request_data.get("data_classification", []),
            intended_use_case=request_data.get("intended_use_case", ""),
            metadata=request_data.get("metadata", {}),
        )
    except Exception as e:
        ctx.print_error(f"Invalid request data: {e}")
        return EXIT_ERROR

    # Parse policies
    policy_set, warnings, errors = _parse_policy_files(policy_path, ctx)

    if errors:
        ctx.print_error("Policy parsing failed:")
        for error in errors:
            ctx.print_error(f"  {error}")
        return EXIT_VALIDATION_ERROR

    if policy_set is None:
        ctx.print_error("No policies parsed")
        return EXIT_VALIDATION_ERROR

    # Match request against policies
    matcher = PolicyMatcher()
    match_result = matcher.match(policy_set, request)

    # Also get all matching rules for detailed output
    all_matches = matcher.match_all(policy_set, request)

    # Prepare output
    test_result: dict[str, Any] = {
        "request": {
            "provider": request.provider,
            "model": request.model,
            "user_id": request.user_id,
            "department": request.department,
            "data_classification": request.data_classification,
            "intended_use_case": request.intended_use_case,
            "estimated_cost": request.estimated_cost,
        },
        "matched": match_result.matched,
        "primary_match": None,
        "all_matches": [],
    }

    if match_result.matched and match_result.rule:
        test_result["primary_match"] = {
            "rule": match_result.rule.name,
            "action": match_result.rule.action,
            "priority": match_result.rule.priority,
            "score": match_result.match_score,
            "matched_conditions": match_result.matched_conditions,
        }

    for m in all_matches:
        if m.matched and m.rule:
            # MatchResult has 'score' attribute, not 'match_score'
            test_result["all_matches"].append({
                "rule": m.rule.name,
                "action": m.rule.action,
                "priority": m.rule.priority,
                "score": m.score,
            })

    # Output
    if ctx.output_format in ("json", "yaml"):
        ctx.print(format_output(test_result, ctx.output_format))
    else:
        ctx.print("Policy Test Results")
        ctx.print("=" * 50)
        ctx.print("")
        ctx.print("Request:")
        ctx.print(f"  Provider: {request.provider}")
        ctx.print(f"  Model: {request.model}")
        ctx.print(f"  User: {request.user_id}")
        ctx.print(f"  Department: {request.department}")
        ctx.print(f"  Data Classification: {request.data_classification}")
        ctx.print(f"  Use Case: {request.intended_use_case}")
        ctx.print(f"  Estimated Cost: ${request.estimated_cost:.2f}")
        ctx.print("")

        if match_result.matched and match_result.rule:
            ctx.print("Result: MATCH")
            ctx.print("")
            ctx.print("Primary Match:")
            ctx.print(f"  Rule: {match_result.rule.name}")
            ctx.print(f"  Action: {match_result.rule.action}")
            ctx.print(f"  Priority: {match_result.rule.priority}")
            ctx.print(f"  Match Score: {match_result.match_score:.2f}")
            if match_result.matched_conditions:
                ctx.print(f"  Matched Conditions: {match_result.matched_conditions}")

            if len(all_matches) > 1:
                ctx.print("")
                ctx.print(f"All Matching Rules ({len(all_matches)}):")
                for i, m in enumerate(all_matches, 1):
                    if m.matched and m.rule:
                        ctx.print(f"  {i}. {m.rule.name} (action={m.rule.action}, priority={m.rule.priority})")
        else:
            ctx.print("Result: NO MATCH")
            ctx.print("")
            ctx.print("No rules matched this request.")
            ctx.print("The default action from configuration will be applied.")

    return EXIT_SUCCESS
