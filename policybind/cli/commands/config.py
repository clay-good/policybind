"""
Configuration commands for PolicyBind CLI.

This module implements the 'policybind config' commands for
configuration management.

Usage:
    policybind config show
    policybind config validate [PATH]
    policybind config set KEY VALUE
"""

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the config command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "config",
        help="Configuration management",
        description="View and manage PolicyBind configuration.",
    )

    config_subparsers = parser.add_subparsers(
        title="config commands",
        dest="config_command",
        metavar="<subcommand>",
    )

    # config show
    show_parser = config_subparsers.add_parser(
        "show",
        help="Display current configuration",
        description="Display the current active configuration.",
    )
    show_parser.add_argument(
        "--section",
        "-s",
        metavar="SECTION",
        help="Show only a specific section (database, enforcement, etc.)",
    )
    show_parser.add_argument(
        "--include-defaults",
        action="store_true",
        help="Show all values including defaults",
    )
    show_parser.set_defaults(func=run_config_show)

    # config validate
    validate_parser = config_subparsers.add_parser(
        "validate",
        help="Validate configuration file",
        description="Validate a configuration file for errors.",
    )
    validate_parser.add_argument(
        "path",
        nargs="?",
        metavar="PATH",
        help="Path to configuration file (uses --config or default if not specified)",
    )
    validate_parser.set_defaults(func=run_config_validate)

    # config set
    set_parser = config_subparsers.add_parser(
        "set",
        help="Set a configuration value",
        description=(
            "Set a configuration value. Use dot notation for nested keys "
            "(e.g., database.pool_size)."
        ),
    )
    set_parser.add_argument(
        "key",
        metavar="KEY",
        help="Configuration key (e.g., database.pool_size)",
    )
    set_parser.add_argument(
        "value",
        metavar="VALUE",
        help="Value to set",
    )
    set_parser.add_argument(
        "--config-file",
        "-c",
        metavar="PATH",
        help="Configuration file to modify",
    )
    set_parser.set_defaults(func=run_config_set)

    # Default to show help
    parser.set_defaults(func=lambda args, ctx: run_config_help(parser, args, ctx))


def run_config_help(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    ctx: "CLIContext",
) -> int:
    """Show help when no subcommand is specified."""
    parser.print_help()
    return 0


def run_config_show(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the config show command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.formatters import format_output
    from policybind.cli.main import EXIT_SUCCESS

    config = ctx.config
    config_dict = config.to_dict()

    # Filter to specific section if requested
    if args.section:
        section = args.section.lower()
        if section not in config_dict:
            ctx.print_error(f"Unknown section: {section}")
            ctx.print_error(f"Available sections: {', '.join(config_dict.keys())}")
            return 1
        config_dict = {section: config_dict[section]}

    # Format output based on requested format
    output = format_output(config_dict, ctx.output_format, title="Configuration")
    ctx.print(output)

    return EXIT_SUCCESS


def run_config_validate(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the config validate command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_SUCCESS, EXIT_VALIDATION_ERROR
    from policybind.config.loader import ConfigLoader
    from policybind.exceptions import ConfigurationError

    # Determine config path
    config_path = args.path or ctx.config_path

    if config_path is None:
        ctx.print("No configuration file specified.")
        ctx.print("Use 'policybind config validate PATH' or '--config PATH'")
        return EXIT_VALIDATION_ERROR

    config_path = Path(config_path)
    if not config_path.exists():
        ctx.print_error(f"Configuration file not found: {config_path}")
        return EXIT_VALIDATION_ERROR

    ctx.print(f"Validating: {config_path}")

    try:
        loader = ConfigLoader()
        config = loader.load(str(config_path))

        ctx.print("")
        ctx.print("Configuration is valid.")
        ctx.print("")
        ctx.print(f"  Environment: {config.environment}")
        ctx.print(f"  Database: {config.database.path}")
        ctx.print(f"  Policies path: {config.policies_path}")
        ctx.print(f"  Default action: {config.enforcement.default_action}")

        return EXIT_SUCCESS

    except ConfigurationError as e:
        ctx.print_error(f"Configuration validation failed: {e}")
        if hasattr(e, "details") and e.details:
            if "errors" in e.details:
                ctx.print_error("")
                ctx.print_error("Errors:")
                for error in e.details["errors"]:
                    ctx.print_error(f"  - {error}")
        return EXIT_VALIDATION_ERROR


def run_config_set(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the config set command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS

    # Determine config file path
    config_file = args.config_file or ctx.config_path or "policybind.yaml"
    config_path = Path(config_file)

    if not config_path.exists():
        ctx.print_error(f"Configuration file not found: {config_path}")
        ctx.print_error("Use 'policybind init' to create a new configuration.")
        return EXIT_ERROR

    # Load existing config
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        ctx.print_error(f"Failed to parse configuration: {e}")
        return EXIT_ERROR

    # Parse the key path
    key_parts = args.key.split(".")

    # Convert value to appropriate type
    value = _parse_value(args.value)

    # Set the nested value
    current = config_data
    for part in key_parts[:-1]:
        if part not in current:
            current[part] = {}
        elif not isinstance(current[part], dict):
            ctx.print_error(f"Cannot set nested key: {args.key}")
            ctx.print_error(f"  '{part}' is not a dictionary")
            return EXIT_ERROR
        current = current[part]

    old_value = current.get(key_parts[-1])
    current[key_parts[-1]] = value

    # Write back to file
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
    except OSError as e:
        ctx.print_error(f"Failed to write configuration: {e}")
        return EXIT_ERROR

    ctx.print(f"Updated {args.key}:")
    if old_value is not None:
        ctx.print(f"  Old value: {old_value}")
    ctx.print(f"  New value: {value}")

    return EXIT_SUCCESS


def _parse_value(value_str: str) -> Any:
    """
    Parse a string value to the appropriate type.

    Args:
        value_str: String value to parse.

    Returns:
        Parsed value (int, float, bool, list, or string).
    """
    # Try to parse as JSON first (handles lists, objects, etc.)
    try:
        return json.loads(value_str)
    except json.JSONDecodeError:
        pass

    # Try common types
    if value_str.lower() in ("true", "yes", "on"):
        return True
    if value_str.lower() in ("false", "no", "off"):
        return False
    if value_str.lower() in ("null", "none", "~"):
        return None

    # Try int
    try:
        return int(value_str)
    except ValueError:
        pass

    # Try float
    try:
        return float(value_str)
    except ValueError:
        pass

    # Return as string
    return value_str
