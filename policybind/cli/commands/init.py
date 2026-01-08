"""
Initialize command for PolicyBind CLI.

This module implements the 'policybind init' command which sets up
a new PolicyBind database, configuration, and example policies.

Usage:
    policybind init [--path PATH] [--force]
"""

import argparse
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from policybind.cli.main import CLIContext


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register the init command with the parser.

    Args:
        subparsers: Subparsers action to add command to.
    """
    parser = subparsers.add_parser(
        "init",
        help="Initialize a new PolicyBind database and config",
        description=(
            "Initialize a new PolicyBind project directory with database, "
            "configuration, and example policies."
        ),
    )
    parser.add_argument(
        "--path",
        "-p",
        metavar="PATH",
        default=".",
        help="Directory to initialize (default: current directory)",
    )
    parser.add_argument(
        "--force",
        "-F",
        action="store_true",
        help="Overwrite existing files without prompting",
    )
    parser.add_argument(
        "--no-examples",
        action="store_true",
        help="Skip creating example policy files",
    )
    parser.set_defaults(func=run_init)


def run_init(args: argparse.Namespace, ctx: "CLIContext") -> int:
    """
    Execute the init command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context.

    Returns:
        Exit code.
    """
    from policybind.cli.main import EXIT_ERROR, EXIT_SUCCESS
    from policybind.storage.database import Database

    target_path = Path(args.path).resolve()

    ctx.print(f"Initializing PolicyBind in: {target_path}")

    # Create directory if it doesn't exist
    if not target_path.exists():
        target_path.mkdir(parents=True)
        ctx.print(f"  Created directory: {target_path}")

    # Define files to create
    config_file = target_path / "policybind.yaml"
    db_file = target_path / "policybind.db"
    policies_dir = target_path / "policies"

    # Check for existing files
    existing_files = []
    if config_file.exists():
        existing_files.append(str(config_file))
    if db_file.exists():
        existing_files.append(str(db_file))

    if existing_files and not args.force:
        ctx.print_error("The following files already exist:")
        for f in existing_files:
            ctx.print_error(f"  - {f}")
        ctx.print_error("Use --force to overwrite, or choose a different path.")
        return EXIT_ERROR

    # Create configuration file
    _create_config_file(config_file, ctx)

    # Create policies directory
    if not policies_dir.exists():
        policies_dir.mkdir()
        ctx.print(f"  Created directory: {policies_dir}")

    # Create example policies
    if not args.no_examples:
        _create_example_policies(policies_dir, ctx)

    # Initialize database
    _init_database(db_file, ctx)

    ctx.print("")
    ctx.print("PolicyBind initialized successfully.")
    ctx.print("")
    ctx.print("Next steps:")
    ctx.print("  1. Edit policybind.yaml to customize configuration")
    ctx.print("  2. Add or modify policies in the policies/ directory")
    ctx.print("  3. Run 'policybind status' to verify setup")
    ctx.print("  4. Run 'policybind policy load policies/' to load policies")

    return EXIT_SUCCESS


def _create_config_file(config_file: Path, ctx: "CLIContext") -> None:
    """
    Create the configuration file.

    Args:
        config_file: Path to configuration file.
        ctx: CLI context.
    """
    config_content = '''# PolicyBind Configuration
# ========================
# See configs/policybind.example.yaml for all available options

environment: development

database:
  path: policybind.db
  pool_size: 5
  timeout_seconds: 30.0

enforcement:
  default_action: deny
  log_all_requests: true
  require_classification: true
  fail_open: false

registry:
  require_approval_for_high_risk: true
  auto_suspend_on_violations: true
  violation_threshold: 10

tokens:
  default_expiry_days: 30
  max_expiry_days: 365

logging:
  level: INFO
  output_path: ""

policies_path: policies

metadata:
  organization: "My Organization"
'''
    config_file.write_text(config_content)
    ctx.print(f"  Created configuration: {config_file}")


def _create_example_policies(policies_dir: Path, ctx: "CLIContext") -> None:
    """
    Create example policy files.

    Args:
        policies_dir: Path to policies directory.
        ctx: CLI context.
    """
    # Create basic example policy
    basic_policy = policies_dir / "basic.yaml"
    basic_content = '''# Basic PolicyBind Policy Example
# ================================
# This file demonstrates basic policy rules

name: basic-policies
version: "1.0.0"
description: Basic policy rules for AI governance

rules:
  # Deny requests with PII data classification
  - name: deny-pii-to-external
    description: Block PII data from being sent to external models
    match_conditions:
      data_classification:
        contains: pii
      provider:
        not_equals: internal
    action: DENY
    priority: 100

  # Require approval for high-cost requests
  - name: require-approval-high-cost
    description: Require approval for requests estimated over $10
    match_conditions:
      cost:
        greater_than: 10.0
    action: REQUIRE_APPROVAL
    priority: 50

  # Audit all requests from external applications
  - name: audit-external-apps
    description: Flag all external application requests for review
    match_conditions:
      source:
        in:
          - external-app
          - partner-integration
    action: AUDIT
    priority: 10

  # Default allow for internal use
  - name: allow-internal
    description: Allow internal requests by default
    match_conditions:
      department:
        in:
          - engineering
          - research
          - data-science
    action: ALLOW
    priority: 1
'''
    basic_policy.write_text(basic_content)
    ctx.print(f"  Created example policy: {basic_policy}")


def _init_database(db_file: Path, ctx: "CLIContext") -> None:
    """
    Initialize the database.

    Args:
        db_file: Path to database file.
        ctx: CLI context.
    """
    from policybind.storage.database import Database

    # Remove existing database if force is enabled
    if db_file.exists():
        db_file.unlink()

    db = Database(path=str(db_file))
    try:
        db.initialize()
        ctx.print(f"  Initialized database: {db_file}")
    finally:
        db.close()
