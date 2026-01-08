"""
PolicyBind Command Line Interface.

This module provides the command-line interface for PolicyBind,
allowing users to manage policies, model registry, tokens, and
incidents from the terminal.

Commands:
    init: Initialize a new PolicyBind database and configuration
    config: Configuration management
    status: System status and health checks
    policy: Policy management (load, validate, show, diff, etc.)
    registry: Model registry management
    token: Access token management
    audit: Audit log queries and exports
    incident: Incident management

Usage:
    policybind --help
    policybind init --path ./my-project
    policybind status --detailed
"""

from policybind.cli.main import main

__all__ = ["main"]
