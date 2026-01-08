"""
Test fixtures for PolicyBind tests.

This module provides access to sample test data files:
- Sample policies in YAML format
- Sample requests in JSON format
- Sample registry entries

Usage:
    from tests.fixtures import load_policy_yaml, load_sample_requests
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Dict

# Get the fixtures directory path
FIXTURES_DIR = Path(__file__).parent


def load_policy_yaml(filename: str) -> str:
    """Load a policy YAML file from fixtures.

    Args:
        filename: Name of the YAML file (without path).

    Returns:
        Contents of the YAML file as a string.

    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
    filepath = FIXTURES_DIR / "policies" / filename
    return filepath.read_text()


def load_sample_requests(filename: str) -> list[dict[str, Any]]:
    """Load sample requests from a JSON file.

    Args:
        filename: Name of the JSON file (without path).

    Returns:
        List of request dictionaries.

    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
    filepath = FIXTURES_DIR / "requests" / filename
    return json.loads(filepath.read_text())


def load_registry_entries(filename: str) -> list[dict[str, Any]]:
    """Load registry entries from a JSON file.

    Args:
        filename: Name of the JSON file (without path).

    Returns:
        List of registry entry dictionaries.

    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
    filepath = FIXTURES_DIR / "registry" / filename
    return json.loads(filepath.read_text())


def get_all_policy_files() -> list[Path]:
    """Get all policy YAML files in the fixtures directory.

    Returns:
        List of Path objects to policy files.
    """
    policies_dir = FIXTURES_DIR / "policies"
    if not policies_dir.exists():
        return []
    return list(policies_dir.glob("*.yaml")) + list(policies_dir.glob("*.yml"))


def get_all_request_files() -> list[Path]:
    """Get all request JSON files in the fixtures directory.

    Returns:
        List of Path objects to request files.
    """
    requests_dir = FIXTURES_DIR / "requests"
    if not requests_dir.exists():
        return []
    return list(requests_dir.glob("*.json"))
