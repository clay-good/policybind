"""
Policy versioning for PolicyBind.

This module provides the PolicyVersionManager class for managing
policy versions, history, diffing, and rollback capabilities.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from policybind.exceptions import PolicyError
from policybind.models.base import generate_uuid, utc_now
from policybind.models.policy import PolicyRule, PolicySet


@dataclass
class PolicyVersion:
    """
    Represents a specific version of a policy set.

    Attributes:
        version_id: Unique identifier for this version.
        version_number: Sequential version number (1, 2, 3...).
        policy_set: The PolicySet at this version.
        content_hash: SHA-256 hash of the serialized policy content.
        created_at: When this version was created.
        created_by: Who created this version.
        commit_message: Description of changes in this version.
        metadata: Additional metadata about this version.
    """

    version_id: str
    version_number: int
    policy_set: PolicySet
    content_hash: str
    created_at: datetime
    created_by: str = ""
    commit_message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert version to a dictionary."""
        return {
            "version_id": self.version_id,
            "version_number": self.version_number,
            "policy_name": self.policy_set.name,
            "policy_version": self.policy_set.version,
            "content_hash": self.content_hash,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "commit_message": self.commit_message,
            "rule_count": len(self.policy_set.rules),
            "metadata": self.metadata,
        }


@dataclass
class PolicyDiff:
    """
    Represents the difference between two policy versions.

    Attributes:
        from_version: Source version number.
        to_version: Target version number.
        added_rules: Rules that were added.
        removed_rules: Rules that were removed.
        modified_rules: Rules that were modified (tuple of old, new).
        metadata_changes: Changes to policy metadata.
    """

    from_version: int
    to_version: int
    added_rules: list[PolicyRule] = field(default_factory=list)
    removed_rules: list[PolicyRule] = field(default_factory=list)
    modified_rules: list[tuple[PolicyRule, PolicyRule]] = field(default_factory=list)
    metadata_changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return bool(
            self.added_rules
            or self.removed_rules
            or self.modified_rules
            or self.metadata_changes
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert diff to a dictionary."""
        return {
            "from_version": self.from_version,
            "to_version": self.to_version,
            "added_rules": [r.name for r in self.added_rules],
            "removed_rules": [r.name for r in self.removed_rules],
            "modified_rules": [(old.name, new.name) for old, new in self.modified_rules],
            "metadata_changes": self.metadata_changes,
            "has_changes": self.has_changes,
        }

    def summary(self) -> str:
        """Return a human-readable summary of changes."""
        parts = []
        if self.added_rules:
            parts.append(f"+{len(self.added_rules)} rules")
        if self.removed_rules:
            parts.append(f"-{len(self.removed_rules)} rules")
        if self.modified_rules:
            parts.append(f"~{len(self.modified_rules)} modified")
        if self.metadata_changes:
            parts.append(f"{len(self.metadata_changes)} metadata changes")

        if not parts:
            return "No changes"
        return ", ".join(parts)


class PolicyVersionManager:
    """
    Manages policy versions with history, diffing, and rollback support.

    The PolicyVersionManager provides:
    - Version numbering for policy sets
    - Storage of historical policy versions
    - Querying which policy was active at a given time
    - Diffing between policy versions
    - Rollback to previous versions

    Example:
        Managing policy versions::

            manager = PolicyVersionManager()

            # Create initial version
            version = manager.create_version(policy_set, "user@example.com")

            # Get history
            history = manager.get_history()

            # Diff versions
            diff = manager.diff(1, 2)

            # Rollback
            old_policy = manager.rollback(1)
    """

    def __init__(
        self,
        max_versions: int = 100,
        on_version_created: Callable[[PolicyVersion], None] | None = None,
    ) -> None:
        """
        Initialize the version manager.

        Args:
            max_versions: Maximum number of versions to retain.
            on_version_created: Callback when a new version is created.
        """
        self._max_versions = max_versions
        self._on_version_created = on_version_created
        self._versions: dict[int, PolicyVersion] = {}
        self._version_counter = 0
        self._active_version: int | None = None

    def create_version(
        self,
        policy_set: PolicySet,
        created_by: str = "",
        commit_message: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> PolicyVersion:
        """
        Create a new version of a policy set.

        Args:
            policy_set: The PolicySet to version.
            created_by: Who is creating this version.
            commit_message: Description of changes.
            metadata: Additional metadata.

        Returns:
            The created PolicyVersion.
        """
        self._version_counter += 1
        version_number = self._version_counter

        # Compute content hash
        content_hash = self._compute_hash(policy_set)

        version = PolicyVersion(
            version_id=generate_uuid(),
            version_number=version_number,
            policy_set=policy_set,
            content_hash=content_hash,
            created_at=utc_now(),
            created_by=created_by,
            commit_message=commit_message,
            metadata=metadata or {},
        )

        self._versions[version_number] = version
        self._active_version = version_number

        # Prune old versions if needed
        self._prune_old_versions()

        # Notify callback
        if self._on_version_created:
            self._on_version_created(version)

        return version

    def get_version(self, version_number: int) -> PolicyVersion | None:
        """
        Get a specific version.

        Args:
            version_number: The version number to retrieve.

        Returns:
            The PolicyVersion, or None if not found.
        """
        return self._versions.get(version_number)

    def get_active_version(self) -> PolicyVersion | None:
        """
        Get the currently active version.

        Returns:
            The active PolicyVersion, or None if no versions exist.
        """
        if self._active_version is None:
            return None
        return self._versions.get(self._active_version)

    def get_active_policy(self) -> PolicySet | None:
        """
        Get the currently active policy set.

        Returns:
            The active PolicySet, or None if no versions exist.
        """
        version = self.get_active_version()
        return version.policy_set if version else None

    def get_history(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[PolicyVersion]:
        """
        Get version history, newest first.

        Args:
            limit: Maximum number of versions to return.
            offset: Number of versions to skip.

        Returns:
            List of PolicyVersion objects.
        """
        sorted_versions = sorted(
            self._versions.values(),
            key=lambda v: v.version_number,
            reverse=True,
        )
        return sorted_versions[offset : offset + limit]

    def get_version_at_time(self, timestamp: datetime) -> PolicyVersion | None:
        """
        Get the version that was active at a specific time.

        Args:
            timestamp: The time to query.

        Returns:
            The PolicyVersion that was active at that time, or None.
        """
        # Find the latest version created before or at the timestamp
        candidates = [
            v for v in self._versions.values() if v.created_at <= timestamp
        ]
        if not candidates:
            return None

        return max(candidates, key=lambda v: v.created_at)

    def diff(
        self,
        from_version: int,
        to_version: int,
    ) -> PolicyDiff:
        """
        Compute the difference between two versions.

        Args:
            from_version: Source version number.
            to_version: Target version number.

        Returns:
            PolicyDiff describing the changes.

        Raises:
            PolicyError: If either version is not found.
        """
        from_v = self.get_version(from_version)
        to_v = self.get_version(to_version)

        if from_v is None:
            raise PolicyError(f"Version {from_version} not found")
        if to_v is None:
            raise PolicyError(f"Version {to_version} not found")

        return self._compute_diff(from_v.policy_set, to_v.policy_set, from_version, to_version)

    def _compute_diff(
        self,
        from_policy: PolicySet,
        to_policy: PolicySet,
        from_version: int,
        to_version: int,
    ) -> PolicyDiff:
        """
        Compute the difference between two policy sets.

        Args:
            from_policy: Source policy set.
            to_policy: Target policy set.
            from_version: Source version number.
            to_version: Target version number.

        Returns:
            PolicyDiff describing the changes.
        """
        diff = PolicyDiff(from_version=from_version, to_version=to_version)

        # Build name-to-rule mappings
        from_rules = {r.name: r for r in from_policy.rules}
        to_rules = {r.name: r for r in to_policy.rules}

        from_names = set(from_rules.keys())
        to_names = set(to_rules.keys())

        # Added rules
        for name in to_names - from_names:
            diff.added_rules.append(to_rules[name])

        # Removed rules
        for name in from_names - to_names:
            diff.removed_rules.append(from_rules[name])

        # Modified rules (same name, different content)
        for name in from_names & to_names:
            from_rule = from_rules[name]
            to_rule = to_rules[name]
            if self._rule_differs(from_rule, to_rule):
                diff.modified_rules.append((from_rule, to_rule))

        # Metadata changes
        if from_policy.name != to_policy.name:
            diff.metadata_changes["name"] = (from_policy.name, to_policy.name)
        if from_policy.version != to_policy.version:
            diff.metadata_changes["version"] = (from_policy.version, to_policy.version)
        if from_policy.description != to_policy.description:
            diff.metadata_changes["description"] = (
                from_policy.description,
                to_policy.description,
            )

        return diff

    def _rule_differs(self, rule1: PolicyRule, rule2: PolicyRule) -> bool:
        """Check if two rules differ in content (ignoring id and timestamps)."""
        return (
            rule1.description != rule2.description
            or rule1.match_conditions != rule2.match_conditions
            or rule1.action != rule2.action
            or rule1.action_params != rule2.action_params
            or rule1.priority != rule2.priority
            or rule1.enabled != rule2.enabled
            or rule1.tags != rule2.tags
        )

    def rollback(self, version_number: int) -> PolicySet:
        """
        Rollback to a previous version.

        This creates a new version with the content from the specified
        version, preserving version history.

        Args:
            version_number: The version to rollback to.

        Returns:
            The restored PolicySet.

        Raises:
            PolicyError: If the version is not found.
        """
        old_version = self.get_version(version_number)
        if old_version is None:
            raise PolicyError(f"Version {version_number} not found")

        # Create a new version with the old content
        self.create_version(
            policy_set=old_version.policy_set,
            created_by="system",
            commit_message=f"Rollback to version {version_number}",
            metadata={"rollback_from": version_number},
        )

        return old_version.policy_set

    def set_active(self, version_number: int) -> PolicyVersion:
        """
        Set a specific version as active without creating a new version.

        Args:
            version_number: The version to activate.

        Returns:
            The activated PolicyVersion.

        Raises:
            PolicyError: If the version is not found.
        """
        version = self.get_version(version_number)
        if version is None:
            raise PolicyError(f"Version {version_number} not found")

        self._active_version = version_number
        return version

    def get_version_count(self) -> int:
        """Get the total number of stored versions."""
        return len(self._versions)

    def get_latest_version_number(self) -> int:
        """Get the latest version number."""
        return self._version_counter

    def _compute_hash(self, policy_set: PolicySet) -> str:
        """
        Compute a content hash for a policy set.

        Args:
            policy_set: The policy set to hash.

        Returns:
            SHA-256 hash string.
        """
        # Create a normalized representation
        content = {
            "name": policy_set.name,
            "version": policy_set.version,
            "description": policy_set.description,
            "rules": [
                {
                    "name": r.name,
                    "description": r.description,
                    "match_conditions": r.match_conditions,
                    "action": r.action,
                    "action_params": r.action_params,
                    "priority": r.priority,
                    "enabled": r.enabled,
                    "tags": list(r.tags),
                }
                for r in sorted(policy_set.rules, key=lambda r: r.name)
            ],
        }

        json_str = json.dumps(content, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    def _prune_old_versions(self) -> None:
        """Remove oldest versions if we exceed max_versions."""
        while len(self._versions) > self._max_versions:
            # Find oldest version (lowest version number)
            oldest = min(self._versions.keys())
            # Don't delete the active version
            if oldest == self._active_version:
                break
            del self._versions[oldest]

    def clear(self) -> None:
        """Clear all version history."""
        self._versions.clear()
        self._version_counter = 0
        self._active_version = None

    def import_versions(self, versions: list[PolicyVersion]) -> None:
        """
        Import versions from external storage.

        Args:
            versions: List of PolicyVersion objects to import.
        """
        for version in versions:
            self._versions[version.version_number] = version
            if version.version_number > self._version_counter:
                self._version_counter = version.version_number

        if self._versions:
            self._active_version = max(self._versions.keys())

    def export_versions(self) -> list[dict[str, Any]]:
        """
        Export versions for external storage.

        Returns:
            List of version dictionaries.
        """
        return [v.to_dict() for v in self.get_history(limit=self._max_versions)]
