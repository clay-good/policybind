"""
Policy-related data models for PolicyBind.

This module defines the core policy data structures used to represent
policy rules, policy sets (collections of rules), and policy matching results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from policybind.models.base import (
    BaseModel,
    generate_uuid,
    model_to_dict,
    model_to_json,
    utc_now,
)


@dataclass(frozen=True)
class PolicyRule:
    """
    Represents a single policy rule that defines conditions and actions.

    A PolicyRule specifies when it should apply (match_conditions) and what
    should happen when it applies (action and action_params). Rules are
    evaluated in priority order, with higher priority rules taking precedence.

    This class is immutable (frozen) to ensure thread safety and prevent
    accidental modifications during policy evaluation.

    Attributes:
        id: Unique identifier for this rule instance.
        created_at: Timestamp when the rule was created.
        updated_at: Timestamp when the rule was last modified.
        name: Unique identifier for the rule within a PolicySet. Should be
            descriptive and follow naming conventions (e.g., "deny-pii-to-external").
        description: Human-readable explanation of what the rule does and why.
            This is displayed in audit logs and policy documentation.
        match_conditions: Dictionary defining when this rule applies. Supports
            various condition types like provider, model, department, user,
            data_classification, cost, time, etc. Conditions can be combined
            with AND, OR, and NOT logic.
        action: The action to take when the rule matches. Must be one of the
            registered actions: ALLOW, DENY, MODIFY, REQUIRE_APPROVAL,
            RATE_LIMIT, AUDIT, REDIRECT.
        action_params: Additional parameters for the action. The structure
            depends on the action type (e.g., MODIFY might have redaction
            settings, RATE_LIMIT might have rate parameters).
        priority: Numeric priority for rule ordering. Higher values indicate
            higher priority. Rules with equal priority are evaluated in
            the order they appear in the PolicySet. Default is 0.
        enabled: Whether the rule is active. Disabled rules are skipped
            during evaluation. Useful for temporarily disabling rules
            without removing them. Default is True.
        tags: List of tags for categorizing and filtering rules. Tags can
            be used to select subsets of rules or for reporting purposes.
            Examples: ["production", "pii", "compliance"].
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    name: str = ""
    description: str = ""
    match_conditions: dict[str, Any] = field(default_factory=dict)
    action: str = "DENY"
    action_params: dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    enabled: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the rule to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the rule to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the rule's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on rule id."""
        if not isinstance(other, PolicyRule):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"PolicyRule(id={self.id!r}, name={self.name!r}, "
            f"action={self.action!r}, priority={self.priority})"
        )


@dataclass
class PolicySet(BaseModel):
    """
    A collection of PolicyRule objects with metadata.

    PolicySet groups related rules together under a common name and version.
    It provides methods for managing rules and querying them by name or tag.
    PolicySets are versioned to support tracking changes over time.

    Unlike PolicyRule, PolicySet is mutable because rules need to be
    added and removed during policy management.

    Attributes:
        name: Unique identifier for the policy set. Should be descriptive
            and follow naming conventions (e.g., "production-policies").
        version: Version string for the policy set. Should follow semantic
            versioning (e.g., "1.0.0") or be a timestamp-based identifier.
        description: Human-readable description of the policy set's purpose.
        metadata: Additional key-value metadata about the policy set.
            Can include author, source file, compliance frameworks, etc.
        rules: List of PolicyRule objects in this set. Rules are evaluated
            in priority order, then by their position in this list.
    """

    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    rules: list[PolicyRule] = field(default_factory=list)

    def add_rule(self, rule: PolicyRule) -> None:
        """
        Add a rule to the policy set.

        If a rule with the same name already exists, it will be replaced.

        Args:
            rule: The PolicyRule to add to the set.
        """
        # Remove existing rule with same name if present
        self.rules = [r for r in self.rules if r.name != rule.name]
        self.rules.append(rule)

    def remove_rule(self, name: str) -> bool:
        """
        Remove a rule from the policy set by name.

        Args:
            name: The name of the rule to remove.

        Returns:
            True if a rule was removed, False if no rule with that name exists.
        """
        original_count = len(self.rules)
        self.rules = [r for r in self.rules if r.name != name]
        return len(self.rules) < original_count

    def get_rule(self, name: str) -> PolicyRule | None:
        """
        Retrieve a rule by its name.

        Args:
            name: The name of the rule to retrieve.

        Returns:
            The PolicyRule with the given name, or None if not found.
        """
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None

    def get_rules_by_tag(self, tag: str) -> list[PolicyRule]:
        """
        Retrieve all rules that have a specific tag.

        Args:
            tag: The tag to filter by.

        Returns:
            List of PolicyRule objects that have the specified tag.
        """
        return [rule for rule in self.rules if tag in rule.tags]

    def get_enabled_rules(self) -> list[PolicyRule]:
        """
        Retrieve all enabled rules, sorted by priority (highest first).

        Returns:
            List of enabled PolicyRule objects sorted by priority descending.
        """
        enabled = [rule for rule in self.rules if rule.enabled]
        return sorted(enabled, key=lambda r: r.priority, reverse=True)

    def get_rules_by_action(self, action: str) -> list[PolicyRule]:
        """
        Retrieve all rules with a specific action type.

        Args:
            action: The action type to filter by (e.g., "DENY", "ALLOW").

        Returns:
            List of PolicyRule objects with the specified action.
        """
        return [rule for rule in self.rules if rule.action == action]

    def __len__(self) -> int:
        """Return the number of rules in the policy set."""
        return len(self.rules)


@dataclass(frozen=True)
class PolicyMatch:
    """
    Represents the result of matching a request against policies.

    PolicyMatch is returned by the policy matching engine and contains
    information about which rule (if any) matched, how well it matched,
    and which specific conditions were satisfied.

    This class is immutable (frozen) to ensure match results cannot be
    modified after creation.

    Attributes:
        matched: Whether any rule matched the request. If False, the
            default action should be applied.
        rule: The PolicyRule that matched, or None if no rule matched.
            When multiple rules match, this is the highest priority match.
        match_score: A numeric score indicating the strength of the match.
            Higher scores indicate more specific matches. Useful for
            debugging and for choosing between rules with equal priority.
            Range is typically 0.0 to 1.0.
        matched_conditions: Dictionary describing which conditions were
            satisfied and how. Keys are condition names, values describe
            the match (e.g., {"provider": "openai", "model": "gpt-4"}).
        all_matches: Tuple of all rules that matched, sorted by priority.
            Useful for auditing and debugging to see which other rules
            would have applied if not for higher priority rules.
    """

    matched: bool = False
    rule: PolicyRule | None = None
    match_score: float = 0.0
    matched_conditions: dict[str, Any] = field(default_factory=dict)
    all_matches: tuple[PolicyRule, ...] = field(default_factory=tuple)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the match result to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the match result to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        if self.matched and self.rule:
            return (
                f"PolicyMatch(matched=True, rule={self.rule.name!r}, "
                f"score={self.match_score}, conditions={self.matched_conditions})"
            )
        return "PolicyMatch(matched=False)"
