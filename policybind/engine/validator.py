"""
Policy validator for PolicyBind.

This module provides the PolicyValidator class for validating
parsed policies for semantic correctness.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from policybind.engine.actions import Action
from policybind.models.policy import PolicyRule, PolicySet


class MessageLevel(Enum):
    """Severity level for validation messages."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationMessage:
    """
    A validation message with severity and context.

    Attributes:
        level: Severity level of the message.
        message: Human-readable description of the issue.
        rule_name: Name of the rule the message relates to, if any.
        field_name: Name of the field the message relates to, if any.
        details: Additional details about the issue.
    """

    level: MessageLevel
    message: str
    rule_name: str = ""
    field_name: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        """Return formatted message string."""
        prefix = f"[{self.level.value.upper()}]"
        if self.rule_name:
            prefix += f" Rule '{self.rule_name}'"
        if self.field_name:
            prefix += f" field '{self.field_name}'"
        return f"{prefix}: {self.message}"


@dataclass
class ValidationResult:
    """
    Result of policy validation.

    Attributes:
        valid: Whether the policy is valid (no errors).
        errors: List of error messages.
        warnings: List of warning messages.
        info: List of informational messages.
    """

    valid: bool = True
    errors: list[ValidationMessage] = field(default_factory=list)
    warnings: list[ValidationMessage] = field(default_factory=list)
    info: list[ValidationMessage] = field(default_factory=list)

    def add_error(
        self,
        message: str,
        rule_name: str = "",
        field_name: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Add an error message."""
        self.valid = False
        self.errors.append(
            ValidationMessage(
                level=MessageLevel.ERROR,
                message=message,
                rule_name=rule_name,
                field_name=field_name,
                details=details or {},
            )
        )

    def add_warning(
        self,
        message: str,
        rule_name: str = "",
        field_name: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Add a warning message."""
        self.warnings.append(
            ValidationMessage(
                level=MessageLevel.WARNING,
                message=message,
                rule_name=rule_name,
                field_name=field_name,
                details=details or {},
            )
        )

    def add_info(
        self,
        message: str,
        rule_name: str = "",
        field_name: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Add an informational message."""
        self.info.append(
            ValidationMessage(
                level=MessageLevel.INFO,
                message=message,
                rule_name=rule_name,
                field_name=field_name,
                details=details or {},
            )
        )

    def all_messages(self) -> list[ValidationMessage]:
        """Get all messages in order of severity."""
        return self.errors + self.warnings + self.info


class PolicyValidator:
    """
    Validates parsed policies for semantic correctness.

    The PolicyValidator checks:
    - Action references are valid
    - Match condition syntax is correct
    - No conflicting rules (same conditions, different actions)
    - No unreachable rules (shadowed by higher priority)
    - No circular dependencies
    - Required fields are present

    Example:
        Validating a policy::

            validator = PolicyValidator()
            result = validator.validate(policy_set)

            if not result.valid:
                for error in result.errors:
                    print(f"Error: {error}")

            for warning in result.warnings:
                print(f"Warning: {warning}")
    """

    # Valid condition operators
    VALID_OPERATORS = {
        "eq",      # equals
        "ne",      # not equals
        "gt",      # greater than
        "gte",     # greater than or equal
        "lt",      # less than
        "lte",     # less than or equal
        "in",      # in list
        "not_in",  # not in list
        "contains",     # contains substring/element
        "not_contains", # does not contain
        "matches",      # regex match
        "exists",       # field exists
        "not_exists",   # field does not exist
    }

    # Valid condition fields
    VALID_CONDITION_FIELDS = {
        "provider",
        "model",
        "department",
        "user",
        "user_id",
        "data_classification",
        "use_case",
        "intended_use_case",
        "cost",
        "estimated_cost",
        "tokens",
        "estimated_tokens",
        "time",
        "day_of_week",
        "hour_of_day",
        "source",
        "source_application",
        "metadata",
        "and",
        "or",
        "not",
        "all",
        "any",
    }

    def __init__(self) -> None:
        """Initialize the policy validator."""
        self._valid_actions = {action.value for action in Action}

    def validate(self, policy_set: PolicySet) -> ValidationResult:
        """
        Validate a PolicySet.

        Args:
            policy_set: The PolicySet to validate.

        Returns:
            ValidationResult containing any errors, warnings, or info.
        """
        result = ValidationResult()

        # Validate policy set metadata
        self._validate_policy_set(policy_set, result)

        # Validate individual rules
        for rule in policy_set.rules:
            self._validate_rule(rule, result)

        # Check for duplicate rule names
        self._check_duplicate_names(policy_set, result)

        # Check for conflicting rules
        self._check_conflicting_rules(policy_set, result)

        # Check for unreachable rules
        self._check_unreachable_rules(policy_set, result)

        # Add summary info
        enabled_count = len([r for r in policy_set.rules if r.enabled])
        result.add_info(
            f"Policy contains {len(policy_set.rules)} rules "
            f"({enabled_count} enabled)",
        )

        return result

    def _validate_policy_set(
        self,
        policy_set: PolicySet,
        result: ValidationResult,
    ) -> None:
        """Validate PolicySet metadata."""
        if not policy_set.name:
            result.add_warning("Policy set has no name")

        if not policy_set.version:
            result.add_warning("Policy set has no version")

        if not policy_set.rules:
            result.add_warning("Policy set has no rules")

    def _validate_rule(
        self,
        rule: PolicyRule,
        result: ValidationResult,
    ) -> None:
        """Validate a single PolicyRule."""
        # Check rule name
        if not rule.name:
            result.add_error("Rule has no name")
            return

        # Check action
        if rule.action not in self._valid_actions:
            result.add_error(
                f"Invalid action: {rule.action}. "
                f"Valid actions: {sorted(self._valid_actions)}",
                rule_name=rule.name,
                field_name="action",
            )

        # Check match conditions
        if not rule.match_conditions:
            result.add_warning(
                "Rule has no match conditions (will match all requests)",
                rule_name=rule.name,
            )
        else:
            self._validate_conditions(rule.match_conditions, rule.name, result)

        # Check action params based on action type
        self._validate_action_params(rule, result)

        # Check for disabled rule
        if not rule.enabled:
            result.add_info(
                "Rule is disabled",
                rule_name=rule.name,
            )

    def _validate_conditions(
        self,
        conditions: dict[str, Any],
        rule_name: str,
        result: ValidationResult,
        path: str = "",
    ) -> None:
        """Recursively validate match conditions."""
        for key, value in conditions.items():
            current_path = f"{path}.{key}" if path else key

            # Check for logical operators
            if key in ("and", "or", "all", "any"):
                if not isinstance(value, list):
                    result.add_error(
                        f"Logical operator '{key}' requires a list of conditions",
                        rule_name=rule_name,
                        field_name=current_path,
                    )
                else:
                    for i, sub_condition in enumerate(value):
                        if isinstance(sub_condition, dict):
                            self._validate_conditions(
                                sub_condition,
                                rule_name,
                                result,
                                f"{current_path}[{i}]",
                            )
                continue

            if key == "not":
                if isinstance(value, dict):
                    self._validate_conditions(value, rule_name, result, current_path)
                else:
                    result.add_error(
                        "'not' operator requires a condition mapping",
                        rule_name=rule_name,
                        field_name=current_path,
                    )
                continue

            # Check if field is known
            if key not in self.VALID_CONDITION_FIELDS:
                result.add_warning(
                    f"Unknown condition field: {key}. "
                    "This may be a custom field or a typo.",
                    rule_name=rule_name,
                    field_name=current_path,
                )

            # Validate condition value structure
            if isinstance(value, dict):
                self._validate_condition_operators(value, rule_name, current_path, result)

    def _validate_condition_operators(
        self,
        condition: dict[str, Any],
        rule_name: str,
        path: str,
        result: ValidationResult,
    ) -> None:
        """Validate condition operators."""
        for operator, operand in condition.items():
            if operator not in self.VALID_OPERATORS:
                result.add_warning(
                    f"Unknown operator: {operator}. "
                    f"Valid operators: {sorted(self.VALID_OPERATORS)}",
                    rule_name=rule_name,
                    field_name=f"{path}.{operator}",
                )

            # Check operand types for specific operators
            if operator in ("in", "not_in", "contains", "not_contains"):
                if not isinstance(operand, (list, str)):
                    result.add_warning(
                        f"Operator '{operator}' typically expects a list or string",
                        rule_name=rule_name,
                        field_name=f"{path}.{operator}",
                    )

            if operator in ("gt", "gte", "lt", "lte"):
                if not isinstance(operand, (int, float)):
                    result.add_warning(
                        f"Operator '{operator}' expects a numeric value",
                        rule_name=rule_name,
                        field_name=f"{path}.{operator}",
                    )

    def _validate_action_params(
        self,
        rule: PolicyRule,
        result: ValidationResult,
    ) -> None:
        """Validate action parameters based on action type."""
        action = rule.action
        params = rule.action_params

        if action == "MODIFY":
            if not params:
                result.add_warning(
                    "MODIFY action has no action_params specifying modifications",
                    rule_name=rule.name,
                    field_name="action_params",
                )

        elif action == "REDIRECT":
            if not params.get("target_model") and not params.get("target_provider"):
                result.add_warning(
                    "REDIRECT action should specify target_model or target_provider",
                    rule_name=rule.name,
                    field_name="action_params",
                )

        elif action == "RATE_LIMIT":
            if not params.get("requests_per_minute"):
                result.add_warning(
                    "RATE_LIMIT action should specify requests_per_minute",
                    rule_name=rule.name,
                    field_name="action_params",
                )

        elif action == "REQUIRE_APPROVAL":
            if not params.get("approvers"):
                result.add_info(
                    "REQUIRE_APPROVAL action has no approvers specified",
                    rule_name=rule.name,
                    field_name="action_params",
                )

    def _check_duplicate_names(
        self,
        policy_set: PolicySet,
        result: ValidationResult,
    ) -> None:
        """Check for duplicate rule names."""
        seen: dict[str, int] = {}
        for rule in policy_set.rules:
            if rule.name in seen:
                result.add_error(
                    f"Duplicate rule name: {rule.name}",
                    rule_name=rule.name,
                    details={"first_occurrence": seen[rule.name]},
                )
            else:
                seen[rule.name] = len(seen) + 1

    def _check_conflicting_rules(
        self,
        policy_set: PolicySet,
        result: ValidationResult,
    ) -> None:
        """
        Check for conflicting rules.

        Conflicting rules have the same priority and match conditions
        but different actions.
        """
        rules = [r for r in policy_set.rules if r.enabled]

        for i, rule1 in enumerate(rules):
            for rule2 in rules[i + 1 :]:
                if (
                    rule1.priority == rule2.priority
                    and rule1.action != rule2.action
                    and self._conditions_overlap(
                        rule1.match_conditions, rule2.match_conditions
                    )
                ):
                    result.add_warning(
                        f"Potentially conflicting rules with same priority: "
                        f"'{rule1.name}' ({rule1.action}) and "
                        f"'{rule2.name}' ({rule2.action})",
                        rule_name=rule1.name,
                        details={"other_rule": rule2.name},
                    )

    def _check_unreachable_rules(
        self,
        policy_set: PolicySet,
        result: ValidationResult,
    ) -> None:
        """
        Check for unreachable rules.

        A rule is unreachable if a higher priority rule with the same
        or broader conditions will always match first.
        """
        rules = sorted(
            [r for r in policy_set.rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

        for i, rule in enumerate(rules):
            for higher_priority_rule in rules[:i]:
                if self._is_shadowed_by(rule, higher_priority_rule):
                    result.add_warning(
                        f"Rule may be unreachable - shadowed by "
                        f"higher priority rule '{higher_priority_rule.name}'",
                        rule_name=rule.name,
                        details={
                            "shadowing_rule": higher_priority_rule.name,
                            "shadowing_priority": higher_priority_rule.priority,
                        },
                    )
                    break  # Only report once per rule

    def _conditions_overlap(
        self,
        cond1: dict[str, Any],
        cond2: dict[str, Any],
    ) -> bool:
        """
        Check if two condition sets might overlap.

        This is a heuristic check - exact overlap detection would
        require full condition evaluation.
        """
        if not cond1 or not cond2:
            return True  # Empty conditions match everything

        # Check if they reference the same fields
        fields1 = set(cond1.keys())
        fields2 = set(cond2.keys())

        # If no common fields, they might still overlap
        common_fields = fields1 & fields2
        if not common_fields:
            return True  # Can't determine non-overlap

        # Check if any common field has different values
        for field in common_fields:
            val1 = cond1[field]
            val2 = cond2[field]
            if val1 != val2:
                # Different values might not overlap
                # But this is a heuristic - could be wrong
                return False

        return True

    def _is_shadowed_by(
        self,
        rule: PolicyRule,
        other: PolicyRule,
    ) -> bool:
        """
        Check if a rule is shadowed by another.

        A rule is shadowed if the other rule:
        - Has higher or equal priority
        - Has conditions that are a superset (or equal) of this rule's conditions
        """
        if other.priority < rule.priority:
            return False

        # Empty conditions match everything
        if not other.match_conditions:
            return True

        if not rule.match_conditions:
            return False

        # Check if other's conditions are a subset of rule's
        # (meaning other matches everything rule matches and possibly more)
        return self._is_condition_subset(other.match_conditions, rule.match_conditions)

    def _is_condition_subset(
        self,
        subset: dict[str, Any],
        superset: dict[str, Any],
    ) -> bool:
        """
        Check if subset conditions are contained within superset.

        This is a heuristic - returns True if subset appears to
        match a broader set of requests than superset.
        """
        # If subset is empty, it matches everything
        if not subset:
            return True

        # If superset is empty but subset isn't, subset is more restrictive
        if not superset:
            return False

        # Check if all fields in subset are also in superset with same values
        for key, value in subset.items():
            if key not in superset:
                return False
            if superset[key] != value:
                return False

        return True
