"""
Condition evaluators for PolicyBind policy matching.

This module provides individual condition evaluator classes that implement
the Condition interface. Conditions are composable and support complex
logical expressions (AND, OR, NOT).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re
from typing import Any, Callable


class Operator(Enum):
    """Comparison operators for conditions."""

    EQ = "eq"           # equals
    NE = "ne"           # not equals
    GT = "gt"           # greater than
    GTE = "gte"         # greater than or equal
    LT = "lt"           # less than
    LTE = "lte"         # less than or equal
    IN = "in"           # in list
    NOT_IN = "not_in"   # not in list
    CONTAINS = "contains"       # contains substring/element
    NOT_CONTAINS = "not_contains"   # does not contain
    MATCHES = "matches"         # regex match
    EXISTS = "exists"           # field exists
    NOT_EXISTS = "not_exists"   # field does not exist


@dataclass
class EvaluationContext:
    """
    Context for condition evaluation.

    Contains the request data and any additional context needed
    for evaluating conditions.

    Attributes:
        data: Dictionary of field values from the request.
        metadata: Additional metadata for evaluation.
        current_time: Current time for time-based conditions.
    """

    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    current_time: datetime | None = None

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a value from the context.

        Supports dot notation for nested access (e.g., "metadata.project").

        Args:
            key: The key to look up, supports dot notation.
            default: Default value if key is not found.

        Returns:
            The value at the key, or the default.
        """
        parts = key.split(".")
        value: Any = self.data

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
                if value is None:
                    return default
            else:
                return default

        return value if value is not None else default

    def has(self, key: str) -> bool:
        """
        Check if a key exists in the context.

        Args:
            key: The key to check, supports dot notation.

        Returns:
            True if the key exists, False otherwise.
        """
        parts = key.split(".")
        value: Any = self.data

        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return False

        return True


class Condition(ABC):
    """
    Abstract base class for all condition evaluators.

    Conditions are used to evaluate whether a request matches
    a policy rule. They can be simple field comparisons or
    complex logical expressions.
    """

    @abstractmethod
    def evaluate(self, context: EvaluationContext) -> bool:
        """
        Evaluate the condition against the given context.

        Args:
            context: The evaluation context containing request data.

        Returns:
            True if the condition matches, False otherwise.
        """
        pass

    @abstractmethod
    def describe(self) -> str:
        """
        Return a human-readable description of the condition.

        Returns:
            A string describing what this condition checks.
        """
        pass


@dataclass
class FieldCondition(Condition):
    """
    A condition that compares a field value using an operator.

    This is the most common condition type, checking if a field
    matches a given value using various comparison operators.

    Attributes:
        field_name: Name of the field to check.
        operator: The comparison operator.
        value: The value to compare against.
    """

    field_name: str
    operator: Operator
    value: Any

    def evaluate(self, context: EvaluationContext) -> bool:
        """Evaluate the field condition."""
        field_value = context.get(self.field_name)

        if self.operator == Operator.EXISTS:
            return context.has(self.field_name) if self.value else not context.has(self.field_name)

        if self.operator == Operator.NOT_EXISTS:
            return not context.has(self.field_name) if self.value else context.has(self.field_name)

        # For other operators, if the field doesn't exist, return False
        if field_value is None:
            return False

        return self._compare(field_value)

    def _compare(self, field_value: Any) -> bool:
        """Perform the comparison based on operator."""
        if self.operator == Operator.EQ:
            return field_value == self.value

        elif self.operator == Operator.NE:
            return field_value != self.value

        elif self.operator == Operator.GT:
            return self._numeric_compare(field_value, lambda a, b: a > b)

        elif self.operator == Operator.GTE:
            return self._numeric_compare(field_value, lambda a, b: a >= b)

        elif self.operator == Operator.LT:
            return self._numeric_compare(field_value, lambda a, b: a < b)

        elif self.operator == Operator.LTE:
            return self._numeric_compare(field_value, lambda a, b: a <= b)

        elif self.operator == Operator.IN:
            if isinstance(self.value, (list, tuple, set)):
                return field_value in self.value
            return False

        elif self.operator == Operator.NOT_IN:
            if isinstance(self.value, (list, tuple, set)):
                return field_value not in self.value
            return True

        elif self.operator == Operator.CONTAINS:
            return self._contains(field_value, self.value)

        elif self.operator == Operator.NOT_CONTAINS:
            return not self._contains(field_value, self.value)

        elif self.operator == Operator.MATCHES:
            return self._regex_match(field_value, self.value)

        return False

    def _numeric_compare(
        self,
        field_value: Any,
        comparator: Callable[[Any, Any], bool],
    ) -> bool:
        """Perform a numeric comparison."""
        try:
            return comparator(float(field_value), float(self.value))
        except (TypeError, ValueError):
            return False

    def _contains(self, field_value: Any, search_value: Any) -> bool:
        """Check if field_value contains search_value."""
        if isinstance(field_value, str):
            return str(search_value) in field_value
        elif isinstance(field_value, (list, tuple, set)):
            return search_value in field_value
        return False

    def _regex_match(self, field_value: Any, pattern: Any) -> bool:
        """Check if field_value matches the regex pattern."""
        try:
            return bool(re.search(str(pattern), str(field_value)))
        except re.error:
            return False

    def describe(self) -> str:
        """Return a human-readable description."""
        return f"{self.field_name} {self.operator.value} {self.value!r}"


@dataclass
class AndCondition(Condition):
    """
    A condition that combines multiple conditions with AND logic.

    All sub-conditions must evaluate to True for this condition to match.

    Attributes:
        conditions: List of conditions to combine.
    """

    conditions: list[Condition] = field(default_factory=list)

    def evaluate(self, context: EvaluationContext) -> bool:
        """All conditions must match."""
        if not self.conditions:
            return True  # Empty AND is true
        return all(c.evaluate(context) for c in self.conditions)

    def describe(self) -> str:
        """Return a human-readable description."""
        if not self.conditions:
            return "(always true)"
        descriptions = [c.describe() for c in self.conditions]
        return f"({' AND '.join(descriptions)})"


@dataclass
class OrCondition(Condition):
    """
    A condition that combines multiple conditions with OR logic.

    At least one sub-condition must evaluate to True for this condition to match.

    Attributes:
        conditions: List of conditions to combine.
    """

    conditions: list[Condition] = field(default_factory=list)

    def evaluate(self, context: EvaluationContext) -> bool:
        """At least one condition must match."""
        if not self.conditions:
            return False  # Empty OR is false
        return any(c.evaluate(context) for c in self.conditions)

    def describe(self) -> str:
        """Return a human-readable description."""
        if not self.conditions:
            return "(always false)"
        descriptions = [c.describe() for c in self.conditions]
        return f"({' OR '.join(descriptions)})"


@dataclass
class NotCondition(Condition):
    """
    A condition that negates another condition.

    Attributes:
        condition: The condition to negate.
    """

    condition: Condition

    def evaluate(self, context: EvaluationContext) -> bool:
        """Negate the inner condition's result."""
        return not self.condition.evaluate(context)

    def describe(self) -> str:
        """Return a human-readable description."""
        return f"NOT ({self.condition.describe()})"


@dataclass
class TimeCondition(Condition):
    """
    A condition that matches based on time of day or day of week.

    Attributes:
        day_of_week: Day of week to match (0=Monday, 6=Sunday), or None.
        hour_start: Start hour (0-23), or None.
        hour_end: End hour (0-23), or None.
    """

    day_of_week: int | list[int] | None = None
    hour_start: int | None = None
    hour_end: int | None = None

    def evaluate(self, context: EvaluationContext) -> bool:
        """Check if current time matches the condition."""
        current = context.current_time or datetime.now()

        # Check day of week
        if self.day_of_week is not None:
            current_dow = current.weekday()
            if isinstance(self.day_of_week, list):
                if current_dow not in self.day_of_week:
                    return False
            elif current_dow != self.day_of_week:
                return False

        # Check hour range
        if self.hour_start is not None or self.hour_end is not None:
            current_hour = current.hour
            start = self.hour_start if self.hour_start is not None else 0
            end = self.hour_end if self.hour_end is not None else 23

            if start <= end:
                # Normal range (e.g., 9-17)
                if not (start <= current_hour <= end):
                    return False
            else:
                # Overnight range (e.g., 22-6)
                if not (current_hour >= start or current_hour <= end):
                    return False

        return True

    def describe(self) -> str:
        """Return a human-readable description."""
        parts = []
        if self.day_of_week is not None:
            days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            if isinstance(self.day_of_week, list):
                day_names = [days[d] for d in self.day_of_week if 0 <= d <= 6]
                parts.append(f"days={','.join(day_names)}")
            elif 0 <= self.day_of_week <= 6:
                parts.append(f"day={days[self.day_of_week]}")

        if self.hour_start is not None or self.hour_end is not None:
            start = self.hour_start if self.hour_start is not None else 0
            end = self.hour_end if self.hour_end is not None else 23
            parts.append(f"hours={start}-{end}")

        return f"time({', '.join(parts)})"


@dataclass
class AlwaysTrueCondition(Condition):
    """
    A condition that always matches.

    Used for catch-all rules with empty match conditions.
    """

    def evaluate(self, context: EvaluationContext) -> bool:
        """Always returns True."""
        return True

    def describe(self) -> str:
        """Return a human-readable description."""
        return "(always true)"


@dataclass
class AlwaysFalseCondition(Condition):
    """
    A condition that never matches.

    Used for disabled rules or testing.
    """

    def evaluate(self, context: EvaluationContext) -> bool:
        """Always returns False."""
        return False

    def describe(self) -> str:
        """Return a human-readable description."""
        return "(always false)"


class ConditionFactory:
    """
    Factory for creating conditions from parsed policy YAML.

    Converts the dictionary representation of match conditions into
    Condition objects that can be evaluated efficiently.
    """

    # Mapping of operator strings to Operator enum
    OPERATOR_MAP = {
        "eq": Operator.EQ,
        "ne": Operator.NE,
        "gt": Operator.GT,
        "gte": Operator.GTE,
        "lt": Operator.LT,
        "lte": Operator.LTE,
        "in": Operator.IN,
        "not_in": Operator.NOT_IN,
        "contains": Operator.CONTAINS,
        "not_contains": Operator.NOT_CONTAINS,
        "matches": Operator.MATCHES,
        "exists": Operator.EXISTS,
        "not_exists": Operator.NOT_EXISTS,
    }

    def __init__(self) -> None:
        """Initialize the condition factory."""
        self._pattern_cache: dict[str, re.Pattern[str]] = {}

    def create(self, match_conditions: dict[str, Any]) -> Condition:
        """
        Create a Condition from a match_conditions dictionary.

        Args:
            match_conditions: Dictionary of match conditions from policy YAML.

        Returns:
            A Condition object that can be evaluated.
        """
        if not match_conditions:
            return AlwaysTrueCondition()

        return self._parse_conditions(match_conditions)

    def _parse_conditions(self, conditions: dict[str, Any]) -> Condition:
        """
        Parse a conditions dictionary into a Condition object.

        Args:
            conditions: Dictionary of conditions.

        Returns:
            A Condition object.
        """
        # Check for logical operators at the top level
        if "and" in conditions or "all" in conditions:
            sub_conditions = conditions.get("and") or conditions.get("all")
            if isinstance(sub_conditions, list):
                return self._create_and(sub_conditions)

        if "or" in conditions or "any" in conditions:
            sub_conditions = conditions.get("or") or conditions.get("any")
            if isinstance(sub_conditions, list):
                return self._create_or(sub_conditions)

        if "not" in conditions:
            sub_condition = conditions["not"]
            if isinstance(sub_condition, dict):
                return NotCondition(self._parse_conditions(sub_condition))

        # Multiple top-level conditions are implicitly AND-ed
        field_conditions = []
        for key, value in conditions.items():
            if key in ("and", "or", "not", "all", "any"):
                continue
            field_condition = self._create_field_condition(key, value)
            field_conditions.append(field_condition)

        if len(field_conditions) == 0:
            return AlwaysTrueCondition()
        elif len(field_conditions) == 1:
            return field_conditions[0]
        else:
            return AndCondition(conditions=field_conditions)

    def _create_and(self, conditions_list: list[dict[str, Any]]) -> Condition:
        """Create an AND condition from a list of condition dicts."""
        sub_conditions = [
            self._parse_conditions(c) for c in conditions_list
            if isinstance(c, dict)
        ]
        if len(sub_conditions) == 0:
            return AlwaysTrueCondition()
        elif len(sub_conditions) == 1:
            return sub_conditions[0]
        return AndCondition(conditions=sub_conditions)

    def _create_or(self, conditions_list: list[dict[str, Any]]) -> Condition:
        """Create an OR condition from a list of condition dicts."""
        sub_conditions = [
            self._parse_conditions(c) for c in conditions_list
            if isinstance(c, dict)
        ]
        if len(sub_conditions) == 0:
            return AlwaysFalseCondition()
        elif len(sub_conditions) == 1:
            return sub_conditions[0]
        return OrCondition(conditions=sub_conditions)

    def _create_field_condition(self, field_name: str, value: Any) -> Condition:
        """
        Create a field condition from a field name and value.

        Args:
            field_name: The name of the field.
            value: The value or operator expression.

        Returns:
            A Condition for the field.
        """
        # Handle special time conditions
        if field_name == "time":
            return self._create_time_condition(value)

        if field_name == "day_of_week":
            return self._create_day_of_week_condition(value)

        if field_name == "hour_of_day":
            return self._create_hour_condition(value)

        # Simple equality check
        if not isinstance(value, dict):
            return FieldCondition(
                field_name=field_name,
                operator=Operator.EQ,
                value=value,
            )

        # Operator-based condition
        conditions = []
        for op_str, op_value in value.items():
            operator = self.OPERATOR_MAP.get(op_str)
            if operator:
                conditions.append(FieldCondition(
                    field_name=field_name,
                    operator=operator,
                    value=op_value,
                ))
            else:
                # Treat unknown operators as nested field access
                nested_field = f"{field_name}.{op_str}"
                conditions.append(self._create_field_condition(nested_field, op_value))

        if len(conditions) == 0:
            return AlwaysTrueCondition()
        elif len(conditions) == 1:
            return conditions[0]
        else:
            return AndCondition(conditions=conditions)

    def _create_time_condition(self, value: Any) -> Condition:
        """Create a time-based condition."""
        if isinstance(value, dict):
            return TimeCondition(
                day_of_week=value.get("day_of_week"),
                hour_start=value.get("hour_start"),
                hour_end=value.get("hour_end"),
            )
        return AlwaysTrueCondition()

    def _create_day_of_week_condition(self, value: Any) -> Condition:
        """Create a day-of-week condition."""
        if isinstance(value, int):
            return TimeCondition(day_of_week=value)
        elif isinstance(value, list):
            return TimeCondition(day_of_week=value)
        elif isinstance(value, dict):
            # Support operator syntax for day_of_week
            if "in" in value:
                return TimeCondition(day_of_week=value["in"])
            elif "eq" in value:
                return TimeCondition(day_of_week=value["eq"])
        return AlwaysTrueCondition()

    def _create_hour_condition(self, value: Any) -> Condition:
        """Create an hour-of-day condition."""
        if isinstance(value, int):
            return TimeCondition(hour_start=value, hour_end=value)
        elif isinstance(value, dict):
            hour_start = value.get("gte") or value.get("gt")
            hour_end = value.get("lte") or value.get("lt")
            if hour_start is not None or hour_end is not None:
                return TimeCondition(hour_start=hour_start, hour_end=hour_end)
        return AlwaysTrueCondition()

    def get_pattern(self, pattern_str: str) -> re.Pattern[str]:
        """
        Get a compiled regex pattern, using cache if available.

        Args:
            pattern_str: The regex pattern string.

        Returns:
            A compiled regex pattern.
        """
        if pattern_str not in self._pattern_cache:
            self._pattern_cache[pattern_str] = re.compile(pattern_str)
        return self._pattern_cache[pattern_str]

    def clear_cache(self) -> None:
        """Clear the pattern cache."""
        self._pattern_cache.clear()
