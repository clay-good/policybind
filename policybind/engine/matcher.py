"""
Policy matcher for PolicyBind.

This module provides the PolicyMatcher class that evaluates requests
against policy rules and returns matching results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from policybind.engine.conditions import (
    Condition,
    ConditionFactory,
    EvaluationContext,
)
from policybind.models.policy import PolicyMatch, PolicyRule, PolicySet
from policybind.models.request import AIRequest


@dataclass
class MatchResult:
    """
    Result of matching a single rule against a request.

    Attributes:
        rule: The policy rule that was evaluated.
        matched: Whether the rule matched the request.
        score: Match score for ranking (higher is more specific).
        matched_fields: Fields that contributed to the match.
    """

    rule: PolicyRule
    matched: bool
    score: float = 0.0
    matched_fields: dict[str, Any] = field(default_factory=dict)


class PolicyMatcher:
    """
    Evaluates requests against policies to find matching rules.

    The PolicyMatcher takes a PolicySet and evaluates an AIRequest
    against all enabled rules, returning all matching rules sorted
    by priority.

    Example:
        Matching a request against policies::

            matcher = PolicyMatcher()
            match = matcher.match(policy_set, request)

            if match.matched:
                print(f"Matched rule: {match.rule.name}")
                print(f"Action: {match.rule.action}")
    """

    def __init__(self) -> None:
        """Initialize the policy matcher."""
        self._condition_factory = ConditionFactory()
        self._compiled_conditions: dict[str, Condition] = {}

    def match(
        self,
        policy_set: PolicySet,
        request: AIRequest,
        current_time: datetime | None = None,
    ) -> PolicyMatch:
        """
        Match a request against a policy set.

        Args:
            policy_set: The PolicySet containing rules to match against.
            request: The AIRequest to match.
            current_time: Optional current time for time-based conditions.

        Returns:
            PolicyMatch with the highest priority matching rule (if any).
        """
        # Build evaluation context from request
        context = self._build_context(request, current_time)

        # Get enabled rules sorted by priority (highest first)
        enabled_rules = policy_set.get_enabled_rules()

        # Find all matching rules
        all_matches: list[PolicyRule] = []
        matched_conditions: dict[str, Any] = {}

        for rule in enabled_rules:
            result = self._evaluate_rule(rule, context)
            if result.matched:
                all_matches.append(rule)
                if not matched_conditions:
                    # Record matched conditions from the first (highest priority) match
                    matched_conditions = result.matched_fields

        if not all_matches:
            return PolicyMatch(matched=False)

        # The first match is the highest priority
        best_match = all_matches[0]
        best_result = self._evaluate_rule(best_match, context)

        return PolicyMatch(
            matched=True,
            rule=best_match,
            match_score=best_result.score,
            matched_conditions=matched_conditions,
            all_matches=tuple(all_matches),
        )

    def match_all(
        self,
        policy_set: PolicySet,
        request: AIRequest,
        current_time: datetime | None = None,
    ) -> list[MatchResult]:
        """
        Find all rules that match a request.

        Args:
            policy_set: The PolicySet containing rules to match against.
            request: The AIRequest to match.
            current_time: Optional current time for time-based conditions.

        Returns:
            List of MatchResult for all matching rules, sorted by priority.
        """
        context = self._build_context(request, current_time)
        enabled_rules = policy_set.get_enabled_rules()

        results = []
        for rule in enabled_rules:
            result = self._evaluate_rule(rule, context)
            if result.matched:
                results.append(result)

        return results

    def would_match(
        self,
        rule: PolicyRule,
        request: AIRequest,
        current_time: datetime | None = None,
    ) -> bool:
        """
        Check if a single rule would match a request.

        This is a convenience method for testing individual rules.

        Args:
            rule: The PolicyRule to test.
            request: The AIRequest to match.
            current_time: Optional current time for time-based conditions.

        Returns:
            True if the rule matches, False otherwise.
        """
        if not rule.enabled:
            return False

        context = self._build_context(request, current_time)
        result = self._evaluate_rule(rule, context)
        return result.matched

    def _build_context(
        self,
        request: AIRequest,
        current_time: datetime | None,
    ) -> EvaluationContext:
        """
        Build an evaluation context from a request.

        Args:
            request: The AIRequest to convert.
            current_time: Optional current time override.

        Returns:
            EvaluationContext for condition evaluation.
        """
        # Convert request to dictionary for context
        data: dict[str, Any] = {
            "provider": request.provider,
            "model": request.model,
            "user": request.user_id,
            "user_id": request.user_id,
            "department": request.department,
            "source": request.source_application,
            "source_application": request.source_application,
            "use_case": request.intended_use_case,
            "intended_use_case": request.intended_use_case,
            "data_classification": request.data_classification,
            "cost": request.estimated_cost,
            "estimated_cost": request.estimated_cost,
            "tokens": request.estimated_tokens,
            "estimated_tokens": request.estimated_tokens,
            "metadata": request.metadata,
        }

        # Add metadata fields to top-level for easier access
        if request.metadata:
            for key, value in request.metadata.items():
                if key not in data:
                    data[key] = value

        return EvaluationContext(
            data=data,
            metadata=request.metadata,
            current_time=current_time or datetime.now(),
        )

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        context: EvaluationContext,
    ) -> MatchResult:
        """
        Evaluate a single rule against the context.

        Args:
            rule: The PolicyRule to evaluate.
            context: The evaluation context.

        Returns:
            MatchResult indicating if the rule matched.
        """
        # Get or compile the condition for this rule
        condition = self._get_condition(rule)

        # Evaluate the condition
        matched = condition.evaluate(context)

        # Calculate match score based on specificity
        score = self._calculate_score(rule, context) if matched else 0.0

        # Collect matched fields
        matched_fields = self._collect_matched_fields(rule, context) if matched else {}

        return MatchResult(
            rule=rule,
            matched=matched,
            score=score,
            matched_fields=matched_fields,
        )

    def _get_condition(self, rule: PolicyRule) -> Condition:
        """
        Get or create a compiled condition for a rule.

        Args:
            rule: The PolicyRule to get the condition for.

        Returns:
            A Condition object for the rule.
        """
        # Use rule ID as cache key
        cache_key = rule.id

        if cache_key not in self._compiled_conditions:
            self._compiled_conditions[cache_key] = self._condition_factory.create(
                rule.match_conditions
            )

        return self._compiled_conditions[cache_key]

    def _calculate_score(
        self,
        rule: PolicyRule,
        context: EvaluationContext,
    ) -> float:
        """
        Calculate a match score for ranking.

        Higher scores indicate more specific matches. The score is based on:
        - Number of conditions matched
        - Specificity of each condition
        - Priority of the rule

        Args:
            rule: The matched PolicyRule.
            context: The evaluation context.

        Returns:
            A score between 0.0 and 1.0.
        """
        if not rule.match_conditions:
            # Empty conditions = least specific
            return 0.1

        # Count the number of condition fields
        field_count = self._count_condition_fields(rule.match_conditions)

        # Base score from field count (more fields = more specific)
        base_score = min(field_count / 10.0, 0.5)

        # Add priority contribution (normalized to 0.0-0.5)
        priority_score = min(rule.priority / 2000.0, 0.5)

        return base_score + priority_score

    def _count_condition_fields(self, conditions: dict[str, Any]) -> int:
        """
        Count the number of field conditions in a condition dict.

        Args:
            conditions: The conditions dictionary.

        Returns:
            Number of field conditions.
        """
        count = 0
        for key, value in conditions.items():
            if key in ("and", "or", "all", "any"):
                if isinstance(value, list):
                    for sub in value:
                        if isinstance(sub, dict):
                            count += self._count_condition_fields(sub)
            elif key == "not":
                if isinstance(value, dict):
                    count += self._count_condition_fields(value)
            else:
                count += 1
        return count

    def _collect_matched_fields(
        self,
        rule: PolicyRule,
        context: EvaluationContext,
    ) -> dict[str, Any]:
        """
        Collect the field values that contributed to the match.

        Args:
            rule: The matched PolicyRule.
            context: The evaluation context.

        Returns:
            Dictionary of field names to their matched values.
        """
        matched = {}
        self._collect_fields(rule.match_conditions, context, matched)
        return matched

    def _collect_fields(
        self,
        conditions: dict[str, Any],
        context: EvaluationContext,
        matched: dict[str, Any],
    ) -> None:
        """
        Recursively collect matched field values.

        Args:
            conditions: The conditions dictionary.
            context: The evaluation context.
            matched: Dictionary to populate with matched values.
        """
        for key, value in conditions.items():
            if key in ("and", "or", "all", "any"):
                if isinstance(value, list):
                    for sub in value:
                        if isinstance(sub, dict):
                            self._collect_fields(sub, context, matched)
            elif key == "not":
                if isinstance(value, dict):
                    self._collect_fields(value, context, matched)
            else:
                # Regular field
                field_value = context.get(key)
                if field_value is not None:
                    matched[key] = field_value

    def clear_cache(self) -> None:
        """Clear the compiled condition cache."""
        self._compiled_conditions.clear()
        self._condition_factory.clear_cache()

    def precompile(self, policy_set: PolicySet) -> None:
        """
        Precompile all conditions in a policy set.

        This can be called during initialization to avoid
        compilation overhead on the first request.

        Args:
            policy_set: The PolicySet to precompile conditions for.
        """
        for rule in policy_set.rules:
            if rule.enabled:
                self._get_condition(rule)
