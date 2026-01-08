"""
Match optimizer for PolicyBind.

This module provides the MatchOptimizer class that preprocesses policies
to create an efficient matching structure for low-latency evaluation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from policybind.engine.conditions import Condition, ConditionFactory
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest


@dataclass
class RuleIndex:
    """
    Index entry for a policy rule.

    Attributes:
        rule: The PolicyRule being indexed.
        condition: The compiled condition for the rule.
        indexed_fields: Fields that can be used for quick filtering.
    """

    rule: PolicyRule
    condition: Condition
    indexed_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchStats:
    """
    Statistics about match performance.

    Attributes:
        total_matches: Total number of match operations performed.
        total_rules_evaluated: Total rules evaluated across all matches.
        avg_rules_per_match: Average number of rules evaluated per match.
        cache_hits: Number of times cached conditions were used.
        cache_misses: Number of times conditions had to be compiled.
        last_match_time_us: Microseconds taken for the last match.
        avg_match_time_us: Average microseconds per match.
    """

    total_matches: int = 0
    total_rules_evaluated: int = 0
    avg_rules_per_match: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    last_match_time_us: int = 0
    avg_match_time_us: float = 0.0
    _total_time_us: int = 0


class MatchOptimizer:
    """
    Optimizes policy matching for low-latency evaluation.

    The MatchOptimizer preprocesses policies to create efficient
    matching structures, including:
    - Indexing rules by common field values
    - Caching compiled conditions
    - Filtering rules by quick checks before full evaluation

    Target: Sub-millisecond matching for typical policy sets (<100 rules).

    Example:
        Optimizing a policy set::

            optimizer = MatchOptimizer()
            optimizer.optimize(policy_set)

            # Fast matching using optimized structures
            candidates = optimizer.get_candidates(request)

            # Statistics
            stats = optimizer.get_stats()
            print(f"Avg rules evaluated: {stats.avg_rules_per_match}")
    """

    # Fields that can be indexed for quick lookups
    INDEXABLE_FIELDS = {
        "provider",
        "model",
        "department",
        "user",
        "user_id",
        "source",
        "source_application",
        "use_case",
        "data_classification",
    }

    def __init__(self) -> None:
        """Initialize the match optimizer."""
        self._condition_factory = ConditionFactory()
        self._rule_indices: list[RuleIndex] = []
        self._field_indices: dict[str, dict[Any, list[RuleIndex]]] = {}
        self._catch_all_rules: list[RuleIndex] = []
        self._optimized = False
        self._stats = MatchStats()

    def optimize(self, policy_set: PolicySet) -> None:
        """
        Optimize a policy set for fast matching.

        This precompiles all conditions and builds indices for
        quick candidate selection.

        Args:
            policy_set: The PolicySet to optimize.
        """
        self._rule_indices.clear()
        self._field_indices.clear()
        self._catch_all_rules.clear()

        # Get enabled rules sorted by priority
        enabled_rules = policy_set.get_enabled_rules()

        for rule in enabled_rules:
            # Compile the condition
            condition = self._condition_factory.create(rule.match_conditions)

            # Extract indexed fields
            indexed_fields = self._extract_indexed_fields(rule.match_conditions)

            rule_index = RuleIndex(
                rule=rule,
                condition=condition,
                indexed_fields=indexed_fields,
            )
            self._rule_indices.append(rule_index)

            # Build field indices
            if indexed_fields:
                self._add_to_indices(rule_index, indexed_fields)
            else:
                # Rules with no indexable conditions are "catch-all"
                self._catch_all_rules.append(rule_index)

        self._optimized = True
        self._stats.cache_hits = 0
        self._stats.cache_misses = len(enabled_rules)

    def get_candidates(self, request: AIRequest) -> list[RuleIndex]:
        """
        Get candidate rules that might match a request.

        This uses field indices to quickly filter rules that
        cannot possibly match, reducing the number of full
        condition evaluations needed.

        Args:
            request: The AIRequest to find candidates for.

        Returns:
            List of RuleIndex objects that might match.
        """
        if not self._optimized:
            return self._rule_indices

        start_time = datetime.now()

        # Collect candidates from field indices
        candidate_set: set[str] = set()
        first_field = True

        # Check each indexed field
        request_data = {
            "provider": request.provider,
            "model": request.model,
            "department": request.department,
            "user": request.user_id,
            "user_id": request.user_id,
            "source": request.source_application,
            "source_application": request.source_application,
            "use_case": request.intended_use_case,
            "data_classification": request.data_classification,
        }

        for field_name, field_value in request_data.items():
            if field_value and field_name in self._field_indices:
                field_index = self._field_indices[field_name]
                matching_rules = field_index.get(field_value, [])

                if matching_rules:
                    rule_ids = {r.rule.id for r in matching_rules}
                    if first_field:
                        candidate_set = rule_ids
                        first_field = False
                    else:
                        # Intersection would be too restrictive for OR conditions
                        # Instead, we union to include all potential matches
                        candidate_set |= rule_ids

        # Convert candidate set to list
        if candidate_set:
            candidates = [
                r for r in self._rule_indices if r.rule.id in candidate_set
            ]
        else:
            candidates = []

        # Always include catch-all rules
        candidates.extend(self._catch_all_rules)

        # Remove duplicates while preserving priority order
        seen: set[str] = set()
        unique_candidates = []
        for candidate in candidates:
            if candidate.rule.id not in seen:
                seen.add(candidate.rule.id)
                unique_candidates.append(candidate)

        # Sort by priority (already sorted in _rule_indices, but after merging we need to resort)
        unique_candidates.sort(key=lambda r: r.rule.priority, reverse=True)

        # Update statistics
        end_time = datetime.now()
        elapsed_us = int((end_time - start_time).total_seconds() * 1_000_000)

        self._stats.total_matches += 1
        self._stats.total_rules_evaluated += len(unique_candidates)
        self._stats.avg_rules_per_match = (
            self._stats.total_rules_evaluated / self._stats.total_matches
        )
        self._stats.last_match_time_us = elapsed_us
        self._stats._total_time_us += elapsed_us
        self._stats.avg_match_time_us = (
            self._stats._total_time_us / self._stats.total_matches
        )

        return unique_candidates

    def get_all_rules(self) -> list[RuleIndex]:
        """
        Get all indexed rules in priority order.

        Returns:
            List of all RuleIndex objects.
        """
        return self._rule_indices.copy()

    def get_stats(self) -> MatchStats:
        """
        Get matching statistics.

        Returns:
            MatchStats with current statistics.
        """
        return self._stats

    def reset_stats(self) -> None:
        """Reset matching statistics."""
        self._stats = MatchStats()

    def is_optimized(self) -> bool:
        """
        Check if a policy set has been optimized.

        Returns:
            True if optimize() has been called.
        """
        return self._optimized

    def clear(self) -> None:
        """Clear all optimized structures."""
        self._rule_indices.clear()
        self._field_indices.clear()
        self._catch_all_rules.clear()
        self._condition_factory.clear_cache()
        self._optimized = False
        self._stats = MatchStats()

    def _extract_indexed_fields(
        self,
        conditions: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Extract fields that can be indexed from conditions.

        Only extracts simple equality conditions on indexable fields.

        Args:
            conditions: The match conditions dictionary.

        Returns:
            Dictionary of indexable field values.
        """
        indexed = {}

        for key, value in conditions.items():
            if key in self.INDEXABLE_FIELDS:
                # Only index simple equality checks
                if isinstance(value, (str, int, float, bool)):
                    indexed[key] = value
                elif isinstance(value, dict):
                    # Check for explicit eq operator
                    if "eq" in value:
                        indexed[key] = value["eq"]

        # Also check inside AND conditions
        if "and" in conditions or "all" in conditions:
            sub_conditions = conditions.get("and") or conditions.get("all")
            if isinstance(sub_conditions, list):
                for sub in sub_conditions:
                    if isinstance(sub, dict):
                        indexed.update(self._extract_indexed_fields(sub))

        return indexed

    def _add_to_indices(
        self,
        rule_index: RuleIndex,
        indexed_fields: dict[str, Any],
    ) -> None:
        """
        Add a rule to field indices.

        Args:
            rule_index: The RuleIndex to add.
            indexed_fields: The indexed field values.
        """
        for field_name, field_value in indexed_fields.items():
            if field_name not in self._field_indices:
                self._field_indices[field_name] = {}

            if field_value not in self._field_indices[field_name]:
                self._field_indices[field_name][field_value] = []

            self._field_indices[field_name][field_value].append(rule_index)

    def get_index_info(self) -> dict[str, Any]:
        """
        Get information about the current indices.

        Returns:
            Dictionary with index statistics.
        """
        return {
            "total_rules": len(self._rule_indices),
            "catch_all_rules": len(self._catch_all_rules),
            "indexed_fields": list(self._field_indices.keys()),
            "field_index_sizes": {
                field: len(values)
                for field, values in self._field_indices.items()
            },
            "optimized": self._optimized,
        }


class OptimizedMatcher:
    """
    A matcher that uses optimization for fast rule evaluation.

    This combines the PolicyMatcher functionality with the MatchOptimizer
    for optimal performance on large policy sets.

    Example:
        Using the optimized matcher::

            matcher = OptimizedMatcher(policy_set)
            match = matcher.match(request)

            stats = matcher.get_stats()
    """

    def __init__(self, policy_set: PolicySet) -> None:
        """
        Initialize with a policy set.

        Args:
            policy_set: The PolicySet to match against.
        """
        from policybind.engine.matcher import PolicyMatcher

        self._policy_set = policy_set
        self._optimizer = MatchOptimizer()
        self._matcher = PolicyMatcher()

        # Optimize the policy set
        self._optimizer.optimize(policy_set)
        self._matcher.precompile(policy_set)

    def match(
        self,
        request: AIRequest,
        current_time: datetime | None = None,
    ) -> "PolicyMatch":
        """
        Match a request using optimized structures.

        Args:
            request: The AIRequest to match.
            current_time: Optional current time for time-based conditions.

        Returns:
            PolicyMatch with the matching result.
        """
        from policybind.engine.conditions import EvaluationContext
        from policybind.models.policy import PolicyMatch

        # Get candidates using optimizer
        candidates = self._optimizer.get_candidates(request)

        if not candidates:
            return PolicyMatch(matched=False)

        # Build context for evaluation
        context = EvaluationContext(
            data={
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
            },
            metadata=request.metadata,
            current_time=current_time or datetime.now(),
        )

        # Evaluate candidates in priority order
        all_matches: list[PolicyRule] = []
        matched_conditions: dict[str, Any] = {}

        for candidate in candidates:
            if candidate.condition.evaluate(context):
                all_matches.append(candidate.rule)
                if not matched_conditions:
                    # Record matched conditions from the first match
                    matched_conditions = self._collect_matched_fields(
                        candidate.rule.match_conditions,
                        context,
                    )

        if not all_matches:
            return PolicyMatch(matched=False)

        return PolicyMatch(
            matched=True,
            rule=all_matches[0],
            match_score=len(matched_conditions) / 10.0,
            matched_conditions=matched_conditions,
            all_matches=tuple(all_matches),
        )

    def _collect_matched_fields(
        self,
        conditions: dict[str, Any],
        context: "EvaluationContext",
    ) -> dict[str, Any]:
        """Collect field values that contributed to the match."""
        matched = {}
        for key, value in conditions.items():
            if key in ("and", "or", "all", "any"):
                if isinstance(value, list):
                    for sub in value:
                        if isinstance(sub, dict):
                            matched.update(
                                self._collect_matched_fields(sub, context)
                            )
            elif key == "not":
                pass  # Don't include negated fields
            else:
                field_value = context.get(key)
                if field_value is not None:
                    matched[key] = field_value
        return matched

    def get_stats(self) -> MatchStats:
        """Get matching statistics."""
        return self._optimizer.get_stats()

    def get_index_info(self) -> dict[str, Any]:
        """Get index information."""
        return self._optimizer.get_index_info()

    def reload(self, policy_set: PolicySet) -> None:
        """
        Reload with a new policy set.

        Args:
            policy_set: The new PolicySet to use.
        """
        self._policy_set = policy_set
        self._optimizer.clear()
        self._optimizer.optimize(policy_set)
        self._matcher.clear_cache()
        self._matcher.precompile(policy_set)
