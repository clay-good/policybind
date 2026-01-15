"""
What-if analysis for PolicyBind.

This module provides tools for analyzing the impact of policy changes,
comparing policy sets, and performing what-if scenario analysis.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from policybind.models.base import generate_uuid, utc_now
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, Decision
from policybind.simulation.models import (
    SimulationMode,
    SimulationOptions,
    SimulationResult,
    SimulationSummary,
)
from policybind.simulation.simulator import PolicySimulator

logger = logging.getLogger("policybind.simulation.analyzer")


@dataclass
class WhatIfScenario:
    """
    A what-if scenario for policy analysis.

    Defines a hypothetical situation to analyze, such as
    adding/removing rules or changing conditions.

    Attributes:
        id: Unique identifier for this scenario.
        name: Human-readable name for the scenario.
        description: Description of what the scenario tests.
        rules_to_add: Rules to add to the policy set.
        rules_to_remove: Names of rules to remove.
        rules_to_modify: Modifications to existing rules.
        context_changes: Changes to request context.
    """

    id: str = field(default_factory=generate_uuid)
    name: str = ""
    description: str = ""
    rules_to_add: list[PolicyRule] = field(default_factory=list)
    rules_to_remove: list[str] = field(default_factory=list)
    rules_to_modify: dict[str, dict[str, Any]] = field(default_factory=dict)
    context_changes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rules_to_add": [r.name for r in self.rules_to_add],
            "rules_to_remove": self.rules_to_remove,
            "rules_to_modify": self.rules_to_modify,
            "context_changes": self.context_changes,
        }


@dataclass
class WhatIfResult:
    """
    Result of a what-if scenario analysis.

    Compares behavior between current and hypothetical policies.

    Attributes:
        scenario: The scenario that was analyzed.
        baseline_result: Result with current policy.
        scenario_result: Result with scenario applied.
        decision_changed: Whether the decision changed.
        matched_rules_changed: Whether matched rules changed.
        changes: Summary of changes.
    """

    scenario: WhatIfScenario
    baseline_result: SimulationResult
    scenario_result: SimulationResult
    decision_changed: bool = False
    matched_rules_changed: bool = False
    changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scenario": self.scenario.to_dict(),
            "baseline_decision": self.baseline_result.decision.value,
            "scenario_decision": self.scenario_result.decision.value,
            "decision_changed": self.decision_changed,
            "matched_rules_changed": self.matched_rules_changed,
            "baseline_matched_rules": self.baseline_result.all_matched_rules,
            "scenario_matched_rules": self.scenario_result.all_matched_rules,
            "changes": self.changes,
        }

    def has_impact(self) -> bool:
        """Check if the scenario had any impact."""
        return self.decision_changed or self.matched_rules_changed


@dataclass
class RuleImpact:
    """
    Impact analysis for a single rule.

    Shows how a rule affects requests.

    Attributes:
        rule_name: Name of the rule.
        total_requests: Total requests evaluated.
        matched_count: Number of requests that matched.
        would_allow: Requests that would be allowed.
        would_deny: Requests that would be denied.
        would_modify: Requests that would be modified.
        match_rate: Percentage of requests matched.
        sample_matched: Sample of matched request IDs.
    """

    rule_name: str = ""
    total_requests: int = 0
    matched_count: int = 0
    would_allow: int = 0
    would_deny: int = 0
    would_modify: int = 0
    match_rate: float = 0.0
    sample_matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "total_requests": self.total_requests,
            "matched_count": self.matched_count,
            "would_allow": self.would_allow,
            "would_deny": self.would_deny,
            "would_modify": self.would_modify,
            "match_rate": self.match_rate,
            "sample_matched": self.sample_matched[:10],
        }


@dataclass
class PolicyComparison:
    """
    Comparison between two policy sets.

    Shows how behavior differs between policies.

    Attributes:
        id: Unique identifier for this comparison.
        compared_at: When the comparison was performed.
        policy_a_version: Version of first policy set.
        policy_b_version: Version of second policy set.
        total_requests: Total requests compared.
        same_decision: Requests with same decision.
        different_decision: Requests with different decision.
        decision_changes: Breakdown of decision changes.
        rules_only_in_a: Rules only in first policy set.
        rules_only_in_b: Rules only in second policy set.
        rules_in_both: Rules in both policy sets.
    """

    id: str = field(default_factory=generate_uuid)
    compared_at: datetime = field(default_factory=utc_now)
    policy_a_version: str = ""
    policy_b_version: str = ""
    total_requests: int = 0
    same_decision: int = 0
    different_decision: int = 0
    decision_changes: dict[str, int] = field(default_factory=dict)
    rules_only_in_a: list[str] = field(default_factory=list)
    rules_only_in_b: list[str] = field(default_factory=list)
    rules_in_both: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "compared_at": self.compared_at.isoformat(),
            "policy_a_version": self.policy_a_version,
            "policy_b_version": self.policy_b_version,
            "total_requests": self.total_requests,
            "same_decision": self.same_decision,
            "different_decision": self.different_decision,
            "agreement_rate": self.get_agreement_rate(),
            "decision_changes": self.decision_changes,
            "rules_only_in_a": self.rules_only_in_a,
            "rules_only_in_b": self.rules_only_in_b,
            "rules_in_both": self.rules_in_both,
        }

    def get_agreement_rate(self) -> float:
        """Get the percentage of requests with same decision."""
        if self.total_requests == 0:
            return 0.0
        return (self.same_decision / self.total_requests) * 100


@dataclass
class ImpactAnalysis:
    """
    Impact analysis for policy changes.

    Provides comprehensive analysis of how policy changes
    would affect request handling.

    Attributes:
        id: Unique identifier for this analysis.
        analyzed_at: When the analysis was performed.
        current_policy_version: Current policy version.
        proposed_changes: Description of proposed changes.
        total_requests_analyzed: Total requests analyzed.
        requests_affected: Requests with changed behavior.
        summary_before: Summary with current policy.
        summary_after: Summary with proposed changes.
        rule_impacts: Impact analysis per rule.
        recommendations: Recommendations based on analysis.
    """

    id: str = field(default_factory=generate_uuid)
    analyzed_at: datetime = field(default_factory=utc_now)
    current_policy_version: str = ""
    proposed_changes: str = ""
    total_requests_analyzed: int = 0
    requests_affected: int = 0
    summary_before: SimulationSummary = field(default_factory=SimulationSummary)
    summary_after: SimulationSummary = field(default_factory=SimulationSummary)
    rule_impacts: list[RuleImpact] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "analyzed_at": self.analyzed_at.isoformat(),
            "current_policy_version": self.current_policy_version,
            "proposed_changes": self.proposed_changes,
            "total_requests_analyzed": self.total_requests_analyzed,
            "requests_affected": self.requests_affected,
            "impact_rate": self.get_impact_rate(),
            "summary_before": self.summary_before.to_dict(),
            "summary_after": self.summary_after.to_dict(),
            "rule_impacts": [r.to_dict() for r in self.rule_impacts],
            "recommendations": self.recommendations,
        }

    def get_impact_rate(self) -> float:
        """Get the percentage of requests affected."""
        if self.total_requests_analyzed == 0:
            return 0.0
        return (self.requests_affected / self.total_requests_analyzed) * 100


class WhatIfAnalyzer:
    """
    Analyzes what-if scenarios for policy changes.

    The WhatIfAnalyzer helps understand the impact of policy changes
    by comparing behavior between current and hypothetical policies.

    Example:
        Analyzing a scenario::

            analyzer = WhatIfAnalyzer(policy_set)
            scenario = WhatIfScenario(
                name="Add stricter cost rule",
                rules_to_add=[new_cost_rule],
            )
            result = analyzer.analyze_scenario(request, scenario)

            if result.decision_changed:
                print(f"Decision would change from {result.baseline_result.decision}"
                      f" to {result.scenario_result.decision}")
    """

    def __init__(self, policy_set: PolicySet) -> None:
        """
        Initialize the analyzer.

        Args:
            policy_set: The current PolicySet to analyze against.
        """
        self._policy_set = policy_set
        self._simulator = PolicySimulator(policy_set)

    def analyze_scenario(
        self,
        request: AIRequest,
        scenario: WhatIfScenario,
    ) -> WhatIfResult:
        """
        Analyze a what-if scenario for a single request.

        Args:
            request: The AIRequest to analyze.
            scenario: The scenario to apply.

        Returns:
            WhatIfResult comparing baseline and scenario.
        """
        # Get baseline result
        baseline = self._simulator.simulate(request)

        # Apply scenario to create modified policy set
        modified_policy = self._apply_scenario(scenario)

        # Simulate with modified policy
        options = SimulationOptions(
            mode=SimulationMode.WHAT_IF,
            context_overrides=scenario.context_changes,
        )
        temp_simulator = PolicySimulator(modified_policy, options)
        scenario_result = temp_simulator.simulate(request, options)

        # Compare results
        decision_changed = baseline.decision != scenario_result.decision
        rules_changed = set(baseline.all_matched_rules) != set(scenario_result.all_matched_rules)

        # Generate change descriptions
        changes = []
        if decision_changed:
            changes.append(
                f"Decision changed: {baseline.decision.value} -> {scenario_result.decision.value}"
            )
        if rules_changed:
            added = set(scenario_result.all_matched_rules) - set(baseline.all_matched_rules)
            removed = set(baseline.all_matched_rules) - set(scenario_result.all_matched_rules)
            if added:
                changes.append(f"New matching rules: {list(added)}")
            if removed:
                changes.append(f"Rules no longer matching: {list(removed)}")

        return WhatIfResult(
            scenario=scenario,
            baseline_result=baseline,
            scenario_result=scenario_result,
            decision_changed=decision_changed,
            matched_rules_changed=rules_changed,
            changes=changes,
        )

    def analyze_batch(
        self,
        requests: list[AIRequest],
        scenario: WhatIfScenario,
    ) -> list[WhatIfResult]:
        """
        Analyze a scenario against multiple requests.

        Args:
            requests: List of AIRequests to analyze.
            scenario: The scenario to apply.

        Returns:
            List of WhatIfResults.
        """
        results = []
        for request in requests:
            result = self.analyze_scenario(request, scenario)
            results.append(result)
        return results

    def compare_policies(
        self,
        policy_a: PolicySet,
        policy_b: PolicySet,
        requests: list[AIRequest],
    ) -> PolicyComparison:
        """
        Compare two policy sets against a set of requests.

        Args:
            policy_a: First PolicySet.
            policy_b: Second PolicySet.
            requests: Requests to compare against.

        Returns:
            PolicyComparison with detailed comparison.
        """
        sim_a = PolicySimulator(policy_a)
        sim_b = PolicySimulator(policy_b)

        comparison = PolicyComparison(
            policy_a_version=policy_a.version,
            policy_b_version=policy_b.version,
        )

        # Analyze rules
        rules_a = {r.name for r in policy_a.rules}
        rules_b = {r.name for r in policy_b.rules}
        comparison.rules_only_in_a = list(rules_a - rules_b)
        comparison.rules_only_in_b = list(rules_b - rules_a)
        comparison.rules_in_both = list(rules_a & rules_b)

        # Compare against requests
        for request in requests:
            result_a = sim_a.simulate(request)
            result_b = sim_b.simulate(request)

            comparison.total_requests += 1

            if result_a.decision == result_b.decision:
                comparison.same_decision += 1
            else:
                comparison.different_decision += 1
                change_key = f"{result_a.decision.value}->{result_b.decision.value}"
                comparison.decision_changes[change_key] = (
                    comparison.decision_changes.get(change_key, 0) + 1
                )

        return comparison

    def analyze_rule_impact(
        self,
        rule: PolicyRule,
        requests: list[AIRequest],
    ) -> RuleImpact:
        """
        Analyze the impact of a specific rule.

        Args:
            rule: The rule to analyze.
            requests: Requests to analyze against.

        Returns:
            RuleImpact with analysis results.
        """
        impact = RuleImpact(
            rule_name=rule.name,
            total_requests=len(requests),
        )

        # Create a policy set with just this rule
        single_rule_policy = PolicySet(
            name="single_rule_test",
            version="test",
            rules=[rule],
        )
        simulator = PolicySimulator(single_rule_policy)

        for request in requests:
            result = simulator.simulate(request)

            if result.applied_rule == rule.name:
                impact.matched_count += 1

                if result.decision == Decision.ALLOW:
                    impact.would_allow += 1
                elif result.decision == Decision.DENY:
                    impact.would_deny += 1
                elif result.decision == Decision.MODIFY:
                    impact.would_modify += 1

                # Store sample
                if len(impact.sample_matched) < 10:
                    impact.sample_matched.append(request.request_id)

        # Calculate match rate
        if impact.total_requests > 0:
            impact.match_rate = (impact.matched_count / impact.total_requests) * 100

        return impact

    def analyze_impact(
        self,
        proposed_changes: WhatIfScenario,
        requests: list[AIRequest],
    ) -> ImpactAnalysis:
        """
        Perform comprehensive impact analysis of proposed changes.

        Args:
            proposed_changes: The proposed policy changes.
            requests: Requests to analyze.

        Returns:
            ImpactAnalysis with comprehensive results.
        """
        analysis = ImpactAnalysis(
            current_policy_version=self._policy_set.version,
            proposed_changes=proposed_changes.description or proposed_changes.name,
            total_requests_analyzed=len(requests),
        )

        # Simulate with current policy
        current_batch = self._simulator.simulate_batch(requests)
        analysis.summary_before = current_batch.summary

        # Apply changes and simulate
        modified_policy = self._apply_scenario(proposed_changes)
        modified_simulator = PolicySimulator(modified_policy)
        modified_batch = modified_simulator.simulate_batch(requests)
        analysis.summary_after = modified_batch.summary

        # Count affected requests
        for i, request in enumerate(requests):
            if i < len(current_batch.results) and i < len(modified_batch.results):
                if current_batch.results[i].decision != modified_batch.results[i].decision:
                    analysis.requests_affected += 1

        # Analyze impact of added rules
        for rule in proposed_changes.rules_to_add:
            impact = self.analyze_rule_impact(rule, requests)
            analysis.rule_impacts.append(impact)

        # Generate recommendations
        analysis.recommendations = self._generate_recommendations(analysis)

        return analysis

    def _apply_scenario(self, scenario: WhatIfScenario) -> PolicySet:
        """Apply a scenario to create a modified policy set."""
        # Start with a copy of current rules
        modified_rules = list(self._policy_set.rules)

        # Remove rules
        if scenario.rules_to_remove:
            modified_rules = [
                r for r in modified_rules
                if r.name not in scenario.rules_to_remove
            ]

        # Add rules
        if scenario.rules_to_add:
            modified_rules.extend(scenario.rules_to_add)

        # Modify rules
        if scenario.rules_to_modify:
            for i, rule in enumerate(modified_rules):
                if rule.name in scenario.rules_to_modify:
                    modifications = scenario.rules_to_modify[rule.name]
                    # Create modified rule using dataclass replace
                    from dataclasses import replace
                    modified_rules[i] = replace(rule, **modifications)

        return PolicySet(
            name=f"{self._policy_set.name} (modified)",
            version=f"{self._policy_set.version}-whatif",
            rules=modified_rules,
            metadata={**self._policy_set.metadata, "scenario": scenario.name},
        )

    def _generate_recommendations(self, analysis: ImpactAnalysis) -> list[str]:
        """Generate recommendations based on impact analysis."""
        recommendations = []

        # Check impact rate
        impact_rate = analysis.get_impact_rate()
        if impact_rate > 50:
            recommendations.append(
                f"High impact rate ({impact_rate:.1f}%) - consider gradual rollout"
            )
        elif impact_rate > 20:
            recommendations.append(
                f"Moderate impact rate ({impact_rate:.1f}%) - monitor closely after deployment"
            )

        # Check decision changes
        before = analysis.summary_before
        after = analysis.summary_after

        if after.denied > before.denied:
            increase = after.denied - before.denied
            recommendations.append(
                f"Change would increase denials by {increase} requests"
            )

        if after.allowed > before.allowed:
            increase = after.allowed - before.allowed
            recommendations.append(
                f"Change would increase allowed requests by {increase}"
            )

        # Check for overly broad rules
        for impact in analysis.rule_impacts:
            if impact.match_rate > 80:
                recommendations.append(
                    f"Rule '{impact.rule_name}' matches {impact.match_rate:.1f}% of requests - "
                    "consider if conditions are too broad"
                )
            elif impact.match_rate == 0:
                recommendations.append(
                    f"Rule '{impact.rule_name}' matches no requests - "
                    "verify conditions are correct"
                )

        if not recommendations:
            recommendations.append("No significant concerns identified")

        return recommendations

    def reload_policies(self, policy_set: PolicySet) -> None:
        """Reload with a new policy set."""
        self._policy_set = policy_set
        self._simulator = PolicySimulator(policy_set)


def create_what_if_scenario(
    name: str,
    description: str = "",
    add_rules: list[PolicyRule] | None = None,
    remove_rules: list[str] | None = None,
    modify_rules: dict[str, dict[str, Any]] | None = None,
    context_changes: dict[str, Any] | None = None,
) -> WhatIfScenario:
    """
    Helper function to create a what-if scenario.

    Args:
        name: Name for the scenario.
        description: Description of what it tests.
        add_rules: Rules to add.
        remove_rules: Rule names to remove.
        modify_rules: Modifications to existing rules.
        context_changes: Changes to request context.

    Returns:
        WhatIfScenario instance.
    """
    return WhatIfScenario(
        name=name,
        description=description,
        rules_to_add=add_rules or [],
        rules_to_remove=remove_rules or [],
        rules_to_modify=modify_rules or {},
        context_changes=context_changes or {},
    )
