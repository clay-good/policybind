"""
Policy simulator for PolicyBind.

This module provides the PolicySimulator class for dry-run policy
enforcement and simulation without side effects.
"""

import logging
import time
from dataclasses import replace
from datetime import datetime
from typing import Any

from policybind.engine.conditions import ConditionFactory, EvaluationContext
from policybind.engine.matcher import PolicyMatcher
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, Decision
from policybind.simulation.models import (
    BatchSimulationResult,
    EvaluationTrace,
    RuleEvaluation,
    SimulationMode,
    SimulationOptions,
    SimulationResult,
)

logger = logging.getLogger("policybind.simulation.simulator")


class PolicySimulator:
    """
    Simulates policy enforcement without side effects.

    The PolicySimulator evaluates requests against policies in dry-run mode,
    providing detailed information about what would happen without actually
    enforcing the policies or logging the results.

    This is useful for:
    - Testing new policies before deployment
    - Debugging policy issues
    - Understanding why a request was allowed/denied
    - Batch analysis of historical requests
    - What-if analysis for policy changes

    Example:
        Simulating a request::

            simulator = PolicySimulator(policy_set)
            result = simulator.simulate(request)

            print(f"Decision: {result.decision.value}")
            print(f"Applied rule: {result.applied_rule}")
            for eval in result.rule_evaluations:
                print(f"  {eval.rule_name}: {eval.matched}")
    """

    def __init__(
        self,
        policy_set: PolicySet,
        options: SimulationOptions | None = None,
    ) -> None:
        """
        Initialize the policy simulator.

        Args:
            policy_set: The PolicySet to simulate against.
            options: Simulation options.
        """
        self._policy_set = policy_set
        self._options = options or SimulationOptions()
        self._matcher = PolicyMatcher()
        self._condition_factory = ConditionFactory()

        # Precompile for performance
        self._matcher.precompile(policy_set)

    def simulate(
        self,
        request: AIRequest,
        options: SimulationOptions | None = None,
    ) -> SimulationResult:
        """
        Simulate enforcement for a single request.

        Args:
            request: The AIRequest to simulate.
            options: Override options for this simulation.

        Returns:
            SimulationResult with detailed evaluation information.
        """
        opts = options or self._options
        start_time = time.perf_counter()

        # Create result
        result = SimulationResult(
            request_id=request.request_id,
            mode=opts.mode,
        )

        # Initialize trace if enabled
        trace = EvaluationTrace() if opts.include_trace else None
        if trace:
            trace.add_step("start", f"Starting simulation for request {request.request_id}")

        try:
            # Build evaluation context
            context = self._build_context(request, opts)
            if trace:
                trace.add_step("context", "Built evaluation context", {"keys": list(context.data.keys())})

            # Evaluate all rules
            rule_evaluations = self._evaluate_all_rules(context, opts, trace)
            result.rule_evaluations = rule_evaluations

            # Collect matched rules
            matched = [e for e in rule_evaluations if e.matched]
            result.all_matched_rules = [e.rule_name for e in matched]

            if trace:
                trace.total_rules_evaluated = len(rule_evaluations)
                trace.add_step(
                    "matching",
                    f"Evaluated {len(rule_evaluations)} rules, {len(matched)} matched",
                )

            # Determine decision
            if matched:
                # Get highest priority matched rule
                best = max(matched, key=lambda e: e.priority)
                result.applied_rule = best.rule_name
                result.decision = self._action_to_decision(best.action)
                result.reason = f"Rule '{best.rule_name}' matched with action '{best.action}'"

                # Get modifications from the rule
                rule = self._get_rule_by_name(best.rule_name)
                if rule and rule.action_params:
                    result.modifications = dict(rule.action_params)

                if trace:
                    trace.add_step(
                        "decision",
                        f"Applied rule '{best.rule_name}' with action '{best.action}'",
                    )
            else:
                result.decision = Decision.DENY
                result.reason = "No matching policy rule - denied by default"
                if trace:
                    trace.add_step("decision", "No rules matched - default deny")

        except Exception as e:
            logger.error(f"Simulation error: {e}")
            result.decision = Decision.DENY
            result.reason = f"Simulation error: {e}"
            result.warnings.append(str(e))
            if trace:
                trace.add_step("error", f"Simulation error: {e}")

        # Finalize
        result.total_time_ms = (time.perf_counter() - start_time) * 1000
        result.trace = trace

        if trace:
            trace.add_step(
                "complete",
                f"Simulation complete in {result.total_time_ms:.2f}ms",
            )

        return result

    def simulate_batch(
        self,
        requests: list[AIRequest],
        options: SimulationOptions | None = None,
    ) -> BatchSimulationResult:
        """
        Simulate enforcement for multiple requests.

        Args:
            requests: List of AIRequests to simulate.
            options: Override options for this simulation.

        Returns:
            BatchSimulationResult with individual results and summary.
        """
        opts = options or self._options

        batch = BatchSimulationResult(
            mode=opts.mode,
            policy_version=self._policy_set.version,
            options=opts,
        )

        for request in requests:
            result = self.simulate(request, opts)
            batch.add_result(result)

        batch.complete()
        return batch

    def simulate_with_policy(
        self,
        request: AIRequest,
        policy_set: PolicySet,
        options: SimulationOptions | None = None,
    ) -> SimulationResult:
        """
        Simulate with a different policy set.

        This is useful for what-if analysis - testing how a request
        would be handled with a different policy.

        Args:
            request: The AIRequest to simulate.
            policy_set: The PolicySet to simulate against.
            options: Simulation options.

        Returns:
            SimulationResult.
        """
        # Create a temporary simulator with the new policy
        temp_simulator = PolicySimulator(policy_set, options or self._options)
        return temp_simulator.simulate(request, options)

    def _build_context(
        self,
        request: AIRequest,
        options: SimulationOptions,
    ) -> EvaluationContext:
        """Build evaluation context from request."""
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

        # Apply context overrides
        if options.context_overrides:
            data.update(options.context_overrides)

        return EvaluationContext(
            data=data,
            metadata=request.metadata,
            current_time=options.current_time or datetime.now(),
        )

    def _evaluate_all_rules(
        self,
        context: EvaluationContext,
        options: SimulationOptions,
        trace: EvaluationTrace | None,
    ) -> list[RuleEvaluation]:
        """Evaluate all rules against the context."""
        evaluations: list[RuleEvaluation] = []
        enabled_rules = self._policy_set.get_enabled_rules()

        for rule in enabled_rules:
            start = time.perf_counter()
            eval_result = self._evaluate_rule(rule, context, options)
            eval_result.evaluation_time_ms = (time.perf_counter() - start) * 1000
            evaluations.append(eval_result)

            if trace:
                trace.add_step(
                    "rule_eval",
                    f"Rule '{rule.name}': {'MATCHED' if eval_result.matched else 'no match'}",
                    {
                        "priority": rule.priority,
                        "action": rule.action,
                        "matched_conditions": eval_result.matched_conditions,
                    },
                )

            # Limit number of rules in results
            if len(evaluations) >= options.max_rules:
                break

        return evaluations

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        context: EvaluationContext,
        options: SimulationOptions,
    ) -> RuleEvaluation:
        """Evaluate a single rule."""
        evaluation = RuleEvaluation(
            rule_name=rule.name,
            rule_id=rule.id,
            priority=rule.priority,
            action=rule.action,
        )

        if not rule.enabled:
            return evaluation

        try:
            # Create condition from rule
            condition = self._condition_factory.create(rule.match_conditions)
            matched = condition.evaluate(context)
            evaluation.matched = matched

            if matched:
                # Calculate match score
                evaluation.match_score = self._calculate_score(rule, context)

                # Collect matched conditions
                if options.include_conditions:
                    evaluation.matched_conditions = self._collect_matched_conditions(
                        rule.match_conditions, context
                    )
            else:
                # Collect failed conditions
                if options.include_conditions:
                    evaluation.failed_conditions = self._collect_failed_conditions(
                        rule.match_conditions, context
                    )

        except Exception as e:
            logger.warning(f"Error evaluating rule {rule.name}: {e}")
            evaluation.matched = False

        return evaluation

    def _calculate_score(
        self,
        rule: PolicyRule,
        context: EvaluationContext,
    ) -> float:
        """Calculate a match score for ranking."""
        if not rule.match_conditions:
            return 0.1

        field_count = self._count_condition_fields(rule.match_conditions)
        base_score = min(field_count / 10.0, 0.5)
        priority_score = min(rule.priority / 2000.0, 0.5)

        return base_score + priority_score

    def _count_condition_fields(self, conditions: dict[str, Any]) -> int:
        """Count condition fields recursively."""
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

    def _collect_matched_conditions(
        self,
        conditions: dict[str, Any],
        context: EvaluationContext,
    ) -> dict[str, Any]:
        """Collect conditions that matched."""
        matched = {}
        self._collect_conditions(conditions, context, matched, check_match=True)
        return matched

    def _collect_failed_conditions(
        self,
        conditions: dict[str, Any],
        context: EvaluationContext,
    ) -> dict[str, Any]:
        """Collect conditions that failed to match."""
        failed = {}
        self._collect_conditions(conditions, context, failed, check_match=False)
        return failed

    def _collect_conditions(
        self,
        conditions: dict[str, Any],
        context: EvaluationContext,
        result: dict[str, Any],
        check_match: bool,
    ) -> None:
        """Recursively collect condition values."""
        for key, expected_value in conditions.items():
            if key in ("and", "or", "all", "any"):
                if isinstance(expected_value, list):
                    for sub in expected_value:
                        if isinstance(sub, dict):
                            self._collect_conditions(sub, context, result, check_match)
            elif key == "not":
                if isinstance(expected_value, dict):
                    self._collect_conditions(expected_value, context, result, not check_match)
            else:
                actual_value = context.get(key)
                if check_match:
                    # Collect matched conditions
                    if self._values_match(actual_value, expected_value):
                        result[key] = {
                            "expected": expected_value,
                            "actual": actual_value,
                        }
                else:
                    # Collect failed conditions
                    if not self._values_match(actual_value, expected_value):
                        result[key] = {
                            "expected": expected_value,
                            "actual": actual_value,
                        }

    def _values_match(self, actual: Any, expected: Any) -> bool:
        """Check if actual value matches expected condition."""
        if actual is None:
            return False

        # Handle list membership
        if isinstance(expected, list):
            if isinstance(actual, (list, tuple)):
                return any(a in expected for a in actual)
            return actual in expected

        # Handle dict operators
        if isinstance(expected, dict):
            for op, val in expected.items():
                if op == "eq":
                    return actual == val
                elif op == "ne":
                    return actual != val
                elif op == "gt":
                    return actual > val
                elif op == "gte":
                    return actual >= val
                elif op == "lt":
                    return actual < val
                elif op == "lte":
                    return actual <= val
                elif op == "in":
                    if isinstance(actual, (list, tuple)):
                        return any(a in val for a in actual)
                    return actual in val
                elif op == "contains":
                    if isinstance(actual, (list, tuple)):
                        return val in actual
                    return str(val) in str(actual)
            return False

        # Simple equality
        return actual == expected

    def _action_to_decision(self, action: str) -> Decision:
        """Convert action string to Decision enum."""
        action_upper = action.upper()
        if action_upper == "ALLOW":
            return Decision.ALLOW
        elif action_upper == "DENY":
            return Decision.DENY
        elif action_upper == "MODIFY":
            return Decision.MODIFY
        elif action_upper in ("REQUIRE_APPROVAL", "APPROVAL"):
            return Decision.REQUIRE_APPROVAL
        elif action_upper in ("AUDIT", "RATE_LIMIT", "REDIRECT"):
            # These actions still allow the request
            return Decision.ALLOW
        else:
            return Decision.DENY

    def _get_rule_by_name(self, name: str) -> PolicyRule | None:
        """Get a rule by name."""
        for rule in self._policy_set.rules:
            if rule.name == name:
                return rule
        return None

    def get_policy_set(self) -> PolicySet:
        """Get the current policy set."""
        return self._policy_set

    def reload_policies(self, policy_set: PolicySet) -> None:
        """Reload with a new policy set."""
        self._policy_set = policy_set
        self._matcher.clear_cache()
        self._matcher.precompile(policy_set)
        self._condition_factory.clear_cache()

    def explain_decision(self, result: SimulationResult) -> str:
        """
        Generate a human-readable explanation of a simulation result.

        Args:
            result: The simulation result to explain.

        Returns:
            Human-readable explanation string.
        """
        lines = []
        lines.append(f"Simulation Result for Request: {result.request_id}")
        lines.append("=" * 60)
        lines.append(f"Decision: {result.decision.value}")
        lines.append(f"Reason: {result.reason}")
        lines.append("")

        if result.applied_rule:
            lines.append(f"Applied Rule: {result.applied_rule}")
        else:
            lines.append("Applied Rule: (none)")

        lines.append("")
        lines.append(f"Total Matched Rules: {len(result.all_matched_rules)}")

        if result.all_matched_rules:
            lines.append("Matched Rules:")
            for rule_name in result.all_matched_rules:
                lines.append(f"  - {rule_name}")

        lines.append("")
        lines.append("Rule Evaluations:")
        for eval in result.rule_evaluations:
            status = "MATCHED" if eval.matched else "no match"
            lines.append(f"  [{status}] {eval.rule_name} (priority={eval.priority})")
            if eval.matched and eval.matched_conditions:
                lines.append(f"    Matched: {list(eval.matched_conditions.keys())}")
            elif not eval.matched and eval.failed_conditions:
                lines.append(f"    Failed: {list(eval.failed_conditions.keys())}")

        if result.modifications:
            lines.append("")
            lines.append("Modifications:")
            for key, value in result.modifications.items():
                lines.append(f"  {key}: {value}")

        if result.warnings:
            lines.append("")
            lines.append("Warnings:")
            for warning in result.warnings:
                lines.append(f"  - {warning}")

        lines.append("")
        lines.append(f"Simulation Time: {result.total_time_ms:.2f}ms")

        return "\n".join(lines)
