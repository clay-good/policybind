"""
Tests for the policy simulation module.

Tests simulation models, PolicySimulator, and WhatIfAnalyzer.
"""

import pytest
from datetime import datetime

from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, Decision
from policybind.simulation import (
    BatchSimulationResult,
    ImpactAnalysis,
    PolicyComparison,
    PolicySimulator,
    RuleImpact,
    SimulationMode,
    SimulationOptions,
    SimulationResult,
    SimulationSummary,
    WhatIfAnalyzer,
    WhatIfResult,
    WhatIfScenario,
)
from policybind.simulation.models import EvaluationTrace, RuleEvaluation


class TestSimulationModels:
    """Tests for simulation data models."""

    def test_simulation_mode_enum(self):
        """Test SimulationMode enum values."""
        assert SimulationMode.DRY_RUN.value == "dry_run"
        assert SimulationMode.SHADOW.value == "shadow"
        assert SimulationMode.COMPARE.value == "compare"
        assert SimulationMode.WHAT_IF.value == "what_if"

    def test_simulation_options_defaults(self):
        """Test SimulationOptions default values."""
        options = SimulationOptions()

        assert options.mode == SimulationMode.DRY_RUN
        assert options.include_all_matches is True  # Actual default
        assert options.include_timing is True
        assert options.include_conditions is True
        assert options.include_trace is False
        assert options.max_rules == 100  # Actual default
        assert options.current_time is None
        assert options.context_overrides == {}

    def test_simulation_options_custom(self):
        """Test SimulationOptions with custom values."""
        custom_time = datetime(2024, 1, 1, 12, 0, 0)
        options = SimulationOptions(
            mode=SimulationMode.WHAT_IF,
            include_all_matches=True,
            include_trace=True,
            max_rules=10,
            current_time=custom_time,
            context_overrides={"department": "engineering"},
        )

        assert options.mode == SimulationMode.WHAT_IF
        assert options.include_all_matches is True
        assert options.include_trace is True
        assert options.max_rules == 10
        assert options.current_time == custom_time
        assert options.context_overrides == {"department": "engineering"}

    def test_rule_evaluation(self):
        """Test RuleEvaluation dataclass."""
        eval_result = RuleEvaluation(
            rule_name="test-rule",
            rule_id="rule-123",
            matched=True,
            match_score=0.95,
            action="ALLOW",
            priority=100,
            matched_conditions={"provider": "openai"},
            failed_conditions={},
            evaluation_time_ms=5.0,
        )

        assert eval_result.rule_name == "test-rule"
        assert eval_result.matched is True
        assert eval_result.match_score == 0.95
        assert eval_result.action == "ALLOW"

    def test_evaluation_trace(self):
        """Test EvaluationTrace dataclass."""
        trace = EvaluationTrace(
            steps=[],
            total_rules_evaluated=5,
            rules_skipped=1,
            short_circuit_at=None,
        )

        trace.add_step("rule_matching", "Evaluating rule: test-rule", {"matched": True})

        assert len(trace.steps) == 1
        assert trace.steps[0]["type"] == "rule_matching"
        assert trace.total_rules_evaluated == 5

    def test_simulation_result(self):
        """Test SimulationResult dataclass."""
        result = SimulationResult(
            request_id="req-123",
            decision=Decision.ALLOW,
            applied_rule="allow-all",
            all_matched_rules=["allow-all"],
            rule_evaluations=[],
            total_time_ms=10.0,
            mode=SimulationMode.DRY_RUN,
        )

        assert result.request_id == "req-123"
        assert result.decision == Decision.ALLOW
        assert result.applied_rule == "allow-all"
        assert result.mode == SimulationMode.DRY_RUN

    def test_simulation_summary(self):
        """Test SimulationSummary dataclass."""
        summary = SimulationSummary(
            total_requests=100,
            allowed=60,
            denied=30,
            modified=10,
            require_approval=0,
            avg_time_ms=5.0,
            rule_hit_counts={"rule-1": 40, "rule-2": 60},
        )

        assert summary.total_requests == 100
        assert summary.allowed == 60
        assert summary.denied == 30
        assert summary.rule_hit_counts["rule-1"] == 40

    def test_batch_simulation_result(self):
        """Test BatchSimulationResult dataclass."""
        result = BatchSimulationResult(
            results=[],
            summary=SimulationSummary(
                total_requests=0,
                allowed=0,
                denied=0,
                modified=0,
                require_approval=0,
                avg_time_ms=0.0,
                rule_hit_counts={},
            ),
        )

        assert result.results == []
        assert result.summary.total_requests == 0


class TestPolicySimulator:
    """Tests for PolicySimulator."""

    @pytest.fixture
    def basic_policy_set(self):
        """Create a basic policy set for testing."""
        policy_set = PolicySet(name="test-policy", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-openai",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-anthropic",
            match_conditions={"provider": "anthropic"},
            action="DENY",
            priority=100,
            action_params={"reason": "Anthropic provider is blocked"},
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
            action_params={"reason": "Default deny"},
        ))
        return policy_set

    @pytest.fixture
    def complex_policy_set(self):
        """Create a more complex policy set for testing."""
        policy_set = PolicySet(name="complex-policy", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-engineering-gpt4",
            match_conditions={
                "provider": "openai",
                "model": "gpt-4",
                "department": "engineering",
            },
            action="ALLOW",
            priority=200,
        ))
        policy_set.add_rule(PolicyRule(
            name="modify-hr-requests",
            match_conditions={"department": "hr"},
            action="MODIFY",
            priority=150,
            action_params={"modifications": {"max_tokens": 1000}},
        ))
        policy_set.add_rule(PolicyRule(
            name="require-approval-finance",
            match_conditions={"department": "finance"},
            action="REQUIRE_APPROVAL",
            priority=150,
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
        ))
        return policy_set

    def test_simulate_allow_decision(self, basic_policy_set):
        """Test simulating a request that results in ALLOW."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        options = SimulationOptions()

        result = simulator.simulate(request, options)

        assert result.decision == Decision.ALLOW
        assert result.applied_rule == "allow-openai"
        assert result.total_time_ms >= 0

    def test_simulate_deny_decision(self, basic_policy_set):
        """Test simulating a request that results in DENY."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="anthropic", model="claude")
        options = SimulationOptions()

        result = simulator.simulate(request, options)

        assert result.decision == Decision.DENY
        assert result.applied_rule == "deny-anthropic"

    def test_simulate_with_all_matches(self, basic_policy_set):
        """Test simulation with include_all_matches option."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        options = SimulationOptions(include_all_matches=True)

        result = simulator.simulate(request, options)

        assert result.decision == Decision.ALLOW
        assert len(result.rule_evaluations) > 0

    def test_simulate_with_trace(self, basic_policy_set):
        """Test simulation with trace enabled."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        options = SimulationOptions(include_trace=True)

        result = simulator.simulate(request, options)

        assert result.trace is not None
        assert isinstance(result.trace, EvaluationTrace)

    def test_simulate_modify_decision(self, complex_policy_set):
        """Test simulating a request that results in MODIFY."""
        simulator = PolicySimulator(complex_policy_set)
        request = AIRequest(provider="openai", model="gpt-3.5-turbo", department="hr")
        options = SimulationOptions()

        result = simulator.simulate(request, options)

        assert result.decision == Decision.MODIFY
        assert result.applied_rule == "modify-hr-requests"

    def test_simulate_require_approval_decision(self, complex_policy_set):
        """Test simulating a request that requires approval."""
        simulator = PolicySimulator(complex_policy_set)
        request = AIRequest(provider="openai", model="gpt-4", department="finance")
        options = SimulationOptions()

        result = simulator.simulate(request, options)

        assert result.decision == Decision.REQUIRE_APPROVAL
        assert result.applied_rule == "require-approval-finance"

    def test_simulate_with_context_overrides(self, complex_policy_set):
        """Test simulation with context overrides."""
        simulator = PolicySimulator(complex_policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        options = SimulationOptions(
            context_overrides={"department": "engineering"}
        )

        result = simulator.simulate(request, options)

        assert result.decision == Decision.ALLOW
        assert result.applied_rule == "allow-engineering-gpt4"

    def test_simulate_batch(self, basic_policy_set):
        """Test batch simulation."""
        simulator = PolicySimulator(basic_policy_set)
        requests = [
            AIRequest(provider="openai", model="gpt-4"),
            AIRequest(provider="anthropic", model="claude"),
            AIRequest(provider="openai", model="gpt-3.5-turbo"),
        ]
        options = SimulationOptions()

        result = simulator.simulate_batch(requests, options)

        assert result.summary.total_requests == 3
        assert result.summary.allowed == 2
        assert result.summary.denied == 1
        assert len(result.results) == 3

    def test_simulate_batch_empty(self, basic_policy_set):
        """Test batch simulation with empty list."""
        simulator = PolicySimulator(basic_policy_set)
        requests = []
        options = SimulationOptions()

        result = simulator.simulate_batch(requests, options)

        assert result.summary.total_requests == 0
        assert len(result.results) == 0

    def test_simulate_with_policy(self, basic_policy_set, complex_policy_set):
        """Test simulation with a different policy set."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="openai", model="gpt-4", department="hr")
        options = SimulationOptions()

        # With basic policy set
        result1 = simulator.simulate(request, options)
        assert result1.decision == Decision.ALLOW

        # With complex policy set (should modify for HR)
        result2 = simulator.simulate_with_policy(request, complex_policy_set, options)
        assert result2.decision == Decision.MODIFY

    def test_explain_decision_allow(self, basic_policy_set):
        """Test explain_decision for ALLOW result."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        options = SimulationOptions()

        result = simulator.simulate(request, options)
        explanation = simulator.explain_decision(result)

        assert "ALLOW" in explanation
        assert "allow-openai" in explanation

    def test_explain_decision_deny(self, basic_policy_set):
        """Test explain_decision for DENY result."""
        simulator = PolicySimulator(basic_policy_set)
        request = AIRequest(provider="anthropic", model="claude")
        options = SimulationOptions()

        result = simulator.simulate(request, options)
        explanation = simulator.explain_decision(result)

        assert "DENY" in explanation
        assert "deny-anthropic" in explanation

    def test_simulate_max_rules(self, complex_policy_set):
        """Test simulation with max_rules limit."""
        simulator = PolicySimulator(complex_policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        options = SimulationOptions(max_rules=2, include_all_matches=True)

        result = simulator.simulate(request, options)

        # Check that some rules were evaluated
        assert len(result.rule_evaluations) <= 2


class TestWhatIfAnalyzer:
    """Tests for WhatIfAnalyzer."""

    @pytest.fixture
    def policy_set(self):
        """Create a policy set for testing."""
        policy_set = PolicySet(name="whatif-test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-openai",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
        ))
        return policy_set

    @pytest.fixture
    def analyzer(self, policy_set):
        """Create a WhatIfAnalyzer instance."""
        return WhatIfAnalyzer(policy_set)

    def test_what_if_scenario_creation(self):
        """Test WhatIfScenario creation."""
        scenario = WhatIfScenario(
            name="test-scenario",
            description="Test adding a new rule",
            rules_to_add=[PolicyRule(
                name="allow-anthropic",
                match_conditions={"provider": "anthropic"},
                action="ALLOW",
                priority=100,
            )],
        )

        assert scenario.name == "test-scenario"
        assert len(scenario.rules_to_add) == 1
        assert scenario.rules_to_remove == []
        assert scenario.rules_to_modify == {}
        assert scenario.context_changes == {}

    def test_analyze_scenario_add_rule(self, analyzer):
        """Test analyzing scenario with added rule."""
        request = AIRequest(provider="anthropic", model="claude")

        # Baseline should deny
        scenario = WhatIfScenario(
            name="add-anthropic-allow",
            rules_to_add=[PolicyRule(
                name="allow-anthropic",
                match_conditions={"provider": "anthropic"},
                action="ALLOW",
                priority=100,
            )],
        )

        result = analyzer.analyze_scenario(request, scenario)

        assert isinstance(result, WhatIfResult)
        assert result.baseline_result.decision == Decision.DENY
        assert result.scenario_result.decision == Decision.ALLOW
        assert result.decision_changed is True

    def test_analyze_scenario_remove_rule(self, analyzer):
        """Test analyzing scenario with removed rule."""
        request = AIRequest(provider="openai", model="gpt-4")

        scenario = WhatIfScenario(
            name="remove-openai-allow",
            rules_to_remove=["allow-openai"],
        )

        result = analyzer.analyze_scenario(request, scenario)

        assert result.baseline_result.decision == Decision.ALLOW
        assert result.scenario_result.decision == Decision.DENY
        assert result.decision_changed is True

    def test_analyze_scenario_context_change(self, analyzer):
        """Test analyzing scenario with context changes."""
        request = AIRequest(provider="openai", model="gpt-4")

        scenario = WhatIfScenario(
            name="change-provider",
            context_changes={"provider": "anthropic"},
        )

        result = analyzer.analyze_scenario(request, scenario)

        assert result.baseline_result.decision == Decision.ALLOW
        assert result.scenario_result.decision == Decision.DENY
        assert result.decision_changed is True

    def test_analyze_batch(self, analyzer):
        """Test batch what-if analysis."""
        requests = [
            AIRequest(provider="openai", model="gpt-4"),
            AIRequest(provider="anthropic", model="claude"),
        ]

        scenario = WhatIfScenario(
            name="add-anthropic-allow",
            rules_to_add=[PolicyRule(
                name="allow-anthropic",
                match_conditions={"provider": "anthropic"},
                action="ALLOW",
                priority=100,
            )],
        )

        results = analyzer.analyze_batch(requests, scenario)

        assert len(results) == 2
        # First request should have no change (already allowed)
        assert results[0].decision_changed is False
        # Second request should change from deny to allow
        assert results[1].decision_changed is True

    def test_compare_policies(self, analyzer):
        """Test comparing two policy sets."""
        policy_a = PolicySet(name="policy-a", version="1.0.0")
        policy_a.add_rule(PolicyRule(
            name="allow-openai",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))
        policy_a.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
        ))

        policy_b = PolicySet(name="policy-b", version="1.0.0")
        policy_b.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
            priority=100,
        ))

        requests = [
            AIRequest(provider="openai", model="gpt-4"),
            AIRequest(provider="anthropic", model="claude"),
        ]

        comparison = analyzer.compare_policies(policy_a, policy_b, requests)

        assert isinstance(comparison, PolicyComparison)
        assert comparison.policy_a_version == "1.0.0"
        assert comparison.policy_b_version == "1.0.0"
        assert comparison.total_requests == 2
        # OpenAI: allowed in both, Anthropic: denied in A, allowed in B
        assert comparison.different_decision >= 1

    def test_analyze_rule_impact(self, analyzer):
        """Test analyzing impact of a single rule."""
        requests = [
            AIRequest(provider="openai", model="gpt-4"),
            AIRequest(provider="anthropic", model="claude"),
            AIRequest(provider="openai", model="gpt-3.5-turbo"),
        ]

        rule = PolicyRule(
            name="allow-openai",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        )

        impact = analyzer.analyze_rule_impact(rule, requests)

        assert isinstance(impact, RuleImpact)
        assert impact.rule_name == "allow-openai"
        assert impact.matched_count >= 2  # Two OpenAI requests

    def test_analyze_impact(self, analyzer):
        """Test analyzing impact of proposed changes."""
        requests = [
            AIRequest(provider="openai", model="gpt-4"),
            AIRequest(provider="anthropic", model="claude"),
        ]

        proposed_changes = WhatIfScenario(
            name="add-anthropic",
            rules_to_add=[PolicyRule(
                name="allow-anthropic",
                match_conditions={"provider": "anthropic"},
                action="ALLOW",
                priority=100,
            )],
        )

        analysis = analyzer.analyze_impact(proposed_changes, requests)

        assert isinstance(analysis, ImpactAnalysis)
        assert analysis.total_requests_analyzed == 2
        assert analysis.requests_affected >= 1

    def test_what_if_result_no_change(self, analyzer):
        """Test WhatIfResult when decision doesn't change."""
        request = AIRequest(provider="openai", model="gpt-4")

        # Add a rule that doesn't affect OpenAI requests
        scenario = WhatIfScenario(
            name="add-unrelated-rule",
            rules_to_add=[PolicyRule(
                name="allow-google",
                match_conditions={"provider": "google"},
                action="ALLOW",
                priority=100,
            )],
        )

        result = analyzer.analyze_scenario(request, scenario)

        assert result.decision_changed is False
        assert result.baseline_result.decision == Decision.ALLOW
        assert result.scenario_result.decision == Decision.ALLOW


class TestSimulationIntegration:
    """Integration tests for simulation components."""

    def test_full_simulation_workflow(self):
        """Test complete simulation workflow."""
        # Create policy set
        policy_set = PolicySet(name="integration-test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-engineering",
            match_conditions={
                "provider": "openai",
                "department": "engineering",
            },
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="modify-sales",
            match_conditions={"department": "sales"},
            action="MODIFY",
            priority=90,
            action_params={"modifications": {"max_tokens": 500}},
        ))
        policy_set.add_rule(PolicyRule(
            name="deny-default",
            match_conditions={},
            action="DENY",
            priority=1,
        ))

        # Create simulator and analyzer
        simulator = PolicySimulator(policy_set)
        analyzer = WhatIfAnalyzer(policy_set)

        # Test requests
        requests = [
            AIRequest(provider="openai", model="gpt-4", department="engineering"),
            AIRequest(provider="openai", model="gpt-4", department="sales"),
            AIRequest(provider="openai", model="gpt-4", department="marketing"),
        ]

        # Simulate batch
        batch_result = simulator.simulate_batch(requests, SimulationOptions())

        assert batch_result.summary.allowed == 1
        assert batch_result.summary.modified == 1
        assert batch_result.summary.denied == 1

        # What-if: Add marketing department allowance
        scenario = WhatIfScenario(
            name="allow-marketing",
            rules_to_add=[PolicyRule(
                name="allow-marketing",
                match_conditions={"department": "marketing"},
                action="ALLOW",
                priority=90,
            )],
        )

        impact = analyzer.analyze_impact(scenario, requests)

        assert impact.requests_affected >= 1

    def test_simulation_modes(self):
        """Test different simulation modes."""
        policy_set = PolicySet(name="mode-test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))

        simulator = PolicySimulator(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        # Test DRY_RUN mode
        result = simulator.simulate(
            request,
            SimulationOptions(mode=SimulationMode.DRY_RUN)
        )
        assert result.mode == SimulationMode.DRY_RUN

        # Test SHADOW mode
        result = simulator.simulate(
            request,
            SimulationOptions(mode=SimulationMode.SHADOW)
        )
        assert result.mode == SimulationMode.SHADOW

        # Test COMPARE mode
        result = simulator.simulate(
            request,
            SimulationOptions(mode=SimulationMode.COMPARE)
        )
        assert result.mode == SimulationMode.COMPARE

        # Test WHAT_IF mode
        result = simulator.simulate(
            request,
            SimulationOptions(mode=SimulationMode.WHAT_IF)
        )
        assert result.mode == SimulationMode.WHAT_IF


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_policy_set(self):
        """Test simulation with empty policy set."""
        policy_set = PolicySet(name="empty", version="1.0.0")
        simulator = PolicySimulator(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        result = simulator.simulate(request, SimulationOptions())

        # Should deny by default when no rules match
        assert result.decision == Decision.DENY

    def test_simulation_with_none_request_fields(self):
        """Test simulation with minimal request."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))

        simulator = PolicySimulator(policy_set)
        request = AIRequest()  # Minimal request

        result = simulator.simulate(request, SimulationOptions())

        assert result.decision == Decision.ALLOW

    def test_scenario_with_all_modifications(self):
        """Test scenario with rules added, removed, and modified."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="rule-to-keep",
            match_conditions={"provider": "google"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="rule-to-remove",
            match_conditions={"provider": "anthropic"},
            action="DENY",
            priority=100,
        ))

        analyzer = WhatIfAnalyzer(policy_set)
        request = AIRequest(provider="anthropic", model="claude")

        scenario = WhatIfScenario(
            name="complex-scenario",
            rules_to_add=[PolicyRule(
                name="allow-anthropic",
                match_conditions={"provider": "anthropic"},
                action="ALLOW",
                priority=150,
            )],
            rules_to_remove=["rule-to-remove"],
        )

        result = analyzer.analyze_scenario(request, scenario)

        # Should change from deny to allow
        assert result.baseline_result.decision == Decision.DENY
        assert result.scenario_result.decision == Decision.ALLOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
