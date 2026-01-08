"""
Tests for the policy matching engine.

Tests conditions, matcher, and optimizer components.
"""

import pytest
from datetime import datetime

from policybind.engine.conditions import (
    AlwaysFalseCondition,
    AlwaysTrueCondition,
    AndCondition,
    Condition,
    ConditionFactory,
    EvaluationContext,
    FieldCondition,
    NotCondition,
    Operator,
    OrCondition,
    TimeCondition,
)
from policybind.engine.matcher import PolicyMatcher
from policybind.engine.optimizer import MatchOptimizer, OptimizedMatcher
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest


class TestEvaluationContext:
    """Tests for EvaluationContext."""

    def test_get_simple_value(self):
        """Test getting a simple value."""
        context = EvaluationContext(data={"provider": "openai"})
        assert context.get("provider") == "openai"

    def test_get_nested_value(self):
        """Test getting a nested value with dot notation."""
        context = EvaluationContext(
            data={"metadata": {"project": "test-project"}}
        )
        assert context.get("metadata.project") == "test-project"

    def test_get_missing_value(self):
        """Test getting a missing value returns default."""
        context = EvaluationContext(data={"provider": "openai"})
        assert context.get("model") is None
        assert context.get("model", "default") == "default"

    def test_has_existing_key(self):
        """Test has returns True for existing keys."""
        context = EvaluationContext(data={"provider": "openai"})
        assert context.has("provider")

    def test_has_missing_key(self):
        """Test has returns False for missing keys."""
        context = EvaluationContext(data={"provider": "openai"})
        assert not context.has("model")

    def test_has_nested_key(self):
        """Test has with nested dot notation."""
        context = EvaluationContext(
            data={"metadata": {"project": "test"}}
        )
        assert context.has("metadata.project")
        assert not context.has("metadata.missing")


class TestFieldCondition:
    """Tests for FieldCondition."""

    def test_eq_operator(self):
        """Test equals operator."""
        condition = FieldCondition("provider", Operator.EQ, "openai")
        context = EvaluationContext(data={"provider": "openai"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"provider": "anthropic"})
        assert not condition.evaluate(context)

    def test_ne_operator(self):
        """Test not equals operator."""
        condition = FieldCondition("provider", Operator.NE, "openai")
        context = EvaluationContext(data={"provider": "anthropic"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"provider": "openai"})
        assert not condition.evaluate(context)

    def test_gt_operator(self):
        """Test greater than operator."""
        condition = FieldCondition("cost", Operator.GT, 10.0)
        context = EvaluationContext(data={"cost": 15.0})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"cost": 5.0})
        assert not condition.evaluate(context)

        context = EvaluationContext(data={"cost": 10.0})
        assert not condition.evaluate(context)

    def test_gte_operator(self):
        """Test greater than or equal operator."""
        condition = FieldCondition("cost", Operator.GTE, 10.0)
        context = EvaluationContext(data={"cost": 10.0})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"cost": 5.0})
        assert not condition.evaluate(context)

    def test_lt_operator(self):
        """Test less than operator."""
        condition = FieldCondition("cost", Operator.LT, 10.0)
        context = EvaluationContext(data={"cost": 5.0})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"cost": 15.0})
        assert not condition.evaluate(context)

    def test_lte_operator(self):
        """Test less than or equal operator."""
        condition = FieldCondition("cost", Operator.LTE, 10.0)
        context = EvaluationContext(data={"cost": 10.0})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"cost": 15.0})
        assert not condition.evaluate(context)

    def test_in_operator(self):
        """Test in list operator."""
        condition = FieldCondition("department", Operator.IN, ["eng", "research"])
        context = EvaluationContext(data={"department": "eng"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"department": "marketing"})
        assert not condition.evaluate(context)

    def test_not_in_operator(self):
        """Test not in list operator."""
        condition = FieldCondition("department", Operator.NOT_IN, ["eng", "research"])
        context = EvaluationContext(data={"department": "marketing"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"department": "eng"})
        assert not condition.evaluate(context)

    def test_contains_operator_string(self):
        """Test contains operator on strings."""
        condition = FieldCondition("data_classification", Operator.CONTAINS, "pii")
        context = EvaluationContext(data={"data_classification": "pii,financial"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"data_classification": "public"})
        assert not condition.evaluate(context)

    def test_contains_operator_list(self):
        """Test contains operator on lists."""
        condition = FieldCondition("tags", Operator.CONTAINS, "production")
        context = EvaluationContext(data={"tags": ["production", "high-priority"]})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"tags": ["staging", "low-priority"]})
        assert not condition.evaluate(context)

    def test_not_contains_operator(self):
        """Test not contains operator."""
        condition = FieldCondition("data_classification", Operator.NOT_CONTAINS, "pii")
        context = EvaluationContext(data={"data_classification": "public"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"data_classification": "pii"})
        assert not condition.evaluate(context)

    def test_matches_operator(self):
        """Test regex matches operator."""
        condition = FieldCondition("model", Operator.MATCHES, "gpt-4.*")
        context = EvaluationContext(data={"model": "gpt-4-turbo"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"model": "gpt-3.5-turbo"})
        assert not condition.evaluate(context)

    def test_exists_operator(self):
        """Test field exists operator."""
        condition = FieldCondition("approval_ticket", Operator.EXISTS, True)
        context = EvaluationContext(data={"approval_ticket": "TICKET-123"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"provider": "openai"})
        assert not condition.evaluate(context)

    def test_not_exists_operator(self):
        """Test field not exists operator."""
        condition = FieldCondition("approval_ticket", Operator.NOT_EXISTS, True)
        context = EvaluationContext(data={"provider": "openai"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"approval_ticket": "TICKET-123"})
        assert not condition.evaluate(context)

    def test_missing_field_returns_false(self):
        """Test that missing field returns False for most operators."""
        condition = FieldCondition("missing", Operator.EQ, "value")
        context = EvaluationContext(data={"provider": "openai"})
        assert not condition.evaluate(context)

    def test_describe(self):
        """Test condition description."""
        condition = FieldCondition("provider", Operator.EQ, "openai")
        assert "provider" in condition.describe()
        assert "eq" in condition.describe()


class TestLogicalConditions:
    """Tests for logical condition operators."""

    def test_and_condition(self):
        """Test AND condition."""
        condition = AndCondition(conditions=[
            FieldCondition("provider", Operator.EQ, "openai"),
            FieldCondition("model", Operator.EQ, "gpt-4"),
        ])
        context = EvaluationContext(data={"provider": "openai", "model": "gpt-4"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"provider": "openai", "model": "gpt-3.5"})
        assert not condition.evaluate(context)

    def test_and_condition_empty(self):
        """Test empty AND condition returns True."""
        condition = AndCondition(conditions=[])
        context = EvaluationContext(data={})
        assert condition.evaluate(context)

    def test_or_condition(self):
        """Test OR condition."""
        condition = OrCondition(conditions=[
            FieldCondition("department", Operator.EQ, "engineering"),
            FieldCondition("department", Operator.EQ, "research"),
        ])
        context = EvaluationContext(data={"department": "engineering"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"department": "research"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"department": "marketing"})
        assert not condition.evaluate(context)

    def test_or_condition_empty(self):
        """Test empty OR condition returns False."""
        condition = OrCondition(conditions=[])
        context = EvaluationContext(data={})
        assert not condition.evaluate(context)

    def test_not_condition(self):
        """Test NOT condition."""
        condition = NotCondition(
            condition=FieldCondition("data_classification", Operator.CONTAINS, "pii")
        )
        context = EvaluationContext(data={"data_classification": "public"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"data_classification": "pii"})
        assert not condition.evaluate(context)

    def test_complex_nested_conditions(self):
        """Test complex nested conditions."""
        # (provider == "openai") AND ((dept == "eng") OR (dept == "research")) AND NOT (pii in classification)
        condition = AndCondition(conditions=[
            FieldCondition("provider", Operator.EQ, "openai"),
            OrCondition(conditions=[
                FieldCondition("department", Operator.EQ, "engineering"),
                FieldCondition("department", Operator.EQ, "research"),
            ]),
            NotCondition(
                condition=FieldCondition("data_classification", Operator.CONTAINS, "pii")
            ),
        ])

        # Should match
        context = EvaluationContext(data={
            "provider": "openai",
            "department": "engineering",
            "data_classification": "public",
        })
        assert condition.evaluate(context)

        # Wrong provider
        context = EvaluationContext(data={
            "provider": "anthropic",
            "department": "engineering",
            "data_classification": "public",
        })
        assert not condition.evaluate(context)

        # Contains PII
        context = EvaluationContext(data={
            "provider": "openai",
            "department": "engineering",
            "data_classification": "pii",
        })
        assert not condition.evaluate(context)


class TestTimeCondition:
    """Tests for time-based conditions."""

    def test_day_of_week_single(self):
        """Test matching a single day of week."""
        # Monday = 0
        condition = TimeCondition(day_of_week=0)

        # Monday
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 12, 0)  # Monday
        )
        assert condition.evaluate(context)

        # Tuesday
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 2, 12, 0)  # Tuesday
        )
        assert not condition.evaluate(context)

    def test_day_of_week_list(self):
        """Test matching multiple days of week."""
        condition = TimeCondition(day_of_week=[0, 1, 2, 3, 4])  # Weekdays

        # Monday
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 12, 0)
        )
        assert condition.evaluate(context)

        # Saturday
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 6, 12, 0)
        )
        assert not condition.evaluate(context)

    def test_hour_range(self):
        """Test matching hour range."""
        condition = TimeCondition(hour_start=9, hour_end=17)

        # During business hours
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 12, 0)
        )
        assert condition.evaluate(context)

        # Before business hours
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 7, 0)
        )
        assert not condition.evaluate(context)

    def test_overnight_hour_range(self):
        """Test overnight hour range (e.g., 22-6)."""
        condition = TimeCondition(hour_start=22, hour_end=6)

        # Late night
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 23, 0)
        )
        assert condition.evaluate(context)

        # Early morning
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 4, 0)
        )
        assert condition.evaluate(context)

        # Afternoon
        context = EvaluationContext(
            data={},
            current_time=datetime(2024, 1, 1, 14, 0)
        )
        assert not condition.evaluate(context)


class TestConditionFactory:
    """Tests for ConditionFactory."""

    def test_create_empty_conditions(self):
        """Test creating condition from empty dict returns AlwaysTrue."""
        factory = ConditionFactory()
        condition = factory.create({})
        context = EvaluationContext(data={})
        assert condition.evaluate(context)

    def test_create_simple_equality(self):
        """Test creating simple equality condition."""
        factory = ConditionFactory()
        condition = factory.create({"provider": "openai"})

        context = EvaluationContext(data={"provider": "openai"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"provider": "anthropic"})
        assert not condition.evaluate(context)

    def test_create_operator_condition(self):
        """Test creating operator-based condition."""
        factory = ConditionFactory()
        condition = factory.create({"cost": {"gt": 10.0}})

        context = EvaluationContext(data={"cost": 15.0})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"cost": 5.0})
        assert not condition.evaluate(context)

    def test_create_and_condition(self):
        """Test creating AND condition."""
        factory = ConditionFactory()
        condition = factory.create({
            "and": [
                {"provider": "openai"},
                {"department": "engineering"},
            ]
        })

        context = EvaluationContext(data={
            "provider": "openai",
            "department": "engineering",
        })
        assert condition.evaluate(context)

        context = EvaluationContext(data={
            "provider": "openai",
            "department": "marketing",
        })
        assert not condition.evaluate(context)

    def test_create_or_condition(self):
        """Test creating OR condition."""
        factory = ConditionFactory()
        condition = factory.create({
            "or": [
                {"department": "engineering"},
                {"department": "research"},
            ]
        })

        context = EvaluationContext(data={"department": "engineering"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"department": "research"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"department": "marketing"})
        assert not condition.evaluate(context)

    def test_create_not_condition(self):
        """Test creating NOT condition."""
        factory = ConditionFactory()
        condition = factory.create({
            "not": {"data_classification": {"contains": "pii"}}
        })

        context = EvaluationContext(data={"data_classification": "public"})
        assert condition.evaluate(context)

        context = EvaluationContext(data={"data_classification": "pii"})
        assert not condition.evaluate(context)

    def test_create_complex_nested(self):
        """Test creating complex nested conditions."""
        factory = ConditionFactory()
        condition = factory.create({
            "and": [
                {"provider": "openai"},
                {
                    "or": [
                        {"department": "engineering"},
                        {"user": {"in": ["admin1", "admin2"]}},
                    ]
                },
                {
                    "not": {"cost": {"gt": 100.0}}
                }
            ]
        })

        context = EvaluationContext(data={
            "provider": "openai",
            "department": "engineering",
            "cost": 50.0,
        })
        assert condition.evaluate(context)

        context = EvaluationContext(data={
            "provider": "openai",
            "user": "admin1",
            "cost": 50.0,
        })
        assert condition.evaluate(context)

        context = EvaluationContext(data={
            "provider": "openai",
            "department": "engineering",
            "cost": 150.0,
        })
        assert not condition.evaluate(context)

    def test_multiple_top_level_conditions_anded(self):
        """Test that multiple top-level conditions are AND-ed."""
        factory = ConditionFactory()
        condition = factory.create({
            "provider": "openai",
            "department": "engineering",
        })

        context = EvaluationContext(data={
            "provider": "openai",
            "department": "engineering",
        })
        assert condition.evaluate(context)

        context = EvaluationContext(data={
            "provider": "openai",
            "department": "marketing",
        })
        assert not condition.evaluate(context)


class TestPolicyMatcher:
    """Tests for PolicyMatcher."""

    def test_match_simple_rule(self):
        """Test matching a simple rule."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-engineering",
            match_conditions={"department": "engineering"},
            action="ALLOW",
            priority=100,
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        )

        result = matcher.match(policy_set, request)
        assert result.matched
        assert result.rule is not None
        assert result.rule.name == "allow-engineering"

    def test_no_match(self):
        """Test when no rules match."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-engineering",
            match_conditions={"department": "engineering"},
            action="ALLOW",
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="marketing",
        )

        result = matcher.match(policy_set, request)
        assert not result.matched
        assert result.rule is None

    def test_priority_ordering(self):
        """Test that higher priority rules match first."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="low-priority",
            match_conditions={"department": "engineering"},
            action="ALLOW",
            priority=10,
        ))
        policy_set.add_rule(PolicyRule(
            name="high-priority",
            match_conditions={"department": "engineering"},
            action="DENY",
            priority=100,
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        )

        result = matcher.match(policy_set, request)
        assert result.matched
        assert result.rule.name == "high-priority"
        assert result.rule.action == "DENY"

    def test_all_matches_returned(self):
        """Test that all matching rules are returned."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="rule-1",
            match_conditions={"department": "engineering"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="rule-2",
            match_conditions={"provider": "openai"},
            action="AUDIT",
            priority=50,
        ))
        policy_set.add_rule(PolicyRule(
            name="rule-3",
            match_conditions={"department": "marketing"},
            action="DENY",
            priority=50,
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        )

        result = matcher.match(policy_set, request)
        assert result.matched
        assert len(result.all_matches) == 2  # rule-1 and rule-2
        assert result.all_matches[0].name == "rule-1"  # Highest priority
        assert result.all_matches[1].name == "rule-2"

    def test_disabled_rules_skipped(self):
        """Test that disabled rules are not matched."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="disabled-rule",
            match_conditions={"department": "engineering"},
            action="DENY",
            enabled=False,
        ))
        policy_set.add_rule(PolicyRule(
            name="enabled-rule",
            match_conditions={"department": "engineering"},
            action="ALLOW",
            enabled=True,
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        )

        result = matcher.match(policy_set, request)
        assert result.matched
        assert result.rule.name == "enabled-rule"

    def test_catch_all_rule(self):
        """Test catch-all rule with empty conditions."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="catch-all",
            match_conditions={},
            action="DENY",
            priority=0,
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="marketing",
        )

        result = matcher.match(policy_set, request)
        assert result.matched
        assert result.rule.name == "catch-all"

    def test_complex_conditions(self):
        """Test matching with complex conditions."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="complex-rule",
            match_conditions={
                "and": [
                    {"provider": "openai"},
                    {
                        "or": [
                            {"department": "engineering"},
                            {"department": "research"},
                        ]
                    },
                    {
                        "not": {"data_classification": {"contains": "pii"}}
                    },
                ]
            },
            action="ALLOW",
        ))

        matcher = PolicyMatcher()

        # Should match
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
            data_classification="public",
        )
        result = matcher.match(policy_set, request)
        assert result.matched

        # Should not match (contains PII)
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
            data_classification="pii",
        )
        result = matcher.match(policy_set, request)
        assert not result.matched

    def test_would_match_convenience_method(self):
        """Test the would_match convenience method."""
        rule = PolicyRule(
            name="test-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        )

        matcher = PolicyMatcher()
        request = AIRequest(provider="openai", model="gpt-4")
        assert matcher.would_match(rule, request)

        request = AIRequest(provider="anthropic", model="claude")
        assert not matcher.would_match(rule, request)

    def test_match_all_method(self):
        """Test the match_all method."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="rule-1",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="rule-2",
            match_conditions={"department": "engineering"},
            action="AUDIT",
            priority=50,
        ))

        matcher = PolicyMatcher()
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        )

        results = matcher.match_all(policy_set, request)
        assert len(results) == 2
        assert results[0].rule.name == "rule-1"  # Sorted by priority
        assert results[1].rule.name == "rule-2"


class TestMatchOptimizer:
    """Tests for MatchOptimizer."""

    def test_optimize_creates_indices(self):
        """Test that optimize creates field indices."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="openai-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))
        policy_set.add_rule(PolicyRule(
            name="anthropic-rule",
            match_conditions={"provider": "anthropic"},
            action="ALLOW",
        ))

        optimizer = MatchOptimizer()
        optimizer.optimize(policy_set)

        info = optimizer.get_index_info()
        assert info["optimized"]
        assert info["total_rules"] == 2
        assert "provider" in info["indexed_fields"]

    def test_get_candidates_filters_rules(self):
        """Test that get_candidates returns relevant rules."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="openai-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))
        policy_set.add_rule(PolicyRule(
            name="anthropic-rule",
            match_conditions={"provider": "anthropic"},
            action="ALLOW",
        ))

        optimizer = MatchOptimizer()
        optimizer.optimize(policy_set)

        request = AIRequest(provider="openai", model="gpt-4")
        candidates = optimizer.get_candidates(request)

        # Should include the openai rule
        rule_names = [c.rule.name for c in candidates]
        assert "openai-rule" in rule_names

    def test_catch_all_rules_always_included(self):
        """Test that catch-all rules are always included."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="specific-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))
        policy_set.add_rule(PolicyRule(
            name="catch-all",
            match_conditions={},
            action="DENY",
            priority=0,
        ))

        optimizer = MatchOptimizer()
        optimizer.optimize(policy_set)

        request = AIRequest(provider="anthropic", model="claude")
        candidates = optimizer.get_candidates(request)

        rule_names = [c.rule.name for c in candidates]
        assert "catch-all" in rule_names

    def test_stats_tracking(self):
        """Test that statistics are tracked."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="test-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))

        optimizer = MatchOptimizer()
        optimizer.optimize(policy_set)

        request = AIRequest(provider="openai", model="gpt-4")
        optimizer.get_candidates(request)
        optimizer.get_candidates(request)

        stats = optimizer.get_stats()
        assert stats.total_matches == 2

    def test_clear_resets_optimizer(self):
        """Test that clear resets the optimizer."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="test-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))

        optimizer = MatchOptimizer()
        optimizer.optimize(policy_set)
        assert optimizer.is_optimized()

        optimizer.clear()
        assert not optimizer.is_optimized()


class TestOptimizedMatcher:
    """Tests for OptimizedMatcher."""

    def test_basic_matching(self):
        """Test basic matching with OptimizedMatcher."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))

        matcher = OptimizedMatcher(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        result = matcher.match(request)
        assert result.matched
        assert result.rule.name == "allow-rule"

    def test_stats_available(self):
        """Test that stats are available through OptimizedMatcher."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="test-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))

        matcher = OptimizedMatcher(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")
        matcher.match(request)

        stats = matcher.get_stats()
        assert stats.total_matches >= 1

    def test_reload_policy(self):
        """Test reloading with new policy set."""
        policy_set1 = PolicySet(name="test1", version="1.0.0")
        policy_set1.add_rule(PolicyRule(
            name="rule-1",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))

        matcher = OptimizedMatcher(policy_set1)

        policy_set2 = PolicySet(name="test2", version="2.0.0")
        policy_set2.add_rule(PolicyRule(
            name="rule-2",
            match_conditions={"provider": "anthropic"},
            action="DENY",
        ))

        matcher.reload(policy_set2)

        request = AIRequest(provider="anthropic", model="claude")
        result = matcher.match(request)
        assert result.matched
        assert result.rule.name == "rule-2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
