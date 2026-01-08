"""
Unit tests for PolicyBind policy matcher.

This module tests the PolicyMatcher class for evaluating requests
against policy rules.
"""

from datetime import datetime

import pytest

from policybind.engine.matcher import MatchResult, PolicyMatcher
from policybind.models.policy import PolicyMatch, PolicyRule, PolicySet
from policybind.models.request import AIRequest


# =============================================================================
# MatchResult Tests
# =============================================================================


class TestMatchResult:
    """Tests for MatchResult class."""

    def test_create_matched_result(self) -> None:
        """Test creating a matched result."""
        rule = PolicyRule(name="test-rule", action="ALLOW")
        result = MatchResult(rule=rule, matched=True, score=0.5)
        assert result.matched is True
        assert result.score == 0.5
        assert result.rule.name == "test-rule"

    def test_create_unmatched_result(self) -> None:
        """Test creating an unmatched result."""
        rule = PolicyRule(name="test-rule", action="DENY")
        result = MatchResult(rule=rule, matched=False)
        assert result.matched is False
        assert result.score == 0.0

    def test_matched_fields(self) -> None:
        """Test matched fields collection."""
        rule = PolicyRule(name="test-rule", action="ALLOW")
        result = MatchResult(
            rule=rule,
            matched=True,
            matched_fields={"provider": "openai", "model": "gpt-4"},
        )
        assert result.matched_fields["provider"] == "openai"
        assert result.matched_fields["model"] == "gpt-4"


# =============================================================================
# PolicyMatcher Basic Tests
# =============================================================================


class TestPolicyMatcher:
    """Tests for PolicyMatcher class."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    @pytest.fixture
    def simple_request(self) -> AIRequest:
        """Create a simple test request."""
        return AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user123",
            department="engineering",
        )

    def test_match_empty_policy_set(self, matcher: PolicyMatcher) -> None:
        """Test matching against empty policy set."""
        policy = PolicySet(name="empty", version="1.0.0", rules=[])
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is False
        assert result.rule is None

    def test_match_simple_rule(
        self, matcher: PolicyMatcher, simple_request: AIRequest
    ) -> None:
        """Test matching a simple rule."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-openai",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                )
            ],
        )
        result = matcher.match(policy, simple_request)
        assert result.matched is True
        assert result.rule is not None
        assert result.rule.name == "allow-openai"

    def test_no_match_different_provider(
        self, matcher: PolicyMatcher, simple_request: AIRequest
    ) -> None:
        """Test no match when provider differs."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-anthropic",
                    action="ALLOW",
                    match_conditions={"provider": "anthropic"},
                )
            ],
        )
        result = matcher.match(policy, simple_request)
        assert result.matched is False

    def test_match_multiple_conditions(
        self, matcher: PolicyMatcher, simple_request: AIRequest
    ) -> None:
        """Test matching with multiple conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-gpt4",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "gpt-4",
                    },
                )
            ],
        )
        result = matcher.match(policy, simple_request)
        assert result.matched is True

    def test_no_match_partial_conditions(
        self, matcher: PolicyMatcher, simple_request: AIRequest
    ) -> None:
        """Test no match when only some conditions match."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-claude",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "claude-3",  # Different model
                    },
                )
            ],
        )
        result = matcher.match(policy, simple_request)
        assert result.matched is False


class TestPolicyMatcherPriority:
    """Tests for priority-based matching."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_highest_priority_wins(self, matcher: PolicyMatcher) -> None:
        """Test that highest priority rule wins."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="low-priority",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
                PolicyRule(
                    name="high-priority",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=100,
                ),
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is True
        assert result.rule is not None
        assert result.rule.name == "high-priority"

    def test_all_matches_returned(self, matcher: PolicyMatcher) -> None:
        """Test that all matching rules are tracked."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
                PolicyRule(
                    name="rule2",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=20,
                ),
                PolicyRule(
                    name="rule3",
                    action="ALLOW",
                    match_conditions={"provider": "anthropic"},  # Won't match
                    priority=30,
                ),
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is True
        assert len(result.all_matches) == 2
        # Should be sorted by priority (highest first)
        assert result.all_matches[0].name == "rule2"
        assert result.all_matches[1].name == "rule1"


class TestPolicyMatcherDisabledRules:
    """Tests for disabled rule handling."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_disabled_rules_ignored(self, matcher: PolicyMatcher) -> None:
        """Test that disabled rules are not matched."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="disabled-rule",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=100,
                    enabled=False,
                ),
                PolicyRule(
                    name="enabled-rule",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is True
        assert result.rule is not None
        assert result.rule.name == "enabled-rule"

    def test_all_disabled_no_match(self, matcher: PolicyMatcher) -> None:
        """Test no match when all rules are disabled."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="disabled1",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    enabled=False,
                ),
                PolicyRule(
                    name="disabled2",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    enabled=False,
                ),
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is False


class TestPolicyMatcherConditions:
    """Tests for various condition types."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_empty_conditions_match_all(self, matcher: PolicyMatcher) -> None:
        """Test that empty conditions match all requests."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="catch-all",
                    action="ALLOW",
                    match_conditions={},  # Empty = match all
                )
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is True

    def test_and_conditions(self, matcher: PolicyMatcher) -> None:
        """Test AND logical operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="and-rule",
                    action="ALLOW",
                    match_conditions={
                        "and": [
                            {"provider": "openai"},
                            {"model": "gpt-4"},
                        ]
                    },
                )
            ],
        )
        # Should match
        request1 = AIRequest(provider="openai", model="gpt-4")
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match (wrong model)
        request2 = AIRequest(provider="openai", model="gpt-3.5")
        result2 = matcher.match(policy, request2)
        assert result2.matched is False

    def test_or_conditions(self, matcher: PolicyMatcher) -> None:
        """Test OR logical operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="or-rule",
                    action="ALLOW",
                    match_conditions={
                        "or": [
                            {"model": "gpt-4"},
                            {"model": "gpt-3.5-turbo"},
                        ]
                    },
                )
            ],
        )
        # Should match gpt-4
        request1 = AIRequest(provider="openai", model="gpt-4")
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should match gpt-3.5-turbo
        request2 = AIRequest(provider="openai", model="gpt-3.5-turbo")
        result2 = matcher.match(policy, request2)
        assert result2.matched is True

        # Should not match
        request3 = AIRequest(provider="openai", model="davinci")
        result3 = matcher.match(policy, request3)
        assert result3.matched is False

    def test_not_conditions(self, matcher: PolicyMatcher) -> None:
        """Test NOT logical operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="not-rule",
                    action="DENY",
                    match_conditions={
                        "not": {"department": "engineering"},
                    },
                )
            ],
        )
        # Should not match (is engineering)
        request1 = AIRequest(provider="openai", department="engineering")
        result1 = matcher.match(policy, request1)
        assert result1.matched is False

        # Should match (is not engineering)
        request2 = AIRequest(provider="openai", department="marketing")
        result2 = matcher.match(policy, request2)
        assert result2.matched is True

    def test_nested_conditions(self, matcher: PolicyMatcher) -> None:
        """Test complex nested conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="nested-rule",
                    action="ALLOW",
                    match_conditions={
                        "and": [
                            {"provider": "openai"},
                            {
                                "or": [
                                    {"model": "gpt-4"},
                                    {"model": "gpt-4-turbo"},
                                ]
                            },
                        ]
                    },
                )
            ],
        )
        # Should match
        request1 = AIRequest(provider="openai", model="gpt-4")
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should match
        request2 = AIRequest(provider="openai", model="gpt-4-turbo")
        result2 = matcher.match(policy, request2)
        assert result2.matched is True

        # Should not match (wrong provider)
        request3 = AIRequest(provider="anthropic", model="gpt-4")
        result3 = matcher.match(policy, request3)
        assert result3.matched is False


class TestPolicyMatcherOperators:
    """Tests for condition operators."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_in_operator(self, matcher: PolicyMatcher) -> None:
        """Test 'in' operator for list membership."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="in-rule",
                    action="ALLOW",
                    match_conditions={
                        "department": {"in": ["engineering", "research"]}
                    },
                )
            ],
        )
        # Should match
        request1 = AIRequest(provider="openai", department="engineering")
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match
        request2 = AIRequest(provider="openai", department="marketing")
        result2 = matcher.match(policy, request2)
        assert result2.matched is False

    def test_not_in_operator(self, matcher: PolicyMatcher) -> None:
        """Test 'not_in' operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="not-in-rule",
                    action="DENY",
                    match_conditions={
                        "department": {"not_in": ["restricted", "external"]}
                    },
                )
            ],
        )
        # Should match (not in restricted list)
        request1 = AIRequest(provider="openai", department="engineering")
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match (is in restricted list)
        request2 = AIRequest(provider="openai", department="restricted")
        result2 = matcher.match(policy, request2)
        assert result2.matched is False

    def test_gt_operator(self, matcher: PolicyMatcher) -> None:
        """Test 'gt' (greater than) operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="gt-rule",
                    action="DENY",
                    match_conditions={"cost": {"gt": 100.0}},
                )
            ],
        )
        # Should match (cost > 100)
        request1 = AIRequest(provider="openai", estimated_cost=150.0)
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match (cost <= 100)
        request2 = AIRequest(provider="openai", estimated_cost=50.0)
        result2 = matcher.match(policy, request2)
        assert result2.matched is False

    def test_gte_operator(self, matcher: PolicyMatcher) -> None:
        """Test 'gte' (greater than or equal) operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="gte-rule",
                    action="DENY",
                    match_conditions={"tokens": {"gte": 1000}},
                )
            ],
        )
        # Should match (tokens >= 1000)
        request1 = AIRequest(provider="openai", estimated_tokens=1000)
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match
        request2 = AIRequest(provider="openai", estimated_tokens=999)
        result2 = matcher.match(policy, request2)
        assert result2.matched is False

    def test_lt_operator(self, matcher: PolicyMatcher) -> None:
        """Test 'lt' (less than) operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="lt-rule",
                    action="ALLOW",
                    match_conditions={"cost": {"lt": 10.0}},
                )
            ],
        )
        # Should match
        request1 = AIRequest(provider="openai", estimated_cost=5.0)
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match
        request2 = AIRequest(provider="openai", estimated_cost=10.0)
        result2 = matcher.match(policy, request2)
        assert result2.matched is False

    def test_lte_operator(self, matcher: PolicyMatcher) -> None:
        """Test 'lte' (less than or equal) operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="lte-rule",
                    action="ALLOW",
                    match_conditions={"tokens": {"lte": 500}},
                )
            ],
        )
        # Should match
        request1 = AIRequest(provider="openai", estimated_tokens=500)
        result1 = matcher.match(policy, request1)
        assert result1.matched is True

        # Should not match
        request2 = AIRequest(provider="openai", estimated_tokens=501)
        result2 = matcher.match(policy, request2)
        assert result2.matched is False


class TestPolicyMatcherMethods:
    """Tests for other matcher methods."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_match_all(self, matcher: PolicyMatcher) -> None:
        """Test match_all returns all matching rules."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
                PolicyRule(
                    name="rule2",
                    action="LOG",
                    match_conditions={"provider": "openai"},
                    priority=20,
                ),
                PolicyRule(
                    name="rule3",
                    action="DENY",
                    match_conditions={"provider": "anthropic"},
                    priority=30,
                ),
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        results = matcher.match_all(policy, request)
        assert len(results) == 2
        assert all(r.matched for r in results)

    def test_would_match_single_rule(self, matcher: PolicyMatcher) -> None:
        """Test would_match for a single rule."""
        rule = PolicyRule(
            name="test-rule",
            action="ALLOW",
            match_conditions={"provider": "openai"},
        )
        request1 = AIRequest(provider="openai")
        assert matcher.would_match(rule, request1) is True

        request2 = AIRequest(provider="anthropic")
        assert matcher.would_match(rule, request2) is False

    def test_would_match_disabled_rule(self, matcher: PolicyMatcher) -> None:
        """Test would_match returns False for disabled rules."""
        rule = PolicyRule(
            name="disabled-rule",
            action="ALLOW",
            match_conditions={"provider": "openai"},
            enabled=False,
        )
        request = AIRequest(provider="openai")
        assert matcher.would_match(rule, request) is False

    def test_clear_cache(self, matcher: PolicyMatcher) -> None:
        """Test clearing the condition cache."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                )
            ],
        )
        request = AIRequest(provider="openai")
        # First match compiles conditions
        matcher.match(policy, request)
        assert len(matcher._compiled_conditions) > 0

        # Clear cache
        matcher.clear_cache()
        assert len(matcher._compiled_conditions) == 0

    def test_precompile(self, matcher: PolicyMatcher) -> None:
        """Test precompiling conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                ),
                PolicyRule(
                    name="rule2",
                    action="DENY",
                    match_conditions={"model": "gpt-4"},
                ),
                PolicyRule(
                    name="rule3-disabled",
                    action="ALLOW",
                    match_conditions={"department": "test"},
                    enabled=False,
                ),
            ],
        )
        matcher.precompile(policy)
        # Only enabled rules should be precompiled
        assert len(matcher._compiled_conditions) == 2


class TestPolicyMatcherScore:
    """Tests for match scoring."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_empty_conditions_low_score(self, matcher: PolicyMatcher) -> None:
        """Test that empty conditions have low specificity score."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="catch-all",
                    action="ALLOW",
                    match_conditions={},
                )
            ],
        )
        request = AIRequest(provider="openai")
        result = matcher.match(policy, request)
        assert result.matched is True
        assert result.match_score < 0.2  # Low score for empty conditions

    def test_specific_conditions_higher_score(self, matcher: PolicyMatcher) -> None:
        """Test that more specific conditions have higher score."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="specific-rule",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "gpt-4",
                        "department": "engineering",
                    },
                    priority=100,
                )
            ],
        )
        request = AIRequest(
            provider="openai", model="gpt-4", department="engineering"
        )
        result = matcher.match(policy, request)
        assert result.matched is True
        assert result.match_score > 0.2  # Higher score


class TestPolicyMatcherMetadata:
    """Tests for metadata handling."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_metadata_conditions(self, matcher: PolicyMatcher) -> None:
        """Test matching on metadata fields."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="metadata-rule",
                    action="ALLOW",
                    match_conditions={"project": "alpha"},
                )
            ],
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"project": "alpha"},
        )
        result = matcher.match(policy, request)
        assert result.matched is True

    def test_nested_metadata(self, matcher: PolicyMatcher) -> None:
        """Test matching on nested metadata fields."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="nested-metadata-rule",
                    action="ALLOW",
                    match_conditions={"metadata.project": "alpha"},
                )
            ],
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"project": "alpha"},
        )
        result = matcher.match(policy, request)
        assert result.matched is True


class TestPolicyMatcherEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def matcher(self) -> PolicyMatcher:
        """Create a policy matcher."""
        return PolicyMatcher()

    def test_unicode_values(self, matcher: PolicyMatcher) -> None:
        """Test matching with unicode values."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="unicode-rule",
                    action="ALLOW",
                    match_conditions={"department": "日本語チーム"},
                )
            ],
        )
        request = AIRequest(provider="openai", department="日本語チーム")
        result = matcher.match(policy, request)
        assert result.matched is True

    def test_special_characters(self, matcher: PolicyMatcher) -> None:
        """Test matching with special characters."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="special-chars-rule",
                    action="ALLOW",
                    match_conditions={"user_id": "user@example.com"},
                )
            ],
        )
        request = AIRequest(provider="openai", user_id="user@example.com")
        result = matcher.match(policy, request)
        assert result.matched is True

    def test_many_rules(self, matcher: PolicyMatcher) -> None:
        """Test performance with many rules."""
        rules = [
            PolicyRule(
                name=f"rule-{i}",
                action="ALLOW",
                match_conditions={"department": f"dept-{i}"},
                priority=i,
            )
            for i in range(100)
        ]
        policy = PolicySet(name="test", version="1.0.0", rules=rules)
        request = AIRequest(provider="openai", department="dept-50")
        result = matcher.match(policy, request)
        assert result.matched is True
        assert result.rule is not None
        assert result.rule.name == "rule-50"

    def test_matched_conditions_in_result(self, matcher: PolicyMatcher) -> None:
        """Test that matched conditions are included in result."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="test-rule",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "gpt-4",
                    },
                )
            ],
        )
        request = AIRequest(provider="openai", model="gpt-4")
        result = matcher.match(policy, request)
        assert result.matched is True
        assert "provider" in result.matched_conditions
        assert "model" in result.matched_conditions

    def test_time_based_matching(self, matcher: PolicyMatcher) -> None:
        """Test matching with custom time."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="test-rule",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                )
            ],
        )
        request = AIRequest(provider="openai")
        custom_time = datetime(2024, 1, 15, 10, 30, 0)
        result = matcher.match(policy, request, current_time=custom_time)
        assert result.matched is True
