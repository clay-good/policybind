"""
Unit tests for PolicyBind enforcement pipeline.

This module tests the EnforcementPipeline class for orchestrating
the full request enforcement lifecycle.
"""

import pytest

from policybind.engine.pipeline import (
    EnforcementPipeline,
    FailureMode,
    PipelineConfig,
)
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, Decision


# =============================================================================
# PipelineConfig Tests
# =============================================================================


class TestPipelineConfig:
    """Tests for PipelineConfig class."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = PipelineConfig()
        assert config.failure_mode == FailureMode.FAIL_CLOSED
        assert config.enable_timing is True
        assert config.enable_audit is True
        assert config.require_classification is False
        assert config.rate_limit_enabled is False
        assert config.requests_per_minute == 60.0
        assert config.cost_tracking_enabled is False
        assert config.default_budget is None

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = PipelineConfig(
            failure_mode=FailureMode.FAIL_OPEN,
            enable_timing=False,
            enable_audit=False,
            require_classification=True,
            rate_limit_enabled=True,
            requests_per_minute=30.0,
            cost_tracking_enabled=True,
            default_budget=100.0,
        )
        assert config.failure_mode == FailureMode.FAIL_OPEN
        assert config.enable_timing is False
        assert config.enable_audit is False
        assert config.require_classification is True
        assert config.rate_limit_enabled is True
        assert config.requests_per_minute == 30.0
        assert config.cost_tracking_enabled is True
        assert config.default_budget == 100.0


class TestFailureMode:
    """Tests for FailureMode enum."""

    def test_fail_closed_value(self) -> None:
        """Test fail closed value."""
        assert FailureMode.FAIL_CLOSED.value == "fail_closed"

    def test_fail_open_value(self) -> None:
        """Test fail open value."""
        assert FailureMode.FAIL_OPEN.value == "fail_open"


# =============================================================================
# EnforcementPipeline Tests
# =============================================================================


class TestEnforcementPipeline:
    """Tests for EnforcementPipeline class."""

    @pytest.fixture
    def simple_policy(self) -> PolicySet:
        """Create a simple policy set."""
        return PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-openai",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                )
            ],
        )

    @pytest.fixture
    def multi_rule_policy(self) -> PolicySet:
        """Create a policy set with multiple rules."""
        return PolicySet(
            name="multi-rule-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="deny-high-cost",
                    action="DENY",
                    match_conditions={"cost": {"gt": 100.0}},
                    priority=100,
                ),
                PolicyRule(
                    name="allow-gpt4",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "gpt-4",
                    },
                    priority=50,
                ),
                PolicyRule(
                    name="allow-anthropic",
                    action="ALLOW",
                    match_conditions={"provider": "anthropic"},
                    priority=10,
                ),
            ],
        )

    def test_create_pipeline(self, simple_policy: PolicySet) -> None:
        """Test creating a pipeline."""
        pipeline = EnforcementPipeline(simple_policy)
        assert pipeline.get_policy_set() == simple_policy

    def test_create_pipeline_with_config(self, simple_policy: PolicySet) -> None:
        """Test creating a pipeline with custom config."""
        config = PipelineConfig(
            failure_mode=FailureMode.FAIL_OPEN,
            enable_audit=False,
        )
        pipeline = EnforcementPipeline(simple_policy, config)
        assert pipeline.get_policy_set() == simple_policy

    def test_process_allowed_request(self, simple_policy: PolicySet) -> None:
        """Test processing an allowed request."""
        pipeline = EnforcementPipeline(simple_policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.ALLOW
        assert "allow-openai" in response.applied_rules

    def test_process_denied_no_match(self, simple_policy: PolicySet) -> None:
        """Test processing a request with no matching rule."""
        pipeline = EnforcementPipeline(simple_policy)
        request = AIRequest(provider="anthropic", model="claude-3")
        response = pipeline.process(request)
        assert response.decision == Decision.DENY
        assert "No matching policy rule" in response.reason

    def test_process_with_priority(self, multi_rule_policy: PolicySet) -> None:
        """Test that higher priority rules are applied first."""
        pipeline = EnforcementPipeline(multi_rule_policy)
        # High cost request should be denied by high-priority rule
        request = AIRequest(
            provider="openai", model="gpt-4", estimated_cost=150.0
        )
        response = pipeline.process(request)
        assert response.decision == Decision.DENY
        assert "deny-high-cost" in response.applied_rules

    def test_process_with_context(self, simple_policy: PolicySet) -> None:
        """Test processing with context returned."""
        pipeline = EnforcementPipeline(simple_policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response, context = pipeline.process_with_context(request)
        assert response.decision == Decision.ALLOW
        assert context.request == request
        assert len(context.stage_results) > 0


class TestEnforcementPipelineMiddleware:
    """Tests for pipeline middleware."""

    @pytest.fixture
    def policy(self) -> PolicySet:
        """Create a simple policy set."""
        return PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                )
            ],
        )

    def test_middleware_chain(self, policy: PolicySet) -> None:
        """Test that middleware chain is set up."""
        pipeline = EnforcementPipeline(policy)
        middleware = pipeline.get_middleware()
        assert len(middleware) > 0

    def test_rate_limit_middleware(self, policy: PolicySet) -> None:
        """Test rate limit middleware is added when enabled."""
        config = PipelineConfig(rate_limit_enabled=True)
        pipeline = EnforcementPipeline(policy, config)
        middleware = pipeline.get_middleware()
        middleware_names = [type(m).__name__ for m in middleware]
        assert "RateLimiter" in middleware_names

    def test_cost_tracking_middleware(self, policy: PolicySet) -> None:
        """Test cost tracking middleware is added when enabled."""
        config = PipelineConfig(cost_tracking_enabled=True, default_budget=100.0)
        pipeline = EnforcementPipeline(policy, config)
        middleware = pipeline.get_middleware()
        middleware_names = [type(m).__name__ for m in middleware]
        assert "CostTracker" in middleware_names

    def test_audit_disabled(self, policy: PolicySet) -> None:
        """Test audit middleware is not added when disabled."""
        config = PipelineConfig(enable_audit=False)
        pipeline = EnforcementPipeline(policy, config)
        middleware = pipeline.get_middleware()
        middleware_names = [type(m).__name__ for m in middleware]
        assert "AuditLogger" not in middleware_names


class TestEnforcementPipelineFailure:
    """Tests for failure handling."""

    @pytest.fixture
    def empty_policy(self) -> PolicySet:
        """Create an empty policy set."""
        return PolicySet(name="empty", version="1.0.0", rules=[])

    def test_fail_closed_mode(self, empty_policy: PolicySet) -> None:
        """Test fail closed mode denies on no match."""
        config = PipelineConfig(failure_mode=FailureMode.FAIL_CLOSED)
        pipeline = EnforcementPipeline(empty_policy, config)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.DENY

    def test_response_includes_timing(self) -> None:
        """Test that response includes timing information."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(name="allow-all", action="ALLOW", match_conditions={})
            ],
        )
        config = PipelineConfig(enable_timing=True)
        pipeline = EnforcementPipeline(policy, config)
        request = AIRequest(provider="openai")
        response = pipeline.process(request)
        assert response.enforcement_time_ms >= 0


class TestEnforcementPipelineReload:
    """Tests for policy reloading."""

    def test_reload_policies(self) -> None:
        """Test reloading policies."""
        policy1 = PolicySet(
            name="policy1",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="deny-all",
                    action="DENY",
                    match_conditions={},
                )
            ],
        )
        policy2 = PolicySet(
            name="policy2",
            version="2.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                )
            ],
        )

        pipeline = EnforcementPipeline(policy1)
        request = AIRequest(provider="openai", model="gpt-4")

        # Should deny with policy1
        response1 = pipeline.process(request)
        assert response1.decision == Decision.DENY

        # Reload with policy2
        pipeline.reload_policies(policy2)
        assert pipeline.get_policy_set() == policy2

        # Should allow with policy2
        response2 = pipeline.process(request)
        assert response2.decision == Decision.ALLOW


class TestEnforcementPipelineActions:
    """Tests for different action types."""

    def test_allow_action(self) -> None:
        """Test ALLOW action."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-rule",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.ALLOW

    def test_deny_action(self) -> None:
        """Test DENY action."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="deny-rule",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.DENY

    def test_modify_action(self) -> None:
        """Test MODIFY action."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="modify-rule",
                    action="MODIFY",
                    match_conditions={"provider": "openai"},
                    action_params={"max_tokens": 1000},
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.MODIFY


class TestEnforcementPipelineEdgeCases:
    """Tests for edge cases."""

    def test_disabled_rules_skipped(self) -> None:
        """Test that disabled rules are skipped."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="disabled-deny",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=100,
                    enabled=False,
                ),
                PolicyRule(
                    name="enabled-allow",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.ALLOW
        assert "enabled-allow" in response.applied_rules

    def test_empty_request_validation_fails(self) -> None:
        """Test processing empty request fails validation (requires provider/model)."""
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
        pipeline = EnforcementPipeline(policy)
        request = AIRequest()  # Empty request - will fail validation
        response = pipeline.process(request)
        # Empty request fails validation because provider/model are required by default
        assert response.decision == Decision.DENY
        assert "Missing required fields" in response.reason

    def test_complex_conditions(self) -> None:
        """Test with complex nested conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="complex-rule",
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
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.ALLOW

    def test_multiple_matching_rules(self) -> None:
        """Test with multiple matching rules."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="low-priority",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
                PolicyRule(
                    name="high-priority",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=100,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.DENY
        assert "high-priority" in response.applied_rules

    def test_response_has_request_id(self) -> None:
        """Test that response has correct request ID."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(request_id="test-request-123", provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.request_id == "test-request-123"
