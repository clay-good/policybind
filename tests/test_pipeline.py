"""
Tests for the enforcement pipeline.

Tests context, middleware, executor, and pipeline components.
"""

import pytest
import time
from datetime import datetime

from policybind.engine.context import (
    EnforcementContext,
    EnforcementResult,
    PipelineStage,
    StageResult,
)
from policybind.engine.executor import ActionExecutor
from policybind.engine.middleware import (
    AuditLogger,
    ClassificationEnforcer,
    CostTracker,
    Middleware,
    RateLimiter,
    RequestValidator,
)
from policybind.engine.pipeline import (
    EnforcementPipeline,
    FailureMode,
    PipelineConfig,
)
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, Decision


class TestEnforcementContext:
    """Tests for EnforcementContext."""

    def test_create_context(self):
        """Test creating a context."""
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        assert context.request == request
        assert context.current_stage == PipelineStage.VALIDATION
        assert context.final_decision == Decision.DENY

    def test_start_and_complete(self):
        """Test start and complete tracking."""
        context = EnforcementContext()
        context.start()

        assert context.start_time is not None
        assert context.end_time is None

        time.sleep(0.01)
        context.complete()

        assert context.end_time is not None
        assert context.current_stage == PipelineStage.COMPLETE
        assert context.get_total_duration_ms() > 0

    def test_short_circuit(self):
        """Test short-circuiting the pipeline."""
        context = EnforcementContext()
        context.short_circuit(Decision.DENY, "Rate limit exceeded")

        assert context.is_short_circuited
        assert context.short_circuit_reason == "Rate limit exceeded"
        assert context.final_decision == Decision.DENY

    def test_add_stage_result(self):
        """Test adding stage results."""
        context = EnforcementContext()
        result = StageResult(
            stage=PipelineStage.VALIDATION,
            success=True,
            duration_ms=5.0,
        )
        context.add_stage_result(result)

        assert len(context.stage_results) == 1
        assert context.get_stage_duration_ms(PipelineStage.VALIDATION) == 5.0

    def test_add_modification(self):
        """Test adding modifications."""
        context = EnforcementContext()
        context.add_modification("redacted_fields", ["ssn", "credit_card"])

        assert "redacted_fields" in context.modifications

    def test_add_warning(self):
        """Test adding warnings."""
        context = EnforcementContext()
        context.add_warning("Classification not provided")

        assert len(context.warnings) == 1

    def test_to_dict(self):
        """Test serialization to dict."""
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)
        context.start()
        context.complete()

        data = context.to_dict()

        assert "id" in data
        assert data["request_id"] == request.request_id
        assert "total_duration_ms" in data


class TestEnforcementResult:
    """Tests for EnforcementResult."""

    def test_from_context(self):
        """Test creating result from context."""
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)
        context.start()
        context.final_decision = Decision.ALLOW
        context.complete()

        result = EnforcementResult.from_context(context)

        assert result.request_id == request.request_id
        assert result.decision == Decision.ALLOW
        assert result.duration_ms >= 0

    def test_is_allowed(self):
        """Test is_allowed method."""
        result = EnforcementResult(
            request_id="test",
            decision=Decision.ALLOW,
        )
        assert result.is_allowed()

        result = EnforcementResult(
            request_id="test",
            decision=Decision.MODIFY,
        )
        assert result.is_allowed()

        result = EnforcementResult(
            request_id="test",
            decision=Decision.DENY,
        )
        assert not result.is_allowed()

    def test_is_denied(self):
        """Test is_denied method."""
        result = EnforcementResult(
            request_id="test",
            decision=Decision.DENY,
        )
        assert result.is_denied()

    def test_requires_approval(self):
        """Test requires_approval method."""
        result = EnforcementResult(
            request_id="test",
            decision=Decision.REQUIRE_APPROVAL,
        )
        assert result.requires_approval()


class TestRequestValidator:
    """Tests for RequestValidator middleware."""

    def test_valid_request(self):
        """Test that valid request passes validation."""
        validator = RequestValidator()
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = validator.process(context)

        assert result.success
        assert not result.error

    def test_missing_provider(self):
        """Test that missing provider fails validation."""
        validator = RequestValidator(require_provider=True)
        request = AIRequest(model="gpt-4")
        context = EnforcementContext(request=request)

        result = validator.process(context)

        assert not result.success
        assert "provider" in result.error

    def test_missing_model(self):
        """Test that missing model fails validation."""
        validator = RequestValidator(require_model=True)
        request = AIRequest(provider="openai")
        context = EnforcementContext(request=request)

        result = validator.process(context)

        assert not result.success
        assert "model" in result.error

    def test_custom_validator(self):
        """Test custom validation function."""
        def check_department(ctx):
            if ctx.request and not ctx.request.department:
                return "Department is required"
            return None

        validator = RequestValidator(custom_validators=[check_department])
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = validator.process(context)

        assert not result.success
        assert "Department" in result.error


class TestClassificationEnforcer:
    """Tests for ClassificationEnforcer middleware."""

    def test_classification_not_required(self):
        """Test that classification is optional by default."""
        enforcer = ClassificationEnforcer(require_classification=False)
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = enforcer.process(context)

        assert result.success

    def test_classification_required_missing(self):
        """Test that missing classification fails when required."""
        enforcer = ClassificationEnforcer(require_classification=True)
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = enforcer.process(context)

        assert not result.success
        assert "classification" in result.error.lower()

    def test_classification_provided(self):
        """Test that provided classification passes."""
        enforcer = ClassificationEnforcer(require_classification=True)
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=("public",),
        )
        context = EnforcementContext(request=request)

        result = enforcer.process(context)

        assert result.success

    def test_invalid_classification(self):
        """Test that invalid classification fails."""
        enforcer = ClassificationEnforcer(
            allowed_classifications={"public", "internal"}
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=("secret",),
        )
        context = EnforcementContext(request=request)

        result = enforcer.process(context)

        assert not result.success


class TestRateLimiter:
    """Tests for RateLimiter middleware."""

    def test_rate_limiter_disabled(self):
        """Test that disabled rate limiter passes."""
        limiter = RateLimiter(enabled=False)
        request = AIRequest(provider="openai", model="gpt-4", user_id="user1")
        context = EnforcementContext(request=request)

        result = limiter.process(context)

        assert result.success

    def test_rate_limiter_allows_within_limit(self):
        """Test that requests within limit are allowed."""
        limiter = RateLimiter(
            requests_per_minute=60,
            burst_size=10,
            enabled=True,
        )
        request = AIRequest(provider="openai", model="gpt-4", user_id="user1")
        context = EnforcementContext(request=request)

        # First request should succeed
        result = limiter.process(context)
        assert result.success

    def test_rate_limiter_blocks_excess(self):
        """Test that excess requests are blocked."""
        limiter = RateLimiter(
            requests_per_minute=60,
            burst_size=2,
            enabled=True,
        )
        request = AIRequest(provider="openai", model="gpt-4", user_id="user1")

        # Exhaust the burst
        for _ in range(3):
            context = EnforcementContext(request=request)
            result = limiter.process(context)

        # The third request should fail
        assert not result.success or context.is_short_circuited

    def test_rate_limiter_reset(self):
        """Test resetting rate limiter."""
        limiter = RateLimiter(burst_size=1, enabled=True)
        request = AIRequest(provider="openai", model="gpt-4", user_id="user1")

        context = EnforcementContext(request=request)
        limiter.process(context)

        limiter.reset("user1")

        # Should succeed after reset
        context = EnforcementContext(request=request)
        result = limiter.process(context)
        assert result.success


class TestCostTracker:
    """Tests for CostTracker middleware."""

    def test_cost_tracker_disabled(self):
        """Test that disabled cost tracker passes."""
        tracker = CostTracker(enabled=False)
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user1",
            estimated_cost=100.0,
        )
        context = EnforcementContext(request=request)

        result = tracker.process(context)

        assert result.success

    def test_cost_within_budget(self):
        """Test that costs within budget are allowed."""
        tracker = CostTracker(default_budget=100.0, enabled=True)
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user1",
            estimated_cost=10.0,
        )
        context = EnforcementContext(request=request)

        result = tracker.process(context)

        assert result.success

    def test_cost_exceeds_budget(self):
        """Test that costs exceeding budget are blocked."""
        tracker = CostTracker(default_budget=10.0, enabled=True)
        tracker.set_budget("user:user1", 10.0)

        # Record some spending
        tracker.record_cost("user1", "", 8.0)

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user1",
            estimated_cost=5.0,  # Would exceed budget
        )
        context = EnforcementContext(request=request)

        result = tracker.process(context)

        assert not result.success or context.is_short_circuited


class TestAuditLogger:
    """Tests for AuditLogger middleware."""

    def test_audit_logger_logs(self):
        """Test that audit logger creates logs."""
        logger = AuditLogger()
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)
        context.final_decision = Decision.ALLOW

        result = logger.process(context)

        assert result.success
        logs = logger.get_logs()
        assert len(logs) == 1
        assert logs[0]["decision"] == "ALLOW"

    def test_audit_logger_custom_func(self):
        """Test audit logger with custom function."""
        logged_entries = []

        def log_func(entry):
            logged_entries.append(entry)

        logger = AuditLogger(log_func=log_func)
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        logger.process(context)

        assert len(logged_entries) == 1


class TestActionExecutor:
    """Tests for ActionExecutor."""

    def test_execute_allow_action(self):
        """Test executing ALLOW action."""
        executor = ActionExecutor()
        rule = PolicyRule(
            name="allow-rule",
            action="ALLOW",
        )
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = executor.execute(rule, context)

        assert result.success
        assert result.decision == Decision.ALLOW

    def test_execute_deny_action(self):
        """Test executing DENY action."""
        executor = ActionExecutor()
        rule = PolicyRule(
            name="deny-rule",
            action="DENY",
            action_params={"reason": "Access denied"},
        )
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = executor.execute(rule, context)

        assert result.success
        assert result.decision == Decision.DENY

    def test_execute_modify_action(self):
        """Test executing MODIFY action."""
        executor = ActionExecutor()
        rule = PolicyRule(
            name="modify-rule",
            action="MODIFY",
            action_params={"modifications": {"max_tokens": 1000}},
        )
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = executor.execute(rule, context)

        assert result.success
        assert result.decision == Decision.MODIFY
        assert "max_tokens" in result.modifications

    def test_execute_invalid_action(self):
        """Test executing invalid action."""
        executor = ActionExecutor()
        rule = PolicyRule(
            name="invalid-rule",
            action="INVALID_ACTION",
        )
        request = AIRequest(provider="openai", model="gpt-4")
        context = EnforcementContext(request=request)

        result = executor.execute(rule, context)

        assert not result.success

    def test_pre_and_post_hooks(self):
        """Test pre and post hooks."""
        executor = ActionExecutor()

        pre_called = []
        post_called = []

        def pre_hook(action, ctx, params):
            pre_called.append(action)

        def post_hook(action, ctx, params):
            post_called.append(action)

        executor.add_pre_hook(pre_hook)
        executor.add_post_hook(post_hook)

        rule = PolicyRule(name="test", action="ALLOW")
        context = EnforcementContext(request=AIRequest(provider="openai", model="gpt-4"))

        executor.execute(rule, context)

        assert len(pre_called) == 1
        assert len(post_called) == 1


class TestEnforcementPipeline:
    """Tests for EnforcementPipeline."""

    def test_simple_allow(self):
        """Test pipeline with simple allow rule."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))

        pipeline = EnforcementPipeline(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        response = pipeline.process(request)

        assert response.decision == Decision.ALLOW
        assert response.is_allowed()

    def test_simple_deny(self):
        """Test pipeline with simple deny rule."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="deny-all",
            match_conditions={},
            action="DENY",
            action_params={"reason": "All requests denied"},
        ))

        pipeline = EnforcementPipeline(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        response = pipeline.process(request)

        assert response.decision == Decision.DENY
        assert response.is_denied()

    def test_conditional_matching(self):
        """Test pipeline with conditional matching."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="deny-anthropic",
            match_conditions={"provider": "anthropic"},
            action="DENY",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="allow-openai",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))

        pipeline = EnforcementPipeline(policy_set)

        # OpenAI should be allowed
        response = pipeline.process(AIRequest(provider="openai", model="gpt-4"))
        assert response.decision == Decision.ALLOW

        # Anthropic should be denied
        response = pipeline.process(AIRequest(provider="anthropic", model="claude"))
        assert response.decision == Decision.DENY

    def test_no_matching_rule(self):
        """Test pipeline when no rule matches."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-openai",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))

        pipeline = EnforcementPipeline(policy_set)
        request = AIRequest(provider="anthropic", model="claude")

        response = pipeline.process(request)

        # Default is deny when no rule matches
        assert response.decision == Decision.DENY

    def test_fail_closed(self):
        """Test fail-closed behavior."""
        policy_set = PolicySet(name="test", version="1.0.0")
        config = PipelineConfig(failure_mode=FailureMode.FAIL_CLOSED)

        pipeline = EnforcementPipeline(policy_set, config)
        request = AIRequest(provider="openai", model="gpt-4")

        response = pipeline.process(request)

        # Should deny when no rules
        assert response.decision == Decision.DENY

    def test_with_context(self):
        """Test process_with_context method."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))

        pipeline = EnforcementPipeline(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        response, context = pipeline.process_with_context(request)

        assert response.decision == Decision.ALLOW
        assert context.current_stage == PipelineStage.COMPLETE
        assert len(context.stage_results) > 0

    def test_reload_policies(self):
        """Test reloading policies."""
        policy_set1 = PolicySet(name="test", version="1.0.0")
        policy_set1.add_rule(PolicyRule(
            name="deny-all",
            match_conditions={},
            action="DENY",
        ))

        pipeline = EnforcementPipeline(policy_set1)

        # Should deny
        response = pipeline.process(AIRequest(provider="openai", model="gpt-4"))
        assert response.decision == Decision.DENY

        # Reload with allow policy
        policy_set2 = PolicySet(name="test", version="2.0.0")
        policy_set2.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))
        pipeline.reload_policies(policy_set2)

        # Should now allow
        response = pipeline.process(AIRequest(provider="openai", model="gpt-4"))
        assert response.decision == Decision.ALLOW

    def test_custom_middleware(self):
        """Test adding custom middleware."""

        class CustomMiddleware(Middleware):
            def __init__(self):
                self.processed = False

            @property
            def name(self) -> str:
                return "CustomMiddleware"

            def process(self, context):
                self.processed = True
                return self._success_result()

        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))

        pipeline = EnforcementPipeline(policy_set)
        custom = CustomMiddleware()
        pipeline.add_middleware(custom)

        pipeline.process(AIRequest(provider="openai", model="gpt-4"))

        assert custom.processed

    def test_timing_instrumentation(self):
        """Test that timing is recorded."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="allow-all",
            match_conditions={},
            action="ALLOW",
        ))

        pipeline = EnforcementPipeline(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        response = pipeline.process(request)

        assert response.enforcement_time_ms > 0

    def test_modification_action(self):
        """Test that modifications are recorded."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="modify-request",
            match_conditions={},
            action="MODIFY",
            action_params={"modifications": {"max_tokens": 500}},
        ))

        pipeline = EnforcementPipeline(policy_set)
        request = AIRequest(provider="openai", model="gpt-4")

        response = pipeline.process(request)

        assert response.decision == Decision.MODIFY
        assert "max_tokens" in response.modifications


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
