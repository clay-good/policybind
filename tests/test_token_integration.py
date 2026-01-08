"""
Tests for token middleware and policy integration.

This module tests the TokenAuthMiddleware, TokenBudgetTracker,
TokenCondition, TokenAction, and their integration with the
enforcement pipeline.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock

import pytest

from policybind.engine.conditions import EvaluationContext, Operator
from policybind.engine.context import EnforcementContext, PipelineStage
from policybind.models.base import utc_now
from policybind.models.request import AIRequest, Decision
from policybind.tokens.manager import TokenManager
from policybind.tokens.middleware import (
    BudgetReservation,
    ReservationStatus,
    TokenAuthConfig,
    TokenAuthMiddleware,
    TokenBudgetTracker,
    TokenExtractionMethod,
    TokenUsageRecorder,
)
from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    Token,
    TokenPermissions,
    TokenStatus,
)
from policybind.tokens.policies import (
    TokenAction,
    TokenActionExecutor,
    TokenActionFactory,
    TokenActionType,
    TokenCondition,
    TokenConditionFactory,
    TokenField,
)
from policybind.tokens.validator import TokenValidator


# =============================================================================
# TokenAuthMiddleware Tests
# =============================================================================


class TestTokenAuthMiddleware:
    """Tests for the TokenAuthMiddleware class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    @pytest.fixture
    def validator(self, manager: TokenManager) -> TokenValidator:
        """Create a token validator."""
        return TokenValidator(manager)

    @pytest.fixture
    def token_result(self, manager: TokenManager):
        """Create a test token."""
        return manager.create_token(
            name="test-token",
            subject="test-user",
            permissions=TokenPermissions(
                allowed_models=["gpt-4"],
                budget_limit=100.0,
                budget_period=BudgetPeriod.MONTHLY,
            ),
            expires_in_days=30,
        )

    @pytest.fixture
    def middleware(
        self,
        validator: TokenValidator,
        manager: TokenManager,
    ) -> TokenAuthMiddleware:
        """Create a middleware instance."""
        return TokenAuthMiddleware(
            validator=validator,
            manager=manager,
            config=TokenAuthConfig(
                extraction_method=TokenExtractionMethod.METADATA,
                metadata_key="token",
                require_token=True,
            ),
        )

    def test_process_with_valid_token(
        self,
        middleware: TokenAuthMiddleware,
        token_result,
    ) -> None:
        """Test processing a request with a valid token."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"token": token_result.plaintext_token},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is True
        assert "token" in context.metadata
        assert context.metadata["token"]["subject"] == "test-user"

    def test_process_without_token_required(
        self,
        middleware: TokenAuthMiddleware,
    ) -> None:
        """Test processing a request without token when required."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is False
        assert "Token required" in result.error

    def test_process_without_token_optional(
        self,
        validator: TokenValidator,
        manager: TokenManager,
    ) -> None:
        """Test processing a request without token when optional."""
        middleware = TokenAuthMiddleware(
            validator=validator,
            manager=manager,
            config=TokenAuthConfig(
                require_token=False,
                allow_anonymous=True,
            ),
        )

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is True
        assert result.metadata.get("anonymous") is True

    def test_process_with_invalid_token(
        self,
        middleware: TokenAuthMiddleware,
    ) -> None:
        """Test processing a request with an invalid token."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"token": "invalid_token"},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is False
        assert context.is_short_circuited
        assert context.final_decision == Decision.DENY

    def test_process_with_expired_token(
        self,
        middleware: TokenAuthMiddleware,
        manager: TokenManager,
    ) -> None:
        """Test processing a request with an expired token."""
        # Create an expired token
        result = manager.create_token(
            name="expired-token",
            subject="test-user",
            permissions=TokenPermissions(),
            expires_at=utc_now() - timedelta(days=1),
        )

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"token": result.plaintext_token},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is False
        assert context.is_short_circuited

    def test_process_with_revoked_token(
        self,
        middleware: TokenAuthMiddleware,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test processing a request with a revoked token."""
        manager.revoke_token(token_result.token.token_id, "Test revocation")

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"token": token_result.plaintext_token},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is False
        assert context.is_short_circuited

    def test_process_with_denied_model(
        self,
        middleware: TokenAuthMiddleware,
        manager: TokenManager,
    ) -> None:
        """Test processing a request with a denied model."""
        token_result = manager.create_token(
            name="limited-token",
            subject="test-user",
            permissions=TokenPermissions(
                allowed_models=["gpt-3.5-turbo"],
            ),
            expires_in_days=30,
        )

        request = AIRequest(
            provider="openai",
            model="gpt-4",  # Not allowed
            metadata={"token": token_result.plaintext_token},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is False
        assert context.is_short_circuited

    def test_extract_token_from_header(
        self,
        validator: TokenValidator,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test extracting token from Authorization header."""
        middleware = TokenAuthMiddleware(
            validator=validator,
            manager=manager,
            config=TokenAuthConfig(
                extraction_method=TokenExtractionMethod.HEADER,
                header_name="Authorization",
                require_token=True,
            ),
        )

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={
                "headers": {
                    "Authorization": f"Bearer {token_result.plaintext_token}",
                }
            },
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)

        assert result.success is True


# =============================================================================
# TokenBudgetTracker Tests
# =============================================================================


class TestTokenBudgetTracker:
    """Tests for the TokenBudgetTracker class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    @pytest.fixture
    def token_with_budget(self, manager: TokenManager):
        """Create a token with a budget."""
        return manager.create_token(
            name="budget-token",
            subject="test-user",
            permissions=TokenPermissions(
                budget_limit=100.0,
                budget_period=BudgetPeriod.MONTHLY,
            ),
            expires_in_days=30,
        )

    @pytest.fixture
    def tracker(self, manager: TokenManager) -> TokenBudgetTracker:
        """Create a budget tracker."""
        return TokenBudgetTracker(
            manager=manager,
            reservation_ttl_seconds=300,
        )

    def test_reserve_budget(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test reserving budget."""
        token_id = token_with_budget.token.token_id

        reservation_id = tracker.reserve(token_id=token_id, amount=10.0)

        assert reservation_id is not None
        reservation = tracker.get_reservation(reservation_id)
        assert reservation is not None
        assert reservation.amount == 10.0
        assert reservation.status == ReservationStatus.PENDING

    def test_reserve_exceeds_budget(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test reserving more than available budget."""
        token_id = token_with_budget.token.token_id

        reservation_id = tracker.reserve(token_id=token_id, amount=150.0)

        assert reservation_id is None

    def test_commit_reservation(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test committing a reservation."""
        token_id = token_with_budget.token.token_id

        reservation_id = tracker.reserve(token_id=token_id, amount=10.0)
        assert reservation_id is not None

        success = tracker.commit(reservation_id, actual_amount=8.0)

        assert success is True
        reservation = tracker.get_reservation(reservation_id)
        assert reservation.status == ReservationStatus.COMMITTED
        assert reservation.committed_amount == 8.0

    def test_release_reservation(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test releasing a reservation."""
        token_id = token_with_budget.token.token_id

        reservation_id = tracker.reserve(token_id=token_id, amount=10.0)
        assert reservation_id is not None

        success = tracker.release(reservation_id)

        assert success is True
        reservation = tracker.get_reservation(reservation_id)
        assert reservation.status == ReservationStatus.RELEASED

    def test_get_reserved_amount(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test getting total reserved amount."""
        token_id = token_with_budget.token.token_id

        tracker.reserve(token_id=token_id, amount=10.0)
        tracker.reserve(token_id=token_id, amount=20.0)

        reserved = tracker.get_reserved_amount(token_id)

        assert reserved == 30.0

    def test_get_available_budget(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test getting available budget."""
        token_id = token_with_budget.token.token_id

        tracker.reserve(token_id=token_id, amount=30.0)

        available = tracker.get_available_budget(token_id)

        assert available == 70.0  # 100 - 30

    def test_multiple_reservations(
        self,
        tracker: TokenBudgetTracker,
        token_with_budget,
    ) -> None:
        """Test multiple concurrent reservations."""
        token_id = token_with_budget.token.token_id

        res1 = tracker.reserve(token_id=token_id, amount=30.0)
        res2 = tracker.reserve(token_id=token_id, amount=30.0)
        res3 = tracker.reserve(token_id=token_id, amount=30.0)
        res4 = tracker.reserve(token_id=token_id, amount=30.0)

        # First three should succeed, fourth should fail
        assert res1 is not None
        assert res2 is not None
        assert res3 is not None
        assert res4 is None  # Would exceed budget


# =============================================================================
# TokenCondition Tests
# =============================================================================


class TestTokenCondition:
    """Tests for the TokenCondition class."""

    @pytest.fixture
    def token_context(self) -> EvaluationContext:
        """Create an evaluation context with token data."""
        return EvaluationContext(
            data={},
            metadata={
                "token": {
                    "token_id": "token-123",
                    "subject": "test-user",
                    "subject_type": "user",
                    "issuer": "admin-service",
                    "issued_at": (utc_now() - timedelta(days=15)).isoformat(),
                    "expires_at": (utc_now() + timedelta(days=15)).isoformat(),
                    "remaining_budget": 15.0,
                    "rate_limit_remaining": 5,
                    "permissions": {
                        "allowed_models": ["gpt-4", "gpt-3.5-turbo"],
                        "budget_limit": 100.0,
                        "rate_limit": {"max_requests": 60},
                        "valid_hours": {"start": "09:00", "end": "17:00"},
                    },
                    "warnings": ["Budget low"],
                }
            },
        )

    @pytest.fixture
    def empty_context(self) -> EvaluationContext:
        """Create an evaluation context without token data."""
        return EvaluationContext(data={}, metadata={})

    def test_evaluate_subject_eq(self, token_context: EvaluationContext) -> None:
        """Test evaluating subject equality."""
        condition = TokenCondition(
            field=TokenField.SUBJECT,
            operator=Operator.EQ,
            value="test-user",
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_subject_ne(self, token_context: EvaluationContext) -> None:
        """Test evaluating subject not equal."""
        condition = TokenCondition(
            field=TokenField.SUBJECT,
            operator=Operator.NE,
            value="other-user",
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_issuer_eq(self, token_context: EvaluationContext) -> None:
        """Test evaluating issuer equality."""
        condition = TokenCondition(
            field=TokenField.ISSUER,
            operator=Operator.EQ,
            value="admin-service",
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_token_age_days(self, token_context: EvaluationContext) -> None:
        """Test evaluating token age in days."""
        condition = TokenCondition(
            field=TokenField.TOKEN_AGE_DAYS,
            operator=Operator.GT,
            value=10,
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_days_until_expiry(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating days until expiry."""
        condition = TokenCondition(
            field=TokenField.DAYS_UNTIL_EXPIRY,
            operator=Operator.LT,
            value=30,
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_remaining_budget(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating remaining budget."""
        condition = TokenCondition(
            field=TokenField.REMAINING_BUDGET,
            operator=Operator.LT,
            value=50.0,
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_remaining_budget_percent(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating remaining budget percentage."""
        condition = TokenCondition(
            field=TokenField.REMAINING_BUDGET_PERCENT,
            operator=Operator.LT,
            value=40.0,  # 30% remaining
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_allowed_models_contains(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating allowed models contains."""
        condition = TokenCondition(
            field=TokenField.ALLOWED_MODELS,
            operator=Operator.CONTAINS,
            value="gpt-4",
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_is_near_budget_limit(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating is_near_budget_limit."""
        condition = TokenCondition(
            field=TokenField.IS_NEAR_BUDGET_LIMIT,
            operator=Operator.EQ,
            value=True,
        )
        assert condition.evaluate(token_context) is True  # 15% remaining < 20%

    def test_evaluate_has_time_restrictions(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating has_time_restrictions."""
        condition = TokenCondition(
            field=TokenField.HAS_TIME_RESTRICTIONS,
            operator=Operator.EQ,
            value=True,
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_warnings_contains(
        self, token_context: EvaluationContext
    ) -> None:
        """Test evaluating warnings contains."""
        condition = TokenCondition(
            field=TokenField.WARNINGS,
            operator=Operator.CONTAINS,
            value="Budget low",
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_without_token_data(
        self, empty_context: EvaluationContext
    ) -> None:
        """Test evaluating without token data returns False."""
        condition = TokenCondition(
            field=TokenField.SUBJECT,
            operator=Operator.EQ,
            value="test-user",
        )
        assert condition.evaluate(empty_context) is False

    def test_evaluate_exists(self, token_context: EvaluationContext) -> None:
        """Test evaluating field exists."""
        condition = TokenCondition(
            field=TokenField.SUBJECT,
            operator=Operator.EXISTS,
            value=True,
        )
        assert condition.evaluate(token_context) is True

    def test_evaluate_not_exists(self, token_context: EvaluationContext) -> None:
        """Test evaluating field not exists."""
        condition = TokenCondition(
            field=TokenField.TOTAL_REQUESTS,
            operator=Operator.NOT_EXISTS,
            value=True,
        )
        assert condition.evaluate(token_context) is True

    def test_describe(self) -> None:
        """Test condition description."""
        condition = TokenCondition(
            field=TokenField.REMAINING_BUDGET_PERCENT,
            operator=Operator.LT,
            value=20.0,
        )
        description = condition.describe()
        assert "remaining_budget_percent" in description.lower()
        assert "lt" in description


# =============================================================================
# TokenConditionFactory Tests
# =============================================================================


class TestTokenConditionFactory:
    """Tests for the TokenConditionFactory class."""

    @pytest.fixture
    def factory(self) -> TokenConditionFactory:
        """Create a factory instance."""
        return TokenConditionFactory()

    def test_create_from_config(self, factory: TokenConditionFactory) -> None:
        """Test creating condition from config."""
        condition = factory.create("remaining_budget_percent", {"lt": 20.0})

        assert condition is not None
        assert condition.field == TokenField.REMAINING_BUDGET_PERCENT
        assert condition.operator == Operator.LT
        assert condition.value == 20.0

    def test_create_subject_match(self, factory: TokenConditionFactory) -> None:
        """Test creating subject match condition."""
        condition = factory.create_subject_match("admin")

        assert condition.field == TokenField.SUBJECT
        assert condition.operator == Operator.EQ
        assert condition.value == "admin"

    def test_create_issuer_match(self, factory: TokenConditionFactory) -> None:
        """Test creating issuer match condition."""
        condition = factory.create_issuer_match("auth-service")

        assert condition.field == TokenField.ISSUER
        assert condition.value == "auth-service"

    def test_create_age_check(self, factory: TokenConditionFactory) -> None:
        """Test creating age check condition."""
        condition = factory.create_age_check(30)

        assert condition.field == TokenField.TOKEN_AGE_DAYS
        assert condition.operator == Operator.GT
        assert condition.value == 30

    def test_create_budget_check(self, factory: TokenConditionFactory) -> None:
        """Test creating budget check condition."""
        condition = factory.create_budget_check(20.0)

        assert condition.field == TokenField.REMAINING_BUDGET_PERCENT
        assert condition.operator == Operator.LT
        assert condition.value == 20.0

    def test_create_near_budget_limit(
        self, factory: TokenConditionFactory
    ) -> None:
        """Test creating near budget limit condition."""
        condition = factory.create_near_budget_limit()

        assert condition.field == TokenField.IS_NEAR_BUDGET_LIMIT
        assert condition.value is True

    def test_create_near_rate_limit(
        self, factory: TokenConditionFactory
    ) -> None:
        """Test creating near rate limit condition."""
        condition = factory.create_near_rate_limit()

        assert condition.field == TokenField.IS_NEAR_RATE_LIMIT
        assert condition.value is True

    def test_create_invalid_field(self, factory: TokenConditionFactory) -> None:
        """Test creating with invalid field returns None."""
        condition = factory.create("invalid_field", {"eq": "value"})
        assert condition is None


# =============================================================================
# TokenAction Tests
# =============================================================================


class TestTokenActionExecutor:
    """Tests for the TokenActionExecutor class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    @pytest.fixture
    def token_result(self, manager: TokenManager):
        """Create a test token."""
        return manager.create_token(
            name="test-token",
            subject="test-user",
            permissions=TokenPermissions(
                budget_limit=100.0,
                rate_limit=RateLimit(max_requests=60, period_seconds=60),
            ),
            expires_in_days=30,
        )

    @pytest.fixture
    def executor(self, manager: TokenManager) -> TokenActionExecutor:
        """Create an action executor."""
        return TokenActionExecutor(manager=manager)

    def test_execute_revoke(
        self,
        executor: TokenActionExecutor,
        token_result,
    ) -> None:
        """Test executing revoke action."""
        action = TokenAction(
            action_type=TokenActionType.REVOKE,
            params={"reason": "Policy violation"},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert result.action_type == TokenActionType.REVOKE
        assert result.details["reason"] == "Policy violation"

    def test_execute_suspend(
        self,
        executor: TokenActionExecutor,
        token_result,
    ) -> None:
        """Test executing suspend action."""
        action = TokenAction(
            action_type=TokenActionType.SUSPEND,
            params={"reason": "Suspicious activity"},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert result.action_type == TokenActionType.SUSPEND

    def test_execute_reduce_budget(
        self,
        executor: TokenActionExecutor,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test executing reduce budget action."""
        action = TokenAction(
            action_type=TokenActionType.REDUCE_BUDGET,
            params={"new_limit": 50.0},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert result.details["old_limit"] == 100.0
        assert result.details["new_limit"] == 50.0

        # Verify the token was updated
        token = manager.get_token(token_result.token.token_id)
        assert token.permissions.budget_limit == 50.0

    def test_execute_reduce_budget_by_percent(
        self,
        executor: TokenActionExecutor,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test executing reduce budget by percentage."""
        action = TokenAction(
            action_type=TokenActionType.REDUCE_BUDGET,
            params={"reduction_percent": 25.0},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert result.details["new_limit"] == 75.0  # 100 - 25%

    def test_execute_reduce_rate_limit(
        self,
        executor: TokenActionExecutor,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test executing reduce rate limit action."""
        action = TokenAction(
            action_type=TokenActionType.REDUCE_RATE_LIMIT,
            params={"new_limit": 30},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert result.details["old_limit"] == 60
        assert result.details["new_limit"] == 30

    def test_execute_add_restriction(
        self,
        executor: TokenActionExecutor,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test executing add restriction action."""
        action = TokenAction(
            action_type=TokenActionType.ADD_RESTRICTION,
            params={
                "type": "denied_models",
                "value": "gpt-4-32k",
            },
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True

        token = manager.get_token(token_result.token.token_id)
        assert "gpt-4-32k" in token.permissions.denied_models

    def test_execute_notify_owner_no_notifier(
        self,
        executor: TokenActionExecutor,
        token_result,
    ) -> None:
        """Test notify action without notifier returns error."""
        action = TokenAction(
            action_type=TokenActionType.NOTIFY_OWNER,
            params={"message": "Budget warning"},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is False
        assert "No notifier" in result.error

    def test_execute_notify_owner_with_notifier(
        self,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test notify action with notifier."""
        notifications = []

        def notifier(subject, message, context):
            notifications.append((subject, message, context))

        executor = TokenActionExecutor(manager=manager, notifier=notifier)

        action = TokenAction(
            action_type=TokenActionType.NOTIFY_OWNER,
            params={"message": "Budget warning", "severity": "warning"},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert len(notifications) == 1
        assert notifications[0][0] == "test-user"
        assert notifications[0][1] == "Budget warning"

    def test_execute_extend_expiry(
        self,
        executor: TokenActionExecutor,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test executing extend expiry action."""
        original_expiry = token_result.token.expires_at

        action = TokenAction(
            action_type=TokenActionType.EXTEND_EXPIRY,
            params={"days": 15, "hours": 12},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True

        token = manager.get_token(token_result.token.token_id)
        assert token.expires_at > original_expiry

    def test_execute_refresh(
        self,
        executor: TokenActionExecutor,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test executing refresh action."""
        action = TokenAction(
            action_type=TokenActionType.REFRESH,
            params={"expiry_days": 60},
        )

        result = executor.execute(token_result.token.token_id, action)

        assert result.success is True
        assert result.details["expiry_days"] == 60

    def test_execute_on_nonexistent_token(
        self,
        executor: TokenActionExecutor,
    ) -> None:
        """Test executing action on nonexistent token."""
        action = TokenAction(
            action_type=TokenActionType.REVOKE,
            params={"reason": "Test"},
        )

        result = executor.execute("nonexistent-token", action)

        assert result.success is False
        assert "not found" in result.error.lower() or "Failed" in result.error


# =============================================================================
# TokenActionFactory Tests
# =============================================================================


class TestTokenActionFactory:
    """Tests for the TokenActionFactory class."""

    @pytest.fixture
    def factory(self) -> TokenActionFactory:
        """Create a factory instance."""
        return TokenActionFactory()

    def test_create_from_type(self, factory: TokenActionFactory) -> None:
        """Test creating action from type."""
        action = factory.create("revoke", {"reason": "Test"})

        assert action is not None
        assert action.action_type == TokenActionType.REVOKE
        assert action.params["reason"] == "Test"

    def test_create_revoke(self, factory: TokenActionFactory) -> None:
        """Test creating revoke action."""
        action = factory.create_revoke("Violation detected")

        assert action.action_type == TokenActionType.REVOKE
        assert action.params["reason"] == "Violation detected"

    def test_create_suspend(self, factory: TokenActionFactory) -> None:
        """Test creating suspend action."""
        action = factory.create_suspend("Investigation", duration_hours=48)

        assert action.action_type == TokenActionType.SUSPEND
        assert action.params["duration_hours"] == 48

    def test_create_reduce_budget(self, factory: TokenActionFactory) -> None:
        """Test creating reduce budget action."""
        action = factory.create_reduce_budget(new_limit=50.0)

        assert action.action_type == TokenActionType.REDUCE_BUDGET
        assert action.params["new_limit"] == 50.0

    def test_create_notify(self, factory: TokenActionFactory) -> None:
        """Test creating notify action."""
        action = factory.create_notify("Budget warning", severity="warning")

        assert action.action_type == TokenActionType.NOTIFY_OWNER
        assert action.params["message"] == "Budget warning"
        assert action.params["severity"] == "warning"

    def test_create_invalid_type(self, factory: TokenActionFactory) -> None:
        """Test creating with invalid type returns None."""
        action = factory.create("invalid_action", {})
        assert action is None


# =============================================================================
# TokenUsageRecorder Tests
# =============================================================================


class TestTokenUsageRecorder:
    """Tests for the TokenUsageRecorder class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    @pytest.fixture
    def token_result(self, manager: TokenManager):
        """Create a test token."""
        return manager.create_token(
            name="test-token",
            subject="test-user",
            permissions=TokenPermissions(
                budget_limit=100.0,
            ),
            expires_in_days=30,
        )

    @pytest.fixture
    def recorder(self, manager: TokenManager) -> TokenUsageRecorder:
        """Create a usage recorder."""
        return TokenUsageRecorder(manager=manager)

    def test_record_usage_allowed(
        self,
        recorder: TokenUsageRecorder,
        manager: TokenManager,
        token_result,
    ) -> None:
        """Test recording usage for allowed request."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            estimated_cost=5.0,
        )
        context = EnforcementContext(
            request=request,
            final_decision=Decision.ALLOW,
        )
        context.metadata["token"] = {
            "token_id": token_result.token.token_id,
        }

        result = recorder.process(context)

        assert result.success is True
        assert result.metadata["actual_cost"] == 5.0
        assert result.metadata["success"] is True

    def test_record_usage_denied(
        self,
        recorder: TokenUsageRecorder,
        token_result,
    ) -> None:
        """Test recording usage for denied request."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            estimated_cost=5.0,
        )
        context = EnforcementContext(
            request=request,
            final_decision=Decision.DENY,
        )
        context.metadata["token"] = {
            "token_id": token_result.token.token_id,
        }

        result = recorder.process(context)

        assert result.success is True
        assert result.metadata["success"] is False

    def test_record_usage_no_token(
        self,
        recorder: TokenUsageRecorder,
    ) -> None:
        """Test recording with no token in context."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
        )
        context = EnforcementContext(
            request=request,
            final_decision=Decision.ALLOW,
        )

        result = recorder.process(context)

        assert result.success is True


# =============================================================================
# Integration Tests
# =============================================================================


class TestTokenPolicyIntegration:
    """Integration tests for token middleware and policies."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    @pytest.fixture
    def validator(self, manager: TokenManager) -> TokenValidator:
        """Create a token validator."""
        return TokenValidator(manager)

    def test_full_flow(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test the full flow from authentication to condition to action."""
        # Step 1: Create a token with limited budget
        token_result = manager.create_token(
            name="limited-token",
            subject="developer@example.com",
            permissions=TokenPermissions(
                allowed_models=["gpt-4"],
                budget_limit=100.0,
            ),
            issuer="admin-service",
            expires_in_days=30,
        )

        # Step 2: Authenticate via middleware
        middleware = TokenAuthMiddleware(
            validator=validator,
            manager=manager,
            config=TokenAuthConfig(require_token=True),
        )

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            estimated_cost=10.0,
            metadata={"token": token_result.plaintext_token},
        )
        context = EnforcementContext(request=request)

        result = middleware.process(context)
        assert result.success is True
        assert "token" in context.metadata

        # Step 3: Evaluate conditions against enriched context
        eval_context = EvaluationContext(
            data={},
            metadata=context.metadata,
        )

        # Check issuer
        issuer_condition = TokenCondition(
            field=TokenField.ISSUER,
            operator=Operator.EQ,
            value="admin-service",
        )
        assert issuer_condition.evaluate(eval_context) is True

        # Check subject type
        subject_condition = TokenCondition(
            field=TokenField.SUBJECT,
            operator=Operator.EQ,
            value="developer@example.com",
        )
        assert subject_condition.evaluate(eval_context) is True

        # Step 4: Execute actions based on conditions
        executor = TokenActionExecutor(manager=manager)

        # Simulate budget running low - reduce further
        reduce_action = TokenAction(
            action_type=TokenActionType.REDUCE_BUDGET,
            params={"new_limit": 50.0},
        )
        action_result = executor.execute(
            token_result.token.token_id,
            reduce_action,
        )
        assert action_result.success is True

        # Verify budget was reduced
        token = manager.get_token(token_result.token.token_id)
        assert token.permissions.budget_limit == 50.0

    def test_factory_created_conditions_and_actions(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test conditions and actions created via factories."""
        # Create token
        token_result = manager.create_token(
            name="test-token",
            subject="user@example.com",
            permissions=TokenPermissions(budget_limit=100.0),
            expires_in_days=30,
        )

        # Authenticate
        middleware = TokenAuthMiddleware(
            validator=validator,
            manager=manager,
            config=TokenAuthConfig(require_token=True),
        )

        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"token": token_result.plaintext_token},
        )
        context = EnforcementContext(request=request)
        middleware.process(context)

        # Use factories to create conditions
        condition_factory = TokenConditionFactory()
        action_factory = TokenActionFactory()

        # Create condition using factory
        subject_condition = condition_factory.create("subject", {"eq": "user@example.com"})
        assert subject_condition is not None

        eval_context = EvaluationContext(data={}, metadata=context.metadata)
        assert subject_condition.evaluate(eval_context) is True

        # Create action using factory
        notify_action = action_factory.create("notify", {
            "message": "Token usage recorded",
            "severity": "info",
        })
        assert notify_action is not None
        assert notify_action.action_type == TokenActionType.NOTIFY_OWNER
