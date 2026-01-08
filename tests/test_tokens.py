"""
Tests for the token management system.

This module tests the TokenManager, TokenValidator, and related
models for access token management and validation.
"""

from datetime import datetime, time, timedelta, timezone

import pytest

from policybind.models.request import AIRequest
from policybind.tokens.manager import TokenEvent, TokenManager
from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    TimeWindow,
    Token,
    TokenCreationResult,
    TokenPermissions,
    TokenStatus,
    TokenUsageStats,
)
from policybind.tokens.validator import (
    TokenValidator,
    ValidationFailureReason,
    ValidationResult,
)


# =============================================================================
# TokenPermissions Tests
# =============================================================================


class TestTokenPermissions:
    """Tests for the TokenPermissions class."""

    def test_create_default_permissions(self) -> None:
        """Test creating default permissions."""
        permissions = TokenPermissions()

        assert permissions.allowed_models == []
        assert permissions.denied_models == []
        assert permissions.budget_limit is None
        assert permissions.rate_limit is None

    def test_create_with_model_restrictions(self) -> None:
        """Test creating permissions with model restrictions."""
        permissions = TokenPermissions(
            allowed_models=["gpt-4", "gpt-3.5-turbo"],
            denied_models=["gpt-4-32k"],
        )

        assert "gpt-4" in permissions.allowed_models
        assert "gpt-4-32k" in permissions.denied_models

    def test_create_with_budget(self) -> None:
        """Test creating permissions with budget constraints."""
        permissions = TokenPermissions(
            budget_limit=100.0,
            budget_period=BudgetPeriod.MONTHLY,
            budget_currency="USD",
        )

        assert permissions.budget_limit == 100.0
        assert permissions.budget_period == BudgetPeriod.MONTHLY
        assert permissions.budget_currency == "USD"

    def test_create_with_rate_limit(self) -> None:
        """Test creating permissions with rate limit."""
        permissions = TokenPermissions(
            rate_limit=RateLimit(max_requests=100, period_seconds=60),
        )

        assert permissions.rate_limit is not None
        assert permissions.rate_limit.max_requests == 100

    def test_create_with_time_window(self) -> None:
        """Test creating permissions with time window."""
        permissions = TokenPermissions(
            valid_hours=TimeWindow(
                start=time(9, 0),
                end=time(17, 0),
                days_of_week=(0, 1, 2, 3, 4),
            ),
        )

        assert permissions.valid_hours is not None
        assert permissions.valid_hours.start == time(9, 0)
        assert permissions.valid_hours.end == time(17, 0)

    def test_to_dict_and_from_dict(self) -> None:
        """Test serialization round-trip."""
        permissions = TokenPermissions(
            allowed_models=["gpt-4"],
            denied_use_cases=["harmful"],
            budget_limit=50.0,
            budget_period=BudgetPeriod.WEEKLY,
            rate_limit=RateLimit.per_minute(10),
            valid_hours=TimeWindow.business_hours(),
            max_tokens_per_request=4000,
            custom_constraints={"department": "engineering"},
        )

        data = permissions.to_dict()
        restored = TokenPermissions.from_dict(data)

        assert restored.allowed_models == permissions.allowed_models
        assert restored.denied_use_cases == permissions.denied_use_cases
        assert restored.budget_limit == permissions.budget_limit
        assert restored.rate_limit is not None
        assert restored.rate_limit.max_requests == 10

    def test_unrestricted_factory(self) -> None:
        """Test unrestricted permissions factory."""
        permissions = TokenPermissions.unrestricted()

        assert permissions.allowed_models == []
        assert permissions.budget_limit is None

    def test_read_only_factory(self) -> None:
        """Test read-only permissions factory."""
        permissions = TokenPermissions.read_only()

        assert "generation" in permissions.denied_use_cases
        assert "embedding" in permissions.allowed_use_cases


# =============================================================================
# Token Tests
# =============================================================================


class TestToken:
    """Tests for the Token class."""

    def test_create_token(self) -> None:
        """Test creating a token."""
        token = Token(
            name="test-token",
            subject="user@example.com",
            issuer="system",
        )

        assert token.token_id is not None
        assert token.name == "test-token"
        assert token.subject == "user@example.com"
        assert token.status == TokenStatus.ACTIVE

    def test_is_expired_with_future_date(self) -> None:
        """Test is_expired with future expiration."""
        token = Token(
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        assert token.is_expired() is False

    def test_is_expired_with_past_date(self) -> None:
        """Test is_expired with past expiration."""
        token = Token(
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        assert token.is_expired() is True

    def test_is_expired_with_no_expiration(self) -> None:
        """Test is_expired with no expiration date."""
        token = Token()

        assert token.is_expired() is False

    def test_is_active(self) -> None:
        """Test is_active method."""
        active_token = Token(
            status=TokenStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        revoked_token = Token(status=TokenStatus.REVOKED)
        expired_token = Token(
            status=TokenStatus.ACTIVE,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )

        assert active_token.is_active() is True
        assert revoked_token.is_active() is False
        assert expired_token.is_active() is False

    def test_time_until_expiry(self) -> None:
        """Test time_until_expiry method."""
        token_with_expiry = Token(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        token_without_expiry = Token()
        expired_token = Token(
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

        assert token_with_expiry.time_until_expiry() is not None
        assert token_with_expiry.time_until_expiry() > 0
        assert token_without_expiry.time_until_expiry() is None
        assert expired_token.time_until_expiry() == 0.0

    def test_to_dict_and_from_dict(self) -> None:
        """Test serialization round-trip."""
        token = Token(
            name="test",
            subject="user",
            permissions=TokenPermissions(allowed_models=["gpt-4"]),
            tags=["test", "dev"],
            metadata={"key": "value"},
        )

        data = token.to_dict()
        restored = Token.from_dict(data)

        assert restored.name == token.name
        assert restored.subject == token.subject
        assert restored.permissions.allowed_models == ["gpt-4"]
        assert "test" in restored.tags


# =============================================================================
# RateLimit Tests
# =============================================================================


class TestRateLimit:
    """Tests for the RateLimit class."""

    def test_per_minute_factory(self) -> None:
        """Test per_minute factory."""
        limit = RateLimit.per_minute(100)

        assert limit.max_requests == 100
        assert limit.period_seconds == 60

    def test_per_hour_factory(self) -> None:
        """Test per_hour factory."""
        limit = RateLimit.per_hour(1000)

        assert limit.max_requests == 1000
        assert limit.period_seconds == 3600

    def test_per_day_factory(self) -> None:
        """Test per_day factory."""
        limit = RateLimit.per_day(10000)

        assert limit.max_requests == 10000
        assert limit.period_seconds == 86400


# =============================================================================
# TimeWindow Tests
# =============================================================================


class TestTimeWindow:
    """Tests for the TimeWindow class."""

    def test_business_hours_factory(self) -> None:
        """Test business_hours factory."""
        window = TimeWindow.business_hours()

        assert window.start == time(9, 0)
        assert window.end == time(17, 0)
        assert window.days_of_week == (0, 1, 2, 3, 4)  # Mon-Fri

    def test_to_dict_and_from_dict(self) -> None:
        """Test serialization round-trip."""
        window = TimeWindow(
            start=time(8, 30),
            end=time(18, 0),
            timezone="UTC",
            days_of_week=(1, 2, 3),
        )

        data = window.to_dict()
        restored = TimeWindow.from_dict(data)

        assert restored.start == window.start
        assert restored.end == window.end
        assert restored.days_of_week == window.days_of_week


# =============================================================================
# TokenManager Tests
# =============================================================================


class TestTokenManager:
    """Tests for the TokenManager class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager for testing."""
        return TokenManager()

    def test_create_token(self, manager: TokenManager) -> None:
        """Test creating a token."""
        result = manager.create_token(
            name="test-token",
            subject="user@example.com",
            issuer="test",
        )

        assert isinstance(result, TokenCreationResult)
        assert result.token.name == "test-token"
        assert result.plaintext_token.startswith("pb_")

    def test_create_token_with_permissions(self, manager: TokenManager) -> None:
        """Test creating a token with permissions."""
        permissions = TokenPermissions(
            allowed_models=["gpt-4"],
            budget_limit=100.0,
        )

        result = manager.create_token(
            name="restricted-token",
            subject="user@example.com",
            permissions=permissions,
        )

        assert result.token.permissions.allowed_models == ["gpt-4"]
        assert result.token.permissions.budget_limit == 100.0

    def test_create_token_with_expiration(self, manager: TokenManager) -> None:
        """Test creating a token with expiration."""
        result = manager.create_token(
            name="expiring-token",
            subject="user@example.com",
            expires_in_days=30,
        )

        assert result.token.expires_at is not None
        assert result.token.is_expired() is False

    def test_create_token_requires_name(self, manager: TokenManager) -> None:
        """Test that token creation requires a name."""
        from policybind.exceptions import TokenError

        with pytest.raises(TokenError, match="name is required"):
            manager.create_token(name="", subject="user@example.com")

    def test_create_token_requires_subject(self, manager: TokenManager) -> None:
        """Test that token creation requires a subject."""
        from policybind.exceptions import TokenError

        with pytest.raises(TokenError, match="subject is required"):
            manager.create_token(name="test", subject="")

    def test_get_token_by_id(self, manager: TokenManager) -> None:
        """Test getting a token by ID."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        token = manager.get_token(result.token.token_id)

        assert token is not None
        assert token.token_id == result.token.token_id

    def test_get_token_by_value(self, manager: TokenManager) -> None:
        """Test getting a token by plaintext value."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        token = manager.get_token_by_value(result.plaintext_token)

        assert token is not None
        assert token.token_id == result.token.token_id

    def test_validate_token(self, manager: TokenManager) -> None:
        """Test validating a token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            expires_in_days=30,
        )

        token = manager.validate_token(result.plaintext_token)

        assert token is not None
        assert token.is_active()

    def test_validate_invalid_token(self, manager: TokenManager) -> None:
        """Test validating an invalid token."""
        token = manager.validate_token("pb_invalid_token_value")

        assert token is None

    def test_revoke_token(self, manager: TokenManager) -> None:
        """Test revoking a token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        success = manager.revoke_token(
            result.token.token_id,
            revoked_by="admin",
            reason="No longer needed",
        )

        assert success is True
        token = manager.get_token(result.token.token_id)
        assert token is not None
        assert token.status == TokenStatus.REVOKED
        assert token.revoked_by == "admin"

    def test_revoke_tokens_for_subject(self, manager: TokenManager) -> None:
        """Test revoking all tokens for a subject."""
        for i in range(3):
            manager.create_token(
                name=f"token-{i}",
                subject="user@example.com",
            )
        manager.create_token(
            name="other-token",
            subject="other@example.com",
        )

        count = manager.revoke_tokens_for_subject(
            "user@example.com",
            revoked_by="admin",
        )

        assert count == 3
        tokens = manager.list_tokens(subject="user@example.com", include_expired=True)
        assert all(t.status == TokenStatus.REVOKED for t in tokens)

    def test_suspend_token(self, manager: TokenManager) -> None:
        """Test suspending a token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        success = manager.suspend_token(
            result.token.token_id,
            suspended_by="admin",
            reason="Investigation",
        )

        assert success is True
        token = manager.get_token(result.token.token_id)
        assert token is not None
        assert token.status == TokenStatus.SUSPENDED

    def test_unsuspend_token(self, manager: TokenManager) -> None:
        """Test unsuspending a token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )
        manager.suspend_token(result.token.token_id, suspended_by="admin")

        success = manager.unsuspend_token(
            result.token.token_id,
            unsuspended_by="admin",
        )

        assert success is True
        token = manager.get_token(result.token.token_id)
        assert token is not None
        assert token.status == TokenStatus.ACTIVE

    def test_record_usage(self, manager: TokenManager) -> None:
        """Test recording token usage."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        stats = manager.record_usage(
            result.token.token_id,
            tokens_used=100,
            cost=0.01,
        )

        assert stats is not None
        assert stats.total_requests == 1
        assert stats.total_tokens_used == 100
        assert stats.total_cost == 0.01

    def test_record_multiple_usage(self, manager: TokenManager) -> None:
        """Test recording multiple usages."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        for i in range(5):
            manager.record_usage(
                result.token.token_id,
                tokens_used=100,
                cost=0.01,
            )

        stats = manager.get_usage_stats(result.token.token_id)

        assert stats is not None
        assert stats.total_requests == 5
        assert stats.total_tokens_used == 500
        assert stats.total_cost == pytest.approx(0.05)

    def test_get_remaining_budget(self, manager: TokenManager) -> None:
        """Test getting remaining budget."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(budget_limit=100.0),
        )

        manager.record_usage(result.token.token_id, cost=25.0)

        remaining = manager.get_remaining_budget(result.token.token_id)

        assert remaining == pytest.approx(75.0)

    def test_is_rate_limited(self, manager: TokenManager) -> None:
        """Test rate limiting check."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(
                rate_limit=RateLimit(max_requests=3, period_seconds=60),
            ),
        )

        # Make requests up to the limit
        for _ in range(3):
            manager.record_usage(result.token.token_id)

        assert manager.is_rate_limited(result.token.token_id) is True

    def test_renew_token(self, manager: TokenManager) -> None:
        """Test renewing a token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            expires_in_days=1,
        )

        renewed = manager.renew_token(
            result.token.token_id,
            renewed_by="admin",
            expires_in_days=30,
        )

        assert renewed is not None
        assert renewed.time_until_expiry() > 86400 * 29  # More than 29 days

    def test_update_permissions(self, manager: TokenManager) -> None:
        """Test updating token permissions."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )

        new_permissions = TokenPermissions(
            allowed_models=["gpt-4"],
            budget_limit=50.0,
        )

        updated = manager.update_permissions(
            result.token.token_id,
            new_permissions,
            updated_by="admin",
        )

        assert updated is not None
        assert updated.permissions.allowed_models == ["gpt-4"]
        assert updated.permissions.budget_limit == 50.0

    def test_list_tokens(self, manager: TokenManager) -> None:
        """Test listing tokens with filters."""
        manager.create_token(name="token-1", subject="user1@example.com", tags=["dev"])
        manager.create_token(name="token-2", subject="user1@example.com", tags=["prod"])
        manager.create_token(name="token-3", subject="user2@example.com", tags=["dev"])

        # Filter by subject
        user1_tokens = manager.list_tokens(subject="user1@example.com")
        assert len(user1_tokens) == 2

        # Filter by tags
        dev_tokens = manager.list_tokens(tags=["dev"])
        assert len(dev_tokens) == 2

    def test_get_statistics(self, manager: TokenManager) -> None:
        """Test getting token statistics."""
        result = manager.create_token(name="test", subject="user@example.com")
        manager.record_usage(result.token.token_id, cost=10.0)

        stats = manager.get_statistics()

        assert stats["total_tokens"] == 1
        assert stats["active_tokens"] == 1
        assert stats["total_requests"] == 1
        assert stats["total_cost"] == 10.0

    def test_token_event_callback(self, manager: TokenManager) -> None:
        """Test token event callbacks."""
        events: list[TokenEvent] = []

        def callback(event: TokenEvent) -> None:
            events.append(event)

        manager.on_token_event(callback)

        result = manager.create_token(name="test", subject="user@example.com")
        manager.revoke_token(result.token.token_id, revoked_by="admin")

        assert len(events) == 2
        assert events[0].event_type == "created"
        assert events[1].event_type == "revoked"

    def test_get_events(self, manager: TokenManager) -> None:
        """Test getting token events."""
        result = manager.create_token(name="test", subject="user@example.com")
        manager.revoke_token(result.token.token_id, revoked_by="admin")

        events = manager.get_events(token_id=result.token.token_id)

        assert len(events) == 2

    def test_delete_token(self, manager: TokenManager) -> None:
        """Test permanently deleting a token."""
        result = manager.create_token(name="test", subject="user@example.com")

        success = manager.delete_token(result.token.token_id)

        assert success is True
        assert manager.get_token(result.token.token_id) is None


# =============================================================================
# TokenValidator Tests
# =============================================================================


class TestTokenValidator:
    """Tests for the TokenValidator class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager for testing."""
        return TokenManager()

    @pytest.fixture
    def validator(self, manager: TokenManager) -> TokenValidator:
        """Create a validator for testing."""
        return TokenValidator(manager, enable_cache=False)

    def test_validate_valid_token(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a valid token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            expires_in_days=30,
        )

        validation = validator.validate_token(result.plaintext_token)

        assert validation.valid is True
        assert validation.token is not None

    def test_validate_invalid_token(self, validator: TokenValidator) -> None:
        """Test validating an invalid token."""
        validation = validator.validate_token("pb_nonexistent_token")

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.TOKEN_NOT_FOUND

    def test_validate_invalid_format(self, validator: TokenValidator) -> None:
        """Test validating a token with invalid format."""
        validation = validator.validate_token("invalid_format")

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.INVALID_TOKEN_FORMAT

    def test_validate_expired_token(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating an expired token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

        validation = validator.validate_token(result.plaintext_token)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.TOKEN_EXPIRED

    def test_validate_revoked_token(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a revoked token."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )
        manager.revoke_token(result.token.token_id, revoked_by="admin")

        validation = validator.validate_token(result.plaintext_token)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.TOKEN_REVOKED

    def test_validate_request_allowed_model(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request with allowed model."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(allowed_models=["gpt-4", "gpt-3.5*"]),
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is True

    def test_validate_request_denied_model(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request with denied model."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(allowed_models=["gpt-3.5-turbo"]),
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.MODEL_NOT_ALLOWED

    def test_validate_request_pattern_matching(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test pattern matching for models."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(allowed_models=["gpt-*"]),
        )

        gpt4_request = AIRequest(provider="openai", model="gpt-4")
        claude_request = AIRequest(provider="anthropic", model="claude-3")

        assert validator.validate_request(result.plaintext_token, gpt4_request).valid
        assert not validator.validate_request(result.plaintext_token, claude_request).valid

    def test_validate_request_denied_provider(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request with denied provider."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(denied_providers=["anthropic"]),
        )
        request = AIRequest(
            provider="anthropic",
            model="claude-3",
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.PROVIDER_NOT_ALLOWED

    def test_validate_request_denied_use_case(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request with denied use case."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(denied_use_cases=["harmful*"]),
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            intended_use_case="harmful-content",
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.USE_CASE_NOT_ALLOWED

    def test_validate_request_denied_data_classification(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request with denied data classification."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(denied_data_classifications=["pii", "phi"]),
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=["pii"],
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert (
            validation.failure_reason
            == ValidationFailureReason.DATA_CLASSIFICATION_NOT_ALLOWED
        )

    def test_validate_request_invalid_source(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request from invalid source."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(valid_sources=["app-1", "app-2"]),
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            source_application="app-3",
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.SOURCE_NOT_ALLOWED

    def test_validate_request_budget_exceeded(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request that exceeds budget."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(budget_limit=10.0),
        )
        # Exhaust most of the budget
        manager.record_usage(result.token.token_id, cost=9.0)

        request = AIRequest(provider="openai", model="gpt-4")

        validation = validator.validate_request(
            result.plaintext_token,
            request,
            estimated_cost=5.0,
        )

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.BUDGET_EXCEEDED

    def test_validate_request_rate_limited(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request when rate limited."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(
                rate_limit=RateLimit(max_requests=2, period_seconds=60),
            ),
        )

        # Exhaust rate limit
        manager.record_usage(result.token.token_id)
        manager.record_usage(result.token.token_id)

        request = AIRequest(provider="openai", model="gpt-4")

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.RATE_LIMITED

    def test_validate_request_max_tokens_exceeded(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request that exceeds max tokens."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(max_tokens_per_request=1000),
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            estimated_tokens=2000,
        )

        validation = validator.validate_request(result.plaintext_token, request)

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.MAX_TOKENS_EXCEEDED

    def test_validate_request_approval_required(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test validating a request that requires approval."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(require_approval_above=10.0),
        )
        request = AIRequest(provider="openai", model="gpt-4")

        validation = validator.validate_request(
            result.plaintext_token,
            request,
            estimated_cost=15.0,
        )

        assert validation.valid is False
        assert validation.failure_reason == ValidationFailureReason.APPROVAL_REQUIRED

    def test_validate_request_returns_remaining_budget(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test that validation returns remaining budget."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(budget_limit=100.0),
        )
        manager.record_usage(result.token.token_id, cost=25.0)

        request = AIRequest(provider="openai", model="gpt-4")

        validation = validator.validate_request(
            result.plaintext_token,
            request,
            estimated_cost=5.0,
        )

        assert validation.valid is True
        assert validation.remaining_budget == pytest.approx(75.0)

    def test_validate_request_returns_warnings(
        self,
        manager: TokenManager,
        validator: TokenValidator,
    ) -> None:
        """Test that validation returns warnings for low budget."""
        result = manager.create_token(
            name="test",
            subject="user@example.com",
            permissions=TokenPermissions(budget_limit=100.0),
        )
        # Use up most of the budget
        manager.record_usage(result.token.token_id, cost=95.0)

        request = AIRequest(provider="openai", model="gpt-4")

        validation = validator.validate_request(
            result.plaintext_token,
            request,
            estimated_cost=1.0,
        )

        assert validation.valid is True
        assert len(validation.warnings) > 0
        assert "low" in validation.warnings[0].lower()

    def test_validation_caching(self, manager: TokenManager) -> None:
        """Test that validation results are cached."""
        validator = TokenValidator(manager, enable_cache=True, cache_ttl_seconds=60)

        result = manager.create_token(
            name="test",
            subject="user@example.com",
        )
        request = AIRequest(provider="openai", model="gpt-4")

        # First validation
        validation1 = validator.validate_request(result.plaintext_token, request)
        assert validation1.valid is True

        # Should use cache
        stats = validator.get_cache_stats()
        assert stats["total_entries"] == 1

        # Clear cache
        validator.clear_cache()
        stats = validator.get_cache_stats()
        assert stats["total_entries"] == 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestTokenIntegration:
    """Integration tests for the token system."""

    def test_full_token_lifecycle(self) -> None:
        """Test the complete token lifecycle."""
        manager = TokenManager()
        validator = TokenValidator(manager)

        # Create token
        creation = manager.create_token(
            name="dev-token",
            subject="developer@example.com",
            permissions=TokenPermissions(
                allowed_models=["gpt-4", "gpt-3.5-turbo"],
                budget_limit=50.0,
                budget_period=BudgetPeriod.DAILY,
                rate_limit=RateLimit.per_minute(10),
            ),
            expires_in_days=7,
            issuer="admin",
        )

        # Use the token
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            intended_use_case="coding-assistant",
        )

        for i in range(5):
            validation = validator.validate_request(
                creation.plaintext_token,
                request,
                estimated_cost=2.0,
            )
            assert validation.valid is True

            manager.record_usage(
                creation.token.token_id,
                tokens_used=500,
                cost=2.0,
            )

        # Check stats
        stats = manager.get_usage_stats(creation.token.token_id)
        assert stats is not None
        assert stats.total_requests == 5
        assert stats.total_cost == 10.0

        # Check remaining budget
        remaining = manager.get_remaining_budget(creation.token.token_id)
        assert remaining == pytest.approx(40.0)

        # Revoke the token
        manager.revoke_token(
            creation.token.token_id,
            revoked_by="admin",
            reason="Testing complete",
        )

        # Token should no longer validate
        final_validation = validator.validate_request(
            creation.plaintext_token,
            request,
        )
        assert final_validation.valid is False
        assert final_validation.failure_reason == ValidationFailureReason.TOKEN_REVOKED

    def test_multiple_tokens_same_subject(self) -> None:
        """Test managing multiple tokens for the same subject."""
        manager = TokenManager()

        # Create multiple tokens
        dev_token = manager.create_token(
            name="dev-token",
            subject="user@example.com",
            permissions=TokenPermissions(allowed_models=["gpt-3.5-turbo"]),
            tags=["development"],
        )

        prod_token = manager.create_token(
            name="prod-token",
            subject="user@example.com",
            permissions=TokenPermissions(allowed_models=["gpt-4"]),
            tags=["production"],
        )

        # List tokens for subject
        tokens = manager.list_tokens(subject="user@example.com")
        assert len(tokens) == 2

        # List by tag
        dev_tokens = manager.list_tokens(tags=["development"])
        assert len(dev_tokens) == 1
        assert dev_tokens[0].token_id == dev_token.token.token_id

        # Revoke all tokens for subject
        count = manager.revoke_tokens_for_subject(
            "user@example.com",
            revoked_by="admin",
        )
        assert count == 2

        # Verify both are revoked
        tokens = manager.list_tokens(
            subject="user@example.com",
            status=TokenStatus.REVOKED,
            include_expired=True,
        )
        assert len(tokens) == 2
