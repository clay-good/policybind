"""
Unit tests for PolicyBind token management.

This module tests the TokenManager class and related token models.
"""

from datetime import time, timedelta

import pytest

from policybind.models.base import utc_now
from policybind.tokens.manager import (
    TOKEN_PREFIX,
    TokenEvent,
    TokenManager,
    _generate_token_value,
    _hash_token,
)
from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    TimeWindow,
    TokenPermissions,
    TokenStatus,
)


# =============================================================================
# Token Model Tests
# =============================================================================


class TestTokenStatus:
    """Tests for TokenStatus enum."""

    def test_active_value(self) -> None:
        """Test active status value."""
        assert TokenStatus.ACTIVE.value == "active"

    def test_expired_value(self) -> None:
        """Test expired status value."""
        assert TokenStatus.EXPIRED.value == "expired"

    def test_revoked_value(self) -> None:
        """Test revoked status value."""
        assert TokenStatus.REVOKED.value == "revoked"

    def test_suspended_value(self) -> None:
        """Test suspended status value."""
        assert TokenStatus.SUSPENDED.value == "suspended"


class TestBudgetPeriod:
    """Tests for BudgetPeriod enum."""

    def test_all_periods(self) -> None:
        """Test all budget period values."""
        assert BudgetPeriod.HOURLY.value == "hourly"
        assert BudgetPeriod.DAILY.value == "daily"
        assert BudgetPeriod.WEEKLY.value == "weekly"
        assert BudgetPeriod.MONTHLY.value == "monthly"
        assert BudgetPeriod.YEARLY.value == "yearly"


class TestTimeWindow:
    """Tests for TimeWindow class."""

    def test_create_time_window(self) -> None:
        """Test creating a time window."""
        window = TimeWindow(
            start=time(9, 0),
            end=time(17, 0),
        )
        assert window.start == time(9, 0)
        assert window.end == time(17, 0)
        assert window.timezone == "UTC"

    def test_time_window_with_days(self) -> None:
        """Test time window with days of week."""
        window = TimeWindow(
            start=time(9, 0),
            end=time(17, 0),
            days_of_week=(0, 1, 2, 3, 4),  # Mon-Fri
        )
        assert window.days_of_week == (0, 1, 2, 3, 4)

    def test_business_hours(self) -> None:
        """Test business hours factory method."""
        window = TimeWindow.business_hours()
        assert window.start == time(9, 0)
        assert window.end == time(17, 0)
        assert window.days_of_week == (0, 1, 2, 3, 4)

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        window = TimeWindow(
            start=time(9, 0),
            end=time(17, 0),
            days_of_week=(0, 1, 2),
        )
        d = window.to_dict()
        assert d["start"] == "09:00:00"
        assert d["end"] == "17:00:00"
        assert d["days_of_week"] == [0, 1, 2]

    def test_from_dict(self) -> None:
        """Test creation from dictionary."""
        d = {
            "start": "09:00:00",
            "end": "17:00:00",
            "timezone": "UTC",
            "days_of_week": [0, 1],
        }
        window = TimeWindow.from_dict(d)
        assert window.start == time(9, 0)
        assert window.end == time(17, 0)
        assert window.days_of_week == (0, 1)


class TestRateLimit:
    """Tests for RateLimit class."""

    def test_create_rate_limit(self) -> None:
        """Test creating a rate limit."""
        limit = RateLimit(max_requests=100, period_seconds=60)
        assert limit.max_requests == 100
        assert limit.period_seconds == 60
        assert limit.burst_limit is None

    def test_rate_limit_with_burst(self) -> None:
        """Test rate limit with burst."""
        limit = RateLimit(max_requests=100, period_seconds=60, burst_limit=10)
        assert limit.burst_limit == 10

    def test_per_minute(self) -> None:
        """Test per minute factory method."""
        limit = RateLimit.per_minute(60)
        assert limit.max_requests == 60
        assert limit.period_seconds == 60

    def test_per_hour(self) -> None:
        """Test per hour factory method."""
        limit = RateLimit.per_hour(1000)
        assert limit.max_requests == 1000
        assert limit.period_seconds == 3600

    def test_per_day(self) -> None:
        """Test per day factory method."""
        limit = RateLimit.per_day(10000)
        assert limit.max_requests == 10000
        assert limit.period_seconds == 86400

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        limit = RateLimit(max_requests=100, period_seconds=60, burst_limit=10)
        d = limit.to_dict()
        assert d["max_requests"] == 100
        assert d["period_seconds"] == 60
        assert d["burst_limit"] == 10

    def test_from_dict(self) -> None:
        """Test creation from dictionary."""
        d = {"max_requests": 50, "period_seconds": 120, "burst_limit": 5}
        limit = RateLimit.from_dict(d)
        assert limit.max_requests == 50
        assert limit.period_seconds == 120
        assert limit.burst_limit == 5


class TestTokenPermissions:
    """Tests for TokenPermissions class."""

    def test_default_permissions(self) -> None:
        """Test default permissions."""
        perms = TokenPermissions()
        assert perms.allowed_providers == []
        assert perms.allowed_models == []
        assert perms.denied_models == []
        assert perms.budget_limit is None

    def test_permissions_with_models(self) -> None:
        """Test permissions with specific models."""
        perms = TokenPermissions(
            allowed_providers=["openai", "anthropic"],
            allowed_models=["gpt-4", "claude-3"],
        )
        assert "openai" in perms.allowed_providers
        assert "gpt-4" in perms.allowed_models

    def test_permissions_with_budget(self) -> None:
        """Test permissions with budget limit."""
        perms = TokenPermissions(
            budget_limit=100.0,
            budget_period=BudgetPeriod.DAILY,
        )
        assert perms.budget_limit == 100.0
        assert perms.budget_period == BudgetPeriod.DAILY

    def test_permissions_with_rate_limit(self) -> None:
        """Test permissions with rate limit."""
        rate_limit = RateLimit.per_minute(60)
        perms = TokenPermissions(rate_limit=rate_limit)
        assert perms.rate_limit is not None
        assert perms.rate_limit.max_requests == 60


# =============================================================================
# Token Event Tests
# =============================================================================


class TestTokenEvent:
    """Tests for TokenEvent class."""

    def test_create_event(self) -> None:
        """Test creating a token event."""
        event = TokenEvent(
            event_type="created",
            token_id="token123",
            actor="user@example.com",
        )
        assert event.event_type == "created"
        assert event.token_id == "token123"
        assert event.actor == "user@example.com"

    def test_event_with_details(self) -> None:
        """Test event with details."""
        event = TokenEvent(
            event_type="revoked",
            token_id="token123",
            details={"reason": "compromised"},
        )
        assert event.details["reason"] == "compromised"

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        event = TokenEvent(
            event_type="used",
            token_id="token123",
        )
        d = event.to_dict()
        assert d["event_type"] == "used"
        assert d["token_id"] == "token123"
        assert "timestamp" in d


# =============================================================================
# Token Generation Helper Tests
# =============================================================================


class TestTokenGeneration:
    """Tests for token generation helpers."""

    def test_generate_token_value(self) -> None:
        """Test token value generation."""
        token = _generate_token_value()
        assert token.startswith(TOKEN_PREFIX)
        assert len(token) > len(TOKEN_PREFIX) + 10

    def test_generated_tokens_unique(self) -> None:
        """Test that generated tokens are unique."""
        tokens = [_generate_token_value() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_hash_token(self) -> None:
        """Test token hashing."""
        token = "pb_testtoken123"
        hash1 = _hash_token(token)
        hash2 = _hash_token(token)
        assert hash1 == hash2  # Consistent
        assert len(hash1) == 64  # SHA-256 hex digest

    def test_different_tokens_different_hashes(self) -> None:
        """Test that different tokens have different hashes."""
        hash1 = _hash_token("token1")
        hash2 = _hash_token("token2")
        assert hash1 != hash2


# =============================================================================
# TokenManager Tests
# =============================================================================


class TestTokenManager:
    """Tests for TokenManager class."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    def test_create_token(self, manager: TokenManager) -> None:
        """Test creating a token."""
        result = manager.create_token(
            name="test-token",
            subject="user@example.com",
        )
        assert result.token is not None
        assert result.plaintext_token.startswith(TOKEN_PREFIX)
        assert result.token.status == TokenStatus.ACTIVE

    def test_create_token_with_permissions(self, manager: TokenManager) -> None:
        """Test creating a token with permissions."""
        permissions = TokenPermissions(
            allowed_models=["gpt-4", "gpt-3.5-turbo"],
            budget_limit=100.0,
        )
        result = manager.create_token(
            name="limited-token",
            subject="user@example.com",
            permissions=permissions,
        )
        assert result.token.permissions is not None
        assert "gpt-4" in result.token.permissions.allowed_models

    def test_create_token_with_expiration(self, manager: TokenManager) -> None:
        """Test creating a token with expiration."""
        result = manager.create_token(
            name="expiring-token",
            subject="user@example.com",
            expires_in_days=30,
        )
        assert result.token.expires_at is not None
        assert result.token.expires_at > utc_now()

    def test_validate_token(self, manager: TokenManager) -> None:
        """Test validating a token."""
        result = manager.create_token(
            name="valid-token",
            subject="user@example.com",
        )
        validated = manager.validate_token(result.plaintext_token)
        assert validated is not None
        assert validated.token_id == result.token.token_id

    def test_validate_invalid_token(self, manager: TokenManager) -> None:
        """Test validating an invalid token."""
        validated = manager.validate_token("invalid_token_value")
        assert validated is None

    def test_validate_expired_token(self, manager: TokenManager) -> None:
        """Test validating an expired token."""
        # Create a token that's already expired
        result = manager.create_token(
            name="expired-token",
            subject="user@example.com",
            expires_at=utc_now() - timedelta(hours=1),
        )
        validated = manager.validate_token(result.plaintext_token)
        assert validated is None


class TestTokenManagerRevocation:
    """Tests for token revocation."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    def test_revoke_token(self, manager: TokenManager) -> None:
        """Test revoking a token."""
        result = manager.create_token(
            name="revocable-token",
            subject="user@example.com",
        )
        success = manager.revoke_token(result.token.token_id, revoked_by="admin")
        assert success is True

        # Token should no longer validate
        validated = manager.validate_token(result.plaintext_token)
        assert validated is None

    def test_revoke_nonexistent_token(self, manager: TokenManager) -> None:
        """Test revoking a nonexistent token."""
        success = manager.revoke_token("nonexistent-id", revoked_by="admin")
        assert success is False

    def test_revoke_with_reason(self, manager: TokenManager) -> None:
        """Test revoking with a reason."""
        result = manager.create_token(
            name="revocable-token",
            subject="user@example.com",
        )
        success = manager.revoke_token(
            result.token.token_id,
            revoked_by="admin",
            reason="Security concern",
        )
        assert success is True


class TestTokenManagerUsage:
    """Tests for token usage tracking."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    def test_record_usage(self, manager: TokenManager) -> None:
        """Test recording token usage."""
        result = manager.create_token(
            name="tracked-token",
            subject="user@example.com",
        )
        stats = manager.record_usage(
            result.token.token_id,
            tokens_used=100,
            cost=0.01,
        )
        assert stats is not None
        assert stats.total_requests == 1

    def test_get_usage_stats(self, manager: TokenManager) -> None:
        """Test getting usage statistics."""
        result = manager.create_token(
            name="tracked-token",
            subject="user@example.com",
        )
        manager.record_usage(
            result.token.token_id,
            tokens_used=100,
            cost=0.01,
        )
        manager.record_usage(
            result.token.token_id,
            tokens_used=200,
            cost=0.02,
        )

        stats = manager.get_usage_stats(result.token.token_id)
        assert stats is not None
        assert stats.total_requests == 2
        assert stats.total_tokens_used == 300

    def test_usage_nonexistent_token(self, manager: TokenManager) -> None:
        """Test usage for nonexistent token returns None."""
        stats = manager.record_usage(
            "nonexistent-id",
            tokens_used=100,
            cost=0.01,
        )
        assert stats is None


class TestTokenManagerListing:
    """Tests for token listing."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    def test_list_tokens(self, manager: TokenManager) -> None:
        """Test listing all tokens."""
        manager.create_token(name="token1", subject="user1@example.com")
        manager.create_token(name="token2", subject="user2@example.com")

        tokens = manager.list_tokens()
        assert len(tokens) == 2

    def test_list_tokens_by_subject(self, manager: TokenManager) -> None:
        """Test listing tokens by subject."""
        manager.create_token(name="token1", subject="user1@example.com")
        manager.create_token(name="token2", subject="user1@example.com")
        manager.create_token(name="token3", subject="user2@example.com")

        tokens = manager.list_tokens(subject="user1@example.com")
        assert len(tokens) == 2
        assert all(t.subject == "user1@example.com" for t in tokens)

    def test_list_active_tokens(self, manager: TokenManager) -> None:
        """Test listing only active tokens."""
        result1 = manager.create_token(name="active", subject="user@example.com")
        result2 = manager.create_token(name="revoked", subject="user@example.com")
        manager.revoke_token(result2.token.token_id, revoked_by="admin")

        tokens = manager.list_tokens(status=TokenStatus.ACTIVE)
        assert len(tokens) == 1
        assert tokens[0].token_id == result1.token.token_id

    def test_get_token_by_id(self, manager: TokenManager) -> None:
        """Test getting a token by ID."""
        result = manager.create_token(name="test", subject="user@example.com")
        token = manager.get_token(result.token.token_id)
        assert token is not None
        assert token.name == "test"

    def test_get_nonexistent_token(self, manager: TokenManager) -> None:
        """Test getting a nonexistent token."""
        token = manager.get_token("nonexistent-id")
        assert token is None


class TestTokenManagerEvents:
    """Tests for token event tracking."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    def test_create_generates_event(self, manager: TokenManager) -> None:
        """Test that creating a token generates an event."""
        result = manager.create_token(name="test", subject="user@example.com")
        events = manager.get_events(result.token.token_id)
        assert len(events) >= 1
        assert any(e.event_type == "created" for e in events)

    def test_revoke_generates_event(self, manager: TokenManager) -> None:
        """Test that revoking a token generates an event."""
        result = manager.create_token(name="test", subject="user@example.com")
        manager.revoke_token(result.token.token_id, revoked_by="admin")
        events = manager.get_events(result.token.token_id)
        assert any(e.event_type == "revoked" for e in events)

    def test_event_callback(self, manager: TokenManager) -> None:
        """Test event callback registration."""
        received_events: list[TokenEvent] = []

        def callback(event: TokenEvent) -> None:
            received_events.append(event)

        manager.on_token_event(callback)
        manager.create_token(name="test", subject="user@example.com")

        assert len(received_events) >= 1


class TestTokenManagerEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def manager(self) -> TokenManager:
        """Create a token manager."""
        return TokenManager()

    def test_empty_token_list(self, manager: TokenManager) -> None:
        """Test listing tokens when none exist."""
        tokens = manager.list_tokens()
        assert len(tokens) == 0

    def test_duplicate_token_names_allowed(self, manager: TokenManager) -> None:
        """Test that duplicate token names are allowed."""
        result1 = manager.create_token(name="same-name", subject="user1@example.com")
        result2 = manager.create_token(name="same-name", subject="user2@example.com")
        assert result1.token.token_id != result2.token.token_id

    def test_unicode_in_subject(self, manager: TokenManager) -> None:
        """Test unicode characters in subject."""
        result = manager.create_token(
            name="unicode-token",
            subject="用户@example.com",
        )
        assert result.token.subject == "用户@example.com"

    def test_special_chars_in_name(self, manager: TokenManager) -> None:
        """Test special characters in token name."""
        result = manager.create_token(
            name="token-with_special.chars",
            subject="user@example.com",
        )
        assert result.token.name == "token-with_special.chars"

    def test_thread_safety(self, manager: TokenManager) -> None:
        """Test basic thread safety of token operations."""
        import threading

        results = []
        errors = []

        def create_token(i: int) -> None:
            try:
                result = manager.create_token(
                    name=f"token-{i}",
                    subject=f"user{i}@example.com",
                )
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_token, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 10
        assert len(manager.list_tokens()) == 10
