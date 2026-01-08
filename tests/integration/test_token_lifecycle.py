"""
Integration tests for token lifecycle.

This module tests the complete token lifecycle including:
- Token creation
- Validation
- Usage tracking
- Budget management
- Revocation
"""

import pytest
from datetime import timedelta

from policybind.models.base import utc_now
from policybind.tokens.manager import TokenManager
from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    Token,
    TokenPermissions,
    TokenStatus,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def token_manager() -> TokenManager:
    """Create a token manager for testing."""
    return TokenManager()


# =============================================================================
# Token Creation Tests
# =============================================================================


class TestTokenCreation:
    """Tests for token creation."""

    def test_create_basic_token(self, token_manager: TokenManager) -> None:
        """Test creating a basic token."""
        result = token_manager.create_token(
            name="test-token",
            subject="test-user@example.com",
        )

        assert result is not None
        assert result.token is not None
        assert result.plaintext_token is not None
        assert result.plaintext_token.startswith("pb_")
        assert result.token.name == "test-token"
        assert result.token.subject == "test-user@example.com"
        assert result.token.status == TokenStatus.ACTIVE

    def test_create_token_with_expiration(self, token_manager: TokenManager) -> None:
        """Test creating a token with expiration."""
        result = token_manager.create_token(
            name="expiring-token",
            subject="test-user@example.com",
            expires_in_days=30,
        )

        assert result.token.expires_at is not None
        # Should expire within ~30 days
        now = utc_now()
        assert result.token.expires_at > now
        assert result.token.expires_at < now + timedelta(days=31)

    def test_create_token_with_permissions(self, token_manager: TokenManager) -> None:
        """Test creating a token with specific permissions."""
        permissions = TokenPermissions(
            allowed_models=["gpt-4", "gpt-3.5-turbo"],
            denied_models=["dall-e-3"],
            budget_limit=100.0,
            budget_period=BudgetPeriod.MONTHLY,
        )

        result = token_manager.create_token(
            name="limited-token",
            subject="test-user@example.com",
            permissions=permissions,
        )

        assert result.token.permissions.allowed_models == ["gpt-4", "gpt-3.5-turbo"]
        assert result.token.permissions.budget_limit == 100.0
        assert result.token.permissions.budget_period == BudgetPeriod.MONTHLY

    def test_create_token_with_rate_limit(self, token_manager: TokenManager) -> None:
        """Test creating a token with rate limiting."""
        permissions = TokenPermissions(
            rate_limit=RateLimit(
                max_requests=100,
                period_seconds=60,
            ),
        )

        result = token_manager.create_token(
            name="rate-limited-token",
            subject="test-user@example.com",
            permissions=permissions,
        )

        assert result.token.permissions.rate_limit is not None
        assert result.token.permissions.rate_limit.max_requests == 100
        assert result.token.permissions.rate_limit.period_seconds == 60

    def test_create_token_with_metadata(self, token_manager: TokenManager) -> None:
        """Test creating a token with custom metadata."""
        result = token_manager.create_token(
            name="metadata-token",
            subject="test-user@example.com",
            description="A token for testing metadata",
            tags=["test", "development"],
            metadata={
                "team": "engineering",
                "project": "alpha",
            },
        )

        assert result.token.description == "A token for testing metadata"
        assert "test" in result.token.tags
        assert "development" in result.token.tags
        assert result.token.metadata.get("team") == "engineering"

    def test_create_token_generates_event(self, token_manager: TokenManager) -> None:
        """Test that token creation generates an event."""
        events = []
        token_manager.on_token_event(lambda e: events.append(e))

        token_manager.create_token(
            name="event-test",
            subject="test-user@example.com",
        )

        assert len(events) >= 1
        assert any(e.event_type == "created" for e in events)


# =============================================================================
# Token Validation Tests
# =============================================================================


class TestTokenValidation:
    """Tests for token validation."""

    def test_validate_active_token(self, token_manager: TokenManager) -> None:
        """Test validating an active token."""
        result = token_manager.create_token(
            name="valid-token",
            subject="test-user@example.com",
        )

        validated = token_manager.validate_token(result.plaintext_token)
        assert validated is not None
        assert validated.token_id == result.token.token_id

    def test_validate_invalid_token(self, token_manager: TokenManager) -> None:
        """Test validating an invalid token."""
        validated = token_manager.validate_token("pb_invalid_token_123")
        assert validated is None

    def test_validate_revoked_token(self, token_manager: TokenManager) -> None:
        """Test that revoked tokens cannot be validated."""
        result = token_manager.create_token(
            name="to-be-revoked",
            subject="test-user@example.com",
        )

        # Revoke the token
        token_manager.revoke_token(
            token_id=result.token.token_id,
            revoked_by="admin@example.com",
            reason="Test revocation",
        )

        # Token should not validate
        validated = token_manager.validate_token(result.plaintext_token)
        assert validated is None

    def test_validate_suspended_token(self, token_manager: TokenManager) -> None:
        """Test that suspended tokens cannot be validated."""
        result = token_manager.create_token(
            name="to-be-suspended",
            subject="test-user@example.com",
        )

        # Suspend the token
        token_manager.suspend_token(
            token_id=result.token.token_id,
            suspended_by="admin@example.com",
            reason="Test suspension",
        )

        # Token should not validate
        validated = token_manager.validate_token(result.plaintext_token)
        assert validated is None

    def test_get_token_by_id(self, token_manager: TokenManager) -> None:
        """Test getting a token by its ID."""
        result = token_manager.create_token(
            name="get-by-id",
            subject="test-user@example.com",
        )

        token = token_manager.get_token(result.token.token_id)
        assert token is not None
        assert token.name == "get-by-id"

    def test_get_token_by_value(self, token_manager: TokenManager) -> None:
        """Test getting a token by its plaintext value."""
        result = token_manager.create_token(
            name="get-by-value",
            subject="test-user@example.com",
        )

        token = token_manager.get_token_by_value(result.plaintext_token)
        assert token is not None
        assert token.name == "get-by-value"


# =============================================================================
# Usage Tracking Tests
# =============================================================================


class TestUsageTracking:
    """Tests for token usage tracking."""

    def test_record_basic_usage(self, token_manager: TokenManager) -> None:
        """Test recording basic usage."""
        result = token_manager.create_token(
            name="usage-test",
            subject="test-user@example.com",
        )

        stats = token_manager.record_usage(
            token_id=result.token.token_id,
            tokens_used=100,
            cost=0.01,
            success=True,
        )

        assert stats is not None
        assert stats.total_requests == 1
        assert stats.total_tokens_used == 100
        assert stats.total_cost == 0.01

    def test_track_multiple_requests(self, token_manager: TokenManager) -> None:
        """Test tracking multiple requests."""
        result = token_manager.create_token(
            name="multi-request",
            subject="test-user@example.com",
        )

        # Record multiple uses
        for i in range(5):
            token_manager.record_usage(
                token_id=result.token.token_id,
                tokens_used=100 + i * 10,
                cost=0.01 + i * 0.005,
            )

        stats = token_manager.get_usage_stats(result.token.token_id)
        assert stats is not None
        assert stats.total_requests == 5
        assert stats.total_tokens_used == 100 + 110 + 120 + 130 + 140  # 600
        # 0.01 + 0.015 + 0.02 + 0.025 + 0.03 = 0.10
        assert abs(stats.total_cost - 0.10) < 0.001

    def test_track_failed_requests(self, token_manager: TokenManager) -> None:
        """Test tracking failed requests."""
        result = token_manager.create_token(
            name="error-tracking",
            subject="test-user@example.com",
        )

        # Record a successful and a failed request
        token_manager.record_usage(
            token_id=result.token.token_id,
            tokens_used=100,
            cost=0.01,
            success=True,
        )
        token_manager.record_usage(
            token_id=result.token.token_id,
            tokens_used=0,
            cost=0.0,
            success=False,
        )

        stats = token_manager.get_usage_stats(result.token.token_id)
        assert stats is not None
        assert stats.total_requests == 2
        assert stats.error_count == 1

    def test_track_denied_requests(self, token_manager: TokenManager) -> None:
        """Test tracking denied requests."""
        result = token_manager.create_token(
            name="denied-tracking",
            subject="test-user@example.com",
        )

        # Record denied requests
        token_manager.record_denied_request(result.token.token_id)
        token_manager.record_denied_request(result.token.token_id)

        stats = token_manager.get_usage_stats(result.token.token_id)
        assert stats is not None
        assert stats.denied_requests == 2

    def test_update_last_used_timestamp(self, token_manager: TokenManager) -> None:
        """Test that usage updates last_used_at timestamp."""
        result = token_manager.create_token(
            name="timestamp-test",
            subject="test-user@example.com",
        )

        before_use = utc_now()
        token_manager.record_usage(
            token_id=result.token.token_id,
            tokens_used=100,
            cost=0.01,
        )

        token = token_manager.get_token(result.token.token_id)
        assert token is not None
        assert token.last_used_at is not None
        assert token.last_used_at >= before_use


# =============================================================================
# Budget Management Tests
# =============================================================================


class TestBudgetManagement:
    """Tests for budget tracking and enforcement."""

    def test_budget_tracking(self, token_manager: TokenManager) -> None:
        """Test budget tracking."""
        permissions = TokenPermissions(
            budget_limit=10.0,
            budget_period=BudgetPeriod.MONTHLY,
        )

        result = token_manager.create_token(
            name="budget-test",
            subject="test-user@example.com",
            permissions=permissions,
        )

        # Use some budget
        token_manager.record_usage(
            token_id=result.token.token_id,
            tokens_used=1000,
            cost=3.0,
        )

        remaining = token_manager.get_remaining_budget(result.token.token_id)
        assert remaining is not None
        assert remaining == 7.0

    def test_budget_exhaustion(self, token_manager: TokenManager) -> None:
        """Test budget exhaustion tracking."""
        permissions = TokenPermissions(
            budget_limit=5.0,
            budget_period=BudgetPeriod.MONTHLY,
        )

        result = token_manager.create_token(
            name="exhaustion-test",
            subject="test-user@example.com",
            permissions=permissions,
        )

        # Exhaust budget
        token_manager.record_usage(
            token_id=result.token.token_id,
            tokens_used=5000,
            cost=6.0,  # Over budget
        )

        remaining = token_manager.get_remaining_budget(result.token.token_id)
        assert remaining is not None
        assert remaining == 0.0  # Should not go negative

    def test_unlimited_budget(self, token_manager: TokenManager) -> None:
        """Test tokens with unlimited budget."""
        result = token_manager.create_token(
            name="unlimited-test",
            subject="test-user@example.com",
            # No budget_limit in permissions = unlimited
        )

        remaining = token_manager.get_remaining_budget(result.token.token_id)
        assert remaining is None  # None indicates unlimited


# =============================================================================
# Token Revocation Tests
# =============================================================================


class TestTokenRevocation:
    """Tests for token revocation."""

    def test_revoke_token(self, token_manager: TokenManager) -> None:
        """Test revoking a token."""
        result = token_manager.create_token(
            name="to-revoke",
            subject="test-user@example.com",
        )

        success = token_manager.revoke_token(
            token_id=result.token.token_id,
            revoked_by="admin@example.com",
            reason="Security concern",
        )
        assert success is True

        token = token_manager.get_token(result.token.token_id)
        assert token is not None
        assert token.status == TokenStatus.REVOKED
        assert token.revoked_by == "admin@example.com"
        assert token.revocation_reason == "Security concern"

    def test_revoke_all_tokens_for_subject(self, token_manager: TokenManager) -> None:
        """Test revoking all tokens for a subject."""
        subject = "multi-token-user@example.com"

        # Create multiple tokens for same subject
        for i in range(3):
            token_manager.create_token(
                name=f"token-{i}",
                subject=subject,
            )

        # Create token for different subject
        token_manager.create_token(
            name="other-token",
            subject="other-user@example.com",
        )

        # Revoke all for subject
        count = token_manager.revoke_tokens_for_subject(
            subject=subject,
            revoked_by="admin@example.com",
            reason="User deactivated",
        )
        assert count == 3

        # Verify subject's tokens are revoked
        subject_tokens = token_manager.list_tokens(subject=subject, include_expired=True)
        assert all(t.status == TokenStatus.REVOKED for t in subject_tokens)

        # Verify other user's token is unaffected
        other_tokens = token_manager.list_tokens(subject="other-user@example.com")
        assert len(other_tokens) == 1
        assert other_tokens[0].status == TokenStatus.ACTIVE

    def test_revoke_generates_event(self, token_manager: TokenManager) -> None:
        """Test that revocation generates an event."""
        result = token_manager.create_token(
            name="event-revoke",
            subject="test-user@example.com",
        )

        events = []
        token_manager.on_token_event(lambda e: events.append(e))

        token_manager.revoke_token(
            token_id=result.token.token_id,
            revoked_by="admin@example.com",
        )

        assert any(e.event_type == "revoked" for e in events)


# =============================================================================
# Token Suspension Tests
# =============================================================================


class TestTokenSuspension:
    """Tests for token suspension and unsuspension."""

    def test_suspend_token(self, token_manager: TokenManager) -> None:
        """Test suspending a token."""
        result = token_manager.create_token(
            name="to-suspend",
            subject="test-user@example.com",
        )

        success = token_manager.suspend_token(
            token_id=result.token.token_id,
            suspended_by="admin@example.com",
            reason="Temporary suspension",
        )
        assert success is True

        token = token_manager.get_token(result.token.token_id)
        assert token is not None
        assert token.status == TokenStatus.SUSPENDED

    def test_unsuspend_token(self, token_manager: TokenManager) -> None:
        """Test unsuspending a token."""
        result = token_manager.create_token(
            name="to-unsuspend",
            subject="test-user@example.com",
        )

        # Suspend first
        token_manager.suspend_token(
            token_id=result.token.token_id,
            suspended_by="admin@example.com",
        )

        # Then unsuspend
        success = token_manager.unsuspend_token(
            token_id=result.token.token_id,
            unsuspended_by="admin@example.com",
        )
        assert success is True

        token = token_manager.get_token(result.token.token_id)
        assert token is not None
        assert token.status == TokenStatus.ACTIVE


# =============================================================================
# Token Renewal Tests
# =============================================================================


class TestTokenRenewal:
    """Tests for token renewal."""

    def test_renew_token(self, token_manager: TokenManager) -> None:
        """Test renewing a token's expiration."""
        result = token_manager.create_token(
            name="to-renew",
            subject="test-user@example.com",
            expires_in_days=7,
        )

        original_expiry = result.token.expires_at
        assert original_expiry is not None

        # Renew for 30 more days
        renewed = token_manager.renew_token(
            token_id=result.token.token_id,
            renewed_by="admin@example.com",
            expires_in_days=30,
        )

        assert renewed is not None
        assert renewed.expires_at is not None
        assert renewed.expires_at > original_expiry

    def test_renew_generates_event(self, token_manager: TokenManager) -> None:
        """Test that renewal generates an event."""
        result = token_manager.create_token(
            name="event-renew",
            subject="test-user@example.com",
            expires_in_days=7,
        )

        events = []
        token_manager.on_token_event(lambda e: events.append(e))

        token_manager.renew_token(
            token_id=result.token.token_id,
            renewed_by="admin@example.com",
            expires_in_days=30,
        )

        assert any(e.event_type == "renewed" for e in events)


# =============================================================================
# Permission Update Tests
# =============================================================================


class TestPermissionUpdates:
    """Tests for updating token permissions."""

    def test_update_permissions(self, token_manager: TokenManager) -> None:
        """Test updating token permissions."""
        result = token_manager.create_token(
            name="update-perms",
            subject="test-user@example.com",
            permissions=TokenPermissions(
                budget_limit=50.0,
            ),
        )

        new_permissions = TokenPermissions(
            budget_limit=100.0,
            allowed_models=["gpt-4"],
        )

        updated = token_manager.update_permissions(
            token_id=result.token.token_id,
            permissions=new_permissions,
            updated_by="admin@example.com",
        )

        assert updated is not None
        assert updated.permissions.budget_limit == 100.0
        assert updated.permissions.allowed_models == ["gpt-4"]


# =============================================================================
# Listing and Query Tests
# =============================================================================


class TestListingAndQueries:
    """Tests for listing and querying tokens."""

    def test_list_all_tokens(self, token_manager: TokenManager) -> None:
        """Test listing all tokens."""
        for i in range(3):
            token_manager.create_token(
                name=f"list-test-{i}",
                subject="test-user@example.com",
            )

        tokens = token_manager.list_tokens()
        assert len(tokens) == 3

    def test_list_by_subject(self, token_manager: TokenManager) -> None:
        """Test listing tokens by subject."""
        token_manager.create_token(
            name="user-a-token",
            subject="user-a@example.com",
        )
        token_manager.create_token(
            name="user-b-token",
            subject="user-b@example.com",
        )

        user_a_tokens = token_manager.list_tokens(subject="user-a@example.com")
        assert len(user_a_tokens) == 1
        assert user_a_tokens[0].name == "user-a-token"

    def test_list_by_status(self, token_manager: TokenManager) -> None:
        """Test listing tokens by status."""
        active = token_manager.create_token(
            name="active-token",
            subject="test-user@example.com",
        )
        revoked = token_manager.create_token(
            name="revoked-token",
            subject="test-user@example.com",
        )
        token_manager.revoke_token(
            token_id=revoked.token.token_id,
            revoked_by="admin@example.com",
        )

        active_tokens = token_manager.list_tokens(status=TokenStatus.ACTIVE)
        assert len(active_tokens) == 1
        assert active_tokens[0].name == "active-token"

    def test_list_by_tags(self, token_manager: TokenManager) -> None:
        """Test listing tokens by tags."""
        token_manager.create_token(
            name="prod-token",
            subject="test-user@example.com",
            tags=["production", "api"],
        )
        token_manager.create_token(
            name="dev-token",
            subject="test-user@example.com",
            tags=["development", "api"],
        )

        prod_tokens = token_manager.list_tokens(tags=["production"])
        assert len(prod_tokens) == 1
        assert prod_tokens[0].name == "prod-token"

    def test_get_token_count(self, token_manager: TokenManager) -> None:
        """Test getting token count."""
        for i in range(5):
            result = token_manager.create_token(
                name=f"count-test-{i}",
                subject="test-user@example.com",
            )
            if i == 0:
                token_manager.revoke_token(
                    token_id=result.token.token_id,
                    revoked_by="admin@example.com",
                )

        assert token_manager.get_token_count() == 5
        assert token_manager.get_token_count(status=TokenStatus.ACTIVE) == 4
        assert token_manager.get_token_count(status=TokenStatus.REVOKED) == 1


# =============================================================================
# Statistics Tests
# =============================================================================


class TestStatistics:
    """Tests for token statistics."""

    def test_get_statistics(self, token_manager: TokenManager) -> None:
        """Test getting overall statistics."""
        # Create tokens with different statuses
        active = token_manager.create_token(
            name="active",
            subject="test-user@example.com",
        )
        revoked = token_manager.create_token(
            name="revoked",
            subject="test-user@example.com",
        )
        token_manager.revoke_token(
            token_id=revoked.token.token_id,
            revoked_by="admin@example.com",
        )

        # Record some usage
        token_manager.record_usage(
            token_id=active.token.token_id,
            tokens_used=500,
            cost=0.05,
        )
        token_manager.record_denied_request(active.token.token_id)

        stats = token_manager.get_statistics()
        assert stats["total_tokens"] == 2
        assert stats["active_tokens"] == 1
        assert stats["revoked_tokens"] == 1
        assert stats["total_requests"] == 1
        assert stats["total_cost"] == 0.05
        assert stats["total_denied_requests"] == 1


# =============================================================================
# Event Tracking Tests
# =============================================================================


class TestEventTracking:
    """Tests for event tracking."""

    def test_get_events_for_token(self, token_manager: TokenManager) -> None:
        """Test getting events for a specific token."""
        result = token_manager.create_token(
            name="event-token",
            subject="test-user@example.com",
        )

        token_manager.suspend_token(
            token_id=result.token.token_id,
            suspended_by="admin@example.com",
        )
        token_manager.unsuspend_token(
            token_id=result.token.token_id,
            unsuspended_by="admin@example.com",
        )

        events = token_manager.get_events(token_id=result.token.token_id)
        event_types = [e.event_type for e in events]

        assert "created" in event_types
        assert "suspended" in event_types
        assert "unsuspended" in event_types

    def test_filter_events_by_type(self, token_manager: TokenManager) -> None:
        """Test filtering events by type."""
        for i in range(3):
            token_manager.create_token(
                name=f"filter-event-{i}",
                subject="test-user@example.com",
            )

        created_events = token_manager.get_events(event_type="created")
        assert len(created_events) == 3


# =============================================================================
# Full Lifecycle Tests
# =============================================================================


class TestFullLifecycle:
    """Tests for complete token lifecycle."""

    def test_full_token_lifecycle(self, token_manager: TokenManager) -> None:
        """Test complete token lifecycle from creation to deletion."""
        # 1. Create token
        result = token_manager.create_token(
            name="lifecycle-test",
            subject="test-user@example.com",
            permissions=TokenPermissions(
                budget_limit=100.0,
                budget_period=BudgetPeriod.MONTHLY,
            ),
            expires_in_days=30,
        )
        assert result.token.status == TokenStatus.ACTIVE

        # 2. Validate token
        validated = token_manager.validate_token(result.plaintext_token)
        assert validated is not None

        # 3. Use token
        for i in range(5):
            token_manager.record_usage(
                token_id=result.token.token_id,
                tokens_used=1000,
                cost=5.0,
            )

        # 4. Check budget
        remaining = token_manager.get_remaining_budget(result.token.token_id)
        assert remaining is not None
        assert remaining == 75.0  # 100 - (5 * 5)

        # 5. Suspend token
        token_manager.suspend_token(
            token_id=result.token.token_id,
            suspended_by="admin@example.com",
            reason="Investigation",
        )
        suspended_validation = token_manager.validate_token(result.plaintext_token)
        assert suspended_validation is None

        # 6. Unsuspend token
        token_manager.unsuspend_token(
            token_id=result.token.token_id,
            unsuspended_by="admin@example.com",
        )
        unsuspended_validation = token_manager.validate_token(result.plaintext_token)
        assert unsuspended_validation is not None

        # 7. Renew token
        token_manager.renew_token(
            token_id=result.token.token_id,
            renewed_by="admin@example.com",
            expires_in_days=60,
        )

        # 8. Update permissions
        token_manager.update_permissions(
            token_id=result.token.token_id,
            permissions=TokenPermissions(
                budget_limit=200.0,
                allowed_models=["gpt-4"],
            ),
            updated_by="admin@example.com",
        )

        # 9. Revoke token
        token_manager.revoke_token(
            token_id=result.token.token_id,
            revoked_by="admin@example.com",
            reason="End of project",
        )
        revoked_validation = token_manager.validate_token(result.plaintext_token)
        assert revoked_validation is None

        # 10. Verify final state
        final_token = token_manager.get_token(result.token.token_id)
        assert final_token is not None
        assert final_token.status == TokenStatus.REVOKED

        # 11. Delete token
        deleted = token_manager.delete_token(result.token.token_id)
        assert deleted is True

        # Verify deleted
        assert token_manager.get_token(result.token.token_id) is None

    def test_multiple_tokens_per_user(self, token_manager: TokenManager) -> None:
        """Test managing multiple tokens for same user."""
        subject = "multi-token@example.com"

        # Create tokens for different purposes
        dev_token = token_manager.create_token(
            name="dev-token",
            subject=subject,
            tags=["development"],
            permissions=TokenPermissions(budget_limit=10.0),
        )
        prod_token = token_manager.create_token(
            name="prod-token",
            subject=subject,
            tags=["production"],
            permissions=TokenPermissions(budget_limit=1000.0),
        )

        # Use both tokens
        token_manager.record_usage(
            token_id=dev_token.token.token_id,
            tokens_used=100,
            cost=1.0,
        )
        token_manager.record_usage(
            token_id=prod_token.token.token_id,
            tokens_used=5000,
            cost=50.0,
        )

        # Query by subject
        user_tokens = token_manager.list_tokens(subject=subject)
        assert len(user_tokens) == 2

        # Query by tag
        dev_tokens = token_manager.list_tokens(tags=["development"])
        assert len(dev_tokens) == 1
        prod_tokens = token_manager.list_tokens(tags=["production"])
        assert len(prod_tokens) == 1

        # Revoke dev token only
        token_manager.revoke_token(
            token_id=dev_token.token.token_id,
            revoked_by="admin@example.com",
        )

        # Verify dev is revoked but prod still active
        active_tokens = token_manager.list_tokens(subject=subject, status=TokenStatus.ACTIVE)
        assert len(active_tokens) == 1
        assert active_tokens[0].name == "prod-token"
