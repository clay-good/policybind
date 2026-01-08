"""
Token management for PolicyBind.

This module provides the TokenManager class for issuing, validating,
and revoking access tokens for AI API authorization.
"""

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from policybind.exceptions import TokenError
from policybind.models.base import utc_now
from policybind.tokens.models import (
    BudgetPeriod,
    Token,
    TokenCreationResult,
    TokenPermissions,
    TokenStatus,
    TokenUsageStats,
)


# Constants for token generation
TOKEN_PREFIX = "pb_"
TOKEN_LENGTH = 32  # 32 bytes = 256 bits of entropy
HASH_ALGORITHM = "sha256"


def _hash_token(plaintext: str) -> str:
    """
    Create a secure hash of a plaintext token.

    Uses SHA-256 with a consistent encoding for storage.

    Args:
        plaintext: The plaintext token value.

    Returns:
        Hex-encoded hash of the token.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _generate_token_value() -> str:
    """
    Generate a cryptographically secure token value.

    Returns:
        A prefixed token string with high entropy.
    """
    random_bytes = secrets.token_hex(TOKEN_LENGTH)
    return f"{TOKEN_PREFIX}{random_bytes}"


@dataclass
class TokenEvent:
    """
    Represents an event in the token lifecycle.

    Attributes:
        event_type: Type of event (created, used, revoked, etc.).
        token_id: ID of the affected token.
        timestamp: When the event occurred.
        actor: Who performed the action.
        details: Additional event details.
    """

    event_type: str
    token_id: str
    timestamp: datetime = field(default_factory=utc_now)
    actor: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type,
            "token_id": self.token_id,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "details": self.details,
        }


TokenCallback = Callable[[TokenEvent], None]


class TokenManager:
    """
    Manages access tokens for AI API authorization.

    TokenManager provides the core functionality for token lifecycle
    management including creation, validation, usage tracking, and
    revocation.

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        Creating and using tokens::

            manager = TokenManager()

            # Create a token
            result = manager.create_token(
                name="dev-token",
                subject="developer@example.com",
                permissions=TokenPermissions(
                    allowed_models=["gpt-4"],
                    budget_limit=100.0,
                ),
                expires_in_days=30,
            )
            print(f"Token: {result.plaintext_token}")

            # Validate and use the token
            token = manager.validate_token(result.plaintext_token)
            if token:
                manager.record_usage(
                    token.token_id,
                    tokens_used=100,
                    cost=0.01,
                )
    """

    def __init__(self) -> None:
        """Initialize the token manager."""
        self._tokens: dict[str, Token] = {}
        self._token_by_hash: dict[str, str] = {}  # hash -> token_id
        self._usage_stats: dict[str, TokenUsageStats] = {}
        self._events: list[TokenEvent] = []
        self._callbacks: list[TokenCallback] = []
        self._lock = threading.RLock()
        self._max_events = 10000

    def create_token(
        self,
        name: str,
        subject: str,
        permissions: TokenPermissions | None = None,
        expires_in_days: int | None = None,
        expires_at: datetime | None = None,
        issuer: str = "system",
        issued_for: str = "",
        subject_type: str = "user",
        description: str = "",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TokenCreationResult:
        """
        Create a new access token.

        Args:
            name: Human-readable name for the token.
            subject: Who/what this token is for.
            permissions: Token permissions (default: unrestricted).
            expires_in_days: Days until expiration (mutually exclusive with expires_at).
            expires_at: Explicit expiration datetime.
            issuer: Who is issuing the token.
            issued_for: Optional reference to what triggered issuance.
            subject_type: Type of subject (user, service, application).
            description: Description of the token's purpose.
            tags: Tags for categorization.
            metadata: Additional token metadata.

        Returns:
            TokenCreationResult with the token and plaintext value.

        Raises:
            TokenError: If token creation fails or parameters are invalid.
        """
        if not name:
            raise TokenError("Token name is required")
        if not subject:
            raise TokenError("Token subject is required")

        if expires_in_days is not None and expires_at is not None:
            raise TokenError("Cannot specify both expires_in_days and expires_at")

        # Calculate expiration
        exp_at = expires_at
        if expires_in_days is not None:
            exp_at = utc_now() + timedelta(days=expires_in_days)

        # Generate token value and hash
        plaintext_token = _generate_token_value()
        token_hash = _hash_token(plaintext_token)

        # Create token object
        token = Token(
            token_hash=token_hash,
            name=name,
            description=description,
            subject=subject,
            subject_type=subject_type,
            permissions=permissions or TokenPermissions(),
            status=TokenStatus.ACTIVE,
            expires_at=exp_at,
            issuer=issuer,
            issued_for=issued_for,
            tags=tags or [],
            metadata=metadata or {},
        )

        with self._lock:
            # Store the token
            self._tokens[token.token_id] = token
            self._token_by_hash[token_hash] = token.token_id

            # Initialize usage stats
            self._usage_stats[token.token_id] = TokenUsageStats(
                token_id=token.token_id
            )

            # Record event
            self._add_event(TokenEvent(
                event_type="created",
                token_id=token.token_id,
                actor=issuer,
                details={
                    "name": name,
                    "subject": subject,
                    "expires_at": exp_at.isoformat() if exp_at else None,
                },
            ))

        return TokenCreationResult(token=token, plaintext_token=plaintext_token)

    def get_token(self, token_id: str) -> Token | None:
        """
        Get a token by its ID.

        Args:
            token_id: The token ID.

        Returns:
            The token if found, None otherwise.
        """
        with self._lock:
            return self._tokens.get(token_id)

    def get_token_by_value(self, plaintext_token: str) -> Token | None:
        """
        Get a token by its plaintext value.

        Args:
            plaintext_token: The plaintext token value.

        Returns:
            The token if found and valid, None otherwise.
        """
        token_hash = _hash_token(plaintext_token)
        with self._lock:
            token_id = self._token_by_hash.get(token_hash)
            if token_id:
                return self._tokens.get(token_id)
            return None

    def validate_token(self, plaintext_token: str) -> Token | None:
        """
        Validate a plaintext token.

        Checks if the token exists and is currently active
        (not expired, revoked, or suspended).

        Args:
            plaintext_token: The plaintext token value.

        Returns:
            The token if valid, None otherwise.
        """
        token = self.get_token_by_value(plaintext_token)
        if token and token.is_active():
            return token
        return None

    def revoke_token(
        self,
        token_id: str,
        revoked_by: str,
        reason: str = "",
    ) -> bool:
        """
        Revoke a token.

        Args:
            token_id: The token to revoke.
            revoked_by: Who is revoking the token.
            reason: Reason for revocation.

        Returns:
            True if the token was revoked, False if not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return False

            if token.status == TokenStatus.REVOKED:
                return True  # Already revoked

            token.status = TokenStatus.REVOKED
            token.revoked_at = utc_now()
            token.revoked_by = revoked_by
            token.revocation_reason = reason

            self._add_event(TokenEvent(
                event_type="revoked",
                token_id=token_id,
                actor=revoked_by,
                details={"reason": reason},
            ))

            return True

    def revoke_tokens_for_subject(
        self,
        subject: str,
        revoked_by: str,
        reason: str = "",
    ) -> int:
        """
        Revoke all tokens for a subject.

        Args:
            subject: The subject whose tokens should be revoked.
            revoked_by: Who is revoking the tokens.
            reason: Reason for revocation.

        Returns:
            Number of tokens revoked.
        """
        count = 0
        with self._lock:
            for token in self._tokens.values():
                if token.subject == subject and token.status == TokenStatus.ACTIVE:
                    self.revoke_token(token.token_id, revoked_by, reason)
                    count += 1
        return count

    def revoke_expired_tokens(self, revoked_by: str = "system") -> int:
        """
        Revoke all expired tokens.

        Args:
            revoked_by: Who is performing the cleanup.

        Returns:
            Number of tokens revoked.
        """
        count = 0
        with self._lock:
            for token in list(self._tokens.values()):
                if token.status == TokenStatus.ACTIVE and token.is_expired():
                    token.status = TokenStatus.EXPIRED
                    self._add_event(TokenEvent(
                        event_type="expired",
                        token_id=token.token_id,
                        actor=revoked_by,
                    ))
                    count += 1
        return count

    def suspend_token(self, token_id: str, suspended_by: str, reason: str = "") -> bool:
        """
        Temporarily suspend a token.

        Args:
            token_id: The token to suspend.
            suspended_by: Who is suspending the token.
            reason: Reason for suspension.

        Returns:
            True if the token was suspended, False if not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return False

            if token.status != TokenStatus.ACTIVE:
                return False

            token.status = TokenStatus.SUSPENDED
            token.metadata["suspended_by"] = suspended_by
            token.metadata["suspension_reason"] = reason
            token.metadata["suspended_at"] = utc_now().isoformat()

            self._add_event(TokenEvent(
                event_type="suspended",
                token_id=token_id,
                actor=suspended_by,
                details={"reason": reason},
            ))

            return True

    def unsuspend_token(
        self,
        token_id: str,
        unsuspended_by: str,
    ) -> bool:
        """
        Remove suspension from a token.

        Args:
            token_id: The token to unsuspend.
            unsuspended_by: Who is unsuspending the token.

        Returns:
            True if the token was unsuspended, False if not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return False

            if token.status != TokenStatus.SUSPENDED:
                return False

            token.status = TokenStatus.ACTIVE
            token.metadata.pop("suspended_by", None)
            token.metadata.pop("suspension_reason", None)
            token.metadata.pop("suspended_at", None)

            self._add_event(TokenEvent(
                event_type="unsuspended",
                token_id=token_id,
                actor=unsuspended_by,
            ))

            return True

    def record_usage(
        self,
        token_id: str,
        tokens_used: int = 0,
        cost: float = 0.0,
        success: bool = True,
    ) -> TokenUsageStats | None:
        """
        Record usage of a token.

        Updates usage statistics and the last_used_at timestamp.

        Args:
            token_id: The token that was used.
            tokens_used: Number of AI tokens consumed.
            cost: Cost incurred by this request.
            success: Whether the request succeeded.

        Returns:
            Updated usage stats, or None if token not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return None

            stats = self._usage_stats.get(token_id)
            if not stats:
                stats = TokenUsageStats(token_id=token_id)
                self._usage_stats[token_id] = stats

            # Update token last used
            token.last_used_at = utc_now()

            # Check if we need to reset period stats
            self._maybe_reset_period(stats, token.permissions.budget_period)

            # Update stats
            stats.total_requests += 1
            stats.total_tokens_used += tokens_used
            stats.total_cost += cost
            stats.period_requests += 1
            stats.period_cost += cost
            stats.last_request_at = utc_now()

            if not success:
                stats.error_count += 1

            # Update rate limit tracking
            self._update_rate_limit_window(stats, token)
            stats.rate_limit_requests += 1

            return stats

    def record_denied_request(self, token_id: str) -> None:
        """
        Record a denied request for a token.

        Args:
            token_id: The token that was denied.
        """
        with self._lock:
            stats = self._usage_stats.get(token_id)
            if stats:
                stats.denied_requests += 1

    def get_usage_stats(self, token_id: str) -> TokenUsageStats | None:
        """
        Get usage statistics for a token.

        Args:
            token_id: The token ID.

        Returns:
            Usage stats if found, None otherwise.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            stats = self._usage_stats.get(token_id)
            if stats and token:
                # Ensure period is current
                self._maybe_reset_period(stats, token.permissions.budget_period)
            return stats

    def get_remaining_budget(self, token_id: str) -> float | None:
        """
        Get remaining budget for a token.

        Args:
            token_id: The token ID.

        Returns:
            Remaining budget in the current period, or None if unlimited.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return None

            if token.permissions.budget_limit is None:
                return None

            stats = self._usage_stats.get(token_id)
            if not stats:
                return token.permissions.budget_limit

            # Ensure period is current
            self._maybe_reset_period(stats, token.permissions.budget_period)

            return max(0.0, token.permissions.budget_limit - stats.period_cost)

    def is_rate_limited(self, token_id: str) -> bool:
        """
        Check if a token is currently rate limited.

        Args:
            token_id: The token ID.

        Returns:
            True if rate limited, False otherwise.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token or not token.permissions.rate_limit:
                return False

            stats = self._usage_stats.get(token_id)
            if not stats:
                return False

            rate_limit = token.permissions.rate_limit
            self._update_rate_limit_window(stats, token)

            return stats.rate_limit_requests >= rate_limit.max_requests

    def _update_rate_limit_window(self, stats: TokenUsageStats, token: Token) -> None:
        """Update rate limit window and reset if needed."""
        if not token.permissions.rate_limit:
            return

        rate_limit = token.permissions.rate_limit
        window_seconds = rate_limit.period_seconds
        now = utc_now()
        elapsed = (now - stats.rate_limit_window_start).total_seconds()

        if elapsed >= window_seconds:
            # Reset the window
            stats.rate_limit_requests = 0
            stats.rate_limit_window_start = now

    def _maybe_reset_period(
        self,
        stats: TokenUsageStats,
        period: BudgetPeriod,
    ) -> None:
        """Reset period stats if a new period has started."""
        now = utc_now()
        should_reset = False

        if period == BudgetPeriod.HOURLY:
            should_reset = (now - stats.period_start).total_seconds() >= 3600
        elif period == BudgetPeriod.DAILY:
            should_reset = (now - stats.period_start).days >= 1
        elif period == BudgetPeriod.WEEKLY:
            should_reset = (now - stats.period_start).days >= 7
        elif period == BudgetPeriod.MONTHLY:
            # Approximate: 30 days
            should_reset = (now - stats.period_start).days >= 30
        elif period == BudgetPeriod.YEARLY:
            should_reset = (now - stats.period_start).days >= 365

        if should_reset:
            stats.period_requests = 0
            stats.period_cost = 0.0
            stats.period_start = now

    def renew_token(
        self,
        token_id: str,
        renewed_by: str,
        expires_in_days: int | None = None,
        expires_at: datetime | None = None,
    ) -> Token | None:
        """
        Renew a token's expiration.

        Args:
            token_id: The token to renew.
            renewed_by: Who is renewing the token.
            expires_in_days: New expiration in days from now.
            expires_at: New explicit expiration datetime.

        Returns:
            The renewed token, or None if not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return None

            if token.status == TokenStatus.REVOKED:
                return None  # Cannot renew revoked tokens

            # Calculate new expiration
            new_expires: datetime | None = expires_at
            if expires_in_days is not None:
                new_expires = utc_now() + timedelta(days=expires_in_days)

            old_expires = token.expires_at
            token.expires_at = new_expires

            # If token was expired, reactivate it
            if token.status == TokenStatus.EXPIRED:
                token.status = TokenStatus.ACTIVE

            self._add_event(TokenEvent(
                event_type="renewed",
                token_id=token_id,
                actor=renewed_by,
                details={
                    "old_expires_at": old_expires.isoformat() if old_expires else None,
                    "new_expires_at": new_expires.isoformat() if new_expires else None,
                },
            ))

            return token

    def update_permissions(
        self,
        token_id: str,
        permissions: TokenPermissions,
        updated_by: str,
    ) -> Token | None:
        """
        Update a token's permissions.

        Args:
            token_id: The token to update.
            permissions: New permissions.
            updated_by: Who is updating the permissions.

        Returns:
            The updated token, or None if not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return None

            old_permissions = token.permissions
            token.permissions = permissions

            self._add_event(TokenEvent(
                event_type="permissions_updated",
                token_id=token_id,
                actor=updated_by,
                details={
                    "old_permissions": old_permissions.to_dict(),
                    "new_permissions": permissions.to_dict(),
                },
            ))

            return token

    def list_tokens(
        self,
        subject: str | None = None,
        status: TokenStatus | None = None,
        tags: list[str] | None = None,
        issuer: str | None = None,
        include_expired: bool = False,
    ) -> list[Token]:
        """
        List tokens matching the given criteria.

        Args:
            subject: Filter by subject.
            status: Filter by status.
            tags: Filter by tags (any match).
            issuer: Filter by issuer.
            include_expired: Include expired tokens in results.

        Returns:
            List of matching tokens.
        """
        with self._lock:
            tokens = []
            for token in self._tokens.values():
                # Filter by subject
                if subject and token.subject != subject:
                    continue

                # Filter by status
                if status and token.status != status:
                    continue

                # Filter by issuer
                if issuer and token.issuer != issuer:
                    continue

                # Filter by tags
                if tags and not any(tag in token.tags for tag in tags):
                    continue

                # Filter out expired unless requested
                if not include_expired and token.is_expired():
                    continue

                tokens.append(token)

            return tokens

    def get_token_count(
        self,
        status: TokenStatus | None = None,
    ) -> int:
        """
        Get count of tokens.

        Args:
            status: Filter by status.

        Returns:
            Number of tokens.
        """
        with self._lock:
            if status is None:
                return len(self._tokens)
            return sum(1 for t in self._tokens.values() if t.status == status)

    def get_statistics(self) -> dict[str, Any]:
        """
        Get overall token statistics.

        Returns:
            Dictionary with token statistics.
        """
        with self._lock:
            total = len(self._tokens)
            active = sum(1 for t in self._tokens.values() if t.is_active())
            expired = sum(1 for t in self._tokens.values() if t.is_expired())
            revoked = sum(
                1 for t in self._tokens.values() if t.status == TokenStatus.REVOKED
            )
            suspended = sum(
                1 for t in self._tokens.values() if t.status == TokenStatus.SUSPENDED
            )

            total_requests = sum(s.total_requests for s in self._usage_stats.values())
            total_cost = sum(s.total_cost for s in self._usage_stats.values())
            total_denied = sum(s.denied_requests for s in self._usage_stats.values())

            return {
                "total_tokens": total,
                "active_tokens": active,
                "expired_tokens": expired,
                "revoked_tokens": revoked,
                "suspended_tokens": suspended,
                "total_requests": total_requests,
                "total_cost": total_cost,
                "total_denied_requests": total_denied,
            }

    def on_token_event(self, callback: TokenCallback) -> None:
        """
        Register a callback for token events.

        Args:
            callback: Function to call on token events.
        """
        with self._lock:
            self._callbacks.append(callback)

    def remove_callback(self, callback: TokenCallback) -> bool:
        """
        Remove a token event callback.

        Args:
            callback: The callback to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
                return True
            return False

    def get_events(
        self,
        token_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[TokenEvent]:
        """
        Get token events.

        Args:
            token_id: Filter by token ID.
            event_type: Filter by event type.
            limit: Maximum events to return.

        Returns:
            List of matching events (newest first).
        """
        with self._lock:
            events = self._events
            if token_id:
                events = [e for e in events if e.token_id == token_id]
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            return list(reversed(events[-limit:]))

    def _add_event(self, event: TokenEvent) -> None:
        """Add an event and notify callbacks."""
        self._events.append(event)

        # Trim events if needed
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Don't let callback errors affect operation

    def delete_token(self, token_id: str) -> bool:
        """
        Permanently delete a token.

        Use revoke_token for normal deactivation. This method
        completely removes the token from the system.

        Args:
            token_id: The token to delete.

        Returns:
            True if deleted, False if not found.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return False

            # Remove from all storage
            del self._tokens[token_id]
            self._token_by_hash.pop(token.token_hash, None)
            self._usage_stats.pop(token_id, None)

            self._add_event(TokenEvent(
                event_type="deleted",
                token_id=token_id,
            ))

            return True

    def clear(self) -> None:
        """Clear all tokens (for testing)."""
        with self._lock:
            self._tokens.clear()
            self._token_by_hash.clear()
            self._usage_stats.clear()
            self._events.clear()
