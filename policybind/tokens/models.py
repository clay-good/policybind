"""
Token-related data models for PolicyBind.

This module provides data models for access tokens and permissions
used to authorize AI API requests within the PolicyBind system.
"""

from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, serialize_value, utc_now


class BudgetPeriod(Enum):
    """Period over which budget is calculated."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"


class TokenStatus(Enum):
    """Status of an access token."""

    ACTIVE = "active"
    """Token is valid and can be used."""

    EXPIRED = "expired"
    """Token has passed its expiration date."""

    REVOKED = "revoked"
    """Token has been explicitly revoked."""

    SUSPENDED = "suspended"
    """Token is temporarily suspended."""


@dataclass
class TimeWindow:
    """
    Represents a time window during which access is permitted.

    Used to restrict token usage to specific hours of the day.

    Attributes:
        start: Start time of the allowed window (inclusive).
        end: End time of the allowed window (inclusive).
        timezone: Timezone for the time window (default UTC).
        days_of_week: Days of week when access is allowed (0=Monday, 6=Sunday).
            If None, all days are allowed.
    """

    start: time
    end: time
    timezone: str = "UTC"
    days_of_week: tuple[int, ...] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "timezone": self.timezone,
            "days_of_week": list(self.days_of_week) if self.days_of_week else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimeWindow":
        """Create from dictionary."""
        return cls(
            start=time.fromisoformat(data["start"]),
            end=time.fromisoformat(data["end"]),
            timezone=data.get("timezone", "UTC"),
            days_of_week=(
                tuple(data["days_of_week"])
                if data.get("days_of_week") is not None
                else None
            ),
        )

    @classmethod
    def business_hours(cls) -> "TimeWindow":
        """Create a typical business hours window (9 AM - 5 PM, Mon-Fri)."""
        return cls(
            start=time(9, 0),
            end=time(17, 0),
            days_of_week=(0, 1, 2, 3, 4),  # Monday to Friday
        )


@dataclass
class RateLimit:
    """
    Defines rate limiting constraints for a token.

    Attributes:
        max_requests: Maximum number of requests allowed.
        period_seconds: Time period in seconds for the limit.
        burst_limit: Optional maximum burst of requests allowed at once.
    """

    max_requests: int
    period_seconds: int = 60  # Default: per minute
    burst_limit: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "max_requests": self.max_requests,
            "period_seconds": self.period_seconds,
            "burst_limit": self.burst_limit,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RateLimit":
        """Create from dictionary."""
        return cls(
            max_requests=data["max_requests"],
            period_seconds=data.get("period_seconds", 60),
            burst_limit=data.get("burst_limit"),
        )

    @classmethod
    def per_minute(cls, max_requests: int) -> "RateLimit":
        """Create a per-minute rate limit."""
        return cls(max_requests=max_requests, period_seconds=60)

    @classmethod
    def per_hour(cls, max_requests: int) -> "RateLimit":
        """Create a per-hour rate limit."""
        return cls(max_requests=max_requests, period_seconds=3600)

    @classmethod
    def per_day(cls, max_requests: int) -> "RateLimit":
        """Create a per-day rate limit."""
        return cls(max_requests=max_requests, period_seconds=86400)


@dataclass
class TokenPermissions:
    """
    Defines what a token is allowed to do.

    TokenPermissions provides fine-grained control over what operations
    a token can perform, including model access, use cases, data handling,
    budget constraints, and time restrictions.

    All permission lists support glob-style patterns using * as a wildcard.
    For example, "openai/*" matches all OpenAI models.

    Attributes:
        allowed_models: List of permitted model patterns.
            Empty list means all models are allowed.
        denied_models: List of explicitly denied model patterns.
            Overrides allowed_models if there's a conflict.
        allowed_providers: List of permitted provider patterns.
            Empty list means all providers are allowed.
        denied_providers: Explicitly denied provider patterns.
        allowed_use_cases: List of permitted use case patterns.
            Empty list means all use cases are allowed.
        denied_use_cases: Explicitly denied use cases (overrides allowed).
        allowed_data_classifications: What data classifications can be processed.
            Empty list means all classifications are allowed.
        denied_data_classifications: Denied data classifications.
        budget_limit: Maximum spend allowed (None = unlimited).
        budget_period: Period over which budget is calculated.
        budget_currency: Currency for budget (default USD).
        rate_limit: Rate limiting constraints.
        valid_sources: Applications that can use this token.
            Empty list means all sources are allowed.
        valid_hours: Time-of-day restrictions.
        max_tokens_per_request: Maximum tokens per request.
        max_requests_per_session: Maximum requests in a single session.
        require_approval_above: Require manual approval for costs above this.
        custom_constraints: Dict of additional constraints.
    """

    # Model access control
    allowed_models: list[str] = field(default_factory=list)
    denied_models: list[str] = field(default_factory=list)
    allowed_providers: list[str] = field(default_factory=list)
    denied_providers: list[str] = field(default_factory=list)

    # Use case control
    allowed_use_cases: list[str] = field(default_factory=list)
    denied_use_cases: list[str] = field(default_factory=list)

    # Data classification control
    allowed_data_classifications: list[str] = field(default_factory=list)
    denied_data_classifications: list[str] = field(default_factory=list)

    # Budget and cost control
    budget_limit: float | None = None
    budget_period: BudgetPeriod = BudgetPeriod.MONTHLY
    budget_currency: str = "USD"

    # Rate limiting
    rate_limit: RateLimit | None = None

    # Source application control
    valid_sources: list[str] = field(default_factory=list)

    # Time restrictions
    valid_hours: TimeWindow | None = None

    # Request constraints
    max_tokens_per_request: int | None = None
    max_requests_per_session: int | None = None

    # Approval thresholds
    require_approval_above: float | None = None

    # Custom constraints
    custom_constraints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {
            "allowed_models": self.allowed_models,
            "denied_models": self.denied_models,
            "allowed_providers": self.allowed_providers,
            "denied_providers": self.denied_providers,
            "allowed_use_cases": self.allowed_use_cases,
            "denied_use_cases": self.denied_use_cases,
            "allowed_data_classifications": self.allowed_data_classifications,
            "denied_data_classifications": self.denied_data_classifications,
            "budget_limit": self.budget_limit,
            "budget_period": self.budget_period.value,
            "budget_currency": self.budget_currency,
            "rate_limit": self.rate_limit.to_dict() if self.rate_limit else None,
            "valid_sources": self.valid_sources,
            "valid_hours": self.valid_hours.to_dict() if self.valid_hours else None,
            "max_tokens_per_request": self.max_tokens_per_request,
            "max_requests_per_session": self.max_requests_per_session,
            "require_approval_above": self.require_approval_above,
            "custom_constraints": self.custom_constraints,
        }
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenPermissions":
        """Create from dictionary."""
        rate_limit = None
        if data.get("rate_limit"):
            rate_limit = RateLimit.from_dict(data["rate_limit"])

        valid_hours = None
        if data.get("valid_hours"):
            valid_hours = TimeWindow.from_dict(data["valid_hours"])

        budget_period = BudgetPeriod.MONTHLY
        if data.get("budget_period"):
            budget_period = BudgetPeriod(data["budget_period"])

        return cls(
            allowed_models=data.get("allowed_models", []),
            denied_models=data.get("denied_models", []),
            allowed_providers=data.get("allowed_providers", []),
            denied_providers=data.get("denied_providers", []),
            allowed_use_cases=data.get("allowed_use_cases", []),
            denied_use_cases=data.get("denied_use_cases", []),
            allowed_data_classifications=data.get("allowed_data_classifications", []),
            denied_data_classifications=data.get("denied_data_classifications", []),
            budget_limit=data.get("budget_limit"),
            budget_period=budget_period,
            budget_currency=data.get("budget_currency", "USD"),
            rate_limit=rate_limit,
            valid_sources=data.get("valid_sources", []),
            valid_hours=valid_hours,
            max_tokens_per_request=data.get("max_tokens_per_request"),
            max_requests_per_session=data.get("max_requests_per_session"),
            require_approval_above=data.get("require_approval_above"),
            custom_constraints=data.get("custom_constraints", {}),
        )

    @classmethod
    def unrestricted(cls) -> "TokenPermissions":
        """Create permissions with no restrictions."""
        return cls()

    @classmethod
    def read_only(cls) -> "TokenPermissions":
        """Create read-only permissions (no model calls)."""
        return cls(
            allowed_models=[],  # Empty means all allowed
            denied_use_cases=["generation", "completion", "chat"],
            allowed_use_cases=["embedding", "classification", "analysis"],
        )


@dataclass
class TokenUsageStats:
    """
    Usage statistics for a token.

    Tracks how much a token has been used within various periods
    and constraints.

    Attributes:
        token_id: ID of the token these stats belong to.
        total_requests: Total number of requests made.
        total_tokens_used: Total AI tokens consumed.
        total_cost: Total cost incurred.
        period_requests: Requests in current budget period.
        period_cost: Cost in current budget period.
        period_start: Start of current budget period.
        last_request_at: Timestamp of last request.
        rate_limit_requests: Requests in current rate limit window.
        rate_limit_window_start: Start of current rate limit window.
        denied_requests: Number of denied requests.
        error_count: Number of requests that resulted in errors.
    """

    token_id: str
    total_requests: int = 0
    total_tokens_used: int = 0
    total_cost: float = 0.0
    period_requests: int = 0
    period_cost: float = 0.0
    period_start: datetime = field(default_factory=utc_now)
    last_request_at: datetime | None = None
    rate_limit_requests: int = 0
    rate_limit_window_start: datetime = field(default_factory=utc_now)
    denied_requests: int = 0
    error_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "token_id": self.token_id,
            "total_requests": self.total_requests,
            "total_tokens_used": self.total_tokens_used,
            "total_cost": self.total_cost,
            "period_requests": self.period_requests,
            "period_cost": self.period_cost,
            "period_start": self.period_start.isoformat(),
            "last_request_at": (
                self.last_request_at.isoformat() if self.last_request_at else None
            ),
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_window_start": self.rate_limit_window_start.isoformat(),
            "denied_requests": self.denied_requests,
            "error_count": self.error_count,
        }


@dataclass
class Token:
    """
    Represents an access token for AI API authorization.

    Token is the primary authorization credential in PolicyBind. Each token
    has associated permissions that define what operations are allowed.

    Security Note:
        The actual token value is never stored. Only a secure hash
        (token_hash) is persisted. The plaintext token is only available
        at creation time.

    Attributes:
        token_id: Unique identifier for the token.
        token_hash: Secure hash of the actual token value.
        name: Human-readable name for the token.
        description: Description of the token's purpose.
        subject: Who/what this token is for (user, service, etc.).
        subject_type: Type of subject (user, service, application).
        permissions: TokenPermissions defining allowed operations.
        status: Current status of the token.
        issued_at: When the token was issued.
        expires_at: When the token expires (None = never).
        last_used_at: When the token was last used.
        issuer: Who issued the token.
        issued_for: Optional reference to what triggered issuance.
        revoked_at: When the token was revoked (if applicable).
        revoked_by: Who revoked the token.
        revocation_reason: Why the token was revoked.
        tags: Tags for categorization.
        metadata: Additional token metadata.
    """

    token_id: str = field(default_factory=generate_uuid)
    token_hash: str = ""
    name: str = ""
    description: str = ""
    subject: str = ""
    subject_type: str = "user"
    permissions: TokenPermissions = field(default_factory=TokenPermissions)
    status: TokenStatus = TokenStatus.ACTIVE
    issued_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    issuer: str = ""
    issued_for: str = ""
    revoked_at: datetime | None = None
    revoked_by: str = ""
    revocation_reason: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the token has expired."""
        if self.expires_at is None:
            return False
        return utc_now() >= self.expires_at

    def is_active(self) -> bool:
        """Check if the token is currently usable."""
        if self.status != TokenStatus.ACTIVE:
            return False
        return not self.is_expired()

    def is_revoked(self) -> bool:
        """Check if the token has been revoked."""
        return self.status == TokenStatus.REVOKED

    def is_suspended(self) -> bool:
        """Check if the token is suspended."""
        return self.status == TokenStatus.SUSPENDED

    def time_until_expiry(self) -> float | None:
        """
        Get seconds until token expires.

        Returns:
            Seconds until expiry, 0 if expired, None if no expiry.
        """
        if self.expires_at is None:
            return None
        delta = (self.expires_at - utc_now()).total_seconds()
        return max(0.0, delta)

    def to_dict(self, exclude_hash: bool = False) -> dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Args:
            exclude_hash: If True, exclude the token_hash from output.
        """
        result: dict[str, Any] = {
            "token_id": self.token_id,
            "name": self.name,
            "description": self.description,
            "subject": self.subject,
            "subject_type": self.subject_type,
            "permissions": self.permissions.to_dict(),
            "status": self.status.value,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": (
                self.last_used_at.isoformat() if self.last_used_at else None
            ),
            "issuer": self.issuer,
            "issued_for": self.issued_for,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
            "revocation_reason": self.revocation_reason,
            "tags": self.tags,
            "metadata": serialize_value(self.metadata),
        }

        if not exclude_hash:
            result["token_hash"] = self.token_hash

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Token":
        """Create from dictionary."""
        permissions = TokenPermissions.from_dict(data.get("permissions", {}))
        status = TokenStatus(data.get("status", "active"))

        return cls(
            token_id=data.get("token_id", generate_uuid()),
            token_hash=data.get("token_hash", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            subject=data.get("subject", ""),
            subject_type=data.get("subject_type", "user"),
            permissions=permissions,
            status=status,
            issued_at=(
                datetime.fromisoformat(data["issued_at"])
                if data.get("issued_at")
                else utc_now()
            ),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            last_used_at=(
                datetime.fromisoformat(data["last_used_at"])
                if data.get("last_used_at")
                else None
            ),
            issuer=data.get("issuer", ""),
            issued_for=data.get("issued_for", ""),
            revoked_at=(
                datetime.fromisoformat(data["revoked_at"])
                if data.get("revoked_at")
                else None
            ),
            revoked_by=data.get("revoked_by", ""),
            revocation_reason=data.get("revocation_reason", ""),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"Token(token_id={self.token_id!r}, name={self.name!r}, "
            f"subject={self.subject!r}, status={self.status.value!r})"
        )


@dataclass
class TokenCreationResult:
    """
    Result of creating a new token.

    Contains both the Token object and the plaintext token value.
    The plaintext value is only available at creation time and should
    be securely transmitted to the token holder.

    Attributes:
        token: The created Token object (without plaintext value).
        plaintext_token: The actual token value to use for authentication.
    """

    token: Token
    plaintext_token: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "token": self.token.to_dict(exclude_hash=True),
            "plaintext_token": self.plaintext_token,
        }
