"""
Token validation for PolicyBind.

This module provides the TokenValidator class for validating access tokens
and checking if requests are permitted under a token's permissions.
"""

import fnmatch
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from enum import Enum
from typing import Any

from policybind.models.base import utc_now
from policybind.models.request import AIRequest
from policybind.tokens.manager import TokenManager
from policybind.tokens.models import (
    RateLimit,
    TimeWindow,
    Token,
    TokenPermissions,
    TokenStatus,
    TokenUsageStats,
)


class ValidationFailureReason(Enum):
    """Reasons why token validation failed."""

    TOKEN_NOT_FOUND = "token_not_found"
    """Token does not exist."""

    TOKEN_EXPIRED = "token_expired"
    """Token has passed its expiration date."""

    TOKEN_REVOKED = "token_revoked"
    """Token has been revoked."""

    TOKEN_SUSPENDED = "token_suspended"
    """Token is temporarily suspended."""

    INVALID_TOKEN_FORMAT = "invalid_token_format"
    """Token format is invalid."""

    MODEL_NOT_ALLOWED = "model_not_allowed"
    """The requested model is not permitted."""

    PROVIDER_NOT_ALLOWED = "provider_not_allowed"
    """The requested provider is not permitted."""

    USE_CASE_NOT_ALLOWED = "use_case_not_allowed"
    """The use case is not permitted."""

    DATA_CLASSIFICATION_NOT_ALLOWED = "data_classification_not_allowed"
    """The data classification is not permitted."""

    SOURCE_NOT_ALLOWED = "source_not_allowed"
    """The source application is not permitted."""

    OUTSIDE_VALID_HOURS = "outside_valid_hours"
    """Request is outside the allowed time window."""

    BUDGET_EXCEEDED = "budget_exceeded"
    """Token has exceeded its budget limit."""

    RATE_LIMITED = "rate_limited"
    """Token has exceeded its rate limit."""

    MAX_TOKENS_EXCEEDED = "max_tokens_exceeded"
    """Request exceeds maximum tokens per request."""

    APPROVAL_REQUIRED = "approval_required"
    """Request requires manual approval due to cost threshold."""

    CUSTOM_CONSTRAINT_FAILED = "custom_constraint_failed"
    """A custom constraint was not satisfied."""


@dataclass
class ValidationResult:
    """
    Result of validating a token against a request.

    Attributes:
        valid: Whether the validation passed.
        token: The validated token (if found).
        failure_reason: Why validation failed (if applicable).
        failure_details: Additional details about the failure.
        warnings: Non-fatal warnings about the request.
        remaining_budget: Remaining budget after this request.
        rate_limit_remaining: Remaining requests in rate limit window.
    """

    valid: bool
    token: Token | None = None
    failure_reason: ValidationFailureReason | None = None
    failure_details: str = ""
    warnings: list[str] = field(default_factory=list)
    remaining_budget: float | None = None
    rate_limit_remaining: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "valid": self.valid,
            "token_id": self.token.token_id if self.token else None,
            "failure_reason": (
                self.failure_reason.value if self.failure_reason else None
            ),
            "failure_details": self.failure_details,
            "warnings": self.warnings,
            "remaining_budget": self.remaining_budget,
            "rate_limit_remaining": self.rate_limit_remaining,
        }


@dataclass
class CachedValidation:
    """A cached validation result."""

    result: ValidationResult
    expires_at: datetime
    request_hash: str


class TokenValidator:
    """
    Validates access tokens and checks request permissions.

    TokenValidator provides comprehensive validation of tokens against
    incoming requests, checking all permission constraints including
    model access, use cases, data classifications, budgets, rate limits,
    and time restrictions.

    Thread Safety:
        All operations are thread-safe through internal locking.

    Example:
        Validating a request::

            validator = TokenValidator(token_manager)

            result = validator.validate_request(
                plaintext_token="pb_abc123...",
                request=AIRequest(
                    provider="openai",
                    model="gpt-4",
                    intended_use_case="customer-support",
                ),
            )

            if result.valid:
                print("Request allowed")
            else:
                print(f"Denied: {result.failure_reason.value}")
    """

    def __init__(
        self,
        token_manager: TokenManager,
        cache_ttl_seconds: int = 60,
        enable_cache: bool = True,
    ) -> None:
        """
        Initialize the token validator.

        Args:
            token_manager: The TokenManager to use for token lookup.
            cache_ttl_seconds: How long to cache validation results.
            enable_cache: Whether to enable validation caching.
        """
        self._manager = token_manager
        self._cache_ttl = cache_ttl_seconds
        self._cache_enabled = enable_cache
        self._cache: dict[str, CachedValidation] = {}
        self._lock = threading.RLock()

    def validate_token(self, plaintext_token: str) -> ValidationResult:
        """
        Validate a token without a specific request.

        Checks if the token exists and is currently active.

        Args:
            plaintext_token: The plaintext token value.

        Returns:
            ValidationResult indicating success or failure.
        """
        # Check format
        if not self._is_valid_format(plaintext_token):
            return ValidationResult(
                valid=False,
                failure_reason=ValidationFailureReason.INVALID_TOKEN_FORMAT,
                failure_details="Token does not have the expected format",
            )

        # Look up token
        token = self._manager.get_token_by_value(plaintext_token)
        if not token:
            return ValidationResult(
                valid=False,
                failure_reason=ValidationFailureReason.TOKEN_NOT_FOUND,
                failure_details="Token not found in the system",
            )

        # Check status
        if token.status == TokenStatus.REVOKED:
            return ValidationResult(
                valid=False,
                token=token,
                failure_reason=ValidationFailureReason.TOKEN_REVOKED,
                failure_details=f"Token was revoked: {token.revocation_reason}",
            )

        if token.status == TokenStatus.SUSPENDED:
            return ValidationResult(
                valid=False,
                token=token,
                failure_reason=ValidationFailureReason.TOKEN_SUSPENDED,
                failure_details="Token is temporarily suspended",
            )

        # Check expiration
        if token.is_expired():
            return ValidationResult(
                valid=False,
                token=token,
                failure_reason=ValidationFailureReason.TOKEN_EXPIRED,
                failure_details=f"Token expired at {token.expires_at}",
            )

        return ValidationResult(valid=True, token=token)

    def validate_request(
        self,
        plaintext_token: str,
        request: AIRequest | None = None,
        estimated_cost: float = 0.0,
        check_rate_limit: bool = True,
        check_budget: bool = True,
    ) -> ValidationResult:
        """
        Validate a token against a specific request.

        Performs comprehensive validation including:
        - Token status and expiration
        - Model and provider permissions
        - Use case permissions
        - Data classification permissions
        - Source application permissions
        - Time window restrictions
        - Rate limiting
        - Budget constraints

        Args:
            plaintext_token: The plaintext token value.
            request: The AI request to validate.
            estimated_cost: Estimated cost of this request.
            check_rate_limit: Whether to check rate limits.
            check_budget: Whether to check budget limits.

        Returns:
            ValidationResult with detailed validation status.
        """
        # ALWAYS validate the token itself first (never cache token status)
        # This ensures revoked/expired tokens are caught even with caching enabled
        base_result = self.validate_token(plaintext_token)
        if not base_result.valid:
            return base_result

        token = base_result.token
        if not token:
            return base_result

        # Check cache for permission validation (after confirming token is valid)
        if self._cache_enabled and request:
            cached = self._get_cached(plaintext_token, request)
            if cached and cached.valid:
                # Return cached result but with fresh token reference
                return ValidationResult(
                    valid=cached.valid,
                    token=token,
                    failure_reason=cached.failure_reason,
                    failure_details=cached.failure_details,
                    warnings=cached.warnings,
                    remaining_budget=cached.remaining_budget,
                    rate_limit_remaining=cached.rate_limit_remaining,
                )

        permissions = token.permissions
        warnings: list[str] = []

        # If no request, we're done with basic validation
        if not request:
            return ValidationResult(valid=True, token=token)

        # Check provider
        if not self._check_provider(request.provider, permissions):
            return ValidationResult(
                valid=False,
                token=token,
                failure_reason=ValidationFailureReason.PROVIDER_NOT_ALLOWED,
                failure_details=f"Provider '{request.provider}' is not permitted",
            )

        # Check model
        if not self._check_model(request.model, permissions):
            return ValidationResult(
                valid=False,
                token=token,
                failure_reason=ValidationFailureReason.MODEL_NOT_ALLOWED,
                failure_details=f"Model '{request.model}' is not permitted",
            )

        # Check use case
        if request.intended_use_case:
            if not self._check_use_case(request.intended_use_case, permissions):
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.USE_CASE_NOT_ALLOWED,
                    failure_details=(
                        f"Use case '{request.intended_use_case}' is not permitted"
                    ),
                )

        # Check data classifications
        if request.data_classification:
            for classification in request.data_classification:
                if not self._check_data_classification(classification, permissions):
                    return ValidationResult(
                        valid=False,
                        token=token,
                        failure_reason=(
                            ValidationFailureReason.DATA_CLASSIFICATION_NOT_ALLOWED
                        ),
                        failure_details=(
                            f"Data classification '{classification}' is not permitted"
                        ),
                    )

        # Check source application
        if request.source_application:
            if not self._check_source(request.source_application, permissions):
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.SOURCE_NOT_ALLOWED,
                    failure_details=(
                        f"Source '{request.source_application}' is not permitted"
                    ),
                )

        # Check time window
        if permissions.valid_hours:
            if not self._check_time_window(permissions.valid_hours):
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.OUTSIDE_VALID_HOURS,
                    failure_details=(
                        f"Request is outside valid hours "
                        f"({permissions.valid_hours.start} - {permissions.valid_hours.end})"
                    ),
                )

        # Check max tokens per request
        if permissions.max_tokens_per_request and request.estimated_tokens:
            if request.estimated_tokens > permissions.max_tokens_per_request:
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.MAX_TOKENS_EXCEEDED,
                    failure_details=(
                        f"Request uses {request.estimated_tokens} tokens, "
                        f"maximum is {permissions.max_tokens_per_request}"
                    ),
                )

        # Check rate limit
        remaining_rate = None
        if check_rate_limit and permissions.rate_limit:
            if self._manager.is_rate_limited(token.token_id):
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.RATE_LIMITED,
                    failure_details=(
                        f"Rate limit exceeded: "
                        f"{permissions.rate_limit.max_requests} requests "
                        f"per {permissions.rate_limit.period_seconds} seconds"
                    ),
                )
            # Calculate remaining
            stats = self._manager.get_usage_stats(token.token_id)
            if stats:
                remaining_rate = max(
                    0,
                    permissions.rate_limit.max_requests - stats.rate_limit_requests,
                )

        # Check budget
        remaining_budget = None
        if check_budget and permissions.budget_limit is not None:
            remaining = self._manager.get_remaining_budget(token.token_id)
            if remaining is not None:
                remaining_budget = remaining
                if estimated_cost > 0 and estimated_cost > remaining:
                    return ValidationResult(
                        valid=False,
                        token=token,
                        failure_reason=ValidationFailureReason.BUDGET_EXCEEDED,
                        failure_details=(
                            f"Request cost ${estimated_cost:.2f} exceeds "
                            f"remaining budget ${remaining:.2f}"
                        ),
                    )

                # Warn if budget is low
                if remaining < permissions.budget_limit * 0.1:
                    warnings.append(
                        f"Budget is low: ${remaining:.2f} remaining"
                    )

        # Check approval threshold
        if permissions.require_approval_above is not None:
            if estimated_cost > permissions.require_approval_above:
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.APPROVAL_REQUIRED,
                    failure_details=(
                        f"Request cost ${estimated_cost:.2f} requires approval "
                        f"(threshold: ${permissions.require_approval_above:.2f})"
                    ),
                )

        # Check custom constraints
        for constraint_name, constraint_value in permissions.custom_constraints.items():
            if not self._check_custom_constraint(
                constraint_name, constraint_value, request
            ):
                return ValidationResult(
                    valid=False,
                    token=token,
                    failure_reason=ValidationFailureReason.CUSTOM_CONSTRAINT_FAILED,
                    failure_details=f"Custom constraint '{constraint_name}' not satisfied",
                )

        result = ValidationResult(
            valid=True,
            token=token,
            warnings=warnings,
            remaining_budget=remaining_budget,
            rate_limit_remaining=remaining_rate,
        )

        # Cache the result
        if self._cache_enabled:
            self._cache_result(plaintext_token, request, result)

        return result

    def _is_valid_format(self, token: str) -> bool:
        """Check if token has valid format."""
        if not token:
            return False
        # Token should start with prefix and have sufficient length
        if not token.startswith("pb_"):
            return False
        if len(token) < 20:  # Minimum reasonable length
            return False
        return True

    def _check_provider(self, provider: str | None, permissions: TokenPermissions) -> bool:
        """Check if provider is allowed."""
        if not provider:
            return True

        # Check denied first (deny takes precedence)
        if permissions.denied_providers:
            for pattern in permissions.denied_providers:
                if self._matches_pattern(provider, pattern):
                    return False

        # If allowed list is empty, all are allowed
        if not permissions.allowed_providers:
            return True

        # Check allowed
        for pattern in permissions.allowed_providers:
            if self._matches_pattern(provider, pattern):
                return True

        return False

    def _check_model(self, model: str | None, permissions: TokenPermissions) -> bool:
        """Check if model is allowed."""
        if not model:
            return True

        # Check denied first
        if permissions.denied_models:
            for pattern in permissions.denied_models:
                if self._matches_pattern(model, pattern):
                    return False

        # If allowed list is empty, all are allowed
        if not permissions.allowed_models:
            return True

        # Check allowed
        for pattern in permissions.allowed_models:
            if self._matches_pattern(model, pattern):
                return True

        return False

    def _check_use_case(self, use_case: str, permissions: TokenPermissions) -> bool:
        """Check if use case is allowed."""
        # Check denied first
        if permissions.denied_use_cases:
            for pattern in permissions.denied_use_cases:
                if self._matches_pattern(use_case, pattern):
                    return False

        # If allowed list is empty, all are allowed
        if not permissions.allowed_use_cases:
            return True

        # Check allowed
        for pattern in permissions.allowed_use_cases:
            if self._matches_pattern(use_case, pattern):
                return True

        return False

    def _check_data_classification(
        self,
        classification: str,
        permissions: TokenPermissions,
    ) -> bool:
        """Check if data classification is allowed."""
        # Check denied first
        if permissions.denied_data_classifications:
            for pattern in permissions.denied_data_classifications:
                if self._matches_pattern(classification, pattern):
                    return False

        # If allowed list is empty, all are allowed
        if not permissions.allowed_data_classifications:
            return True

        # Check allowed
        for pattern in permissions.allowed_data_classifications:
            if self._matches_pattern(classification, pattern):
                return True

        return False

    def _check_source(self, source: str, permissions: TokenPermissions) -> bool:
        """Check if source application is allowed."""
        # If valid_sources is empty, all are allowed
        if not permissions.valid_sources:
            return True

        for pattern in permissions.valid_sources:
            if self._matches_pattern(source, pattern):
                return True

        return False

    def _check_time_window(self, window: TimeWindow) -> bool:
        """Check if current time is within the allowed window."""
        try:
            # Get current time in the window's timezone
            tz = timezone.utc
            if window.timezone != "UTC":
                # For simplicity, we'll use UTC offset parsing
                # In production, use pytz or zoneinfo
                tz = timezone.utc

            now = datetime.now(tz)
            current_time = now.time()

            # Check day of week
            if window.days_of_week is not None:
                if now.weekday() not in window.days_of_week:
                    return False

            # Check time range
            if window.start <= window.end:
                # Normal range (e.g., 9:00 - 17:00)
                return window.start <= current_time <= window.end
            else:
                # Overnight range (e.g., 22:00 - 06:00)
                return current_time >= window.start or current_time <= window.end

        except Exception:
            # If we can't determine time, allow by default
            return True

    def _check_custom_constraint(
        self,
        name: str,
        value: Any,
        request: AIRequest,
    ) -> bool:
        """Check a custom constraint against the request."""
        # Custom constraints are checked against request metadata
        if not request.metadata:
            return True

        # If the constraint key exists in metadata, check if values match
        if name in request.metadata:
            request_value = request.metadata[name]
            if isinstance(value, list):
                return request_value in value
            return request_value == value

        return True

    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """Check if value matches a glob pattern."""
        if not value or not pattern:
            return False

        # Use fnmatch for glob-style matching
        return fnmatch.fnmatch(value.lower(), pattern.lower())

    def _get_cached(
        self,
        token: str,
        request: AIRequest,
    ) -> ValidationResult | None:
        """Get cached validation result if available."""
        with self._lock:
            request_hash = self._hash_request(token, request)
            cached = self._cache.get(request_hash)
            if cached and cached.expires_at > utc_now():
                return cached.result
            return None

    def _cache_result(
        self,
        token: str,
        request: AIRequest,
        result: ValidationResult,
    ) -> None:
        """Cache a validation result."""
        with self._lock:
            request_hash = self._hash_request(token, request)
            from datetime import timedelta
            self._cache[request_hash] = CachedValidation(
                result=result,
                expires_at=utc_now() + timedelta(seconds=self._cache_ttl),
                request_hash=request_hash,
            )

    def _hash_request(self, token: str, request: AIRequest) -> str:
        """Create a hash key for caching."""
        import hashlib
        parts = [
            token[:10],  # Only use part of token for key
            request.provider or "",
            request.model or "",
            request.intended_use_case or "",
            request.source_application or "",
            ",".join(sorted(request.data_classification or [])),
        ]
        key = "|".join(parts)
        return hashlib.md5(key.encode()).hexdigest()

    def clear_cache(self) -> None:
        """Clear the validation cache."""
        with self._lock:
            self._cache.clear()

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics."""
        with self._lock:
            total = len(self._cache)
            now = utc_now()
            valid = sum(1 for c in self._cache.values() if c.expires_at > now)
            return {"total_entries": total, "valid_entries": valid}
