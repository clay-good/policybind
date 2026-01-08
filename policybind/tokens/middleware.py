"""
Token middleware for PolicyBind enforcement pipeline.

This module provides middleware for token-based authentication and
authorization in the policy enforcement pipeline.
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from policybind.engine.context import EnforcementContext, PipelineStage, StageResult
from policybind.engine.middleware import Middleware
from policybind.models.base import generate_uuid, utc_now
from policybind.models.request import Decision
from policybind.tokens.manager import TokenManager
from policybind.tokens.models import BudgetPeriod, Token, TokenPermissions, TokenUsageStats
from policybind.tokens.validator import TokenValidator, ValidationFailureReason, ValidationResult


class TokenExtractionMethod(Enum):
    """Methods for extracting tokens from requests."""

    HEADER = "header"
    """Extract from request headers."""

    METADATA = "metadata"
    """Extract from request metadata."""

    QUERY_PARAM = "query_param"
    """Extract from query parameters."""


@dataclass
class TokenAuthConfig:
    """
    Configuration for token authentication middleware.

    Attributes:
        extraction_method: How to extract the token from requests.
        header_name: Header name if using HEADER extraction.
        metadata_key: Metadata key if using METADATA extraction.
        query_param_name: Query parameter name if using QUERY_PARAM extraction.
        require_token: Whether to reject requests without tokens.
        allow_anonymous: Whether to allow requests without tokens (overridden by require_token).
        track_usage: Whether to track token usage.
        reject_on_budget_exceeded: Whether to reject requests that exceed budget.
        reject_on_rate_limit: Whether to reject requests that are rate limited.
        add_token_to_context: Whether to add token info to context metadata.
    """

    extraction_method: TokenExtractionMethod = TokenExtractionMethod.METADATA
    header_name: str = "Authorization"
    metadata_key: str = "token"
    query_param_name: str = "api_token"
    require_token: bool = True
    allow_anonymous: bool = False
    track_usage: bool = True
    reject_on_budget_exceeded: bool = True
    reject_on_rate_limit: bool = True
    add_token_to_context: bool = True


class TokenAuthMiddleware(Middleware):
    """
    Pipeline middleware for token-based authentication.

    TokenAuthMiddleware extracts tokens from incoming requests, validates them,
    attaches token information to the enforcement context, and rejects requests
    with invalid or expired tokens.

    Example:
        Using token authentication in a pipeline::

            from policybind.tokens.middleware import TokenAuthMiddleware, TokenAuthConfig
            from policybind.tokens.manager import TokenManager
            from policybind.tokens.validator import TokenValidator

            manager = TokenManager()
            validator = TokenValidator(manager)

            middleware = TokenAuthMiddleware(
                validator=validator,
                manager=manager,
                config=TokenAuthConfig(
                    require_token=True,
                    track_usage=True,
                ),
            )

            # Add to pipeline
            pipeline.add_middleware(middleware)
    """

    def __init__(
        self,
        validator: TokenValidator,
        manager: TokenManager | None = None,
        config: TokenAuthConfig | None = None,
        budget_tracker: "TokenBudgetTracker | None" = None,
    ) -> None:
        """
        Initialize the token authentication middleware.

        Args:
            validator: The token validator to use.
            manager: The token manager for usage tracking (optional).
            config: Configuration options.
            budget_tracker: Budget tracker for managing token budgets.
        """
        self._validator = validator
        self._manager = manager
        self._config = config or TokenAuthConfig()
        self._budget_tracker = budget_tracker

    @property
    def name(self) -> str:
        return "TokenAuthMiddleware"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.VALIDATION

    def process(self, context: EnforcementContext) -> StageResult:
        """
        Process a request through token authentication.

        This method:
        1. Extracts the token from the request
        2. Validates the token
        3. Checks token permissions against the request
        4. Attaches token information to the context
        5. Rejects requests with invalid/expired tokens

        Args:
            context: The enforcement context.

        Returns:
            StageResult indicating success or failure.
        """
        start = time.perf_counter()

        # Extract token from request
        plaintext_token = self._extract_token(context)

        if not plaintext_token:
            if self._config.require_token and not self._config.allow_anonymous:
                return self._failure_result(
                    "Token required but not provided",
                    decision=Decision.DENY,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            # Allow anonymous access if configured
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
                metadata={"anonymous": True},
            )

        # Validate the token against the request
        estimated_cost = self._get_estimated_cost(context)
        validation_result = self._validator.validate_request(
            plaintext_token=plaintext_token,
            request=context.request,
            estimated_cost=estimated_cost,
            check_rate_limit=self._config.reject_on_rate_limit,
            check_budget=self._config.reject_on_budget_exceeded,
        )

        # Handle validation failure
        if not validation_result.valid:
            return self._handle_validation_failure(
                context,
                validation_result,
                start,
            )

        # Validation succeeded - attach token info to context
        if self._config.add_token_to_context and validation_result.token:
            self._attach_token_to_context(context, validation_result)

        # Reserve budget if budget tracker is available
        if self._budget_tracker and validation_result.token and estimated_cost > 0:
            reservation_id = self._budget_tracker.reserve(
                token_id=validation_result.token.token_id,
                amount=estimated_cost,
            )
            if reservation_id:
                context.metadata["budget_reservation_id"] = reservation_id
            elif self._config.reject_on_budget_exceeded:
                return self._failure_result(
                    "Budget reservation failed",
                    decision=Decision.DENY,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
            metadata={
                "token_id": validation_result.token.token_id if validation_result.token else None,
                "token_subject": validation_result.token.subject if validation_result.token else None,
                "remaining_budget": validation_result.remaining_budget,
                "rate_limit_remaining": validation_result.rate_limit_remaining,
            },
        )

    def _extract_token(self, context: EnforcementContext) -> str | None:
        """Extract the token from the request."""
        if context.request is None:
            return None

        request = context.request

        if self._config.extraction_method == TokenExtractionMethod.METADATA:
            return request.metadata.get(self._config.metadata_key)

        elif self._config.extraction_method == TokenExtractionMethod.HEADER:
            headers = request.metadata.get("headers", {})
            auth_header = headers.get(self._config.header_name, "")
            # Handle "Bearer <token>" format
            if auth_header.startswith("Bearer "):
                return auth_header[7:]
            return auth_header if auth_header else None

        elif self._config.extraction_method == TokenExtractionMethod.QUERY_PARAM:
            query_params = request.metadata.get("query_params", {})
            return query_params.get(self._config.query_param_name)

        return None

    def _get_estimated_cost(self, context: EnforcementContext) -> float:
        """Get the estimated cost from the request."""
        if context.request is None:
            return 0.0
        return context.request.estimated_cost

    def _handle_validation_failure(
        self,
        context: EnforcementContext,
        result: ValidationResult,
        start: float,
    ) -> StageResult:
        """Handle a token validation failure."""
        reason = result.failure_reason

        # Map validation failure reasons to decisions
        if reason in (
            ValidationFailureReason.TOKEN_NOT_FOUND,
            ValidationFailureReason.INVALID_TOKEN_FORMAT,
        ):
            error = f"Invalid token: {result.failure_details}"

        elif reason in (
            ValidationFailureReason.TOKEN_EXPIRED,
            ValidationFailureReason.TOKEN_REVOKED,
            ValidationFailureReason.TOKEN_SUSPENDED,
        ):
            error = f"Token not valid: {result.failure_details}"

        elif reason == ValidationFailureReason.BUDGET_EXCEEDED:
            if not self._config.reject_on_budget_exceeded:
                context.add_warning(f"Token budget exceeded: {result.failure_details}")
                return self._success_result(
                    duration_ms=(time.perf_counter() - start) * 1000,
                    metadata={"budget_exceeded_warning": True},
                )
            error = f"Budget exceeded: {result.failure_details}"

        elif reason == ValidationFailureReason.RATE_LIMITED:
            if not self._config.reject_on_rate_limit:
                context.add_warning(f"Token rate limited: {result.failure_details}")
                return self._success_result(
                    duration_ms=(time.perf_counter() - start) * 1000,
                    metadata={"rate_limited_warning": True},
                )
            error = f"Rate limit exceeded: {result.failure_details}"

        elif reason == ValidationFailureReason.APPROVAL_REQUIRED:
            context.short_circuit(Decision.REQUIRE_APPROVAL, result.failure_details)
            return StageResult(
                stage=self.stage,
                success=True,
                duration_ms=(time.perf_counter() - start) * 1000,
                decision=Decision.REQUIRE_APPROVAL,
                metadata={"approval_required": True},
            )

        else:
            error = f"Token validation failed: {result.failure_details}"

        context.short_circuit(Decision.DENY, error)
        return self._failure_result(
            error,
            decision=Decision.DENY,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    def _attach_token_to_context(
        self,
        context: EnforcementContext,
        result: ValidationResult,
    ) -> None:
        """Attach token information to the enforcement context."""
        token = result.token
        if not token:
            return

        context.metadata["token"] = {
            "token_id": token.token_id,
            "subject": token.subject,
            "subject_type": token.subject_type,
            "issuer": token.issuer,
            "issued_at": token.issued_at.isoformat(),
            "expires_at": token.expires_at.isoformat() if token.expires_at else None,
            "permissions": token.permissions.to_dict(),
            "remaining_budget": result.remaining_budget,
            "rate_limit_remaining": result.rate_limit_remaining,
            "warnings": result.warnings,
        }


class ReservationStatus(Enum):
    """Status of a budget reservation."""

    PENDING = "pending"
    """Reservation is pending commitment."""

    COMMITTED = "committed"
    """Reservation has been committed."""

    RELEASED = "released"
    """Reservation has been released."""

    EXPIRED = "expired"
    """Reservation expired without being committed."""


@dataclass
class BudgetReservation:
    """
    A budget reservation for a token.

    Attributes:
        reservation_id: Unique ID for this reservation.
        token_id: The token this reservation is for.
        amount: The reserved amount.
        created_at: When the reservation was created.
        expires_at: When the reservation expires.
        status: Current status of the reservation.
        committed_amount: Actual amount committed (may differ from reserved).
    """

    reservation_id: str
    token_id: str
    amount: float
    created_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    status: ReservationStatus = ReservationStatus.PENDING
    committed_amount: float | None = None

    def is_expired(self) -> bool:
        """Check if the reservation has expired."""
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at


class TokenBudgetTracker:
    """
    Tracks spending against token budgets.

    TokenBudgetTracker provides atomic budget reservation and commitment
    to prevent race conditions when multiple requests use the same token.

    Thread Safety:
        All operations are thread-safe.

    Example:
        Using budget tracking::

            tracker = TokenBudgetTracker(
                manager=token_manager,
                reservation_ttl_seconds=300,
            )

            # Reserve budget before processing
            reservation_id = tracker.reserve(
                token_id="token-123",
                amount=10.50,
            )

            if reservation_id:
                try:
                    # Process the request
                    actual_cost = process_request()

                    # Commit the actual cost
                    tracker.commit(reservation_id, actual_cost)
                except Exception:
                    # Release the reservation on failure
                    tracker.release(reservation_id)
    """

    def __init__(
        self,
        manager: TokenManager,
        reservation_ttl_seconds: int = 300,
        auto_cleanup_interval: int = 60,
    ) -> None:
        """
        Initialize the budget tracker.

        Args:
            manager: The token manager for budget updates.
            reservation_ttl_seconds: How long reservations stay valid.
            auto_cleanup_interval: Interval for cleaning up expired reservations.
        """
        self._manager = manager
        self._reservation_ttl = timedelta(seconds=reservation_ttl_seconds)
        self._cleanup_interval = auto_cleanup_interval

        self._reservations: dict[str, BudgetReservation] = {}
        self._token_reserved: dict[str, float] = {}  # token_id -> total reserved
        self._lock = threading.RLock()

        self._last_cleanup = utc_now()

    def reserve(
        self,
        token_id: str,
        amount: float,
        buffer_percentage: float = 0.0,
    ) -> str | None:
        """
        Reserve budget for a token.

        Args:
            token_id: The token to reserve budget for.
            amount: Amount to reserve.
            buffer_percentage: Extra percentage to reserve as buffer.

        Returns:
            Reservation ID if successful, None if budget not available.
        """
        self._maybe_cleanup()

        with self._lock:
            # Calculate total amount with buffer
            total_amount = amount * (1 + buffer_percentage / 100)

            # Get current token stats
            stats = self._manager.get_usage_stats(token_id)
            if stats is None:
                return None

            # Get token to check budget limit
            token = self._manager.get_token(token_id)
            if token is None or token.permissions.budget_limit is None:
                # No budget limit - reservation always succeeds
                reservation = self._create_reservation(token_id, total_amount)
                return reservation.reservation_id

            # Calculate available budget (accounting for existing reservations)
            current_reserved = self._token_reserved.get(token_id, 0.0)
            remaining = token.permissions.budget_limit - stats.period_cost - current_reserved

            if remaining < total_amount:
                return None

            # Create reservation
            reservation = self._create_reservation(token_id, total_amount)
            self._token_reserved[token_id] = current_reserved + total_amount

            return reservation.reservation_id

    def commit(
        self,
        reservation_id: str,
        actual_amount: float | None = None,
    ) -> bool:
        """
        Commit a budget reservation.

        Args:
            reservation_id: The reservation to commit.
            actual_amount: Actual amount to commit (uses reserved amount if None).

        Returns:
            True if committed successfully, False otherwise.
        """
        with self._lock:
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                return False

            if reservation.status != ReservationStatus.PENDING:
                return False

            if reservation.is_expired():
                self._release_internal(reservation)
                return False

            # Determine amount to commit
            commit_amount = actual_amount if actual_amount is not None else reservation.amount

            # Record the usage in the token manager
            self._manager.record_usage(
                token_id=reservation.token_id,
                tokens_used=0,
                cost=commit_amount,
                success=True,
            )

            # Update reservation
            reservation.status = ReservationStatus.COMMITTED
            reservation.committed_amount = commit_amount

            # Release any unused reserved amount
            released = reservation.amount - commit_amount
            current_reserved = self._token_reserved.get(reservation.token_id, 0.0)
            self._token_reserved[reservation.token_id] = max(0, current_reserved - reservation.amount)

            return True

    def release(self, reservation_id: str) -> bool:
        """
        Release a budget reservation without committing.

        Args:
            reservation_id: The reservation to release.

        Returns:
            True if released successfully, False otherwise.
        """
        with self._lock:
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                return False

            if reservation.status != ReservationStatus.PENDING:
                return False

            self._release_internal(reservation)
            return True

    def get_reservation(self, reservation_id: str) -> BudgetReservation | None:
        """Get a reservation by ID."""
        with self._lock:
            return self._reservations.get(reservation_id)

    def get_reserved_amount(self, token_id: str) -> float:
        """Get total reserved amount for a token."""
        with self._lock:
            return self._token_reserved.get(token_id, 0.0)

    def get_available_budget(self, token_id: str) -> float | None:
        """
        Get available budget for a token (accounting for reservations).

        Args:
            token_id: The token ID.

        Returns:
            Available budget, or None if token has no budget limit.
        """
        with self._lock:
            token = self._manager.get_token(token_id)
            if token is None or token.permissions.budget_limit is None:
                return None

            stats = self._manager.get_usage_stats(token_id)
            if stats is None:
                return token.permissions.budget_limit

            current_reserved = self._token_reserved.get(token_id, 0.0)
            return token.permissions.budget_limit - stats.period_cost - current_reserved

    def _create_reservation(
        self,
        token_id: str,
        amount: float,
    ) -> BudgetReservation:
        """Create a new reservation."""
        reservation = BudgetReservation(
            reservation_id=generate_uuid(),
            token_id=token_id,
            amount=amount,
            expires_at=utc_now() + self._reservation_ttl,
        )
        self._reservations[reservation.reservation_id] = reservation
        return reservation

    def _release_internal(self, reservation: BudgetReservation) -> None:
        """Internal method to release a reservation."""
        reservation.status = ReservationStatus.RELEASED
        current_reserved = self._token_reserved.get(reservation.token_id, 0.0)
        self._token_reserved[reservation.token_id] = max(
            0, current_reserved - reservation.amount
        )

    def _maybe_cleanup(self) -> None:
        """Clean up expired reservations if needed."""
        now = utc_now()
        if (now - self._last_cleanup).total_seconds() < self._cleanup_interval:
            return

        with self._lock:
            self._last_cleanup = now
            expired = [
                rid for rid, res in self._reservations.items()
                if res.status == ReservationStatus.PENDING and res.is_expired()
            ]
            for rid in expired:
                reservation = self._reservations[rid]
                self._release_internal(reservation)
                reservation.status = ReservationStatus.EXPIRED

    def cleanup_all(self) -> int:
        """
        Clean up all expired reservations.

        Returns:
            Number of reservations cleaned up.
        """
        with self._lock:
            expired = [
                rid for rid, res in self._reservations.items()
                if res.status == ReservationStatus.PENDING and res.is_expired()
            ]
            for rid in expired:
                reservation = self._reservations[rid]
                self._release_internal(reservation)
                reservation.status = ReservationStatus.EXPIRED

            return len(expired)


class TokenUsageRecorder(Middleware):
    """
    Records token usage after request completion.

    This middleware should be placed at the end of the pipeline to record
    the actual cost and tokens used after the request completes.

    Example:
        Using the usage recorder::

            recorder = TokenUsageRecorder(
                manager=token_manager,
                budget_tracker=budget_tracker,
            )

            # Add to pipeline after other middleware
            pipeline.add_middleware(recorder, stage=PipelineStage.LOGGING)
    """

    def __init__(
        self,
        manager: TokenManager,
        budget_tracker: TokenBudgetTracker | None = None,
        cost_calculator: Callable[[EnforcementContext], float] | None = None,
    ) -> None:
        """
        Initialize the usage recorder.

        Args:
            manager: The token manager for recording usage.
            budget_tracker: Budget tracker for committing reservations.
            cost_calculator: Custom function to calculate actual cost.
        """
        self._manager = manager
        self._budget_tracker = budget_tracker
        self._cost_calculator = cost_calculator

    @property
    def name(self) -> str:
        return "TokenUsageRecorder"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.LOGGING

    def process(self, context: EnforcementContext) -> StageResult:
        """Record token usage after request processing."""
        start = time.perf_counter()

        # Get token info from context
        token_data = context.metadata.get("token")
        if not token_data:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        token_id = token_data.get("token_id")
        if not token_id:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Calculate actual cost
        if self._cost_calculator:
            actual_cost = self._cost_calculator(context)
        else:
            actual_cost = context.request.estimated_cost if context.request else 0.0

        # Determine if request was successful
        success = context.final_decision in (Decision.ALLOW, Decision.MODIFY)

        # Commit budget reservation if we have one
        reservation_id = context.metadata.get("budget_reservation_id")
        if reservation_id and self._budget_tracker:
            self._budget_tracker.commit(reservation_id, actual_cost)
        elif success:
            # No reservation but successful - record usage directly
            self._manager.record_usage(
                token_id=token_id,
                tokens_used=context.modifications.get("tokens_used", 0),
                cost=actual_cost,
                success=True,
            )
        else:
            # Request was denied
            self._manager.record_denied_request(token_id)
            # Release reservation if we had one
            if reservation_id and self._budget_tracker:
                self._budget_tracker.release(reservation_id)

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
            metadata={
                "token_id": token_id,
                "actual_cost": actual_cost,
                "success": success,
            },
        )
