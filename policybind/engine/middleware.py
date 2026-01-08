"""
Middleware for the PolicyBind enforcement pipeline.

This module provides the middleware interface and built-in middleware
implementations for request validation, classification, rate limiting,
cost tracking, and audit logging.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
import threading
import time

from policybind.engine.context import EnforcementContext, PipelineStage, StageResult
from policybind.models.request import Decision


class Middleware(ABC):
    """
    Abstract base class for pipeline middleware.

    Middleware can inspect, modify, or short-circuit requests as they
    pass through the enforcement pipeline.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the middleware name for logging."""
        pass

    @property
    def stage(self) -> PipelineStage:
        """Return the pipeline stage this middleware belongs to."""
        return PipelineStage.VALIDATION

    @abstractmethod
    def process(self, context: EnforcementContext) -> StageResult:
        """
        Process the request through this middleware.

        Args:
            context: The enforcement context.

        Returns:
            StageResult indicating success/failure and any modifications.
        """
        pass

    def _success_result(
        self,
        duration_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> StageResult:
        """Create a successful stage result."""
        return StageResult(
            stage=self.stage,
            success=True,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

    def _failure_result(
        self,
        error: str,
        decision: Decision = Decision.DENY,
        duration_ms: float = 0.0,
    ) -> StageResult:
        """Create a failed stage result."""
        return StageResult(
            stage=self.stage,
            success=False,
            duration_ms=duration_ms,
            decision=decision,
            error=error,
        )


class RequestValidator(Middleware):
    """
    Validates that incoming requests have required fields.

    This middleware ensures that requests have the minimum required
    information for policy evaluation.
    """

    def __init__(
        self,
        require_provider: bool = True,
        require_model: bool = True,
        require_user: bool = False,
        require_department: bool = False,
        custom_validators: list[Callable[[EnforcementContext], str | None]] | None = None,
    ) -> None:
        """
        Initialize the request validator.

        Args:
            require_provider: Whether provider is required.
            require_model: Whether model is required.
            require_user: Whether user_id is required.
            require_department: Whether department is required.
            custom_validators: Additional validation functions.
        """
        self._require_provider = require_provider
        self._require_model = require_model
        self._require_user = require_user
        self._require_department = require_department
        self._custom_validators = custom_validators or []

    @property
    def name(self) -> str:
        return "RequestValidator"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.VALIDATION

    def process(self, context: EnforcementContext) -> StageResult:
        """Validate the request."""
        start = time.perf_counter()

        if context.request is None:
            return self._failure_result(
                "No request in context",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        request = context.request
        missing_fields = []

        if self._require_provider and not request.provider:
            missing_fields.append("provider")

        if self._require_model and not request.model:
            missing_fields.append("model")

        if self._require_user and not request.user_id:
            missing_fields.append("user_id")

        if self._require_department and not request.department:
            missing_fields.append("department")

        if missing_fields:
            return self._failure_result(
                f"Missing required fields: {', '.join(missing_fields)}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Run custom validators
        for validator in self._custom_validators:
            error = validator(context)
            if error:
                return self._failure_result(
                    error,
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
        )


class ClassificationEnforcer(Middleware):
    """
    Ensures data classification is provided when required.

    This middleware enforces that requests include data classification
    information, which may be required by organizational policy.
    """

    def __init__(
        self,
        require_classification: bool = True,
        allowed_classifications: set[str] | None = None,
        default_classification: str | None = None,
    ) -> None:
        """
        Initialize the classification enforcer.

        Args:
            require_classification: Whether classification is required.
            allowed_classifications: Set of valid classification values.
            default_classification: Default if not provided (if not required).
        """
        self._require_classification = require_classification
        self._allowed_classifications = allowed_classifications
        self._default_classification = default_classification

    @property
    def name(self) -> str:
        return "ClassificationEnforcer"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.CLASSIFICATION

    def process(self, context: EnforcementContext) -> StageResult:
        """Enforce classification requirements."""
        start = time.perf_counter()

        if context.request is None:
            return self._failure_result(
                "No request in context",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        classification = context.request.data_classification

        if not classification:
            if self._require_classification:
                return self._failure_result(
                    "Data classification is required but not provided",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            elif self._default_classification:
                context.add_modification(
                    "default_classification",
                    self._default_classification,
                )
                context.add_warning(
                    f"Using default classification: {self._default_classification}"
                )

        elif self._allowed_classifications:
            # Check that all classifications are allowed
            if isinstance(classification, (list, tuple)):
                invalid = [
                    c for c in classification
                    if c not in self._allowed_classifications
                ]
            else:
                invalid = (
                    [classification]
                    if classification not in self._allowed_classifications
                    else []
                )

            if invalid:
                return self._failure_result(
                    f"Invalid data classification(s): {', '.join(invalid)}",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
        )


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.

    Attributes:
        capacity: Maximum tokens in the bucket.
        tokens: Current token count.
        refill_rate: Tokens added per second.
        last_refill: Time of last refill.
    """

    capacity: float
    tokens: float
    refill_rate: float
    last_refill: float = field(default_factory=time.time)

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume.

        Returns:
            True if tokens were consumed, False if insufficient.
        """
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now


class RateLimiter(Middleware):
    """
    Implements token bucket rate limiting.

    Rate limits can be applied per user, department, or application.
    """

    def __init__(
        self,
        requests_per_minute: float = 60.0,
        burst_size: float = 10.0,
        key_type: str = "user",
        enabled: bool = True,
    ) -> None:
        """
        Initialize the rate limiter.

        Args:
            requests_per_minute: Maximum requests per minute.
            burst_size: Maximum burst size.
            key_type: What to rate limit by (user, department, source).
            enabled: Whether rate limiting is enabled.
        """
        self._requests_per_minute = requests_per_minute
        self._burst_size = burst_size
        self._key_type = key_type
        self._enabled = enabled
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "RateLimiter"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.VALIDATION

    def process(self, context: EnforcementContext) -> StageResult:
        """Check and apply rate limits."""
        start = time.perf_counter()

        if not self._enabled:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if context.request is None:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Get the rate limit key
        key = self._get_key(context)
        if not key:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Get or create bucket
        bucket = self._get_bucket(key)

        # Try to consume a token
        if not bucket.consume():
            context.short_circuit(Decision.DENY, f"Rate limit exceeded for {self._key_type}: {key}")
            return self._failure_result(
                f"Rate limit exceeded for {self._key_type}: {key}",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
            metadata={"rate_limit_key": key, "tokens_remaining": bucket.tokens},
        )

    def _get_key(self, context: EnforcementContext) -> str:
        """Get the rate limit key from the context."""
        request = context.request
        if request is None:
            return ""

        if self._key_type == "user":
            return request.user_id
        elif self._key_type == "department":
            return request.department
        elif self._key_type == "source":
            return request.source_application
        else:
            return request.user_id

    def _get_bucket(self, key: str) -> TokenBucket:
        """Get or create a token bucket for the key."""
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(
                    capacity=self._burst_size,
                    tokens=self._burst_size,
                    refill_rate=self._requests_per_minute / 60.0,
                )
            return self._buckets[key]

    def reset(self, key: str | None = None) -> None:
        """
        Reset rate limit buckets.

        Args:
            key: Specific key to reset, or None to reset all.
        """
        with self._lock:
            if key:
                self._buckets.pop(key, None)
            else:
                self._buckets.clear()


@dataclass
class BudgetEntry:
    """
    Budget tracking entry.

    Attributes:
        limit: Budget limit in USD.
        spent: Amount spent so far.
        period_start: Start of the budget period.
        period_duration: Duration of the budget period.
    """

    limit: float
    spent: float = 0.0
    period_start: datetime = field(default_factory=datetime.now)
    period_duration: timedelta = field(default_factory=lambda: timedelta(days=30))

    def is_expired(self) -> bool:
        """Check if the budget period has expired."""
        return datetime.now() > self.period_start + self.period_duration

    def reset_if_expired(self) -> None:
        """Reset the budget if the period has expired."""
        if self.is_expired():
            self.spent = 0.0
            self.period_start = datetime.now()

    def can_spend(self, amount: float) -> bool:
        """Check if the amount can be spent within budget."""
        self.reset_if_expired()
        return self.spent + amount <= self.limit

    def spend(self, amount: float) -> bool:
        """
        Record spending.

        Args:
            amount: Amount to spend.

        Returns:
            True if spent successfully, False if over budget.
        """
        self.reset_if_expired()
        if self.spent + amount > self.limit:
            return False
        self.spent += amount
        return True


class CostTracker(Middleware):
    """
    Tracks cumulative costs against budgets.

    Budgets can be set per user, department, or globally.
    """

    def __init__(
        self,
        default_budget: float | None = None,
        budget_period_days: int = 30,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the cost tracker.

        Args:
            default_budget: Default budget limit per key.
            budget_period_days: Budget period in days.
            enabled: Whether cost tracking is enabled.
        """
        self._default_budget = default_budget
        self._budget_period = timedelta(days=budget_period_days)
        self._enabled = enabled
        self._budgets: dict[str, BudgetEntry] = {}
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "CostTracker"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.VALIDATION

    def process(self, context: EnforcementContext) -> StageResult:
        """Check and track costs."""
        start = time.perf_counter()

        if not self._enabled or self._default_budget is None:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        if context.request is None:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        cost = context.request.estimated_cost
        if cost <= 0:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Check user budget
        user_id = context.request.user_id
        if user_id:
            budget = self._get_budget(f"user:{user_id}")
            if not budget.can_spend(cost):
                context.short_circuit(
                    Decision.DENY,
                    f"User budget exceeded (spent: ${budget.spent:.2f}, limit: ${budget.limit:.2f})",
                )
                return self._failure_result(
                    f"User budget exceeded",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        # Check department budget
        department = context.request.department
        if department:
            budget = self._get_budget(f"department:{department}")
            if not budget.can_spend(cost):
                context.short_circuit(
                    Decision.DENY,
                    f"Department budget exceeded (spent: ${budget.spent:.2f}, limit: ${budget.limit:.2f})",
                )
                return self._failure_result(
                    f"Department budget exceeded",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
            metadata={"estimated_cost": cost},
        )

    def record_cost(self, user_id: str, department: str, cost: float) -> None:
        """
        Record a cost after request completion.

        Args:
            user_id: The user who made the request.
            department: The department.
            cost: The actual cost.
        """
        if user_id:
            budget = self._get_budget(f"user:{user_id}")
            budget.spend(cost)
        if department:
            budget = self._get_budget(f"department:{department}")
            budget.spend(cost)

    def set_budget(self, key: str, limit: float) -> None:
        """
        Set a budget for a specific key.

        Args:
            key: Budget key (e.g., "user:john", "department:engineering").
            limit: Budget limit in USD.
        """
        with self._lock:
            self._budgets[key] = BudgetEntry(
                limit=limit,
                period_duration=self._budget_period,
            )

    def get_remaining_budget(self, key: str) -> float:
        """
        Get remaining budget for a key.

        Args:
            key: Budget key.

        Returns:
            Remaining budget in USD.
        """
        budget = self._get_budget(key)
        budget.reset_if_expired()
        return max(0, budget.limit - budget.spent)

    def _get_budget(self, key: str) -> BudgetEntry:
        """Get or create a budget entry."""
        with self._lock:
            if key not in self._budgets:
                self._budgets[key] = BudgetEntry(
                    limit=self._default_budget or float("inf"),
                    period_duration=self._budget_period,
                )
            return self._budgets[key]


class AuditLogger(Middleware):
    """
    Logs all requests and decisions for auditing.

    This middleware runs at the end of the pipeline to record
    the complete enforcement result.
    """

    def __init__(
        self,
        log_func: Callable[[dict[str, Any]], None] | None = None,
        include_metadata: bool = True,
    ) -> None:
        """
        Initialize the audit logger.

        Args:
            log_func: Function to call with audit data.
            include_metadata: Whether to include full metadata.
        """
        self._log_func = log_func
        self._include_metadata = include_metadata
        self._logs: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "AuditLogger"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.LOGGING

    def process(self, context: EnforcementContext) -> StageResult:
        """Log the enforcement result."""
        start = time.perf_counter()

        audit_entry = self._create_audit_entry(context)

        with self._lock:
            self._logs.append(audit_entry)

        if self._log_func:
            try:
                self._log_func(audit_entry)
            except Exception as e:
                context.add_warning(f"Audit logging failed: {e}")

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
            metadata={"audit_id": audit_entry.get("id", "")},
        )

    def _create_audit_entry(self, context: EnforcementContext) -> dict[str, Any]:
        """Create an audit log entry."""
        request = context.request

        entry: dict[str, Any] = {
            "id": context.id,
            "timestamp": datetime.now().isoformat(),
            "request_id": request.request_id if request else None,
            "provider": request.provider if request else None,
            "model": request.model if request else None,
            "user_id": request.user_id if request else None,
            "department": request.department if request else None,
            "decision": context.final_decision.value,
            "applied_rule": context.applied_rule.name if context.applied_rule else None,
            "matched_rules": [r.name for r in context.matched_rules],
            "duration_ms": context.get_total_duration_ms(),
            "warnings": context.warnings,
        }

        if self._include_metadata:
            entry["modifications"] = context.modifications
            entry["stage_results"] = [
                {
                    "stage": r.stage.value,
                    "success": r.success,
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                }
                for r in context.stage_results
            ]

        return entry

    def get_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Get recent audit logs.

        Args:
            limit: Maximum number of logs to return.

        Returns:
            List of audit log entries.
        """
        with self._lock:
            return list(self._logs[-limit:])

    def clear_logs(self) -> None:
        """Clear all stored logs."""
        with self._lock:
            self._logs.clear()
