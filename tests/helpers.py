"""
Test utilities and helpers for PolicyBind tests.

This module provides:
- Factory functions for creating test objects
- Assertion helpers for common checks
- Mock implementations for external dependencies
- Performance timing utilities
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Generator, Optional, TypeVar, List, Dict
from unittest.mock import MagicMock

from policybind.models.base import utc_now, generate_uuid
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision
from policybind.models.registry import (
    ApprovalStatus,
    ModelDeployment,
    RiskLevel,
)
from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    Token,
    TokenPermissions,
    TokenStatus,
)
from policybind.incidents.models import (
    Incident,
    IncidentComment,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
)


# =============================================================================
# Type Variables
# =============================================================================

T = TypeVar("T")


# =============================================================================
# Factory Functions - Policy Objects
# =============================================================================


class PolicyFactory:
    """Factory for creating policy-related test objects."""

    @staticmethod
    def create_rule(
        name: str | None = None,
        action: str = "ALLOW",
        priority: int = 100,
        match_conditions: dict[str, Any] | None = None,
        description: str | None = None,
        enabled: bool = True,
        tags: list[str] | None = None,
    ) -> PolicyRule:
        """Create a PolicyRule with sensible defaults.

        Args:
            name: Rule name (auto-generated if not provided).
            action: Action type (ALLOW, DENY, etc.).
            priority: Rule priority (higher = evaluated first).
            match_conditions: Conditions for matching requests.
            description: Optional description.
            enabled: Whether the rule is active.
            tags: Optional list of tags.

        Returns:
            A PolicyRule instance.
        """
        return PolicyRule(
            name=name or f"test-rule-{generate_uuid()[:8]}",
            action=action,
            priority=priority,
            match_conditions=match_conditions or {},
            description=description or "Test rule",
            enabled=enabled,
            tags=tags or [],
        )

    @staticmethod
    def create_policy_set(
        name: str | None = None,
        version: str = "1.0.0",
        rules: list[PolicyRule] | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PolicySet:
        """Create a PolicySet with sensible defaults.

        Args:
            name: Policy set name (auto-generated if not provided).
            version: Version string.
            rules: List of rules (empty if not provided).
            description: Optional description.
            metadata: Optional metadata dict.

        Returns:
            A PolicySet instance.
        """
        return PolicySet(
            name=name or f"test-policy-{generate_uuid()[:8]}",
            version=version,
            rules=rules or [],
            description=description or "Test policy set",
            metadata=metadata or {},
        )

    @staticmethod
    def create_allow_all_policy() -> PolicySet:
        """Create a policy set that allows all requests."""
        return PolicySet(
            name="allow-all-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    priority=1,
                    match_conditions={},
                    description="Allow all requests",
                ),
            ],
        )

    @staticmethod
    def create_deny_all_policy() -> PolicySet:
        """Create a policy set that denies all requests."""
        return PolicySet(
            name="deny-all-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="deny-all",
                    action="DENY",
                    priority=1,
                    match_conditions={},
                    description="Deny all requests",
                ),
            ],
        )


# =============================================================================
# Factory Functions - Request Objects
# =============================================================================


class RequestFactory:
    """Factory for creating request-related test objects."""

    @staticmethod
    def create_request(
        provider: str = "openai",
        model: str = "gpt-4",
        user_id: str | None = None,
        department: str | None = None,
        data_classification: tuple[str, ...] | None = None,
        request_id: str | None = None,
        **kwargs: Any,
    ) -> AIRequest:
        """Create an AIRequest with sensible defaults.

        Args:
            provider: AI provider name.
            model: Model name.
            user_id: User identifier (auto-generated if not provided).
            department: Department name.
            data_classification: Data classification tuple.
            request_id: Request ID (auto-generated if not provided).
            **kwargs: Additional request attributes.

        Returns:
            An AIRequest instance.
        """
        return AIRequest(
            request_id=request_id or generate_uuid(),
            provider=provider,
            model=model,
            user_id=user_id or f"test-user-{generate_uuid()[:8]}",
            department=department,
            data_classification=data_classification,
            **kwargs,
        )

    @staticmethod
    def create_response(
        decision: Decision = Decision.ALLOW,
        request_id: str | None = None,
        reason: str | None = None,
        applied_rules: list[str] | None = None,
        modifications: dict[str, Any] | None = None,
        enforcement_time_ms: float = 1.0,
    ) -> AIResponse:
        """Create an AIResponse with sensible defaults.

        Args:
            decision: The enforcement decision.
            request_id: Request ID (auto-generated if not provided).
            reason: Reason for the decision.
            applied_rules: List of applied rule names.
            modifications: Any modifications applied.
            enforcement_time_ms: Time taken for enforcement.

        Returns:
            An AIResponse instance.
        """
        return AIResponse(
            request_id=request_id or generate_uuid(),
            decision=decision,
            reason=reason or f"Test response: {decision.value}",
            applied_rules=applied_rules or [],
            modifications=modifications or {},
            enforcement_time_ms=enforcement_time_ms,
        )


# =============================================================================
# Factory Functions - Registry Objects
# =============================================================================


class RegistryFactory:
    """Factory for creating registry-related test objects."""

    @staticmethod
    def create_deployment(
        name: str | None = None,
        model_provider: str = "openai",
        model_name: str = "gpt-4",
        owner: str | None = None,
        owner_contact: str | None = None,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        approval_status: ApprovalStatus = ApprovalStatus.PENDING,
        deployment_id: str | None = None,
        description: str | None = None,
        data_categories: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ModelDeployment:
        """Create a ModelDeployment with sensible defaults.

        Args:
            name: Deployment name (auto-generated if not provided).
            model_provider: AI provider name.
            model_name: Model name.
            owner: Owner identifier (auto-generated if not provided).
            owner_contact: Owner contact email.
            risk_level: Risk level assessment.
            approval_status: Current approval status.
            deployment_id: Deployment ID (auto-generated if not provided).
            description: Optional description.
            data_categories: List of data categories.
            metadata: Optional metadata dict.

        Returns:
            A ModelDeployment instance.
        """
        owner_id = owner or f"test-team-{generate_uuid()[:8]}"
        return ModelDeployment(
            deployment_id=deployment_id or generate_uuid(),
            name=name or f"test-deployment-{generate_uuid()[:8]}",
            description=description or "Test deployment",
            model_provider=model_provider,
            model_name=model_name,
            owner=owner_id,
            owner_contact=owner_contact or f"{owner_id}@example.com",
            risk_level=risk_level,
            approval_status=approval_status,
            data_categories=data_categories or [],
            metadata=metadata or {},
        )


# =============================================================================
# Factory Functions - Token Objects
# =============================================================================


class TokenFactory:
    """Factory for creating token-related test objects."""

    @staticmethod
    def create_permissions(
        allowed_models: list[str] | None = None,
        denied_models: list[str] | None = None,
        budget_limit: float | None = None,
        budget_period: BudgetPeriod | None = None,
        rate_limit: RateLimit | None = None,
    ) -> TokenPermissions:
        """Create TokenPermissions with sensible defaults.

        Args:
            allowed_models: List of allowed model patterns.
            denied_models: List of denied model patterns.
            budget_limit: Budget limit amount.
            budget_period: Budget period (daily, weekly, monthly).
            rate_limit: Rate limit configuration.

        Returns:
            A TokenPermissions instance.
        """
        return TokenPermissions(
            allowed_models=allowed_models,
            denied_models=denied_models,
            budget_limit=budget_limit,
            budget_period=budget_period,
            rate_limit=rate_limit,
        )

    @staticmethod
    def create_token(
        name: str | None = None,
        subject: str | None = None,
        token_id: str | None = None,
        status: TokenStatus = TokenStatus.ACTIVE,
        permissions: TokenPermissions | None = None,
        expires_at: datetime | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Token:
        """Create a Token with sensible defaults.

        Args:
            name: Token name (auto-generated if not provided).
            subject: Token subject (auto-generated if not provided).
            token_id: Token ID (auto-generated if not provided).
            status: Token status.
            permissions: Token permissions.
            expires_at: Expiration time.
            tags: List of tags.
            metadata: Optional metadata dict.

        Returns:
            A Token instance.
        """
        now = utc_now()
        return Token(
            token_id=token_id or generate_uuid(),
            name=name or f"test-token-{generate_uuid()[:8]}",
            subject=subject or f"test-user-{generate_uuid()[:8]}@example.com",
            token_hash="test-hash-" + generate_uuid(),
            status=status,
            permissions=permissions or TokenPermissions(),
            issued_at=now,
            expires_at=expires_at or (now + timedelta(days=30)),
            issuer="test-issuer",
            tags=tags or [],
            metadata=metadata or {},
        )


# =============================================================================
# Factory Functions - Incident Objects
# =============================================================================


class IncidentFactory:
    """Factory for creating incident-related test objects."""

    @staticmethod
    def create_incident(
        title: str | None = None,
        incident_type: IncidentType = IncidentType.POLICY_VIOLATION,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        status: IncidentStatus = IncidentStatus.OPEN,
        incident_id: str | None = None,
        description: str | None = None,
        deployment_id: str | None = None,
        assignee: str | None = None,
        tags: list[str] | None = None,
        evidence: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        """Create an Incident with sensible defaults.

        Args:
            title: Incident title (auto-generated if not provided).
            incident_type: Type of incident.
            severity: Severity level.
            status: Current status.
            incident_id: Incident ID (auto-generated if not provided).
            description: Optional description.
            deployment_id: Related deployment ID.
            assignee: Assigned investigator.
            tags: List of tags.
            evidence: Evidence dict.
            metadata: Optional metadata dict.

        Returns:
            An Incident instance.
        """
        return Incident(
            incident_id=incident_id or generate_uuid(),
            title=title or f"Test Incident {generate_uuid()[:8]}",
            description=description or "Test incident description",
            incident_type=incident_type,
            severity=severity,
            status=status,
            deployment_id=deployment_id,
            assignee=assignee,
            tags=tags or [],
            evidence=evidence or {},
            metadata=metadata or {},
        )

    @staticmethod
    def create_comment(
        incident_id: str,
        content: str | None = None,
        author: str | None = None,
        comment_id: str | None = None,
    ) -> IncidentComment:
        """Create an IncidentComment with sensible defaults.

        Args:
            incident_id: Parent incident ID.
            content: Comment content.
            author: Comment author.
            comment_id: Comment ID (auto-generated if not provided).

        Returns:
            An IncidentComment instance.
        """
        return IncidentComment(
            comment_id=comment_id or generate_uuid(),
            incident_id=incident_id,
            author=author or f"test-user-{generate_uuid()[:8]}@example.com",
            content=content or "Test comment content",
            created_at=utc_now(),
        )


# =============================================================================
# Assertion Helpers
# =============================================================================


class AssertHelpers:
    """Helper class for common test assertions."""

    @staticmethod
    def assert_decision(
        response: AIResponse,
        expected_decision: Decision,
        message: str | None = None,
    ) -> None:
        """Assert that a response has the expected decision.

        Args:
            response: The AIResponse to check.
            expected_decision: The expected Decision enum value.
            message: Optional custom error message.
        """
        assert response.decision == expected_decision, (
            message or f"Expected decision {expected_decision.value}, "
            f"got {response.decision.value}: {response.reason}"
        )

    @staticmethod
    def assert_allowed(response: AIResponse, message: str | None = None) -> None:
        """Assert that a response is ALLOW."""
        AssertHelpers.assert_decision(response, Decision.ALLOW, message)

    @staticmethod
    def assert_denied(response: AIResponse, message: str | None = None) -> None:
        """Assert that a response is DENY."""
        AssertHelpers.assert_decision(response, Decision.DENY, message)

    @staticmethod
    def assert_rule_applied(
        response: AIResponse,
        rule_name: str,
        message: str | None = None,
    ) -> None:
        """Assert that a specific rule was applied.

        Args:
            response: The AIResponse to check.
            rule_name: The name of the rule that should have been applied.
            message: Optional custom error message.
        """
        assert rule_name in response.applied_rules, (
            message or f"Expected rule '{rule_name}' to be applied. "
            f"Applied rules: {response.applied_rules}"
        )

    @staticmethod
    def assert_no_rule_applied(
        response: AIResponse,
        rule_name: str,
        message: str | None = None,
    ) -> None:
        """Assert that a specific rule was NOT applied.

        Args:
            response: The AIResponse to check.
            rule_name: The name of the rule that should NOT have been applied.
            message: Optional custom error message.
        """
        assert rule_name not in response.applied_rules, (
            message or f"Expected rule '{rule_name}' NOT to be applied. "
            f"Applied rules: {response.applied_rules}"
        )

    @staticmethod
    def assert_enforcement_time_under(
        response: AIResponse,
        max_ms: float,
        message: str | None = None,
    ) -> None:
        """Assert that enforcement time is under a threshold.

        Args:
            response: The AIResponse to check.
            max_ms: Maximum allowed enforcement time in milliseconds.
            message: Optional custom error message.
        """
        assert response.enforcement_time_ms < max_ms, (
            message or f"Enforcement time {response.enforcement_time_ms}ms "
            f"exceeds limit of {max_ms}ms"
        )

    @staticmethod
    def assert_token_status(
        token: Token,
        expected_status: TokenStatus,
        message: str | None = None,
    ) -> None:
        """Assert that a token has the expected status.

        Args:
            token: The Token to check.
            expected_status: The expected TokenStatus.
            message: Optional custom error message.
        """
        assert token.status == expected_status, (
            message or f"Expected token status {expected_status.value}, "
            f"got {token.status.value}"
        )

    @staticmethod
    def assert_incident_status(
        incident: Incident,
        expected_status: IncidentStatus,
        message: str | None = None,
    ) -> None:
        """Assert that an incident has the expected status.

        Args:
            incident: The Incident to check.
            expected_status: The expected IncidentStatus.
            message: Optional custom error message.
        """
        assert incident.status == expected_status, (
            message or f"Expected incident status {expected_status.value}, "
            f"got {incident.status.value}"
        )


# =============================================================================
# Performance Timing Utilities
# =============================================================================


@dataclass
class TimingResult:
    """Result of a timed operation."""
    elapsed_seconds: float
    elapsed_ms: float
    iterations: int
    avg_ms_per_iteration: float

    def __str__(self) -> str:
        return (
            f"TimingResult(total={self.elapsed_ms:.2f}ms, "
            f"iterations={self.iterations}, "
            f"avg={self.avg_ms_per_iteration:.4f}ms)"
        )


@contextmanager
def timer() -> Generator[dict[str, float], None, None]:
    """Context manager for timing code blocks.

    Usage:
        with timer() as t:
            # code to time
        print(f"Elapsed: {t['elapsed_ms']}ms")

    Yields:
        Dict that will be populated with 'elapsed_seconds' and 'elapsed_ms'.
    """
    result: dict[str, float] = {}
    start = time.perf_counter()
    try:
        yield result
    finally:
        end = time.perf_counter()
        result["elapsed_seconds"] = end - start
        result["elapsed_ms"] = (end - start) * 1000


def time_function(
    func: Callable[[], T],
    iterations: int = 1,
) -> tuple[T, TimingResult]:
    """Time a function over multiple iterations.

    Args:
        func: The function to time (must take no arguments).
        iterations: Number of times to run the function.

    Returns:
        Tuple of (result from last iteration, TimingResult).
    """
    start = time.perf_counter()
    result: T | None = None
    for _ in range(iterations):
        result = func()
    end = time.perf_counter()

    elapsed = end - start
    elapsed_ms = elapsed * 1000
    avg_ms = elapsed_ms / iterations if iterations > 0 else 0

    timing = TimingResult(
        elapsed_seconds=elapsed,
        elapsed_ms=elapsed_ms,
        iterations=iterations,
        avg_ms_per_iteration=avg_ms,
    )

    # result will never be None since iterations >= 1
    assert result is not None
    return result, timing


def benchmark(
    func: Callable[[], Any],
    warmup_iterations: int = 10,
    benchmark_iterations: int = 100,
    name: str | None = None,
) -> TimingResult:
    """Run a benchmark on a function.

    Args:
        func: The function to benchmark.
        warmup_iterations: Number of warmup iterations (not timed).
        benchmark_iterations: Number of benchmark iterations.
        name: Optional name for the benchmark (for logging).

    Returns:
        TimingResult with benchmark statistics.
    """
    # Warmup phase
    for _ in range(warmup_iterations):
        func()

    # Benchmark phase
    _, timing = time_function(func, benchmark_iterations)

    return timing


# =============================================================================
# Mock Implementations
# =============================================================================


class MockNotificationChannel:
    """Mock notification channel for testing."""

    def __init__(self) -> None:
        self.notifications: list[dict[str, Any]] = []

    def send(
        self,
        recipient: str,
        subject: str,
        body: str,
        **kwargs: Any,
    ) -> bool:
        """Record a notification (always succeeds)."""
        self.notifications.append({
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "timestamp": utc_now(),
            **kwargs,
        })
        return True

    def get_notifications_for(self, recipient: str) -> list[dict[str, Any]]:
        """Get all notifications sent to a recipient."""
        return [n for n in self.notifications if n["recipient"] == recipient]

    def clear(self) -> None:
        """Clear all recorded notifications."""
        self.notifications.clear()


class MockEventHandler:
    """Mock event handler for testing event emissions."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def __call__(self, event: Any) -> None:
        """Record an event."""
        self.events.append(event)

    def get_events_of_type(self, event_type: type) -> list[Any]:
        """Get all events of a specific type."""
        return [e for e in self.events if isinstance(e, event_type)]

    def has_event(self, predicate: Callable[[Any], bool]) -> bool:
        """Check if any event matches a predicate."""
        return any(predicate(e) for e in self.events)

    def clear(self) -> None:
        """Clear all recorded events."""
        self.events.clear()


class MockDatabase:
    """Mock database for testing without SQLite.

    Provides in-memory storage that mimics database operations.
    """

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self.closed = False

    def initialize(self) -> None:
        """Initialize mock tables."""
        self.tables = {
            "policies": [],
            "policy_audit_log": [],
            "model_registry": [],
            "model_usage": [],
            "enforcement_log": [],
            "tokens": [],
            "incidents": [],
        }

    def execute(self, query: str, params: tuple = ()) -> MagicMock:
        """Mock execute (returns empty cursor)."""
        cursor = MagicMock()
        cursor.fetchall.return_value = []
        cursor.fetchone.return_value = None
        return cursor

    def commit(self) -> None:
        """Mock commit (no-op)."""
        pass

    def close(self) -> None:
        """Mark as closed."""
        self.closed = True

    def is_healthy(self) -> bool:
        """Check if mock database is healthy."""
        return not self.closed


# =============================================================================
# Test Data Generators
# =============================================================================


def generate_test_requests(
    count: int,
    providers: list[str] | None = None,
    models: list[str] | None = None,
    departments: list[str] | None = None,
) -> list[AIRequest]:
    """Generate multiple test requests with varied attributes.

    Args:
        count: Number of requests to generate.
        providers: List of providers to rotate through.
        models: List of models to rotate through.
        departments: List of departments to rotate through.

    Returns:
        List of AIRequest instances.
    """
    providers = providers or ["openai", "anthropic", "google"]
    models = models or ["gpt-4", "gpt-3.5-turbo", "claude-3"]
    departments = departments or ["engineering", "finance", "marketing", "hr"]

    requests = []
    for i in range(count):
        requests.append(
            RequestFactory.create_request(
                provider=providers[i % len(providers)],
                model=models[i % len(models)],
                department=departments[i % len(departments)],
                user_id=f"user-{i}",
            )
        )
    return requests


def generate_test_tokens(
    count: int,
    status: TokenStatus = TokenStatus.ACTIVE,
) -> list[Token]:
    """Generate multiple test tokens.

    Args:
        count: Number of tokens to generate.
        status: Status for all generated tokens.

    Returns:
        List of Token instances.
    """
    return [
        TokenFactory.create_token(
            name=f"token-{i}",
            subject=f"user-{i}@example.com",
            status=status,
        )
        for i in range(count)
    ]


def generate_test_incidents(
    count: int,
    severity_distribution: dict[IncidentSeverity, int] | None = None,
) -> list[Incident]:
    """Generate multiple test incidents.

    Args:
        count: Number of incidents to generate.
        severity_distribution: Optional dict mapping severity to count.
            If not provided, generates evenly across severities.

    Returns:
        List of Incident instances.
    """
    if severity_distribution:
        incidents = []
        for severity, num in severity_distribution.items():
            for i in range(num):
                incidents.append(
                    IncidentFactory.create_incident(
                        title=f"Incident {len(incidents) + 1}",
                        severity=severity,
                    )
                )
        return incidents

    severities = list(IncidentSeverity)
    return [
        IncidentFactory.create_incident(
            title=f"Incident {i + 1}",
            severity=severities[i % len(severities)],
        )
        for i in range(count)
    ]
