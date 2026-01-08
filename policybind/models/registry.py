"""
Model registry data models for PolicyBind.

This module defines the data structures used to track AI model deployments
in the registry, including their approval status, risk level, and usage
statistics.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, model_to_dict, model_to_json, utc_now


class RiskLevel(Enum):
    """
    Enumeration of risk levels for AI model deployments.

    Risk levels determine the approval requirements and monitoring
    intensity for a deployment.
    """

    LOW = "LOW"
    """
    Minimal risk. Standard approval process.
    Examples: Internal documentation assistants, code formatters.
    """

    MEDIUM = "MEDIUM"
    """
    Moderate risk. Enhanced review required.
    Examples: Customer-facing bots, data analysis tools.
    """

    HIGH = "HIGH"
    """
    Significant risk. Executive approval required.
    Examples: Financial advice, medical information, legal documents.
    """

    CRITICAL = "CRITICAL"
    """
    Highest risk. Board-level approval and continuous monitoring.
    Examples: Autonomous decision-making, safety-critical applications.
    """


class ApprovalStatus(Enum):
    """
    Enumeration of approval statuses for model deployments.

    Tracks the lifecycle of a deployment through the approval process.
    """

    PENDING = "PENDING"
    """Awaiting initial review and approval."""

    APPROVED = "APPROVED"
    """Approved for use. Deployment is active."""

    REJECTED = "REJECTED"
    """Approval was denied. Deployment cannot be used."""

    SUSPENDED = "SUSPENDED"
    """
    Previously approved but now suspended.
    May be due to policy violations, overdue reviews, or manual action.
    """


@dataclass(frozen=True)
class ModelDeployment:
    """
    Represents a registered AI model deployment in the registry.

    ModelDeployment tracks all metadata about an AI model that has been
    registered for use within the organization. This includes ownership,
    approval status, risk assessment, and compliance information.

    This class is immutable (frozen) to ensure deployment records cannot
    be accidentally modified. Updates should create new records.

    Attributes:
        id: Unique identifier for this model instance.
        created_at: Timestamp when the instance was created.
        updated_at: Timestamp when the instance was last modified.
        deployment_id: Unique identifier for this deployment. Different
            from 'id' which is the base model ID. This is the primary
            identifier used in policies and audit logs.
        name: Human-readable name for the deployment (e.g., "Customer
            Support Bot v2", "Code Review Assistant").
        description: Detailed description of the deployment's purpose,
            capabilities, and intended use cases.
        model_provider: The AI provider (e.g., "openai", "anthropic",
            "google"). Used for vendor management and cost tracking.
        model_name: The specific model being used (e.g., "gpt-4",
            "claude-3-opus", "gemini-pro").
        model_version: Version of the model or deployment configuration.
            Used for tracking updates and rollbacks.
        owner: Username or team identifier responsible for this deployment.
            Receives notifications about reviews and incidents.
        owner_contact: Email or other contact information for the owner.
            Used for urgent notifications and compliance inquiries.
        data_categories: Tuple of data categories this deployment processes
            (e.g., ("pii", "financial", "healthcare")). Used for compliance
            checks and data handling policies.
        risk_level: Assessed risk level for this deployment. Determines
            approval requirements and monitoring intensity.
        approval_status: Current status in the approval workflow.
            Only APPROVED deployments can actively process requests.
        approval_ticket: Reference to the approval ticket or request
            (e.g., JIRA ticket, ServiceNow request). For audit trails.
        deployment_date: When the deployment was first put into production.
            None if not yet deployed.
        last_review_date: When the deployment was last reviewed for
            compliance and continued appropriateness. None if never reviewed.
        next_review_date: When the next scheduled review is due. Based on
            risk level and organization policy.
        metadata: Additional key-value metadata about the deployment.
            Can include custom fields for organization-specific tracking.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    deployment_id: str = ""
    name: str = ""
    description: str = ""
    model_provider: str = ""
    model_name: str = ""
    model_version: str = ""
    owner: str = ""
    owner_contact: str = ""
    data_categories: tuple[str, ...] = field(default_factory=tuple)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_ticket: str = ""
    deployment_date: datetime | None = None
    last_review_date: datetime | None = None
    next_review_date: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Set deployment_id from id if not provided."""
        if not self.deployment_id:
            object.__setattr__(self, "deployment_id", self.id)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the deployment to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the deployment to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the deployment's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on deployment id."""
        if not isinstance(other, ModelDeployment):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"ModelDeployment(id={self.id!r}, name={self.name!r}, "
            f"status={self.approval_status.value}, risk={self.risk_level.value})"
        )

    def is_active(self) -> bool:
        """
        Check if the deployment is active and can process requests.

        Returns:
            True if the deployment is approved and not suspended.
        """
        return self.approval_status == ApprovalStatus.APPROVED

    def is_high_risk(self) -> bool:
        """
        Check if the deployment is classified as high risk or above.

        Returns:
            True if risk level is HIGH or CRITICAL.
        """
        return self.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def needs_review(self, as_of: datetime | None = None) -> bool:
        """
        Check if the deployment is due for review.

        Args:
            as_of: The datetime to check against. Defaults to now.

        Returns:
            True if next_review_date is set and has passed.
        """
        if self.next_review_date is None:
            return False
        check_date = as_of or utc_now()
        return check_date >= self.next_review_date


@dataclass(frozen=True)
class ModelUsageStats:
    """
    Tracks usage statistics for a model deployment over a time period.

    ModelUsageStats aggregates metrics about how a deployment is being
    used, including request counts, token usage, costs, and violations.
    These statistics are used for reporting, billing, and policy
    enforcement (e.g., budget limits).

    This class is immutable (frozen) to ensure statistics cannot be
    modified after collection.

    Attributes:
        id: Unique identifier for this stats record.
        created_at: Timestamp when the stats record was created.
        updated_at: Timestamp when the stats record was last modified.
        deployment_id: The ID of the ModelDeployment these stats are for.
        period_start: Start of the measurement period (inclusive).
        period_end: End of the measurement period (exclusive).
        request_count: Total number of requests processed during the period.
        token_count: Total number of tokens consumed (input + output).
        estimated_cost: Estimated cost in USD for the period.
        error_count: Number of requests that resulted in errors.
        policy_violation_count: Number of requests that violated policies.
            Includes both blocked requests and flagged requests.
        avg_latency_ms: Average enforcement latency in milliseconds.
        p95_latency_ms: 95th percentile enforcement latency.
        unique_users: Number of unique users who made requests.
        top_use_cases: Dictionary mapping use case names to request counts.
        metadata: Additional key-value metadata about the statistics.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    deployment_id: str = ""
    period_start: datetime = field(default_factory=utc_now)
    period_end: datetime = field(default_factory=utc_now)
    request_count: int = 0
    token_count: int = 0
    estimated_cost: float = 0.0
    error_count: int = 0
    policy_violation_count: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    unique_users: int = 0
    top_use_cases: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the stats to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the stats to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the stats record's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on stats id."""
        if not isinstance(other, ModelUsageStats):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"ModelUsageStats(id={self.id!r}, deployment_id={self.deployment_id!r}, "
            f"requests={self.request_count}, cost=${self.estimated_cost:.2f})"
        )

    def error_rate(self) -> float:
        """
        Calculate the error rate for the period.

        Returns:
            Percentage of requests that resulted in errors (0.0 to 100.0).
            Returns 0.0 if there were no requests.
        """
        if self.request_count == 0:
            return 0.0
        return (self.error_count / self.request_count) * 100.0

    def violation_rate(self) -> float:
        """
        Calculate the policy violation rate for the period.

        Returns:
            Percentage of requests that violated policies (0.0 to 100.0).
            Returns 0.0 if there were no requests.
        """
        if self.request_count == 0:
            return 0.0
        return (self.policy_violation_count / self.request_count) * 100.0

    def avg_cost_per_request(self) -> float:
        """
        Calculate the average cost per request.

        Returns:
            Average cost in USD per request. Returns 0.0 if no requests.
        """
        if self.request_count == 0:
            return 0.0
        return self.estimated_cost / self.request_count
