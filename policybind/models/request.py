"""
Request and response data models for PolicyBind.

This module defines the data structures used to represent AI API requests
that are submitted for policy enforcement and the responses returned
after enforcement decisions are made.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, model_to_dict, model_to_json, utc_now


class Decision(Enum):
    """
    Enumeration of possible enforcement decisions.

    These decisions represent the outcome of policy evaluation for an
    AI API request.
    """

    ALLOW = "ALLOW"
    """Request is permitted to proceed unchanged."""

    DENY = "DENY"
    """Request is blocked and should not proceed."""

    MODIFY = "MODIFY"
    """Request is permitted but has been modified (e.g., PII redacted)."""

    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    """Request requires human approval before proceeding."""


@dataclass(frozen=True)
class AIRequest:
    """
    Represents an incoming AI API request for policy enforcement.

    AIRequest captures all the metadata about an AI API request that is
    needed for policy evaluation. It intentionally does not include the
    actual prompt content for privacy reasons; only a hash is stored.

    This class is immutable (frozen) to ensure request data cannot be
    modified during policy evaluation.

    Attributes:
        id: Unique identifier for the model instance.
        created_at: Timestamp when the instance was created.
        updated_at: Timestamp when the instance was last modified.
        request_id: Unique identifier for this request. Can be provided
            by the caller or auto-generated. Used for correlation with
            responses and audit logs.
        timestamp: When the request was received. Defaults to current
            UTC time if not provided.
        provider: The AI provider being called (e.g., "openai", "anthropic",
            "google", "azure"). Used for provider-specific policies.
        model: The specific model being requested (e.g., "gpt-4", "claude-3",
            "gemini-pro"). Used for model-specific policies.
        prompt_hash: SHA-256 hash of the prompt content. Used for detecting
            duplicate requests and for audit purposes without storing
            actual prompt content.
        estimated_tokens: Estimated number of tokens in the request.
            Used for cost estimation and token-based rate limiting.
        estimated_cost: Estimated cost in USD for this request.
            Used for budget enforcement policies.
        source_application: Identifier for the application making the
            request (e.g., "customer-support-bot", "code-assistant").
            Used for application-specific policies.
        user_id: Identifier for the user initiating the request.
            Used for user-specific policies and auditing.
        department: Department or team the user belongs to (e.g.,
            "engineering", "marketing", "legal"). Used for department
            budget and access policies.
        data_classification: Tuple of data classifications present in
            the request (e.g., ("pii", "financial", "confidential")).
            Used for data handling policies.
        intended_use_case: Description of what the AI is being used for
            (e.g., "summarization", "code-generation", "customer-response").
            Used for use-case-specific policies.
        metadata: Additional key-value metadata about the request.
            Can include custom fields for organization-specific policies.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    request_id: str = ""
    timestamp: datetime = field(default_factory=utc_now)
    provider: str = ""
    model: str = ""
    prompt_hash: str = ""
    estimated_tokens: int = 0
    estimated_cost: float = 0.0
    source_application: str = ""
    user_id: str = ""
    department: str = ""
    data_classification: tuple[str, ...] = field(default_factory=tuple)
    intended_use_case: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Set request_id from id if not provided."""
        if not self.request_id:
            # Use object.__setattr__ because the dataclass is frozen
            object.__setattr__(self, "request_id", self.id)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the request to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the request to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the request's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on request id."""
        if not isinstance(other, AIRequest):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"AIRequest(id={self.id!r}, provider={self.provider!r}, "
            f"model={self.model!r}, user_id={self.user_id!r})"
        )


@dataclass(frozen=True)
class AIResponse:
    """
    Represents the enforcement response for an AI API request.

    AIResponse contains the enforcement decision, the rules that were
    applied, any modifications made to the request, and timing information.
    This is returned after a request is processed through the enforcement
    pipeline.

    This class is immutable (frozen) to ensure response data cannot be
    modified after creation.

    Attributes:
        id: Unique identifier for this response instance.
        created_at: Timestamp when the response was created.
        updated_at: Timestamp when the response was last modified.
        request_id: The ID of the AIRequest this response corresponds to.
            Used for correlation in audit logs.
        decision: The enforcement decision (ALLOW, DENY, MODIFY, or
            REQUIRE_APPROVAL). This determines whether the original
            request should proceed.
        applied_rules: Tuple of rule names that matched the request and
            contributed to the decision. Ordered by priority (highest
            first). Used for auditing and debugging.
        modifications: Dictionary describing any modifications made to
            the request when decision is MODIFY. Structure depends on
            the modification type (e.g., {"redacted_fields": ["ssn"]}).
        enforcement_time_ms: Time taken to process the request through
            the enforcement pipeline, in milliseconds. Used for
            performance monitoring.
        reason: Human-readable explanation of the enforcement decision.
            Should explain why the decision was made and which policies
            were involved. Displayed in audit logs and error messages.
        warnings: Tuple of warning messages generated during enforcement.
            These don't change the decision but indicate potential issues.
        metadata: Additional key-value metadata about the enforcement.
            Can include debug information, trace IDs, etc.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    request_id: str = ""
    decision: Decision = Decision.DENY
    applied_rules: tuple[str, ...] = field(default_factory=tuple)
    modifications: dict[str, Any] = field(default_factory=dict)
    enforcement_time_ms: float = 0.0
    reason: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the response to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the response to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the response's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on response id."""
        if not isinstance(other, AIResponse):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"AIResponse(id={self.id!r}, request_id={self.request_id!r}, "
            f"decision={self.decision.value})"
        )

    def is_allowed(self) -> bool:
        """
        Check if the request is allowed to proceed.

        Returns:
            True if the decision allows the request (ALLOW or MODIFY),
            False otherwise.
        """
        return self.decision in (Decision.ALLOW, Decision.MODIFY)

    def is_denied(self) -> bool:
        """
        Check if the request is denied.

        Returns:
            True if the decision is DENY, False otherwise.
        """
        return self.decision == Decision.DENY

    def requires_approval(self) -> bool:
        """
        Check if the request requires approval.

        Returns:
            True if the decision is REQUIRE_APPROVAL, False otherwise.
        """
        return self.decision == Decision.REQUIRE_APPROVAL
