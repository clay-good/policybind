"""
Incident data models for PolicyBind.

This module defines the data structures used for incident management,
including policy violations, AI safety events, and their investigation
workflows.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, model_to_dict, model_to_json, utc_now


class IncidentSeverity(Enum):
    """
    Severity levels for incidents.

    Severity determines the urgency of response and escalation paths.
    """

    LOW = "LOW"
    """
    Minor incident with limited impact.
    Examples: Single policy warning, minor configuration issue.
    """

    MEDIUM = "MEDIUM"
    """
    Moderate incident requiring attention.
    Examples: Repeated violations, potential data exposure.
    """

    HIGH = "HIGH"
    """
    Significant incident requiring immediate response.
    Examples: Confirmed data leak, jailbreak attempt, regulatory concern.
    """

    CRITICAL = "CRITICAL"
    """
    Severe incident requiring emergency response.
    Examples: Active security breach, major data exfiltration, safety failure.
    """


class IncidentStatus(Enum):
    """
    Status values for incident lifecycle.

    Tracks the progress of an incident through investigation and resolution.
    """

    OPEN = "OPEN"
    """Incident is newly created and awaiting triage."""

    INVESTIGATING = "INVESTIGATING"
    """Incident is being actively investigated."""

    RESOLVED = "RESOLVED"
    """
    Incident has been resolved.
    Root cause identified and remediation applied.
    """

    CLOSED = "CLOSED"
    """
    Incident is closed.
    No further action needed or incident was a false positive.
    """


class IncidentType(Enum):
    """
    Types of incidents that can occur.

    Categorizes incidents by their nature for proper routing and handling.
    """

    POLICY_VIOLATION = "POLICY_VIOLATION"
    """Request violated one or more policies."""

    HARMFUL_OUTPUT = "HARMFUL_OUTPUT"
    """Model generated potentially harmful content."""

    JAILBREAK = "JAILBREAK"
    """Attempt to bypass model safety constraints."""

    DATA_LEAK = "DATA_LEAK"
    """Potential or confirmed data exfiltration."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    """Attempt to inject malicious prompts."""

    ABUSE = "ABUSE"
    """Misuse or abuse of AI resources."""

    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    """Token or cost budget was exceeded."""

    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    """Rate limits were exceeded significantly."""

    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    """Attempt to access unauthorized resources or models."""

    ANOMALY = "ANOMALY"
    """Anomalous usage pattern detected."""

    OTHER = "OTHER"
    """Other types of incidents not covered above."""


class TimelineEventType(Enum):
    """
    Types of events that can occur in an incident timeline.
    """

    CREATED = "CREATED"
    """Incident was created."""

    STATUS_CHANGE = "STATUS_CHANGE"
    """Incident status changed."""

    ASSIGNMENT = "ASSIGNMENT"
    """Incident was assigned or reassigned."""

    COMMENT = "COMMENT"
    """Comment was added to the incident."""

    ESCALATION = "ESCALATION"
    """Incident was escalated."""

    SEVERITY_CHANGE = "SEVERITY_CHANGE"
    """Incident severity was changed."""

    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    """Evidence was added to the incident."""

    RELATED_INCIDENT = "RELATED_INCIDENT"
    """Related incident was linked."""

    REMEDIATION = "REMEDIATION"
    """Remediation action was taken."""

    NOTIFICATION = "NOTIFICATION"
    """Notification was sent."""


@dataclass(frozen=True)
class Incident:
    """
    Represents an incident record for policy violations and AI safety events.

    Incidents track issues discovered through policy enforcement, manual
    reporting, or automated detection. They follow a workflow from creation
    through investigation to resolution.

    This class is immutable (frozen) to ensure incident records maintain
    their integrity. Updates should create new records with updated values.

    Attributes:
        id: Unique identifier for the database record.
        created_at: Timestamp when the incident was created.
        updated_at: Timestamp when the incident was last modified.
        incident_id: Unique identifier for the incident. This is the
            primary identifier used in workflows and reports.
        severity: Severity level of the incident.
        status: Current status in the incident lifecycle.
        incident_type: Type/category of the incident.
        title: Short, descriptive title for the incident.
        description: Detailed description of what occurred.
        source_request_id: ID of the request that triggered the incident,
            if applicable. Links to enforcement logs.
        deployment_id: ID of the model deployment involved, if applicable.
            Links to the model registry.
        evidence: Dictionary containing relevant evidence data such as
            prompt hashes, response samples, policy matches, etc.
        assignee: Username or identifier of the person investigating.
        resolution: Description of how the incident was resolved.
        root_cause: Identified root cause of the incident.
        tags: Tags for categorization and searching.
        resolved_at: Timestamp when the incident was resolved.
        related_incidents: IDs of related incidents.
        metadata: Additional key-value metadata about the incident.
    """

    id: str = field(default_factory=generate_uuid)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    incident_id: str = field(default_factory=generate_uuid)
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    incident_type: IncidentType = IncidentType.OTHER
    title: str = ""
    description: str = ""
    source_request_id: str | None = None
    deployment_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    assignee: str | None = None
    resolution: str | None = None
    root_cause: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    resolved_at: datetime | None = None
    related_incidents: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the incident to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the incident to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __hash__(self) -> int:
        """Return hash based on the incident's id."""
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        """Check equality based on incident id."""
        if not isinstance(other, Incident):
            return NotImplemented
        return self.id == other.id

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"Incident(id={self.incident_id!r}, title={self.title!r}, "
            f"severity={self.severity.value}, status={self.status.value})"
        )

    def is_open(self) -> bool:
        """Check if the incident is still open (not resolved or closed)."""
        return self.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)

    def is_high_priority(self) -> bool:
        """Check if the incident is high priority (HIGH or CRITICAL severity)."""
        return self.severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL)

    def is_assigned(self) -> bool:
        """Check if the incident has been assigned to someone."""
        return self.assignee is not None and self.assignee != ""

    def has_resolution(self) -> bool:
        """Check if the incident has a resolution."""
        return self.resolution is not None and self.resolution != ""


@dataclass(frozen=True)
class IncidentComment:
    """
    Represents a comment or note on an incident.

    Comments track the investigation progress, findings, and discussions
    related to an incident.

    Attributes:
        id: Unique identifier for the comment.
        incident_id: ID of the incident this comment belongs to.
        author: Username or identifier of the comment author.
        content: The comment text content.
        created_at: Timestamp when the comment was created.
        metadata: Additional key-value metadata about the comment.
    """

    id: int = 0
    incident_id: str = ""
    author: str = ""
    content: str = ""
    created_at: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the comment to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the comment to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return f"IncidentComment(id={self.id}, author={self.author!r}, content={preview!r})"


@dataclass(frozen=True)
class IncidentTimelineEntry:
    """
    Represents an entry in the incident timeline.

    The timeline tracks all changes and events related to an incident,
    providing a complete audit trail.

    Attributes:
        id: Unique identifier for the timeline entry.
        incident_id: ID of the incident this entry belongs to.
        event_type: Type of event that occurred.
        old_value: Previous value (for changes).
        new_value: New value (for changes).
        actor: Username or identifier of who performed the action.
        timestamp: When the event occurred.
        metadata: Additional key-value metadata about the event.
    """

    id: int = 0
    incident_id: str = ""
    event_type: TimelineEventType = TimelineEventType.CREATED
    old_value: str | None = None
    new_value: str | None = None
    actor: str | None = None
    timestamp: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the timeline entry to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the timeline entry to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"IncidentTimelineEntry(id={self.id}, event={self.event_type.value}, "
            f"actor={self.actor!r})"
        )


@dataclass(frozen=True)
class IncidentMetrics:
    """
    Aggregated metrics for incident tracking and reporting.

    Provides summary statistics about incidents for a given time period
    or set of filters.

    Attributes:
        total_count: Total number of incidents.
        open_count: Number of open incidents.
        investigating_count: Number of incidents being investigated.
        resolved_count: Number of resolved incidents.
        closed_count: Number of closed incidents.
        by_severity: Count of incidents by severity level.
        by_type: Count of incidents by incident type.
        by_deployment: Count of incidents by deployment ID.
        mean_time_to_acknowledge_hours: Average time to first assignment.
        mean_time_to_resolve_hours: Average time from creation to resolution.
        period_start: Start of the metrics period.
        period_end: End of the metrics period.
    """

    total_count: int = 0
    open_count: int = 0
    investigating_count: int = 0
    resolved_count: int = 0
    closed_count: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    by_deployment: dict[str, int] = field(default_factory=dict)
    mean_time_to_acknowledge_hours: float | None = None
    mean_time_to_resolve_hours: float | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the metrics to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the metrics to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"IncidentMetrics(total={self.total_count}, open={self.open_count}, "
            f"resolved={self.resolved_count})"
        )

    @property
    def resolution_rate(self) -> float:
        """
        Calculate the percentage of incidents that have been resolved.

        Returns:
            Resolution rate as a percentage (0.0 to 100.0).
        """
        if self.total_count == 0:
            return 0.0
        return ((self.resolved_count + self.closed_count) / self.total_count) * 100.0


@dataclass
class DetectionRule:
    """
    A rule for automatically detecting incidents from enforcement logs.

    Detection rules define patterns that, when matched, trigger automatic
    incident creation.

    Attributes:
        rule_id: Unique identifier for the rule.
        name: Human-readable name for the rule.
        description: Detailed description of what the rule detects.
        enabled: Whether the rule is currently active.
        severity: Severity to assign to detected incidents.
        incident_type: Type to assign to detected incidents.
        condition: Dictionary defining the detection condition.
        threshold: Number of occurrences before triggering.
        window_minutes: Time window for counting occurrences.
        cooldown_minutes: Minimum time between incident creation.
        auto_assign: Username to auto-assign incidents to.
        tags: Tags to apply to detected incidents.
        metadata: Additional key-value metadata about the rule.
    """

    rule_id: str = field(default_factory=generate_uuid)
    name: str = ""
    description: str = ""
    enabled: bool = True
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    incident_type: IncidentType = IncidentType.ANOMALY
    condition: dict[str, Any] = field(default_factory=dict)
    threshold: int = 1
    window_minutes: int = 60
    cooldown_minutes: int = 30
    auto_assign: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert the rule to a dictionary."""
        return model_to_dict(self, exclude_none)

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert the rule to a JSON string."""
        return model_to_json(self, indent, exclude_none)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        return (
            f"DetectionRule(id={self.rule_id!r}, name={self.name!r}, "
            f"enabled={self.enabled})"
        )
