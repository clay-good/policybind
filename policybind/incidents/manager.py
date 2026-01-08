"""
Incident management for PolicyBind.

This module provides the IncidentManager class for creating, tracking,
and managing incidents related to policy violations and AI safety events.
"""

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from policybind.exceptions import IncidentError
from policybind.incidents.models import (
    Incident,
    IncidentComment,
    IncidentMetrics,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    IncidentType,
    TimelineEventType,
)
from policybind.models.base import generate_uuid, utc_now
from policybind.storage import IncidentRepository


# Type alias for incident callbacks
IncidentCallback = Callable[["IncidentEvent"], None]


@dataclass
class IncidentEvent:
    """
    Event emitted when an incident state changes.

    Attributes:
        event_type: Type of event that occurred.
        incident_id: ID of the incident.
        incident: The incident at the time of the event.
        actor: Who triggered the event.
        old_value: Previous value (for changes).
        new_value: New value (for changes).
        timestamp: When the event occurred.
    """

    event_type: TimelineEventType
    incident_id: str
    incident: Incident
    actor: str | None = None
    old_value: str | None = None
    new_value: str | None = None
    timestamp: datetime | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = utc_now()


class IncidentManager:
    """
    Manages the lifecycle of incidents for policy violations and AI safety events.

    The IncidentManager provides functionality to:
    - Create incidents from policy violations or manual reports
    - Update incident status through investigation workflow
    - Link related incidents
    - Track incident metrics and trends
    - Emit events for incident state changes

    Example:
        Using the IncidentManager::

            from policybind.incidents import IncidentManager, IncidentType, IncidentSeverity
            from policybind.storage import Database, IncidentRepository

            db = Database()
            repository = IncidentRepository(db)
            manager = IncidentManager(repository)

            # Create an incident from a policy violation
            incident = manager.create_from_violation(
                request_id="req-123",
                policy_rule="deny-pii-access",
                description="Request attempted to access PII data",
                severity=IncidentSeverity.HIGH,
            )

            # Assign the incident
            manager.assign(incident.incident_id, "security-team", actor="admin")

            # Add investigation notes
            manager.add_comment(
                incident.incident_id,
                author="analyst",
                content="Investigating source of request",
            )

            # Resolve the incident
            manager.resolve(
                incident.incident_id,
                resolution="Revoked token and updated policy",
                root_cause="Misconfigured token permissions",
                actor="analyst",
            )
    """

    def __init__(
        self,
        repository: IncidentRepository,
    ) -> None:
        """
        Initialize the IncidentManager.

        Args:
            repository: Repository for incident persistence.
        """
        self._repository = repository
        self._callbacks: list[IncidentCallback] = []
        self._lock = threading.RLock()

    # -------------------------------------------------------------------------
    # Incident Creation
    # -------------------------------------------------------------------------

    def create(
        self,
        title: str,
        incident_type: IncidentType,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        description: str = "",
        source_request_id: str | None = None,
        deployment_id: str | None = None,
        evidence: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        """
        Create a new incident.

        Args:
            title: Short, descriptive title for the incident.
            incident_type: Type/category of the incident.
            severity: Severity level of the incident.
            description: Detailed description of what occurred.
            source_request_id: ID of the triggering request.
            deployment_id: ID of the involved model deployment.
            evidence: Dictionary containing relevant evidence data.
            tags: Tags for categorization.
            metadata: Additional metadata.

        Returns:
            The created Incident.

        Raises:
            IncidentError: If incident creation fails.
        """
        with self._lock:
            try:
                incident_id = self._repository.create(
                    title=title,
                    incident_type=incident_type.value,
                    severity=severity.value,
                    description=description,
                    source_request_id=source_request_id,
                    deployment_id=deployment_id,
                    evidence=evidence,
                    tags=tags,
                    metadata=metadata,
                )

                incident = self.get(incident_id)
                if incident is None:
                    raise IncidentError(
                        "Failed to create incident",
                        {"title": title, "type": incident_type.value},
                    )

                self._emit_event(
                    TimelineEventType.CREATED,
                    incident,
                    new_value="OPEN",
                )

                return incident

            except IncidentError:
                raise
            except Exception as e:
                raise IncidentError(
                    f"Failed to create incident: {e}",
                    {"title": title, "type": incident_type.value},
                ) from e

    def create_from_violation(
        self,
        request_id: str,
        policy_rule: str,
        description: str,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        deployment_id: str | None = None,
        user_id: str | None = None,
        additional_evidence: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        """
        Create an incident from a policy violation.

        Args:
            request_id: ID of the request that violated the policy.
            policy_rule: Name of the violated policy rule.
            description: Description of the violation.
            severity: Severity level.
            deployment_id: ID of the involved model deployment.
            user_id: ID of the user who made the request.
            additional_evidence: Additional evidence to include.
            metadata: Additional metadata.

        Returns:
            The created Incident.
        """
        evidence: dict[str, Any] = {
            "request_id": request_id,
            "policy_rule": policy_rule,
        }
        if user_id:
            evidence["user_id"] = user_id
        if additional_evidence:
            evidence.update(additional_evidence)

        title = f"Policy violation: {policy_rule}"

        return self.create(
            title=title,
            incident_type=IncidentType.POLICY_VIOLATION,
            severity=severity,
            description=description,
            source_request_id=request_id,
            deployment_id=deployment_id,
            evidence=evidence,
            tags=["policy-violation", policy_rule],
            metadata=metadata,
        )

    def create_from_detection(
        self,
        detection_rule: str,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        description: str,
        evidence: dict[str, Any],
        source_request_id: str | None = None,
        deployment_id: str | None = None,
        auto_assign: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        """
        Create an incident from automated detection.

        Args:
            detection_rule: Name of the detection rule that triggered.
            incident_type: Type of incident.
            severity: Severity level.
            description: Description of what was detected.
            evidence: Evidence collected by the detector.
            source_request_id: ID of a triggering request if applicable.
            deployment_id: ID of the involved deployment if applicable.
            auto_assign: Username to auto-assign the incident to.
            tags: Tags for categorization.
            metadata: Additional metadata.

        Returns:
            The created Incident.
        """
        all_tags = list(tags) if tags else []
        all_tags.append("auto-detected")
        all_tags.append(f"rule:{detection_rule}")

        evidence_with_rule = dict(evidence)
        evidence_with_rule["detection_rule"] = detection_rule

        title = f"Detected: {detection_rule}"

        incident = self.create(
            title=title,
            incident_type=incident_type,
            severity=severity,
            description=description,
            source_request_id=source_request_id,
            deployment_id=deployment_id,
            evidence=evidence_with_rule,
            tags=all_tags,
            metadata=metadata,
        )

        if auto_assign:
            incident = self.assign(incident.incident_id, auto_assign, actor="system")

        return incident

    # -------------------------------------------------------------------------
    # Incident Retrieval
    # -------------------------------------------------------------------------

    def get(self, incident_id: str) -> Incident | None:
        """
        Get an incident by ID.

        Args:
            incident_id: The incident ID.

        Returns:
            The Incident if found, None otherwise.
        """
        data = self._repository.get_by_id(incident_id)
        if data is None:
            return None
        return self._dict_to_incident(data)

    def get_or_raise(self, incident_id: str) -> Incident:
        """
        Get an incident by ID, raising if not found.

        Args:
            incident_id: The incident ID.

        Returns:
            The Incident.

        Raises:
            IncidentError: If incident is not found.
        """
        incident = self.get(incident_id)
        if incident is None:
            raise IncidentError(
                f"Incident not found: {incident_id}",
                {"incident_id": incident_id},
            )
        return incident

    def list_incidents(
        self,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        incident_type: IncidentType | None = None,
        deployment_id: str | None = None,
        assignee: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Incident]:
        """
        List incidents with optional filters.

        Args:
            status: Filter by status.
            severity: Filter by severity.
            incident_type: Filter by type.
            deployment_id: Filter by deployment.
            assignee: Filter by assignee.
            limit: Maximum number of incidents to return.
            offset: Number of incidents to skip.

        Returns:
            List of matching Incidents.
        """
        data_list = self._repository.list_all(
            status=status.value if status else None,
            severity=severity.value if severity else None,
            incident_type=incident_type.value if incident_type else None,
            deployment_id=deployment_id,
            assignee=assignee,
            limit=limit,
            offset=offset,
        )
        return [self._dict_to_incident(d) for d in data_list]

    def get_open_incidents(self) -> list[Incident]:
        """
        Get all open incidents.

        Returns:
            List of open Incidents sorted by severity and creation time.
        """
        data_list = self._repository.get_open()
        return [self._dict_to_incident(d) for d in data_list]

    def get_incidents_by_deployment(
        self,
        deployment_id: str,
        include_closed: bool = False,
    ) -> list[Incident]:
        """
        Get all incidents for a specific deployment.

        Args:
            deployment_id: The deployment ID.
            include_closed: Whether to include closed incidents.

        Returns:
            List of Incidents for the deployment.
        """
        incidents = self.list_incidents(deployment_id=deployment_id)
        if not include_closed:
            incidents = [
                i for i in incidents if i.status != IncidentStatus.CLOSED
            ]
        return incidents

    # -------------------------------------------------------------------------
    # Status Management
    # -------------------------------------------------------------------------

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        actor: str | None = None,
    ) -> Incident:
        """
        Update the status of an incident.

        Args:
            incident_id: The incident ID.
            status: New status.
            actor: Who is making the change.

        Returns:
            The updated Incident.

        Raises:
            IncidentError: If update fails or transition is invalid.
        """
        with self._lock:
            incident = self.get_or_raise(incident_id)
            old_status = incident.status

            # Validate status transition
            if not self._is_valid_transition(old_status, status):
                raise IncidentError(
                    f"Invalid status transition: {old_status.value} -> {status.value}",
                    {
                        "incident_id": incident_id,
                        "old_status": old_status.value,
                        "new_status": status.value,
                    },
                )

            success = self._repository.update_status(
                incident_id, status.value, actor
            )
            if not success:
                raise IncidentError(
                    f"Failed to update incident status: {incident_id}",
                    {"incident_id": incident_id, "status": status.value},
                )

            updated = self.get_or_raise(incident_id)
            self._emit_event(
                TimelineEventType.STATUS_CHANGE,
                updated,
                actor=actor,
                old_value=old_status.value,
                new_value=status.value,
            )
            return updated

    def start_investigation(
        self,
        incident_id: str,
        actor: str | None = None,
    ) -> Incident:
        """
        Move an incident to INVESTIGATING status.

        Args:
            incident_id: The incident ID.
            actor: Who is starting the investigation.

        Returns:
            The updated Incident.
        """
        return self.update_status(incident_id, IncidentStatus.INVESTIGATING, actor)

    def resolve(
        self,
        incident_id: str,
        resolution: str,
        root_cause: str | None = None,
        actor: str | None = None,
    ) -> Incident:
        """
        Resolve an incident.

        Args:
            incident_id: The incident ID.
            resolution: Description of how the incident was resolved.
            root_cause: Identified root cause.
            actor: Who is resolving the incident.

        Returns:
            The updated Incident.
        """
        with self._lock:
            incident = self.get_or_raise(incident_id)

            # Update resolution and root cause
            success = self._repository.set_resolution(
                incident_id, resolution, root_cause
            )
            if not success:
                raise IncidentError(
                    f"Failed to set resolution: {incident_id}",
                    {"incident_id": incident_id},
                )

            # Update status to RESOLVED
            return self.update_status(incident_id, IncidentStatus.RESOLVED, actor)

    def close(
        self,
        incident_id: str,
        actor: str | None = None,
    ) -> Incident:
        """
        Close an incident.

        Args:
            incident_id: The incident ID.
            actor: Who is closing the incident.

        Returns:
            The updated Incident.
        """
        return self.update_status(incident_id, IncidentStatus.CLOSED, actor)

    def reopen(
        self,
        incident_id: str,
        reason: str,
        actor: str | None = None,
    ) -> Incident:
        """
        Reopen a closed or resolved incident.

        Args:
            incident_id: The incident ID.
            reason: Reason for reopening.
            actor: Who is reopening the incident.

        Returns:
            The updated Incident.
        """
        with self._lock:
            # Add comment explaining why it was reopened
            self.add_comment(
                incident_id,
                author=actor or "system",
                content=f"Incident reopened: {reason}",
            )

            # Update status back to OPEN
            return self.update_status(incident_id, IncidentStatus.OPEN, actor)

    # -------------------------------------------------------------------------
    # Assignment
    # -------------------------------------------------------------------------

    def assign(
        self,
        incident_id: str,
        assignee: str,
        actor: str | None = None,
    ) -> Incident:
        """
        Assign an incident to someone.

        Args:
            incident_id: The incident ID.
            assignee: Username to assign to.
            actor: Who is making the assignment.

        Returns:
            The updated Incident.
        """
        with self._lock:
            incident = self.get_or_raise(incident_id)
            old_assignee = incident.assignee

            success = self._repository.assign(incident_id, assignee, actor)
            if not success:
                raise IncidentError(
                    f"Failed to assign incident: {incident_id}",
                    {"incident_id": incident_id, "assignee": assignee},
                )

            updated = self.get_or_raise(incident_id)
            self._emit_event(
                TimelineEventType.ASSIGNMENT,
                updated,
                actor=actor,
                old_value=old_assignee,
                new_value=assignee,
            )
            return updated

    def unassign(
        self,
        incident_id: str,
        actor: str | None = None,
    ) -> Incident:
        """
        Remove the assignee from an incident.

        Args:
            incident_id: The incident ID.
            actor: Who is removing the assignment.

        Returns:
            The updated Incident.
        """
        with self._lock:
            incident = self.get_or_raise(incident_id)
            old_assignee = incident.assignee

            success = self._repository.unassign(incident_id)
            if not success:
                raise IncidentError(
                    f"Failed to unassign incident: {incident_id}",
                    {"incident_id": incident_id},
                )

            updated = self.get_or_raise(incident_id)
            self._emit_event(
                TimelineEventType.ASSIGNMENT,
                updated,
                actor=actor,
                old_value=old_assignee,
                new_value=None,
            )
            return updated

    # -------------------------------------------------------------------------
    # Severity Management
    # -------------------------------------------------------------------------

    def update_severity(
        self,
        incident_id: str,
        severity: IncidentSeverity,
        reason: str | None = None,
        actor: str | None = None,
    ) -> Incident:
        """
        Update the severity of an incident.

        Args:
            incident_id: The incident ID.
            severity: New severity level.
            reason: Reason for the change.
            actor: Who is making the change.

        Returns:
            The updated Incident.
        """
        with self._lock:
            incident = self.get_or_raise(incident_id)
            old_severity = incident.severity

            success = self._repository.update_severity(
                incident_id, severity.value, actor
            )
            if not success:
                raise IncidentError(
                    f"Failed to update severity: {incident_id}",
                    {"incident_id": incident_id, "severity": severity.value},
                )

            if reason:
                self.add_comment(
                    incident_id,
                    author=actor or "system",
                    content=f"Severity changed: {reason}",
                )

            updated = self.get_or_raise(incident_id)
            self._emit_event(
                TimelineEventType.SEVERITY_CHANGE,
                updated,
                actor=actor,
                old_value=old_severity.value,
                new_value=severity.value,
            )
            return updated

    def escalate(
        self,
        incident_id: str,
        reason: str,
        actor: str | None = None,
    ) -> Incident:
        """
        Escalate an incident to the next severity level.

        Args:
            incident_id: The incident ID.
            reason: Reason for escalation.
            actor: Who is escalating.

        Returns:
            The updated Incident.
        """
        incident = self.get_or_raise(incident_id)

        severity_order = [
            IncidentSeverity.LOW,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.HIGH,
            IncidentSeverity.CRITICAL,
        ]

        current_idx = severity_order.index(incident.severity)
        if current_idx >= len(severity_order) - 1:
            raise IncidentError(
                "Cannot escalate: already at highest severity",
                {"incident_id": incident_id, "severity": incident.severity.value},
            )

        new_severity = severity_order[current_idx + 1]

        self._emit_event(
            TimelineEventType.ESCALATION,
            incident,
            actor=actor,
            old_value=incident.severity.value,
            new_value=new_severity.value,
        )

        return self.update_severity(
            incident_id, new_severity, reason=reason, actor=actor
        )

    # -------------------------------------------------------------------------
    # Comments
    # -------------------------------------------------------------------------

    def add_comment(
        self,
        incident_id: str,
        author: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """
        Add a comment to an incident.

        Args:
            incident_id: The incident ID.
            author: Username of the comment author.
            content: The comment text.
            metadata: Additional metadata for the comment.

        Returns:
            The comment ID.
        """
        comment_id = self._repository.add_comment(
            incident_id, author, content, metadata
        )

        incident = self.get(incident_id)
        if incident:
            self._emit_event(
                TimelineEventType.COMMENT,
                incident,
                actor=author,
                new_value=content[:100] + "..." if len(content) > 100 else content,
            )

        return comment_id

    def get_comments(self, incident_id: str) -> list[IncidentComment]:
        """
        Get all comments for an incident.

        Args:
            incident_id: The incident ID.

        Returns:
            List of IncidentComments.
        """
        data_list = self._repository.get_comments(incident_id)
        return [self._dict_to_comment(d) for d in data_list]

    # -------------------------------------------------------------------------
    # Timeline
    # -------------------------------------------------------------------------

    def get_timeline(self, incident_id: str) -> list[IncidentTimelineEntry]:
        """
        Get the timeline for an incident.

        Args:
            incident_id: The incident ID.

        Returns:
            List of IncidentTimelineEntries in chronological order.
        """
        data_list = self._repository.get_timeline(incident_id)
        return [self._dict_to_timeline_entry(d) for d in data_list]

    # -------------------------------------------------------------------------
    # Related Incidents
    # -------------------------------------------------------------------------

    def link_incidents(
        self,
        incident_id: str,
        related_id: str,
        actor: str | None = None,
    ) -> None:
        """
        Link two related incidents.

        Args:
            incident_id: The primary incident ID.
            related_id: The related incident ID.
            actor: Who is creating the link.
        """
        with self._lock:
            # Verify both incidents exist
            self.get_or_raise(incident_id)
            self.get_or_raise(related_id)

            self._repository.link_incidents(incident_id, related_id)

            incident = self.get_or_raise(incident_id)
            self._emit_event(
                TimelineEventType.RELATED_INCIDENT,
                incident,
                actor=actor,
                new_value=related_id,
            )

    def get_related_incidents(self, incident_id: str) -> list[Incident]:
        """
        Get all incidents related to a given incident.

        Args:
            incident_id: The incident ID.

        Returns:
            List of related Incidents.
        """
        related_ids = self._repository.get_related_incidents(incident_id)
        return [self.get_or_raise(rid) for rid in related_ids]

    def find_similar_incidents(
        self,
        incident_id: str,
        limit: int = 5,
    ) -> list[Incident]:
        """
        Find incidents similar to the given one.

        Similarity is based on incident type, deployment, and tags.

        Args:
            incident_id: The incident ID.
            limit: Maximum number of similar incidents to return.

        Returns:
            List of similar Incidents.
        """
        incident = self.get_or_raise(incident_id)

        # Find by same deployment
        similar = []
        if incident.deployment_id:
            similar.extend(
                self.list_incidents(
                    deployment_id=incident.deployment_id,
                    limit=limit,
                )
            )

        # Find by same type
        similar.extend(
            self.list_incidents(
                incident_type=incident.incident_type,
                limit=limit,
            )
        )

        # Deduplicate and exclude self
        seen: set[str] = {incident.incident_id}
        result = []
        for i in similar:
            if i.incident_id not in seen:
                seen.add(i.incident_id)
                result.append(i)
                if len(result) >= limit:
                    break

        return result

    # -------------------------------------------------------------------------
    # Metrics
    # -------------------------------------------------------------------------

    def get_metrics(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        deployment_id: str | None = None,
    ) -> IncidentMetrics:
        """
        Get aggregated metrics for incidents.

        Args:
            since: Start of the period (inclusive).
            until: End of the period (exclusive).
            deployment_id: Filter by deployment.

        Returns:
            IncidentMetrics with aggregated data.
        """
        metrics = self._repository.get_metrics(since, until, deployment_id)
        return IncidentMetrics(
            total_count=metrics.get("total_count", 0),
            open_count=metrics.get("open_count", 0),
            investigating_count=metrics.get("investigating_count", 0),
            resolved_count=metrics.get("resolved_count", 0),
            closed_count=metrics.get("closed_count", 0),
            by_severity=metrics.get("by_severity", {}),
            by_type=metrics.get("by_type", {}),
            by_deployment=metrics.get("by_deployment", {}),
            mean_time_to_acknowledge_hours=metrics.get("mtta_hours"),
            mean_time_to_resolve_hours=metrics.get("mttr_hours"),
            period_start=since,
            period_end=until,
        )

    def get_trend(
        self,
        days: int = 30,
        deployment_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get incident trend data over time.

        Args:
            days: Number of days to look back.
            deployment_id: Filter by deployment.

        Returns:
            List of daily counts with date and counts by severity.
        """
        return self._repository.get_trend(days, deployment_id)

    # -------------------------------------------------------------------------
    # Event Callbacks
    # -------------------------------------------------------------------------

    def on_event(self, callback: IncidentCallback) -> None:
        """
        Register a callback for incident events.

        Args:
            callback: Function to call when events occur.
        """
        self._callbacks.append(callback)

    def remove_callback(self, callback: IncidentCallback) -> bool:
        """
        Remove a callback.

        Args:
            callback: The callback to remove.

        Returns:
            True if the callback was removed, False if not found.
        """
        try:
            self._callbacks.remove(callback)
            return True
        except ValueError:
            return False

    # -------------------------------------------------------------------------
    # Private Methods
    # -------------------------------------------------------------------------

    def _emit_event(
        self,
        event_type: TimelineEventType,
        incident: Incident,
        actor: str | None = None,
        old_value: str | None = None,
        new_value: str | None = None,
    ) -> None:
        """Emit an event to all registered callbacks."""
        event = IncidentEvent(
            event_type=event_type,
            incident_id=incident.incident_id,
            incident=incident,
            actor=actor,
            old_value=old_value,
            new_value=new_value,
        )
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                # Don't let callback failures affect the manager
                pass

    def _is_valid_transition(
        self,
        old_status: IncidentStatus,
        new_status: IncidentStatus,
    ) -> bool:
        """Check if a status transition is valid."""
        # Define valid transitions
        valid_transitions = {
            IncidentStatus.OPEN: {
                IncidentStatus.INVESTIGATING,
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
            },
            IncidentStatus.INVESTIGATING: {
                IncidentStatus.OPEN,  # Back to open if blocked
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
            },
            IncidentStatus.RESOLVED: {
                IncidentStatus.OPEN,  # Reopen
                IncidentStatus.CLOSED,
            },
            IncidentStatus.CLOSED: {
                IncidentStatus.OPEN,  # Reopen
            },
        }

        return new_status in valid_transitions.get(old_status, set())

    def _dict_to_incident(self, data: dict[str, Any]) -> Incident:
        """Convert a repository dict to an Incident."""
        return Incident(
            id=data.get("id", ""),
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            incident_id=data.get("incident_id", ""),
            severity=IncidentSeverity(data.get("severity", "MEDIUM")),
            status=IncidentStatus(data.get("status", "OPEN")),
            incident_type=IncidentType(data.get("incident_type", "OTHER")),
            title=data.get("title", ""),
            description=data.get("description", ""),
            source_request_id=data.get("source_request_id"),
            deployment_id=data.get("deployment_id"),
            evidence=data.get("evidence") or {},
            assignee=data.get("assignee"),
            resolution=data.get("resolution"),
            root_cause=data.get("root_cause"),
            tags=tuple(data.get("tags") or []),
            resolved_at=self._parse_datetime(data.get("resolved_at")),
            related_incidents=tuple(data.get("related_incidents") or []),
            metadata=data.get("metadata") or {},
        )

    def _dict_to_comment(self, data: dict[str, Any]) -> IncidentComment:
        """Convert a repository dict to an IncidentComment."""
        return IncidentComment(
            id=data.get("id", 0),
            incident_id=data.get("incident_id", ""),
            author=data.get("author", ""),
            content=data.get("content", ""),
            created_at=self._parse_datetime(data.get("created_at")),
            metadata=data.get("metadata") or {},
        )

    def _dict_to_timeline_entry(self, data: dict[str, Any]) -> IncidentTimelineEntry:
        """Convert a repository dict to an IncidentTimelineEntry."""
        return IncidentTimelineEntry(
            id=data.get("id", 0),
            incident_id=data.get("incident_id", ""),
            event_type=TimelineEventType(data.get("event_type", "CREATED")),
            old_value=data.get("old_value"),
            new_value=data.get("new_value"),
            actor=data.get("actor"),
            timestamp=self._parse_datetime(data.get("timestamp")),
            metadata=data.get("metadata") or {},
        )

    def _parse_datetime(self, value: str | datetime | None) -> datetime:
        """Parse a datetime value from string or return as-is."""
        if value is None:
            return utc_now()
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return utc_now()
