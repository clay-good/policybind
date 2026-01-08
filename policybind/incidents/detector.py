"""
Incident detection for PolicyBind.

This module provides automated detection of incidents based on enforcement
logs, usage patterns, and configurable detection rules.
"""

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from policybind.incidents.models import (
    DetectionRule,
    IncidentSeverity,
    IncidentType,
)
from policybind.models.base import generate_uuid, utc_now


@dataclass
class DetectionMatch:
    """
    Represents a match from a detection rule.

    Attributes:
        rule: The rule that matched.
        occurrences: Number of occurrences that triggered the match.
        evidence: Evidence collected from the matched events.
        first_occurrence: Timestamp of the first matching event.
        last_occurrence: Timestamp of the last matching event.
        source_ids: IDs of the source events/requests.
    """

    rule: DetectionRule
    occurrences: int
    evidence: dict[str, Any]
    first_occurrence: datetime
    last_occurrence: datetime
    source_ids: list[str] = field(default_factory=list)


@dataclass
class DetectionWindow:
    """
    Tracks occurrences within a time window for a detection rule.

    Attributes:
        rule_id: ID of the detection rule.
        key: The grouping key (e.g., user_id, deployment_id).
        occurrences: List of (timestamp, event_data) tuples.
        last_incident_time: Last time an incident was created.
    """

    rule_id: str
    key: str
    occurrences: list[tuple[datetime, dict[str, Any]]] = field(default_factory=list)
    last_incident_time: datetime | None = None

    def add_occurrence(self, timestamp: datetime, event_data: dict[str, Any]) -> None:
        """Add an occurrence to the window."""
        self.occurrences.append((timestamp, event_data))

    def prune(self, window_minutes: int) -> None:
        """Remove occurrences outside the time window."""
        cutoff = utc_now() - timedelta(minutes=window_minutes)
        self.occurrences = [
            (ts, data) for ts, data in self.occurrences
            if ts >= cutoff
        ]

    def count(self) -> int:
        """Get the number of occurrences in the window."""
        return len(self.occurrences)

    def can_trigger(self, cooldown_minutes: int) -> bool:
        """Check if enough time has passed since the last incident."""
        if self.last_incident_time is None:
            return True
        elapsed = utc_now() - self.last_incident_time
        return elapsed >= timedelta(minutes=cooldown_minutes)


class IncidentDetector:
    """
    Detects incidents from enforcement logs and usage patterns.

    The IncidentDetector analyzes enforcement decisions and other events
    to identify patterns that may indicate policy violations, abuse,
    or anomalies requiring investigation.

    Features:
    - Configurable detection rules with thresholds
    - Time-windowed occurrence counting
    - Cooldown periods to prevent alert fatigue
    - Custom detection rule support
    - Pattern-based matching

    Example:
        Using the IncidentDetector::

            from policybind.incidents import IncidentDetector, IncidentManager
            from policybind.incidents.models import DetectionRule, IncidentType, IncidentSeverity

            manager = IncidentManager(repository)
            detector = IncidentDetector(manager)

            # Register a detection rule
            rule = DetectionRule(
                name="repeated-denials",
                description="Multiple policy denials from same user",
                severity=IncidentSeverity.MEDIUM,
                incident_type=IncidentType.ABUSE,
                condition={"decision": "DENY"},
                threshold=5,
                window_minutes=10,
                cooldown_minutes=30,
            )
            detector.register_rule(rule)

            # Process an enforcement event
            detector.process_event({
                "request_id": "req-123",
                "user_id": "user-456",
                "decision": "DENY",
                "policy_rule": "no-pii",
            })
    """

    # Built-in detection rule templates
    BUILTIN_RULES = [
        DetectionRule(
            rule_id="repeated-violations",
            name="Repeated Policy Violations",
            description="Multiple policy violations from the same source",
            enabled=True,
            severity=IncidentSeverity.MEDIUM,
            incident_type=IncidentType.POLICY_VIOLATION,
            condition={"decision": "DENY"},
            threshold=5,
            window_minutes=30,
            cooldown_minutes=60,
            tags=["violation", "repeated"],
        ),
        DetectionRule(
            rule_id="jailbreak-attempt",
            name="Potential Jailbreak Attempt",
            description="Request patterns indicating jailbreak attempts",
            enabled=True,
            severity=IncidentSeverity.HIGH,
            incident_type=IncidentType.JAILBREAK,
            condition={"policy_rule": "jailbreak-detection"},
            threshold=1,
            window_minutes=60,
            cooldown_minutes=120,
            tags=["jailbreak", "security"],
        ),
        DetectionRule(
            rule_id="data-leak-risk",
            name="Data Leak Risk",
            description="Potential data exfiltration detected",
            enabled=True,
            severity=IncidentSeverity.CRITICAL,
            incident_type=IncidentType.DATA_LEAK,
            condition={"data_classification": ["pii", "phi", "pci"]},
            threshold=1,
            window_minutes=5,
            cooldown_minutes=30,
            tags=["data-leak", "security"],
        ),
        DetectionRule(
            rule_id="rate-limit-abuse",
            name="Rate Limit Abuse",
            description="Excessive requests hitting rate limits",
            enabled=True,
            severity=IncidentSeverity.MEDIUM,
            incident_type=IncidentType.RATE_LIMIT_EXCEEDED,
            condition={"decision": "DENY", "reason": "rate_limit"},
            threshold=10,
            window_minutes=5,
            cooldown_minutes=30,
            tags=["rate-limit", "abuse"],
        ),
        DetectionRule(
            rule_id="budget-exceeded",
            name="Budget Exceeded",
            description="Token or user exceeded budget limits",
            enabled=True,
            severity=IncidentSeverity.MEDIUM,
            incident_type=IncidentType.BUDGET_EXCEEDED,
            condition={"decision": "DENY", "reason": "budget_exceeded"},
            threshold=1,
            window_minutes=60,
            cooldown_minutes=120,
            tags=["budget", "cost"],
        ),
        DetectionRule(
            rule_id="unauthorized-model",
            name="Unauthorized Model Access",
            description="Attempts to access unauthorized models",
            enabled=True,
            severity=IncidentSeverity.HIGH,
            incident_type=IncidentType.UNAUTHORIZED_ACCESS,
            condition={"decision": "DENY", "reason": "model_not_allowed"},
            threshold=3,
            window_minutes=30,
            cooldown_minutes=60,
            tags=["unauthorized", "access"],
        ),
        DetectionRule(
            rule_id="anomalous-usage",
            name="Anomalous Usage Pattern",
            description="Unusual usage pattern detected",
            enabled=False,  # Disabled by default, needs tuning
            severity=IncidentSeverity.LOW,
            incident_type=IncidentType.ANOMALY,
            condition={"anomaly_score": {"$gt": 0.8}},
            threshold=3,
            window_minutes=60,
            cooldown_minutes=120,
            tags=["anomaly", "behavior"],
        ),
    ]

    def __init__(
        self,
        incident_manager: Any | None = None,
        include_builtins: bool = True,
    ) -> None:
        """
        Initialize the IncidentDetector.

        Args:
            incident_manager: Optional IncidentManager for creating incidents.
            include_builtins: Whether to include built-in detection rules.
        """
        self._manager = incident_manager
        self._rules: dict[str, DetectionRule] = {}
        self._windows: dict[str, dict[str, DetectionWindow]] = defaultdict(dict)
        self._lock = threading.RLock()
        self._matches: list[DetectionMatch] = []

        if include_builtins:
            for rule in self.BUILTIN_RULES:
                self.register_rule(rule)

    # -------------------------------------------------------------------------
    # Rule Management
    # -------------------------------------------------------------------------

    def register_rule(self, rule: DetectionRule) -> None:
        """
        Register a detection rule.

        Args:
            rule: The detection rule to register.
        """
        with self._lock:
            self._rules[rule.rule_id] = rule

    def unregister_rule(self, rule_id: str) -> bool:
        """
        Unregister a detection rule.

        Args:
            rule_id: ID of the rule to remove.

        Returns:
            True if the rule was removed, False if not found.
        """
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                if rule_id in self._windows:
                    del self._windows[rule_id]
                return True
            return False

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """
        Get a detection rule by ID.

        Args:
            rule_id: ID of the rule.

        Returns:
            The DetectionRule if found, None otherwise.
        """
        return self._rules.get(rule_id)

    def list_rules(self, enabled_only: bool = False) -> list[DetectionRule]:
        """
        List all registered rules.

        Args:
            enabled_only: If True, only return enabled rules.

        Returns:
            List of DetectionRules.
        """
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules

    def enable_rule(self, rule_id: str) -> bool:
        """
        Enable a detection rule.

        Args:
            rule_id: ID of the rule to enable.

        Returns:
            True if the rule was enabled, False if not found.
        """
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule:
                rule.enabled = True
                return True
            return False

    def disable_rule(self, rule_id: str) -> bool:
        """
        Disable a detection rule.

        Args:
            rule_id: ID of the rule to disable.

        Returns:
            True if the rule was disabled, False if not found.
        """
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule:
                rule.enabled = False
                return True
            return False

    # -------------------------------------------------------------------------
    # Event Processing
    # -------------------------------------------------------------------------

    def process_event(
        self,
        event: dict[str, Any],
        auto_create_incident: bool = True,
    ) -> list[DetectionMatch]:
        """
        Process an event and check against detection rules.

        Args:
            event: The event data (e.g., enforcement decision).
            auto_create_incident: Whether to automatically create incidents.

        Returns:
            List of DetectionMatches that were triggered.
        """
        matches: list[DetectionMatch] = []
        timestamp = self._get_event_timestamp(event)

        with self._lock:
            for rule in self._rules.values():
                if not rule.enabled:
                    continue

                if self._matches_condition(event, rule.condition):
                    key = self._get_grouping_key(event, rule)
                    match = self._add_to_window(rule, key, timestamp, event)

                    if match:
                        matches.append(match)
                        self._matches.append(match)

                        if auto_create_incident and self._manager:
                            self._create_incident_from_match(match)

        return matches

    def process_events(
        self,
        events: list[dict[str, Any]],
        auto_create_incident: bool = True,
    ) -> list[DetectionMatch]:
        """
        Process multiple events.

        Args:
            events: List of event data.
            auto_create_incident: Whether to automatically create incidents.

        Returns:
            List of all DetectionMatches that were triggered.
        """
        all_matches = []
        for event in events:
            matches = self.process_event(event, auto_create_incident)
            all_matches.extend(matches)
        return all_matches

    def check_thresholds(self) -> list[DetectionMatch]:
        """
        Check all windows against thresholds without adding new events.

        Returns:
            List of matches that currently exceed thresholds.
        """
        matches = []

        with self._lock:
            for rule_id, windows in self._windows.items():
                rule = self._rules.get(rule_id)
                if not rule or not rule.enabled:
                    continue

                for key, window in windows.items():
                    window.prune(rule.window_minutes)

                    if window.count() >= rule.threshold:
                        if window.can_trigger(rule.cooldown_minutes):
                            match = self._create_match(rule, window)
                            matches.append(match)

        return matches

    def get_recent_matches(self, limit: int = 100) -> list[DetectionMatch]:
        """
        Get recent detection matches.

        Args:
            limit: Maximum number of matches to return.

        Returns:
            List of recent DetectionMatches.
        """
        return self._matches[-limit:]

    def clear_matches(self) -> None:
        """Clear the match history."""
        with self._lock:
            self._matches.clear()

    # -------------------------------------------------------------------------
    # Analysis
    # -------------------------------------------------------------------------

    def analyze_patterns(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Analyze events for patterns without triggering incidents.

        Args:
            events: List of events to analyze.

        Returns:
            Dictionary with pattern analysis results.
        """
        analysis: dict[str, Any] = {
            "total_events": len(events),
            "rule_matches": {},
            "top_sources": {},
            "by_decision": defaultdict(int),
            "by_type": defaultdict(int),
        }

        # Count by decision and type
        for event in events:
            decision = event.get("decision", "unknown")
            event_type = event.get("incident_type", event.get("type", "unknown"))
            analysis["by_decision"][decision] += 1
            analysis["by_type"][event_type] += 1

        # Check each rule
        for rule in self._rules.values():
            matching_events = [
                e for e in events
                if self._matches_condition(e, rule.condition)
            ]
            if matching_events:
                analysis["rule_matches"][rule.name] = {
                    "count": len(matching_events),
                    "threshold": rule.threshold,
                    "would_trigger": len(matching_events) >= rule.threshold,
                }

        # Find top sources (users, tokens, deployments)
        source_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for event in events:
            if user_id := event.get("user_id"):
                source_counts["users"][user_id] += 1
            if token_id := event.get("token_id"):
                source_counts["tokens"][token_id] += 1
            if deployment_id := event.get("deployment_id"):
                source_counts["deployments"][deployment_id] += 1

        for source_type, counts in source_counts.items():
            sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            analysis["top_sources"][source_type] = sorted_counts[:10]

        return analysis

    def get_risk_score(self, events: list[dict[str, Any]]) -> float:
        """
        Calculate an overall risk score based on events.

        Args:
            events: List of events to score.

        Returns:
            Risk score from 0.0 to 1.0.
        """
        if not events:
            return 0.0

        total_score = 0.0

        # Score based on severity of matching rules
        severity_weights = {
            IncidentSeverity.LOW: 0.1,
            IncidentSeverity.MEDIUM: 0.3,
            IncidentSeverity.HIGH: 0.6,
            IncidentSeverity.CRITICAL: 1.0,
        }

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            matching_count = sum(
                1 for e in events
                if self._matches_condition(e, rule.condition)
            )

            if matching_count > 0:
                weight = severity_weights.get(rule.severity, 0.3)
                ratio = min(1.0, matching_count / rule.threshold)
                total_score += weight * ratio

        # Normalize to 0-1 range
        max_possible = len(self._rules)
        if max_possible > 0:
            return min(1.0, total_score / max_possible)
        return 0.0

    # -------------------------------------------------------------------------
    # Private Methods
    # -------------------------------------------------------------------------

    def _matches_condition(
        self,
        event: dict[str, Any],
        condition: dict[str, Any],
    ) -> bool:
        """Check if an event matches a condition."""
        for key, expected in condition.items():
            actual = event.get(key)

            # Handle list conditions (any match)
            if isinstance(expected, list):
                if isinstance(actual, list):
                    if not any(e in expected for e in actual):
                        return False
                elif actual not in expected:
                    return False

            # Handle dict conditions (operators like $gt, $lt)
            elif isinstance(expected, dict):
                for op, value in expected.items():
                    if op == "$gt" and not (actual is not None and actual > value):
                        return False
                    if op == "$lt" and not (actual is not None and actual < value):
                        return False
                    if op == "$gte" and not (actual is not None and actual >= value):
                        return False
                    if op == "$lte" and not (actual is not None and actual <= value):
                        return False
                    if op == "$ne" and actual == value:
                        return False
                    if op == "$in" and actual not in value:
                        return False
                    if op == "$nin" and actual in value:
                        return False
                    if op == "$contains" and value not in (actual or ""):
                        return False

            # Handle simple equality
            elif actual != expected:
                return False

        return True

    def _get_grouping_key(
        self,
        event: dict[str, Any],
        rule: DetectionRule,
    ) -> str:
        """Get the grouping key for an event based on rule configuration."""
        # Default grouping by user, token, or deployment
        parts = []

        if user_id := event.get("user_id"):
            parts.append(f"user:{user_id}")
        if token_id := event.get("token_id"):
            parts.append(f"token:{token_id}")
        if deployment_id := event.get("deployment_id"):
            parts.append(f"deployment:{deployment_id}")
        if source := event.get("source_application"):
            parts.append(f"source:{source}")

        return "|".join(parts) if parts else "global"

    def _get_event_timestamp(self, event: dict[str, Any]) -> datetime:
        """Extract timestamp from an event."""
        if timestamp := event.get("timestamp"):
            if isinstance(timestamp, datetime):
                return timestamp
            if isinstance(timestamp, str):
                try:
                    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    pass
        return utc_now()

    def _add_to_window(
        self,
        rule: DetectionRule,
        key: str,
        timestamp: datetime,
        event: dict[str, Any],
    ) -> DetectionMatch | None:
        """Add an event to a detection window and check threshold."""
        window = self._windows[rule.rule_id].get(key)

        if window is None:
            window = DetectionWindow(rule_id=rule.rule_id, key=key)
            self._windows[rule.rule_id][key] = window

        window.add_occurrence(timestamp, event)
        window.prune(rule.window_minutes)

        if window.count() >= rule.threshold:
            if window.can_trigger(rule.cooldown_minutes):
                match = self._create_match(rule, window)
                window.last_incident_time = utc_now()
                return match

        return None

    def _create_match(
        self,
        rule: DetectionRule,
        window: DetectionWindow,
    ) -> DetectionMatch:
        """Create a DetectionMatch from a window."""
        occurrences = window.occurrences
        first = occurrences[0] if occurrences else (utc_now(), {})
        last = occurrences[-1] if occurrences else (utc_now(), {})

        evidence: dict[str, Any] = {
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "threshold": rule.threshold,
            "window_minutes": rule.window_minutes,
            "occurrences": len(occurrences),
            "sample_events": [data for _, data in occurrences[:5]],
        }

        source_ids = []
        for _, data in occurrences:
            if request_id := data.get("request_id"):
                source_ids.append(request_id)

        return DetectionMatch(
            rule=rule,
            occurrences=len(occurrences),
            evidence=evidence,
            first_occurrence=first[0],
            last_occurrence=last[0],
            source_ids=source_ids[:50],  # Limit to 50 IDs
        )

    def _create_incident_from_match(self, match: DetectionMatch) -> None:
        """Create an incident from a detection match."""
        if not self._manager:
            return

        rule = match.rule

        # Build description
        description = (
            f"{rule.description}\n\n"
            f"Detection Details:\n"
            f"- Occurrences: {match.occurrences}\n"
            f"- Time window: {rule.window_minutes} minutes\n"
            f"- First seen: {match.first_occurrence.isoformat()}\n"
            f"- Last seen: {match.last_occurrence.isoformat()}"
        )

        # Get first source request if available
        source_request_id = match.source_ids[0] if match.source_ids else None

        # Get deployment from evidence if available
        deployment_id = None
        sample_events = match.evidence.get("sample_events", [])
        if sample_events:
            deployment_id = sample_events[0].get("deployment_id")

        self._manager.create_from_detection(
            detection_rule=rule.name,
            incident_type=rule.incident_type,
            severity=rule.severity,
            description=description,
            evidence=match.evidence,
            source_request_id=source_request_id,
            deployment_id=deployment_id,
            auto_assign=rule.auto_assign,
            tags=list(rule.tags),
            metadata=rule.metadata,
        )
