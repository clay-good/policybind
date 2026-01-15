#!/usr/bin/env python3
"""
PolicyBind Example: Incident Response

This script demonstrates the incident response system in PolicyBind, including:

1. Creating incidents from policy violations
2. Automated incident detection from patterns
3. Incident investigation workflow
4. Severity escalation
5. Resolution and closure
6. Metrics and reporting

The incident response system helps organizations track, investigate, and
resolve AI-related security and policy incidents.

Prerequisites:
    - PolicyBind installed: pip install policybind

Usage:
    python 05_incident_response.py
"""

import sys
from datetime import datetime, timedelta

from policybind.incidents.manager import IncidentManager, IncidentEvent
from policybind.incidents.detector import IncidentDetector, DetectionRule
from policybind.incidents.models import (
    Incident,
    IncidentType,
    IncidentSeverity,
    IncidentStatus,
    TimelineEventType,
)
from policybind.storage import Database, IncidentRepository
from policybind.exceptions import IncidentError


def main() -> int:
    """
    Main function demonstrating incident response.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: Incident Response")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 1: Initialize Incident Management
    # -------------------------------------------------------------------------
    print("Step 1: Initializing Incident Management...")
    print("-" * 60)

    # Create in-memory database and repository
    db = Database(":memory:")
    db.initialize()
    repository = IncidentRepository(db)

    # Create incident manager
    manager = IncidentManager(repository)

    # Track events for demonstration
    events_log = []

    def event_handler(event: IncidentEvent):
        events_log.append(event)
        print(f"  [EVENT] {event.event_type.value}: {event.incident.title[:40]}...")

    manager.on_event(event_handler)

    print("  Incident manager initialized")
    print("  Event handler registered")
    print()

    # -------------------------------------------------------------------------
    # Step 2: Create Incidents from Policy Violations
    # -------------------------------------------------------------------------
    print("Step 2: Creating Incidents from Policy Violations...")
    print("-" * 60)

    # Incident 1: Policy violation - unauthorized model access
    print("\nCreating incident: Unauthorized Model Access")
    incident1 = manager.create_from_violation(
        request_id="req-001-xyz",
        policy_rule="deny-gpt4-non-engineering",
        description=(
            "User attempted to access GPT-4 model but is not in the engineering "
            "department. The request was denied by policy."
        ),
        severity=IncidentSeverity.MEDIUM,
        user_id="user-marketing-001",
        deployment_id="deployment-001",
        additional_evidence={
            "model_requested": "gpt-4",
            "user_department": "marketing",
            "ip_address": "10.0.1.50",
            "user_agent": "InternalApp/1.0",
        },
    )
    print(f"  Incident ID: {incident1.incident_id[:16]}...")
    print(f"  Title: {incident1.title}")
    print(f"  Severity: {incident1.severity.value}")
    print(f"  Status: {incident1.status.value}")

    # Incident 2: Potential data leak
    print("\nCreating incident: Potential Data Leak")
    incident2 = manager.create(
        title="Potential PII Exposure in AI Response",
        incident_type=IncidentType.DATA_LEAK,
        severity=IncidentSeverity.HIGH,
        description=(
            "AI model response contained what appears to be personal identifiable "
            "information (PII). The response included names, addresses, and phone "
            "numbers that were not in the original prompt."
        ),
        source_request_id="req-002-abc",
        deployment_id="deployment-002",
        evidence={
            "pii_types_detected": ["name", "address", "phone"],
            "confidence_score": 0.95,
            "response_sample_hash": "sha256:abc123...",
            "model": "gpt-3.5-turbo",
        },
        tags=["pii", "data-leak", "high-priority"],
    )
    print(f"  Incident ID: {incident2.incident_id[:16]}...")
    print(f"  Title: {incident2.title}")
    print(f"  Severity: {incident2.severity.value}")
    print(f"  Tags: {list(incident2.tags)}")

    # Incident 3: Jailbreak attempt
    print("\nCreating incident: Jailbreak Attempt")
    incident3 = manager.create(
        title="Detected Jailbreak Attempt",
        incident_type=IncidentType.JAILBREAK,
        severity=IncidentSeverity.CRITICAL,
        description=(
            "User attempted to bypass AI safety constraints using a known jailbreak "
            "technique. The attempt was blocked but requires investigation."
        ),
        source_request_id="req-003-def",
        evidence={
            "technique": "DAN (Do Anything Now)",
            "blocked": True,
            "prompt_hash": "sha256:def456...",
            "user_id": "user-external-001",
            "similar_attempts_last_24h": 3,
        },
        tags=["jailbreak", "security", "blocked"],
    )
    print(f"  Incident ID: {incident3.incident_id[:16]}...")
    print(f"  Title: {incident3.title}")
    print(f"  Severity: {incident3.severity.value}")
    print(f"  Type: {incident3.incident_type.value}")

    print()

    # -------------------------------------------------------------------------
    # Step 3: Automated Incident Detection
    # -------------------------------------------------------------------------
    print("Step 3: Automated Incident Detection...")
    print("-" * 60)

    # Create incident detector
    detector = IncidentDetector(
        incident_manager=manager,
        include_builtins=True,
    )

    # List built-in detection rules
    print("\nBuilt-in detection rules:")
    for rule in detector.list_rules(enabled_only=True):
        print(f"  - {rule.name}: threshold={rule.threshold}, window={rule.window_minutes}min")

    # Add a custom detection rule
    print("\nAdding custom detection rule: Repeated API Key Failures")
    custom_rule = DetectionRule(
        rule_id="api-key-failures",
        name="Repeated API Key Failures",
        description="Multiple failed API key validations from same source",
        enabled=True,
        severity=IncidentSeverity.HIGH,
        incident_type=IncidentType.UNAUTHORIZED_ACCESS,
        condition={"decision": "DENY", "reason": "invalid_api_key"},
        threshold=5,
        window_minutes=10,
        cooldown_minutes=30,
        auto_assign="security-team",
        tags=["auth", "security", "api-key"],
    )
    detector.register_rule(custom_rule)
    print(f"  Rule ID: {custom_rule.rule_id}")
    print(f"  Threshold: {custom_rule.threshold} in {custom_rule.window_minutes} minutes")

    # Simulate enforcement events that trigger detection
    print("\nSimulating enforcement events...")
    test_events = [
        {"request_id": f"req-{i}", "user_id": "user-suspicious", "decision": "DENY", "reason": "invalid_api_key"}
        for i in range(7)  # 7 failures, exceeds threshold of 5
    ]

    matches = detector.process_events(test_events, auto_create_incident=True)
    print(f"  Processed {len(test_events)} events")
    print(f"  Detection matches: {len(matches)}")

    if matches:
        for match in matches:
            print(f"    - {match.rule.name}: {match.occurrences} occurrences")

    print()

    # -------------------------------------------------------------------------
    # Step 4: Incident Investigation Workflow
    # -------------------------------------------------------------------------
    print("Step 4: Incident Investigation Workflow...")
    print("-" * 60)

    # Assign the high-severity incident
    print(f"\nAssigning incident: {incident2.title[:40]}...")
    incident2 = manager.assign(
        incident_id=incident2.incident_id,
        assignee="security-analyst-1",
        actor="security-manager",
    )
    print(f"  Assigned to: {incident2.assignee}")

    # Start investigation
    print("\nStarting investigation...")
    incident2 = manager.start_investigation(
        incident_id=incident2.incident_id,
        actor="security-analyst-1",
    )
    print(f"  Status: {incident2.status.value}")

    # Add investigation comments
    print("\nAdding investigation notes...")
    manager.add_comment(
        incident_id=incident2.incident_id,
        author="security-analyst-1",
        content=(
            "Initial analysis complete. The PII appears to have been memorized "
            "from training data. This is a known issue with this model version."
        ),
        metadata={"analysis_time_minutes": 45},
    )
    print("  Added: Initial analysis comment")

    manager.add_comment(
        incident_id=incident2.incident_id,
        author="security-analyst-1",
        content=(
            "Confirmed with AI Safety team. Implementing output filtering as "
            "immediate mitigation. Long-term fix requires model update."
        ),
    )
    print("  Added: Mitigation comment")

    # Get all comments
    comments = manager.get_comments(incident2.incident_id)
    print(f"\n  Total comments: {len(comments)}")
    for comment in comments:
        print(f"    - [{comment.author}]: {comment.content[:50]}...")

    print()

    # -------------------------------------------------------------------------
    # Step 5: Severity Escalation
    # -------------------------------------------------------------------------
    print("Step 5: Handling Severity Escalation...")
    print("-" * 60)

    # Check current incident severity
    print(f"\nCurrent incident: {incident1.title[:40]}...")
    print(f"  Current severity: {incident1.severity.value}")

    # Escalate the incident
    print("\nEscalating incident due to pattern analysis...")
    incident1 = manager.escalate(
        incident_id=incident1.incident_id,
        reason="Pattern analysis reveals this is part of a coordinated access attempt",
        actor="security-manager",
    )
    print(f"  New severity: {incident1.severity.value}")

    # Escalate the critical incident further (should fail - already at max)
    print(f"\nAttempting to escalate critical incident: {incident3.title[:40]}...")
    try:
        manager.escalate(
            incident_id=incident3.incident_id,
            reason="Test escalation",
            actor="admin",
        )
    except IncidentError as e:
        print(f"  Expected error: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 6: Link Related Incidents
    # -------------------------------------------------------------------------
    print("Step 6: Linking Related Incidents...")
    print("-" * 60)

    # Find potentially related incidents
    print(f"\nFinding incidents similar to: {incident1.title[:40]}...")
    similar = manager.find_similar_incidents(incident1.incident_id, limit=5)
    print(f"  Found {len(similar)} potentially related incidents")

    # Link incidents
    print("\nLinking jailbreak and data leak incidents (related attack campaign)...")
    manager.link_incidents(
        incident_id=incident2.incident_id,
        related_id=incident3.incident_id,
        actor="security-analyst-1",
    )

    related = manager.get_related_incidents(incident2.incident_id)
    print(f"  Linked incidents: {len(related)}")
    for rel in related:
        print(f"    - {rel.title[:50]}...")

    print()

    # -------------------------------------------------------------------------
    # Step 7: Resolution and Closure
    # -------------------------------------------------------------------------
    print("Step 7: Resolving and Closing Incidents...")
    print("-" * 60)

    # Resolve the data leak incident
    print(f"\nResolving: {incident2.title[:40]}...")
    incident2 = manager.resolve(
        incident_id=incident2.incident_id,
        resolution=(
            "Implemented output filtering to detect and redact PII. "
            "Updated content moderation policy. Notified affected users."
        ),
        root_cause="Model training data contained PII that was memorized",
        actor="security-analyst-1",
    )
    print(f"  Status: {incident2.status.value}")
    print(f"  Resolution: {incident2.resolution[:50]}...")
    print(f"  Root Cause: {incident2.root_cause}")

    # Close the incident
    print("\nClosing incident after review period...")
    incident2 = manager.close(
        incident_id=incident2.incident_id,
        actor="security-manager",
    )
    print(f"  Status: {incident2.status.value}")

    # Demonstrate reopening
    print("\nReopening incident (new information received)...")
    incident2 = manager.reopen(
        incident_id=incident2.incident_id,
        reason="Additional PII exposure discovered in related logs",
        actor="security-analyst-2",
    )
    print(f"  Status: {incident2.status.value}")

    print()

    # -------------------------------------------------------------------------
    # Step 8: View Incident Timeline
    # -------------------------------------------------------------------------
    print("Step 8: Viewing Incident Timeline...")
    print("-" * 60)

    print(f"\nTimeline for: {incident2.title[:40]}...")
    timeline = manager.get_timeline(incident2.incident_id)
    print(f"  Total events: {len(timeline)}")

    for entry in timeline[:10]:  # Show first 10
        old_val = f"from '{entry.old_value}'" if entry.old_value else ""
        new_val = f"to '{entry.new_value}'" if entry.new_value else ""
        actor = f"by {entry.actor}" if entry.actor else ""
        print(f"    - {entry.event_type.value}: {old_val} {new_val} {actor}")

    print()

    # -------------------------------------------------------------------------
    # Step 9: Query and Filter Incidents
    # -------------------------------------------------------------------------
    print("Step 9: Querying and Filtering Incidents...")
    print("-" * 60)

    # List all open incidents
    print("\nOpen incidents:")
    open_incidents = manager.get_open_incidents()
    for inc in open_incidents:
        print(f"  - [{inc.severity.value}] {inc.title[:50]}...")

    # Filter by severity
    print("\nHigh severity incidents:")
    high_severity = manager.list_incidents(severity=IncidentSeverity.HIGH)
    for inc in high_severity:
        print(f"  - {inc.title[:50]}... ({inc.status.value})")

    # Filter by type
    print("\nJailbreak incidents:")
    jailbreak_incidents = manager.list_incidents(incident_type=IncidentType.JAILBREAK)
    for inc in jailbreak_incidents:
        print(f"  - {inc.title[:50]}... ({inc.status.value})")

    print()

    # -------------------------------------------------------------------------
    # Step 10: Incident Metrics
    # -------------------------------------------------------------------------
    print("Step 10: Incident Metrics and Reporting...")
    print("-" * 60)

    # Get overall metrics
    print("\nOverall incident metrics:")
    metrics = manager.get_metrics()
    print(f"  Total incidents: {metrics.total_count}")
    print(f"  Open: {metrics.open_count}")
    print(f"  Investigating: {metrics.investigating_count}")
    print(f"  Resolved: {metrics.resolved_count}")
    print(f"  Closed: {metrics.closed_count}")
    print(f"  Resolution rate: {metrics.resolution_rate:.1f}%")

    print("\nBy severity:")
    for severity, count in sorted(metrics.by_severity.items()):
        print(f"  - {severity}: {count}")

    print("\nBy type:")
    for inc_type, count in sorted(metrics.by_type.items()):
        print(f"  - {inc_type}: {count}")

    # Get trend data
    print("\nIncident trend (last 7 days):")
    trend = manager.get_trend(days=7)
    for day_data in trend[:3]:  # Show first 3 days
        print(f"  - {day_data.get('date', 'N/A')}: {day_data.get('count', 0)} incidents")

    print()

    # -------------------------------------------------------------------------
    # Step 11: Pattern Analysis
    # -------------------------------------------------------------------------
    print("Step 11: Pattern Analysis with Detector...")
    print("-" * 60)

    # Analyze a batch of events
    print("\nAnalyzing event patterns...")
    sample_events = [
        {"decision": "DENY", "reason": "rate_limit", "user_id": "user-1"},
        {"decision": "DENY", "reason": "rate_limit", "user_id": "user-1"},
        {"decision": "ALLOW", "user_id": "user-2"},
        {"decision": "DENY", "reason": "budget_exceeded", "user_id": "user-3"},
        {"decision": "DENY", "reason": "rate_limit", "user_id": "user-1"},
    ]

    analysis = detector.analyze_patterns(sample_events)
    print(f"  Total events analyzed: {analysis['total_events']}")
    print(f"  By decision: {dict(analysis['by_decision'])}")

    if analysis["rule_matches"]:
        print("  Rule matches:")
        for rule_name, match_info in analysis["rule_matches"].items():
            would_trigger = "YES" if match_info["would_trigger"] else "no"
            print(f"    - {rule_name}: {match_info['count']} matches (trigger: {would_trigger})")

    # Calculate risk score
    risk_score = detector.get_risk_score(sample_events)
    print(f"\n  Overall risk score: {risk_score:.2f}/1.00")

    print()

    # -------------------------------------------------------------------------
    # Event Summary
    # -------------------------------------------------------------------------
    print("Event Summary...")
    print("-" * 60)
    print(f"\nTotal events logged: {len(events_log)}")

    event_counts = {}
    for event in events_log:
        event_type = event.event_type.value
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    print("Events by type:")
    for etype, count in sorted(event_counts.items()):
        print(f"  - {etype}: {count}")

    print()
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. Incidents can be created manually or from policy violations")
    print("  2. Automated detection identifies patterns that warrant investigation")
    print("  3. Investigation workflow tracks progress with comments and timeline")
    print("  4. Severity can be escalated as new information emerges")
    print("  5. Related incidents can be linked for coordinated response")
    print("  6. Metrics help track overall security posture")

    return 0


if __name__ == "__main__":
    sys.exit(main())
