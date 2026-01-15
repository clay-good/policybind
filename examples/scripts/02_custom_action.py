#!/usr/bin/env python3
"""
PolicyBind Example: Custom Action Implementation

This script demonstrates how to implement custom policy actions in PolicyBind.
Custom actions allow you to extend PolicyBind's behavior beyond the built-in
actions (ALLOW, DENY, MODIFY, etc.).

This example shows:
1. Creating a custom action handler
2. Registering it with the ActionRegistry
3. Using it in policy rules
4. Chaining actions together

Use Cases for Custom Actions:
    - Logging to external systems (Splunk, DataDog, etc.)
    - Sending notifications (Slack, email, PagerDuty)
    - Custom data transformations
    - Integration with approval workflows
    - Cost tracking and budget enforcement

Prerequisites:
    - PolicyBind installed: pip install policybind
    - Understanding of basic enforcement (see 01_basic_enforcement.py)

Usage:
    python 02_custom_action.py
"""

import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from policybind.engine.actions import Action, ActionRegistry, ActionResult
from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.engine.executor import ActionExecutor
from policybind.models.request import AIRequest, Decision


# =============================================================================
# Step 1: Define Custom Action Handlers
# =============================================================================
# Action handlers receive an ActionContext and parameters dict, and return
# an ActionResult indicating the outcome.


@dataclass
class NotificationRecord:
    """Record of a notification that would be sent."""

    channel: str
    message: str
    timestamp: datetime
    request_id: str
    severity: str


# In a real implementation, this would be an external service
notification_log: list[NotificationRecord] = []


def notify_action_handler(context: Any, params: dict[str, Any]) -> ActionResult:
    """
    Custom action handler that sends notifications.

    This handler demonstrates how to create a custom action that:
    1. Extracts parameters from the policy rule
    2. Performs custom logic (sending a notification)
    3. Returns an appropriate result

    In production, this would integrate with Slack, email, PagerDuty, etc.

    Expected params:
        channel: Notification channel (e.g., "slack", "email", "pagerduty")
        severity: Alert severity (e.g., "info", "warning", "critical")
        message_template: Optional message template

    Args:
        context: The action context with request information.
        params: Action parameters from the policy rule.

    Returns:
        ActionResult indicating the notification was sent and request allowed.
    """
    # Extract parameters with defaults
    channel = params.get("channel", "default")
    severity = params.get("severity", "info")
    message_template = params.get(
        "message_template",
        "AI request from {user_id} for {model} requires attention"
    )

    # Build the notification message
    message = message_template.format(
        user_id=context.user_id,
        model=context.model,
        provider=context.provider,
        department=getattr(context, "department", "unknown"),
        request_id=context.request_id,
    )

    # Record the notification (in production, send to actual service)
    notification = NotificationRecord(
        channel=channel,
        message=message,
        timestamp=datetime.now(),
        request_id=context.request_id,
        severity=severity,
    )
    notification_log.append(notification)

    print(f"    [NOTIFICATION] Channel: {channel}, Severity: {severity}")
    print(f"    [NOTIFICATION] Message: {message}")

    # Allow the request but include metadata about the notification
    return ActionResult(
        action=Action.AUDIT,  # Treat as AUDIT since we want to allow but track
        allowed=True,
        modified=False,
        reason=f"Notification sent to {channel}",
        metadata={
            "notification_channel": channel,
            "notification_severity": severity,
            "notification_sent": True,
        },
    )


def redact_pii_handler(context: Any, params: dict[str, Any]) -> ActionResult:
    """
    Custom action handler that redacts PII from requests.

    This demonstrates a MODIFY-style action that transforms the request
    before allowing it to proceed.

    Expected params:
        fields: List of fields to redact
        replacement: Replacement string (default: "[REDACTED]")

    Args:
        context: The action context with request information.
        params: Action parameters from the policy rule.

    Returns:
        ActionResult with modifications applied.
    """
    fields_to_redact = params.get("fields", ["ssn", "credit_card", "password"])
    replacement = params.get("replacement", "[REDACTED]")

    # In a real implementation, we would scan the prompt and redact patterns
    # For this example, we'll simulate redaction
    redacted_fields = []

    # Simulate checking for PII patterns
    sample_content = context.metadata.get("prompt_preview", "")
    for field in fields_to_redact:
        if field.lower() in sample_content.lower():
            redacted_fields.append(field)

    modifications = {}
    if redacted_fields:
        modifications["redacted_fields"] = redacted_fields
        modifications["redaction_applied"] = True

    print(f"    [REDACTION] Fields checked: {fields_to_redact}")
    print(f"    [REDACTION] Fields redacted: {redacted_fields or 'none'}")

    return ActionResult(
        action=Action.MODIFY,
        allowed=True,
        modified=bool(redacted_fields),
        modifications=modifications,
        reason=f"PII redaction applied: {redacted_fields}" if redacted_fields else "No PII detected",
    )


def cost_check_handler(context: Any, params: dict[str, Any]) -> ActionResult:
    """
    Custom action handler that checks cost limits.

    This demonstrates a conditional action that may ALLOW or DENY
    based on runtime conditions.

    Expected params:
        max_cost: Maximum allowed cost per request
        budget_key: Key to track budget against (user_id, department, etc.)

    Args:
        context: The action context with request information.
        params: Action parameters from the policy rule.

    Returns:
        ActionResult allowing or denying based on cost.
    """
    max_cost = params.get("max_cost", 1.0)
    budget_key = params.get("budget_key", "user_id")

    # Get estimated cost from context metadata
    estimated_cost = context.metadata.get("estimated_cost", 0.0)

    print(f"    [COST CHECK] Budget key: {budget_key}")
    print(f"    [COST CHECK] Estimated cost: ${estimated_cost:.4f}")
    print(f"    [COST CHECK] Max allowed: ${max_cost:.4f}")

    if estimated_cost > max_cost:
        return ActionResult(
            action=Action.DENY,
            allowed=False,
            reason=f"Cost ${estimated_cost:.4f} exceeds limit ${max_cost:.4f}",
            metadata={
                "estimated_cost": estimated_cost,
                "max_cost": max_cost,
                "budget_key": budget_key,
            },
        )

    return ActionResult(
        action=Action.ALLOW,
        allowed=True,
        reason=f"Cost ${estimated_cost:.4f} within limit",
        metadata={
            "estimated_cost": estimated_cost,
            "max_cost": max_cost,
            "remaining_budget": max_cost - estimated_cost,
        },
    )


# =============================================================================
# Step 2: Policy with Custom Action References
# =============================================================================
# Note: In a real implementation, custom actions would be registered with
# special names. For this example, we'll use the AUDIT action and override
# its handler.

SAMPLE_POLICY = """
name: custom-actions-policy
version: "1.0.0"
description: Policy demonstrating custom actions

rules:
  # Rule 1: High-cost requests need notification
  - name: notify-expensive-requests
    description: Send notification for expensive model usage
    action: AUDIT
    priority: 200
    match_conditions:
      model:
        in:
          - gpt-4
          - gpt-4-turbo
          - claude-3-opus
    # Note: action_params would be used by custom handler
    action_params:
      notification_channel: slack
      severity: warning

  # Rule 2: PII data needs redaction
  - name: redact-pii-data
    description: Redact PII before allowing request
    action: MODIFY
    priority: 150
    match_conditions:
      data_classification:
        contains: pii
    action_params:
      redact_fields:
        - ssn
        - credit_card
        - phone

  # Rule 3: Cost-controlled access
  - name: cost-limit-marketing
    description: Limit marketing department costs
    action: ALLOW
    priority: 100
    match_conditions:
      department: marketing

  # Default allow for demo
  - name: default-allow
    description: Allow other requests
    action: ALLOW
    priority: 1
    match_conditions: {}
"""


def create_sample_requests() -> list[AIRequest]:
    """Create sample requests demonstrating custom action scenarios."""
    return [
        # Request 1: Expensive model - triggers notification
        AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user-001",
            department="engineering",
            metadata={"estimated_cost": 0.05},
        ),
        # Request 2: Contains PII - triggers redaction
        AIRequest(
            provider="openai",
            model="gpt-3.5-turbo",
            user_id="user-002",
            department="hr",
            data_classification=("pii",),
            metadata={
                "prompt_preview": "Process this SSN: 123-45-6789",
                "estimated_cost": 0.01,
            },
        ),
        # Request 3: Marketing with high cost estimate
        AIRequest(
            provider="openai",
            model="gpt-4-turbo",
            user_id="user-003",
            department="marketing",
            metadata={"estimated_cost": 0.75},
        ),
        # Request 4: Standard request
        AIRequest(
            provider="openai",
            model="gpt-3.5-turbo",
            user_id="user-004",
            department="finance",
            metadata={"estimated_cost": 0.002},
        ),
    ]


def main() -> int:
    """
    Main function demonstrating custom action implementation.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: Custom Action Implementation")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 3: Create and configure the action registry
    # -------------------------------------------------------------------------
    print("Step 1: Creating custom action registry...")

    # Create a custom action registry with our handlers
    action_registry = ActionRegistry()

    # Register custom handlers
    # Note: We're overriding the AUDIT handler with our notification handler
    # and MODIFY handler with our redaction handler
    original_audit = action_registry.get_handler(Action.AUDIT)
    original_modify = action_registry.get_handler(Action.MODIFY)

    # For demonstration, we'll wrap the original handlers
    def wrapped_audit_handler(context: Any, params: dict[str, Any]) -> ActionResult:
        """Wrapper that calls our notification handler then original."""
        notify_result = notify_action_handler(context, params)
        # Continue with original AUDIT behavior
        original_result = original_audit(context, params)
        # Merge results
        return ActionResult(
            action=Action.AUDIT,
            allowed=original_result.allowed,
            modified=False,
            reason=notify_result.reason,
            metadata={**original_result.metadata, **notify_result.metadata},
        )

    def wrapped_modify_handler(context: Any, params: dict[str, Any]) -> ActionResult:
        """Wrapper that applies PII redaction."""
        return redact_pii_handler(context, params)

    action_registry.register(Action.AUDIT, wrapped_audit_handler)
    action_registry.register(Action.MODIFY, wrapped_modify_handler)

    print("  Registered custom handlers:")
    print("    - AUDIT -> notification_handler (wrapping original)")
    print("    - MODIFY -> redact_pii_handler")
    print()

    # -------------------------------------------------------------------------
    # Step 4: Parse policy and create pipeline
    # -------------------------------------------------------------------------
    print("Step 2: Parsing policy...")

    parser = PolicyParser()
    result = parser.parse_string(SAMPLE_POLICY)

    if not result.success:
        print("ERROR: Failed to parse policy")
        for error in result.errors:
            print(f"  - {error}")
        return 1

    policy_set = result.policy_set
    print(f"  Loaded policy: {policy_set.name}")
    print(f"  Rules: {len(policy_set.rules)}")
    print()

    # -------------------------------------------------------------------------
    # Step 5: Create pipeline with custom executor
    # -------------------------------------------------------------------------
    print("Step 3: Creating enforcement pipeline with custom actions...")

    # Create executor with our custom registry
    executor = ActionExecutor(action_registry=action_registry)

    config = PipelineConfig(
        enable_timing=True,
        enable_audit=False,
    )

    pipeline = EnforcementPipeline(
        policy_set=policy_set,
        config=config,
        executor=executor,
    )

    print("  Pipeline created with custom action executor")
    print()

    # -------------------------------------------------------------------------
    # Step 6: Process requests
    # -------------------------------------------------------------------------
    print("Step 4: Processing requests...")
    print("-" * 60)

    requests = create_sample_requests()

    for i, request in enumerate(requests, 1):
        print(f"\nRequest {i}:")
        print(f"  Model: {request.model}")
        print(f"  User: {request.user_id}")
        print(f"  Department: {request.department}")
        if request.data_classification:
            print(f"  Data Classification: {request.data_classification}")
        if "estimated_cost" in request.metadata:
            print(f"  Estimated Cost: ${request.metadata['estimated_cost']:.4f}")

        response = pipeline.process(request)

        print(f"  Decision: {response.decision.value}")
        if response.applied_rules:
            print(f"  Applied Rules: {', '.join(response.applied_rules)}")
        if response.reason:
            print(f"  Reason: {response.reason}")
        if response.modifications:
            print(f"  Modifications: {response.modifications}")

    # -------------------------------------------------------------------------
    # Step 7: Show notification log
    # -------------------------------------------------------------------------
    print()
    print("-" * 60)
    print("Notification Log:")
    print("-" * 60)

    if notification_log:
        for notification in notification_log:
            print(f"  [{notification.timestamp.strftime('%H:%M:%S')}] "
                  f"{notification.channel.upper()} ({notification.severity})")
            print(f"    {notification.message}")
    else:
        print("  No notifications sent")

    print()
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. Custom actions extend PolicyBind's capabilities")
    print("  2. Handlers receive context and params, return ActionResult")
    print("  3. Actions can ALLOW, DENY, or MODIFY requests")
    print("  4. Use action_params in policies to configure handlers")

    return 0


if __name__ == "__main__":
    sys.exit(main())
