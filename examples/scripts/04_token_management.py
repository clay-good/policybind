#!/usr/bin/env python3
"""
PolicyBind Example: Token Management

This script demonstrates the token-based access control system in PolicyBind,
including:

1. Creating tokens with various permissions
2. Using natural language to define token permissions
3. Validating tokens against requests
4. Tracking token usage and budgets
5. Revoking tokens
6. Managing token lifecycle

Tokens are the primary mechanism for controlling who can access AI APIs
and what they can do.

Prerequisites:
    - PolicyBind installed: pip install policybind

Usage:
    python 04_token_management.py
"""

import sys
from datetime import datetime, timedelta

from policybind.tokens.manager import TokenManager
from policybind.tokens.models import (
    TokenPermissions,
    TokenStatus,
    BudgetPeriod,
    RateLimit,
)
from policybind.tokens.natural_language import NaturalLanguageTokenParser
from policybind.tokens.templates import PermissionTemplates
from policybind.tokens.validator import TokenValidator
from policybind.models.request import AIRequest
from policybind.exceptions import TokenError


def main() -> int:
    """
    Main function demonstrating token management.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: Token Management")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 1: Initialize Token Manager
    # -------------------------------------------------------------------------
    print("Step 1: Initializing Token Manager...")
    print("-" * 60)

    # Create manager (in-memory for this example)
    manager = TokenManager()

    # Track events
    events = []

    def event_handler(event):
        events.append(event)
        print(f"  [EVENT] {event.event_type}: token {event.token_id[:8]}...")

    manager.on_token_event(event_handler)

    print("  Token manager initialized")
    print()

    # -------------------------------------------------------------------------
    # Step 2: Create Tokens with Explicit Permissions
    # -------------------------------------------------------------------------
    print("Step 2: Creating Tokens with Explicit Permissions...")
    print("-" * 60)

    # Token 1: Developer token with broad access but limited budget
    print("\nCreating: Developer Testing Token")
    permissions1 = TokenPermissions(
        allowed_models=["gpt-3.5-turbo", "gpt-4", "claude-*"],  # Patterns supported
        denied_models=["dall-e-*"],  # Explicitly deny image models
        budget_limit=50.0,
        budget_period=BudgetPeriod.MONTHLY,
        rate_limit=RateLimit(requests_per_minute=30, burst_size=10),
    )

    result1 = manager.create_token(
        name="dev-testing-token",
        subject="developer@company.com",
        permissions=permissions1,
        expires_in_days=30,
        tags=["development", "testing"],
        metadata={"team": "engineering", "project": "ai-platform"},
    )

    print(f"  Token ID: {result1.token.token_id[:16]}...")
    print(f"  Subject: {result1.token.subject}")
    print(f"  Expires: {result1.token.expires_at.strftime('%Y-%m-%d')}")
    print(f"  Budget: ${permissions1.budget_limit:.2f}/{permissions1.budget_period.value}")
    print(f"  Rate Limit: {permissions1.rate_limit.requests_per_minute}/min")
    # IMPORTANT: The plaintext token is only available at creation time!
    print(f"  Token Value: {result1.plaintext_token[:20]}... (SAVE THIS!)")

    # Token 2: Production token with specific model access
    print("\nCreating: Production API Token")
    permissions2 = TokenPermissions(
        allowed_models=["gpt-3.5-turbo"],  # Only one model
        allowed_use_cases=["customer-support", "summarization"],
        budget_limit=500.0,
        budget_period=BudgetPeriod.MONTHLY,
        rate_limit=RateLimit(requests_per_minute=100),
    )

    result2 = manager.create_token(
        name="prod-support-token",
        subject="support-service@company.com",
        permissions=permissions2,
        expires_in_days=365,  # Long-lived production token
        tags=["production", "customer-support"],
    )

    print(f"  Token ID: {result2.token.token_id[:16]}...")
    print(f"  Allowed Models: {permissions2.allowed_models}")
    print(f"  Use Cases: {permissions2.allowed_use_cases}")
    print(f"  Token Value: {result2.plaintext_token[:20]}...")

    # Token 3: Restricted token with time constraints
    print("\nCreating: Contractor Limited Token")
    permissions3 = TokenPermissions(
        allowed_models=["gpt-3.5-turbo"],
        budget_limit=25.0,
        budget_period=BudgetPeriod.WEEKLY,
        valid_hours=(9, 17),  # Only 9 AM - 5 PM
    )

    result3 = manager.create_token(
        name="contractor-token",
        subject="contractor@external.com",
        permissions=permissions3,
        expires_in_days=7,  # Short-lived
        tags=["contractor", "limited"],
    )

    print(f"  Token ID: {result3.token.token_id[:16]}...")
    print(f"  Valid Hours: {permissions3.valid_hours[0]}:00 - {permissions3.valid_hours[1]}:00")
    print(f"  Budget: ${permissions3.budget_limit:.2f}/week")

    print()

    # -------------------------------------------------------------------------
    # Step 3: Create Tokens from Natural Language
    # -------------------------------------------------------------------------
    print("Step 3: Creating Tokens from Natural Language...")
    print("-" * 60)

    parser = NaturalLanguageTokenParser()

    # Parse natural language descriptions
    descriptions = [
        "Allow only GPT-4 with a budget of $100 per month",
        "Read-only access to summarization tasks, no more than 10 requests per minute",
        "Full access to OpenAI models except DALL-E, $50 weekly budget",
    ]

    for desc in descriptions:
        print(f"\nParsing: '{desc}'")
        parse_result = parser.parse(desc)

        print(f"  Confidence: {parse_result.confidence:.0%}")
        if parse_result.permissions.allowed_models:
            print(f"  Allowed Models: {parse_result.permissions.allowed_models}")
        if parse_result.permissions.denied_models:
            print(f"  Denied Models: {parse_result.permissions.denied_models}")
        if parse_result.permissions.budget_limit:
            print(f"  Budget: ${parse_result.permissions.budget_limit:.2f}/{parse_result.permissions.budget_period.value if parse_result.permissions.budget_period else 'unlimited'}")
        if parse_result.permissions.rate_limit:
            print(f"  Rate Limit: {parse_result.permissions.rate_limit.requests_per_minute}/min")
        if parse_result.warnings:
            print(f"  Warnings: {parse_result.warnings}")

    print()

    # -------------------------------------------------------------------------
    # Step 4: Use Permission Templates
    # -------------------------------------------------------------------------
    print("Step 4: Using Permission Templates...")
    print("-" * 60)

    templates = PermissionTemplates()

    print("\nAvailable templates:")
    for template_name in templates.list_templates():
        template = templates.get_template(template_name)
        print(f"  - {template_name}: {template.description}")

    # Create token from template
    print("\nCreating token from 'DEVELOPER_TESTING' template:")
    dev_permissions = templates.get_permissions("DEVELOPER_TESTING")
    result4 = manager.create_token(
        name="from-template-token",
        subject="new-dev@company.com",
        permissions=dev_permissions,
    )
    print(f"  Token created: {result4.token.token_id[:16]}...")

    print()

    # -------------------------------------------------------------------------
    # Step 5: Validate Tokens Against Requests
    # -------------------------------------------------------------------------
    print("Step 5: Validating Tokens Against Requests...")
    print("-" * 60)

    validator = TokenValidator(manager)

    # Create test requests
    test_cases = [
        {
            "token": result1.plaintext_token,
            "request": AIRequest(
                provider="openai",
                model="gpt-4",
                user_id="user-001",
            ),
            "description": "GPT-4 request with dev token",
        },
        {
            "token": result2.plaintext_token,
            "request": AIRequest(
                provider="openai",
                model="gpt-4",  # Not allowed for this token
                user_id="user-002",
            ),
            "description": "GPT-4 request with support token (should fail)",
        },
        {
            "token": result1.plaintext_token,
            "request": AIRequest(
                provider="openai",
                model="dall-e-3",  # Denied for this token
                user_id="user-003",
            ),
            "description": "DALL-E request with dev token (should fail)",
        },
        {
            "token": "pb_invalid_token_12345",
            "request": AIRequest(
                provider="openai",
                model="gpt-3.5-turbo",
                user_id="user-004",
            ),
            "description": "Request with invalid token",
        },
    ]

    for case in test_cases:
        print(f"\nValidating: {case['description']}")
        result = validator.validate(case["token"], case["request"])

        print(f"  Valid: {result.is_valid}")
        if result.is_valid:
            print(f"  Token Subject: {result.token.subject}")
        else:
            print(f"  Reason: {result.error_message}")
            if result.failed_checks:
                print(f"  Failed Checks: {', '.join(result.failed_checks)}")

    print()

    # -------------------------------------------------------------------------
    # Step 6: Track Token Usage
    # -------------------------------------------------------------------------
    print("Step 6: Tracking Token Usage...")
    print("-" * 60)

    # Simulate some usage
    print("\nRecording usage for developer token:")
    for i in range(5):
        manager.record_usage(
            token_id=result1.token.token_id,
            tokens_used=1000 + i * 500,
            cost=0.01 + i * 0.005,
        )
        print(f"  Request {i + 1}: {1000 + i * 500} tokens, ${0.01 + i * 0.005:.4f}")

    # Get usage stats
    stats = manager.get_usage_stats(result1.token.token_id)
    if stats:
        print(f"\nUsage Statistics:")
        print(f"  Total Requests: {stats.total_requests}")
        print(f"  Total Tokens: {stats.total_tokens}")
        print(f"  Total Cost: ${stats.total_cost:.4f}")
        print(f"  Budget Used: {stats.budget_used_percentage:.1f}%")
        print(f"  Budget Remaining: ${stats.budget_remaining:.2f}")

    print()

    # -------------------------------------------------------------------------
    # Step 7: List and Search Tokens
    # -------------------------------------------------------------------------
    print("Step 7: Listing and Searching Tokens...")
    print("-" * 60)

    print("\nAll active tokens:")
    all_tokens = manager.list_tokens(status=TokenStatus.ACTIVE)
    for token in all_tokens:
        print(f"  - {token.name}: {token.subject} (expires {token.expires_at.strftime('%Y-%m-%d')})")

    print("\nTokens by tag 'development':")
    dev_tokens = manager.list_tokens(tags=["development"])
    for token in dev_tokens:
        print(f"  - {token.name}")

    print("\nTokens expiring within 7 days:")
    expiring = manager.get_expiring_tokens(days=7)
    for token in expiring:
        days_left = (token.expires_at - datetime.now(token.expires_at.tzinfo)).days
        print(f"  - {token.name}: {days_left} days left")

    print()

    # -------------------------------------------------------------------------
    # Step 8: Revoke Token
    # -------------------------------------------------------------------------
    print("Step 8: Revoking Tokens...")
    print("-" * 60)

    print(f"\nRevoking contractor token: {result3.token.name}")
    success = manager.revoke_token(
        token_id=result3.token.token_id,
        revoked_by="admin@company.com",
        reason="Contract ended",
    )
    print(f"  Revocation successful: {success}")

    # Verify token is revoked
    token = manager.get_token(result3.token.token_id)
    print(f"  Token status: {token.status.value}")

    # Try to validate revoked token
    print("\nAttempting to use revoked token:")
    result = validator.validate(
        result3.plaintext_token,
        AIRequest(provider="openai", model="gpt-3.5-turbo", user_id="test"),
    )
    print(f"  Valid: {result.is_valid}")
    print(f"  Reason: {result.error_message}")

    print()

    # -------------------------------------------------------------------------
    # Step 9: Token Statistics
    # -------------------------------------------------------------------------
    print("Step 9: Token Manager Statistics...")
    print("-" * 60)

    stats = manager.get_statistics()
    print(f"\nOverall Statistics:")
    print(f"  Total Tokens: {stats.get('total_tokens', 0)}")
    print(f"  Active Tokens: {stats.get('active_tokens', 0)}")
    print(f"  Revoked Tokens: {stats.get('revoked_tokens', 0)}")
    print(f"  Expired Tokens: {stats.get('expired_tokens', 0)}")
    print(f"  Total Requests (all tokens): {stats.get('total_requests', 0)}")
    print(f"  Total Cost (all tokens): ${stats.get('total_cost', 0):.2f}")

    print()

    # -------------------------------------------------------------------------
    # Event Summary
    # -------------------------------------------------------------------------
    print("Event Summary...")
    print("-" * 60)
    print(f"\nTotal events: {len(events)}")
    event_types = {}
    for event in events:
        event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
    for etype, count in sorted(event_types.items()):
        print(f"  - {etype}: {count}")

    print()
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. Tokens control access to AI APIs with fine-grained permissions")
    print("  2. Use natural language or templates for easy token creation")
    print("  3. Tokens can have budgets, rate limits, and time restrictions")
    print("  4. Always validate tokens before processing requests")
    print("  5. Track usage to monitor costs and detect anomalies")
    print("  6. Revoke tokens immediately when no longer needed")

    return 0


if __name__ == "__main__":
    sys.exit(main())
