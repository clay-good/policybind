#!/usr/bin/env python3
"""
PolicyBind Example: Basic Enforcement

This script demonstrates the fundamental usage of PolicyBind for AI request
enforcement. It shows how to:

1. Load policies from a YAML file
2. Create an enforcement pipeline
3. Process AI requests through the pipeline
4. Handle enforcement decisions

This is the recommended starting point for learning PolicyBind.

Prerequisites:
    - PolicyBind installed: pip install policybind
    - A policy file (we'll create one inline for this example)

Usage:
    python 01_basic_enforcement.py
"""

import sys
import tempfile
from pathlib import Path

# =============================================================================
# Step 1: Import PolicyBind components
# =============================================================================
# The main components we need are:
# - PolicyParser: To load policies from YAML
# - EnforcementPipeline: To process requests
# - AIRequest: To represent incoming AI API requests
# - Decision: Enum for enforcement decisions (ALLOW, DENY, etc.)

from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.models.request import AIRequest, Decision
from policybind.exceptions import PolicyError, EnforcementError


# =============================================================================
# Step 2: Define a sample policy
# =============================================================================
# Policies are defined in YAML format. This example policy:
# - Allows GPT-4 and GPT-3.5 models
# - Denies DALL-E (image generation) models
# - Denies all other models by default

SAMPLE_POLICY = """
name: example-policy
version: "1.0.0"
description: A simple example policy for demonstration

rules:
  # Rule 1: Deny image generation models
  # This rule has highest priority (100) so it's evaluated first
  - name: deny-image-generation
    description: Block image generation models for cost control
    action: DENY
    priority: 100
    match_conditions:
      model:
        in:
          - dall-e-3
          - dall-e-2
          - stable-diffusion

  # Rule 2: Allow GPT-4 models
  # Evaluated after deny rules due to lower priority
  - name: allow-gpt4
    description: Allow GPT-4 for general use
    action: ALLOW
    priority: 50
    match_conditions:
      provider: openai
      model:
        in:
          - gpt-4
          - gpt-4-turbo
          - gpt-4o

  # Rule 3: Allow GPT-3.5 models
  - name: allow-gpt35
    description: Allow GPT-3.5 for cost-effective tasks
    action: ALLOW
    priority: 50
    match_conditions:
      provider: openai
      model:
        in:
          - gpt-3.5-turbo
          - gpt-3.5-turbo-16k

  # Rule 4: Default deny
  # Lowest priority - matches everything not matched above
  - name: default-deny
    description: Deny all requests not explicitly allowed
    action: DENY
    priority: 1
    match_conditions: {}
"""


def create_sample_requests() -> list[AIRequest]:
    """
    Create a variety of sample requests to demonstrate different outcomes.

    Returns:
        List of AIRequest objects representing different scenarios.
    """
    return [
        # Request 1: Should be ALLOWED (matches allow-gpt4 rule)
        AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user-001",
            department="engineering",
        ),
        # Request 2: Should be ALLOWED (matches allow-gpt35 rule)
        AIRequest(
            provider="openai",
            model="gpt-3.5-turbo",
            user_id="user-002",
            department="finance",
        ),
        # Request 3: Should be DENIED (matches deny-image-generation rule)
        AIRequest(
            provider="openai",
            model="dall-e-3",
            user_id="user-003",
            department="marketing",
        ),
        # Request 4: Should be DENIED (no matching allow rule, hits default-deny)
        AIRequest(
            provider="anthropic",
            model="claude-3-opus",
            user_id="user-004",
            department="research",
        ),
    ]


def main() -> int:
    """
    Main function demonstrating basic PolicyBind enforcement.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: Basic Enforcement")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 3: Parse the policy
    # -------------------------------------------------------------------------
    # The PolicyParser converts YAML policy definitions into PolicySet objects
    # that can be used by the enforcement pipeline.

    print("Step 1: Parsing policy...")

    parser = PolicyParser()

    try:
        # parse_string() accepts YAML content directly
        # For files, use parse_file("path/to/policy.yaml")
        result = parser.parse_string(SAMPLE_POLICY)

        if not result.success:
            print("ERROR: Failed to parse policy:")
            for error in result.errors:
                print(f"  - {error}")
            return 1

        policy_set = result.policy_set
        print(f"  Loaded policy: {policy_set.name} v{policy_set.version}")
        print(f"  Rules: {len(policy_set.rules)}")
        for rule in policy_set.rules:
            print(f"    - {rule.name}: {rule.action} (priority {rule.priority})")
        print()

    except PolicyError as e:
        print(f"ERROR: Policy error: {e}")
        return 1

    # -------------------------------------------------------------------------
    # Step 4: Create the enforcement pipeline
    # -------------------------------------------------------------------------
    # The pipeline processes requests through multiple stages:
    # 1. Validation - Check required fields
    # 2. Matching - Find matching policy rules
    # 3. Action execution - Execute the matched action
    # 4. Logging - Record the decision

    print("Step 2: Creating enforcement pipeline...")

    # PipelineConfig allows customization of pipeline behavior
    config = PipelineConfig(
        enable_timing=True,  # Track how long enforcement takes
        enable_audit=False,  # Disable audit logging for this example
    )

    pipeline = EnforcementPipeline(
        policy_set=policy_set,
        config=config,
    )

    print("  Pipeline created successfully")
    print()

    # -------------------------------------------------------------------------
    # Step 5: Process requests through the pipeline
    # -------------------------------------------------------------------------
    # Each request is evaluated against the policy rules, and the pipeline
    # returns an AIResponse containing the decision.

    print("Step 3: Processing requests...")
    print("-" * 60)

    requests = create_sample_requests()
    results = {"allowed": 0, "denied": 0}

    for i, request in enumerate(requests, 1):
        print(f"\nRequest {i}:")
        print(f"  Provider: {request.provider}")
        print(f"  Model: {request.model}")
        print(f"  User: {request.user_id}")
        print(f"  Department: {request.department}")

        try:
            # Process the request through the pipeline
            response = pipeline.process(request)

            # Check the decision
            if response.decision == Decision.ALLOW:
                results["allowed"] += 1
                print(f"  Decision: ALLOWED")
            else:
                results["denied"] += 1
                print(f"  Decision: DENIED")

            # Show which rules were applied
            if response.applied_rules:
                print(f"  Applied rules: {', '.join(response.applied_rules)}")

            # Show the reason for the decision
            if response.reason:
                print(f"  Reason: {response.reason}")

            # Show timing information
            print(f"  Enforcement time: {response.enforcement_time_ms:.2f}ms")

        except EnforcementError as e:
            print(f"  ERROR: Enforcement failed: {e}")
            results["denied"] += 1

    # -------------------------------------------------------------------------
    # Step 6: Summary
    # -------------------------------------------------------------------------

    print()
    print("-" * 60)
    print("Summary:")
    print(f"  Total requests: {len(requests)}")
    print(f"  Allowed: {results['allowed']}")
    print(f"  Denied: {results['denied']}")
    print()
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
