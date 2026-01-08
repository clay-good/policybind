"""
Complex test scenarios for multi-policy interactions.

This module tests complex scenarios involving multiple policies
interacting, including:
- Policy prioritization
- Conflicting rules resolution
- Cascading policy effects
- Cross-policy attribute interactions
"""

import pytest

from policybind.engine.pipeline import EnforcementPipeline
from policybind.engine.parser import PolicyParser
from policybind.models.request import AIRequest, Decision
from policybind.storage.database import Database


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    db = Database(":memory:")
    db.initialize()
    yield db
    db.close()


def create_pipeline(policy_yaml: str) -> EnforcementPipeline:
    """Create a pipeline with the given policy YAML."""
    parser = PolicyParser()
    result = parser.parse_string(policy_yaml)
    assert result.success, f"Failed to parse policy: {result.errors}"
    return EnforcementPipeline(result.policy_set)


# =============================================================================
# Multi-Policy Priority Tests
# =============================================================================


class TestMultiPolicyPriority:
    """Tests for multi-policy prioritization."""

    def test_higher_priority_policy_wins(self) -> None:
        """Test that higher priority policy takes precedence."""
        yaml_content = """
name: priority-test
version: "1.0.0"
description: Test policy priority

rules:
  - name: high-priority-deny
    description: High priority deny rule
    action: DENY
    priority: 100
    match_conditions:
      department: finance

  - name: low-priority-allow
    description: Low priority allow rule
    action: ALLOW
    priority: 10
    match_conditions:
      department: finance
"""
        pipeline = create_pipeline(yaml_content)

        response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            department="finance",
        ))

        # Higher priority rule (deny) should win
        assert response.decision == Decision.DENY

    def test_explicit_deny_overrides_allow(self) -> None:
        """Test that explicit deny rules override allow rules."""
        yaml_content = """
name: deny-override-test
version: "1.0.0"
description: Test deny override

rules:
  - name: user-deny
    description: Specific user deny
    action: DENY
    priority: 100
    match_conditions:
      user_id: blocked-user

  - name: general-allow
    description: General allow policy
    action: ALLOW
    priority: 50
    match_conditions:
      model: gpt-4
"""
        pipeline = create_pipeline(yaml_content)

        # Normal user should be allowed
        normal_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="normal-user",
        ))
        assert normal_response.decision == Decision.ALLOW

        # Blocked user should be denied
        blocked_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="blocked-user",
        ))
        assert blocked_response.decision == Decision.DENY

    def test_most_specific_policy_wins(self) -> None:
        """Test that more specific policies take precedence."""
        yaml_content = """
name: specificity-test
version: "1.0.0"
description: Test specificity

rules:
  - name: specific-user-model-deny
    description: Deny GPT-4 for specific user
    action: DENY
    priority: 100
    match_conditions:
      model: gpt-4
      user_id: restricted-user

  - name: general-model-allow
    description: Allow GPT-4 generally
    action: ALLOW
    priority: 50
    match_conditions:
      model: gpt-4
"""
        pipeline = create_pipeline(yaml_content)

        # Generic GPT-4 use should be allowed
        generic_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="generic-user",
        ))
        assert generic_response.decision == Decision.ALLOW

        # Specific user GPT-4 use should be denied
        specific_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="restricted-user",
        ))
        assert specific_response.decision == Decision.DENY


# =============================================================================
# Cross-Policy Attribute Tests
# =============================================================================


class TestCrossPolicyAttributes:
    """Tests for cross-policy attribute interactions."""

    def test_combined_attribute_evaluation(self) -> None:
        """Test policies that evaluate combinations of attributes."""
        yaml_content = """
name: combined-attr-test
version: "1.0.0"
description: Test combined attributes

rules:
  - name: deny-marketing
    description: Deny marketing
    action: DENY
    priority: 100
    match_conditions:
      department: marketing

  - name: allow-engineering-gpt4
    description: Allow engineering GPT-4
    action: ALLOW
    priority: 50
    match_conditions:
      department: engineering
      model: gpt-4

  - name: allow-legal-gpt4
    description: Allow legal GPT-4
    action: ALLOW
    priority: 50
    match_conditions:
      department: legal
      model: gpt-4
"""
        pipeline = create_pipeline(yaml_content)

        # Engineering with GPT-4 - allowed
        eng_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        ))
        assert eng_response.decision == Decision.ALLOW

        # Legal with GPT-4 - allowed
        legal_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            department="legal",
        ))
        assert legal_response.decision == Decision.ALLOW

        # Marketing - denied
        marketing_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            department="marketing",
        ))
        assert marketing_response.decision == Decision.DENY

    def test_data_classification_policy(self) -> None:
        """Test policies with data classification using contains operator."""
        yaml_content = """
name: data-class-test
version: "1.0.0"
description: Test data classification

rules:
  - name: deny-phi
    description: Deny PHI data
    action: DENY
    priority: 100
    match_conditions:
      data_classification:
        contains: phi

  - name: allow-pii-gpt4
    description: Allow PII with GPT-4
    action: ALLOW
    priority: 50
    match_conditions:
      data_classification:
        contains: pii
      model: gpt-4
"""
        pipeline = create_pipeline(yaml_content)

        # PII with GPT-4 - allowed
        pii_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=("pii",),
        ))
        assert pii_response.decision == Decision.ALLOW

        # PHI - denied
        phi_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=("phi",),
        ))
        assert phi_response.decision == Decision.DENY


# =============================================================================
# Complex Rule Interaction Tests
# =============================================================================


class TestComplexRuleInteractions:
    """Tests for complex rule interactions."""

    def test_multiple_matching_rules(self) -> None:
        """Test request that matches multiple rules."""
        yaml_content = """
name: multi-match-test
version: "1.0.0"
description: Test multiple matches

rules:
  - name: provider-match
    description: Match by provider
    action: ALLOW
    priority: 10
    match_conditions:
      provider: openai

  - name: model-match
    description: Match by model
    action: ALLOW
    priority: 20
    match_conditions:
      model: gpt-4

  - name: department-match
    description: Match by department
    action: ALLOW
    priority: 30
    match_conditions:
      department: engineering
"""
        pipeline = create_pipeline(yaml_content)

        response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        ))

        # Should be allowed (highest priority rule)
        assert response.decision == Decision.ALLOW


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases in multi-policy scenarios."""

    def test_empty_policy_set(self) -> None:
        """Test behavior with empty policy set."""
        yaml_content = """
name: empty-test
version: "1.0.0"
description: Empty policy

rules: []
"""
        pipeline = create_pipeline(yaml_content)

        response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
        ))

        # Default behavior when no rules match is DENY
        assert response.decision == Decision.DENY

    def test_no_matching_rules(self) -> None:
        """Test request that matches no rules."""
        yaml_content = """
name: no-match-test
version: "1.0.0"
description: Test no match

rules:
  - name: specific-rule
    description: Very specific rule
    action: DENY
    priority: 100
    match_conditions:
      model: very-specific-model
      department: very-specific-dept
"""
        pipeline = create_pipeline(yaml_content)

        response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
            department="engineering",
        ))

        # No rules matched, default is DENY
        assert response.decision == Decision.DENY

    def test_all_deny_policies(self) -> None:
        """Test with policies that only deny."""
        yaml_content = """
name: all-deny-test
version: "1.0.0"
description: All deny policies

rules:
  - name: deny-expensive
    description: Deny expensive models
    action: DENY
    priority: 100
    match_conditions:
      model:
        in:
          - gpt-4
          - gpt-4-turbo
          - claude-3-opus
"""
        pipeline = create_pipeline(yaml_content)

        # Expensive model - denied
        expensive_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-4",
        ))
        assert expensive_response.decision == Decision.DENY

        # Cheap model - denied (no rule matches, default is DENY)
        cheap_response = pipeline.process(AIRequest(
            provider="openai",
            model="gpt-3.5-turbo",
        ))
        assert cheap_response.decision == Decision.DENY
