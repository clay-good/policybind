"""
Integration tests for complete enforcement flow.

This module tests the full enforcement lifecycle including:
- Loading policies
- Creating requests
- Running through the pipeline
- Verifying decisions
"""

import tempfile
from pathlib import Path

import pytest

from policybind.engine.parser import PolicyParser
from policybind.engine.pipeline import EnforcementPipeline, FailureMode, PipelineConfig
from policybind.engine.validator import PolicyValidator
from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest, Decision
from policybind.storage.database import Database
from policybind.storage.repositories import AuditRepository, PolicyRepository


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


@pytest.fixture
def policy_repo(temp_db: Database) -> PolicyRepository:
    """Create a policy repository."""
    return PolicyRepository(temp_db)


@pytest.fixture
def audit_repo(temp_db: Database) -> AuditRepository:
    """Create an audit repository."""
    return AuditRepository(temp_db)


@pytest.fixture
def sample_policy_yaml() -> str:
    """Create sample policy YAML content."""
    return """
name: test-enterprise-policy
version: "1.0.0"
description: Enterprise AI usage policy for testing

rules:
  - name: allow-engineering-gpt4
    description: Allow engineering team to use GPT-4
    action: ALLOW
    priority: 100
    match_conditions:
      department: engineering
      model: gpt-4

  - name: deny-high-cost
    description: Deny requests that would cost more than $10
    action: DENY
    priority: 200
    match_conditions:
      cost:
        gt: 10.0

  - name: allow-internal-claude
    description: Allow internal data with Claude models
    action: ALLOW
    priority: 50
    match_conditions:
      provider: anthropic
      data_classification:
        in:
          - internal
          - general

  - name: deny-external-pii
    description: Deny PII data to external providers
    action: DENY
    priority: 300
    match_conditions:
      data_classification:
        in:
          - pii
          - confidential

  - name: rate-limit-marketing
    description: Rate limit marketing department
    action: RATE_LIMIT
    priority: 80
    action_params:
      requests_per_minute: 10
    match_conditions:
      department: marketing

  - name: default-allow
    description: Default allow for other requests
    action: ALLOW
    priority: 1
    match_conditions: {}
"""


# =============================================================================
# Basic Enforcement Flow Tests
# =============================================================================


class TestBasicEnforcementFlow:
    """Tests for basic enforcement flow."""

    def test_allow_matching_request(self) -> None:
        """Test that matching requests are allowed."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-openai",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        assert response.decision == Decision.ALLOW
        assert "allow-openai" in response.applied_rules

    def test_deny_non_matching_request(self) -> None:
        """Test that non-matching requests are denied by default."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-anthropic-only",
                    action="ALLOW",
                    match_conditions={"provider": "anthropic"},
                    priority=10,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        assert response.decision == Decision.DENY

    def test_priority_ordering(self) -> None:
        """Test that higher priority rules take precedence."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="low-priority-allow",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
                PolicyRule(
                    name="high-priority-deny",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=100,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        assert response.decision == Decision.DENY
        assert "high-priority-deny" in response.applied_rules

    def test_multiple_conditions_all_must_match(self) -> None:
        """Test that all conditions must match for AND semantics."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="specific-allow",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "gpt-4",
                        "department": "engineering",
                    },
                    priority=10,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)

        # All conditions match - should allow
        request1 = AIRequest(
            provider="openai", model="gpt-4", department="engineering"
        )
        response1 = pipeline.process(request1)
        assert response1.decision == Decision.ALLOW

        # One condition doesn't match - should deny
        request2 = AIRequest(
            provider="openai", model="gpt-4", department="marketing"
        )
        response2 = pipeline.process(request2)
        assert response2.decision == Decision.DENY


# =============================================================================
# Policy Parsing and Enforcement Tests
# =============================================================================


class TestPolicyParsingAndEnforcement:
    """Tests for parsing policies and enforcing them."""

    def test_parse_and_enforce_yaml_policy(
        self, sample_policy_yaml: str
    ) -> None:
        """Test parsing a YAML policy and enforcing it."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(sample_policy_yaml)
            policy_path = f.name

        try:
            # Parse the policy
            parser = PolicyParser()
            result = parser.parse_file(policy_path)
            assert result.success is True
            policy = result.policy_set

            # Validate the policy
            validator = PolicyValidator()
            validation = validator.validate(policy)
            assert validation.valid is True

            # Create pipeline and test enforcement
            pipeline = EnforcementPipeline(policy)

            # Test engineering team with GPT-4 - should be allowed
            request1 = AIRequest(
                provider="openai",
                model="gpt-4",
                department="engineering",
            )
            response1 = pipeline.process(request1)
            assert response1.decision == Decision.ALLOW
            assert "allow-engineering-gpt4" in response1.applied_rules

            # Test high cost request - should be denied
            request2 = AIRequest(
                provider="openai",
                model="gpt-4",
                estimated_cost=15.0,
            )
            response2 = pipeline.process(request2)
            assert response2.decision == Decision.DENY
            assert "deny-high-cost" in response2.applied_rules

        finally:
            Path(policy_path).unlink()

    def test_policy_with_complex_conditions(self) -> None:
        """Test policy with complex nested conditions."""
        policy = PolicySet(
            name="complex-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="complex-rule",
                    action="ALLOW",
                    match_conditions={
                        "and": [
                            {"provider": "openai"},
                            {
                                "or": [
                                    {"model": "gpt-4"},
                                    {"model": "gpt-4-turbo"},
                                ]
                            },
                            {"not": {"department": "restricted"}},
                        ]
                    },
                    priority=10,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)

        # Should match - openai, gpt-4, engineering (not restricted)
        request1 = AIRequest(
            provider="openai", model="gpt-4", department="engineering"
        )
        response1 = pipeline.process(request1)
        assert response1.decision == Decision.ALLOW

        # Should match - openai, gpt-4-turbo, research (not restricted)
        request2 = AIRequest(
            provider="openai", model="gpt-4-turbo", department="research"
        )
        response2 = pipeline.process(request2)
        assert response2.decision == Decision.ALLOW

        # Should NOT match - department is restricted
        request3 = AIRequest(
            provider="openai", model="gpt-4", department="restricted"
        )
        response3 = pipeline.process(request3)
        assert response3.decision == Decision.DENY


# =============================================================================
# Action Tests
# =============================================================================


class TestEnforcementActions:
    """Tests for different enforcement actions."""

    def test_modify_action(self) -> None:
        """Test MODIFY action modifies the request."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="modify-rule",
                    action="MODIFY",
                    match_conditions={"provider": "openai"},
                    action_params={
                        "max_tokens": 1000,
                        "temperature": 0.7,
                    },
                    priority=10,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        assert response.decision == Decision.MODIFY
        assert "modify-rule" in response.applied_rules

    def test_require_approval_action(self) -> None:
        """Test REQUIRE_APPROVAL action."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="approval-rule",
                    action="REQUIRE_APPROVAL",
                    match_conditions={"department": "finance"},
                    action_params={"approvers": ["manager@example.com"]},
                    priority=10,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(
            provider="openai", model="gpt-4", department="finance"
        )
        response = pipeline.process(request)

        assert response.decision == Decision.REQUIRE_APPROVAL
        assert "approval-rule" in response.applied_rules


# =============================================================================
# Pipeline Configuration Tests
# =============================================================================


class TestPipelineConfiguration:
    """Tests for pipeline configuration options."""

    def test_fail_closed_mode(self) -> None:
        """Test fail closed mode denies on no match."""
        policy = PolicySet(
            name="empty-policy", version="1.0.0", rules=[]
        )
        config = PipelineConfig(failure_mode=FailureMode.FAIL_CLOSED)
        pipeline = EnforcementPipeline(policy, config)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        assert response.decision == Decision.DENY

    def test_timing_information(self) -> None:
        """Test that timing information is captured."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                )
            ],
        )
        config = PipelineConfig(enable_timing=True)
        pipeline = EnforcementPipeline(policy, config)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        assert response.enforcement_time_ms >= 0


# =============================================================================
# Policy Hot Reload Tests
# =============================================================================


class TestPolicyReload:
    """Tests for policy hot reloading."""

    def test_reload_changes_behavior(self) -> None:
        """Test that reloading policies changes enforcement behavior."""
        policy1 = PolicySet(
            name="policy-v1",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="deny-all",
                    action="DENY",
                    match_conditions={},
                    priority=1,
                )
            ],
        )
        policy2 = PolicySet(
            name="policy-v2",
            version="2.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                )
            ],
        )

        pipeline = EnforcementPipeline(policy1)
        request = AIRequest(provider="openai", model="gpt-4")

        # With policy1, should deny
        response1 = pipeline.process(request)
        assert response1.decision == Decision.DENY

        # Reload with policy2
        pipeline.reload_policies(policy2)

        # With policy2, should allow
        response2 = pipeline.process(request)
        assert response2.decision == Decision.ALLOW

    def test_reload_preserves_context(self) -> None:
        """Test that reload preserves pipeline configuration."""
        policy1 = PolicySet(
            name="policy-v1",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                )
            ],
        )
        policy2 = PolicySet(
            name="policy-v2",
            version="2.0.0",
            rules=[
                PolicyRule(
                    name="allow-all-v2",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                )
            ],
        )

        config = PipelineConfig(enable_timing=True)
        pipeline = EnforcementPipeline(policy1, config)

        # Reload
        pipeline.reload_policies(policy2)

        # Timing should still be enabled
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.enforcement_time_ms >= 0


# =============================================================================
# Database Integration Tests
# =============================================================================


class TestDatabaseIntegration:
    """Tests for database integration with enforcement."""

    def test_store_and_load_policy(
        self, policy_repo: PolicyRepository
    ) -> None:
        """Test storing and loading a policy from database."""
        # Create and store a policy
        policy_content = {
            "name": "stored-policy",
            "version": "1.0.0",
            "rules": [
                {
                    "name": "allow-openai",
                    "action": "ALLOW",
                    "match_conditions": {"provider": "openai"},
                    "priority": 10,
                }
            ],
        }
        policy_id = policy_repo.create(
            name="stored-policy",
            version="1.0.0",
            content=policy_content,
        )

        # Load the policy
        loaded = policy_repo.get_by_id(policy_id)
        assert loaded is not None
        assert loaded["name"] == "stored-policy"

        # Create PolicySet from loaded content
        policy = PolicySet(
            name=loaded["content"]["name"],
            version=loaded["content"]["version"],
            rules=[
                PolicyRule(
                    name=r["name"],
                    action=r["action"],
                    match_conditions=r.get("match_conditions", {}),
                    priority=r.get("priority", 0),
                )
                for r in loaded["content"]["rules"]
            ],
        )

        # Use in pipeline
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)
        assert response.decision == Decision.ALLOW


# =============================================================================
# Multiple Policy Scenarios
# =============================================================================


class TestMultiplePolicyScenarios:
    """Tests for multiple policy interaction scenarios."""

    def test_department_based_access_control(self) -> None:
        """Test department-based access control policies."""
        policy = PolicySet(
            name="dept-policy",
            version="1.0.0",
            rules=[
                # Engineering gets full access
                PolicyRule(
                    name="engineering-full-access",
                    action="ALLOW",
                    match_conditions={"department": "engineering"},
                    priority=100,
                ),
                # Marketing limited to certain models
                PolicyRule(
                    name="marketing-limited",
                    action="ALLOW",
                    match_conditions={
                        "department": "marketing",
                        "model": {"in": ["gpt-3.5-turbo", "claude-instant"]},
                    },
                    priority=90,
                ),
                # Marketing denied other models
                PolicyRule(
                    name="marketing-denied",
                    action="DENY",
                    match_conditions={"department": "marketing"},
                    priority=80,
                ),
                # Default deny
                PolicyRule(
                    name="default-deny",
                    action="DENY",
                    match_conditions={},
                    priority=1,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)

        # Engineering can use any model
        req1 = AIRequest(
            provider="openai", model="gpt-4", department="engineering"
        )
        resp1 = pipeline.process(req1)
        assert resp1.decision == Decision.ALLOW

        # Marketing can use gpt-3.5-turbo
        req2 = AIRequest(
            provider="openai", model="gpt-3.5-turbo", department="marketing"
        )
        resp2 = pipeline.process(req2)
        assert resp2.decision == Decision.ALLOW

        # Marketing cannot use gpt-4
        req3 = AIRequest(
            provider="openai", model="gpt-4", department="marketing"
        )
        resp3 = pipeline.process(req3)
        assert resp3.decision == Decision.DENY

    def test_cost_based_approval_workflow(self) -> None:
        """Test cost-based approval workflow."""
        policy = PolicySet(
            name="cost-policy",
            version="1.0.0",
            rules=[
                # High cost requires approval
                PolicyRule(
                    name="high-cost-approval",
                    action="REQUIRE_APPROVAL",
                    match_conditions={"cost": {"gt": 50.0}},
                    priority=100,
                ),
                # Medium cost gets audited
                PolicyRule(
                    name="medium-cost-audit",
                    action="AUDIT",
                    match_conditions={"cost": {"gt": 10.0}},
                    priority=90,
                ),
                # Low cost allowed
                PolicyRule(
                    name="low-cost-allow",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)

        # Low cost - allowed
        req1 = AIRequest(
            provider="openai", model="gpt-4", estimated_cost=5.0
        )
        resp1 = pipeline.process(req1)
        assert resp1.decision == Decision.ALLOW

        # High cost - requires approval
        req3 = AIRequest(
            provider="openai", model="gpt-4", estimated_cost=100.0
        )
        resp3 = pipeline.process(req3)
        assert resp3.decision == Decision.REQUIRE_APPROVAL

    def test_data_classification_enforcement(self) -> None:
        """Test data classification-based enforcement."""
        # Note: data_classification is a tuple field on the request. The "contains"
        # operator checks if the condition value is contained in the field value.
        policy = PolicySet(
            name="data-policy",
            version="1.0.0",
            rules=[
                # PII data denied to external providers
                PolicyRule(
                    name="deny-pii-external",
                    action="DENY",
                    match_conditions={
                        "data_classification": {"contains": "pii"},
                        "provider": {"in": ["openai", "anthropic"]},
                    },
                    priority=100,
                ),
                # PHI data also denied
                PolicyRule(
                    name="deny-phi-external",
                    action="DENY",
                    match_conditions={
                        "data_classification": {"contains": "phi"},
                        "provider": {"in": ["openai", "anthropic"]},
                    },
                    priority=100,
                ),
                # Confidential requires approval
                PolicyRule(
                    name="confidential-approval",
                    action="REQUIRE_APPROVAL",
                    match_conditions={
                        "data_classification": {"contains": "confidential"},
                    },
                    priority=90,
                ),
                # Default allow for general data
                PolicyRule(
                    name="allow-general",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)

        # PII to OpenAI - denied
        req1 = AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=("pii",),
        )
        resp1 = pipeline.process(req1)
        assert resp1.decision == Decision.DENY

        # General data - allowed
        req2 = AIRequest(
            provider="openai",
            model="gpt-4",
            data_classification=("general",),
        )
        resp2 = pipeline.process(req2)
        assert resp2.decision == Decision.ALLOW


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in enforcement."""

    def test_missing_required_fields_validation(self) -> None:
        """Test that missing required fields are handled."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-all",
                    action="ALLOW",
                    match_conditions={},
                    priority=1,
                )
            ],
        )
        pipeline = EnforcementPipeline(policy)

        # Empty request should fail validation
        request = AIRequest()
        response = pipeline.process(request)
        assert response.decision == Decision.DENY
        assert "required" in response.reason.lower() or "missing" in response.reason.lower()

    def test_disabled_rules_not_enforced(self) -> None:
        """Test that disabled rules are not enforced."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="disabled-deny",
                    action="DENY",
                    match_conditions={"provider": "openai"},
                    priority=100,
                    enabled=False,
                ),
                PolicyRule(
                    name="enabled-allow",
                    action="ALLOW",
                    match_conditions={"provider": "openai"},
                    priority=10,
                ),
            ],
        )
        pipeline = EnforcementPipeline(policy)
        request = AIRequest(provider="openai", model="gpt-4")
        response = pipeline.process(request)

        # Should be allowed because deny rule is disabled
        assert response.decision == Decision.ALLOW
        assert "enabled-allow" in response.applied_rules
        assert "disabled-deny" not in response.applied_rules
