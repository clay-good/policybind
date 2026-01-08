"""
Unit tests for PolicyBind data models.

This module tests all core data models including base utilities,
policy models, request/response models, and registry models.
"""

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from policybind.models.base import (
    BaseModel,
    generate_uuid,
    model_to_dict,
    model_to_json,
    serialize_value,
    utc_now,
)
from policybind.models.policy import (
    PolicyMatch,
    PolicyRule,
    PolicySet,
)
from policybind.models.request import (
    AIRequest,
    AIResponse,
    Decision,
)
from policybind.models.registry import (
    ApprovalStatus,
    ModelDeployment,
    RiskLevel,
)


# =============================================================================
# Base Model Utilities Tests
# =============================================================================


class TestGenerateUuid:
    """Tests for generate_uuid function."""

    def test_returns_string(self) -> None:
        """Test that generate_uuid returns a string."""
        result = generate_uuid()
        assert isinstance(result, str)

    def test_returns_valid_uuid_format(self) -> None:
        """Test that generate_uuid returns valid UUID4 format."""
        result = generate_uuid()
        # UUID4 format: 8-4-4-4-12 hex characters
        parts = result.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

    def test_generates_unique_values(self) -> None:
        """Test that generate_uuid produces unique values."""
        uuids = [generate_uuid() for _ in range(100)]
        assert len(set(uuids)) == 100


class TestUtcNow:
    """Tests for utc_now function."""

    def test_returns_datetime(self) -> None:
        """Test that utc_now returns a datetime object."""
        result = utc_now()
        assert isinstance(result, datetime)

    def test_has_utc_timezone(self) -> None:
        """Test that utc_now returns UTC timezone."""
        result = utc_now()
        assert result.tzinfo == timezone.utc

    def test_returns_current_time(self) -> None:
        """Test that utc_now returns approximately current time."""
        before = datetime.now(timezone.utc)
        result = utc_now()
        after = datetime.now(timezone.utc)

        assert before <= result <= after


class TestSerializeValue:
    """Tests for serialize_value function."""

    def test_serialize_datetime(self) -> None:
        """Test serializing datetime to ISO format."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = serialize_value(dt)
        assert result == "2024-01-15T10:30:00+00:00"

    def test_serialize_dict(self) -> None:
        """Test serializing nested dict."""
        data = {"a": 1, "b": {"c": 2}}
        result = serialize_value(data)
        assert result == {"a": 1, "b": {"c": 2}}

    def test_serialize_dict_with_datetime(self) -> None:
        """Test serializing dict with datetime values."""
        dt = datetime(2024, 1, 15, tzinfo=timezone.utc)
        data = {"timestamp": dt}
        result = serialize_value(data)
        assert isinstance(result["timestamp"], str)

    def test_serialize_list(self) -> None:
        """Test serializing list."""
        data = [1, 2, 3]
        result = serialize_value(data)
        assert result == [1, 2, 3]

    def test_serialize_tuple(self) -> None:
        """Test serializing tuple."""
        data = (1, 2, 3)
        result = serialize_value(data)
        assert result == [1, 2, 3]

    def test_exclude_none_in_dict(self) -> None:
        """Test excluding None values from dict."""
        data = {"a": 1, "b": None, "c": 3}
        result = serialize_value(data, exclude_none=True)
        assert "b" not in result
        assert result == {"a": 1, "c": 3}

    def test_serialize_enum(self) -> None:
        """Test serializing enum values."""
        result = serialize_value(Decision.ALLOW)
        assert result == "ALLOW"

    def test_serialize_primitive(self) -> None:
        """Test serializing primitive types."""
        assert serialize_value(42) == 42
        assert serialize_value("hello") == "hello"
        assert serialize_value(3.14) == 3.14
        assert serialize_value(True) is True


class TestBaseModel:
    """Tests for BaseModel class."""

    def test_auto_generated_id(self) -> None:
        """Test that id is auto-generated."""
        model = BaseModel()
        assert model.id is not None
        assert len(model.id) > 0

    def test_auto_generated_timestamps(self) -> None:
        """Test that timestamps are auto-generated."""
        model = BaseModel()
        assert model.created_at is not None
        assert model.updated_at is not None
        assert model.created_at.tzinfo == timezone.utc

    def test_custom_id(self) -> None:
        """Test using custom id."""
        model = BaseModel(id="custom-id")
        assert model.id == "custom-id"

    def test_to_dict(self) -> None:
        """Test converting model to dict."""
        model = BaseModel(id="test-id")
        result = model.to_dict()

        assert result["id"] == "test-id"
        assert "created_at" in result
        assert "updated_at" in result
        assert isinstance(result["created_at"], str)

    def test_to_dict_exclude_none(self) -> None:
        """Test to_dict with exclude_none option."""
        model = BaseModel()
        result = model.to_dict(exclude_none=True)
        # BaseModel doesn't have None fields by default
        assert "id" in result

    def test_to_json(self) -> None:
        """Test converting model to JSON."""
        model = BaseModel(id="test-id")
        result = model.to_json()

        parsed = json.loads(result)
        assert parsed["id"] == "test-id"

    def test_to_json_with_indent(self) -> None:
        """Test to_json with indentation."""
        model = BaseModel()
        result = model.to_json(indent=2)
        assert "\n" in result

    def test_from_dict(self) -> None:
        """Test creating model from dict."""
        data = {
            "id": "test-id",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        model = BaseModel.from_dict(data)
        assert model.id == "test-id"

    def test_repr(self) -> None:
        """Test string representation."""
        model = BaseModel(id="test-id")
        result = repr(model)
        assert "BaseModel" in result
        assert "test-id" in result


class TestModelToDict:
    """Tests for model_to_dict function."""

    def test_converts_dataclass(self) -> None:
        """Test converting a dataclass to dict."""
        rule = PolicyRule(name="test-rule", action="ALLOW")
        result = model_to_dict(rule)

        assert result["name"] == "test-rule"
        assert result["action"] == "ALLOW"

    def test_exclude_none(self) -> None:
        """Test excluding None values."""
        rule = PolicyRule(name="test")
        result = model_to_dict(rule, exclude_none=True)
        assert isinstance(result, dict)


class TestModelToJson:
    """Tests for model_to_json function."""

    def test_returns_valid_json(self) -> None:
        """Test that model_to_json returns valid JSON."""
        rule = PolicyRule(name="test-rule")
        result = model_to_json(rule)

        parsed = json.loads(result)
        assert parsed["name"] == "test-rule"


# =============================================================================
# Policy Model Tests
# =============================================================================


class TestPolicyRule:
    """Tests for PolicyRule class."""

    def test_create_minimal_rule(self) -> None:
        """Test creating a rule with minimal fields."""
        rule = PolicyRule(name="test-rule")

        assert rule.name == "test-rule"
        assert rule.action == "DENY"  # default
        assert rule.enabled is True
        assert rule.priority == 0

    def test_create_full_rule(self) -> None:
        """Test creating a rule with all fields."""
        rule = PolicyRule(
            name="deny-pii",
            description="Deny requests containing PII",
            match_conditions={"data_classification": ["pii"]},
            action="DENY",
            action_params={"reason": "PII not allowed"},
            priority=100,
            enabled=True,
            tags=("security", "compliance"),
        )

        assert rule.name == "deny-pii"
        assert rule.description == "Deny requests containing PII"
        assert rule.match_conditions == {"data_classification": ["pii"]}
        assert rule.priority == 100
        assert "security" in rule.tags

    def test_rule_is_frozen(self) -> None:
        """Test that PolicyRule is immutable."""
        rule = PolicyRule(name="test")

        with pytest.raises(FrozenInstanceError):
            rule.name = "new-name"  # type: ignore

    def test_rule_hash(self) -> None:
        """Test that rules are hashable."""
        rule = PolicyRule(name="test")
        rule_set = {rule}  # Should work if hashable
        assert rule in rule_set

    def test_rule_equality(self) -> None:
        """Test rule equality based on id."""
        rule1 = PolicyRule(id="same-id", name="rule1")
        rule2 = PolicyRule(id="same-id", name="rule2")
        rule3 = PolicyRule(id="different-id", name="rule1")

        assert rule1 == rule2
        assert rule1 != rule3

    def test_rule_to_dict(self) -> None:
        """Test converting rule to dict."""
        rule = PolicyRule(name="test", action="ALLOW")
        result = rule.to_dict()

        assert result["name"] == "test"
        assert result["action"] == "ALLOW"
        assert "id" in result

    def test_rule_to_json(self) -> None:
        """Test converting rule to JSON."""
        rule = PolicyRule(name="test")
        result = rule.to_json()

        parsed = json.loads(result)
        assert parsed["name"] == "test"

    def test_rule_repr(self) -> None:
        """Test rule string representation."""
        rule = PolicyRule(name="test-rule", action="DENY", priority=10)
        result = repr(rule)

        assert "PolicyRule" in result
        assert "test-rule" in result
        assert "DENY" in result


class TestPolicySet:
    """Tests for PolicySet class."""

    def test_create_empty_policy_set(self) -> None:
        """Test creating an empty policy set."""
        policy_set = PolicySet(name="test-policies", version="1.0.0")

        assert policy_set.name == "test-policies"
        assert policy_set.version == "1.0.0"
        assert len(policy_set.rules) == 0

    def test_add_rule(self) -> None:
        """Test adding a rule to policy set."""
        policy_set = PolicySet(name="test")
        rule = PolicyRule(name="rule1", action="ALLOW")

        policy_set.add_rule(rule)

        assert len(policy_set.rules) == 1
        assert policy_set.rules[0].name == "rule1"

    def test_add_rule_replaces_same_name(self) -> None:
        """Test that adding rule with same name replaces existing."""
        policy_set = PolicySet(name="test")
        rule1 = PolicyRule(name="rule1", action="ALLOW")
        rule2 = PolicyRule(name="rule1", action="DENY")

        policy_set.add_rule(rule1)
        policy_set.add_rule(rule2)

        assert len(policy_set.rules) == 1
        assert policy_set.rules[0].action == "DENY"

    def test_remove_rule(self) -> None:
        """Test removing a rule from policy set."""
        policy_set = PolicySet(name="test")
        rule = PolicyRule(name="rule1")

        policy_set.add_rule(rule)
        result = policy_set.remove_rule("rule1")

        assert result is True
        assert len(policy_set.rules) == 0

    def test_remove_nonexistent_rule(self) -> None:
        """Test removing a rule that doesn't exist."""
        policy_set = PolicySet(name="test")
        result = policy_set.remove_rule("nonexistent")

        assert result is False

    def test_get_rule_by_name(self) -> None:
        """Test getting a rule by name."""
        policy_set = PolicySet(name="test")
        rule = PolicyRule(name="rule1", action="ALLOW")
        policy_set.add_rule(rule)

        result = policy_set.get_rule("rule1")

        assert result is not None
        assert result.action == "ALLOW"

    def test_get_nonexistent_rule(self) -> None:
        """Test getting a rule that doesn't exist."""
        policy_set = PolicySet(name="test")
        result = policy_set.get_rule("nonexistent")

        assert result is None

    def test_get_rules_by_tag(self) -> None:
        """Test getting rules by tag."""
        policy_set = PolicySet(name="test")
        rule1 = PolicyRule(name="rule1", tags=("security",))
        rule2 = PolicyRule(name="rule2", tags=("compliance",))
        rule3 = PolicyRule(name="rule3", tags=("security", "compliance"))

        policy_set.add_rule(rule1)
        policy_set.add_rule(rule2)
        policy_set.add_rule(rule3)

        security_rules = policy_set.get_rules_by_tag("security")
        assert len(security_rules) == 2

    def test_get_enabled_rules(self) -> None:
        """Test getting only enabled rules."""
        policy_set = PolicySet(name="test")
        rule1 = PolicyRule(name="rule1", enabled=True)
        rule2 = PolicyRule(name="rule2", enabled=False)

        policy_set.add_rule(rule1)
        policy_set.add_rule(rule2)

        enabled = policy_set.get_enabled_rules()
        assert len(enabled) == 1
        assert enabled[0].name == "rule1"

    def test_policy_set_to_dict(self) -> None:
        """Test converting policy set to dict."""
        policy_set = PolicySet(name="test", version="1.0.0")
        rule = PolicyRule(name="rule1")
        policy_set.add_rule(rule)

        result = policy_set.to_dict()

        assert result["name"] == "test"
        assert result["version"] == "1.0.0"
        assert len(result["rules"]) == 1


class TestPolicyMatch:
    """Tests for PolicyMatch class."""

    def test_create_policy_match(self) -> None:
        """Test creating a policy match result."""
        rule = PolicyRule(name="test-rule", action="ALLOW")
        result = PolicyMatch(
            matched=True,
            rule=rule,
            match_score=0.75,
        )

        assert result.matched is True
        assert result.rule is not None
        assert result.rule.name == "test-rule"
        assert result.match_score == 0.75

    def test_policy_match_no_match(self) -> None:
        """Test policy match when no rule matched."""
        result = PolicyMatch(matched=False)

        assert result.matched is False
        assert result.rule is None
        assert result.match_score == 0.0

    def test_policy_match_with_conditions(self) -> None:
        """Test policy match with matched conditions."""
        rule = PolicyRule(name="test-rule", action="ALLOW")
        result = PolicyMatch(
            matched=True,
            rule=rule,
            matched_conditions={"provider": "openai", "model": "gpt-4"},
        )

        assert "provider" in result.matched_conditions
        assert result.matched_conditions["model"] == "gpt-4"


# =============================================================================
# Request/Response Model Tests
# =============================================================================


class TestDecision:
    """Tests for Decision enum."""

    def test_all_decisions_defined(self) -> None:
        """Test that all expected decisions are defined."""
        assert Decision.ALLOW.value == "ALLOW"
        assert Decision.DENY.value == "DENY"
        assert Decision.MODIFY.value == "MODIFY"
        assert Decision.REQUIRE_APPROVAL.value == "REQUIRE_APPROVAL"


class TestAIRequest:
    """Tests for AIRequest class."""

    def test_create_minimal_request(self) -> None:
        """Test creating a request with minimal fields."""
        request = AIRequest(provider="openai", model="gpt-4")

        assert request.provider == "openai"
        assert request.model == "gpt-4"
        assert request.request_id != ""

    def test_create_full_request(self) -> None:
        """Test creating a request with all fields."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            prompt_hash="abc123",
            estimated_tokens=1000,
            estimated_cost=0.05,
            source_application="test-app",
            user_id="user-1",
            department="engineering",
            data_classification=("pii", "confidential"),
            intended_use_case="summarization",
            metadata={"custom": "value"},
        )

        assert request.estimated_tokens == 1000
        assert request.estimated_cost == 0.05
        assert "pii" in request.data_classification

    def test_request_is_frozen(self) -> None:
        """Test that AIRequest is immutable."""
        request = AIRequest(provider="openai", model="gpt-4")

        with pytest.raises(FrozenInstanceError):
            request.provider = "anthropic"  # type: ignore

    def test_request_id_auto_set(self) -> None:
        """Test that request_id is set from id if not provided."""
        request = AIRequest(provider="openai", model="gpt-4")
        assert request.request_id == request.id

    def test_custom_request_id(self) -> None:
        """Test using custom request_id."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            request_id="custom-request-id",
        )
        assert request.request_id == "custom-request-id"

    def test_request_hash(self) -> None:
        """Test that requests are hashable."""
        request = AIRequest(provider="openai", model="gpt-4")
        request_set = {request}
        assert request in request_set

    def test_request_equality(self) -> None:
        """Test request equality based on id."""
        request1 = AIRequest(id="same-id", provider="openai", model="gpt-4")
        request2 = AIRequest(id="same-id", provider="anthropic", model="claude")

        assert request1 == request2

    def test_request_to_dict(self) -> None:
        """Test converting request to dict."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user-1",
        )
        result = request.to_dict()

        assert result["provider"] == "openai"
        assert result["model"] == "gpt-4"
        assert result["user_id"] == "user-1"

    def test_request_to_json(self) -> None:
        """Test converting request to JSON."""
        request = AIRequest(provider="openai", model="gpt-4")
        result = request.to_json()

        parsed = json.loads(result)
        assert parsed["provider"] == "openai"

    def test_request_repr(self) -> None:
        """Test request string representation."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            user_id="user-1",
        )
        result = repr(request)

        assert "AIRequest" in result
        assert "openai" in result
        assert "gpt-4" in result


class TestAIResponse:
    """Tests for AIResponse class."""

    def test_create_response(self) -> None:
        """Test creating a response."""
        response = AIResponse(
            request_id="req-1",
            decision=Decision.ALLOW,
        )

        assert response.request_id == "req-1"
        assert response.decision == Decision.ALLOW

    def test_response_with_applied_rules(self) -> None:
        """Test response with applied rules."""
        response = AIResponse(
            request_id="req-1",
            decision=Decision.DENY,
            applied_rules=("rule1", "rule2"),
            reason="PII detected",
        )

        assert len(response.applied_rules) == 2
        assert response.reason == "PII detected"

    def test_response_with_modifications(self) -> None:
        """Test response with modifications."""
        response = AIResponse(
            request_id="req-1",
            decision=Decision.MODIFY,
            modifications={"redacted_fields": ["email", "phone"]},
        )

        assert "redacted_fields" in response.modifications

    def test_response_is_frozen(self) -> None:
        """Test that AIResponse is immutable."""
        response = AIResponse(request_id="req-1", decision=Decision.ALLOW)

        with pytest.raises(FrozenInstanceError):
            response.decision = Decision.DENY  # type: ignore

    def test_response_to_dict(self) -> None:
        """Test converting response to dict."""
        response = AIResponse(
            request_id="req-1",
            decision=Decision.ALLOW,
        )
        result = response.to_dict()

        assert result["request_id"] == "req-1"
        assert result["decision"] == "ALLOW"


# =============================================================================
# Registry Model Tests
# =============================================================================


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_all_levels_defined(self) -> None:
        """Test that all risk levels are defined."""
        assert RiskLevel.LOW.value == "LOW"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.CRITICAL.value == "CRITICAL"


class TestApprovalStatus:
    """Tests for ApprovalStatus enum."""

    def test_all_statuses_defined(self) -> None:
        """Test that all approval statuses are defined."""
        assert ApprovalStatus.PENDING.value == "PENDING"
        assert ApprovalStatus.APPROVED.value == "APPROVED"
        assert ApprovalStatus.REJECTED.value == "REJECTED"
        assert ApprovalStatus.SUSPENDED.value == "SUSPENDED"


class TestModelDeployment:
    """Tests for ModelDeployment class."""

    def test_create_minimal_deployment(self) -> None:
        """Test creating a deployment with minimal fields."""
        deployment = ModelDeployment(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-a",
        )

        assert deployment.name == "test-deployment"
        assert deployment.model_provider == "openai"
        assert deployment.risk_level == RiskLevel.MEDIUM  # default
        assert deployment.approval_status == ApprovalStatus.PENDING  # default

    def test_create_full_deployment(self) -> None:
        """Test creating a deployment with all fields."""
        deployment = ModelDeployment(
            name="production-gpt4",
            description="Production GPT-4 deployment",
            model_provider="openai",
            model_name="gpt-4",
            model_version="0613",
            owner="ml-team",
            owner_contact="ml-team@example.com",
            data_categories=("general", "pii"),
            risk_level=RiskLevel.HIGH,
            approval_status=ApprovalStatus.APPROVED,
            metadata={"environment": "production"},
        )

        assert deployment.risk_level == RiskLevel.HIGH
        assert deployment.approval_status == ApprovalStatus.APPROVED
        assert "pii" in deployment.data_categories

    def test_deployment_to_dict(self) -> None:
        """Test converting deployment to dict."""
        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            risk_level=RiskLevel.HIGH,
        )
        result = deployment.to_dict()

        assert result["name"] == "test"
        assert result["risk_level"] == "HIGH"

    def test_deployment_repr(self) -> None:
        """Test deployment string representation."""
        deployment = ModelDeployment(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
        )
        result = repr(deployment)

        assert "ModelDeployment" in result
        assert "test-deployment" in result


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_strings(self) -> None:
        """Test handling of empty strings."""
        request = AIRequest(provider="", model="")
        assert request.provider == ""
        assert request.model == ""

    def test_empty_collections(self) -> None:
        """Test handling of empty collections."""
        request = AIRequest(
            provider="test",
            model="test",
            data_classification=(),
            metadata={},
        )
        assert len(request.data_classification) == 0
        assert len(request.metadata) == 0

    def test_unicode_strings(self) -> None:
        """Test handling of unicode strings."""
        rule = PolicyRule(
            name="unicode-test",
            description="Test with unicode: \u4e2d\u6587 \u65e5\u672c\u8a9e",
        )
        result = rule.to_json()
        parsed = json.loads(result)
        assert "\u4e2d\u6587" in parsed["description"]

    def test_large_numbers(self) -> None:
        """Test handling of large numbers."""
        request = AIRequest(
            provider="test",
            model="test",
            estimated_tokens=10**9,
            estimated_cost=10**6,
        )
        assert request.estimated_tokens == 10**9
        assert request.estimated_cost == 10**6

    def test_zero_values(self) -> None:
        """Test handling of zero values."""
        request = AIRequest(
            provider="test",
            model="test",
            estimated_tokens=0,
            estimated_cost=0.0,
        )
        assert request.estimated_tokens == 0
        assert request.estimated_cost == 0.0

    def test_negative_values(self) -> None:
        """Test handling of negative values."""
        rule = PolicyRule(name="test", priority=-100)
        assert rule.priority == -100

    def test_special_characters_in_strings(self) -> None:
        """Test handling of special characters."""
        rule = PolicyRule(
            name="test-rule",
            description='Contains "quotes" and \\backslashes',
        )
        result = rule.to_json()
        parsed = json.loads(result)
        assert "quotes" in parsed["description"]

    def test_deeply_nested_metadata(self) -> None:
        """Test handling of deeply nested metadata."""
        metadata = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}
        request = AIRequest(provider="test", model="test", metadata=metadata)
        result = request.to_dict()
        assert result["metadata"]["a"]["b"]["c"]["d"]["e"] == "deep"
