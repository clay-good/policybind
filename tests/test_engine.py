"""
Tests for the policy engine components.

Tests the parser, validator, and action registry.
"""

import pytest
from pathlib import Path
import tempfile
import os

from policybind.engine import (
    Action,
    ActionRegistry,
    PolicyParser,
    PolicyValidator,
    ValidationResult,
)
from policybind.engine.actions import ActionResult, get_default_registry
from policybind.engine.parser import ParseResult
from policybind.models.policy import PolicyRule, PolicySet


class TestAction:
    """Tests for Action enum."""

    def test_all_actions_defined(self):
        """Test that all expected actions are defined."""
        expected = {
            "ALLOW",
            "DENY",
            "MODIFY",
            "REQUIRE_APPROVAL",
            "RATE_LIMIT",
            "AUDIT",
            "REDIRECT",
        }
        actual = {action.value for action in Action}
        assert actual == expected

    def test_action_values_are_strings(self):
        """Test that action values are uppercase strings."""
        for action in Action:
            assert isinstance(action.value, str)
            assert action.value == action.value.upper()


class TestActionRegistry:
    """Tests for ActionRegistry."""

    def test_default_handlers_registered(self):
        """Test that default handlers are registered for all actions."""
        registry = ActionRegistry()
        for action in Action:
            handler = registry.get_handler(action)
            assert handler is not None
            assert callable(handler)

    def test_list_actions(self):
        """Test listing all registered actions."""
        registry = ActionRegistry()
        actions = registry.list_actions()
        assert len(actions) == len(Action)
        for action in Action:
            assert action.value in actions

    def test_get_action_valid(self):
        """Test getting action from valid string."""
        registry = ActionRegistry()
        assert registry.get_action("ALLOW") == Action.ALLOW
        assert registry.get_action("deny") == Action.DENY
        assert registry.get_action("Modify") == Action.MODIFY

    def test_get_action_invalid(self):
        """Test getting action from invalid string raises error."""
        registry = ActionRegistry()
        with pytest.raises(Exception) as exc_info:
            registry.get_action("INVALID_ACTION")
        assert "Invalid action" in str(exc_info.value)

    def test_custom_handler_registration(self):
        """Test registering a custom handler."""
        registry = ActionRegistry()

        custom_called = False

        def custom_handler(context, params):
            nonlocal custom_called
            custom_called = True
            return ActionResult(
                action=Action.ALLOW,
                allowed=True,
                reason="Custom handler",
            )

        registry.register(Action.ALLOW, custom_handler)
        handler = registry.get_handler(Action.ALLOW)
        assert handler == custom_handler

    def test_get_default_registry(self):
        """Test getting default registry singleton."""
        registry1 = get_default_registry()
        registry2 = get_default_registry()
        assert registry1 is registry2


class TestPolicyParser:
    """Tests for PolicyParser."""

    def test_parse_simple_policy_string(self):
        """Test parsing a simple policy from string."""
        yaml_content = """
name: test-policy
version: "1.0.0"
description: A test policy

rules:
  - name: allow-engineering
    description: Allow engineering department
    match:
      department: engineering
    action: ALLOW
    priority: 100
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success
        assert result.policy_set is not None
        assert result.policy_set.name == "test-policy"
        assert result.policy_set.version == "1.0.0"
        assert len(result.policy_set.rules) == 1

        rule = result.policy_set.rules[0]
        assert rule.name == "allow-engineering"
        assert rule.action == "ALLOW"
        assert rule.priority == 100
        assert rule.match_conditions == {"department": "engineering"}

    def test_parse_policy_with_variables(self):
        """Test variable substitution in policies."""
        yaml_content = """
name: variable-policy
version: "1.0.0"

variables:
  max_cost: 10.0
  target_dept: engineering

rules:
  - name: cost-limit
    match:
      department: ${target_dept}
      cost:
        gt: ${max_cost}
    action: DENY
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success
        rule = result.policy_set.rules[0]
        assert rule.match_conditions["department"] == "engineering"
        assert rule.match_conditions["cost"]["gt"] == 10.0

    def test_parse_policy_with_external_variables(self):
        """Test passing external variables to parser."""
        yaml_content = """
name: external-vars
version: "1.0.0"

variables:
  internal_var: internal_value

rules:
  - name: test-rule
    match:
      department: ${external_var}
      source: ${internal_var}
    action: ALLOW
"""
        parser = PolicyParser()
        result = parser.parse_string(
            yaml_content,
            variables={"external_var": "external_value"},
        )

        assert result.success
        rule = result.policy_set.rules[0]
        assert rule.match_conditions["department"] == "external_value"
        assert rule.match_conditions["source"] == "internal_value"

    def test_parse_policy_with_complex_conditions(self):
        """Test parsing complex match conditions."""
        yaml_content = """
name: complex-policy
version: "1.0.0"

rules:
  - name: complex-rule
    match:
      and:
        - provider: openai
        - or:
            - department: engineering
            - department: research
        - not:
            data_classification:
              contains: pii
    action: ALLOW
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success
        rule = result.policy_set.rules[0]
        assert "and" in rule.match_conditions
        assert len(rule.match_conditions["and"]) == 3

    def test_parse_policy_with_action_params(self):
        """Test parsing action parameters."""
        yaml_content = """
name: action-params-policy
version: "1.0.0"

rules:
  - name: rate-limit-rule
    match:
      department: marketing
    action: RATE_LIMIT
    action_params:
      requests_per_minute: 10
      burst_size: 5
      key: user
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success
        rule = result.policy_set.rules[0]
        assert rule.action == "RATE_LIMIT"
        assert rule.action_params["requests_per_minute"] == 10
        assert rule.action_params["burst_size"] == 5

    def test_parse_policy_with_tags(self):
        """Test parsing rule tags."""
        yaml_content = """
name: tagged-policy
version: "1.0.0"

rules:
  - name: tagged-rule
    match:
      provider: openai
    action: AUDIT
    tags:
      - production
      - high-priority
      - compliance
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success
        rule = result.policy_set.rules[0]
        assert "production" in rule.tags
        assert "high-priority" in rule.tags
        assert len(rule.tags) == 3

    def test_parse_empty_policy_fails(self):
        """Test that empty policy produces error."""
        parser = PolicyParser()
        result = parser.parse_string("")

        assert not result.success
        assert len(result.errors) > 0

    def test_parse_invalid_yaml_fails(self):
        """Test that invalid YAML produces error."""
        parser = PolicyParser()
        result = parser.parse_string("{ invalid yaml: [")

        assert not result.success
        assert len(result.errors) > 0
        assert "YAML" in str(result.errors[0])

    def test_parse_policy_file(self):
        """Test parsing from a file."""
        yaml_content = """
name: file-policy
version: "1.0.0"

rules:
  - name: test-rule
    match:
      provider: anthropic
    action: ALLOW
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            parser = PolicyParser()
            result = parser.parse_file(temp_path)

            assert result.success
            assert result.policy_set.name == "file-policy"
        finally:
            os.unlink(temp_path)

    def test_parse_nonexistent_file_fails(self):
        """Test that nonexistent file produces error."""
        parser = PolicyParser()
        result = parser.parse_file("/nonexistent/path/policy.yaml")

        assert not result.success
        assert len(result.errors) > 0
        assert "not found" in str(result.errors[0])

    def test_parse_policy_with_disabled_rule(self):
        """Test parsing disabled rules."""
        yaml_content = """
name: disabled-policy
version: "1.0.0"

rules:
  - name: disabled-rule
    match:
      provider: openai
    action: DENY
    enabled: false
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success
        rule = result.policy_set.rules[0]
        assert rule.enabled is False

    def test_undefined_variable_warning(self):
        """Test that undefined variables produce warnings."""
        yaml_content = """
name: undefined-var-policy
version: "1.0.0"

rules:
  - name: test-rule
    match:
      department: ${undefined_var}
    action: ALLOW
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)

        assert result.success  # Should still parse
        assert len(result.warnings) > 0
        assert "undefined" in str(result.warnings[0]).lower()


class TestPolicyValidator:
    """Tests for PolicyValidator."""

    def test_validate_valid_policy(self):
        """Test validating a valid policy."""
        policy_set = PolicySet(
            name="valid-policy",
            version="1.0.0",
            description="A valid policy",
        )
        policy_set.add_rule(PolicyRule(
            name="allow-rule",
            description="Allow all",
            match_conditions={},
            action="ALLOW",
            priority=0,
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert len(result.errors) == 0

    def test_validate_invalid_action(self):
        """Test that invalid action produces error."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="bad-rule",
            match_conditions={},
            action="INVALID_ACTION",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert not result.valid
        assert len(result.errors) > 0
        assert "Invalid action" in str(result.errors[0])

    def test_validate_empty_name_produces_error(self):
        """Test that rule without name produces error."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="",
            match_conditions={},
            action="ALLOW",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert not result.valid

    def test_validate_duplicate_rule_names(self):
        """Test that duplicate rule names produce error."""
        policy_set = PolicySet(name="test", version="1.0.0")
        # Directly append to rules list to bypass deduplication in add_rule
        policy_set.rules.append(PolicyRule(
            name="duplicate-name",
            match_conditions={"provider": "openai"},
            action="ALLOW",
        ))
        policy_set.rules.append(PolicyRule(
            name="duplicate-name",
            match_conditions={"provider": "anthropic"},
            action="DENY",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert not result.valid
        assert any("Duplicate" in str(e) for e in result.errors)

    def test_validate_empty_conditions_warning(self):
        """Test that empty conditions produce warning."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="catch-all",
            match_conditions={},
            action="DENY",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid  # Warning, not error
        assert any("match all" in str(w).lower() for w in result.warnings)

    def test_validate_unknown_condition_field_warning(self):
        """Test that unknown condition field produces warning."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="unknown-field-rule",
            match_conditions={"unknown_field": "value"},
            action="ALLOW",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid  # Warning, not error
        assert any("Unknown condition field" in str(w) for w in result.warnings)

    def test_validate_modify_without_params_warning(self):
        """Test that MODIFY without params produces warning."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="modify-rule",
            match_conditions={"provider": "openai"},
            action="MODIFY",
            action_params={},
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert any("MODIFY" in str(w) for w in result.warnings)

    def test_validate_redirect_without_target_warning(self):
        """Test that REDIRECT without target produces warning."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="redirect-rule",
            match_conditions={"provider": "openai"},
            action="REDIRECT",
            action_params={},
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert any("REDIRECT" in str(w) for w in result.warnings)

    def test_validate_rate_limit_without_rate_warning(self):
        """Test that RATE_LIMIT without rate produces warning."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="rate-limit-rule",
            match_conditions={"provider": "openai"},
            action="RATE_LIMIT",
            action_params={},
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert any("RATE_LIMIT" in str(w) for w in result.warnings)

    def test_validate_disabled_rule_info(self):
        """Test that disabled rule produces info message."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="disabled-rule",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            enabled=False,
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert any("disabled" in str(i).lower() for i in result.info)

    def test_validate_policy_set_without_name_warning(self):
        """Test that policy set without name produces warning."""
        policy_set = PolicySet(name="", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="test-rule",
            match_conditions={},
            action="ALLOW",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert any("no name" in str(w).lower() for w in result.warnings)

    def test_validate_policy_set_without_version_warning(self):
        """Test that policy set without version produces warning."""
        policy_set = PolicySet(name="test", version="")
        policy_set.add_rule(PolicyRule(
            name="test-rule",
            match_conditions={},
            action="ALLOW",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid
        assert any("no version" in str(w).lower() for w in result.warnings)

    def test_validate_conflicting_rules_warning(self):
        """Test that conflicting rules produce warning."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="rule-1",
            match_conditions={"provider": "openai"},
            action="ALLOW",
            priority=100,
        ))
        policy_set.add_rule(PolicyRule(
            name="rule-2",
            match_conditions={"provider": "openai"},
            action="DENY",
            priority=100,  # Same priority, same conditions, different action
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid  # Warning, not error
        assert any("conflicting" in str(w).lower() for w in result.warnings)

    def test_validate_logical_operator_conditions(self):
        """Test validation of logical operators in conditions."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="logical-rule",
            match_conditions={
                "and": [
                    {"provider": "openai"},
                    {"department": "engineering"},
                ],
            },
            action="ALLOW",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert result.valid

    def test_validate_invalid_logical_operator(self):
        """Test that invalid logical operator value produces error."""
        policy_set = PolicySet(name="test", version="1.0.0")
        policy_set.add_rule(PolicyRule(
            name="bad-logical-rule",
            match_conditions={
                "and": "not-a-list",  # Should be a list
            },
            action="ALLOW",
        ))

        validator = PolicyValidator()
        result = validator.validate(policy_set)

        assert not result.valid

    def test_validation_result_all_messages(self):
        """Test getting all messages from validation result."""
        result = ValidationResult()
        result.add_error("Error 1")
        result.add_warning("Warning 1")
        result.add_info("Info 1")

        messages = result.all_messages()
        assert len(messages) == 3
        # Errors come first, then warnings, then info
        assert messages[0].message == "Error 1"
        assert messages[1].message == "Warning 1"
        assert messages[2].message == "Info 1"


class TestIntegration:
    """Integration tests for parser and validator together."""

    def test_parse_and_validate_valid_policy(self):
        """Test parsing and validating a complete valid policy."""
        yaml_content = """
name: complete-policy
version: "1.0.0"
description: A complete test policy

variables:
  max_cost: 100.0
  premium_models:
    - gpt-4
    - claude-3-opus

rules:
  - name: block-pii-external
    description: Block PII data from external providers
    match:
      and:
        - data_classification:
            contains: pii
        - provider:
            not_in:
              - internal
              - on-premise
    action: DENY
    action_params:
      reason: "PII data cannot be sent to external providers"
    priority: 500
    tags:
      - security
      - compliance

  - name: cost-limit
    description: Limit costs
    match:
      cost:
        gt: ${max_cost}
    action: DENY
    priority: 400

  - name: premium-model-approval
    description: Require approval for premium models
    match:
      model:
        in: ${premium_models}
    action: REQUIRE_APPROVAL
    action_params:
      approvers:
        - ai-governance
      timeout_hours: 4
    priority: 300

  - name: default-allow
    description: Allow everything else
    match: {}
    action: ALLOW
    priority: 0
"""
        # Parse
        parser = PolicyParser()
        parse_result = parser.parse_string(yaml_content)

        assert parse_result.success
        assert parse_result.policy_set is not None

        # Validate
        validator = PolicyValidator()
        validation_result = validator.validate(parse_result.policy_set)

        assert validation_result.valid
        assert len(validation_result.errors) == 0

        # Check parsed values
        policy = parse_result.policy_set
        assert policy.name == "complete-policy"
        assert len(policy.rules) == 4

        # Check variable substitution
        cost_rule = next(r for r in policy.rules if r.name == "cost-limit")
        assert cost_rule.match_conditions["cost"]["gt"] == 100.0

        premium_rule = next(
            r for r in policy.rules if r.name == "premium-model-approval"
        )
        assert premium_rule.match_conditions["model"]["in"] == [
            "gpt-4", "claude-3-opus"
        ]

    def test_parse_and_validate_with_errors(self):
        """Test parsing a policy that will fail validation."""
        yaml_content = """
name: invalid-policy
version: "1.0.0"

rules:
  - name: bad-action-rule
    match:
      provider: openai
    action: NOT_A_REAL_ACTION
"""
        parser = PolicyParser()
        parse_result = parser.parse_string(yaml_content)

        # Parsing succeeds (syntax is valid)
        assert parse_result.success

        # But validation fails
        validator = PolicyValidator()
        validation_result = validator.validate(parse_result.policy_set)

        assert not validation_result.valid
        assert len(validation_result.errors) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
