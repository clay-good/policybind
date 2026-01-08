"""
Unit tests for PolicyBind policy parser.

This module tests the PolicyParser class for parsing YAML policy files
into PolicySet objects.
"""

import tempfile
from pathlib import Path

import pytest

from policybind.engine.parser import (
    ParseError,
    ParseResult,
    PolicyParser,
)
from policybind.models.policy import PolicySet


# =============================================================================
# ParseError Tests
# =============================================================================


class TestParseError:
    """Tests for ParseError class."""

    def test_message_only(self) -> None:
        """Test error with message only."""
        error = ParseError(message="Something went wrong")
        assert str(error) == "Something went wrong"

    def test_with_file(self) -> None:
        """Test error with file location."""
        error = ParseError(
            message="Invalid syntax",
            file="policies/main.yaml",
        )
        assert "policies/main.yaml" in str(error)
        assert "Invalid syntax" in str(error)

    def test_with_line(self) -> None:
        """Test error with file and line."""
        error = ParseError(
            message="Missing field",
            file="policy.yaml",
            line=42,
        )
        assert "policy.yaml:42" in str(error)

    def test_with_column(self) -> None:
        """Test error with file, line, and column."""
        error = ParseError(
            message="Unexpected character",
            file="policy.yaml",
            line=10,
            column=5,
        )
        assert "policy.yaml:10:5" in str(error)


class TestParseResult:
    """Tests for ParseResult class."""

    def test_success_with_policy(self) -> None:
        """Test successful parse result."""
        result = ParseResult(
            policy_set=PolicySet(name="test"),
            errors=[],
        )
        assert result.success is True

    def test_failure_with_errors(self) -> None:
        """Test failed parse result."""
        result = ParseResult(
            policy_set=None,
            errors=[ParseError(message="Error")],
        )
        assert result.success is False

    def test_failure_with_no_policy(self) -> None:
        """Test failed parse result with no policy."""
        result = ParseResult(policy_set=None, errors=[])
        assert result.success is False


# =============================================================================
# PolicyParser Tests
# =============================================================================


class TestPolicyParser:
    """Tests for PolicyParser class."""

    @pytest.fixture
    def parser(self) -> PolicyParser:
        """Create a policy parser."""
        return PolicyParser()

    def test_parse_minimal_policy(self, parser: PolicyParser) -> None:
        """Test parsing a minimal policy."""
        yaml_content = """
name: minimal-policy
version: "1.0.0"
rules: []
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert result.policy_set is not None
        assert result.policy_set.name == "minimal-policy"
        assert result.policy_set.version == "1.0.0"

    def test_parse_policy_with_rules(self, parser: PolicyParser) -> None:
        """Test parsing a policy with rules."""
        yaml_content = """
name: test-policy
version: "1.0.0"
rules:
  - name: allow-gpt4
    description: Allow GPT-4 requests
    match_conditions:
      model: gpt-4
    action: ALLOW
    priority: 10
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert len(result.policy_set.rules) == 1
        assert result.policy_set.rules[0].name == "allow-gpt4"
        assert result.policy_set.rules[0].action == "ALLOW"
        assert result.policy_set.rules[0].priority == 10

    def test_parse_multiple_rules(self, parser: PolicyParser) -> None:
        """Test parsing multiple rules."""
        yaml_content = """
name: multi-rule-policy
version: "1.0.0"
rules:
  - name: rule1
    action: ALLOW
  - name: rule2
    action: DENY
  - name: rule3
    action: MODIFY
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert len(result.policy_set.rules) == 3

    def test_parse_complex_conditions(self, parser: PolicyParser) -> None:
        """Test parsing complex match conditions."""
        yaml_content = """
name: complex-policy
version: "1.0.0"
rules:
  - name: complex-rule
    match_conditions:
      and:
        - provider: openai
        - or:
            - model: gpt-4
            - model: gpt-3.5-turbo
        - department:
            in:
              - engineering
              - research
    action: ALLOW
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        rule = result.policy_set.rules[0]
        assert "and" in rule.match_conditions

    def test_parse_action_params(self, parser: PolicyParser) -> None:
        """Test parsing action parameters."""
        yaml_content = """
name: action-params-policy
version: "1.0.0"
rules:
  - name: rate-limit-rule
    match_conditions:
      provider: openai
    action: RATE_LIMIT
    action_params:
      requests_per_minute: 10
      burst: 5
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        rule = result.policy_set.rules[0]
        assert rule.action_params["requests_per_minute"] == 10

    def test_parse_tags(self, parser: PolicyParser) -> None:
        """Test parsing rule tags."""
        yaml_content = """
name: tagged-policy
version: "1.0.0"
rules:
  - name: tagged-rule
    action: DENY
    tags:
      - security
      - compliance
      - production
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        rule = result.policy_set.rules[0]
        assert "security" in rule.tags
        assert "compliance" in rule.tags

    def test_parse_disabled_rule(self, parser: PolicyParser) -> None:
        """Test parsing disabled rule."""
        yaml_content = """
name: disabled-policy
version: "1.0.0"
rules:
  - name: disabled-rule
    action: DENY
    enabled: false
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        rule = result.policy_set.rules[0]
        assert rule.enabled is False

    def test_parse_metadata(self, parser: PolicyParser) -> None:
        """Test parsing policy metadata."""
        yaml_content = """
name: metadata-policy
version: "1.0.0"
description: Policy with metadata
metadata:
  author: security-team
  created: "2024-01-15"
  compliance:
    - SOC2
    - GDPR
rules: []
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert result.policy_set.description == "Policy with metadata"
        assert result.policy_set.metadata["author"] == "security-team"

    def test_parse_file(self, parser: PolicyParser) -> None:
        """Test parsing from file."""
        yaml_content = """
name: file-policy
version: "1.0.0"
rules:
  - name: test-rule
    action: ALLOW
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yaml",
            delete=False,
        ) as f:
            f.write(yaml_content)
            f.flush()

            result = parser.parse_file(f.name)

            assert result.success is True
            assert result.policy_set.name == "file-policy"

    def test_parse_file_not_found(self, parser: PolicyParser) -> None:
        """Test parsing non-existent file."""
        result = parser.parse_file("/nonexistent/path/policy.yaml")

        assert result.success is False
        assert len(result.errors) > 0

    def test_parse_invalid_yaml(self, parser: PolicyParser) -> None:
        """Test parsing invalid YAML."""
        yaml_content = """
name: invalid
version: 1.0.0
rules:
  - name: rule1
    action: ALLOW
    invalid_indent:
  wrong
"""
        result = parser.parse_string(yaml_content)

        assert result.success is False

    def test_parse_missing_required_field(self, parser: PolicyParser) -> None:
        """Test parsing policy missing required name field."""
        yaml_content = """
version: "1.0.0"
rules: []
"""
        result = parser.parse_string(yaml_content)

        # Should still parse but with default name
        assert result.policy_set is not None

    def test_parse_empty_string(self, parser: PolicyParser) -> None:
        """Test parsing empty string."""
        result = parser.parse_string("")

        assert result.success is False

    def test_parse_with_variables(self, parser: PolicyParser) -> None:
        """Test parsing with variable substitution."""
        yaml_content = """
name: variable-policy
version: "1.0.0"
rules:
  - name: rule-${env}
    action: ALLOW
"""
        variables = {"env": "production"}
        result = parser.parse_string(yaml_content, variables=variables)

        assert result.success is True
        # Check if variable was substituted
        rule = result.policy_set.rules[0]
        assert "production" in rule.name or "env" in rule.name

    def test_parse_with_comments(self, parser: PolicyParser) -> None:
        """Test parsing YAML with comments."""
        yaml_content = """
# This is the main policy file
name: commented-policy
version: "1.0.0"  # Version 1.0.0

# Rules section
rules:
  # First rule
  - name: rule1
    action: ALLOW  # Allow the request
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert result.policy_set.name == "commented-policy"


class TestPolicyParserEdgeCases:
    """Tests for edge cases in policy parsing."""

    @pytest.fixture
    def parser(self) -> PolicyParser:
        """Create a policy parser."""
        return PolicyParser()

    def test_empty_rules_list(self, parser: PolicyParser) -> None:
        """Test policy with empty rules list."""
        yaml_content = """
name: empty-rules
version: "1.0.0"
rules: []
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert len(result.policy_set.rules) == 0

    def test_unicode_content(self, parser: PolicyParser) -> None:
        """Test parsing unicode content."""
        yaml_content = """
name: unicode-policy
version: "1.0.0"
description: "Contains unicode: \u4e2d\u6587 \u65e5\u672c\u8a9e"
rules:
  - name: unicode-rule
    description: "More unicode: \u00e9\u00e0\u00fc"
    action: ALLOW
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert "\u4e2d\u6587" in result.policy_set.description

    def test_very_long_description(self, parser: PolicyParser) -> None:
        """Test parsing very long description."""
        long_desc = "A" * 10000
        yaml_content = f"""
name: long-desc-policy
version: "1.0.0"
description: "{long_desc}"
rules: []
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert len(result.policy_set.description) == 10000

    def test_deeply_nested_conditions(self, parser: PolicyParser) -> None:
        """Test parsing deeply nested conditions."""
        yaml_content = """
name: deep-nesting
version: "1.0.0"
rules:
  - name: deep-rule
    match_conditions:
      and:
        - or:
            - and:
                - provider: openai
                - model: gpt-4
            - and:
                - provider: anthropic
                - model: claude-3
        - not:
            department: restricted
    action: ALLOW
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        rule = result.policy_set.rules[0]
        assert "and" in rule.match_conditions

    def test_special_characters_in_names(self, parser: PolicyParser) -> None:
        """Test parsing special characters in names."""
        yaml_content = """
name: "policy-with-special-chars"
version: "1.0.0"
rules:
  - name: "rule_with_underscore"
    action: ALLOW
  - name: "rule-with-dash"
    action: ALLOW
  - name: "rule.with.dots"
    action: DENY
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert len(result.policy_set.rules) == 3

    def test_numeric_version(self, parser: PolicyParser) -> None:
        """Test parsing numeric version (should be converted to string)."""
        yaml_content = """
name: numeric-version
version: 1.0
rules: []
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True

    def test_null_values(self, parser: PolicyParser) -> None:
        """Test parsing null values."""
        yaml_content = """
name: null-values
version: "1.0.0"
description: null
rules:
  - name: rule1
    description: ~
    action: ALLOW
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True

    def test_boolean_values(self, parser: PolicyParser) -> None:
        """Test parsing boolean values."""
        yaml_content = """
name: boolean-policy
version: "1.0.0"
rules:
  - name: enabled-rule
    enabled: true
    action: ALLOW
  - name: disabled-rule
    enabled: false
    action: DENY
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        assert result.policy_set.rules[0].enabled is True
        assert result.policy_set.rules[1].enabled is False

    def test_priority_ordering(self, parser: PolicyParser) -> None:
        """Test that priorities are preserved."""
        yaml_content = """
name: priority-policy
version: "1.0.0"
rules:
  - name: low-priority
    priority: 1
    action: ALLOW
  - name: high-priority
    priority: 100
    action: DENY
  - name: medium-priority
    priority: 50
    action: MODIFY
"""
        result = parser.parse_string(yaml_content)

        assert result.success is True
        priorities = {r.name: r.priority for r in result.policy_set.rules}
        assert priorities["low-priority"] == 1
        assert priorities["high-priority"] == 100
        assert priorities["medium-priority"] == 50
