"""
Unit tests for PolicyBind policy validator.

This module tests the PolicyValidator class for validating
parsed policies for semantic correctness.
"""

import pytest

from policybind.engine.validator import (
    MessageLevel,
    PolicyValidator,
    ValidationMessage,
    ValidationResult,
)
from policybind.models.policy import PolicyRule, PolicySet


# =============================================================================
# ValidationMessage Tests
# =============================================================================


class TestValidationMessage:
    """Tests for ValidationMessage class."""

    def test_create_error_message(self) -> None:
        """Test creating an error message."""
        msg = ValidationMessage(
            level=MessageLevel.ERROR,
            message="Something went wrong",
        )
        assert msg.level == MessageLevel.ERROR
        assert msg.message == "Something went wrong"
        assert msg.rule_name == ""
        assert msg.field_name == ""

    def test_create_warning_message(self) -> None:
        """Test creating a warning message."""
        msg = ValidationMessage(
            level=MessageLevel.WARNING,
            message="This might be an issue",
        )
        assert msg.level == MessageLevel.WARNING
        assert msg.message == "This might be an issue"

    def test_create_info_message(self) -> None:
        """Test creating an info message."""
        msg = ValidationMessage(
            level=MessageLevel.INFO,
            message="FYI",
        )
        assert msg.level == MessageLevel.INFO
        assert msg.message == "FYI"

    def test_message_with_rule_name(self) -> None:
        """Test message with rule name."""
        msg = ValidationMessage(
            level=MessageLevel.ERROR,
            message="Invalid action",
            rule_name="my-rule",
        )
        result = str(msg)
        assert "[ERROR]" in result
        assert "my-rule" in result
        assert "Invalid action" in result

    def test_message_with_field_name(self) -> None:
        """Test message with field name."""
        msg = ValidationMessage(
            level=MessageLevel.WARNING,
            message="Unknown field",
            rule_name="my-rule",
            field_name="action_params",
        )
        result = str(msg)
        assert "[WARNING]" in result
        assert "my-rule" in result
        assert "action_params" in result

    def test_message_with_details(self) -> None:
        """Test message with details."""
        msg = ValidationMessage(
            level=MessageLevel.ERROR,
            message="Duplicate name",
            details={"first_occurrence": 1},
        )
        assert msg.details["first_occurrence"] == 1

    def test_str_formatting(self) -> None:
        """Test string formatting of messages."""
        msg = ValidationMessage(
            level=MessageLevel.ERROR,
            message="Test error",
            rule_name="test-rule",
            field_name="test-field",
        )
        result = str(msg)
        assert "[ERROR]" in result
        assert "Rule 'test-rule'" in result
        assert "field 'test-field'" in result
        assert "Test error" in result


class TestMessageLevel:
    """Tests for MessageLevel enum."""

    def test_error_value(self) -> None:
        """Test error level value."""
        assert MessageLevel.ERROR.value == "error"

    def test_warning_value(self) -> None:
        """Test warning level value."""
        assert MessageLevel.WARNING.value == "warning"

    def test_info_value(self) -> None:
        """Test info level value."""
        assert MessageLevel.INFO.value == "info"


# =============================================================================
# ValidationResult Tests
# =============================================================================


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_default_valid(self) -> None:
        """Test that default result is valid."""
        result = ValidationResult()
        assert result.valid is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert len(result.info) == 0

    def test_add_error_invalidates(self) -> None:
        """Test that adding an error makes result invalid."""
        result = ValidationResult()
        result.add_error("Something is wrong")
        assert result.valid is False
        assert len(result.errors) == 1

    def test_add_warning_keeps_valid(self) -> None:
        """Test that adding a warning keeps result valid."""
        result = ValidationResult()
        result.add_warning("This is a warning")
        assert result.valid is True
        assert len(result.warnings) == 1

    def test_add_info_keeps_valid(self) -> None:
        """Test that adding info keeps result valid."""
        result = ValidationResult()
        result.add_info("This is info")
        assert result.valid is True
        assert len(result.info) == 1

    def test_add_error_with_all_fields(self) -> None:
        """Test adding error with all optional fields."""
        result = ValidationResult()
        result.add_error(
            "Error message",
            rule_name="test-rule",
            field_name="action",
            details={"key": "value"},
        )
        error = result.errors[0]
        assert error.message == "Error message"
        assert error.rule_name == "test-rule"
        assert error.field_name == "action"
        assert error.details == {"key": "value"}

    def test_add_warning_with_all_fields(self) -> None:
        """Test adding warning with all optional fields."""
        result = ValidationResult()
        result.add_warning(
            "Warning message",
            rule_name="test-rule",
            field_name="conditions",
            details={"hint": "check syntax"},
        )
        warning = result.warnings[0]
        assert warning.message == "Warning message"
        assert warning.rule_name == "test-rule"
        assert warning.field_name == "conditions"

    def test_add_info_with_all_fields(self) -> None:
        """Test adding info with all optional fields."""
        result = ValidationResult()
        result.add_info(
            "Info message",
            rule_name="test-rule",
            field_name="priority",
            details={"note": "optional"},
        )
        info = result.info[0]
        assert info.message == "Info message"
        assert info.level == MessageLevel.INFO

    def test_all_messages_ordering(self) -> None:
        """Test that all_messages returns messages in severity order."""
        result = ValidationResult()
        result.add_info("info 1")
        result.add_warning("warning 1")
        result.add_error("error 1")
        result.add_info("info 2")
        result.add_error("error 2")

        all_msgs = result.all_messages()
        assert len(all_msgs) == 5
        # Errors first, then warnings, then info
        assert all_msgs[0].level == MessageLevel.ERROR
        assert all_msgs[1].level == MessageLevel.ERROR
        assert all_msgs[2].level == MessageLevel.WARNING
        assert all_msgs[3].level == MessageLevel.INFO
        assert all_msgs[4].level == MessageLevel.INFO

    def test_multiple_errors(self) -> None:
        """Test adding multiple errors."""
        result = ValidationResult()
        result.add_error("Error 1")
        result.add_error("Error 2")
        result.add_error("Error 3")
        assert result.valid is False
        assert len(result.errors) == 3


# =============================================================================
# PolicyValidator Tests
# =============================================================================


class TestPolicyValidator:
    """Tests for PolicyValidator class."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_validate_valid_policy(self, validator: PolicyValidator) -> None:
        """Test validating a valid policy."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-gpt4",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                )
            ],
        )
        result = validator.validate(policy)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_empty_policy(self, validator: PolicyValidator) -> None:
        """Test validating empty policy."""
        policy = PolicySet(name="empty", version="1.0.0", rules=[])
        result = validator.validate(policy)
        assert result.valid is True
        assert any("no rules" in w.message for w in result.warnings)

    def test_validate_policy_without_name(self, validator: PolicyValidator) -> None:
        """Test validating policy without name."""
        policy = PolicySet(name="", version="1.0.0", rules=[])
        result = validator.validate(policy)
        assert any("no name" in w.message for w in result.warnings)

    def test_validate_policy_without_version(self, validator: PolicyValidator) -> None:
        """Test validating policy without version."""
        policy = PolicySet(name="test", version="", rules=[])
        result = validator.validate(policy)
        assert any("no version" in w.message for w in result.warnings)

    def test_validate_rule_without_name(self, validator: PolicyValidator) -> None:
        """Test validating rule without name."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(name="", action="ALLOW"),
            ],
        )
        result = validator.validate(policy)
        assert result.valid is False
        assert any("no name" in e.message for e in result.errors)

    def test_validate_invalid_action(self, validator: PolicyValidator) -> None:
        """Test validating rule with invalid action."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(name="bad-action", action="INVALID_ACTION"),
            ],
        )
        result = validator.validate(policy)
        assert result.valid is False
        assert any("Invalid action" in e.message for e in result.errors)

    def test_validate_all_valid_actions(self, validator: PolicyValidator) -> None:
        """Test all valid action types."""
        valid_actions = [
            "ALLOW",
            "DENY",
            "MODIFY",
            "REDIRECT",
            "RATE_LIMIT",
            "AUDIT",
            "REQUIRE_APPROVAL",
        ]
        for action in valid_actions:
            policy = PolicySet(
                name="test-policy",
                version="1.0.0",
                rules=[
                    PolicyRule(name=f"test-{action}", action=action),
                ],
            )
            result = validator.validate(policy)
            action_errors = [e for e in result.errors if "Invalid action" in e.message]
            assert len(action_errors) == 0, f"Action {action} should be valid"

    def test_validate_rule_without_conditions(
        self, validator: PolicyValidator
    ) -> None:
        """Test warning for rule without match conditions."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(name="catch-all", action="ALLOW", match_conditions={}),
            ],
        )
        result = validator.validate(policy)
        assert any("no match conditions" in w.message for w in result.warnings)

    def test_validate_disabled_rule(self, validator: PolicyValidator) -> None:
        """Test info message for disabled rule."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(name="disabled-rule", action="DENY", enabled=False),
            ],
        )
        result = validator.validate(policy)
        assert any("disabled" in i.message for i in result.info)

    def test_validate_duplicate_rule_names(self, validator: PolicyValidator) -> None:
        """Test error for duplicate rule names."""
        policy = PolicySet(
            name="test-policy",
            version="1.0.0",
            rules=[
                PolicyRule(name="duplicate", action="ALLOW"),
                PolicyRule(name="duplicate", action="DENY"),
            ],
        )
        result = validator.validate(policy)
        assert result.valid is False
        assert any("Duplicate rule name" in e.message for e in result.errors)


class TestPolicyValidatorConditions:
    """Tests for condition validation."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_valid_conditions(self, validator: PolicyValidator) -> None:
        """Test valid match conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={
                        "provider": "openai",
                        "model": "gpt-4",
                        "department": "engineering",
                    },
                )
            ],
        )
        result = validator.validate(policy)
        # No warnings about unknown fields
        unknown_field_warnings = [
            w for w in result.warnings if "Unknown condition field" in w.message
        ]
        assert len(unknown_field_warnings) == 0

    def test_unknown_condition_field(self, validator: PolicyValidator) -> None:
        """Test warning for unknown condition field."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"unknown_field": "value"},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("Unknown condition field" in w.message for w in result.warnings)

    def test_and_operator_with_list(self, validator: PolicyValidator) -> None:
        """Test 'and' operator with proper list."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={
                        "and": [
                            {"provider": "openai"},
                            {"model": "gpt-4"},
                        ]
                    },
                )
            ],
        )
        result = validator.validate(policy)
        # No errors about 'and' operator
        and_errors = [e for e in result.errors if "'and'" in e.message]
        assert len(and_errors) == 0

    def test_and_operator_without_list(self, validator: PolicyValidator) -> None:
        """Test error for 'and' operator without list."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"and": {"provider": "openai"}},
                )
            ],
        )
        result = validator.validate(policy)
        assert result.valid is False
        assert any("requires a list" in e.message for e in result.errors)

    def test_or_operator_with_list(self, validator: PolicyValidator) -> None:
        """Test 'or' operator with proper list."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={
                        "or": [
                            {"model": "gpt-4"},
                            {"model": "gpt-3.5-turbo"},
                        ]
                    },
                )
            ],
        )
        result = validator.validate(policy)
        or_errors = [e for e in result.errors if "'or'" in e.message]
        assert len(or_errors) == 0

    def test_not_operator_with_dict(self, validator: PolicyValidator) -> None:
        """Test 'not' operator with proper dict."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"not": {"department": "restricted"}},
                )
            ],
        )
        result = validator.validate(policy)
        not_errors = [e for e in result.errors if "'not'" in e.message]
        assert len(not_errors) == 0

    def test_not_operator_without_dict(self, validator: PolicyValidator) -> None:
        """Test error for 'not' operator without dict."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"not": "department"},
                )
            ],
        )
        result = validator.validate(policy)
        assert result.valid is False
        assert any("'not' operator" in e.message for e in result.errors)

    def test_nested_conditions(self, validator: PolicyValidator) -> None:
        """Test deeply nested conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={
                        "and": [
                            {
                                "or": [
                                    {"model": "gpt-4"},
                                    {"model": "claude-3"},
                                ]
                            },
                            {"not": {"department": "restricted"}},
                        ]
                    },
                )
            ],
        )
        result = validator.validate(policy)
        # Should validate without errors
        assert result.valid is True


class TestPolicyValidatorOperators:
    """Tests for operator validation."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_valid_operators(self, validator: PolicyValidator) -> None:
        """Test valid operators."""
        # Map operators to appropriate test values
        operator_values = {
            "eq": 100,
            "ne": 100,
            "gt": 100,
            "gte": 100,
            "lt": 100,
            "lte": 100,
            "in": [100, 200],  # 'in' expects a list
            "not_in": [100, 200],  # 'not_in' expects a list
            "matches": ".*pattern.*",  # 'matches' expects a string pattern
        }
        for op, value in operator_values.items():
            policy = PolicySet(
                name="test",
                version="1.0.0",
                rules=[
                    PolicyRule(
                        name="rule1",
                        action="ALLOW",
                        match_conditions={"cost": {op: value}},
                    )
                ],
            )
            result = validator.validate(policy)
            op_warnings = [
                w for w in result.warnings
                if f"Unknown operator" in w.message and f"'{op}'" in w.message
            ]
            assert len(op_warnings) == 0, f"Operator {op} should be valid"

    def test_unknown_operator(self, validator: PolicyValidator) -> None:
        """Test warning for unknown operator."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={"cost": {"unknown_op": 100}},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("Unknown operator" in w.message for w in result.warnings)

    def test_in_operator_with_list(self, validator: PolicyValidator) -> None:
        """Test 'in' operator with list."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="ALLOW",
                    match_conditions={
                        "department": {"in": ["engineering", "research"]}
                    },
                )
            ],
        )
        result = validator.validate(policy)
        # No type warnings for 'in' with list
        type_warnings = [w for w in result.warnings if "'in'" in w.message]
        assert len(type_warnings) == 0

    def test_gt_operator_with_number(self, validator: PolicyValidator) -> None:
        """Test 'gt' operator with number."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="DENY",
                    match_conditions={"cost": {"gt": 100.0}},
                )
            ],
        )
        result = validator.validate(policy)
        # No type warnings for 'gt' with number
        type_warnings = [
            w for w in result.warnings if "'gt'" in w.message and "numeric" in w.message
        ]
        assert len(type_warnings) == 0

    def test_gt_operator_with_non_number(self, validator: PolicyValidator) -> None:
        """Test warning for 'gt' operator with non-number."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="DENY",
                    match_conditions={"cost": {"gt": "high"}},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("numeric" in w.message for w in result.warnings)


class TestPolicyValidatorActionParams:
    """Tests for action parameter validation."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_modify_action_without_params(self, validator: PolicyValidator) -> None:
        """Test warning for MODIFY without params."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="MODIFY",
                    match_conditions={"model": "gpt-4"},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("MODIFY" in w.message for w in result.warnings)

    def test_modify_action_with_params(self, validator: PolicyValidator) -> None:
        """Test MODIFY with params is valid."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="MODIFY",
                    match_conditions={"model": "gpt-4"},
                    action_params={"max_tokens": 1000},
                )
            ],
        )
        result = validator.validate(policy)
        modify_warnings = [
            w for w in result.warnings if "MODIFY" in w.message and "action_params" in w.message
        ]
        assert len(modify_warnings) == 0

    def test_redirect_action_without_target(self, validator: PolicyValidator) -> None:
        """Test warning for REDIRECT without target."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="REDIRECT",
                    match_conditions={"model": "gpt-4"},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("REDIRECT" in w.message for w in result.warnings)

    def test_redirect_action_with_target(self, validator: PolicyValidator) -> None:
        """Test REDIRECT with target is valid."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="REDIRECT",
                    match_conditions={"model": "gpt-4"},
                    action_params={"target_model": "gpt-3.5-turbo"},
                )
            ],
        )
        result = validator.validate(policy)
        redirect_warnings = [
            w for w in result.warnings if "REDIRECT" in w.message and "target" in w.message
        ]
        assert len(redirect_warnings) == 0

    def test_rate_limit_action_without_rate(self, validator: PolicyValidator) -> None:
        """Test warning for RATE_LIMIT without rate."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="RATE_LIMIT",
                    match_conditions={"model": "gpt-4"},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("RATE_LIMIT" in w.message for w in result.warnings)

    def test_rate_limit_action_with_rate(self, validator: PolicyValidator) -> None:
        """Test RATE_LIMIT with rate is valid."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="RATE_LIMIT",
                    match_conditions={"model": "gpt-4"},
                    action_params={"requests_per_minute": 10},
                )
            ],
        )
        result = validator.validate(policy)
        rate_warnings = [
            w for w in result.warnings if "RATE_LIMIT" in w.message and "requests_per_minute" in w.message
        ]
        assert len(rate_warnings) == 0

    def test_require_approval_without_approvers(
        self, validator: PolicyValidator
    ) -> None:
        """Test info for REQUIRE_APPROVAL without approvers."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="rule1",
                    action="REQUIRE_APPROVAL",
                    match_conditions={"model": "gpt-4"},
                )
            ],
        )
        result = validator.validate(policy)
        assert any("REQUIRE_APPROVAL" in i.message for i in result.info)


class TestPolicyValidatorConflicts:
    """Tests for conflict detection."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_conflicting_rules_same_priority(self, validator: PolicyValidator) -> None:
        """Test warning for conflicting rules with same priority."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
                PolicyRule(
                    name="deny-rule",
                    action="DENY",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
            ],
        )
        result = validator.validate(policy)
        assert any("conflicting" in w.message.lower() for w in result.warnings)

    def test_no_conflict_different_priorities(
        self, validator: PolicyValidator
    ) -> None:
        """Test no conflict warning for different priorities."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=20,
                ),
                PolicyRule(
                    name="deny-rule",
                    action="DENY",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
            ],
        )
        result = validator.validate(policy)
        conflict_warnings = [
            w for w in result.warnings if "conflicting" in w.message.lower()
        ]
        assert len(conflict_warnings) == 0

    def test_no_conflict_different_conditions(
        self, validator: PolicyValidator
    ) -> None:
        """Test no conflict warning for different conditions."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
                PolicyRule(
                    name="deny-rule",
                    action="DENY",
                    match_conditions={"model": "gpt-3.5"},
                    priority=10,
                ),
            ],
        )
        result = validator.validate(policy)
        conflict_warnings = [
            w for w in result.warnings if "conflicting" in w.message.lower()
        ]
        assert len(conflict_warnings) == 0

    def test_disabled_rules_not_conflict(self, validator: PolicyValidator) -> None:
        """Test that disabled rules don't count as conflicts."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="allow-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
                PolicyRule(
                    name="deny-rule",
                    action="DENY",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                    enabled=False,
                ),
            ],
        )
        result = validator.validate(policy)
        conflict_warnings = [
            w for w in result.warnings if "conflicting" in w.message.lower()
        ]
        assert len(conflict_warnings) == 0


class TestPolicyValidatorUnreachable:
    """Tests for unreachable rule detection."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_unreachable_rule_shadowed(self, validator: PolicyValidator) -> None:
        """Test warning for rule shadowed by catch-all."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="catch-all",
                    action="DENY",
                    match_conditions={},  # Matches everything
                    priority=100,
                ),
                PolicyRule(
                    name="specific-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
            ],
        )
        result = validator.validate(policy)
        assert any("unreachable" in w.message.lower() for w in result.warnings)

    def test_not_unreachable_higher_priority(self, validator: PolicyValidator) -> None:
        """Test no warning when specific rule has higher priority."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="catch-all",
                    action="DENY",
                    match_conditions={},
                    priority=10,
                ),
                PolicyRule(
                    name="specific-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=100,
                ),
            ],
        )
        result = validator.validate(policy)
        unreachable_warnings = [
            w for w in result.warnings if "unreachable" in w.message.lower()
        ]
        assert len(unreachable_warnings) == 0

    def test_disabled_rule_not_shadow(self, validator: PolicyValidator) -> None:
        """Test that disabled rules don't shadow others."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="catch-all",
                    action="DENY",
                    match_conditions={},
                    priority=100,
                    enabled=False,
                ),
                PolicyRule(
                    name="specific-rule",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                    priority=10,
                ),
            ],
        )
        result = validator.validate(policy)
        unreachable_warnings = [
            w for w in result.warnings if "unreachable" in w.message.lower()
        ]
        assert len(unreachable_warnings) == 0


class TestPolicyValidatorEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def validator(self) -> PolicyValidator:
        """Create a policy validator."""
        return PolicyValidator()

    def test_many_rules(self, validator: PolicyValidator) -> None:
        """Test policy with many rules."""
        rules = [
            PolicyRule(
                name=f"rule-{i}",
                action="ALLOW" if i % 2 == 0 else "DENY",
                match_conditions={"model": f"model-{i}"},
                priority=i,
            )
            for i in range(100)
        ]
        policy = PolicySet(name="test", version="1.0.0", rules=rules)
        result = validator.validate(policy)
        # Should not error for duplicate names since all are unique
        dup_errors = [e for e in result.errors if "Duplicate" in e.message]
        assert len(dup_errors) == 0

    def test_unicode_in_rule_name(self, validator: PolicyValidator) -> None:
        """Test unicode characters in rule name."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="règle-日本語",
                    action="ALLOW",
                    match_conditions={"model": "gpt-4"},
                )
            ],
        )
        result = validator.validate(policy)
        # Should validate without name-related errors
        name_errors = [e for e in result.errors if "name" in e.message.lower()]
        assert len(name_errors) == 0

    def test_special_chars_in_condition_values(
        self, validator: PolicyValidator
    ) -> None:
        """Test special characters in condition values."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(
                    name="special-rule",
                    action="ALLOW",
                    match_conditions={
                        "model": "gpt-4/turbo@v2",
                        "user": "user@example.com",
                    },
                )
            ],
        )
        result = validator.validate(policy)
        assert result.valid is True

    def test_info_message_count(self, validator: PolicyValidator) -> None:
        """Test that info message includes rule count."""
        policy = PolicySet(
            name="test",
            version="1.0.0",
            rules=[
                PolicyRule(name="rule1", action="ALLOW"),
                PolicyRule(name="rule2", action="DENY"),
                PolicyRule(name="rule3", action="ALLOW", enabled=False),
            ],
        )
        result = validator.validate(policy)
        assert any("3 rules" in i.message for i in result.info)
        assert any("2 enabled" in i.message for i in result.info)

    def test_valid_condition_fields(self, validator: PolicyValidator) -> None:
        """Test all valid condition fields."""
        valid_fields = [
            "provider",
            "model",
            "department",
            "user",
            "user_id",
            "data_classification",
            "use_case",
            "cost",
            "tokens",
            "time",
            "source",
        ]
        for field_name in valid_fields:
            policy = PolicySet(
                name="test",
                version="1.0.0",
                rules=[
                    PolicyRule(
                        name="rule1",
                        action="ALLOW",
                        match_conditions={field_name: "value"},
                    )
                ],
            )
            result = validator.validate(policy)
            field_warnings = [
                w
                for w in result.warnings
                if "Unknown condition field" in w.message and field_name in w.message
            ]
            assert len(field_warnings) == 0, f"Field {field_name} should be valid"
