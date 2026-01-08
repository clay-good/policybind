"""
Tests for the registry policy integration module.

This module tests the RegistryCondition, RegistryAction, RegistryEnricher,
and related factory classes that integrate the registry with the policy engine.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock

import pytest

from policybind.engine.conditions import EvaluationContext, Operator
from policybind.engine.context import EnforcementContext, PipelineStage
from policybind.models.base import utc_now
from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel
from policybind.models.request import AIRequest, Decision
from policybind.registry.policy_integration import (
    RegistryAction,
    RegistryActionExecutor,
    RegistryActionFactory,
    RegistryActionResult,
    RegistryActionType,
    RegistryCondition,
    RegistryConditionFactory,
    RegistryEnricher,
    RegistryField,
)


# =============================================================================
# RegistryCondition Tests
# =============================================================================


class TestRegistryCondition:
    """Tests for the RegistryCondition class."""

    @pytest.fixture
    def registry_context(self) -> EvaluationContext:
        """Create an evaluation context with registry data."""
        return EvaluationContext(
            data={},
            metadata={
                "registry": {
                    "risk_level": "HIGH",
                    "approval_status": "APPROVED",
                    "owner": "ml-team",
                    "owner_contact": "ml-team@example.com",
                    "data_categories": ["internal", "customer", "pii"],
                    "model_provider": "openai",
                    "model_name": "gpt-4",
                    "model_version": "2024-01-01",
                    "deployment_date": (utc_now() - timedelta(days=30)).isoformat(),
                    "last_review_date": (utc_now() - timedelta(days=10)).isoformat(),
                    "next_review_date": (utc_now() + timedelta(days=20)).isoformat(),
                    "violation_count": 3,
                }
            },
        )

    @pytest.fixture
    def empty_context(self) -> EvaluationContext:
        """Create an evaluation context without registry data."""
        return EvaluationContext(data={}, metadata={})

    def test_evaluate_risk_level_eq(self, registry_context: EvaluationContext) -> None:
        """Test evaluating risk level equality."""
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.EQ,
            value="HIGH",
        )
        assert condition.evaluate(registry_context) is True

        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.EQ,
            value="LOW",
        )
        assert condition.evaluate(registry_context) is False

    def test_evaluate_risk_level_in(self, registry_context: EvaluationContext) -> None:
        """Test evaluating risk level in a list."""
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.IN,
            value=["HIGH", "CRITICAL"],
        )
        assert condition.evaluate(registry_context) is True

        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.IN,
            value=["LOW", "MEDIUM"],
        )
        assert condition.evaluate(registry_context) is False

    def test_evaluate_owner_eq(self, registry_context: EvaluationContext) -> None:
        """Test evaluating owner equality."""
        condition = RegistryCondition(
            field=RegistryField.OWNER,
            operator=Operator.EQ,
            value="ml-team",
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_data_categories_contains(
        self, registry_context: EvaluationContext
    ) -> None:
        """Test evaluating data categories contains."""
        condition = RegistryCondition(
            field=RegistryField.DATA_CATEGORIES,
            operator=Operator.CONTAINS,
            value="pii",
        )
        assert condition.evaluate(registry_context) is True

        condition = RegistryCondition(
            field=RegistryField.DATA_CATEGORIES,
            operator=Operator.CONTAINS,
            value="financial",
        )
        assert condition.evaluate(registry_context) is False

    def test_evaluate_violation_count_gt(
        self, registry_context: EvaluationContext
    ) -> None:
        """Test evaluating violation count greater than."""
        condition = RegistryCondition(
            field=RegistryField.VIOLATION_COUNT,
            operator=Operator.GT,
            value=2,
        )
        assert condition.evaluate(registry_context) is True

        condition = RegistryCondition(
            field=RegistryField.VIOLATION_COUNT,
            operator=Operator.GT,
            value=5,
        )
        assert condition.evaluate(registry_context) is False

    def test_evaluate_deployment_age_days(
        self, registry_context: EvaluationContext
    ) -> None:
        """Test evaluating deployment age in days."""
        condition = RegistryCondition(
            field=RegistryField.DEPLOYMENT_AGE_DAYS,
            operator=Operator.GTE,
            value=25,
        )
        assert condition.evaluate(registry_context) is True

        condition = RegistryCondition(
            field=RegistryField.DEPLOYMENT_AGE_DAYS,
            operator=Operator.GTE,
            value=60,
        )
        assert condition.evaluate(registry_context) is False

    def test_evaluate_is_high_risk(self, registry_context: EvaluationContext) -> None:
        """Test evaluating is_high_risk computed field."""
        condition = RegistryCondition(
            field=RegistryField.IS_HIGH_RISK,
            operator=Operator.EQ,
            value=True,
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_needs_review_false(
        self, registry_context: EvaluationContext
    ) -> None:
        """Test evaluating needs_review computed field (false case)."""
        # Next review is in the future, so doesn't need review
        condition = RegistryCondition(
            field=RegistryField.NEEDS_REVIEW,
            operator=Operator.EQ,
            value=False,
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_needs_review_true(self) -> None:
        """Test evaluating needs_review computed field (true case)."""
        context = EvaluationContext(
            data={},
            metadata={
                "registry": {
                    "next_review_date": (utc_now() - timedelta(days=5)).isoformat(),
                }
            },
        )
        condition = RegistryCondition(
            field=RegistryField.NEEDS_REVIEW,
            operator=Operator.EQ,
            value=True,
        )
        assert condition.evaluate(context) is True

    def test_evaluate_empty_registry_data(
        self, empty_context: EvaluationContext
    ) -> None:
        """Test evaluation returns False when no registry data."""
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.EQ,
            value="HIGH",
        )
        assert condition.evaluate(empty_context) is False

    def test_evaluate_not_eq(self, registry_context: EvaluationContext) -> None:
        """Test evaluating not equal operator."""
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.NE,
            value="LOW",
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_not_in(self, registry_context: EvaluationContext) -> None:
        """Test evaluating not in operator."""
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.NOT_IN,
            value=["LOW", "MEDIUM"],
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_not_contains(self, registry_context: EvaluationContext) -> None:
        """Test evaluating not contains operator."""
        condition = RegistryCondition(
            field=RegistryField.DATA_CATEGORIES,
            operator=Operator.NOT_CONTAINS,
            value="financial",
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_lte(self, registry_context: EvaluationContext) -> None:
        """Test evaluating less than or equal operator."""
        condition = RegistryCondition(
            field=RegistryField.VIOLATION_COUNT,
            operator=Operator.LTE,
            value=5,
        )
        assert condition.evaluate(registry_context) is True

        condition = RegistryCondition(
            field=RegistryField.VIOLATION_COUNT,
            operator=Operator.LTE,
            value=2,
        )
        assert condition.evaluate(registry_context) is False

    def test_evaluate_lt(self, registry_context: EvaluationContext) -> None:
        """Test evaluating less than operator."""
        condition = RegistryCondition(
            field=RegistryField.VIOLATION_COUNT,
            operator=Operator.LT,
            value=5,
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_exists(self, registry_context: EvaluationContext) -> None:
        """Test evaluating exists operator."""
        condition = RegistryCondition(
            field=RegistryField.OWNER,
            operator=Operator.EXISTS,
            value=True,
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_not_exists(self, empty_context: EvaluationContext) -> None:
        """Test evaluating not_exists operator."""
        # Add partial registry data without owner
        empty_context.metadata["registry"] = {"risk_level": "HIGH"}
        condition = RegistryCondition(
            field=RegistryField.OWNER,
            operator=Operator.NOT_EXISTS,
            value=True,
        )
        assert condition.evaluate(empty_context) is True

    def test_evaluate_with_enum_value(self) -> None:
        """Test evaluating with RiskLevel enum as registry value."""
        context = EvaluationContext(
            data={},
            metadata={
                "registry": {
                    "risk_level": RiskLevel.HIGH,
                }
            },
        )
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.EQ,
            value="HIGH",
        )
        assert condition.evaluate(context) is True

    def test_describe(self) -> None:
        """Test condition description."""
        condition = RegistryCondition(
            field=RegistryField.RISK_LEVEL,
            operator=Operator.IN,
            value=["HIGH", "CRITICAL"],
        )
        description = condition.describe()
        assert "registry.risk_level" in description
        assert "in" in description

    def test_evaluate_model_provider(self, registry_context: EvaluationContext) -> None:
        """Test evaluating model provider field."""
        condition = RegistryCondition(
            field=RegistryField.MODEL_PROVIDER,
            operator=Operator.EQ,
            value="openai",
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_days_since_review(
        self, registry_context: EvaluationContext
    ) -> None:
        """Test evaluating days since last review."""
        condition = RegistryCondition(
            field=RegistryField.DAYS_SINCE_REVIEW,
            operator=Operator.GTE,
            value=5,
        )
        assert condition.evaluate(registry_context) is True

    def test_evaluate_days_until_review(
        self, registry_context: EvaluationContext
    ) -> None:
        """Test evaluating days until next review."""
        condition = RegistryCondition(
            field=RegistryField.DAYS_UNTIL_REVIEW,
            operator=Operator.LTE,
            value=30,
        )
        assert condition.evaluate(registry_context) is True


# =============================================================================
# RegistryAction Tests
# =============================================================================


class TestRegistryAction:
    """Tests for the RegistryAction class."""

    def test_create_action(self) -> None:
        """Test creating a registry action."""
        action = RegistryAction(
            action_type=RegistryActionType.INCREMENT_VIOLATION,
            params={"reason": "Policy violation"},
        )
        assert action.action_type == RegistryActionType.INCREMENT_VIOLATION
        assert action.params == {"reason": "Policy violation"}

    def test_to_dict(self) -> None:
        """Test converting action to dictionary."""
        action = RegistryAction(
            action_type=RegistryActionType.SUSPEND_DEPLOYMENT,
            params={"reason": "Critical violation"},
        )
        d = action.to_dict()
        assert d["action_type"] == "suspend_deployment"
        assert d["params"]["reason"] == "Critical violation"

    def test_default_params(self) -> None:
        """Test action with default params."""
        action = RegistryAction(action_type=RegistryActionType.FLAG_FOR_REVIEW)
        assert action.params == {}


# =============================================================================
# RegistryActionExecutor Tests
# =============================================================================


class TestRegistryActionExecutor:
    """Tests for the RegistryActionExecutor class."""

    @pytest.fixture
    def mock_manager(self) -> MagicMock:
        """Create a mock registry manager."""
        manager = MagicMock()
        manager.record_violation.return_value = 5
        manager.get.return_value = ModelDeployment(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        return manager

    @pytest.fixture
    def executor(self, mock_manager: MagicMock) -> RegistryActionExecutor:
        """Create an executor with mock manager."""
        return RegistryActionExecutor(
            registry_manager=mock_manager,
            notification_callback=Mock(),
        )

    @pytest.fixture
    def executor_no_manager(self) -> RegistryActionExecutor:
        """Create an executor without manager."""
        return RegistryActionExecutor()

    def test_execute_increment_violation(
        self, executor: RegistryActionExecutor, mock_manager: MagicMock
    ) -> None:
        """Test executing increment violation action."""
        action = RegistryAction(
            action_type=RegistryActionType.INCREMENT_VIOLATION,
            params={"reason": "Test violation"},
        )
        result = executor.execute("deploy-123", action)

        assert result.success is True
        assert result.action_type == RegistryActionType.INCREMENT_VIOLATION
        assert result.deployment_id == "deploy-123"
        assert result.changes["violation_count"] == 5
        mock_manager.record_violation.assert_called_once()

    def test_execute_suspend_deployment(
        self, executor: RegistryActionExecutor, mock_manager: MagicMock
    ) -> None:
        """Test executing suspend deployment action."""
        action = RegistryAction(
            action_type=RegistryActionType.SUSPEND_DEPLOYMENT,
            params={"reason": "Critical issue"},
        )
        result = executor.execute("deploy-123", action)

        assert result.success is True
        assert result.action_type == RegistryActionType.SUSPEND_DEPLOYMENT
        mock_manager.suspend.assert_called_once()

    def test_execute_flag_for_review(
        self, executor: RegistryActionExecutor, mock_manager: MagicMock
    ) -> None:
        """Test executing flag for review action."""
        action = RegistryAction(action_type=RegistryActionType.FLAG_FOR_REVIEW)
        result = executor.execute("deploy-123", action)

        assert result.success is True
        assert result.action_type == RegistryActionType.FLAG_FOR_REVIEW
        mock_manager.mark_reviewed.assert_called_once()

    def test_execute_update_metadata(
        self, executor: RegistryActionExecutor, mock_manager: MagicMock
    ) -> None:
        """Test executing update metadata action."""
        action = RegistryAction(
            action_type=RegistryActionType.UPDATE_METADATA,
            params={"metadata": {"policy_flags": ["reviewed"]}},
        )
        result = executor.execute("deploy-123", action)

        assert result.success is True
        assert result.action_type == RegistryActionType.UPDATE_METADATA
        mock_manager.update.assert_called_once()

    def test_execute_notify_owner(self, executor: RegistryActionExecutor) -> None:
        """Test executing notify owner action."""
        action = RegistryAction(
            action_type=RegistryActionType.NOTIFY_OWNER,
            params={
                "subject": "Alert",
                "body": "Your deployment has an issue",
            },
        )
        result = executor.execute("deploy-123", action)

        assert result.success is True
        assert result.action_type == RegistryActionType.NOTIFY_OWNER

    def test_execute_without_manager(
        self, executor_no_manager: RegistryActionExecutor
    ) -> None:
        """Test executing action without a manager."""
        action = RegistryAction(
            action_type=RegistryActionType.INCREMENT_VIOLATION,
            params={"reason": "Test"},
        )
        result = executor_no_manager.execute("deploy-123", action)

        # Should still succeed but with "(no manager)" message
        assert result.success is True
        assert "no manager" in result.message

    def test_execute_with_error(
        self, executor: RegistryActionExecutor, mock_manager: MagicMock
    ) -> None:
        """Test executing action when manager throws error."""
        mock_manager.record_violation.side_effect = Exception("Database error")

        action = RegistryAction(
            action_type=RegistryActionType.INCREMENT_VIOLATION,
            params={"reason": "Test"},
        )
        result = executor.execute("deploy-123", action)

        assert result.success is False
        assert "Failed" in result.message

    def test_get_action_log(self, executor: RegistryActionExecutor) -> None:
        """Test getting the action execution log."""
        action1 = RegistryAction(action_type=RegistryActionType.FLAG_FOR_REVIEW)
        action2 = RegistryAction(action_type=RegistryActionType.INCREMENT_VIOLATION)

        executor.execute("deploy-1", action1)
        executor.execute("deploy-2", action2)

        log = executor.get_action_log()
        assert len(log) == 2
        assert log[0].action_type == RegistryActionType.FLAG_FOR_REVIEW
        assert log[1].action_type == RegistryActionType.INCREMENT_VIOLATION


# =============================================================================
# RegistryEnricher Tests
# =============================================================================


class TestRegistryEnricher:
    """Tests for the RegistryEnricher middleware."""

    @pytest.fixture
    def approved_deployment(self) -> ModelDeployment:
        """Create an approved deployment."""
        return ModelDeployment(
            deployment_id="deploy-123",
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="ml-team",
            owner_contact="ml@example.com",
            risk_level=RiskLevel.HIGH,
            approval_status=ApprovalStatus.APPROVED,
            deployment_date=utc_now() - timedelta(days=30),
        )

    @pytest.fixture
    def mock_manager(self, approved_deployment: ModelDeployment) -> MagicMock:
        """Create a mock registry manager."""
        manager = MagicMock()
        manager.get.return_value = approved_deployment
        manager.get_by_name.return_value = approved_deployment
        manager.get_violation_count.return_value = 2
        return manager

    @pytest.fixture
    def enricher(self, mock_manager: MagicMock) -> RegistryEnricher:
        """Create an enricher with mock manager."""
        return RegistryEnricher(registry_manager=mock_manager)

    def test_stage(self, enricher: RegistryEnricher) -> None:
        """Test that enricher runs in validation stage."""
        assert enricher.stage == PipelineStage.VALIDATION

    def test_name(self, enricher: RegistryEnricher) -> None:
        """Test enricher name."""
        assert enricher.name == "RegistryEnricher"

    def test_enrich_with_deployment_id(
        self, enricher: RegistryEnricher, approved_deployment: ModelDeployment
    ) -> None:
        """Test enriching context with deployment_id in metadata."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "deploy-123"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is True
        assert "registry" in context.metadata
        assert context.metadata["registry"]["deployment_id"] == "deploy-123"
        assert context.metadata["registry"]["risk_level"] == "HIGH"
        assert context.metadata["registry"]["owner"] == "ml-team"

    def test_enrich_with_provider_model(
        self, enricher: RegistryEnricher, mock_manager: MagicMock
    ) -> None:
        """Test enriching using provider/model as identifier."""
        request = AIRequest(
            provider="openai",
            model="gpt-4",
        )
        context = EnforcementContext(request=request)

        mock_manager.get.return_value = None  # First lookup by ID fails
        result = enricher.process(context)

        assert result.success is True

    def test_block_unapproved_deployment(self, mock_manager: MagicMock) -> None:
        """Test blocking unapproved deployments."""
        deployment = ModelDeployment(
            deployment_id="deploy-pending",
            name="pending-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="ml-team",
            approval_status=ApprovalStatus.PENDING,
        )
        mock_manager.get.return_value = deployment

        enricher = RegistryEnricher(
            registry_manager=mock_manager,
            block_unapproved=True,
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "deploy-pending"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is False
        assert context.is_short_circuited
        assert context.final_decision == Decision.DENY

    def test_block_suspended_deployment(self, mock_manager: MagicMock) -> None:
        """Test blocking suspended deployments."""
        deployment = ModelDeployment(
            deployment_id="deploy-suspended",
            name="suspended-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="ml-team",
            approval_status=ApprovalStatus.SUSPENDED,
        )
        mock_manager.get.return_value = deployment

        enricher = RegistryEnricher(
            registry_manager=mock_manager,
            block_unapproved=False,  # Don't block unapproved
            block_suspended=True,
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "deploy-suspended"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is False
        assert context.is_short_circuited

    def test_allow_unapproved_when_disabled(self, mock_manager: MagicMock) -> None:
        """Test allowing unapproved when blocking is disabled."""
        deployment = ModelDeployment(
            deployment_id="deploy-pending",
            name="pending-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="ml-team",
            approval_status=ApprovalStatus.PENDING,
        )
        mock_manager.get.return_value = deployment
        mock_manager.get_violation_count.return_value = 0

        enricher = RegistryEnricher(
            registry_manager=mock_manager,
            block_unapproved=False,
            block_suspended=False,
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "deploy-pending"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is True
        assert "registry" in context.metadata

    def test_fail_on_not_found(self, mock_manager: MagicMock) -> None:
        """Test failing when deployment not found."""
        mock_manager.get.return_value = None
        mock_manager.get_by_name.return_value = None

        enricher = RegistryEnricher(
            registry_manager=mock_manager,
            fail_on_not_found=True,
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "unknown"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is False
        assert context.is_short_circuited

    def test_continue_on_not_found(self, mock_manager: MagicMock) -> None:
        """Test continuing when deployment not found and fail_on_not_found=False."""
        mock_manager.get.return_value = None
        mock_manager.get_by_name.return_value = None

        enricher = RegistryEnricher(
            registry_manager=mock_manager,
            fail_on_not_found=False,
        )
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "unknown"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is True
        # No registry data should be attached
        assert context.metadata.get("registry") is None

    def test_no_request(self, enricher: RegistryEnricher) -> None:
        """Test processing when there's no request."""
        context = EnforcementContext(request=None)

        result = enricher.process(context)

        assert result.success is True

    def test_no_deployment_id(self, enricher: RegistryEnricher) -> None:
        """Test processing when no deployment ID is available."""
        request = AIRequest(
            metadata={},  # No deployment_id
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)

        assert result.success is True


# =============================================================================
# RegistryConditionFactory Tests
# =============================================================================


class TestRegistryConditionFactory:
    """Tests for the RegistryConditionFactory class."""

    @pytest.fixture
    def factory(self) -> RegistryConditionFactory:
        """Create a factory instance."""
        return RegistryConditionFactory()

    def test_create_simple_equality(
        self, factory: RegistryConditionFactory
    ) -> None:
        """Test creating a simple equality condition."""
        condition = factory.create("registry.risk_level", "HIGH")

        assert condition is not None
        assert isinstance(condition, RegistryCondition)
        assert condition.field == RegistryField.RISK_LEVEL
        assert condition.operator == Operator.EQ
        assert condition.value == "HIGH"

    def test_create_with_operator(
        self, factory: RegistryConditionFactory
    ) -> None:
        """Test creating a condition with operator."""
        condition = factory.create(
            "registry.violation_count",
            {"gt": 5},
        )

        assert condition is not None
        assert condition.field == RegistryField.VIOLATION_COUNT
        assert condition.operator == Operator.GT
        assert condition.value == 5

    def test_create_with_in_operator(
        self, factory: RegistryConditionFactory
    ) -> None:
        """Test creating a condition with in operator."""
        condition = factory.create(
            "risk_level",
            {"in": ["HIGH", "CRITICAL"]},
        )

        assert condition is not None
        assert condition.field == RegistryField.RISK_LEVEL
        assert condition.operator == Operator.IN
        assert condition.value == ["HIGH", "CRITICAL"]

    def test_create_non_registry_field(
        self, factory: RegistryConditionFactory
    ) -> None:
        """Test that non-registry fields return None."""
        condition = factory.create("request.provider", "openai")
        assert condition is None

    def test_is_registry_field(self, factory: RegistryConditionFactory) -> None:
        """Test checking if a field is a registry field."""
        assert factory.is_registry_field("registry.risk_level") is True
        assert factory.is_registry_field("risk_level") is True
        assert factory.is_registry_field("owner") is True
        assert factory.is_registry_field("request.provider") is False
        assert factory.is_registry_field("unknown") is False

    def test_all_field_mappings(self, factory: RegistryConditionFactory) -> None:
        """Test that all RegistryField values have mappings."""
        for field in RegistryField:
            # Either the short name or the full name should work
            short_name = field.value.replace("registry.", "")
            full_name = field.value

            assert (
                factory.is_registry_field(short_name)
                or factory.is_registry_field(full_name)
            ), f"Missing mapping for {field}"


# =============================================================================
# RegistryActionFactory Tests
# =============================================================================


class TestRegistryActionFactory:
    """Tests for the RegistryActionFactory class."""

    @pytest.fixture
    def factory(self) -> RegistryActionFactory:
        """Create a factory instance."""
        return RegistryActionFactory()

    def test_create_action(self, factory: RegistryActionFactory) -> None:
        """Test creating a registry action."""
        action = factory.create({
            "type": "increment_violation",
            "params": {"reason": "Test violation"},
        })

        assert action is not None
        assert action.action_type == RegistryActionType.INCREMENT_VIOLATION
        assert action.params["reason"] == "Test violation"

    def test_create_action_no_params(self, factory: RegistryActionFactory) -> None:
        """Test creating an action without params."""
        action = factory.create({"type": "flag_for_review"})

        assert action is not None
        assert action.action_type == RegistryActionType.FLAG_FOR_REVIEW
        assert action.params == {}

    def test_create_invalid_type(self, factory: RegistryActionFactory) -> None:
        """Test creating an action with invalid type returns None."""
        action = factory.create({"type": "invalid_action"})
        assert action is None

    def test_create_missing_type(self, factory: RegistryActionFactory) -> None:
        """Test creating an action without type returns None."""
        action = factory.create({"params": {"reason": "Test"}})
        assert action is None

    def test_create_many(self, factory: RegistryActionFactory) -> None:
        """Test creating multiple actions."""
        actions = factory.create_many([
            {"type": "flag_for_review"},
            {"type": "increment_violation", "params": {"reason": "Test"}},
            {"type": "notify_owner", "params": {"subject": "Alert"}},
        ])

        assert len(actions) == 3
        assert actions[0].action_type == RegistryActionType.FLAG_FOR_REVIEW
        assert actions[1].action_type == RegistryActionType.INCREMENT_VIOLATION
        assert actions[2].action_type == RegistryActionType.NOTIFY_OWNER

    def test_create_many_filters_invalid(
        self, factory: RegistryActionFactory
    ) -> None:
        """Test that create_many filters out invalid actions."""
        actions = factory.create_many([
            {"type": "flag_for_review"},
            {"type": "invalid_action"},
            {"type": "increment_violation"},
        ])

        assert len(actions) == 2


# =============================================================================
# Integration Tests
# =============================================================================


class TestRegistryPolicyIntegration:
    """Integration tests for registry and policy engine."""

    @pytest.fixture
    def registry_manager(self) -> MagicMock:
        """Create a mock registry manager."""
        manager = MagicMock()

        deployment = ModelDeployment(
            deployment_id="deploy-high-risk",
            name="high-risk-model",
            model_provider="openai",
            model_name="gpt-4",
            owner="ml-team",
            owner_contact="ml@example.com",
            risk_level=RiskLevel.HIGH,
            approval_status=ApprovalStatus.APPROVED,
            data_categories=["pii", "internal"],
            deployment_date=utc_now() - timedelta(days=60),
            next_review_date=utc_now() - timedelta(days=5),  # Overdue
        )
        manager.get.return_value = deployment
        manager.get_by_name.return_value = deployment
        manager.get_violation_count.return_value = 3
        manager.record_violation.return_value = 4

        return manager

    def test_full_pipeline_flow(self, registry_manager: MagicMock) -> None:
        """Test the full flow from enrichment to condition to action."""
        # Step 1: Create enricher and enrich context
        enricher = RegistryEnricher(registry_manager=registry_manager)
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "deploy-high-risk"},
        )
        context = EnforcementContext(request=request)

        result = enricher.process(context)
        assert result.success is True
        assert "registry" in context.metadata

        # Step 2: Evaluate conditions against enriched context
        eval_context = EvaluationContext(
            data={},
            metadata=context.metadata,
        )

        # Check high risk
        high_risk_condition = RegistryCondition(
            field=RegistryField.IS_HIGH_RISK,
            operator=Operator.EQ,
            value=True,
        )
        assert high_risk_condition.evaluate(eval_context) is True

        # Check needs review
        needs_review_condition = RegistryCondition(
            field=RegistryField.NEEDS_REVIEW,
            operator=Operator.EQ,
            value=True,
        )
        assert needs_review_condition.evaluate(eval_context) is True

        # Check violation count
        violation_condition = RegistryCondition(
            field=RegistryField.VIOLATION_COUNT,
            operator=Operator.GTE,
            value=3,
        )
        assert violation_condition.evaluate(eval_context) is True

        # Step 3: Execute actions
        executor = RegistryActionExecutor(registry_manager=registry_manager)

        # Flag for review
        flag_action = RegistryAction(action_type=RegistryActionType.FLAG_FOR_REVIEW)
        flag_result = executor.execute("deploy-high-risk", flag_action)
        assert flag_result.success is True

        # Increment violation
        increment_action = RegistryAction(
            action_type=RegistryActionType.INCREMENT_VIOLATION,
            params={"reason": "High-risk + overdue review"},
        )
        increment_result = executor.execute("deploy-high-risk", increment_action)
        assert increment_result.success is True

    def test_factory_created_conditions(self, registry_manager: MagicMock) -> None:
        """Test conditions created via factory work correctly."""
        # Enrich first
        enricher = RegistryEnricher(registry_manager=registry_manager)
        request = AIRequest(
            provider="openai",
            model="gpt-4",
            metadata={"deployment_id": "deploy-high-risk"},
        )
        context = EnforcementContext(request=request)
        enricher.process(context)

        # Create evaluation context
        eval_context = EvaluationContext(
            data={},
            metadata=context.metadata,
        )

        # Use factory to create conditions
        factory = RegistryConditionFactory()

        condition1 = factory.create("risk_level", {"in": ["HIGH", "CRITICAL"]})
        assert condition1 is not None
        assert condition1.evaluate(eval_context) is True

        condition2 = factory.create("data_categories", {"contains": "pii"})
        assert condition2 is not None
        assert condition2.evaluate(eval_context) is True

        condition3 = factory.create("violation_count", {"gte": 3})
        assert condition3 is not None
        assert condition3.evaluate(eval_context) is True

    def test_factory_created_actions(self, registry_manager: MagicMock) -> None:
        """Test actions created via factory work correctly."""
        executor = RegistryActionExecutor(registry_manager=registry_manager)
        factory = RegistryActionFactory()

        actions = factory.create_many([
            {"type": "flag_for_review"},
            {"type": "increment_violation", "params": {"reason": "Factory test"}},
        ])

        for action in actions:
            result = executor.execute("deploy-high-risk", action)
            assert result.success is True
