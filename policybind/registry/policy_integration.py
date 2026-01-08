"""
Registry integration with the PolicyBind policy engine.

This module provides classes for integrating the model registry with policy
conditions, actions, and the enforcement pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
import time

from policybind.engine.conditions import Condition, EvaluationContext, Operator
from policybind.engine.context import EnforcementContext, PipelineStage, StageResult
from policybind.engine.middleware import Middleware
from policybind.models.base import utc_now
from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel
from policybind.models.request import Decision


class RegistryField(Enum):
    """Fields available for registry-based conditions."""

    RISK_LEVEL = "registry.risk_level"
    """Deployment risk level (LOW, MEDIUM, HIGH, CRITICAL)."""

    APPROVAL_STATUS = "registry.approval_status"
    """Deployment approval status (PENDING, APPROVED, REJECTED, SUSPENDED)."""

    OWNER = "registry.owner"
    """Deployment owner identifier."""

    OWNER_CONTACT = "registry.owner_contact"
    """Deployment owner contact email."""

    DATA_CATEGORIES = "registry.data_categories"
    """Data categories the deployment handles."""

    MODEL_PROVIDER = "registry.model_provider"
    """The AI model provider."""

    MODEL_NAME = "registry.model_name"
    """The AI model name."""

    MODEL_VERSION = "registry.model_version"
    """The AI model version."""

    DEPLOYMENT_AGE_DAYS = "registry.deployment_age_days"
    """Days since deployment was activated."""

    DAYS_SINCE_REVIEW = "registry.days_since_review"
    """Days since last review."""

    DAYS_UNTIL_REVIEW = "registry.days_until_review"
    """Days until next scheduled review."""

    IS_HIGH_RISK = "registry.is_high_risk"
    """Whether the deployment is HIGH or CRITICAL risk."""

    NEEDS_REVIEW = "registry.needs_review"
    """Whether the deployment is overdue for review."""

    VIOLATION_COUNT = "registry.violation_count"
    """Number of recorded policy violations."""


@dataclass
class RegistryCondition(Condition):
    """
    A condition that evaluates based on registry deployment data.

    RegistryCondition allows policies to make decisions based on
    deployment attributes like risk level, approval status, owner,
    data categories, and review status.

    Example:
        Matching high-risk deployments::

            condition = RegistryCondition(
                field=RegistryField.RISK_LEVEL,
                operator=Operator.IN,
                value=["HIGH", "CRITICAL"],
            )

        Matching deployments needing review::

            condition = RegistryCondition(
                field=RegistryField.NEEDS_REVIEW,
                operator=Operator.EQ,
                value=True,
            )
    """

    field: RegistryField
    operator: Operator
    value: Any

    def evaluate(self, context: EvaluationContext) -> bool:
        """
        Evaluate the registry condition against the context.

        The context must have registry deployment data attached
        in the metadata under the 'registry' key.

        Args:
            context: The evaluation context.

        Returns:
            True if the condition matches, False otherwise.
        """
        # Get registry data from context
        registry_data = context.metadata.get("registry", {})
        if not registry_data:
            # No registry data means condition cannot match
            return False

        # Get the field value
        field_value = self._get_field_value(registry_data)

        # Handle exists/not_exists operators
        if self.operator == Operator.EXISTS:
            return field_value is not None if self.value else field_value is None

        if self.operator == Operator.NOT_EXISTS:
            return field_value is None if self.value else field_value is not None

        # For other operators, if field doesn't exist, return False
        if field_value is None:
            return False

        return self._compare(field_value)

    def _get_field_value(self, registry_data: dict[str, Any]) -> Any:
        """Extract the field value from registry data."""
        if self.field == RegistryField.RISK_LEVEL:
            return registry_data.get("risk_level")

        elif self.field == RegistryField.APPROVAL_STATUS:
            return registry_data.get("approval_status")

        elif self.field == RegistryField.OWNER:
            return registry_data.get("owner")

        elif self.field == RegistryField.OWNER_CONTACT:
            return registry_data.get("owner_contact")

        elif self.field == RegistryField.DATA_CATEGORIES:
            return registry_data.get("data_categories", [])

        elif self.field == RegistryField.MODEL_PROVIDER:
            return registry_data.get("model_provider")

        elif self.field == RegistryField.MODEL_NAME:
            return registry_data.get("model_name")

        elif self.field == RegistryField.MODEL_VERSION:
            return registry_data.get("model_version")

        elif self.field == RegistryField.DEPLOYMENT_AGE_DAYS:
            deployment_date = registry_data.get("deployment_date")
            if deployment_date:
                if isinstance(deployment_date, str):
                    deployment_date = datetime.fromisoformat(deployment_date)
                return (utc_now() - deployment_date).days
            return None

        elif self.field == RegistryField.DAYS_SINCE_REVIEW:
            last_review = registry_data.get("last_review_date")
            if last_review:
                if isinstance(last_review, str):
                    last_review = datetime.fromisoformat(last_review)
                return (utc_now() - last_review).days
            return None

        elif self.field == RegistryField.DAYS_UNTIL_REVIEW:
            next_review = registry_data.get("next_review_date")
            if next_review:
                if isinstance(next_review, str):
                    next_review = datetime.fromisoformat(next_review)
                return (next_review - utc_now()).days
            return None

        elif self.field == RegistryField.IS_HIGH_RISK:
            risk_level = registry_data.get("risk_level")
            return risk_level in ("HIGH", "CRITICAL", RiskLevel.HIGH, RiskLevel.CRITICAL)

        elif self.field == RegistryField.NEEDS_REVIEW:
            next_review = registry_data.get("next_review_date")
            if next_review:
                if isinstance(next_review, str):
                    next_review = datetime.fromisoformat(next_review)
                return utc_now() >= next_review
            return False

        elif self.field == RegistryField.VIOLATION_COUNT:
            return registry_data.get("violation_count", 0)

        return None

    def _compare(self, field_value: Any) -> bool:
        """Perform the comparison based on operator."""
        if self.operator == Operator.EQ:
            return self._normalize_value(field_value) == self._normalize_value(self.value)

        elif self.operator == Operator.NE:
            return self._normalize_value(field_value) != self._normalize_value(self.value)

        elif self.operator == Operator.GT:
            return self._numeric_compare(field_value, lambda a, b: a > b)

        elif self.operator == Operator.GTE:
            return self._numeric_compare(field_value, lambda a, b: a >= b)

        elif self.operator == Operator.LT:
            return self._numeric_compare(field_value, lambda a, b: a < b)

        elif self.operator == Operator.LTE:
            return self._numeric_compare(field_value, lambda a, b: a <= b)

        elif self.operator == Operator.IN:
            normalized_value = self._normalize_value(field_value)
            if isinstance(self.value, (list, tuple, set)):
                return normalized_value in [self._normalize_value(v) for v in self.value]
            return False

        elif self.operator == Operator.NOT_IN:
            normalized_value = self._normalize_value(field_value)
            if isinstance(self.value, (list, tuple, set)):
                return normalized_value not in [self._normalize_value(v) for v in self.value]
            return True

        elif self.operator == Operator.CONTAINS:
            return self._contains(field_value, self.value)

        elif self.operator == Operator.NOT_CONTAINS:
            return not self._contains(field_value, self.value)

        return False

    def _normalize_value(self, value: Any) -> Any:
        """Normalize values for comparison (e.g., enums to strings)."""
        if isinstance(value, Enum):
            return value.value
        return value

    def _numeric_compare(
        self,
        field_value: Any,
        comparator: Callable[[Any, Any], bool],
    ) -> bool:
        """Perform a numeric comparison."""
        try:
            return comparator(float(field_value), float(self.value))
        except (TypeError, ValueError):
            return False

    def _contains(self, field_value: Any, search_value: Any) -> bool:
        """Check if field_value contains search_value."""
        if isinstance(field_value, str):
            return str(search_value) in field_value
        elif isinstance(field_value, (list, tuple, set)):
            return search_value in field_value
        return False

    def describe(self) -> str:
        """Return a human-readable description."""
        return f"{self.field.value} {self.operator.value} {self.value!r}"


class RegistryActionType(Enum):
    """Types of registry actions that can be triggered by policies."""

    FLAG_FOR_REVIEW = "flag_for_review"
    """Mark the deployment as needing review."""

    INCREMENT_VIOLATION = "increment_violation"
    """Increment the violation counter."""

    SUSPEND_DEPLOYMENT = "suspend_deployment"
    """Suspend the deployment immediately."""

    UPDATE_METADATA = "update_metadata"
    """Update deployment metadata."""

    NOTIFY_OWNER = "notify_owner"
    """Send notification to the deployment owner."""


@dataclass
class RegistryAction:
    """
    An action that affects the model registry.

    RegistryAction provides policy-driven actions that can modify
    deployment state in the registry, such as recording violations,
    triggering reviews, or suspending deployments.

    Example:
        Incrementing violations::

            action = RegistryAction(
                action_type=RegistryActionType.INCREMENT_VIOLATION,
                params={"reason": "Policy violation detected"},
            )

        Suspending on threshold::

            action = RegistryAction(
                action_type=RegistryActionType.SUSPEND_DEPLOYMENT,
                params={
                    "reason": "Exceeded violation threshold",
                    "suspended_by": "policy_engine",
                },
            )
    """

    action_type: RegistryActionType
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_type": self.action_type.value,
            "params": self.params,
        }


@dataclass
class RegistryActionResult:
    """
    Result of executing a registry action.

    Attributes:
        action_type: The action that was executed.
        success: Whether the action succeeded.
        message: Result message.
        deployment_id: The deployment that was affected.
        changes: Changes that were made.
    """

    action_type: RegistryActionType
    success: bool
    message: str = ""
    deployment_id: str = ""
    changes: dict[str, Any] = field(default_factory=dict)


# Type alias for registry action callback
RegistryActionCallback = Callable[[str, RegistryAction], RegistryActionResult]


class RegistryActionExecutor:
    """
    Executes registry actions triggered by policy decisions.

    The executor provides handlers for each action type and can
    integrate with the RegistryManager to apply changes.
    """

    def __init__(
        self,
        registry_manager: Any = None,
        notification_callback: Callable[[str, str, str], None] | None = None,
    ) -> None:
        """
        Initialize the action executor.

        Args:
            registry_manager: The RegistryManager instance.
            notification_callback: Callback for notifications (owner, subject, body).
        """
        self._registry_manager = registry_manager
        self._notification_callback = notification_callback
        self._action_log: list[RegistryActionResult] = []

    def execute(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """
        Execute a registry action.

        Args:
            deployment_id: The deployment to act on.
            action: The action to execute.

        Returns:
            The action result.
        """
        handler = self._get_handler(action.action_type)
        result = handler(deployment_id, action)
        self._action_log.append(result)
        return result

    def _get_handler(
        self,
        action_type: RegistryActionType,
    ) -> Callable[[str, RegistryAction], RegistryActionResult]:
        """Get the handler for an action type."""
        handlers = {
            RegistryActionType.FLAG_FOR_REVIEW: self._handle_flag_for_review,
            RegistryActionType.INCREMENT_VIOLATION: self._handle_increment_violation,
            RegistryActionType.SUSPEND_DEPLOYMENT: self._handle_suspend_deployment,
            RegistryActionType.UPDATE_METADATA: self._handle_update_metadata,
            RegistryActionType.NOTIFY_OWNER: self._handle_notify_owner,
        }
        return handlers.get(action_type, self._handle_unknown)

    def _handle_flag_for_review(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """Handle FLAG_FOR_REVIEW action."""
        if self._registry_manager:
            try:
                # Set next review date to now to trigger immediate review
                self._registry_manager.mark_reviewed(
                    deployment_id,
                    reviewed_by="policy_engine",
                    next_review_days=0,
                )
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=True,
                    message="Deployment flagged for immediate review",
                    deployment_id=deployment_id,
                    changes={"needs_review": True},
                )
            except Exception as e:
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=False,
                    message=f"Failed to flag for review: {e}",
                    deployment_id=deployment_id,
                )

        return RegistryActionResult(
            action_type=action.action_type,
            success=True,
            message="Review flag recorded (no manager)",
            deployment_id=deployment_id,
        )

    def _handle_increment_violation(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """Handle INCREMENT_VIOLATION action."""
        reason = action.params.get("reason", "Policy violation")

        if self._registry_manager:
            try:
                count = self._registry_manager.record_violation(
                    deployment_id,
                    reason=reason,
                )
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=True,
                    message=f"Violation recorded (count: {count})",
                    deployment_id=deployment_id,
                    changes={"violation_count": count, "reason": reason},
                )
            except Exception as e:
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=False,
                    message=f"Failed to record violation: {e}",
                    deployment_id=deployment_id,
                )

        return RegistryActionResult(
            action_type=action.action_type,
            success=True,
            message="Violation recorded (no manager)",
            deployment_id=deployment_id,
        )

    def _handle_suspend_deployment(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """Handle SUSPEND_DEPLOYMENT action."""
        reason = action.params.get("reason", "Suspended by policy")
        suspended_by = action.params.get("suspended_by", "policy_engine")

        if self._registry_manager:
            try:
                self._registry_manager.suspend(
                    deployment_id,
                    suspended_by=suspended_by,
                    reason=reason,
                )
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=True,
                    message=f"Deployment suspended: {reason}",
                    deployment_id=deployment_id,
                    changes={"approval_status": "SUSPENDED", "reason": reason},
                )
            except Exception as e:
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=False,
                    message=f"Failed to suspend: {e}",
                    deployment_id=deployment_id,
                )

        return RegistryActionResult(
            action_type=action.action_type,
            success=True,
            message="Suspension recorded (no manager)",
            deployment_id=deployment_id,
        )

    def _handle_update_metadata(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """Handle UPDATE_METADATA action."""
        metadata_updates = action.params.get("metadata", {})

        if self._registry_manager and metadata_updates:
            try:
                deployment = self._registry_manager.get(deployment_id)
                if deployment:
                    current_metadata = dict(deployment.metadata)
                    current_metadata.update(metadata_updates)
                    self._registry_manager.update(
                        deployment_id,
                        updated_by="policy_engine",
                        metadata=current_metadata,
                    )
                    return RegistryActionResult(
                        action_type=action.action_type,
                        success=True,
                        message="Metadata updated",
                        deployment_id=deployment_id,
                        changes={"metadata": metadata_updates},
                    )
            except Exception as e:
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=False,
                    message=f"Failed to update metadata: {e}",
                    deployment_id=deployment_id,
                )

        return RegistryActionResult(
            action_type=action.action_type,
            success=True,
            message="Metadata update recorded (no manager)",
            deployment_id=deployment_id,
        )

    def _handle_notify_owner(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """Handle NOTIFY_OWNER action."""
        subject = action.params.get("subject", "Policy Notification")
        body = action.params.get("body", "A policy event occurred for your deployment.")

        owner = None
        if self._registry_manager:
            deployment = self._registry_manager.get(deployment_id)
            if deployment:
                owner = deployment.owner_contact or deployment.owner

        if owner and self._notification_callback:
            try:
                self._notification_callback(owner, subject, body)
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=True,
                    message=f"Notification sent to {owner}",
                    deployment_id=deployment_id,
                    changes={"notified": owner},
                )
            except Exception as e:
                return RegistryActionResult(
                    action_type=action.action_type,
                    success=False,
                    message=f"Failed to send notification: {e}",
                    deployment_id=deployment_id,
                )

        return RegistryActionResult(
            action_type=action.action_type,
            success=True,
            message="Notification logged (no callback or owner)",
            deployment_id=deployment_id,
        )

    def _handle_unknown(
        self,
        deployment_id: str,
        action: RegistryAction,
    ) -> RegistryActionResult:
        """Handle unknown action types."""
        return RegistryActionResult(
            action_type=action.action_type,
            success=False,
            message=f"Unknown action type: {action.action_type}",
            deployment_id=deployment_id,
        )

    def get_action_log(self, limit: int = 100) -> list[RegistryActionResult]:
        """Get recent action execution log."""
        return self._action_log[-limit:]


class RegistryEnricher(Middleware):
    """
    Pipeline middleware that enriches requests with registry data.

    The RegistryEnricher looks up deployment information for incoming
    requests and attaches it to the enforcement context, enabling
    registry-aware policy decisions.

    Example:
        Adding to the pipeline::

            enricher = RegistryEnricher(registry_manager)
            pipeline.add_middleware(enricher)

        After enrichment, policies can access registry data via
        the context's metadata under the 'registry' key.
    """

    def __init__(
        self,
        registry_manager: Any = None,
        lookup_by: str = "deployment_id",
        fail_on_not_found: bool = False,
        block_unapproved: bool = True,
        block_suspended: bool = True,
    ) -> None:
        """
        Initialize the registry enricher.

        Args:
            registry_manager: The RegistryManager instance.
            lookup_by: How to look up the deployment (deployment_id, name).
            fail_on_not_found: Whether to deny if deployment not found.
            block_unapproved: Whether to block unapproved deployments.
            block_suspended: Whether to block suspended deployments.
        """
        self._registry_manager = registry_manager
        self._lookup_by = lookup_by
        self._fail_on_not_found = fail_on_not_found
        self._block_unapproved = block_unapproved
        self._block_suspended = block_suspended

    @property
    def name(self) -> str:
        return "RegistryEnricher"

    @property
    def stage(self) -> PipelineStage:
        return PipelineStage.VALIDATION

    def process(self, context: EnforcementContext) -> StageResult:
        """
        Enrich the context with registry data.

        Args:
            context: The enforcement context.

        Returns:
            StageResult indicating success/failure.
        """
        start = time.perf_counter()

        if context.request is None:
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Get deployment identifier from request
        deployment_id = self._get_deployment_id(context)
        if not deployment_id:
            if self._fail_on_not_found:
                context.short_circuit(
                    Decision.DENY,
                    "No deployment identifier in request",
                )
                return self._failure_result(
                    "No deployment identifier in request",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Look up deployment
        deployment = self._lookup_deployment(deployment_id)
        if not deployment:
            if self._fail_on_not_found:
                context.short_circuit(
                    Decision.DENY,
                    f"Deployment not found: {deployment_id}",
                )
                return self._failure_result(
                    f"Deployment not found: {deployment_id}",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            return self._success_result(
                duration_ms=(time.perf_counter() - start) * 1000,
                metadata={"deployment_id": deployment_id, "found": False},
            )

        # Check approval status
        if self._block_unapproved:
            if deployment.approval_status != ApprovalStatus.APPROVED:
                context.short_circuit(
                    Decision.DENY,
                    f"Deployment not approved: {deployment.approval_status.value}",
                )
                return self._failure_result(
                    f"Deployment not approved: {deployment.approval_status.value}",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        # Check suspension status
        if self._block_suspended:
            if deployment.approval_status == ApprovalStatus.SUSPENDED:
                context.short_circuit(
                    Decision.DENY,
                    "Deployment is suspended",
                )
                return self._failure_result(
                    "Deployment is suspended",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        # Enrich context with registry data
        registry_data = self._deployment_to_dict(deployment)

        # Add violation count if available
        if self._registry_manager:
            registry_data["violation_count"] = (
                self._registry_manager.get_violation_count(deployment.deployment_id)
            )

        context.metadata["registry"] = registry_data
        context.metadata["deployment_id"] = deployment.deployment_id

        return self._success_result(
            duration_ms=(time.perf_counter() - start) * 1000,
            metadata={
                "deployment_id": deployment.deployment_id,
                "deployment_name": deployment.name,
                "risk_level": deployment.risk_level.value,
                "found": True,
            },
        )

    def _get_deployment_id(self, context: EnforcementContext) -> str | None:
        """Get the deployment identifier from the request."""
        request = context.request
        if request is None:
            return None

        # Check metadata first
        if request.metadata:
            if "deployment_id" in request.metadata:
                return str(request.metadata["deployment_id"])
            if "deployment_name" in request.metadata:
                return str(request.metadata["deployment_name"])

        # Fall back to model provider/name combination
        if request.provider and request.model:
            return f"{request.provider}/{request.model}"

        return None

    def _lookup_deployment(self, identifier: str) -> ModelDeployment | None:
        """Look up a deployment by identifier."""
        if not self._registry_manager:
            return None

        if self._lookup_by == "name":
            return self._registry_manager.get_by_name(identifier)
        else:
            # Try by ID first, then by name
            deployment = self._registry_manager.get(identifier)
            if not deployment:
                deployment = self._registry_manager.get_by_name(identifier)
            return deployment

    def _deployment_to_dict(self, deployment: ModelDeployment) -> dict[str, Any]:
        """Convert a deployment to a dictionary for context."""
        return {
            "deployment_id": deployment.deployment_id,
            "name": deployment.name,
            "description": deployment.description,
            "model_provider": deployment.model_provider,
            "model_name": deployment.model_name,
            "model_version": deployment.model_version,
            "owner": deployment.owner,
            "owner_contact": deployment.owner_contact,
            "data_categories": list(deployment.data_categories),
            "risk_level": deployment.risk_level.value,
            "approval_status": deployment.approval_status.value,
            "deployment_date": (
                deployment.deployment_date.isoformat()
                if deployment.deployment_date else None
            ),
            "last_review_date": (
                deployment.last_review_date.isoformat()
                if deployment.last_review_date else None
            ),
            "next_review_date": (
                deployment.next_review_date.isoformat()
                if deployment.next_review_date else None
            ),
            "is_high_risk": deployment.is_high_risk(),
            "needs_review": deployment.needs_review(),
            "is_active": deployment.is_active(),
        }


class RegistryConditionFactory:
    """
    Factory for creating registry conditions from policy YAML.

    Converts the dictionary representation of registry conditions
    into RegistryCondition objects that can be evaluated.
    """

    # Mapping of field names to RegistryField enum
    FIELD_MAP = {
        "risk_level": RegistryField.RISK_LEVEL,
        "registry.risk_level": RegistryField.RISK_LEVEL,
        "approval_status": RegistryField.APPROVAL_STATUS,
        "registry.approval_status": RegistryField.APPROVAL_STATUS,
        "owner": RegistryField.OWNER,
        "registry.owner": RegistryField.OWNER,
        "owner_contact": RegistryField.OWNER_CONTACT,
        "registry.owner_contact": RegistryField.OWNER_CONTACT,
        "data_categories": RegistryField.DATA_CATEGORIES,
        "registry.data_categories": RegistryField.DATA_CATEGORIES,
        "model_provider": RegistryField.MODEL_PROVIDER,
        "registry.model_provider": RegistryField.MODEL_PROVIDER,
        "model_name": RegistryField.MODEL_NAME,
        "registry.model_name": RegistryField.MODEL_NAME,
        "model_version": RegistryField.MODEL_VERSION,
        "registry.model_version": RegistryField.MODEL_VERSION,
        "deployment_age_days": RegistryField.DEPLOYMENT_AGE_DAYS,
        "registry.deployment_age_days": RegistryField.DEPLOYMENT_AGE_DAYS,
        "days_since_review": RegistryField.DAYS_SINCE_REVIEW,
        "registry.days_since_review": RegistryField.DAYS_SINCE_REVIEW,
        "days_until_review": RegistryField.DAYS_UNTIL_REVIEW,
        "registry.days_until_review": RegistryField.DAYS_UNTIL_REVIEW,
        "is_high_risk": RegistryField.IS_HIGH_RISK,
        "registry.is_high_risk": RegistryField.IS_HIGH_RISK,
        "needs_review": RegistryField.NEEDS_REVIEW,
        "registry.needs_review": RegistryField.NEEDS_REVIEW,
        "violation_count": RegistryField.VIOLATION_COUNT,
        "registry.violation_count": RegistryField.VIOLATION_COUNT,
    }

    # Mapping of operator strings to Operator enum
    OPERATOR_MAP = {
        "eq": Operator.EQ,
        "ne": Operator.NE,
        "gt": Operator.GT,
        "gte": Operator.GTE,
        "lt": Operator.LT,
        "lte": Operator.LTE,
        "in": Operator.IN,
        "not_in": Operator.NOT_IN,
        "contains": Operator.CONTAINS,
        "not_contains": Operator.NOT_CONTAINS,
        "exists": Operator.EXISTS,
        "not_exists": Operator.NOT_EXISTS,
    }

    def create(
        self,
        field_name: str,
        value: Any,
    ) -> RegistryCondition | None:
        """
        Create a RegistryCondition from a field name and value.

        Args:
            field_name: The field name (e.g., "registry.risk_level").
            value: The value or operator expression.

        Returns:
            A RegistryCondition, or None if not a registry field.
        """
        registry_field = self.FIELD_MAP.get(field_name)
        if not registry_field:
            return None

        # Simple equality check
        if not isinstance(value, dict):
            return RegistryCondition(
                field=registry_field,
                operator=Operator.EQ,
                value=value,
            )

        # Operator-based condition
        for op_str, op_value in value.items():
            operator = self.OPERATOR_MAP.get(op_str)
            if operator:
                return RegistryCondition(
                    field=registry_field,
                    operator=operator,
                    value=op_value,
                )

        # Default to equality with first value
        first_key = next(iter(value.keys()), None)
        if first_key:
            return RegistryCondition(
                field=registry_field,
                operator=Operator.EQ,
                value=value[first_key],
            )

        return None

    def is_registry_field(self, field_name: str) -> bool:
        """Check if a field name is a registry field."""
        return field_name in self.FIELD_MAP


class RegistryActionFactory:
    """
    Factory for creating registry actions from policy YAML.
    """

    # Mapping of action type strings to RegistryActionType enum
    ACTION_TYPE_MAP = {
        "flag_for_review": RegistryActionType.FLAG_FOR_REVIEW,
        "increment_violation": RegistryActionType.INCREMENT_VIOLATION,
        "suspend_deployment": RegistryActionType.SUSPEND_DEPLOYMENT,
        "update_metadata": RegistryActionType.UPDATE_METADATA,
        "notify_owner": RegistryActionType.NOTIFY_OWNER,
    }

    def create(self, action_config: dict[str, Any]) -> RegistryAction | None:
        """
        Create a RegistryAction from configuration.

        Args:
            action_config: Dictionary with 'type' and optional 'params'.

        Returns:
            A RegistryAction, or None if configuration is invalid.
        """
        action_type_str = action_config.get("type")
        if not action_type_str:
            return None

        action_type = self.ACTION_TYPE_MAP.get(action_type_str)
        if not action_type:
            return None

        params = action_config.get("params", {})
        return RegistryAction(
            action_type=action_type,
            params=params,
        )

    def create_many(
        self,
        actions_config: list[dict[str, Any]],
    ) -> list[RegistryAction]:
        """
        Create multiple registry actions from configuration.

        Args:
            actions_config: List of action configuration dictionaries.

        Returns:
            List of RegistryAction objects.
        """
        actions = []
        for config in actions_config:
            action = self.create(config)
            if action:
                actions.append(action)
        return actions
