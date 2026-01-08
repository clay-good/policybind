"""
Token-based policy conditions and actions for PolicyBind.

This module provides classes for integrating token validation with policy
conditions, actions, and the enforcement pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from policybind.engine.conditions import Condition, EvaluationContext, Operator
from policybind.models.base import utc_now
from policybind.tokens.manager import TokenManager
from policybind.tokens.models import Token, TokenPermissions, TokenStatus


class TokenField(Enum):
    """Fields available for token-based conditions."""

    SUBJECT = "token.subject"
    """Token subject (who the token is for)."""

    SUBJECT_TYPE = "token.subject_type"
    """Token subject type (user, service, etc.)."""

    ISSUER = "token.issuer"
    """Who issued the token."""

    TOKEN_ID = "token.token_id"
    """The token's unique identifier."""

    TOKEN_AGE_DAYS = "token.age_days"
    """Days since the token was issued."""

    TOKEN_AGE_HOURS = "token.age_hours"
    """Hours since the token was issued."""

    DAYS_UNTIL_EXPIRY = "token.days_until_expiry"
    """Days until the token expires."""

    HOURS_UNTIL_EXPIRY = "token.hours_until_expiry"
    """Hours until the token expires."""

    REMAINING_BUDGET = "token.remaining_budget"
    """Remaining budget in currency."""

    REMAINING_BUDGET_PERCENT = "token.remaining_budget_percent"
    """Remaining budget as percentage of limit."""

    TOTAL_REQUESTS = "token.total_requests"
    """Total requests made with this token."""

    TOTAL_COST = "token.total_cost"
    """Total cost incurred by this token."""

    ALLOWED_MODELS = "token.allowed_models"
    """Models the token is allowed to use."""

    DENIED_MODELS = "token.denied_models"
    """Models the token is denied from using."""

    ALLOWED_PROVIDERS = "token.allowed_providers"
    """Providers the token is allowed to use."""

    ALLOWED_USE_CASES = "token.allowed_use_cases"
    """Use cases the token is allowed for."""

    BUDGET_LIMIT = "token.budget_limit"
    """Token's budget limit."""

    RATE_LIMIT = "token.rate_limit"
    """Token's rate limit (requests per period)."""

    HAS_TIME_RESTRICTIONS = "token.has_time_restrictions"
    """Whether the token has time-of-day restrictions."""

    IS_NEAR_BUDGET_LIMIT = "token.is_near_budget_limit"
    """Whether the token is near its budget limit (>80% used)."""

    IS_NEAR_RATE_LIMIT = "token.is_near_rate_limit"
    """Whether the token is near its rate limit (>80% used)."""

    WARNINGS = "token.warnings"
    """Current warnings for this token."""


@dataclass
class TokenCondition(Condition):
    """
    A condition that evaluates based on token data.

    TokenCondition allows policies to make decisions based on token
    attributes like subject, issuer, age, remaining budget, and
    permissions.

    Example:
        Matching tokens near budget limit::

            condition = TokenCondition(
                field=TokenField.REMAINING_BUDGET_PERCENT,
                operator=Operator.LT,
                value=20.0,
            )

        Matching tokens issued by a specific issuer::

            condition = TokenCondition(
                field=TokenField.ISSUER,
                operator=Operator.EQ,
                value="admin-service",
            )

        Matching tokens older than 30 days::

            condition = TokenCondition(
                field=TokenField.TOKEN_AGE_DAYS,
                operator=Operator.GT,
                value=30,
            )
    """

    field: TokenField
    operator: Operator
    value: Any

    def evaluate(self, context: EvaluationContext) -> bool:
        """
        Evaluate the token condition against the context.

        The context must have token data attached in the metadata
        under the 'token' key.

        Args:
            context: The evaluation context.

        Returns:
            True if the condition matches, False otherwise.
        """
        # Get token data from context
        token_data = context.metadata.get("token", {})
        if not token_data:
            # No token data means condition cannot match
            return False

        # Get the field value
        field_value = self._get_field_value(token_data)

        # Handle exists/not_exists operators
        if self.operator == Operator.EXISTS:
            return field_value is not None if self.value else field_value is None

        if self.operator == Operator.NOT_EXISTS:
            return field_value is None if self.value else field_value is not None

        # For other operators, if field doesn't exist, return False
        if field_value is None:
            return False

        return self._compare(field_value)

    def _get_field_value(self, token_data: dict[str, Any]) -> Any:
        """Extract the field value from token data."""
        if self.field == TokenField.SUBJECT:
            return token_data.get("subject")

        elif self.field == TokenField.SUBJECT_TYPE:
            return token_data.get("subject_type")

        elif self.field == TokenField.ISSUER:
            return token_data.get("issuer")

        elif self.field == TokenField.TOKEN_ID:
            return token_data.get("token_id")

        elif self.field == TokenField.TOKEN_AGE_DAYS:
            issued_at = token_data.get("issued_at")
            if issued_at:
                if isinstance(issued_at, str):
                    issued_at = datetime.fromisoformat(issued_at)
                return (utc_now() - issued_at).days
            return None

        elif self.field == TokenField.TOKEN_AGE_HOURS:
            issued_at = token_data.get("issued_at")
            if issued_at:
                if isinstance(issued_at, str):
                    issued_at = datetime.fromisoformat(issued_at)
                return (utc_now() - issued_at).total_seconds() / 3600
            return None

        elif self.field == TokenField.DAYS_UNTIL_EXPIRY:
            expires_at = token_data.get("expires_at")
            if expires_at:
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                return (expires_at - utc_now()).days
            return None

        elif self.field == TokenField.HOURS_UNTIL_EXPIRY:
            expires_at = token_data.get("expires_at")
            if expires_at:
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                return (expires_at - utc_now()).total_seconds() / 3600
            return None

        elif self.field == TokenField.REMAINING_BUDGET:
            return token_data.get("remaining_budget")

        elif self.field == TokenField.REMAINING_BUDGET_PERCENT:
            remaining = token_data.get("remaining_budget")
            permissions = token_data.get("permissions", {})
            budget_limit = permissions.get("budget_limit")
            if remaining is not None and budget_limit and budget_limit > 0:
                return (remaining / budget_limit) * 100
            return None

        elif self.field == TokenField.TOTAL_REQUESTS:
            return token_data.get("total_requests")

        elif self.field == TokenField.TOTAL_COST:
            return token_data.get("total_cost")

        elif self.field == TokenField.ALLOWED_MODELS:
            permissions = token_data.get("permissions", {})
            return permissions.get("allowed_models", [])

        elif self.field == TokenField.DENIED_MODELS:
            permissions = token_data.get("permissions", {})
            return permissions.get("denied_models", [])

        elif self.field == TokenField.ALLOWED_PROVIDERS:
            permissions = token_data.get("permissions", {})
            return permissions.get("allowed_providers", [])

        elif self.field == TokenField.ALLOWED_USE_CASES:
            permissions = token_data.get("permissions", {})
            return permissions.get("allowed_use_cases", [])

        elif self.field == TokenField.BUDGET_LIMIT:
            permissions = token_data.get("permissions", {})
            return permissions.get("budget_limit")

        elif self.field == TokenField.RATE_LIMIT:
            permissions = token_data.get("permissions", {})
            rate_limit = permissions.get("rate_limit")
            if rate_limit:
                return rate_limit.get("max_requests")
            return None

        elif self.field == TokenField.HAS_TIME_RESTRICTIONS:
            permissions = token_data.get("permissions", {})
            return permissions.get("valid_hours") is not None

        elif self.field == TokenField.IS_NEAR_BUDGET_LIMIT:
            remaining = token_data.get("remaining_budget")
            permissions = token_data.get("permissions", {})
            budget_limit = permissions.get("budget_limit")
            if remaining is not None and budget_limit and budget_limit > 0:
                return (remaining / budget_limit) < 0.2
            return False

        elif self.field == TokenField.IS_NEAR_RATE_LIMIT:
            rate_remaining = token_data.get("rate_limit_remaining")
            permissions = token_data.get("permissions", {})
            rate_limit = permissions.get("rate_limit")
            if rate_remaining is not None and rate_limit:
                max_requests = rate_limit.get("max_requests", 0)
                if max_requests > 0:
                    return (rate_remaining / max_requests) < 0.2
            return False

        elif self.field == TokenField.WARNINGS:
            return token_data.get("warnings", [])

        return None

    def _compare(self, field_value: Any) -> bool:
        """Compare field value against condition value using the operator."""
        if self.operator == Operator.EQ:
            return field_value == self.value

        elif self.operator == Operator.NE:
            return field_value != self.value

        elif self.operator == Operator.GT:
            return field_value > self.value

        elif self.operator == Operator.GTE:
            return field_value >= self.value

        elif self.operator == Operator.LT:
            return field_value < self.value

        elif self.operator == Operator.LTE:
            return field_value <= self.value

        elif self.operator == Operator.IN:
            if isinstance(self.value, (list, tuple, set)):
                return field_value in self.value
            return False

        elif self.operator == Operator.NOT_IN:
            if isinstance(self.value, (list, tuple, set)):
                return field_value not in self.value
            return True

        elif self.operator == Operator.CONTAINS:
            if isinstance(field_value, (list, tuple, set)):
                return self.value in field_value
            elif isinstance(field_value, str):
                return str(self.value) in field_value
            return False

        elif self.operator == Operator.NOT_CONTAINS:
            if isinstance(field_value, (list, tuple, set)):
                return self.value not in field_value
            elif isinstance(field_value, str):
                return str(self.value) not in field_value
            return True

        return False

    def describe(self) -> str:
        """Return a human-readable description of the condition."""
        return f"token.{self.field.name.lower()} {self.operator.value} {self.value}"


class TokenConditionFactory:
    """
    Factory for creating token conditions from configuration.

    Example:
        Creating conditions from config::

            factory = TokenConditionFactory()

            # Budget percentage condition
            condition = factory.create("remaining_budget_percent", {"lt": 20})

            # Subject match condition
            condition = factory.create("subject", {"eq": "admin"})
    """

    _FIELD_MAP: dict[str, TokenField] = {
        "subject": TokenField.SUBJECT,
        "subject_type": TokenField.SUBJECT_TYPE,
        "issuer": TokenField.ISSUER,
        "token_id": TokenField.TOKEN_ID,
        "age_days": TokenField.TOKEN_AGE_DAYS,
        "age_hours": TokenField.TOKEN_AGE_HOURS,
        "days_until_expiry": TokenField.DAYS_UNTIL_EXPIRY,
        "hours_until_expiry": TokenField.HOURS_UNTIL_EXPIRY,
        "remaining_budget": TokenField.REMAINING_BUDGET,
        "remaining_budget_percent": TokenField.REMAINING_BUDGET_PERCENT,
        "total_requests": TokenField.TOTAL_REQUESTS,
        "total_cost": TokenField.TOTAL_COST,
        "allowed_models": TokenField.ALLOWED_MODELS,
        "denied_models": TokenField.DENIED_MODELS,
        "allowed_providers": TokenField.ALLOWED_PROVIDERS,
        "allowed_use_cases": TokenField.ALLOWED_USE_CASES,
        "budget_limit": TokenField.BUDGET_LIMIT,
        "rate_limit": TokenField.RATE_LIMIT,
        "has_time_restrictions": TokenField.HAS_TIME_RESTRICTIONS,
        "is_near_budget_limit": TokenField.IS_NEAR_BUDGET_LIMIT,
        "is_near_rate_limit": TokenField.IS_NEAR_RATE_LIMIT,
        "warnings": TokenField.WARNINGS,
    }

    _OPERATOR_MAP: dict[str, Operator] = {
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
        config: dict[str, Any],
    ) -> TokenCondition | None:
        """
        Create a token condition from field name and config.

        Args:
            field_name: The field to match on.
            config: Dictionary with operator -> value mappings.

        Returns:
            TokenCondition if valid, None otherwise.
        """
        field = self._FIELD_MAP.get(field_name.lower())
        if field is None:
            return None

        # Find the operator and value
        for op_name, value in config.items():
            operator = self._OPERATOR_MAP.get(op_name.lower())
            if operator:
                return TokenCondition(
                    field=field,
                    operator=operator,
                    value=value,
                )

        return None

    def create_subject_match(self, subject: str) -> TokenCondition:
        """Create a condition matching a specific subject."""
        return TokenCondition(
            field=TokenField.SUBJECT,
            operator=Operator.EQ,
            value=subject,
        )

    def create_issuer_match(self, issuer: str) -> TokenCondition:
        """Create a condition matching a specific issuer."""
        return TokenCondition(
            field=TokenField.ISSUER,
            operator=Operator.EQ,
            value=issuer,
        )

    def create_age_check(self, max_days: int) -> TokenCondition:
        """Create a condition checking if token is older than X days."""
        return TokenCondition(
            field=TokenField.TOKEN_AGE_DAYS,
            operator=Operator.GT,
            value=max_days,
        )

    def create_budget_check(self, min_percent: float) -> TokenCondition:
        """Create a condition checking if budget is below X percent."""
        return TokenCondition(
            field=TokenField.REMAINING_BUDGET_PERCENT,
            operator=Operator.LT,
            value=min_percent,
        )

    def create_near_budget_limit(self) -> TokenCondition:
        """Create a condition for tokens near their budget limit."""
        return TokenCondition(
            field=TokenField.IS_NEAR_BUDGET_LIMIT,
            operator=Operator.EQ,
            value=True,
        )

    def create_near_rate_limit(self) -> TokenCondition:
        """Create a condition for tokens near their rate limit."""
        return TokenCondition(
            field=TokenField.IS_NEAR_RATE_LIMIT,
            operator=Operator.EQ,
            value=True,
        )


class TokenActionType(Enum):
    """Types of token-related actions."""

    REVOKE = "revoke"
    """Revoke the token permanently."""

    SUSPEND = "suspend"
    """Suspend the token temporarily."""

    REDUCE_BUDGET = "reduce_budget"
    """Reduce the token's budget limit."""

    REDUCE_RATE_LIMIT = "reduce_rate_limit"
    """Reduce the token's rate limit."""

    ADD_RESTRICTION = "add_restriction"
    """Add a restriction to the token."""

    NOTIFY_OWNER = "notify_owner"
    """Send notification to token owner."""

    EXTEND_EXPIRY = "extend_expiry"
    """Extend the token's expiration date."""

    REFRESH = "refresh"
    """Refresh/renew the token."""


@dataclass
class TokenActionResult:
    """
    Result of executing a token action.

    Attributes:
        success: Whether the action succeeded.
        action_type: The type of action executed.
        token_id: The affected token ID.
        details: Action-specific details.
        error: Error message if action failed.
    """

    success: bool
    action_type: TokenActionType
    token_id: str
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class TokenAction:
    """
    A token-related policy action.

    Attributes:
        action_type: Type of action to perform.
        params: Action-specific parameters.
    """

    action_type: TokenActionType
    params: dict[str, Any] = field(default_factory=dict)


class TokenActionExecutor:
    """
    Executor for token-related policy actions.

    Example:
        Executing token actions::

            executor = TokenActionExecutor(
                manager=token_manager,
                notifier=my_notification_function,
            )

            # Revoke a token
            result = executor.execute(
                token_id="token-123",
                action=TokenAction(
                    action_type=TokenActionType.REVOKE,
                    params={"reason": "Policy violation"},
                ),
            )

            # Reduce budget
            result = executor.execute(
                token_id="token-456",
                action=TokenAction(
                    action_type=TokenActionType.REDUCE_BUDGET,
                    params={"new_limit": 50.0},
                ),
            )
    """

    def __init__(
        self,
        manager: TokenManager,
        notifier: Callable[[str, str, dict[str, Any]], None] | None = None,
    ) -> None:
        """
        Initialize the action executor.

        Args:
            manager: The token manager.
            notifier: Function to call for notifications (subject, message, context).
        """
        self._manager = manager
        self._notifier = notifier

    def execute(self, token_id: str, action: TokenAction) -> TokenActionResult:
        """
        Execute a token action.

        Args:
            token_id: The token to act on.
            action: The action to execute.

        Returns:
            TokenActionResult with execution status.
        """
        try:
            if action.action_type == TokenActionType.REVOKE:
                return self._execute_revoke(token_id, action.params)

            elif action.action_type == TokenActionType.SUSPEND:
                return self._execute_suspend(token_id, action.params)

            elif action.action_type == TokenActionType.REDUCE_BUDGET:
                return self._execute_reduce_budget(token_id, action.params)

            elif action.action_type == TokenActionType.REDUCE_RATE_LIMIT:
                return self._execute_reduce_rate_limit(token_id, action.params)

            elif action.action_type == TokenActionType.ADD_RESTRICTION:
                return self._execute_add_restriction(token_id, action.params)

            elif action.action_type == TokenActionType.NOTIFY_OWNER:
                return self._execute_notify_owner(token_id, action.params)

            elif action.action_type == TokenActionType.EXTEND_EXPIRY:
                return self._execute_extend_expiry(token_id, action.params)

            elif action.action_type == TokenActionType.REFRESH:
                return self._execute_refresh(token_id, action.params)

            else:
                return TokenActionResult(
                    success=False,
                    action_type=action.action_type,
                    token_id=token_id,
                    error=f"Unknown action type: {action.action_type}",
                )

        except Exception as e:
            return TokenActionResult(
                success=False,
                action_type=action.action_type,
                token_id=token_id,
                error=str(e),
            )

    def _execute_revoke(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Revoke a token."""
        reason = params.get("reason", "Policy action")
        revoked_by = params.get("revoked_by", "system")

        success = self._manager.revoke_token(
            token_id=token_id,
            reason=reason,
            revoked_by=revoked_by,
        )

        if success:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.REVOKE,
                token_id=token_id,
                details={"reason": reason, "revoked_by": revoked_by},
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.REVOKE,
            token_id=token_id,
            error="Failed to revoke token",
        )

    def _execute_suspend(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Suspend a token temporarily."""
        reason = params.get("reason", "Policy action")
        suspended_by = params.get("suspended_by", "system")
        duration_hours = params.get("duration_hours", 24)

        success = self._manager.suspend_token(
            token_id=token_id,
            reason=reason,
            suspended_by=suspended_by,
        )

        if success:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.SUSPEND,
                token_id=token_id,
                details={
                    "reason": reason,
                    "suspended_by": suspended_by,
                    "duration_hours": duration_hours,
                },
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.SUSPEND,
            token_id=token_id,
            error="Failed to suspend token",
        )

    def _execute_reduce_budget(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Reduce a token's budget limit."""
        new_limit = params.get("new_limit")
        reduction_percent = params.get("reduction_percent")

        token = self._manager.get_token(token_id)
        if token is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REDUCE_BUDGET,
                token_id=token_id,
                error="Token not found",
            )

        current_limit = token.permissions.budget_limit
        if current_limit is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REDUCE_BUDGET,
                token_id=token_id,
                error="Token has no budget limit",
            )

        if new_limit is not None:
            final_limit = new_limit
        elif reduction_percent is not None:
            final_limit = current_limit * (1 - reduction_percent / 100)
        else:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REDUCE_BUDGET,
                token_id=token_id,
                error="Must specify new_limit or reduction_percent",
            )

        # Update the token's permissions
        new_permissions = TokenPermissions(
            allowed_models=token.permissions.allowed_models,
            denied_models=token.permissions.denied_models,
            allowed_providers=token.permissions.allowed_providers,
            denied_providers=token.permissions.denied_providers,
            allowed_use_cases=token.permissions.allowed_use_cases,
            denied_use_cases=token.permissions.denied_use_cases,
            allowed_data_classifications=token.permissions.allowed_data_classifications,
            denied_data_classifications=token.permissions.denied_data_classifications,
            budget_limit=final_limit,
            budget_period=token.permissions.budget_period,
            budget_currency=token.permissions.budget_currency,
            rate_limit=token.permissions.rate_limit,
            valid_sources=token.permissions.valid_sources,
            valid_hours=token.permissions.valid_hours,
            max_tokens_per_request=token.permissions.max_tokens_per_request,
            max_requests_per_session=token.permissions.max_requests_per_session,
            require_approval_above=token.permissions.require_approval_above,
            custom_constraints=token.permissions.custom_constraints,
        )

        updated = self._manager.update_permissions(token_id, new_permissions, "policy_action")

        if updated:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.REDUCE_BUDGET,
                token_id=token_id,
                details={
                    "old_limit": current_limit,
                    "new_limit": final_limit,
                },
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.REDUCE_BUDGET,
            token_id=token_id,
            error="Failed to update budget limit",
        )

    def _execute_reduce_rate_limit(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Reduce a token's rate limit."""
        new_limit = params.get("new_limit")
        reduction_percent = params.get("reduction_percent")

        token = self._manager.get_token(token_id)
        if token is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REDUCE_RATE_LIMIT,
                token_id=token_id,
                error="Token not found",
            )

        current_rate_limit = token.permissions.rate_limit
        if current_rate_limit is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REDUCE_RATE_LIMIT,
                token_id=token_id,
                error="Token has no rate limit",
            )

        current_max = current_rate_limit.max_requests

        if new_limit is not None:
            final_limit = int(new_limit)
        elif reduction_percent is not None:
            final_limit = int(current_max * (1 - reduction_percent / 100))
        else:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REDUCE_RATE_LIMIT,
                token_id=token_id,
                error="Must specify new_limit or reduction_percent",
            )

        # Import RateLimit here to avoid circular import
        from policybind.tokens.models import RateLimit

        new_rate_limit = RateLimit(
            max_requests=final_limit,
            period_seconds=current_rate_limit.period_seconds,
            burst_limit=current_rate_limit.burst_limit,
        )

        new_permissions = TokenPermissions(
            allowed_models=token.permissions.allowed_models,
            denied_models=token.permissions.denied_models,
            allowed_providers=token.permissions.allowed_providers,
            denied_providers=token.permissions.denied_providers,
            allowed_use_cases=token.permissions.allowed_use_cases,
            denied_use_cases=token.permissions.denied_use_cases,
            allowed_data_classifications=token.permissions.allowed_data_classifications,
            denied_data_classifications=token.permissions.denied_data_classifications,
            budget_limit=token.permissions.budget_limit,
            budget_period=token.permissions.budget_period,
            budget_currency=token.permissions.budget_currency,
            rate_limit=new_rate_limit,
            valid_sources=token.permissions.valid_sources,
            valid_hours=token.permissions.valid_hours,
            max_tokens_per_request=token.permissions.max_tokens_per_request,
            max_requests_per_session=token.permissions.max_requests_per_session,
            require_approval_above=token.permissions.require_approval_above,
            custom_constraints=token.permissions.custom_constraints,
        )

        updated = self._manager.update_permissions(token_id, new_permissions, "policy_action")

        if updated:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.REDUCE_RATE_LIMIT,
                token_id=token_id,
                details={
                    "old_limit": current_max,
                    "new_limit": final_limit,
                },
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.REDUCE_RATE_LIMIT,
            token_id=token_id,
            error="Failed to update rate limit",
        )

    def _execute_add_restriction(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Add a restriction to a token."""
        restriction_type = params.get("type")
        restriction_value = params.get("value")

        token = self._manager.get_token(token_id)
        if token is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.ADD_RESTRICTION,
                token_id=token_id,
                error="Token not found",
            )

        # Build new permissions with the added restriction
        new_permissions = token.permissions

        if restriction_type == "denied_models":
            new_denied = list(token.permissions.denied_models)
            if isinstance(restriction_value, list):
                new_denied.extend(restriction_value)
            else:
                new_denied.append(restriction_value)
            new_permissions = TokenPermissions(
                allowed_models=token.permissions.allowed_models,
                denied_models=new_denied,
                allowed_providers=token.permissions.allowed_providers,
                denied_providers=token.permissions.denied_providers,
                allowed_use_cases=token.permissions.allowed_use_cases,
                denied_use_cases=token.permissions.denied_use_cases,
                allowed_data_classifications=token.permissions.allowed_data_classifications,
                denied_data_classifications=token.permissions.denied_data_classifications,
                budget_limit=token.permissions.budget_limit,
                budget_period=token.permissions.budget_period,
                budget_currency=token.permissions.budget_currency,
                rate_limit=token.permissions.rate_limit,
                valid_sources=token.permissions.valid_sources,
                valid_hours=token.permissions.valid_hours,
                max_tokens_per_request=token.permissions.max_tokens_per_request,
                max_requests_per_session=token.permissions.max_requests_per_session,
                require_approval_above=token.permissions.require_approval_above,
                custom_constraints=token.permissions.custom_constraints,
            )

        elif restriction_type == "denied_use_cases":
            new_denied = list(token.permissions.denied_use_cases)
            if isinstance(restriction_value, list):
                new_denied.extend(restriction_value)
            else:
                new_denied.append(restriction_value)
            new_permissions = TokenPermissions(
                allowed_models=token.permissions.allowed_models,
                denied_models=token.permissions.denied_models,
                allowed_providers=token.permissions.allowed_providers,
                denied_providers=token.permissions.denied_providers,
                allowed_use_cases=token.permissions.allowed_use_cases,
                denied_use_cases=new_denied,
                allowed_data_classifications=token.permissions.allowed_data_classifications,
                denied_data_classifications=token.permissions.denied_data_classifications,
                budget_limit=token.permissions.budget_limit,
                budget_period=token.permissions.budget_period,
                budget_currency=token.permissions.budget_currency,
                rate_limit=token.permissions.rate_limit,
                valid_sources=token.permissions.valid_sources,
                valid_hours=token.permissions.valid_hours,
                max_tokens_per_request=token.permissions.max_tokens_per_request,
                max_requests_per_session=token.permissions.max_requests_per_session,
                require_approval_above=token.permissions.require_approval_above,
                custom_constraints=token.permissions.custom_constraints,
            )

        elif restriction_type == "custom":
            new_constraints = dict(token.permissions.custom_constraints)
            constraint_name = params.get("constraint_name", "policy_restriction")
            new_constraints[constraint_name] = restriction_value
            new_permissions = TokenPermissions(
                allowed_models=token.permissions.allowed_models,
                denied_models=token.permissions.denied_models,
                allowed_providers=token.permissions.allowed_providers,
                denied_providers=token.permissions.denied_providers,
                allowed_use_cases=token.permissions.allowed_use_cases,
                denied_use_cases=token.permissions.denied_use_cases,
                allowed_data_classifications=token.permissions.allowed_data_classifications,
                denied_data_classifications=token.permissions.denied_data_classifications,
                budget_limit=token.permissions.budget_limit,
                budget_period=token.permissions.budget_period,
                budget_currency=token.permissions.budget_currency,
                rate_limit=token.permissions.rate_limit,
                valid_sources=token.permissions.valid_sources,
                valid_hours=token.permissions.valid_hours,
                max_tokens_per_request=token.permissions.max_tokens_per_request,
                max_requests_per_session=token.permissions.max_requests_per_session,
                require_approval_above=token.permissions.require_approval_above,
                custom_constraints=new_constraints,
            )

        else:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.ADD_RESTRICTION,
                token_id=token_id,
                error=f"Unknown restriction type: {restriction_type}",
            )

        success = self._manager.update_permissions(token_id, new_permissions, "policy_action")

        if success:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.ADD_RESTRICTION,
                token_id=token_id,
                details={
                    "type": restriction_type,
                    "value": restriction_value,
                },
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.ADD_RESTRICTION,
            token_id=token_id,
            error="Failed to add restriction",
        )

    def _execute_notify_owner(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Send a notification to the token owner."""
        message = params.get("message", "Policy notification")
        severity = params.get("severity", "info")

        token = self._manager.get_token(token_id)
        if token is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.NOTIFY_OWNER,
                token_id=token_id,
                error="Token not found",
            )

        if self._notifier is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.NOTIFY_OWNER,
                token_id=token_id,
                error="No notifier configured",
            )

        try:
            self._notifier(
                token.subject,
                message,
                {
                    "token_id": token_id,
                    "severity": severity,
                    "params": params,
                },
            )
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.NOTIFY_OWNER,
                token_id=token_id,
                details={"subject": token.subject, "message": message},
            )
        except Exception as e:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.NOTIFY_OWNER,
                token_id=token_id,
                error=f"Notification failed: {e}",
            )

    def _execute_extend_expiry(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Extend a token's expiration date."""
        days = params.get("days", 0)
        hours = params.get("hours", 0)

        token = self._manager.get_token(token_id)
        if token is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.EXTEND_EXPIRY,
                token_id=token_id,
                error="Token not found",
            )

        if token.expires_at is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.EXTEND_EXPIRY,
                token_id=token_id,
                error="Token has no expiration date",
            )

        extension = timedelta(days=days, hours=hours)
        new_expiry = token.expires_at + extension

        renewed = self._manager.renew_token(token_id, "policy_action", expires_at=new_expiry)

        if renewed:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.EXTEND_EXPIRY,
                token_id=token_id,
                details={
                    "old_expiry": token.expires_at.isoformat(),
                    "new_expiry": new_expiry.isoformat(),
                },
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.EXTEND_EXPIRY,
            token_id=token_id,
            error="Failed to extend expiration",
        )

    def _execute_refresh(
        self,
        token_id: str,
        params: dict[str, Any],
    ) -> TokenActionResult:
        """Refresh/renew a token."""
        new_expiry_days = params.get("expiry_days", 30)

        token = self._manager.get_token(token_id)
        if token is None:
            return TokenActionResult(
                success=False,
                action_type=TokenActionType.REFRESH,
                token_id=token_id,
                error="Token not found",
            )

        renewed = self._manager.renew_token(token_id, "policy_action", expires_in_days=new_expiry_days)

        if renewed:
            return TokenActionResult(
                success=True,
                action_type=TokenActionType.REFRESH,
                token_id=token_id,
                details={
                    "new_expiry": renewed.expires_at.isoformat() if renewed.expires_at else None,
                    "expiry_days": new_expiry_days,
                },
            )

        return TokenActionResult(
            success=False,
            action_type=TokenActionType.REFRESH,
            token_id=token_id,
            error="Failed to refresh token",
        )


class TokenActionFactory:
    """
    Factory for creating token actions from configuration.

    Example:
        Creating actions from config::

            factory = TokenActionFactory()

            # Revoke action
            action = factory.create("revoke", {"reason": "Violation"})

            # Reduce budget action
            action = factory.create("reduce_budget", {"new_limit": 50.0})
    """

    _ACTION_MAP: dict[str, TokenActionType] = {
        "revoke": TokenActionType.REVOKE,
        "suspend": TokenActionType.SUSPEND,
        "reduce_budget": TokenActionType.REDUCE_BUDGET,
        "reduce_rate_limit": TokenActionType.REDUCE_RATE_LIMIT,
        "add_restriction": TokenActionType.ADD_RESTRICTION,
        "notify_owner": TokenActionType.NOTIFY_OWNER,
        "notify": TokenActionType.NOTIFY_OWNER,
        "extend_expiry": TokenActionType.EXTEND_EXPIRY,
        "refresh": TokenActionType.REFRESH,
    }

    def create(
        self,
        action_type: str,
        params: dict[str, Any] | None = None,
    ) -> TokenAction | None:
        """
        Create a token action from type and params.

        Args:
            action_type: The action type name.
            params: Action parameters.

        Returns:
            TokenAction if valid, None otherwise.
        """
        action = self._ACTION_MAP.get(action_type.lower())
        if action is None:
            return None

        return TokenAction(
            action_type=action,
            params=params or {},
        )

    def create_revoke(self, reason: str = "Policy violation") -> TokenAction:
        """Create a revoke action."""
        return TokenAction(
            action_type=TokenActionType.REVOKE,
            params={"reason": reason},
        )

    def create_suspend(
        self,
        reason: str = "Policy violation",
        duration_hours: int = 24,
    ) -> TokenAction:
        """Create a suspend action."""
        return TokenAction(
            action_type=TokenActionType.SUSPEND,
            params={"reason": reason, "duration_hours": duration_hours},
        )

    def create_reduce_budget(
        self,
        new_limit: float | None = None,
        reduction_percent: float | None = None,
    ) -> TokenAction:
        """Create a reduce budget action."""
        params: dict[str, Any] = {}
        if new_limit is not None:
            params["new_limit"] = new_limit
        if reduction_percent is not None:
            params["reduction_percent"] = reduction_percent
        return TokenAction(
            action_type=TokenActionType.REDUCE_BUDGET,
            params=params,
        )

    def create_notify(
        self,
        message: str,
        severity: str = "warning",
    ) -> TokenAction:
        """Create a notify action."""
        return TokenAction(
            action_type=TokenActionType.NOTIFY_OWNER,
            params={"message": message, "severity": severity},
        )
