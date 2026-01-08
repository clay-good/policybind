"""
Policy actions for PolicyBind.

This module defines the available policy actions and provides an
ActionRegistry for registering and executing action implementations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Protocol

from policybind.exceptions import PolicyError


class Action(Enum):
    """
    Enumeration of available policy actions.

    Each action defines what happens when a policy rule matches a request.
    """

    ALLOW = "ALLOW"
    """
    Permit the request unchanged.
    The request proceeds to the AI provider without modification.
    """

    DENY = "DENY"
    """
    Block the request entirely.
    The request is rejected and does not reach the AI provider.
    """

    MODIFY = "MODIFY"
    """
    Transform the request before allowing it.
    Can be used to redact PII, truncate prompts, add disclaimers, etc.
    Requires action_params to specify the modifications.
    """

    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    """
    Queue the request for human approval.
    The request is held until a human approves or denies it.
    """

    RATE_LIMIT = "RATE_LIMIT"
    """
    Apply rate limiting to the request.
    If the rate limit is exceeded, the request is denied.
    Requires action_params: requests_per_minute, burst_size, etc.
    """

    AUDIT = "AUDIT"
    """
    Allow the request but flag it for review.
    The request proceeds but is logged with special attention.
    Useful for monitoring potentially problematic patterns.
    """

    REDIRECT = "REDIRECT"
    """
    Route to a different model or endpoint.
    Can be used to substitute a less capable but cheaper model,
    or to route to a specialized model for certain use cases.
    Requires action_params: target_model, target_provider, etc.
    """


class ActionContext(Protocol):
    """
    Protocol defining the context passed to action handlers.

    Action handlers receive this context containing the request
    and any additional information needed for action execution.
    """

    @property
    def request_id(self) -> str:
        """The unique request identifier."""
        ...

    @property
    def provider(self) -> str:
        """The AI provider name."""
        ...

    @property
    def model(self) -> str:
        """The model name."""
        ...

    @property
    def user_id(self) -> str:
        """The user identifier."""
        ...

    @property
    def department(self) -> str:
        """The department name."""
        ...

    @property
    def metadata(self) -> dict[str, Any]:
        """Additional request metadata."""
        ...


# Type alias for action handler functions
ActionHandler = Callable[[ActionContext, dict[str, Any]], "ActionResult"]


@dataclass
class ActionResult:
    """
    Result of executing an action.

    Attributes:
        action: The action that was executed.
        allowed: Whether the request should proceed.
        modified: Whether the request was modified.
        modifications: Dictionary of modifications made to the request.
        reason: Human-readable explanation of the action result.
        metadata: Additional metadata about the action execution.
    """

    action: Action
    allowed: bool
    modified: bool = False
    modifications: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ActionRegistry:
    """
    Registry for policy action handlers.

    The ActionRegistry allows registering custom implementations for
    each action type. When a policy rule matches, the corresponding
    action handler is called to process the request.

    Default handlers are provided for all built-in actions.

    Example:
        Registering a custom action handler::

            registry = ActionRegistry()

            def my_modify_handler(context, params):
                # Custom modification logic
                return ActionResult(
                    action=Action.MODIFY,
                    allowed=True,
                    modified=True,
                    modifications={"redacted": ["ssn"]},
                    reason="PII redacted"
                )

            registry.register(Action.MODIFY, my_modify_handler)
    """

    def __init__(self) -> None:
        """Initialize the action registry with default handlers."""
        self._handlers: dict[Action, ActionHandler] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default handlers for all built-in actions."""
        self._handlers[Action.ALLOW] = self._handle_allow
        self._handlers[Action.DENY] = self._handle_deny
        self._handlers[Action.MODIFY] = self._handle_modify
        self._handlers[Action.REQUIRE_APPROVAL] = self._handle_require_approval
        self._handlers[Action.RATE_LIMIT] = self._handle_rate_limit
        self._handlers[Action.AUDIT] = self._handle_audit
        self._handlers[Action.REDIRECT] = self._handle_redirect

    def register(self, action: Action, handler: ActionHandler) -> None:
        """
        Register a handler for an action.

        Args:
            action: The action to register the handler for.
            handler: The handler function to call when the action is executed.
        """
        self._handlers[action] = handler

    def get_handler(self, action: Action) -> ActionHandler:
        """
        Get the handler for an action.

        Args:
            action: The action to get the handler for.

        Returns:
            The registered handler function.

        Raises:
            PolicyError: If no handler is registered for the action.
        """
        handler = self._handlers.get(action)
        if handler is None:
            raise PolicyError(
                f"No handler registered for action: {action.value}",
                details={"action": action.value},
            )
        return handler

    def execute(
        self,
        action: Action,
        context: ActionContext,
        params: dict[str, Any] | None = None,
    ) -> ActionResult:
        """
        Execute an action with the given context and parameters.

        Args:
            action: The action to execute.
            context: The action context containing request information.
            params: Optional parameters for the action.

        Returns:
            The result of executing the action.

        Raises:
            PolicyError: If action execution fails.
        """
        handler = self.get_handler(action)
        try:
            return handler(context, params or {})
        except Exception as e:
            raise PolicyError(
                f"Action execution failed: {e}",
                details={"action": action.value},
            ) from e

    def get_action(self, action_str: str) -> Action:
        """
        Convert an action string to an Action enum.

        Args:
            action_str: The action name as a string.

        Returns:
            The corresponding Action enum value.

        Raises:
            PolicyError: If the action string is not valid.
        """
        try:
            return Action(action_str.upper())
        except ValueError:
            valid_actions = [a.value for a in Action]
            raise PolicyError(
                f"Invalid action: {action_str}. Valid actions: {valid_actions}",
                details={"action": action_str, "valid_actions": valid_actions},
            )

    def list_actions(self) -> list[str]:
        """
        List all registered action names.

        Returns:
            List of action names.
        """
        return [action.value for action in self._handlers.keys()]

    # Default action handlers

    def _handle_allow(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """Handle ALLOW action - permit the request unchanged."""
        return ActionResult(
            action=Action.ALLOW,
            allowed=True,
            reason="Request allowed by policy",
        )

    def _handle_deny(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """Handle DENY action - block the request."""
        reason = params.get("reason", "Request denied by policy")
        return ActionResult(
            action=Action.DENY,
            allowed=False,
            reason=reason,
        )

    def _handle_modify(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """
        Handle MODIFY action - transform the request.

        Expected params:
            modifications: Dict of modifications to apply
            reason: Optional reason string
        """
        modifications = params.get("modifications", {})
        reason = params.get("reason", "Request modified by policy")
        return ActionResult(
            action=Action.MODIFY,
            allowed=True,
            modified=True,
            modifications=modifications,
            reason=reason,
        )

    def _handle_require_approval(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """
        Handle REQUIRE_APPROVAL action - queue for human approval.

        Expected params:
            approvers: List of user IDs who can approve
            timeout_hours: How long to wait for approval
            reason: Why approval is required
        """
        reason = params.get("reason", "Request requires human approval")
        return ActionResult(
            action=Action.REQUIRE_APPROVAL,
            allowed=False,  # Not allowed until approved
            reason=reason,
            metadata={
                "approvers": params.get("approvers", []),
                "timeout_hours": params.get("timeout_hours", 24),
                "approval_required": True,
            },
        )

    def _handle_rate_limit(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """
        Handle RATE_LIMIT action - apply rate limiting.

        Expected params:
            requests_per_minute: Maximum requests per minute
            burst_size: Maximum burst size
            key: What to rate limit by (user, department, etc.)

        Note: Actual rate limit checking is done by the enforcement
        pipeline. This handler just marks the request as rate-limited.
        """
        return ActionResult(
            action=Action.RATE_LIMIT,
            allowed=True,  # Allowed if within limits
            reason="Rate limiting applied",
            metadata={
                "rate_limit": {
                    "requests_per_minute": params.get("requests_per_minute", 60),
                    "burst_size": params.get("burst_size", 10),
                    "key": params.get("key", "user"),
                }
            },
        )

    def _handle_audit(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """
        Handle AUDIT action - allow but flag for review.

        Expected params:
            audit_level: Level of scrutiny (low, medium, high)
            tags: Tags to apply to the audit entry
            reason: Why this request is being audited
        """
        reason = params.get("reason", "Request flagged for audit")
        return ActionResult(
            action=Action.AUDIT,
            allowed=True,
            reason=reason,
            metadata={
                "audit": {
                    "level": params.get("audit_level", "medium"),
                    "tags": params.get("tags", []),
                    "flagged": True,
                }
            },
        )

    def _handle_redirect(
        self,
        context: ActionContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """
        Handle REDIRECT action - route to a different model/endpoint.

        Expected params:
            target_provider: Provider to redirect to
            target_model: Model to redirect to
            reason: Why the redirect is happening
        """
        target_provider = params.get("target_provider", context.provider)
        target_model = params.get("target_model", context.model)
        reason = params.get(
            "reason", f"Request redirected to {target_provider}/{target_model}"
        )

        return ActionResult(
            action=Action.REDIRECT,
            allowed=True,
            modified=True,
            modifications={
                "provider": target_provider,
                "model": target_model,
            },
            reason=reason,
        )


# Global default registry instance
_default_registry: ActionRegistry | None = None


def get_default_registry() -> ActionRegistry:
    """
    Get the default action registry.

    Returns a singleton ActionRegistry with default handlers.

    Returns:
        The default ActionRegistry instance.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = ActionRegistry()
    return _default_registry
