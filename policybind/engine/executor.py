"""
Action executor for PolicyBind.

This module provides the ActionExecutor class that executes actions
specified by matched policies, with support for action chaining,
rollback, and async execution.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
import time

from policybind.engine.actions import Action, ActionRegistry, ActionResult
from policybind.engine.context import EnforcementContext, PipelineStage, StageResult
from policybind.models.policy import PolicyRule
from policybind.models.request import Decision


class ActionHook(Protocol):
    """Protocol for action hooks."""

    def __call__(
        self,
        action: Action,
        context: EnforcementContext,
        params: dict[str, Any],
    ) -> None:
        """
        Called before or after an action is executed.

        Args:
            action: The action being executed.
            context: The enforcement context.
            params: Action parameters.
        """
        ...


@dataclass
class ExecutionStep:
    """
    A single step in action execution.

    Attributes:
        action: The action that was executed.
        params: Parameters passed to the action.
        result: Result of the action execution.
        rollback_func: Optional function to call for rollback.
    """

    action: Action
    params: dict[str, Any]
    result: ActionResult | None = None
    rollback_func: Callable[[], None] | None = None


@dataclass
class ExecutionPlan:
    """
    Plan for executing one or more actions.

    Attributes:
        steps: List of execution steps.
        executed: Number of steps executed.
        success: Whether all steps succeeded.
    """

    steps: list[ExecutionStep] = field(default_factory=list)
    executed: int = 0
    success: bool = True

    def add_step(
        self,
        action: Action,
        params: dict[str, Any],
        rollback_func: Callable[[], None] | None = None,
    ) -> None:
        """Add a step to the execution plan."""
        self.steps.append(ExecutionStep(
            action=action,
            params=params,
            rollback_func=rollback_func,
        ))


class ActionExecutor:
    """
    Executes policy actions with support for chaining and rollback.

    The ActionExecutor is responsible for:
    - Executing the action specified by matched policies
    - Handling action chaining (multiple actions in sequence)
    - Implementing rollback if an action fails
    - Providing hooks for custom action implementations
    - Supporting async actions

    Example:
        Executing actions::

            executor = ActionExecutor(registry)
            result = executor.execute(rule, context)

            if result.success:
                print(f"Action {result.action} succeeded")
    """

    def __init__(
        self,
        registry: ActionRegistry | None = None,
        fail_fast: bool = True,
        enable_rollback: bool = True,
    ) -> None:
        """
        Initialize the action executor.

        Args:
            registry: Action registry to use. Defaults to the global registry.
            fail_fast: Whether to stop on first failure.
            enable_rollback: Whether to rollback on failure.
        """
        from policybind.engine.actions import get_default_registry

        self._registry = registry or get_default_registry()
        self._fail_fast = fail_fast
        self._enable_rollback = enable_rollback
        self._pre_hooks: list[ActionHook] = []
        self._post_hooks: list[ActionHook] = []
        self._custom_handlers: dict[Action, Callable[..., ActionResult]] = {}

    def execute(
        self,
        rule: PolicyRule,
        context: EnforcementContext,
    ) -> StageResult:
        """
        Execute the action for a matched rule.

        Args:
            rule: The matched PolicyRule containing the action to execute.
            context: The enforcement context.

        Returns:
            StageResult with the execution outcome.
        """
        start = time.perf_counter()

        try:
            action = self._registry.get_action(rule.action)
        except Exception as e:
            return StageResult(
                stage=PipelineStage.ACTION_EXECUTION,
                success=False,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Invalid action: {e}",
            )

        params = rule.action_params

        # Run pre-hooks
        for hook in self._pre_hooks:
            try:
                hook(action, context, params)
            except Exception as e:
                context.add_warning(f"Pre-hook failed: {e}")

        # Execute the action
        try:
            result = self._execute_action(action, context, params)
        except Exception as e:
            return StageResult(
                stage=PipelineStage.ACTION_EXECUTION,
                success=False,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Action execution failed: {e}",
            )

        # Run post-hooks
        for hook in self._post_hooks:
            try:
                hook(action, context, params)
            except Exception as e:
                context.add_warning(f"Post-hook failed: {e}")

        # Map action result to decision
        decision = self._action_to_decision(result)

        return StageResult(
            stage=PipelineStage.ACTION_EXECUTION,
            success=True,
            duration_ms=(time.perf_counter() - start) * 1000,
            decision=decision,
            modifications=result.modifications,
            metadata={
                "action": action.value,
                "allowed": result.allowed,
                "reason": result.reason,
            },
        )

    def execute_chain(
        self,
        rules: list[PolicyRule],
        context: EnforcementContext,
    ) -> StageResult:
        """
        Execute a chain of actions from multiple rules.

        Actions are executed in order. If any action fails and
        fail_fast is enabled, remaining actions are skipped and
        rollback is performed if enabled.

        Args:
            rules: List of rules to execute in order.
            context: The enforcement context.

        Returns:
            StageResult with the combined outcome.
        """
        start = time.perf_counter()

        plan = ExecutionPlan()
        all_modifications: dict[str, Any] = {}
        final_decision: Decision | None = None

        for rule in rules:
            try:
                action = self._registry.get_action(rule.action)
            except Exception as e:
                if self._fail_fast:
                    self._rollback(plan)
                    return StageResult(
                        stage=PipelineStage.ACTION_EXECUTION,
                        success=False,
                        duration_ms=(time.perf_counter() - start) * 1000,
                        error=f"Invalid action in chain: {e}",
                    )
                context.add_warning(f"Skipping invalid action: {e}")
                continue

            plan.add_step(action, rule.action_params)

            try:
                result = self._execute_action(action, context, rule.action_params)
                plan.steps[-1].result = result
                plan.executed += 1

                all_modifications.update(result.modifications)
                final_decision = self._action_to_decision(result)

                if not result.allowed and self._fail_fast:
                    break

            except Exception as e:
                plan.success = False
                if self._fail_fast:
                    self._rollback(plan)
                    return StageResult(
                        stage=PipelineStage.ACTION_EXECUTION,
                        success=False,
                        duration_ms=(time.perf_counter() - start) * 1000,
                        error=f"Action chain failed: {e}",
                    )
                context.add_warning(f"Action failed, continuing: {e}")

        return StageResult(
            stage=PipelineStage.ACTION_EXECUTION,
            success=plan.success,
            duration_ms=(time.perf_counter() - start) * 1000,
            decision=final_decision,
            modifications=all_modifications,
            metadata={"steps_executed": plan.executed},
        )

    def register_handler(
        self,
        action: Action,
        handler: Callable[..., ActionResult],
    ) -> None:
        """
        Register a custom handler for an action.

        Args:
            action: The action to handle.
            handler: The handler function.
        """
        self._custom_handlers[action] = handler

    def add_pre_hook(self, hook: ActionHook) -> None:
        """
        Add a hook to run before action execution.

        Args:
            hook: The hook function.
        """
        self._pre_hooks.append(hook)

    def add_post_hook(self, hook: ActionHook) -> None:
        """
        Add a hook to run after action execution.

        Args:
            hook: The hook function.
        """
        self._post_hooks.append(hook)

    def _execute_action(
        self,
        action: Action,
        context: EnforcementContext,
        params: dict[str, Any],
    ) -> ActionResult:
        """Execute a single action."""
        # Check for custom handler first
        if action in self._custom_handlers:
            return self._custom_handlers[action](context, params)

        # Create a simple action context from enforcement context
        action_context = SimpleActionContext(context)
        return self._registry.execute(action, action_context, params)

    def _action_to_decision(self, result: ActionResult) -> Decision:
        """Map an action result to a decision."""
        if not result.allowed:
            if result.action == Action.REQUIRE_APPROVAL:
                return Decision.REQUIRE_APPROVAL
            return Decision.DENY

        if result.modified:
            return Decision.MODIFY

        return Decision.ALLOW

    def _rollback(self, plan: ExecutionPlan) -> None:
        """Rollback executed steps in reverse order."""
        if not self._enable_rollback:
            return

        for step in reversed(plan.steps[:plan.executed]):
            if step.rollback_func:
                try:
                    step.rollback_func()
                except Exception:
                    pass  # Best effort rollback


@dataclass
class SimpleActionContext:
    """
    Simple implementation of ActionContext protocol.

    Wraps an EnforcementContext to provide the ActionContext interface.
    """

    _context: EnforcementContext

    @property
    def request_id(self) -> str:
        """Get the request ID."""
        if self._context.request:
            return self._context.request.request_id
        return ""

    @property
    def provider(self) -> str:
        """Get the provider."""
        if self._context.request:
            return self._context.request.provider
        return ""

    @property
    def model(self) -> str:
        """Get the model."""
        if self._context.request:
            return self._context.request.model
        return ""

    @property
    def user_id(self) -> str:
        """Get the user ID."""
        if self._context.request:
            return self._context.request.user_id
        return ""

    @property
    def department(self) -> str:
        """Get the department."""
        if self._context.request:
            return self._context.request.department
        return ""

    @property
    def metadata(self) -> dict[str, Any]:
        """Get the metadata."""
        if self._context.request:
            return self._context.request.metadata
        return {}


class AsyncActionExecutor:
    """
    Async version of ActionExecutor for I/O-bound actions.

    This executor supports async action handlers and can be used
    when actions need to perform network calls or other I/O operations.
    """

    def __init__(
        self,
        registry: ActionRegistry | None = None,
    ) -> None:
        """
        Initialize the async action executor.

        Args:
            registry: Action registry to use.
        """
        from policybind.engine.actions import get_default_registry

        self._registry = registry or get_default_registry()
        self._sync_executor = ActionExecutor(registry)

    async def execute_async(
        self,
        rule: PolicyRule,
        context: EnforcementContext,
    ) -> StageResult:
        """
        Execute an action asynchronously.

        Currently delegates to the sync executor but can be extended
        to support truly async action handlers.

        Args:
            rule: The matched PolicyRule.
            context: The enforcement context.

        Returns:
            StageResult with the execution outcome.
        """
        # For now, delegate to sync executor
        # In a real async implementation, we would have async handlers
        return self._sync_executor.execute(rule, context)
