"""
Enforcement pipeline for PolicyBind.

This module provides the EnforcementPipeline class that orchestrates
the full request lifecycle through validation, matching, action
execution, and logging.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import time

from policybind.engine.context import (
    EnforcementContext,
    EnforcementResult,
    PipelineStage,
    StageResult,
)
from policybind.engine.executor import ActionExecutor
from policybind.engine.matcher import PolicyMatcher
from policybind.engine.middleware import (
    AuditLogger,
    ClassificationEnforcer,
    CostTracker,
    Middleware,
    RateLimiter,
    RequestValidator,
)
from policybind.models.policy import PolicySet
from policybind.models.request import AIRequest, AIResponse, Decision


class FailureMode(Enum):
    """How to handle enforcement failures."""

    FAIL_CLOSED = "fail_closed"
    """Deny requests when enforcement fails."""

    FAIL_OPEN = "fail_open"
    """Allow requests when enforcement fails."""


@dataclass
class PipelineConfig:
    """
    Configuration for the enforcement pipeline.

    Attributes:
        failure_mode: How to handle enforcement failures.
        enable_timing: Whether to collect timing information.
        enable_audit: Whether to enable audit logging.
        require_classification: Whether data classification is required.
        rate_limit_enabled: Whether to enable rate limiting.
        requests_per_minute: Rate limit requests per minute.
        cost_tracking_enabled: Whether to enable cost tracking.
        default_budget: Default budget per user/department.
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED
    enable_timing: bool = True
    enable_audit: bool = True
    require_classification: bool = False
    rate_limit_enabled: bool = False
    requests_per_minute: float = 60.0
    cost_tracking_enabled: bool = False
    default_budget: float | None = None


class EnforcementPipeline:
    """
    Orchestrates the full request enforcement lifecycle.

    The pipeline processes requests through multiple stages:
    1. Validation - Ensure request has required fields
    2. Classification - Enforce data classification requirements
    3. Matching - Find matching policy rules
    4. Action Execution - Execute the matched action
    5. Logging - Audit log the result

    Each stage can modify the request, make a decision, or
    short-circuit the pipeline.

    Example:
        Processing a request::

            pipeline = EnforcementPipeline(policy_set)
            response = pipeline.process(request)

            if response.is_allowed():
                print("Request allowed")
            else:
                print(f"Request denied: {response.reason}")
    """

    def __init__(
        self,
        policy_set: PolicySet,
        config: PipelineConfig | None = None,
        matcher: PolicyMatcher | None = None,
        executor: ActionExecutor | None = None,
    ) -> None:
        """
        Initialize the enforcement pipeline.

        Args:
            policy_set: The PolicySet to enforce.
            config: Pipeline configuration.
            matcher: Custom policy matcher.
            executor: Custom action executor.
        """
        self._policy_set = policy_set
        self._config = config or PipelineConfig()
        self._matcher = matcher or PolicyMatcher()
        self._executor = executor or ActionExecutor()

        # Initialize middleware
        self._middleware: list[Middleware] = []
        self._setup_middleware()

        # Precompile policies for fast matching
        self._matcher.precompile(policy_set)

    def _setup_middleware(self) -> None:
        """Set up the default middleware chain."""
        # Request validation
        self._middleware.append(RequestValidator())

        # Classification enforcement
        self._middleware.append(ClassificationEnforcer(
            require_classification=self._config.require_classification,
        ))

        # Rate limiting
        if self._config.rate_limit_enabled:
            self._middleware.append(RateLimiter(
                requests_per_minute=self._config.requests_per_minute,
            ))

        # Cost tracking
        if self._config.cost_tracking_enabled:
            self._middleware.append(CostTracker(
                default_budget=self._config.default_budget,
            ))

        # Audit logging (runs last)
        if self._config.enable_audit:
            self._middleware.append(AuditLogger())

    def process(self, request: AIRequest) -> AIResponse:
        """
        Process a request through the enforcement pipeline.

        Args:
            request: The AIRequest to process.

        Returns:
            AIResponse with the enforcement decision.
        """
        # Create enforcement context
        context = EnforcementContext(request=request)
        context.start()

        try:
            # Run through pipeline stages
            self._run_validation_stage(context)

            if not context.is_short_circuited:
                self._run_classification_stage(context)

            if not context.is_short_circuited:
                self._run_matching_stage(context)

            if not context.is_short_circuited:
                self._run_action_stage(context)

            # Always run logging stage
            self._run_logging_stage(context)

            context.complete()

        except Exception as e:
            context.fail(str(e))
            self._handle_failure(context, e)

        return self._create_response(context)

    def process_with_context(self, request: AIRequest) -> tuple[AIResponse, EnforcementContext]:
        """
        Process a request and return both response and context.

        This is useful when you need access to detailed enforcement
        information beyond what's in the response.

        Args:
            request: The AIRequest to process.

        Returns:
            Tuple of (AIResponse, EnforcementContext).
        """
        context = EnforcementContext(request=request)
        context.start()

        try:
            self._run_validation_stage(context)

            if not context.is_short_circuited:
                self._run_classification_stage(context)

            if not context.is_short_circuited:
                self._run_matching_stage(context)

            if not context.is_short_circuited:
                self._run_action_stage(context)

            self._run_logging_stage(context)
            context.complete()

        except Exception as e:
            context.fail(str(e))
            self._handle_failure(context, e)

        return self._create_response(context), context

    def _run_validation_stage(self, context: EnforcementContext) -> None:
        """Run validation middleware."""
        context.current_stage = PipelineStage.VALIDATION

        for middleware in self._middleware:
            if middleware.stage == PipelineStage.VALIDATION:
                result = middleware.process(context)
                context.add_stage_result(result)

                if not result.success:
                    context.short_circuit(
                        Decision.DENY,
                        result.error or "Validation failed",
                    )
                    return

                if context.is_short_circuited:
                    return

    def _run_classification_stage(self, context: EnforcementContext) -> None:
        """Run classification middleware."""
        context.current_stage = PipelineStage.CLASSIFICATION

        for middleware in self._middleware:
            if middleware.stage == PipelineStage.CLASSIFICATION:
                result = middleware.process(context)
                context.add_stage_result(result)

                if not result.success:
                    context.short_circuit(
                        Decision.DENY,
                        result.error or "Classification failed",
                    )
                    return

                if context.is_short_circuited:
                    return

    def _run_matching_stage(self, context: EnforcementContext) -> None:
        """Run policy matching."""
        context.current_stage = PipelineStage.MATCHING
        start = time.perf_counter()

        if context.request is None:
            context.short_circuit(Decision.DENY, "No request to match")
            return

        try:
            match_result = self._matcher.match(self._policy_set, context.request)
            context.set_match_result(match_result)

            result = StageResult(
                stage=PipelineStage.MATCHING,
                success=True,
                duration_ms=(time.perf_counter() - start) * 1000,
                metadata={
                    "matched": match_result.matched,
                    "matched_rule": match_result.rule.name if match_result.rule else None,
                    "match_score": match_result.match_score,
                },
            )
            context.add_stage_result(result)

            if not match_result.matched:
                # No rule matched - apply default action
                context.short_circuit(Decision.DENY, "No matching policy rule")

        except Exception as e:
            result = StageResult(
                stage=PipelineStage.MATCHING,
                success=False,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
            )
            context.add_stage_result(result)
            raise

    def _run_action_stage(self, context: EnforcementContext) -> None:
        """Run action execution."""
        context.current_stage = PipelineStage.ACTION_EXECUTION

        if context.applied_rule is None:
            context.short_circuit(Decision.DENY, "No rule to execute")
            return

        result = self._executor.execute(context.applied_rule, context)
        context.add_stage_result(result)

        if not result.success:
            context.short_circuit(
                Decision.DENY,
                result.error or "Action execution failed",
            )

    def _run_logging_stage(self, context: EnforcementContext) -> None:
        """Run logging middleware."""
        context.current_stage = PipelineStage.LOGGING

        for middleware in self._middleware:
            if middleware.stage == PipelineStage.LOGGING:
                result = middleware.process(context)
                context.add_stage_result(result)

    def _handle_failure(self, context: EnforcementContext, error: Exception) -> None:
        """Handle a pipeline failure."""
        if self._config.failure_mode == FailureMode.FAIL_OPEN:
            context.final_decision = Decision.ALLOW
            context.add_warning(f"Enforcement failed, allowing due to fail-open: {error}")
        else:
            context.final_decision = Decision.DENY
            context.add_warning(f"Enforcement failed, denying due to fail-closed: {error}")

    def _create_response(self, context: EnforcementContext) -> AIResponse:
        """Create an AIResponse from the enforcement context."""
        return AIResponse(
            request_id=context.request.request_id if context.request else "",
            decision=context.final_decision,
            applied_rules=context.get_applied_rule_names(),
            modifications=context.modifications,
            enforcement_time_ms=context.get_total_duration_ms(),
            reason=context.get_reason(),
            warnings=tuple(context.warnings),
            metadata=context.metadata,
        )

    def add_middleware(self, middleware: Middleware) -> None:
        """
        Add custom middleware to the pipeline.

        Middleware is inserted before the audit logger.

        Args:
            middleware: The middleware to add.
        """
        # Find the position before audit logger
        insert_pos = len(self._middleware)
        for i, mw in enumerate(self._middleware):
            if isinstance(mw, AuditLogger):
                insert_pos = i
                break

        self._middleware.insert(insert_pos, middleware)

    def get_middleware(self) -> list[Middleware]:
        """
        Get the list of middleware.

        Returns:
            List of middleware in execution order.
        """
        return self._middleware.copy()

    def reload_policies(self, policy_set: PolicySet) -> None:
        """
        Reload the pipeline with a new policy set.

        Args:
            policy_set: The new PolicySet to use.
        """
        self._policy_set = policy_set
        self._matcher.clear_cache()
        self._matcher.precompile(policy_set)

    def get_policy_set(self) -> PolicySet:
        """
        Get the current policy set.

        Returns:
            The current PolicySet.
        """
        return self._policy_set

    def get_result(self, context: EnforcementContext) -> EnforcementResult:
        """
        Get an EnforcementResult from a context.

        Args:
            context: The enforcement context.

        Returns:
            EnforcementResult with summary data.
        """
        return EnforcementResult.from_context(context)


class AsyncEnforcementPipeline:
    """
    Async version of the enforcement pipeline.

    This pipeline supports async middleware and action handlers
    for I/O-bound operations.
    """

    def __init__(
        self,
        policy_set: PolicySet,
        config: PipelineConfig | None = None,
    ) -> None:
        """
        Initialize the async enforcement pipeline.

        Args:
            policy_set: The PolicySet to enforce.
            config: Pipeline configuration.
        """
        # Delegate to sync pipeline for now
        self._sync_pipeline = EnforcementPipeline(policy_set, config)

    async def process_async(self, request: AIRequest) -> AIResponse:
        """
        Process a request asynchronously.

        Args:
            request: The AIRequest to process.

        Returns:
            AIResponse with the enforcement decision.
        """
        # For now, delegate to sync pipeline
        # In a real async implementation, we would have async middleware
        return self._sync_pipeline.process(request)

    def reload_policies(self, policy_set: PolicySet) -> None:
        """Reload policies."""
        self._sync_pipeline.reload_policies(policy_set)
