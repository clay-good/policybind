"""
Enforcement context for PolicyBind.

This module provides the EnforcementContext class that carries request data
through the enforcement pipeline, accumulating decisions and modifications.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, utc_now
from policybind.models.policy import PolicyMatch, PolicyRule
from policybind.models.request import AIRequest, Decision


class PipelineStage(Enum):
    """Stages in the enforcement pipeline."""

    VALIDATION = "validation"
    CLASSIFICATION = "classification"
    MATCHING = "matching"
    ACTION_EXECUTION = "action_execution"
    LOGGING = "logging"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class StageResult:
    """
    Result of processing a single pipeline stage.

    Attributes:
        stage: The pipeline stage that was executed.
        success: Whether the stage completed successfully.
        duration_ms: Time taken to execute the stage in milliseconds.
        decision: Optional decision made by this stage.
        modifications: Any modifications made to the request.
        error: Error message if the stage failed.
        metadata: Additional stage-specific metadata.
    """

    stage: PipelineStage
    success: bool
    duration_ms: float = 0.0
    decision: Decision | None = None
    modifications: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnforcementContext:
    """
    Context that carries request data through the enforcement pipeline.

    The EnforcementContext accumulates decisions and modifications from
    each stage of the pipeline. It tracks timing information and can be
    serialized for logging and replay.

    Attributes:
        id: Unique identifier for this enforcement context.
        request: The original AIRequest being processed.
        created_at: When the context was created.
        current_stage: The current pipeline stage.
        final_decision: The final enforcement decision.
        matched_rules: Rules that matched during matching stage.
        applied_rule: The rule that was actually applied.
        modifications: Accumulated modifications to the request.
        stage_results: Results from each completed stage.
        warnings: Warning messages accumulated during processing.
        metadata: Additional context metadata.
        start_time: When processing started.
        end_time: When processing completed.
    """

    id: str = field(default_factory=generate_uuid)
    request: AIRequest | None = None
    created_at: datetime = field(default_factory=utc_now)
    current_stage: PipelineStage = PipelineStage.VALIDATION
    final_decision: Decision = Decision.DENY
    matched_rules: list[PolicyRule] = field(default_factory=list)
    applied_rule: PolicyRule | None = None
    modifications: dict[str, Any] = field(default_factory=dict)
    stage_results: list[StageResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    start_time: datetime | None = None
    end_time: datetime | None = None
    _short_circuited: bool = False
    _short_circuit_reason: str = ""

    def start(self) -> None:
        """Mark the start of processing."""
        self.start_time = utc_now()

    def complete(self) -> None:
        """Mark processing as complete."""
        self.end_time = utc_now()
        self.current_stage = PipelineStage.COMPLETE

    def fail(self, error: str) -> None:
        """Mark processing as failed."""
        self.end_time = utc_now()
        self.current_stage = PipelineStage.FAILED
        self.add_warning(f"Pipeline failed: {error}")

    def short_circuit(self, decision: Decision, reason: str) -> None:
        """
        Short-circuit the pipeline with a final decision.

        This stops further pipeline processing and sets the final decision.

        Args:
            decision: The final decision to apply.
            reason: Reason for short-circuiting.
        """
        self._short_circuited = True
        self._short_circuit_reason = reason
        self.final_decision = decision

    @property
    def is_short_circuited(self) -> bool:
        """Check if the pipeline has been short-circuited."""
        return self._short_circuited

    @property
    def short_circuit_reason(self) -> str:
        """Get the reason for short-circuiting."""
        return self._short_circuit_reason

    def add_stage_result(self, result: StageResult) -> None:
        """
        Add a stage result to the context.

        Args:
            result: The stage result to add.
        """
        self.stage_results.append(result)
        if result.decision is not None:
            self.final_decision = result.decision
        if result.modifications:
            self.modifications.update(result.modifications)

    def add_modification(self, key: str, value: Any) -> None:
        """
        Add a modification to the context.

        Args:
            key: The modification key.
            value: The modification value.
        """
        self.modifications[key] = value

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message.

        Args:
            warning: The warning message.
        """
        self.warnings.append(warning)

    def set_match_result(self, match: PolicyMatch) -> None:
        """
        Set the match result from the matching stage.

        Args:
            match: The policy match result.
        """
        if match.matched:
            self.matched_rules = list(match.all_matches)
            self.applied_rule = match.rule

    def get_total_duration_ms(self) -> float:
        """
        Get the total processing duration in milliseconds.

        Returns:
            Total duration, or 0 if not yet completed.
        """
        if self.start_time is None:
            return 0.0
        end = self.end_time or utc_now()
        return (end - self.start_time).total_seconds() * 1000

    def get_stage_duration_ms(self, stage: PipelineStage) -> float:
        """
        Get the duration of a specific stage.

        Args:
            stage: The stage to get duration for.

        Returns:
            Duration in milliseconds, or 0 if stage not found.
        """
        for result in self.stage_results:
            if result.stage == stage:
                return result.duration_ms
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the context to a dictionary for serialization.

        Returns:
            Dictionary representation of the context.
        """
        return {
            "id": self.id,
            "request_id": self.request.request_id if self.request else None,
            "created_at": self.created_at.isoformat(),
            "current_stage": self.current_stage.value,
            "final_decision": self.final_decision.value,
            "applied_rule": self.applied_rule.name if self.applied_rule else None,
            "matched_rules": [r.name for r in self.matched_rules],
            "modifications": self.modifications,
            "warnings": self.warnings,
            "total_duration_ms": self.get_total_duration_ms(),
            "stage_durations": {
                r.stage.value: r.duration_ms for r in self.stage_results
            },
            "metadata": self.metadata,
        }

    def get_applied_rule_names(self) -> tuple[str, ...]:
        """
        Get the names of all rules that were applied.

        Returns:
            Tuple of rule names.
        """
        if self.applied_rule:
            return (self.applied_rule.name,)
        return tuple()

    def get_reason(self) -> str:
        """
        Get a human-readable reason for the decision.

        Returns:
            Reason string.
        """
        if self._short_circuited:
            return self._short_circuit_reason

        if self.applied_rule:
            action_params = self.applied_rule.action_params
            if "reason" in action_params:
                return str(action_params["reason"])
            return f"Rule '{self.applied_rule.name}' applied action {self.applied_rule.action}"

        if self.final_decision == Decision.DENY:
            return "Request denied by default policy"

        return f"Decision: {self.final_decision.value}"


@dataclass
class EnforcementResult:
    """
    Final result of enforcement processing.

    This is a simplified view of the enforcement context suitable
    for returning to callers.

    Attributes:
        request_id: The ID of the request that was processed.
        decision: The final enforcement decision.
        applied_rules: Names of rules that were applied.
        modifications: Any modifications made to the request.
        reason: Human-readable reason for the decision.
        duration_ms: Total processing time in milliseconds.
        warnings: Any warnings generated during processing.
    """

    request_id: str
    decision: Decision
    applied_rules: tuple[str, ...] = field(default_factory=tuple)
    modifications: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    duration_ms: float = 0.0
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_context(cls, context: EnforcementContext) -> "EnforcementResult":
        """
        Create an EnforcementResult from an EnforcementContext.

        Args:
            context: The enforcement context to convert.

        Returns:
            An EnforcementResult with the relevant data.
        """
        return cls(
            request_id=context.request.request_id if context.request else "",
            decision=context.final_decision,
            applied_rules=context.get_applied_rule_names(),
            modifications=context.modifications.copy(),
            reason=context.get_reason(),
            duration_ms=context.get_total_duration_ms(),
            warnings=tuple(context.warnings),
        )

    def is_allowed(self) -> bool:
        """Check if the request is allowed."""
        return self.decision in (Decision.ALLOW, Decision.MODIFY)

    def is_denied(self) -> bool:
        """Check if the request is denied."""
        return self.decision == Decision.DENY

    def requires_approval(self) -> bool:
        """Check if the request requires approval."""
        return self.decision == Decision.REQUIRE_APPROVAL
