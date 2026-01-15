"""
Simulation data models for PolicyBind.

This module defines the data structures used for policy simulation,
dry-run mode, and what-if analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import generate_uuid, model_to_dict, model_to_json, utc_now
from policybind.models.policy import PolicyRule
from policybind.models.request import AIRequest, Decision


class SimulationMode(Enum):
    """
    Mode of simulation execution.

    Controls how the simulation behaves and what side effects
    (if any) are recorded.
    """

    DRY_RUN = "dry_run"
    """Execute without any side effects - no logging, no metrics."""

    SHADOW = "shadow"
    """Execute in shadow mode - log results but don't enforce."""

    COMPARE = "compare"
    """Compare against another policy set."""

    WHAT_IF = "what_if"
    """Analyze what would happen with policy changes."""


@dataclass
class SimulationOptions:
    """
    Options for controlling simulation behavior.

    Attributes:
        mode: The simulation mode to use.
        include_all_matches: Include all matching rules, not just the best.
        include_timing: Include timing information in results.
        include_conditions: Include detailed condition evaluation.
        include_trace: Include full evaluation trace.
        max_rules: Maximum number of rules to include in results.
        current_time: Override the current time for time-based conditions.
        context_overrides: Override context values for simulation.
    """

    mode: SimulationMode = SimulationMode.DRY_RUN
    include_all_matches: bool = True
    include_timing: bool = True
    include_conditions: bool = True
    include_trace: bool = False
    max_rules: int = 100
    current_time: datetime | None = None
    context_overrides: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mode": self.mode.value,
            "include_all_matches": self.include_all_matches,
            "include_timing": self.include_timing,
            "include_conditions": self.include_conditions,
            "include_trace": self.include_trace,
            "max_rules": self.max_rules,
            "current_time": self.current_time.isoformat() if self.current_time else None,
            "context_overrides": self.context_overrides,
        }


@dataclass
class RuleEvaluation:
    """
    Result of evaluating a single rule.

    Attributes:
        rule_name: Name of the rule.
        rule_id: Unique ID of the rule.
        matched: Whether the rule matched.
        priority: Priority of the rule.
        action: Action that would be taken if matched.
        match_score: Score of the match (0-1).
        matched_conditions: Conditions that matched.
        failed_conditions: Conditions that failed to match.
        evaluation_time_ms: Time taken to evaluate the rule.
    """

    rule_name: str = ""
    rule_id: str = ""
    matched: bool = False
    priority: int = 0
    action: str = ""
    match_score: float = 0.0
    matched_conditions: dict[str, Any] = field(default_factory=dict)
    failed_conditions: dict[str, Any] = field(default_factory=dict)
    evaluation_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "matched": self.matched,
            "priority": self.priority,
            "action": self.action,
            "match_score": self.match_score,
            "matched_conditions": self.matched_conditions,
            "failed_conditions": self.failed_conditions,
            "evaluation_time_ms": self.evaluation_time_ms,
        }


@dataclass
class EvaluationTrace:
    """
    Detailed trace of the evaluation process.

    Provides step-by-step visibility into how a request was
    evaluated against policies.

    Attributes:
        steps: List of evaluation steps.
        total_rules_evaluated: Total number of rules evaluated.
        rules_skipped: Number of rules skipped (disabled, etc.).
        short_circuit_at: Rule that caused short-circuit (if any).
    """

    steps: list[dict[str, Any]] = field(default_factory=list)
    total_rules_evaluated: int = 0
    rules_skipped: int = 0
    short_circuit_at: str | None = None

    def add_step(
        self,
        step_type: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Add a step to the trace."""
        self.steps.append({
            "type": step_type,
            "description": description,
            "details": details or {},
            "timestamp": utc_now().isoformat(),
        })

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "steps": self.steps,
            "total_rules_evaluated": self.total_rules_evaluated,
            "rules_skipped": self.rules_skipped,
            "short_circuit_at": self.short_circuit_at,
        }


@dataclass
class SimulationResult:
    """
    Result of simulating a single request.

    Contains the simulated enforcement decision along with
    detailed information about how the decision was reached.

    Attributes:
        id: Unique identifier for this simulation.
        request_id: ID of the simulated request.
        simulated_at: When the simulation was performed.
        mode: Simulation mode used.
        decision: The simulated enforcement decision.
        reason: Human-readable reason for the decision.
        applied_rule: The rule that would be applied (if any).
        all_matched_rules: All rules that matched the request.
        rule_evaluations: Detailed evaluation of each rule.
        modifications: Modifications that would be applied.
        trace: Full evaluation trace (if enabled).
        total_time_ms: Total simulation time in milliseconds.
        warnings: Any warnings generated during simulation.
        metadata: Additional simulation metadata.
    """

    id: str = field(default_factory=generate_uuid)
    request_id: str = ""
    simulated_at: datetime = field(default_factory=utc_now)
    mode: SimulationMode = SimulationMode.DRY_RUN
    decision: Decision = Decision.DENY
    reason: str = ""
    applied_rule: str | None = None
    all_matched_rules: list[str] = field(default_factory=list)
    rule_evaluations: list[RuleEvaluation] = field(default_factory=list)
    modifications: dict[str, Any] = field(default_factory=dict)
    trace: EvaluationTrace | None = None
    total_time_ms: float = 0.0
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = False) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "request_id": self.request_id,
            "simulated_at": self.simulated_at.isoformat(),
            "mode": self.mode.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "applied_rule": self.applied_rule,
            "all_matched_rules": self.all_matched_rules,
            "rule_evaluations": [r.to_dict() for r in self.rule_evaluations],
            "modifications": self.modifications,
            "trace": self.trace.to_dict() if self.trace else None,
            "total_time_ms": self.total_time_ms,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }
        if exclude_none:
            result = {k: v for k, v in result.items() if v is not None}
        return result

    def to_json(self, indent: int | None = None, exclude_none: bool = False) -> str:
        """Convert to JSON string."""
        return model_to_json(self, indent, exclude_none)

    def is_allowed(self) -> bool:
        """Check if the simulated decision allows the request."""
        return self.decision in (Decision.ALLOW, Decision.MODIFY)

    def is_denied(self) -> bool:
        """Check if the simulated decision denies the request."""
        return self.decision == Decision.DENY

    def get_matched_rule_count(self) -> int:
        """Get the number of rules that matched."""
        return len(self.all_matched_rules)


@dataclass
class SimulationSummary:
    """
    Summary statistics for a batch simulation.

    Provides aggregate metrics across multiple simulated requests.

    Attributes:
        total_requests: Total number of requests simulated.
        allowed: Number of requests that would be allowed.
        denied: Number of requests that would be denied.
        modified: Number of requests that would be modified.
        require_approval: Number of requests requiring approval.
        avg_time_ms: Average simulation time per request.
        max_time_ms: Maximum simulation time.
        min_time_ms: Minimum simulation time.
        rule_hit_counts: Count of how many times each rule matched.
        decision_breakdown: Breakdown by decision type.
        warnings_count: Total number of warnings generated.
    """

    total_requests: int = 0
    allowed: int = 0
    denied: int = 0
    modified: int = 0
    require_approval: int = 0
    avg_time_ms: float = 0.0
    max_time_ms: float = 0.0
    min_time_ms: float = 0.0
    rule_hit_counts: dict[str, int] = field(default_factory=dict)
    decision_breakdown: dict[str, int] = field(default_factory=dict)
    warnings_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "allowed": self.allowed,
            "denied": self.denied,
            "modified": self.modified,
            "require_approval": self.require_approval,
            "avg_time_ms": self.avg_time_ms,
            "max_time_ms": self.max_time_ms,
            "min_time_ms": self.min_time_ms,
            "rule_hit_counts": self.rule_hit_counts,
            "decision_breakdown": self.decision_breakdown,
            "warnings_count": self.warnings_count,
        }

    def add_result(self, result: SimulationResult) -> None:
        """Add a simulation result to the summary."""
        self.total_requests += 1

        # Count by decision
        if result.decision == Decision.ALLOW:
            self.allowed += 1
        elif result.decision == Decision.DENY:
            self.denied += 1
        elif result.decision == Decision.MODIFY:
            self.modified += 1
        elif result.decision == Decision.REQUIRE_APPROVAL:
            self.require_approval += 1

        # Update decision breakdown
        decision_key = result.decision.value
        self.decision_breakdown[decision_key] = (
            self.decision_breakdown.get(decision_key, 0) + 1
        )

        # Update timing
        if result.total_time_ms > self.max_time_ms:
            self.max_time_ms = result.total_time_ms
        if self.min_time_ms == 0.0 or result.total_time_ms < self.min_time_ms:
            self.min_time_ms = result.total_time_ms

        # Update rule hit counts
        for rule_name in result.all_matched_rules:
            self.rule_hit_counts[rule_name] = (
                self.rule_hit_counts.get(rule_name, 0) + 1
            )

        # Count warnings
        self.warnings_count += len(result.warnings)

    def finalize(self) -> None:
        """Finalize the summary (calculate averages, etc.)."""
        # Currently a no-op placeholder for future enhancements
        # like calculating average processing times across requests
        pass


@dataclass
class BatchSimulationResult:
    """
    Result of simulating multiple requests.

    Contains individual results and aggregate summary statistics.

    Attributes:
        id: Unique identifier for this batch simulation.
        started_at: When the batch simulation started.
        completed_at: When the batch simulation completed.
        mode: Simulation mode used.
        policy_version: Version of the policy set used.
        results: Individual simulation results.
        summary: Aggregate summary statistics.
        options: Options used for the simulation.
        metadata: Additional batch metadata.
    """

    id: str = field(default_factory=generate_uuid)
    started_at: datetime = field(default_factory=utc_now)
    completed_at: datetime | None = None
    mode: SimulationMode = SimulationMode.DRY_RUN
    policy_version: str = ""
    results: list[SimulationResult] = field(default_factory=list)
    summary: SimulationSummary = field(default_factory=SimulationSummary)
    options: SimulationOptions | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_results: bool = True) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "mode": self.mode.value,
            "policy_version": self.policy_version,
            "summary": self.summary.to_dict(),
            "options": self.options.to_dict() if self.options else None,
            "metadata": self.metadata,
        }
        if include_results:
            result["results"] = [r.to_dict() for r in self.results]
        else:
            result["result_count"] = len(self.results)
        return result

    def add_result(self, result: SimulationResult) -> None:
        """Add a result to the batch."""
        self.results.append(result)
        self.summary.add_result(result)

    def complete(self) -> None:
        """Mark the batch as complete."""
        self.completed_at = utc_now()
        self.summary.finalize()

    def get_allowed_rate(self) -> float:
        """Get the percentage of requests that would be allowed."""
        if self.summary.total_requests == 0:
            return 0.0
        return (self.summary.allowed / self.summary.total_requests) * 100

    def get_denied_rate(self) -> float:
        """Get the percentage of requests that would be denied."""
        if self.summary.total_requests == 0:
            return 0.0
        return (self.summary.denied / self.summary.total_requests) * 100

    def get_top_rules(self, limit: int = 10) -> list[tuple[str, int]]:
        """Get the most frequently matched rules."""
        sorted_rules = sorted(
            self.summary.rule_hit_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        return sorted_rules[:limit]
