"""
Metrics collector for PolicyBind.

This module provides a centralized metrics collection system that tracks
enforcement decisions, latency, rule matches, and other operational metrics.
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from policybind.models.base import utc_now


@dataclass
class EnforcementMetric:
    """A single enforcement metric data point."""

    timestamp: datetime
    decision: str
    latency_ms: float
    provider: str
    model: str
    rules_matched: list[str]
    department: str = ""
    user_id: str = ""
    data_classification: tuple[str, ...] = ()


@dataclass
class TimeSeriesPoint:
    """A time series data point."""

    timestamp: datetime
    value: float


@dataclass
class MetricsSummary:
    """Summary of metrics for a time period."""

    period_start: datetime
    period_end: datetime
    total_requests: int = 0
    decisions: dict[str, int] = field(default_factory=dict)
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    requests_by_provider: dict[str, int] = field(default_factory=dict)
    requests_by_model: dict[str, int] = field(default_factory=dict)
    requests_by_department: dict[str, int] = field(default_factory=dict)
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    error_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "total_requests": self.total_requests,
            "decisions": self.decisions,
            "latency": {
                "avg_ms": round(self.avg_latency_ms, 2),
                "p50_ms": round(self.p50_latency_ms, 2),
                "p95_ms": round(self.p95_latency_ms, 2),
                "p99_ms": round(self.p99_latency_ms, 2),
                "max_ms": round(self.max_latency_ms, 2),
                "min_ms": round(self.min_latency_ms, 2),
            },
            "requests_by_provider": self.requests_by_provider,
            "requests_by_model": self.requests_by_model,
            "requests_by_department": self.requests_by_department,
            "top_rules": [{"rule": r, "count": c} for r, c in self.top_rules],
            "error_count": self.error_count,
        }


class MetricsCollector:
    """
    Centralized metrics collector for PolicyBind.

    Collects and aggregates real-time metrics for:
    - Enforcement decisions (ALLOW, DENY, etc.)
    - Request latency with percentiles
    - Rule match frequency
    - Provider/model usage
    - Department/user activity
    - Time series data for trends

    Thread-safe for concurrent access.
    """

    # Time window for keeping detailed metrics (default: 1 hour)
    DEFAULT_WINDOW_SECONDS = 3600

    # Maximum number of data points to keep
    MAX_DATA_POINTS = 10000

    # Bucket size for time series aggregation
    BUCKET_SECONDS = 60

    def __init__(
        self,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        max_data_points: int = MAX_DATA_POINTS,
    ) -> None:
        """
        Initialize the metrics collector.

        Args:
            window_seconds: Time window for keeping detailed metrics.
            max_data_points: Maximum number of data points to retain.
        """
        self._window_seconds = window_seconds
        self._max_data_points = max_data_points
        self._lock = threading.RLock()

        # Raw enforcement metrics (circular buffer)
        self._enforcement_metrics: deque[EnforcementMetric] = deque(
            maxlen=max_data_points
        )

        # Aggregated counters (persistent)
        self._total_requests = 0
        self._total_by_decision: dict[str, int] = {}
        self._total_by_provider: dict[str, int] = {}
        self._total_by_model: dict[str, int] = {}
        self._total_by_department: dict[str, int] = {}
        self._total_by_rule: dict[str, int] = {}
        self._error_count = 0

        # Latency tracking
        self._latency_sum_ms = 0.0
        self._latency_count = 0

        # Time series buckets for trend analysis
        self._time_series_requests: dict[int, int] = {}
        self._time_series_latency: dict[int, list[float]] = {}
        self._time_series_decisions: dict[int, dict[str, int]] = {}

        # Start time for uptime tracking
        self._start_time = time.time()

    def record_enforcement(
        self,
        decision: str,
        latency_ms: float,
        provider: str,
        model: str,
        rules_matched: list[str] | None = None,
        department: str = "",
        user_id: str = "",
        data_classification: tuple[str, ...] | None = None,
    ) -> None:
        """
        Record an enforcement decision.

        Args:
            decision: The enforcement decision (ALLOW, DENY, etc.).
            latency_ms: Request processing time in milliseconds.
            provider: AI provider name.
            model: Model name.
            rules_matched: List of rule names that matched.
            department: Department identifier.
            user_id: User identifier.
            data_classification: Data classification categories.
        """
        now = utc_now()
        rules = rules_matched or []
        classifications = data_classification or ()

        metric = EnforcementMetric(
            timestamp=now,
            decision=decision,
            latency_ms=latency_ms,
            provider=provider,
            model=model,
            rules_matched=rules,
            department=department,
            user_id=user_id,
            data_classification=classifications,
        )

        with self._lock:
            # Add to detailed metrics
            self._enforcement_metrics.append(metric)

            # Update aggregated counters
            self._total_requests += 1
            self._total_by_decision[decision] = (
                self._total_by_decision.get(decision, 0) + 1
            )
            self._total_by_provider[provider] = (
                self._total_by_provider.get(provider, 0) + 1
            )
            self._total_by_model[model] = self._total_by_model.get(model, 0) + 1
            if department:
                self._total_by_department[department] = (
                    self._total_by_department.get(department, 0) + 1
                )
            for rule in rules:
                self._total_by_rule[rule] = self._total_by_rule.get(rule, 0) + 1

            # Track latency
            self._latency_sum_ms += latency_ms
            self._latency_count += 1

            # Update time series
            bucket = self._get_time_bucket(now)
            self._time_series_requests[bucket] = (
                self._time_series_requests.get(bucket, 0) + 1
            )
            if bucket not in self._time_series_latency:
                self._time_series_latency[bucket] = []
            self._time_series_latency[bucket].append(latency_ms)
            if bucket not in self._time_series_decisions:
                self._time_series_decisions[bucket] = {}
            self._time_series_decisions[bucket][decision] = (
                self._time_series_decisions[bucket].get(decision, 0) + 1
            )

            # Prune old time series data
            self._prune_time_series()

    def record_error(self) -> None:
        """Record an error occurrence."""
        with self._lock:
            self._error_count += 1

    def _get_time_bucket(self, dt: datetime) -> int:
        """Get the time bucket key for a datetime."""
        timestamp = int(dt.timestamp())
        return timestamp - (timestamp % self.BUCKET_SECONDS)

    def _prune_time_series(self) -> None:
        """Remove old time series data outside the window."""
        cutoff = int(time.time()) - self._window_seconds
        cutoff_bucket = cutoff - (cutoff % self.BUCKET_SECONDS)

        # Prune each time series dict
        for ts_dict in [
            self._time_series_requests,
            self._time_series_latency,
            self._time_series_decisions,
        ]:
            keys_to_remove = [k for k in ts_dict if k < cutoff_bucket]
            for k in keys_to_remove:
                del ts_dict[k]

    def get_summary(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> MetricsSummary:
        """
        Get a summary of metrics for a time period.

        Args:
            since: Start of the period (default: window start).
            until: End of the period (default: now).

        Returns:
            MetricsSummary with aggregated data.
        """
        now = utc_now()
        if until is None:
            until = now
        if since is None:
            since = now - timedelta(seconds=self._window_seconds)

        with self._lock:
            # Filter metrics within the time window
            filtered_metrics = [
                m
                for m in self._enforcement_metrics
                if since <= m.timestamp <= until
            ]

            if not filtered_metrics:
                return MetricsSummary(
                    period_start=since,
                    period_end=until,
                )

            # Calculate metrics
            decisions: dict[str, int] = {}
            providers: dict[str, int] = {}
            models: dict[str, int] = {}
            departments: dict[str, int] = {}
            rules: dict[str, int] = {}
            latencies: list[float] = []

            for m in filtered_metrics:
                decisions[m.decision] = decisions.get(m.decision, 0) + 1
                providers[m.provider] = providers.get(m.provider, 0) + 1
                models[m.model] = models.get(m.model, 0) + 1
                if m.department:
                    departments[m.department] = (
                        departments.get(m.department, 0) + 1
                    )
                for rule in m.rules_matched:
                    rules[rule] = rules.get(rule, 0) + 1
                latencies.append(m.latency_ms)

            # Calculate latency percentiles
            latencies.sort()
            n = len(latencies)

            def percentile(p: float) -> float:
                if not latencies:
                    return 0.0
                idx = int(n * p / 100)
                return latencies[min(idx, n - 1)]

            # Get top rules by match count
            top_rules = sorted(rules.items(), key=lambda x: x[1], reverse=True)[
                :10
            ]

            return MetricsSummary(
                period_start=since,
                period_end=until,
                total_requests=len(filtered_metrics),
                decisions=decisions,
                avg_latency_ms=sum(latencies) / n if n else 0,
                p50_latency_ms=percentile(50),
                p95_latency_ms=percentile(95),
                p99_latency_ms=percentile(99),
                max_latency_ms=max(latencies) if latencies else 0,
                min_latency_ms=min(latencies) if latencies else 0,
                requests_by_provider=providers,
                requests_by_model=models,
                requests_by_department=departments,
                top_rules=top_rules,
                error_count=self._error_count,
            )

    def get_time_series(
        self,
        metric: str = "requests",
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[TimeSeriesPoint]:
        """
        Get time series data for a metric.

        Args:
            metric: The metric to get ("requests", "latency", or "decisions").
            since: Start of the period.
            until: End of the period.

        Returns:
            List of TimeSeriesPoint with timestamp and value.
        """
        now = utc_now()
        if until is None:
            until = now
        if since is None:
            since = now - timedelta(seconds=self._window_seconds)

        start_bucket = self._get_time_bucket(since)
        end_bucket = self._get_time_bucket(until)

        with self._lock:
            points: list[TimeSeriesPoint] = []

            if metric == "requests":
                for bucket, count in sorted(self._time_series_requests.items()):
                    if start_bucket <= bucket <= end_bucket:
                        points.append(
                            TimeSeriesPoint(
                                timestamp=datetime.fromtimestamp(
                                    bucket, tz=now.tzinfo
                                ),
                                value=float(count),
                            )
                        )

            elif metric == "latency":
                for bucket, latencies in sorted(
                    self._time_series_latency.items()
                ):
                    if start_bucket <= bucket <= end_bucket and latencies:
                        avg = sum(latencies) / len(latencies)
                        points.append(
                            TimeSeriesPoint(
                                timestamp=datetime.fromtimestamp(
                                    bucket, tz=now.tzinfo
                                ),
                                value=avg,
                            )
                        )

            return points

    def get_decision_time_series(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, list[TimeSeriesPoint]]:
        """
        Get time series data for decisions by type.

        Args:
            since: Start of the period.
            until: End of the period.

        Returns:
            Dictionary mapping decision type to list of TimeSeriesPoints.
        """
        now = utc_now()
        if until is None:
            until = now
        if since is None:
            since = now - timedelta(seconds=self._window_seconds)

        start_bucket = self._get_time_bucket(since)
        end_bucket = self._get_time_bucket(until)

        with self._lock:
            # Collect all decision types
            all_decisions: set[str] = set()
            for decisions in self._time_series_decisions.values():
                all_decisions.update(decisions.keys())

            result: dict[str, list[TimeSeriesPoint]] = {
                d: [] for d in all_decisions
            }

            for bucket in sorted(self._time_series_decisions.keys()):
                if start_bucket <= bucket <= end_bucket:
                    decisions = self._time_series_decisions[bucket]
                    ts = datetime.fromtimestamp(bucket, tz=now.tzinfo)
                    for decision in all_decisions:
                        result[decision].append(
                            TimeSeriesPoint(
                                timestamp=ts,
                                value=float(decisions.get(decision, 0)),
                            )
                        )

            return result

    def get_totals(self) -> dict[str, Any]:
        """
        Get total aggregated metrics since start.

        Returns:
            Dictionary with total metrics.
        """
        with self._lock:
            avg_latency = 0.0
            if self._latency_count > 0:
                avg_latency = self._latency_sum_ms / self._latency_count

            return {
                "total_requests": self._total_requests,
                "uptime_seconds": time.time() - self._start_time,
                "decisions": dict(self._total_by_decision),
                "providers": dict(self._total_by_provider),
                "models": dict(self._total_by_model),
                "departments": dict(self._total_by_department),
                "avg_latency_ms": round(avg_latency, 2),
                "error_count": self._error_count,
                "top_rules": sorted(
                    self._total_by_rule.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10],
            }

    def get_rates(
        self,
        window_seconds: int = 60,
    ) -> dict[str, float]:
        """
        Get request rates for a recent window.

        Args:
            window_seconds: Size of the window in seconds.

        Returns:
            Dictionary with rate metrics.
        """
        now = utc_now()
        since = now - timedelta(seconds=window_seconds)

        with self._lock:
            count = sum(
                1
                for m in self._enforcement_metrics
                if m.timestamp >= since
            )

            allow_count = sum(
                1
                for m in self._enforcement_metrics
                if m.timestamp >= since and m.decision == "ALLOW"
            )

            deny_count = sum(
                1
                for m in self._enforcement_metrics
                if m.timestamp >= since and m.decision == "DENY"
            )

            return {
                "requests_per_second": round(count / window_seconds, 2),
                "allows_per_second": round(allow_count / window_seconds, 2),
                "denies_per_second": round(deny_count / window_seconds, 2),
                "allow_rate_percent": round(
                    (allow_count / count * 100) if count > 0 else 0, 2
                ),
                "deny_rate_percent": round(
                    (deny_count / count * 100) if count > 0 else 0, 2
                ),
            }

    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        with self._lock:
            self._enforcement_metrics.clear()
            self._total_requests = 0
            self._total_by_decision.clear()
            self._total_by_provider.clear()
            self._total_by_model.clear()
            self._total_by_department.clear()
            self._total_by_rule.clear()
            self._error_count = 0
            self._latency_sum_ms = 0.0
            self._latency_count = 0
            self._time_series_requests.clear()
            self._time_series_latency.clear()
            self._time_series_decisions.clear()
            self._start_time = time.time()


# Global collector instance
_collector: MetricsCollector | None = None
_collector_lock = threading.Lock()


def get_collector() -> MetricsCollector:
    """
    Get the global metrics collector instance.

    Returns:
        The singleton MetricsCollector instance.
    """
    global _collector
    if _collector is None:
        with _collector_lock:
            if _collector is None:
                _collector = MetricsCollector()
    return _collector
