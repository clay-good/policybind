"""
Dashboard data provider for PolicyBind.

This module provides structured dashboard data combining metrics from
various sources for real-time monitoring displays.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from policybind.metrics.collector import MetricsCollector, get_collector
from policybind.models.base import utc_now

if TYPE_CHECKING:
    from policybind.incidents.manager import IncidentManager
    from policybind.registry.manager import RegistryManager
    from policybind.tokens.manager import TokenManager


@dataclass
class RealTimeStats:
    """Real-time statistics for the dashboard header."""

    requests_per_minute: float = 0.0
    avg_latency_ms: float = 0.0
    allow_rate_percent: float = 0.0
    deny_rate_percent: float = 0.0
    active_tokens: int = 0
    active_deployments: int = 0
    open_incidents: int = 0
    policy_rules: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "requests_per_minute": round(self.requests_per_minute, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "allow_rate_percent": round(self.allow_rate_percent, 2),
            "deny_rate_percent": round(self.deny_rate_percent, 2),
            "active_tokens": self.active_tokens,
            "active_deployments": self.active_deployments,
            "open_incidents": self.open_incidents,
            "policy_rules": self.policy_rules,
        }


@dataclass
class TrendData:
    """Time series trend data for charts."""

    timestamps: list[str] = field(default_factory=list)
    requests: list[int] = field(default_factory=list)
    latency: list[float] = field(default_factory=list)
    allows: list[int] = field(default_factory=list)
    denies: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamps": self.timestamps,
            "requests": self.requests,
            "latency": [round(l, 2) for l in self.latency],
            "allows": self.allows,
            "denies": self.denies,
        }


@dataclass
class TopItem:
    """A top item in a ranked list."""

    name: str
    count: int
    percentage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "count": self.count,
            "percentage": round(self.percentage, 2),
        }


@dataclass
class DashboardData:
    """
    Complete dashboard data package.

    Contains all data needed to render a monitoring dashboard including
    real-time stats, trends, breakdowns, and alerts.
    """

    generated_at: datetime = field(default_factory=utc_now)
    real_time: RealTimeStats = field(default_factory=RealTimeStats)
    trends: TrendData = field(default_factory=TrendData)
    top_providers: list[TopItem] = field(default_factory=list)
    top_models: list[TopItem] = field(default_factory=list)
    top_rules: list[TopItem] = field(default_factory=list)
    top_departments: list[TopItem] = field(default_factory=list)
    decision_breakdown: dict[str, int] = field(default_factory=dict)
    recent_incidents: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "real_time": self.real_time.to_dict(),
            "trends": self.trends.to_dict(),
            "top_providers": [p.to_dict() for p in self.top_providers],
            "top_models": [m.to_dict() for m in self.top_models],
            "top_rules": [r.to_dict() for r in self.top_rules],
            "top_departments": [d.to_dict() for d in self.top_departments],
            "decision_breakdown": self.decision_breakdown,
            "recent_incidents": self.recent_incidents,
            "alerts": self.alerts,
        }


class DashboardMetrics:
    """
    Dashboard metrics provider.

    Aggregates data from various sources to provide a complete
    dashboard view of the PolicyBind system.
    """

    def __init__(
        self,
        collector: MetricsCollector | None = None,
        registry_manager: "RegistryManager | None" = None,
        token_manager: "TokenManager | None" = None,
        incident_manager: "IncidentManager | None" = None,
        policy_rules_count: int = 0,
    ) -> None:
        """
        Initialize the dashboard metrics provider.

        Args:
            collector: Metrics collector instance (uses global if None).
            registry_manager: Registry manager for deployment stats.
            token_manager: Token manager for token stats.
            incident_manager: Incident manager for incident stats.
            policy_rules_count: Current number of policy rules.
        """
        self._collector = collector or get_collector()
        self._registry_manager = registry_manager
        self._token_manager = token_manager
        self._incident_manager = incident_manager
        self._policy_rules_count = policy_rules_count

    def set_policy_rules_count(self, count: int) -> None:
        """Update the policy rules count."""
        self._policy_rules_count = count

    def get_dashboard_data(
        self,
        trend_minutes: int = 60,
    ) -> DashboardData:
        """
        Get complete dashboard data.

        Args:
            trend_minutes: Number of minutes of trend data to include.

        Returns:
            DashboardData with all dashboard information.
        """
        now = utc_now()
        since = now - timedelta(minutes=trend_minutes)

        # Get summary from collector
        summary = self._collector.get_summary(since=since, until=now)

        # Get rates
        rates = self._collector.get_rates(window_seconds=60)

        # Build real-time stats
        real_time = RealTimeStats(
            requests_per_minute=rates["requests_per_second"] * 60,
            avg_latency_ms=summary.avg_latency_ms,
            allow_rate_percent=rates["allow_rate_percent"],
            deny_rate_percent=rates["deny_rate_percent"],
            policy_rules=self._policy_rules_count,
        )

        # Get active tokens count
        if self._token_manager:
            try:
                stats = self._token_manager.get_statistics()
                real_time.active_tokens = stats.get("active_tokens", 0)
            except Exception:
                pass

        # Get active deployments count
        if self._registry_manager:
            try:
                stats = self._registry_manager.get_statistics()
                real_time.active_deployments = stats.get("total_deployments", 0)
            except Exception:
                pass

        # Get open incidents count
        if self._incident_manager:
            try:
                metrics = self._incident_manager.get_metrics()
                real_time.open_incidents = metrics.open_count
            except Exception:
                pass

        # Build trend data
        trends = self._build_trend_data(since, now)

        # Build top items
        total = summary.total_requests or 1
        top_providers = self._build_top_items(
            summary.requests_by_provider, total
        )
        top_models = self._build_top_items(summary.requests_by_model, total)
        top_rules = [
            TopItem(
                name=name,
                count=count,
                percentage=(count / total * 100) if total else 0,
            )
            for name, count in summary.top_rules[:5]
        ]
        top_departments = self._build_top_items(
            summary.requests_by_department, total
        )

        # Get recent incidents
        recent_incidents: list[dict[str, Any]] = []
        if self._incident_manager:
            try:
                incidents = self._incident_manager.list_incidents(
                    limit=5,
                )
                recent_incidents = [
                    {
                        "incident_id": i.incident_id,
                        "severity": i.severity.value,
                        "status": i.status.value,
                        "incident_type": i.incident_type.value,
                        "created_at": i.created_at.isoformat(),
                        "description": i.description[:100] if i.description else "",
                    }
                    for i in incidents
                ]
            except Exception:
                pass

        # Generate alerts
        alerts = self._generate_alerts(summary, rates)

        return DashboardData(
            generated_at=now,
            real_time=real_time,
            trends=trends,
            top_providers=top_providers,
            top_models=top_models,
            top_rules=top_rules,
            top_departments=top_departments,
            decision_breakdown=summary.decisions,
            recent_incidents=recent_incidents,
            alerts=alerts,
        )

    def _build_trend_data(
        self,
        since: datetime,
        until: datetime,
    ) -> TrendData:
        """Build time series trend data."""
        request_series = self._collector.get_time_series(
            metric="requests",
            since=since,
            until=until,
        )
        latency_series = self._collector.get_time_series(
            metric="latency",
            since=since,
            until=until,
        )
        decision_series = self._collector.get_decision_time_series(
            since=since,
            until=until,
        )

        trends = TrendData()

        # Build aligned timestamps from request series
        for point in request_series:
            trends.timestamps.append(point.timestamp.isoformat())
            trends.requests.append(int(point.value))

        # Align latency data
        latency_by_ts = {
            p.timestamp.isoformat(): p.value for p in latency_series
        }
        for ts in trends.timestamps:
            trends.latency.append(latency_by_ts.get(ts, 0.0))

        # Align decision data
        allows = decision_series.get("ALLOW", [])
        denies = decision_series.get("DENY", [])
        allow_by_ts = {p.timestamp.isoformat(): int(p.value) for p in allows}
        deny_by_ts = {p.timestamp.isoformat(): int(p.value) for p in denies}
        for ts in trends.timestamps:
            trends.allows.append(allow_by_ts.get(ts, 0))
            trends.denies.append(deny_by_ts.get(ts, 0))

        return trends

    def _build_top_items(
        self,
        data: dict[str, int],
        total: int,
        limit: int = 5,
    ) -> list[TopItem]:
        """Build a list of top items from a count dictionary."""
        sorted_items = sorted(data.items(), key=lambda x: x[1], reverse=True)
        return [
            TopItem(
                name=name,
                count=count,
                percentage=(count / total * 100) if total else 0,
            )
            for name, count in sorted_items[:limit]
        ]

    def _generate_alerts(
        self,
        summary: Any,
        rates: dict[str, float],
    ) -> list[dict[str, Any]]:
        """Generate alerts based on metrics thresholds."""
        alerts: list[dict[str, Any]] = []

        # High denial rate alert
        if rates["deny_rate_percent"] > 20:
            alerts.append({
                "level": "warning",
                "type": "high_denial_rate",
                "message": f"High denial rate: {rates['deny_rate_percent']:.1f}%",
                "threshold": 20,
                "value": rates["deny_rate_percent"],
            })

        # High latency alert
        if summary.p95_latency_ms > 100:
            alerts.append({
                "level": "warning",
                "type": "high_latency",
                "message": f"High P95 latency: {summary.p95_latency_ms:.1f}ms",
                "threshold": 100,
                "value": summary.p95_latency_ms,
            })

        # Very high latency alert
        if summary.p99_latency_ms > 500:
            alerts.append({
                "level": "critical",
                "type": "very_high_latency",
                "message": f"Critical P99 latency: {summary.p99_latency_ms:.1f}ms",
                "threshold": 500,
                "value": summary.p99_latency_ms,
            })

        # Error rate alert
        if summary.error_count > 0:
            error_rate = (
                summary.error_count / summary.total_requests * 100
                if summary.total_requests
                else 0
            )
            if error_rate > 5:
                alerts.append({
                    "level": "critical",
                    "type": "high_error_rate",
                    "message": f"High error rate: {error_rate:.1f}%",
                    "threshold": 5,
                    "value": error_rate,
                })

        return alerts

    def get_prometheus_metrics(self) -> str:
        """
        Get metrics in Prometheus format.

        Returns:
            String with Prometheus-format metrics.
        """
        totals = self._collector.get_totals()
        rates = self._collector.get_rates()
        summary = self._collector.get_summary()

        lines: list[str] = []

        # Server status
        lines.extend([
            "# HELP policybind_up PolicyBind server is up",
            "# TYPE policybind_up gauge",
            "policybind_up 1",
            "",
            "# HELP policybind_uptime_seconds Server uptime in seconds",
            "# TYPE policybind_uptime_seconds counter",
            f"policybind_uptime_seconds {totals['uptime_seconds']:.2f}",
            "",
        ])

        # Total requests by decision
        lines.extend([
            "# HELP policybind_requests_total Total enforcement requests",
            "# TYPE policybind_requests_total counter",
        ])
        for decision, count in totals["decisions"].items():
            lines.append(
                f'policybind_requests_total{{decision="{decision}"}} {count}'
            )
        lines.append("")

        # Requests by provider
        lines.extend([
            "# HELP policybind_requests_by_provider Requests by provider",
            "# TYPE policybind_requests_by_provider counter",
        ])
        for provider, count in totals["providers"].items():
            lines.append(
                f'policybind_requests_by_provider{{provider="{provider}"}} {count}'
            )
        lines.append("")

        # Requests by model
        lines.extend([
            "# HELP policybind_requests_by_model Requests by model",
            "# TYPE policybind_requests_by_model counter",
        ])
        for model, count in totals["models"].items():
            lines.append(
                f'policybind_requests_by_model{{model="{model}"}} {count}'
            )
        lines.append("")

        # Latency metrics
        lines.extend([
            "# HELP policybind_latency_avg_ms Average latency in milliseconds",
            "# TYPE policybind_latency_avg_ms gauge",
            f"policybind_latency_avg_ms {totals['avg_latency_ms']:.2f}",
            "",
            "# HELP policybind_latency_p50_ms P50 latency in milliseconds",
            "# TYPE policybind_latency_p50_ms gauge",
            f"policybind_latency_p50_ms {summary.p50_latency_ms:.2f}",
            "",
            "# HELP policybind_latency_p95_ms P95 latency in milliseconds",
            "# TYPE policybind_latency_p95_ms gauge",
            f"policybind_latency_p95_ms {summary.p95_latency_ms:.2f}",
            "",
            "# HELP policybind_latency_p99_ms P99 latency in milliseconds",
            "# TYPE policybind_latency_p99_ms gauge",
            f"policybind_latency_p99_ms {summary.p99_latency_ms:.2f}",
            "",
        ])

        # Rate metrics
        lines.extend([
            "# HELP policybind_requests_per_second Current request rate",
            "# TYPE policybind_requests_per_second gauge",
            f"policybind_requests_per_second {rates['requests_per_second']:.2f}",
            "",
            "# HELP policybind_allow_rate Allow rate percentage",
            "# TYPE policybind_allow_rate gauge",
            f"policybind_allow_rate {rates['allow_rate_percent']:.2f}",
            "",
            "# HELP policybind_deny_rate Deny rate percentage",
            "# TYPE policybind_deny_rate gauge",
            f"policybind_deny_rate {rates['deny_rate_percent']:.2f}",
            "",
        ])

        # Error count
        lines.extend([
            "# HELP policybind_errors_total Total errors",
            "# TYPE policybind_errors_total counter",
            f"policybind_errors_total {totals['error_count']}",
            "",
        ])

        # Policy rules
        lines.extend([
            "# HELP policybind_policy_rules_total Number of policy rules",
            "# TYPE policybind_policy_rules_total gauge",
            f"policybind_policy_rules_total {self._policy_rules_count}",
            "",
        ])

        # Top rules matched
        lines.extend([
            "# HELP policybind_rule_matches_total Rule match counts",
            "# TYPE policybind_rule_matches_total counter",
        ])
        for rule, count in totals["top_rules"]:
            lines.append(
                f'policybind_rule_matches_total{{rule="{rule}"}} {count}'
            )
        lines.append("")

        return "\n".join(lines)
