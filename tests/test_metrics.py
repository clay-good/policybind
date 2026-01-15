"""
Tests for PolicyBind metrics collection and dashboard functionality.
"""

import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from policybind.metrics.collector import (
    EnforcementMetric,
    MetricsCollector,
    MetricsSummary,
    TimeSeriesPoint,
    get_collector,
)
from policybind.metrics.dashboard import (
    DashboardData,
    DashboardMetrics,
    RealTimeStats,
    TopItem,
    TrendData,
)
from policybind.models.base import utc_now


class TestEnforcementMetric:
    """Tests for EnforcementMetric dataclass."""

    def test_create_metric(self):
        """Test creating an enforcement metric."""
        now = utc_now()
        metric = EnforcementMetric(
            timestamp=now,
            decision="ALLOW",
            latency_ms=15.5,
            provider="openai",
            model="gpt-4",
            rules_matched=["allow_gpt4"],
            department="engineering",
            user_id="user123",
        )

        assert metric.timestamp == now
        assert metric.decision == "ALLOW"
        assert metric.latency_ms == 15.5
        assert metric.provider == "openai"
        assert metric.model == "gpt-4"
        assert metric.department == "engineering"
        assert metric.rules_matched == ["allow_gpt4"]
        assert metric.user_id == "user123"

    def test_create_metric_minimal(self):
        """Test creating a metric with minimal fields."""
        now = utc_now()
        metric = EnforcementMetric(
            timestamp=now,
            decision="DENY",
            latency_ms=5.0,
            provider="anthropic",
            model="claude-3",
            rules_matched=[],
        )

        assert metric.decision == "DENY"
        assert metric.department == ""
        assert metric.user_id == ""
        assert metric.data_classification == ()


class TestTimeSeriesPoint:
    """Tests for TimeSeriesPoint dataclass."""

    def test_create_point(self):
        """Test creating a time series point."""
        now = utc_now()
        point = TimeSeriesPoint(timestamp=now, value=42.5)

        assert point.timestamp == now
        assert point.value == 42.5


class TestMetricsSummary:
    """Tests for MetricsSummary dataclass."""

    def test_default_summary(self):
        """Test default summary values."""
        now = utc_now()
        summary = MetricsSummary(
            period_start=now - timedelta(hours=1),
            period_end=now,
        )

        assert summary.total_requests == 0
        assert summary.avg_latency_ms == 0.0
        assert summary.p50_latency_ms == 0.0
        assert summary.p95_latency_ms == 0.0
        assert summary.p99_latency_ms == 0.0
        assert summary.min_latency_ms == 0.0
        assert summary.max_latency_ms == 0.0
        assert summary.error_count == 0
        assert summary.decisions == {}
        assert summary.requests_by_provider == {}
        assert summary.requests_by_model == {}
        assert summary.requests_by_department == {}
        assert summary.top_rules == []

    def test_to_dict(self):
        """Test converting summary to dict."""
        now = utc_now()
        summary = MetricsSummary(
            period_start=now - timedelta(hours=1),
            period_end=now,
            total_requests=100,
            avg_latency_ms=15.5,
            decisions={"ALLOW": 80, "DENY": 20},
        )

        result = summary.to_dict()
        assert result["total_requests"] == 100
        assert result["latency"]["avg_ms"] == 15.5
        assert result["decisions"] == {"ALLOW": 80, "DENY": 20}


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    @pytest.fixture
    def collector(self):
        """Create a fresh collector for each test."""
        return MetricsCollector(max_data_points=100)

    def test_record_enforcement(self, collector):
        """Test recording enforcement metrics."""
        collector.record_enforcement(
            decision="ALLOW",
            latency_ms=10.5,
            provider="openai",
            model="gpt-4",
            department="engineering",
            rules_matched=["allow_rule"],
        )

        summary = collector.get_summary()
        assert summary.total_requests == 1
        assert summary.decisions.get("ALLOW", 0) == 1
        assert summary.requests_by_provider.get("openai", 0) == 1
        assert summary.requests_by_model.get("gpt-4", 0) == 1

    def test_record_multiple_enforcements(self, collector):
        """Test recording multiple enforcements."""
        for i in range(10):
            collector.record_enforcement(
                decision="ALLOW" if i % 2 == 0 else "DENY",
                latency_ms=10.0 + i,
                provider="openai" if i % 3 == 0 else "anthropic",
                model="gpt-4",
            )

        summary = collector.get_summary()
        assert summary.total_requests == 10
        assert summary.decisions.get("ALLOW", 0) == 5
        assert summary.decisions.get("DENY", 0) == 5

    def test_record_enforcement_with_error(self, collector):
        """Test recording error count."""
        collector.record_enforcement(
            decision="ERROR",
            latency_ms=5.0,
            provider="openai",
            model="gpt-4",
        )
        collector.record_error()

        summary = collector.get_summary()
        assert summary.error_count == 1
        assert summary.decisions.get("ERROR", 0) == 1

    def test_latency_percentiles(self, collector):
        """Test latency percentile calculations."""
        # Record 100 metrics with increasing latency
        for i in range(100):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=float(i + 1),  # 1-100ms
                provider="openai",
                model="gpt-4",
            )

        summary = collector.get_summary()
        assert summary.min_latency_ms == 1.0
        assert summary.max_latency_ms == 100.0
        assert summary.avg_latency_ms == 50.5  # Average of 1-100
        # Percentile calculations may vary slightly based on implementation
        assert 49.0 <= summary.p50_latency_ms <= 52.0  # Around median
        assert 94.0 <= summary.p95_latency_ms <= 97.0  # Around 95th percentile
        assert 98.0 <= summary.p99_latency_ms <= 100.0  # Around 99th percentile

    def test_max_metrics_limit(self, collector):
        """Test that metrics are limited by max_data_points."""
        # Record more than max_data_points
        for i in range(150):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
            )

        # Collector should only keep last 100 in detailed metrics
        summary = collector.get_summary()
        assert summary.total_requests == 100

    def test_summary_with_time_range(self, collector):
        """Test summary with time range filter."""
        now = utc_now()

        # Record some metrics
        for i in range(5):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
            )

        # Get summary for recent time
        summary = collector.get_summary(
            since=now - timedelta(minutes=1),
            until=now + timedelta(minutes=1),
        )
        assert summary.total_requests == 5

        # Get summary for future time (should be empty)
        future = now + timedelta(hours=1)
        summary = collector.get_summary(
            since=future,
            until=future + timedelta(minutes=1),
        )
        assert summary.total_requests == 0

    def test_top_rules(self, collector):
        """Test top rules tracking."""
        # Record metrics with different rules
        for _ in range(10):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
                rules_matched=["rule_a"],
            )
        for _ in range(5):
            collector.record_enforcement(
                decision="DENY",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
                rules_matched=["rule_b"],
            )
        for _ in range(3):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
                rules_matched=["rule_c"],
            )

        summary = collector.get_summary()
        # Top rules should be sorted by count
        assert len(summary.top_rules) >= 3
        assert summary.top_rules[0] == ("rule_a", 10)
        assert summary.top_rules[1] == ("rule_b", 5)
        assert summary.top_rules[2] == ("rule_c", 3)

    def test_get_totals(self, collector):
        """Test getting total metrics."""
        for i in range(10):
            collector.record_enforcement(
                decision="ALLOW" if i % 2 == 0 else "DENY",
                latency_ms=10.0 + i,
                provider="openai" if i % 2 == 0 else "anthropic",
                model="gpt-4",
                rules_matched=[f"rule_{i % 3}"],
            )

        totals = collector.get_totals()
        assert totals["total_requests"] == 10
        assert "decisions" in totals
        assert "providers" in totals
        assert "models" in totals
        assert "avg_latency_ms" in totals
        assert "uptime_seconds" in totals
        assert "top_rules" in totals

    def test_get_rates(self, collector):
        """Test getting request rates."""
        # Record some metrics
        for i in range(10):
            collector.record_enforcement(
                decision="ALLOW" if i < 7 else "DENY",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
            )

        rates = collector.get_rates(window_seconds=60)
        assert "requests_per_second" in rates
        assert "allow_rate_percent" in rates
        assert "deny_rate_percent" in rates

        # 7 allows, 3 denies
        assert rates["allow_rate_percent"] == 70.0
        assert rates["deny_rate_percent"] == 30.0

    def test_get_time_series(self, collector):
        """Test getting time series data."""
        # Record some metrics
        for i in range(5):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=10.0 + i,
                provider="openai",
                model="gpt-4",
            )

        now = utc_now()
        series = collector.get_time_series(
            metric="requests",
            since=now - timedelta(minutes=5),
            until=now + timedelta(minutes=1),
        )

        assert isinstance(series, list)
        # Series should have time series points
        for point in series:
            assert isinstance(point, TimeSeriesPoint)

    def test_get_decision_time_series(self, collector):
        """Test getting decision time series."""
        for i in range(10):
            collector.record_enforcement(
                decision="ALLOW" if i % 2 == 0 else "DENY",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
            )

        now = utc_now()
        series = collector.get_decision_time_series(
            since=now - timedelta(minutes=5),
            until=now + timedelta(minutes=1),
        )

        assert isinstance(series, dict)
        # Should have decision keys
        assert "ALLOW" in series or "DENY" in series

    def test_reset(self, collector):
        """Test resetting metrics."""
        # Record some metrics
        for i in range(5):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
            )

        assert collector.get_summary().total_requests == 5

        collector.reset()
        assert collector.get_summary().total_requests == 0


class TestGlobalCollector:
    """Tests for global collector singleton."""

    def test_get_collector_singleton(self):
        """Test that get_collector returns same instance."""
        collector1 = get_collector()
        collector2 = get_collector()
        assert collector1 is collector2


class TestRealTimeStats:
    """Tests for RealTimeStats dataclass."""

    def test_default_stats(self):
        """Test default stats values."""
        stats = RealTimeStats()

        assert stats.requests_per_minute == 0.0
        assert stats.avg_latency_ms == 0.0
        assert stats.allow_rate_percent == 0.0
        assert stats.deny_rate_percent == 0.0
        assert stats.active_tokens == 0
        assert stats.active_deployments == 0
        assert stats.open_incidents == 0
        assert stats.policy_rules == 0

    def test_to_dict(self):
        """Test converting stats to dict."""
        stats = RealTimeStats(
            requests_per_minute=120.5,
            avg_latency_ms=15.7,
            allow_rate_percent=85.3,
            deny_rate_percent=14.7,
            active_tokens=50,
            active_deployments=10,
            open_incidents=3,
            policy_rules=25,
        )

        result = stats.to_dict()
        assert result["requests_per_minute"] == 120.5
        assert result["avg_latency_ms"] == 15.7
        assert result["allow_rate_percent"] == 85.3
        assert result["deny_rate_percent"] == 14.7
        assert result["active_tokens"] == 50
        assert result["active_deployments"] == 10
        assert result["open_incidents"] == 3
        assert result["policy_rules"] == 25


class TestTrendData:
    """Tests for TrendData dataclass."""

    def test_default_trend_data(self):
        """Test default trend data."""
        trends = TrendData()

        assert trends.timestamps == []
        assert trends.requests == []
        assert trends.latency == []
        assert trends.allows == []
        assert trends.denies == []

    def test_to_dict(self):
        """Test converting trend data to dict."""
        trends = TrendData(
            timestamps=["2024-01-01T00:00:00", "2024-01-01T00:01:00"],
            requests=[100, 150],
            latency=[10.5, 12.3],
            allows=[80, 120],
            denies=[20, 30],
        )

        result = trends.to_dict()
        assert result["timestamps"] == ["2024-01-01T00:00:00", "2024-01-01T00:01:00"]
        assert result["requests"] == [100, 150]
        assert result["latency"] == [10.5, 12.3]
        assert result["allows"] == [80, 120]
        assert result["denies"] == [20, 30]


class TestTopItem:
    """Tests for TopItem dataclass."""

    def test_create_top_item(self):
        """Test creating a top item."""
        item = TopItem(name="openai", count=100, percentage=45.5)

        assert item.name == "openai"
        assert item.count == 100
        assert item.percentage == 45.5

    def test_to_dict(self):
        """Test converting to dict."""
        item = TopItem(name="anthropic", count=75, percentage=33.33)

        result = item.to_dict()
        assert result["name"] == "anthropic"
        assert result["count"] == 75
        assert result["percentage"] == 33.33


class TestDashboardData:
    """Tests for DashboardData dataclass."""

    def test_default_dashboard_data(self):
        """Test default dashboard data."""
        data = DashboardData()

        assert data.real_time is not None
        assert data.trends is not None
        assert data.top_providers == []
        assert data.top_models == []
        assert data.top_rules == []
        assert data.top_departments == []
        assert data.decision_breakdown == {}
        assert data.recent_incidents == []
        assert data.alerts == []

    def test_to_dict(self):
        """Test converting dashboard data to dict."""
        data = DashboardData(
            real_time=RealTimeStats(requests_per_minute=100.0),
            top_providers=[TopItem(name="openai", count=50, percentage=50.0)],
            decision_breakdown={"ALLOW": 80, "DENY": 20},
        )

        result = data.to_dict()
        assert "generated_at" in result
        assert "real_time" in result
        assert "trends" in result
        assert "top_providers" in result
        assert "decision_breakdown" in result
        assert result["decision_breakdown"] == {"ALLOW": 80, "DENY": 20}


class TestDashboardMetrics:
    """Tests for DashboardMetrics class."""

    @pytest.fixture
    def collector(self):
        """Create a metrics collector with test data."""
        collector = MetricsCollector()
        # Add some test data
        for i in range(20):
            collector.record_enforcement(
                decision="ALLOW" if i % 3 != 0 else "DENY",
                latency_ms=10.0 + (i * 2),
                provider="openai" if i % 2 == 0 else "anthropic",
                model="gpt-4" if i % 2 == 0 else "claude-3",
                department="engineering" if i % 3 == 0 else "marketing",
                rules_matched=[f"rule_{i % 5}"],
            )
        return collector

    @pytest.fixture
    def dashboard(self, collector):
        """Create a dashboard metrics instance."""
        return DashboardMetrics(
            collector=collector,
            policy_rules_count=10,
        )

    def test_get_dashboard_data(self, dashboard):
        """Test getting full dashboard data."""
        data = dashboard.get_dashboard_data()

        assert isinstance(data, DashboardData)
        assert data.real_time.policy_rules == 10
        assert data.real_time.requests_per_minute >= 0
        assert len(data.top_providers) > 0
        assert len(data.top_models) > 0

    def test_dashboard_with_managers(self, collector):
        """Test dashboard with manager mocks."""
        # Create mock managers
        token_manager = MagicMock()
        token_manager.get_statistics.return_value = {"active_tokens": 25}

        registry_manager = MagicMock()
        registry_manager.get_statistics.return_value = {"total_deployments": 15}

        incident_manager = MagicMock()
        incident_metrics = MagicMock()
        incident_metrics.open_count = 5
        incident_manager.get_metrics.return_value = incident_metrics
        incident_manager.list_incidents.return_value = []

        dashboard = DashboardMetrics(
            collector=collector,
            token_manager=token_manager,
            registry_manager=registry_manager,
            incident_manager=incident_manager,
            policy_rules_count=10,
        )

        data = dashboard.get_dashboard_data()

        assert data.real_time.active_tokens == 25
        assert data.real_time.active_deployments == 15
        assert data.real_time.open_incidents == 5

    def test_set_policy_rules_count(self, dashboard):
        """Test setting policy rules count."""
        dashboard.set_policy_rules_count(50)
        data = dashboard.get_dashboard_data()
        assert data.real_time.policy_rules == 50

    def test_trend_data(self, dashboard):
        """Test that trend data is populated."""
        data = dashboard.get_dashboard_data(trend_minutes=60)

        assert isinstance(data.trends, TrendData)
        # May or may not have data depending on bucketing

    def test_alerts_high_denial_rate(self):
        """Test alert generation for high denial rate."""
        # Create collector with mostly denies
        collector = MetricsCollector()
        for i in range(10):
            collector.record_enforcement(
                decision="DENY",  # All denies
                latency_ms=10.0,
                provider="openai",
                model="gpt-4",
            )

        dashboard = DashboardMetrics(collector=collector)
        data = dashboard.get_dashboard_data()

        # Should have high denial rate alert
        denial_alerts = [a for a in data.alerts if a["type"] == "high_denial_rate"]
        assert len(denial_alerts) > 0

    def test_alerts_high_latency(self):
        """Test alert generation for high latency."""
        collector = MetricsCollector()
        for i in range(10):
            collector.record_enforcement(
                decision="ALLOW",
                latency_ms=200.0,  # High latency
                provider="openai",
                model="gpt-4",
            )

        dashboard = DashboardMetrics(collector=collector)
        data = dashboard.get_dashboard_data()

        # Should have high latency alert
        latency_alerts = [a for a in data.alerts if a["type"] == "high_latency"]
        assert len(latency_alerts) > 0

    def test_get_prometheus_metrics(self, dashboard):
        """Test Prometheus format metrics output."""
        metrics = dashboard.get_prometheus_metrics()

        assert isinstance(metrics, str)
        assert "policybind_up 1" in metrics
        assert "policybind_requests_total" in metrics
        assert "policybind_latency_avg_ms" in metrics
        assert "policybind_requests_per_second" in metrics
        assert "policybind_policy_rules_total" in metrics

    def test_prometheus_metrics_format(self, dashboard):
        """Test that Prometheus metrics are properly formatted."""
        metrics = dashboard.get_prometheus_metrics()
        lines = metrics.split("\n")

        # Check for HELP and TYPE comments
        help_lines = [l for l in lines if l.startswith("# HELP")]
        type_lines = [l for l in lines if l.startswith("# TYPE")]

        assert len(help_lines) > 0
        assert len(type_lines) > 0

        # Check metric format (name{labels} value)
        metric_lines = [l for l in lines if l and not l.startswith("#")]
        for line in metric_lines:
            # Should have metric name and value
            parts = line.split()
            assert len(parts) >= 1  # At minimum metric name


class TestDashboardHandlers:
    """Tests for dashboard HTTP handlers."""

    def test_routes_registered(self):
        """Test that dashboard routes are registered."""
        pytest.importorskip("aiohttp")
        from aiohttp import web
        from policybind.server.routes import setup_routes

        app = web.Application()
        setup_routes(app)
        routes = {r.resource.canonical for r in app.router.routes() if r.resource}

        assert "/v1/dashboard" in routes
        assert "/v1/dashboard/realtime" in routes
        assert "/v1/dashboard/trends" in routes
        assert "/v1/dashboard/breakdown" in routes
        assert "/v1/dashboard/latency" in routes
        assert "/v1/dashboard/alerts" in routes
        assert "/v1/dashboard/prometheus" in routes
