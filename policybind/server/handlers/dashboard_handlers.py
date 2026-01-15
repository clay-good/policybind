"""
Dashboard API handlers for PolicyBind.

This module provides HTTP handlers for the real-time metrics dashboard,
including summary data, time series, and detailed breakdowns.
"""

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from policybind.metrics.collector import get_collector
from policybind.metrics.dashboard import DashboardMetrics
from policybind.models.base import utc_now

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.dashboard")


def _get_dashboard_metrics(app: "web.Application") -> DashboardMetrics:
    """Get or create DashboardMetrics instance for the app."""
    if "dashboard_metrics" not in app:
        policy_set = app.get("policy_set")
        rule_count = len(policy_set.rules) if policy_set else 0

        app["dashboard_metrics"] = DashboardMetrics(
            collector=get_collector(),
            registry_manager=app.get("registry_manager"),
            token_manager=app.get("token_manager"),
            incident_manager=app.get("incident_manager"),
            policy_rules_count=rule_count,
        )
    return app["dashboard_metrics"]


async def dashboard_summary(request: "web.Request") -> "web.Response":
    """
    Get dashboard summary data.

    Returns complete dashboard data including real-time stats, trends,
    top items, and alerts.

    Query Parameters:
        trend_minutes: Number of minutes of trend data (default: 60)

    Returns:
        JSON response with dashboard data.
    """
    from aiohttp import web

    try:
        trend_minutes = int(request.query.get("trend_minutes", "60"))
        trend_minutes = max(1, min(1440, trend_minutes))  # 1 min to 24 hours

        dashboard = _get_dashboard_metrics(request.app)

        # Update policy rules count
        policy_set = request.app.get("policy_set")
        if policy_set:
            dashboard.set_policy_rules_count(len(policy_set.rules))

        data = dashboard.get_dashboard_data(trend_minutes=trend_minutes)

        return web.json_response(data.to_dict())

    except Exception as e:
        logger.exception(f"Dashboard summary error: {e}")
        return web.json_response(
            {"error": {"code": "DASHBOARD_ERROR", "message": str(e)}},
            status=500,
        )


async def dashboard_realtime(request: "web.Request") -> "web.Response":
    """
    Get real-time stats only.

    Returns just the real-time statistics for quick updates.

    Returns:
        JSON response with real-time stats.
    """
    from aiohttp import web

    try:
        dashboard = _get_dashboard_metrics(request.app)

        # Update policy rules count
        policy_set = request.app.get("policy_set")
        if policy_set:
            dashboard.set_policy_rules_count(len(policy_set.rules))

        data = dashboard.get_dashboard_data(trend_minutes=1)

        return web.json_response({
            "generated_at": data.generated_at.isoformat(),
            "stats": data.real_time.to_dict(),
        })

    except Exception as e:
        logger.exception(f"Dashboard realtime error: {e}")
        return web.json_response(
            {"error": {"code": "DASHBOARD_ERROR", "message": str(e)}},
            status=500,
        )


async def dashboard_trends(request: "web.Request") -> "web.Response":
    """
    Get trend data for charts.

    Query Parameters:
        minutes: Number of minutes of data (default: 60)
        metric: Metric type - requests, latency, decisions (default: all)

    Returns:
        JSON response with time series data.
    """
    from aiohttp import web

    try:
        minutes = int(request.query.get("minutes", "60"))
        minutes = max(1, min(1440, minutes))
        metric = request.query.get("metric", "all")

        collector = get_collector()
        now = utc_now()
        since = now - timedelta(minutes=minutes)

        result: dict[str, Any] = {
            "generated_at": now.isoformat(),
            "period_minutes": minutes,
        }

        if metric in ("requests", "all"):
            series = collector.get_time_series("requests", since, now)
            result["requests"] = [
                {"timestamp": p.timestamp.isoformat(), "value": int(p.value)}
                for p in series
            ]

        if metric in ("latency", "all"):
            series = collector.get_time_series("latency", since, now)
            result["latency"] = [
                {"timestamp": p.timestamp.isoformat(), "value": round(p.value, 2)}
                for p in series
            ]

        if metric in ("decisions", "all"):
            series = collector.get_decision_time_series(since, now)
            result["decisions"] = {
                decision: [
                    {"timestamp": p.timestamp.isoformat(), "value": int(p.value)}
                    for p in points
                ]
                for decision, points in series.items()
            }

        return web.json_response(result)

    except Exception as e:
        logger.exception(f"Dashboard trends error: {e}")
        return web.json_response(
            {"error": {"code": "DASHBOARD_ERROR", "message": str(e)}},
            status=500,
        )


async def dashboard_breakdown(request: "web.Request") -> "web.Response":
    """
    Get detailed breakdown of metrics.

    Query Parameters:
        minutes: Number of minutes of data (default: 60)
        by: Breakdown type - provider, model, department, rule, decision

    Returns:
        JSON response with breakdown data.
    """
    from aiohttp import web

    try:
        minutes = int(request.query.get("minutes", "60"))
        minutes = max(1, min(1440, minutes))
        by = request.query.get("by", "decision")

        collector = get_collector()
        now = utc_now()
        since = now - timedelta(minutes=minutes)
        summary = collector.get_summary(since, now)

        result: dict[str, Any] = {
            "generated_at": now.isoformat(),
            "period_minutes": minutes,
            "total_requests": summary.total_requests,
        }

        if by == "provider":
            result["breakdown"] = summary.requests_by_provider
        elif by == "model":
            result["breakdown"] = summary.requests_by_model
        elif by == "department":
            result["breakdown"] = summary.requests_by_department
        elif by == "rule":
            result["breakdown"] = dict(summary.top_rules)
        else:  # decision
            result["breakdown"] = summary.decisions

        # Calculate percentages
        total = summary.total_requests or 1
        result["percentages"] = {
            k: round(v / total * 100, 2)
            for k, v in result["breakdown"].items()
        }

        return web.json_response(result)

    except Exception as e:
        logger.exception(f"Dashboard breakdown error: {e}")
        return web.json_response(
            {"error": {"code": "DASHBOARD_ERROR", "message": str(e)}},
            status=500,
        )


async def dashboard_latency(request: "web.Request") -> "web.Response":
    """
    Get detailed latency metrics.

    Query Parameters:
        minutes: Number of minutes of data (default: 60)

    Returns:
        JSON response with latency percentiles and distribution.
    """
    from aiohttp import web

    try:
        minutes = int(request.query.get("minutes", "60"))
        minutes = max(1, min(1440, minutes))

        collector = get_collector()
        now = utc_now()
        since = now - timedelta(minutes=minutes)
        summary = collector.get_summary(since, now)

        result = {
            "generated_at": now.isoformat(),
            "period_minutes": minutes,
            "total_requests": summary.total_requests,
            "latency": {
                "avg_ms": round(summary.avg_latency_ms, 2),
                "min_ms": round(summary.min_latency_ms, 2),
                "max_ms": round(summary.max_latency_ms, 2),
                "p50_ms": round(summary.p50_latency_ms, 2),
                "p95_ms": round(summary.p95_latency_ms, 2),
                "p99_ms": round(summary.p99_latency_ms, 2),
            },
        }

        return web.json_response(result)

    except Exception as e:
        logger.exception(f"Dashboard latency error: {e}")
        return web.json_response(
            {"error": {"code": "DASHBOARD_ERROR", "message": str(e)}},
            status=500,
        )


async def dashboard_alerts(request: "web.Request") -> "web.Response":
    """
    Get current dashboard alerts.

    Returns:
        JSON response with active alerts.
    """
    from aiohttp import web

    try:
        dashboard = _get_dashboard_metrics(request.app)
        data = dashboard.get_dashboard_data(trend_minutes=5)

        return web.json_response({
            "generated_at": data.generated_at.isoformat(),
            "alerts": data.alerts,
            "alert_count": len(data.alerts),
            "critical_count": sum(
                1 for a in data.alerts if a["level"] == "critical"
            ),
            "warning_count": sum(
                1 for a in data.alerts if a["level"] == "warning"
            ),
        })

    except Exception as e:
        logger.exception(f"Dashboard alerts error: {e}")
        return web.json_response(
            {"error": {"code": "DASHBOARD_ERROR", "message": str(e)}},
            status=500,
        )


async def dashboard_prometheus(request: "web.Request") -> "web.Response":
    """
    Get metrics in Prometheus format.

    Returns:
        Text response with Prometheus-format metrics.
    """
    from aiohttp import web

    try:
        dashboard = _get_dashboard_metrics(request.app)

        # Update policy rules count
        policy_set = request.app.get("policy_set")
        if policy_set:
            dashboard.set_policy_rules_count(len(policy_set.rules))

        metrics_text = dashboard.get_prometheus_metrics()

        response = web.Response(body=metrics_text.encode("utf-8"))
        response.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
        return response

    except Exception as e:
        logger.exception(f"Dashboard prometheus error: {e}")
        return web.Response(
            body=f"# Error: {e}".encode("utf-8"),
            status=500,
        )
