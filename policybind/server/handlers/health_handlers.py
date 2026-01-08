"""
Health and readiness check handlers.

This module provides handlers for health, readiness, and metrics endpoints.
"""

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.health")


# Metrics storage (simple in-memory counters)
_metrics: dict[str, Any] = {
    "requests_total": 0,
    "requests_by_status": {},
    "enforcement_requests_total": 0,
    "enforcement_latency_sum_ms": 0.0,
    "enforcement_latency_count": 0,
    "start_time": time.time(),
}


def record_request(status_code: int) -> None:
    """Record a request for metrics."""
    _metrics["requests_total"] += 1
    status_str = str(status_code)
    if status_str not in _metrics["requests_by_status"]:
        _metrics["requests_by_status"][status_str] = 0
    _metrics["requests_by_status"][status_str] += 1


def record_enforcement(latency_ms: float) -> None:
    """Record an enforcement request for metrics."""
    _metrics["enforcement_requests_total"] += 1
    _metrics["enforcement_latency_sum_ms"] += latency_ms
    _metrics["enforcement_latency_count"] += 1


async def health_check(request: "web.Request") -> "web.Response":
    """
    Health check endpoint.

    Returns a simple OK response to indicate the server is running.
    This endpoint is suitable for load balancer health checks.

    Returns:
        JSON response with status "healthy".
    """
    from aiohttp import web

    return web.json_response({
        "status": "healthy",
        "timestamp": time.time(),
    })


async def readiness_check(request: "web.Request") -> "web.Response":
    """
    Readiness check endpoint.

    Checks that all dependencies are available and the server is
    ready to accept requests.

    Returns:
        JSON response with readiness status and component checks.
    """
    from aiohttp import web

    app = request.app

    checks: dict[str, dict[str, Any]] = {}
    all_ready = True

    # Check database connection
    try:
        database = app.get("database")
        if database:
            # Try a simple query
            database.execute("SELECT 1")
            checks["database"] = {"status": "ready"}
        else:
            checks["database"] = {"status": "not_configured"}
    except Exception as e:
        checks["database"] = {"status": "error", "message": str(e)}
        all_ready = False

    # Check policy set is loaded
    try:
        policy_set = app.get("policy_set")
        if policy_set:
            checks["policies"] = {
                "status": "ready",
                "rule_count": len(policy_set.rules),
            }
        else:
            checks["policies"] = {"status": "not_loaded"}
            all_ready = False
    except Exception as e:
        checks["policies"] = {"status": "error", "message": str(e)}
        all_ready = False

    # Check enforcement pipeline
    try:
        pipeline = app.get("pipeline")
        if pipeline:
            checks["enforcement"] = {"status": "ready"}
        else:
            checks["enforcement"] = {"status": "not_configured"}
            all_ready = False
    except Exception as e:
        checks["enforcement"] = {"status": "error", "message": str(e)}
        all_ready = False

    status_code = 200 if all_ready else 503
    status = "ready" if all_ready else "not_ready"

    return web.json_response(
        {
            "status": status,
            "checks": checks,
            "timestamp": time.time(),
        },
        status=status_code,
    )


async def metrics(request: "web.Request") -> "web.Response":
    """
    Prometheus-format metrics endpoint.

    Returns metrics in Prometheus text format for scraping.

    Returns:
        Text response with Prometheus metrics.
    """
    from aiohttp import web

    uptime = time.time() - _metrics["start_time"]

    # Calculate average enforcement latency
    avg_latency = 0.0
    if _metrics["enforcement_latency_count"] > 0:
        avg_latency = (
            _metrics["enforcement_latency_sum_ms"] / _metrics["enforcement_latency_count"]
        )

    lines = [
        "# HELP policybind_up PolicyBind server is up",
        "# TYPE policybind_up gauge",
        "policybind_up 1",
        "",
        "# HELP policybind_uptime_seconds Server uptime in seconds",
        "# TYPE policybind_uptime_seconds counter",
        f"policybind_uptime_seconds {uptime:.2f}",
        "",
        "# HELP policybind_requests_total Total HTTP requests",
        "# TYPE policybind_requests_total counter",
        f"policybind_requests_total {_metrics['requests_total']}",
        "",
        "# HELP policybind_requests_by_status HTTP requests by status code",
        "# TYPE policybind_requests_by_status counter",
    ]

    for status, count in _metrics["requests_by_status"].items():
        lines.append(f'policybind_requests_by_status{{status="{status}"}} {count}')

    lines.extend([
        "",
        "# HELP policybind_enforcement_requests_total Total enforcement requests",
        "# TYPE policybind_enforcement_requests_total counter",
        f"policybind_enforcement_requests_total {_metrics['enforcement_requests_total']}",
        "",
        "# HELP policybind_enforcement_latency_avg_ms Average enforcement latency in ms",
        "# TYPE policybind_enforcement_latency_avg_ms gauge",
        f"policybind_enforcement_latency_avg_ms {avg_latency:.2f}",
        "",
    ])

    # Add app-specific metrics if available
    app = request.app
    policy_set = app.get("policy_set")
    if policy_set:
        lines.extend([
            "# HELP policybind_policy_rules_total Number of active policy rules",
            "# TYPE policybind_policy_rules_total gauge",
            f"policybind_policy_rules_total {len(policy_set.rules)}",
            "",
        ])

    response = web.Response(
        body="\n".join(lines).encode("utf-8"),
    )
    response.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    return response
