"""
Simulation API handlers for PolicyBind.

This module provides HTTP handlers for policy simulation endpoints
including dry-run enforcement, what-if analysis, and batch simulation.
"""

import json
import logging
from typing import TYPE_CHECKING, Any

from policybind.models.policy import PolicyRule, PolicySet
from policybind.models.request import AIRequest
from policybind.server.auth import AuthContext, Role
from policybind.simulation import (
    BatchSimulationResult,
    ImpactAnalysis,
    PolicyComparison,
    PolicySimulator,
    SimulationMode,
    SimulationOptions,
    SimulationResult,
    WhatIfAnalyzer,
    WhatIfScenario,
)

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.simulation")

# Global simulator instances
_simulator: PolicySimulator | None = None
_analyzer: WhatIfAnalyzer | None = None


def get_simulator() -> PolicySimulator | None:
    """Get the global policy simulator."""
    return _simulator


def set_simulator(simulator: PolicySimulator | None) -> None:
    """Set the global policy simulator."""
    global _simulator
    _simulator = simulator


def get_analyzer() -> WhatIfAnalyzer | None:
    """Get the global what-if analyzer."""
    return _analyzer


def set_analyzer(analyzer: WhatIfAnalyzer | None) -> None:
    """Set the global what-if analyzer."""
    global _analyzer
    _analyzer = analyzer


def init_simulation(policy_set: PolicySet) -> None:
    """Initialize simulation with a policy set."""
    global _simulator, _analyzer
    _simulator = PolicySimulator(policy_set)
    _analyzer = WhatIfAnalyzer(policy_set)


def _require_read_access(request: "web.Request") -> AuthContext:
    """Require at least read access."""
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())
    if auth_context.role not in (Role.READER, Role.ENFORCER, Role.OPERATOR, Role.ADMIN):
        if not auth_context.authenticated:
            raise web.HTTPUnauthorized(
                text=json.dumps({"error": "Authentication required"}),
                content_type="application/json",
            )
    return auth_context


def _require_operator_access(request: "web.Request") -> AuthContext:
    """Require operator or admin access."""
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())
    if auth_context.role not in (Role.OPERATOR, Role.ADMIN):
        raise web.HTTPForbidden(
            text=json.dumps({"error": "Operator access required"}),
            content_type="application/json",
        )
    return auth_context


def _parse_request(data: dict[str, Any]) -> AIRequest:
    """Parse an AIRequest from request data."""
    return AIRequest(
        request_id=data.get("request_id", ""),
        provider=data.get("provider", ""),
        model=data.get("model", ""),
        user_id=data.get("user_id", ""),
        department=data.get("department", ""),
        source_application=data.get("source_application", ""),
        intended_use_case=data.get("intended_use_case", ""),
        data_classification=tuple(data.get("data_classification", [])),
        estimated_cost=data.get("estimated_cost", 0.0),
        estimated_tokens=data.get("estimated_tokens", 0),
        metadata=data.get("metadata", {}),
    )


def _parse_simulation_options(data: dict[str, Any]) -> SimulationOptions:
    """Parse SimulationOptions from request data."""
    mode_str = data.get("mode", "dry_run")
    try:
        mode = SimulationMode(mode_str)
    except ValueError:
        mode = SimulationMode.DRY_RUN

    return SimulationOptions(
        mode=mode,
        include_all_matches=data.get("include_all_matches", True),
        include_timing=data.get("include_timing", True),
        include_conditions=data.get("include_conditions", True),
        include_trace=data.get("include_trace", False),
        max_rules=data.get("max_rules", 100),
        context_overrides=data.get("context_overrides", {}),
    )


# =============================================================================
# Simulation Endpoints
# =============================================================================


async def simulate_request(request: "web.Request") -> "web.Response":
    """
    Simulate policy enforcement for a request.

    POST /v1/simulate

    Body:
        {
            "request": {
                "provider": "openai",
                "model": "gpt-4",
                "user_id": "user-123",
                ...
            },
            "options": {
                "mode": "dry_run",
                "include_trace": true,
                ...
            }
        }

    Returns:
        Simulation result with decision and details.
    """
    from aiohttp import web

    _require_read_access(request)

    if not _simulator:
        return web.json_response(
            {"error": "Simulation is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse the request
    request_data = data.get("request", {})
    if not request_data:
        return web.json_response(
            {"error": "Request data is required"},
            status=400,
        )

    ai_request = _parse_request(request_data)
    options = _parse_simulation_options(data.get("options", {}))

    # Run simulation
    result = _simulator.simulate(ai_request, options)

    logger.info(
        f"Simulated request {ai_request.request_id}: "
        f"decision={result.decision.value}, rule={result.applied_rule}"
    )

    return web.json_response(result.to_dict())


async def simulate_batch(request: "web.Request") -> "web.Response":
    """
    Simulate policy enforcement for multiple requests.

    POST /v1/simulate/batch

    Body:
        {
            "requests": [
                {"provider": "openai", "model": "gpt-4", ...},
                {"provider": "anthropic", "model": "claude-3", ...}
            ],
            "options": {
                "mode": "dry_run",
                ...
            }
        }

    Returns:
        Batch simulation result with summary and individual results.
    """
    from aiohttp import web

    _require_operator_access(request)

    if not _simulator:
        return web.json_response(
            {"error": "Simulation is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse requests
    requests_data = data.get("requests", [])
    if not requests_data:
        return web.json_response(
            {"error": "At least one request is required"},
            status=400,
        )

    ai_requests = [_parse_request(r) for r in requests_data]
    options = _parse_simulation_options(data.get("options", {}))

    # Run batch simulation
    batch_result = _simulator.simulate_batch(ai_requests, options)

    # Option to exclude individual results for large batches
    include_results = data.get("include_results", len(ai_requests) <= 100)

    logger.info(
        f"Batch simulation: {batch_result.summary.total_requests} requests, "
        f"allowed={batch_result.summary.allowed}, denied={batch_result.summary.denied}"
    )

    return web.json_response(batch_result.to_dict(include_results=include_results))


async def simulate_explain(request: "web.Request") -> "web.Response":
    """
    Get a human-readable explanation of a simulation.

    POST /v1/simulate/explain

    Body:
        {
            "request": {
                "provider": "openai",
                "model": "gpt-4",
                ...
            }
        }

    Returns:
        Text explanation of the simulation result.
    """
    from aiohttp import web

    _require_read_access(request)

    if not _simulator:
        return web.json_response(
            {"error": "Simulation is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    request_data = data.get("request", {})
    if not request_data:
        return web.json_response(
            {"error": "Request data is required"},
            status=400,
        )

    ai_request = _parse_request(request_data)

    # Run simulation with trace
    options = SimulationOptions(
        include_all_matches=True,
        include_conditions=True,
        include_trace=True,
    )
    result = _simulator.simulate(ai_request, options)

    # Generate explanation
    explanation = _simulator.explain_decision(result)

    return web.json_response({
        "explanation": explanation,
        "decision": result.decision.value,
        "applied_rule": result.applied_rule,
    })


# =============================================================================
# What-If Analysis Endpoints
# =============================================================================


async def whatif_analyze(request: "web.Request") -> "web.Response":
    """
    Perform what-if analysis for a scenario.

    POST /v1/simulate/whatif

    Body:
        {
            "request": {
                "provider": "openai",
                "model": "gpt-4",
                ...
            },
            "scenario": {
                "name": "Test stricter rules",
                "rules_to_add": [...],
                "rules_to_remove": ["old_rule"],
                "context_changes": {}
            }
        }

    Returns:
        What-if analysis result.
    """
    from aiohttp import web

    _require_operator_access(request)

    if not _analyzer:
        return web.json_response(
            {"error": "What-if analysis is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse request
    request_data = data.get("request", {})
    if not request_data:
        return web.json_response(
            {"error": "Request data is required"},
            status=400,
        )

    ai_request = _parse_request(request_data)

    # Parse scenario
    scenario_data = data.get("scenario", {})
    if not scenario_data:
        return web.json_response(
            {"error": "Scenario is required"},
            status=400,
        )

    # Parse rules to add
    rules_to_add = []
    for rule_data in scenario_data.get("rules_to_add", []):
        rules_to_add.append(PolicyRule(
            name=rule_data.get("name", ""),
            description=rule_data.get("description", ""),
            match_conditions=rule_data.get("match_conditions", {}),
            action=rule_data.get("action", "DENY"),
            action_params=rule_data.get("action_params", {}),
            priority=rule_data.get("priority", 0),
            enabled=rule_data.get("enabled", True),
        ))

    scenario = WhatIfScenario(
        name=scenario_data.get("name", "Unnamed scenario"),
        description=scenario_data.get("description", ""),
        rules_to_add=rules_to_add,
        rules_to_remove=scenario_data.get("rules_to_remove", []),
        rules_to_modify=scenario_data.get("rules_to_modify", {}),
        context_changes=scenario_data.get("context_changes", {}),
    )

    # Run analysis
    result = _analyzer.analyze_scenario(ai_request, scenario)

    logger.info(
        f"What-if analysis for '{scenario.name}': "
        f"decision_changed={result.decision_changed}"
    )

    return web.json_response(result.to_dict())


async def whatif_impact(request: "web.Request") -> "web.Response":
    """
    Analyze impact of proposed policy changes.

    POST /v1/simulate/whatif/impact

    Body:
        {
            "requests": [
                {"provider": "openai", "model": "gpt-4", ...},
                ...
            ],
            "scenario": {
                "name": "Add new department restrictions",
                "rules_to_add": [...],
                ...
            }
        }

    Returns:
        Impact analysis with statistics and recommendations.
    """
    from aiohttp import web

    _require_operator_access(request)

    if not _analyzer:
        return web.json_response(
            {"error": "What-if analysis is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse requests
    requests_data = data.get("requests", [])
    if not requests_data:
        return web.json_response(
            {"error": "At least one request is required"},
            status=400,
        )

    ai_requests = [_parse_request(r) for r in requests_data]

    # Parse scenario
    scenario_data = data.get("scenario", {})
    if not scenario_data:
        return web.json_response(
            {"error": "Scenario is required"},
            status=400,
        )

    # Parse rules to add
    rules_to_add = []
    for rule_data in scenario_data.get("rules_to_add", []):
        rules_to_add.append(PolicyRule(
            name=rule_data.get("name", ""),
            description=rule_data.get("description", ""),
            match_conditions=rule_data.get("match_conditions", {}),
            action=rule_data.get("action", "DENY"),
            action_params=rule_data.get("action_params", {}),
            priority=rule_data.get("priority", 0),
            enabled=rule_data.get("enabled", True),
        ))

    scenario = WhatIfScenario(
        name=scenario_data.get("name", "Impact analysis"),
        description=scenario_data.get("description", ""),
        rules_to_add=rules_to_add,
        rules_to_remove=scenario_data.get("rules_to_remove", []),
        rules_to_modify=scenario_data.get("rules_to_modify", {}),
    )

    # Run impact analysis
    analysis = _analyzer.analyze_impact(scenario, ai_requests)

    logger.info(
        f"Impact analysis for '{scenario.name}': "
        f"{analysis.requests_affected}/{analysis.total_requests_analyzed} affected"
    )

    return web.json_response(analysis.to_dict())


async def whatif_compare(request: "web.Request") -> "web.Response":
    """
    Compare two policy versions.

    POST /v1/simulate/whatif/compare

    Body:
        {
            "requests": [...],
            "policy_a": {
                "name": "Current",
                "version": "1.0",
                "rules": [...]
            },
            "policy_b": {
                "name": "Proposed",
                "version": "2.0",
                "rules": [...]
            }
        }

    Returns:
        Policy comparison results.
    """
    from aiohttp import web

    _require_operator_access(request)

    if not _analyzer:
        return web.json_response(
            {"error": "What-if analysis is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse requests
    requests_data = data.get("requests", [])
    if not requests_data:
        return web.json_response(
            {"error": "At least one request is required"},
            status=400,
        )

    ai_requests = [_parse_request(r) for r in requests_data]

    # Parse policies
    def parse_policy(policy_data: dict) -> PolicySet:
        rules = []
        for rule_data in policy_data.get("rules", []):
            rules.append(PolicyRule(
                name=rule_data.get("name", ""),
                description=rule_data.get("description", ""),
                match_conditions=rule_data.get("match_conditions", {}),
                action=rule_data.get("action", "DENY"),
                action_params=rule_data.get("action_params", {}),
                priority=rule_data.get("priority", 0),
                enabled=rule_data.get("enabled", True),
            ))
        return PolicySet(
            name=policy_data.get("name", ""),
            version=policy_data.get("version", ""),
            rules=rules,
        )

    policy_a_data = data.get("policy_a", {})
    policy_b_data = data.get("policy_b", {})

    if not policy_a_data or not policy_b_data:
        return web.json_response(
            {"error": "Both policy_a and policy_b are required"},
            status=400,
        )

    policy_a = parse_policy(policy_a_data)
    policy_b = parse_policy(policy_b_data)

    # Run comparison
    comparison = _analyzer.compare_policies(policy_a, policy_b, ai_requests)

    logger.info(
        f"Policy comparison: {comparison.policy_a_version} vs {comparison.policy_b_version}, "
        f"agreement={comparison.get_agreement_rate():.1f}%"
    )

    return web.json_response(comparison.to_dict())


# =============================================================================
# Rule Analysis Endpoints
# =============================================================================


async def analyze_rule(request: "web.Request") -> "web.Response":
    """
    Analyze the impact of a specific rule.

    POST /v1/simulate/rule/analyze

    Body:
        {
            "rule": {
                "name": "block_expensive",
                "match_conditions": {"cost": {"gt": 1.0}},
                "action": "DENY",
                ...
            },
            "requests": [...]
        }

    Returns:
        Rule impact analysis.
    """
    from aiohttp import web

    _require_operator_access(request)

    if not _analyzer:
        return web.json_response(
            {"error": "Analysis is not initialized"},
            status=503,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    # Parse rule
    rule_data = data.get("rule", {})
    if not rule_data:
        return web.json_response(
            {"error": "Rule is required"},
            status=400,
        )

    rule = PolicyRule(
        name=rule_data.get("name", ""),
        description=rule_data.get("description", ""),
        match_conditions=rule_data.get("match_conditions", {}),
        action=rule_data.get("action", "DENY"),
        action_params=rule_data.get("action_params", {}),
        priority=rule_data.get("priority", 0),
        enabled=rule_data.get("enabled", True),
    )

    # Parse requests
    requests_data = data.get("requests", [])
    if not requests_data:
        return web.json_response(
            {"error": "At least one request is required"},
            status=400,
        )

    ai_requests = [_parse_request(r) for r in requests_data]

    # Run analysis
    impact = _analyzer.analyze_rule_impact(rule, ai_requests)

    logger.info(
        f"Rule analysis for '{rule.name}': "
        f"matched {impact.matched_count}/{impact.total_requests} requests"
    )

    return web.json_response(impact.to_dict())


async def get_simulation_status(request: "web.Request") -> "web.Response":
    """
    Get simulation system status.

    GET /v1/simulate/status

    Returns:
        Status information about the simulation system.
    """
    from aiohttp import web

    _require_read_access(request)

    status = {
        "simulator_initialized": _simulator is not None,
        "analyzer_initialized": _analyzer is not None,
    }

    if _simulator:
        policy = _simulator.get_policy_set()
        status["policy_name"] = policy.name
        status["policy_version"] = policy.version
        status["rule_count"] = len(policy.rules)
        status["enabled_rules"] = len(policy.get_enabled_rules())

    return web.json_response(status)
