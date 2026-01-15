"""
Policy simulation and dry-run mode for PolicyBind.

This package provides simulation capabilities for testing policies
without affecting real enforcement, including what-if analysis,
batch simulation, and policy impact assessment.

Modules:
    models: Simulation result data models
    simulator: PolicySimulator for dry-run enforcement
    analyzer: What-if analysis and impact assessment
"""

from policybind.simulation.analyzer import (
    ImpactAnalysis,
    PolicyComparison,
    RuleImpact,
    WhatIfAnalyzer,
    WhatIfResult,
    WhatIfScenario,
)
from policybind.simulation.models import (
    BatchSimulationResult,
    SimulationMode,
    SimulationOptions,
    SimulationResult,
    SimulationSummary,
)
from policybind.simulation.simulator import (
    PolicySimulator,
)

__all__ = [
    # Models
    "SimulationMode",
    "SimulationOptions",
    "SimulationResult",
    "SimulationSummary",
    "BatchSimulationResult",
    # Simulator
    "PolicySimulator",
    # Analyzer
    "WhatIfAnalyzer",
    "WhatIfScenario",
    "WhatIfResult",
    "ImpactAnalysis",
    "PolicyComparison",
    "RuleImpact",
]
