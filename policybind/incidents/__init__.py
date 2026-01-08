"""
Incident management for PolicyBind.

This module provides incident tracking and management for policy violations
and AI safety events, including automated detection, investigation workflows,
and reporting.
"""

from policybind.incidents.detector import (
    DetectionMatch,
    DetectionWindow,
    IncidentDetector,
)
from policybind.incidents.manager import (
    IncidentCallback,
    IncidentEvent,
    IncidentManager,
)
from policybind.incidents.models import (
    DetectionRule,
    Incident,
    IncidentComment,
    IncidentMetrics,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    IncidentType,
    TimelineEventType,
)
from policybind.incidents.reports import (
    IncidentReporter,
    ReportFormat,
    ReportMetrics,
    TrendDataPoint,
)
from policybind.incidents.workflows import (
    IncidentInvestigationWorkflow,
    IncidentRemediationWorkflow,
    IncidentTriageWorkflow,
    RemediationAction,
    RemediationStep,
    TriageDecision,
    TriageRule,
    WorkflowStep,
    WorkflowStepStatus,
)

__all__ = [
    # Models
    "DetectionRule",
    "Incident",
    "IncidentComment",
    "IncidentMetrics",
    "IncidentSeverity",
    "IncidentStatus",
    "IncidentTimelineEntry",
    "IncidentType",
    "TimelineEventType",
    # Manager
    "IncidentCallback",
    "IncidentEvent",
    "IncidentManager",
    # Detector
    "DetectionMatch",
    "DetectionWindow",
    "IncidentDetector",
    # Workflows
    "IncidentInvestigationWorkflow",
    "IncidentRemediationWorkflow",
    "IncidentTriageWorkflow",
    "RemediationAction",
    "RemediationStep",
    "TriageDecision",
    "TriageRule",
    "WorkflowStep",
    "WorkflowStepStatus",
    # Reports
    "IncidentReporter",
    "ReportFormat",
    "ReportMetrics",
    "TrendDataPoint",
]
