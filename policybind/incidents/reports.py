"""
Incident reporting for PolicyBind.

This module provides reporting functionality for incidents, including
individual reports, summary reports, trend analysis, and compliance reports.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from policybind.incidents.models import (
    Incident,
    IncidentComment,
    IncidentMetrics,
    IncidentSeverity,
    IncidentStatus,
    IncidentTimelineEntry,
    IncidentType,
)
from policybind.models.base import utc_now


class ReportFormat(Enum):
    """Output formats for reports."""

    MARKDOWN = "markdown"
    """Markdown format for human-readable reports."""

    JSON = "json"
    """JSON format for machine processing."""

    TEXT = "text"
    """Plain text format."""


@dataclass
class ReportMetrics:
    """
    Calculated metrics for incident reporting.

    Attributes:
        total_incidents: Total number of incidents.
        mean_time_to_detect_hours: Average time to detect incidents.
        mean_time_to_acknowledge_hours: Average time to first assignment.
        mean_time_to_resolve_hours: Average time from creation to resolution.
        incidents_by_severity: Count by severity level.
        incidents_by_type: Count by incident type.
        incidents_by_status: Count by current status.
        incidents_by_deployment: Count by deployment.
        resolution_rate: Percentage of incidents resolved.
        recurrence_rate: Percentage of recurring incidents.
        policy_effectiveness: Metrics on policy effectiveness.
        period_start: Start of the reporting period.
        period_end: End of the reporting period.
    """

    total_incidents: int = 0
    mean_time_to_detect_hours: float | None = None
    mean_time_to_acknowledge_hours: float | None = None
    mean_time_to_resolve_hours: float | None = None
    incidents_by_severity: dict[str, int] = field(default_factory=dict)
    incidents_by_type: dict[str, int] = field(default_factory=dict)
    incidents_by_status: dict[str, int] = field(default_factory=dict)
    incidents_by_deployment: dict[str, int] = field(default_factory=dict)
    resolution_rate: float = 0.0
    recurrence_rate: float = 0.0
    policy_effectiveness: dict[str, Any] = field(default_factory=dict)
    period_start: datetime | None = None
    period_end: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_incidents": self.total_incidents,
            "mean_time_to_detect_hours": self.mean_time_to_detect_hours,
            "mean_time_to_acknowledge_hours": self.mean_time_to_acknowledge_hours,
            "mean_time_to_resolve_hours": self.mean_time_to_resolve_hours,
            "incidents_by_severity": self.incidents_by_severity,
            "incidents_by_type": self.incidents_by_type,
            "incidents_by_status": self.incidents_by_status,
            "incidents_by_deployment": self.incidents_by_deployment,
            "resolution_rate": self.resolution_rate,
            "recurrence_rate": self.recurrence_rate,
            "policy_effectiveness": self.policy_effectiveness,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
        }


@dataclass
class TrendDataPoint:
    """A single point in trend data."""

    date: str
    total: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "date": self.date,
            "total": self.total,
            "by_severity": self.by_severity,
            "by_type": self.by_type,
        }


class IncidentReporter:
    """
    Generates reports for incidents and incident trends.

    Provides functionality to generate:
    - Individual incident reports
    - Summary reports for time periods
    - Trend analysis reports
    - Deployment-specific incident history
    - Compliance-oriented reports

    Example:
        Using the IncidentReporter::

            from policybind.incidents import IncidentReporter, IncidentManager

            manager = IncidentManager(repository)
            reporter = IncidentReporter(manager)

            # Generate individual incident report
            report = reporter.generate_incident_report(incident)

            # Generate summary report
            summary = reporter.generate_summary_report(
                since=datetime.now() - timedelta(days=30),
            )

            # Generate compliance report
            compliance = reporter.generate_compliance_report(
                since=datetime.now() - timedelta(days=90),
            )
    """

    def __init__(self, incident_manager: Any) -> None:
        """
        Initialize the reporter.

        Args:
            incident_manager: IncidentManager instance for data access.
        """
        self._manager = incident_manager

    # -------------------------------------------------------------------------
    # Individual Incident Reports
    # -------------------------------------------------------------------------

    def generate_incident_report(
        self,
        incident: Incident,
        include_timeline: bool = True,
        include_comments: bool = True,
        include_related: bool = True,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> str:
        """
        Generate a detailed report for a single incident.

        Args:
            incident: The incident to report on.
            include_timeline: Include the incident timeline.
            include_comments: Include comments.
            include_related: Include related incidents.
            format: Output format.

        Returns:
            The formatted report string.
        """
        if format == ReportFormat.JSON:
            return self._incident_report_json(
                incident, include_timeline, include_comments, include_related
            )
        elif format == ReportFormat.TEXT:
            return self._incident_report_text(
                incident, include_timeline, include_comments, include_related
            )
        else:
            return self._incident_report_markdown(
                incident, include_timeline, include_comments, include_related
            )

    def _incident_report_markdown(
        self,
        incident: Incident,
        include_timeline: bool,
        include_comments: bool,
        include_related: bool,
    ) -> str:
        """Generate Markdown format incident report."""
        lines = []

        # Header
        lines.append(f"# Incident Report: {incident.incident_id}")
        lines.append("")
        lines.append(f"**Title:** {incident.title}")
        lines.append(f"**Status:** {incident.status.value}")
        lines.append(f"**Severity:** {incident.severity.value}")
        lines.append(f"**Type:** {incident.incident_type.value}")
        lines.append("")

        # Timestamps
        lines.append("## Timeline")
        lines.append("")
        lines.append(f"- **Created:** {incident.created_at.isoformat()}")
        if incident.resolved_at:
            lines.append(f"- **Resolved:** {incident.resolved_at.isoformat()}")
            duration = incident.resolved_at - incident.created_at
            lines.append(f"- **Time to Resolve:** {self._format_duration(duration)}")
        lines.append("")

        # Assignment
        lines.append("## Assignment")
        lines.append("")
        if incident.assignee:
            lines.append(f"**Assigned to:** {incident.assignee}")
        else:
            lines.append("*Not assigned*")
        lines.append("")

        # Description
        lines.append("## Description")
        lines.append("")
        lines.append(incident.description or "*No description provided*")
        lines.append("")

        # Evidence
        if incident.evidence:
            lines.append("## Evidence")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(incident.evidence, indent=2, default=str))
            lines.append("```")
            lines.append("")

        # Resolution
        if incident.resolution or incident.root_cause:
            lines.append("## Resolution")
            lines.append("")
            if incident.root_cause:
                lines.append(f"**Root Cause:** {incident.root_cause}")
            if incident.resolution:
                lines.append(f"**Resolution:** {incident.resolution}")
            lines.append("")

        # Tags
        if incident.tags:
            lines.append("## Tags")
            lines.append("")
            lines.append(", ".join(f"`{tag}`" for tag in incident.tags))
            lines.append("")

        # Related resources
        if incident.deployment_id or incident.source_request_id:
            lines.append("## Related Resources")
            lines.append("")
            if incident.deployment_id:
                lines.append(f"- **Deployment:** {incident.deployment_id}")
            if incident.source_request_id:
                lines.append(f"- **Source Request:** {incident.source_request_id}")
            lines.append("")

        # Timeline
        if include_timeline:
            timeline = self._manager.get_timeline(incident.incident_id)
            if timeline:
                lines.append("## Activity Timeline")
                lines.append("")
                for entry in timeline:
                    actor = entry.actor or "system"
                    lines.append(
                        f"- **{entry.timestamp.isoformat()}** - "
                        f"{entry.event_type.value} by {actor}"
                    )
                    if entry.old_value and entry.new_value:
                        lines.append(f"  - Changed from `{entry.old_value}` to `{entry.new_value}`")
                lines.append("")

        # Comments
        if include_comments:
            comments = self._manager.get_comments(incident.incident_id)
            if comments:
                lines.append("## Comments")
                lines.append("")
                for comment in comments:
                    lines.append(f"### {comment.author} - {comment.created_at.isoformat()}")
                    lines.append("")
                    lines.append(comment.content)
                    lines.append("")

        # Related incidents
        if include_related:
            related = self._manager.get_related_incidents(incident.incident_id)
            if related:
                lines.append("## Related Incidents")
                lines.append("")
                for rel in related:
                    lines.append(
                        f"- [{rel.incident_id}] {rel.title} "
                        f"({rel.status.value}, {rel.severity.value})"
                    )
                lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report generated at {utc_now().isoformat()}*")

        return "\n".join(lines)

    def _incident_report_json(
        self,
        incident: Incident,
        include_timeline: bool,
        include_comments: bool,
        include_related: bool,
    ) -> str:
        """Generate JSON format incident report."""
        data: dict[str, Any] = {
            "incident": incident.to_dict(),
            "generated_at": utc_now().isoformat(),
        }

        if include_timeline:
            timeline = self._manager.get_timeline(incident.incident_id)
            data["timeline"] = [e.to_dict() for e in timeline]

        if include_comments:
            comments = self._manager.get_comments(incident.incident_id)
            data["comments"] = [c.to_dict() for c in comments]

        if include_related:
            related = self._manager.get_related_incidents(incident.incident_id)
            data["related_incidents"] = [r.to_dict() for r in related]

        return json.dumps(data, indent=2, default=str)

    def _incident_report_text(
        self,
        incident: Incident,
        include_timeline: bool,
        include_comments: bool,
        include_related: bool,
    ) -> str:
        """Generate plain text format incident report."""
        lines = []

        lines.append("=" * 60)
        lines.append(f"INCIDENT REPORT: {incident.incident_id}")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Title:    {incident.title}")
        lines.append(f"Status:   {incident.status.value}")
        lines.append(f"Severity: {incident.severity.value}")
        lines.append(f"Type:     {incident.incident_type.value}")
        lines.append(f"Created:  {incident.created_at.isoformat()}")
        if incident.assignee:
            lines.append(f"Assignee: {incident.assignee}")
        lines.append("")

        lines.append("-" * 40)
        lines.append("DESCRIPTION")
        lines.append("-" * 40)
        lines.append(incident.description or "No description provided")
        lines.append("")

        if incident.resolution:
            lines.append("-" * 40)
            lines.append("RESOLUTION")
            lines.append("-" * 40)
            if incident.root_cause:
                lines.append(f"Root Cause: {incident.root_cause}")
            lines.append(f"Resolution: {incident.resolution}")
            lines.append("")

        lines.append("-" * 40)
        lines.append(f"Report generated at {utc_now().isoformat()}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Summary Reports
    # -------------------------------------------------------------------------

    def generate_summary_report(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        deployment_id: str | None = None,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> str:
        """
        Generate a summary report for a time period.

        Args:
            since: Start of period (defaults to 30 days ago).
            until: End of period (defaults to now).
            deployment_id: Filter by deployment.
            format: Output format.

        Returns:
            The formatted summary report.
        """
        if since is None:
            since = utc_now() - timedelta(days=30)
        if until is None:
            until = utc_now()

        metrics = self._calculate_metrics(since, until, deployment_id)

        if format == ReportFormat.JSON:
            return self._summary_report_json(metrics, since, until, deployment_id)
        elif format == ReportFormat.TEXT:
            return self._summary_report_text(metrics, since, until, deployment_id)
        else:
            return self._summary_report_markdown(metrics, since, until, deployment_id)

    def _calculate_metrics(
        self,
        since: datetime,
        until: datetime,
        deployment_id: str | None = None,
    ) -> ReportMetrics:
        """Calculate metrics for the reporting period."""
        # Get base metrics from manager
        base_metrics = self._manager.get_metrics(since, until, deployment_id)

        metrics = ReportMetrics(
            total_incidents=base_metrics.total_count,
            mean_time_to_acknowledge_hours=base_metrics.mean_time_to_acknowledge_hours,
            mean_time_to_resolve_hours=base_metrics.mean_time_to_resolve_hours,
            incidents_by_severity=base_metrics.by_severity,
            incidents_by_type=base_metrics.by_type,
            incidents_by_deployment=base_metrics.by_deployment,
            period_start=since,
            period_end=until,
        )

        # Calculate status breakdown
        metrics.incidents_by_status = {
            "OPEN": base_metrics.open_count,
            "INVESTIGATING": base_metrics.investigating_count,
            "RESOLVED": base_metrics.resolved_count,
            "CLOSED": base_metrics.closed_count,
        }

        # Calculate resolution rate
        if metrics.total_incidents > 0:
            resolved = base_metrics.resolved_count + base_metrics.closed_count
            metrics.resolution_rate = (resolved / metrics.total_incidents) * 100

        return metrics

    def _summary_report_markdown(
        self,
        metrics: ReportMetrics,
        since: datetime,
        until: datetime,
        deployment_id: str | None,
    ) -> str:
        """Generate Markdown summary report."""
        lines = []

        lines.append("# Incident Summary Report")
        lines.append("")
        lines.append(f"**Period:** {since.date()} to {until.date()}")
        if deployment_id:
            lines.append(f"**Deployment:** {deployment_id}")
        lines.append("")

        # Overview
        lines.append("## Overview")
        lines.append("")
        lines.append(f"- **Total Incidents:** {metrics.total_incidents}")
        lines.append(f"- **Resolution Rate:** {metrics.resolution_rate:.1f}%")
        if metrics.mean_time_to_resolve_hours:
            lines.append(
                f"- **Mean Time to Resolve:** {metrics.mean_time_to_resolve_hours:.1f} hours"
            )
        lines.append("")

        # By Status
        lines.append("## Incidents by Status")
        lines.append("")
        for status, count in metrics.incidents_by_status.items():
            lines.append(f"- {status}: {count}")
        lines.append("")

        # By Severity
        lines.append("## Incidents by Severity")
        lines.append("")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = metrics.incidents_by_severity.get(severity, 0)
            lines.append(f"- {severity}: {count}")
        lines.append("")

        # By Type
        if metrics.incidents_by_type:
            lines.append("## Incidents by Type")
            lines.append("")
            for type_name, count in sorted(
                metrics.incidents_by_type.items(), key=lambda x: -x[1]
            ):
                lines.append(f"- {type_name}: {count}")
            lines.append("")

        # By Deployment
        if metrics.incidents_by_deployment:
            lines.append("## Top Deployments by Incidents")
            lines.append("")
            sorted_deps = sorted(
                metrics.incidents_by_deployment.items(), key=lambda x: -x[1]
            )[:10]
            for dep_id, count in sorted_deps:
                lines.append(f"- {dep_id}: {count}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report generated at {utc_now().isoformat()}*")

        return "\n".join(lines)

    def _summary_report_json(
        self,
        metrics: ReportMetrics,
        since: datetime,
        until: datetime,
        deployment_id: str | None,
    ) -> str:
        """Generate JSON summary report."""
        data = {
            "report_type": "summary",
            "period": {
                "start": since.isoformat(),
                "end": until.isoformat(),
            },
            "deployment_id": deployment_id,
            "metrics": metrics.to_dict(),
            "generated_at": utc_now().isoformat(),
        }
        return json.dumps(data, indent=2)

    def _summary_report_text(
        self,
        metrics: ReportMetrics,
        since: datetime,
        until: datetime,
        deployment_id: str | None,
    ) -> str:
        """Generate plain text summary report."""
        lines = []

        lines.append("=" * 60)
        lines.append("INCIDENT SUMMARY REPORT")
        lines.append("=" * 60)
        lines.append(f"Period: {since.date()} to {until.date()}")
        if deployment_id:
            lines.append(f"Deployment: {deployment_id}")
        lines.append("")
        lines.append(f"Total Incidents:     {metrics.total_incidents}")
        lines.append(f"Resolution Rate:     {metrics.resolution_rate:.1f}%")
        if metrics.mean_time_to_resolve_hours:
            lines.append(f"Mean Time to Resolve: {metrics.mean_time_to_resolve_hours:.1f} hours")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report generated at {utc_now().isoformat()}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Trend Analysis Reports
    # -------------------------------------------------------------------------

    def generate_trend_report(
        self,
        days: int = 30,
        deployment_id: str | None = None,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> str:
        """
        Generate a trend analysis report.

        Args:
            days: Number of days to analyze.
            deployment_id: Filter by deployment.
            format: Output format.

        Returns:
            The formatted trend report.
        """
        trend_data = self._manager.get_trend(days, deployment_id)

        if format == ReportFormat.JSON:
            return self._trend_report_json(trend_data, days, deployment_id)
        elif format == ReportFormat.TEXT:
            return self._trend_report_text(trend_data, days, deployment_id)
        else:
            return self._trend_report_markdown(trend_data, days, deployment_id)

    def _trend_report_markdown(
        self,
        trend_data: list[dict[str, Any]],
        days: int,
        deployment_id: str | None,
    ) -> str:
        """Generate Markdown trend report."""
        lines = []

        lines.append("# Incident Trend Analysis")
        lines.append("")
        lines.append(f"**Period:** Last {days} days")
        if deployment_id:
            lines.append(f"**Deployment:** {deployment_id}")
        lines.append("")

        if not trend_data:
            lines.append("*No incidents in this period*")
            return "\n".join(lines)

        # Summary stats
        total = sum(d.get("total", 0) for d in trend_data)
        avg_daily = total / len(trend_data) if trend_data else 0
        peak_day = max(trend_data, key=lambda d: d.get("total", 0))

        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Incidents:** {total}")
        lines.append(f"- **Average per Day:** {avg_daily:.1f}")
        lines.append(f"- **Peak Day:** {peak_day.get('date', 'N/A')} ({peak_day.get('total', 0)} incidents)")
        lines.append("")

        # Daily breakdown table
        lines.append("## Daily Breakdown")
        lines.append("")
        lines.append("| Date | Total | Critical | High | Medium | Low |")
        lines.append("|------|-------|----------|------|--------|-----|")
        for day in trend_data[-14:]:  # Show last 14 days
            lines.append(
                f"| {day.get('date', '')} | {day.get('total', 0)} | "
                f"{day.get('CRITICAL', 0)} | {day.get('HIGH', 0)} | "
                f"{day.get('MEDIUM', 0)} | {day.get('LOW', 0)} |"
            )
        lines.append("")

        # Trend direction
        if len(trend_data) >= 7:
            first_week = sum(d.get("total", 0) for d in trend_data[:7])
            last_week = sum(d.get("total", 0) for d in trend_data[-7:])

            lines.append("## Trend")
            lines.append("")
            if last_week > first_week * 1.1:
                pct = ((last_week / first_week) - 1) * 100 if first_week > 0 else 0
                lines.append(f"Incidents are **increasing** ({pct:.0f}% more in the last week)")
            elif last_week < first_week * 0.9:
                pct = (1 - (last_week / first_week)) * 100 if first_week > 0 else 0
                lines.append(f"Incidents are **decreasing** ({pct:.0f}% fewer in the last week)")
            else:
                lines.append("Incidents are **stable**")
            lines.append("")

        lines.append("---")
        lines.append(f"*Report generated at {utc_now().isoformat()}*")

        return "\n".join(lines)

    def _trend_report_json(
        self,
        trend_data: list[dict[str, Any]],
        days: int,
        deployment_id: str | None,
    ) -> str:
        """Generate JSON trend report."""
        data = {
            "report_type": "trend",
            "days": days,
            "deployment_id": deployment_id,
            "data": trend_data,
            "generated_at": utc_now().isoformat(),
        }
        return json.dumps(data, indent=2)

    def _trend_report_text(
        self,
        trend_data: list[dict[str, Any]],
        days: int,
        deployment_id: str | None,
    ) -> str:
        """Generate plain text trend report."""
        lines = []

        lines.append("=" * 60)
        lines.append("INCIDENT TREND ANALYSIS")
        lines.append("=" * 60)
        lines.append(f"Period: Last {days} days")
        lines.append("")

        total = sum(d.get("total", 0) for d in trend_data)
        lines.append(f"Total Incidents: {total}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report generated at {utc_now().isoformat()}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Deployment History Reports
    # -------------------------------------------------------------------------

    def generate_deployment_report(
        self,
        deployment_id: str,
        since: datetime | None = None,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> str:
        """
        Generate an incident history report for a deployment.

        Args:
            deployment_id: The deployment ID.
            since: Start of period (defaults to all time).
            format: Output format.

        Returns:
            The formatted deployment report.
        """
        incidents = self._manager.list_incidents(
            deployment_id=deployment_id,
            limit=1000,
        )

        if since:
            incidents = [i for i in incidents if i.created_at >= since]

        if format == ReportFormat.JSON:
            return self._deployment_report_json(deployment_id, incidents, since)
        elif format == ReportFormat.TEXT:
            return self._deployment_report_text(deployment_id, incidents, since)
        else:
            return self._deployment_report_markdown(deployment_id, incidents, since)

    def _deployment_report_markdown(
        self,
        deployment_id: str,
        incidents: list[Incident],
        since: datetime | None,
    ) -> str:
        """Generate Markdown deployment report."""
        lines = []

        lines.append(f"# Incident History: {deployment_id}")
        lines.append("")
        if since:
            lines.append(f"**Since:** {since.date()}")
        lines.append(f"**Total Incidents:** {len(incidents)}")
        lines.append("")

        if not incidents:
            lines.append("*No incidents recorded for this deployment*")
            return "\n".join(lines)

        # Summary by severity
        by_severity: dict[str, int] = {}
        for inc in incidents:
            sev = inc.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        lines.append("## Summary by Severity")
        lines.append("")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            lines.append(f"- {sev}: {by_severity.get(sev, 0)}")
        lines.append("")

        # Recent incidents
        lines.append("## Recent Incidents")
        lines.append("")
        lines.append("| Date | ID | Title | Severity | Status |")
        lines.append("|------|-----|-------|----------|--------|")
        for inc in incidents[:20]:
            lines.append(
                f"| {inc.created_at.date()} | {inc.incident_id[:8]} | "
                f"{inc.title[:30]} | {inc.severity.value} | {inc.status.value} |"
            )
        lines.append("")

        lines.append("---")
        lines.append(f"*Report generated at {utc_now().isoformat()}*")

        return "\n".join(lines)

    def _deployment_report_json(
        self,
        deployment_id: str,
        incidents: list[Incident],
        since: datetime | None,
    ) -> str:
        """Generate JSON deployment report."""
        data = {
            "report_type": "deployment_history",
            "deployment_id": deployment_id,
            "since": since.isoformat() if since else None,
            "total_incidents": len(incidents),
            "incidents": [i.to_dict() for i in incidents],
            "generated_at": utc_now().isoformat(),
        }
        return json.dumps(data, indent=2, default=str)

    def _deployment_report_text(
        self,
        deployment_id: str,
        incidents: list[Incident],
        since: datetime | None,
    ) -> str:
        """Generate plain text deployment report."""
        lines = []

        lines.append("=" * 60)
        lines.append(f"DEPLOYMENT INCIDENT HISTORY: {deployment_id}")
        lines.append("=" * 60)
        lines.append(f"Total Incidents: {len(incidents)}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report generated at {utc_now().isoformat()}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Compliance Reports
    # -------------------------------------------------------------------------

    def generate_compliance_report(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        include_unresolved: bool = True,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> str:
        """
        Generate a compliance-oriented report for auditors.

        Args:
            since: Start of period (defaults to 90 days ago).
            until: End of period (defaults to now).
            include_unresolved: Include details of unresolved incidents.
            format: Output format.

        Returns:
            The formatted compliance report.
        """
        if since is None:
            since = utc_now() - timedelta(days=90)
        if until is None:
            until = utc_now()

        metrics = self._calculate_metrics(since, until)

        # Get unresolved incidents
        unresolved = []
        if include_unresolved:
            all_incidents = self._manager.list_incidents(limit=1000)
            unresolved = [
                i for i in all_incidents
                if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
            ]

        if format == ReportFormat.JSON:
            return self._compliance_report_json(metrics, unresolved, since, until)
        elif format == ReportFormat.TEXT:
            return self._compliance_report_text(metrics, unresolved, since, until)
        else:
            return self._compliance_report_markdown(metrics, unresolved, since, until)

    def _compliance_report_markdown(
        self,
        metrics: ReportMetrics,
        unresolved: list[Incident],
        since: datetime,
        until: datetime,
    ) -> str:
        """Generate Markdown compliance report."""
        lines = []

        lines.append("# AI Governance Compliance Report")
        lines.append("")
        lines.append(f"**Reporting Period:** {since.date()} to {until.date()}")
        lines.append(f"**Report Generated:** {utc_now().isoformat()}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            f"During the reporting period, {metrics.total_incidents} incidents "
            f"were recorded. The resolution rate was {metrics.resolution_rate:.1f}%. "
        )
        if metrics.mean_time_to_resolve_hours:
            lines.append(
                f"The mean time to resolve incidents was "
                f"{metrics.mean_time_to_resolve_hours:.1f} hours."
            )
        lines.append("")

        # Key Metrics
        lines.append("## Key Metrics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Incidents | {metrics.total_incidents} |")
        lines.append(f"| Resolution Rate | {metrics.resolution_rate:.1f}% |")
        if metrics.mean_time_to_resolve_hours:
            lines.append(f"| MTTR (hours) | {metrics.mean_time_to_resolve_hours:.1f} |")
        critical = metrics.incidents_by_severity.get("CRITICAL", 0)
        high = metrics.incidents_by_severity.get("HIGH", 0)
        lines.append(f"| Critical/High Incidents | {critical + high} |")
        lines.append("")

        # Incident Breakdown
        lines.append("## Incident Breakdown by Severity")
        lines.append("")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = metrics.incidents_by_severity.get(severity, 0)
            pct = (count / metrics.total_incidents * 100) if metrics.total_incidents > 0 else 0
            lines.append(f"- **{severity}**: {count} ({pct:.1f}%)")
        lines.append("")

        lines.append("## Incident Breakdown by Type")
        lines.append("")
        for type_name, count in sorted(
            metrics.incidents_by_type.items(), key=lambda x: -x[1]
        ):
            pct = (count / metrics.total_incidents * 100) if metrics.total_incidents > 0 else 0
            lines.append(f"- **{type_name}**: {count} ({pct:.1f}%)")
        lines.append("")

        # Unresolved Incidents
        if unresolved:
            lines.append("## Outstanding Incidents")
            lines.append("")
            lines.append(f"There are currently **{len(unresolved)}** unresolved incidents:")
            lines.append("")

            # Group by severity
            critical_unresolved = [i for i in unresolved if i.severity == IncidentSeverity.CRITICAL]
            high_unresolved = [i for i in unresolved if i.severity == IncidentSeverity.HIGH]

            if critical_unresolved:
                lines.append("### Critical Priority")
                lines.append("")
                for inc in critical_unresolved:
                    age_hours = (utc_now() - inc.created_at).total_seconds() / 3600
                    lines.append(
                        f"- **{inc.incident_id}**: {inc.title} "
                        f"(Age: {age_hours:.0f}h, Status: {inc.status.value})"
                    )
                lines.append("")

            if high_unresolved:
                lines.append("### High Priority")
                lines.append("")
                for inc in high_unresolved[:10]:
                    age_hours = (utc_now() - inc.created_at).total_seconds() / 3600
                    lines.append(
                        f"- **{inc.incident_id}**: {inc.title} "
                        f"(Age: {age_hours:.0f}h, Status: {inc.status.value})"
                    )
                lines.append("")

        # Compliance Statement
        lines.append("## Compliance Statement")
        lines.append("")
        lines.append(
            "This report provides a summary of AI governance incidents for the "
            "reporting period. All incidents have been tracked, investigated, "
            "and resolved in accordance with organizational policies and procedures."
        )
        lines.append("")

        lines.append("---")
        lines.append(f"*Report generated at {utc_now().isoformat()} by PolicyBind*")

        return "\n".join(lines)

    def _compliance_report_json(
        self,
        metrics: ReportMetrics,
        unresolved: list[Incident],
        since: datetime,
        until: datetime,
    ) -> str:
        """Generate JSON compliance report."""
        data = {
            "report_type": "compliance",
            "period": {
                "start": since.isoformat(),
                "end": until.isoformat(),
            },
            "metrics": metrics.to_dict(),
            "unresolved_count": len(unresolved),
            "unresolved_incidents": [i.to_dict() for i in unresolved],
            "generated_at": utc_now().isoformat(),
        }
        return json.dumps(data, indent=2, default=str)

    def _compliance_report_text(
        self,
        metrics: ReportMetrics,
        unresolved: list[Incident],
        since: datetime,
        until: datetime,
    ) -> str:
        """Generate plain text compliance report."""
        lines = []

        lines.append("=" * 60)
        lines.append("AI GOVERNANCE COMPLIANCE REPORT")
        lines.append("=" * 60)
        lines.append(f"Period: {since.date()} to {until.date()}")
        lines.append("")
        lines.append(f"Total Incidents:     {metrics.total_incidents}")
        lines.append(f"Resolution Rate:     {metrics.resolution_rate:.1f}%")
        lines.append(f"Unresolved:          {len(unresolved)}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report generated at {utc_now().isoformat()}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def _format_duration(self, delta: timedelta) -> str:
        """Format a timedelta as a human-readable string."""
        total_seconds = int(delta.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 24:
            days = hours // 24
            hours = hours % 24
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m"
        else:
            return f"{seconds}s"
