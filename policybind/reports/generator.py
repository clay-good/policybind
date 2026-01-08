"""
Report generation for PolicyBind.

This module provides the ReportGenerator class for creating various types
of reports in multiple formats (JSON, Markdown, HTML, PDF).
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from string import Template
from typing import Any

from policybind.models.base import utc_now

logger = logging.getLogger("policybind.reports.generator")


class ReportFormat(Enum):
    """Output formats for reports."""

    JSON = "json"
    """JSON format for machine processing."""

    MARKDOWN = "markdown"
    """Markdown format for human-readable reports."""

    HTML = "html"
    """HTML format with embedded styling."""

    TEXT = "text"
    """Plain text format."""


class ReportType(Enum):
    """Types of reports that can be generated."""

    POLICY_COMPLIANCE = "policy_compliance"
    """Policy compliance report showing rule coverage and effectiveness."""

    USAGE_COST = "usage_cost"
    """Usage and cost report showing API consumption and spending."""

    INCIDENT_SUMMARY = "incident_summary"
    """Incident summary report with metrics and trends."""

    AUDIT_TRAIL = "audit_trail"
    """Audit trail report for compliance purposes."""

    RISK_ASSESSMENT = "risk_assessment"
    """Risk assessment report for deployments."""

    REGISTRY_STATUS = "registry_status"
    """Registry status report showing deployment inventory."""


@dataclass
class ReportMetadata:
    """
    Metadata for a generated report.

    Attributes:
        report_id: Unique identifier for the report.
        report_type: Type of report.
        format: Output format.
        generated_at: When the report was generated.
        generated_by: Who generated the report.
        period_start: Start of the reporting period.
        period_end: End of the reporting period.
        parameters: Parameters used to generate the report.
        checksum: SHA-256 checksum of the report content.
    """

    report_id: str
    report_type: ReportType
    format: ReportFormat
    generated_at: datetime
    generated_by: str = "system"
    period_start: datetime | None = None
    period_end: datetime | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    checksum: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "format": self.format.value,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "parameters": self.parameters,
            "checksum": self.checksum,
        }


@dataclass
class BrandingConfig:
    """
    Branding configuration for reports.

    Attributes:
        organization_name: Name of the organization.
        logo_base64: Base64-encoded logo image (PNG/JPEG).
        primary_color: Primary color for styling (hex).
        secondary_color: Secondary color for styling (hex).
        footer_text: Custom footer text.
    """

    organization_name: str = "PolicyBind"
    logo_base64: str | None = None
    primary_color: str = "#2563eb"
    secondary_color: str = "#64748b"
    footer_text: str = ""


class ReportGenerator:
    """
    Generates various types of reports for PolicyBind.

    Supports multiple report types and output formats with customizable
    branding and styling.

    Example:
        Basic report generation::

            from policybind.reports import ReportGenerator, ReportType, ReportFormat

            generator = ReportGenerator(
                policy_repository=policy_repo,
                registry_repository=registry_repo,
                audit_repository=audit_repo,
                incident_manager=incident_mgr,
            )

            # Generate a policy compliance report
            report = generator.generate(
                report_type=ReportType.POLICY_COMPLIANCE,
                format=ReportFormat.HTML,
                since=datetime.now() - timedelta(days=30),
            )

            # Save the report
            with open("compliance_report.html", "w") as f:
                f.write(report)
    """

    def __init__(
        self,
        policy_repository: Any | None = None,
        registry_repository: Any | None = None,
        audit_repository: Any | None = None,
        incident_manager: Any | None = None,
        token_manager: Any | None = None,
        branding: BrandingConfig | None = None,
    ) -> None:
        """
        Initialize the report generator.

        Args:
            policy_repository: Repository for policy data.
            registry_repository: Repository for registry data.
            audit_repository: Repository for audit logs.
            incident_manager: Manager for incident data.
            token_manager: Manager for token data.
            branding: Branding configuration for reports.
        """
        self._policy_repo = policy_repository
        self._registry_repo = registry_repository
        self._audit_repo = audit_repository
        self._incident_mgr = incident_manager
        self._token_mgr = token_manager
        self._branding = branding or BrandingConfig()

    def generate(
        self,
        report_type: ReportType,
        format: ReportFormat = ReportFormat.MARKDOWN,
        since: datetime | None = None,
        until: datetime | None = None,
        deployment_id: str | None = None,
        generated_by: str = "system",
        **kwargs: Any,
    ) -> str:
        """
        Generate a report of the specified type.

        Args:
            report_type: Type of report to generate.
            format: Output format.
            since: Start of reporting period (defaults based on report type).
            until: End of reporting period (defaults to now).
            deployment_id: Filter by deployment (optional).
            generated_by: Who is generating the report.
            **kwargs: Additional parameters specific to report type.

        Returns:
            The generated report as a string.

        Raises:
            ValueError: If required repositories are not configured.
        """
        if until is None:
            until = utc_now()

        # Set default period based on report type
        if since is None:
            if report_type == ReportType.AUDIT_TRAIL:
                since = until - timedelta(days=90)
            elif report_type == ReportType.INCIDENT_SUMMARY:
                since = until - timedelta(days=30)
            else:
                since = until - timedelta(days=30)

        # Generate report based on type
        if report_type == ReportType.POLICY_COMPLIANCE:
            data = self._collect_policy_compliance_data(since, until, deployment_id)
        elif report_type == ReportType.USAGE_COST:
            data = self._collect_usage_cost_data(since, until, deployment_id)
        elif report_type == ReportType.INCIDENT_SUMMARY:
            data = self._collect_incident_summary_data(since, until, deployment_id)
        elif report_type == ReportType.AUDIT_TRAIL:
            data = self._collect_audit_trail_data(since, until, deployment_id, **kwargs)
        elif report_type == ReportType.RISK_ASSESSMENT:
            data = self._collect_risk_assessment_data(deployment_id)
        elif report_type == ReportType.REGISTRY_STATUS:
            data = self._collect_registry_status_data()
        else:
            raise ValueError(f"Unknown report type: {report_type}")

        # Create metadata
        import uuid

        metadata = ReportMetadata(
            report_id=str(uuid.uuid4()),
            report_type=report_type,
            format=format,
            generated_at=utc_now(),
            generated_by=generated_by,
            period_start=since,
            period_end=until,
            parameters={"deployment_id": deployment_id, **kwargs},
        )

        # Format the report
        if format == ReportFormat.JSON:
            report = self._format_json(report_type, data, metadata)
        elif format == ReportFormat.HTML:
            report = self._format_html(report_type, data, metadata)
        elif format == ReportFormat.TEXT:
            report = self._format_text(report_type, data, metadata)
        else:
            report = self._format_markdown(report_type, data, metadata)

        # Calculate checksum
        metadata.checksum = hashlib.sha256(report.encode()).hexdigest()

        return report

    # -------------------------------------------------------------------------
    # Data Collection Methods
    # -------------------------------------------------------------------------

    def _collect_policy_compliance_data(
        self,
        since: datetime,
        until: datetime,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        """Collect data for policy compliance report."""
        data: dict[str, Any] = {
            "period": {"start": since, "end": until},
            "deployment_id": deployment_id,
            "policies": [],
            "enforcement_stats": {},
            "rule_effectiveness": [],
            "compliance_score": 0.0,
        }

        # Get current policies
        if self._policy_repo:
            try:
                policy_set = self._policy_repo.get_current()
                if policy_set:
                    data["policies"] = [
                        {
                            "name": r.name,
                            "description": r.description,
                            "enabled": r.enabled,
                            "priority": r.priority,
                            "tags": list(r.tags) if r.tags else [],
                        }
                        for r in policy_set.rules
                    ]
                    data["policy_version"] = policy_set.version
                    data["total_rules"] = len(policy_set.rules)
                    data["enabled_rules"] = sum(1 for r in policy_set.rules if r.enabled)
            except Exception as e:
                logger.warning(f"Failed to get policies: {e}")

        # Get enforcement statistics
        if self._audit_repo:
            try:
                stats = self._audit_repo.get_enforcement_stats(since, until)
                data["enforcement_stats"] = stats

                # Calculate compliance score
                total = stats.get("total_requests", 0)
                allowed = stats.get("by_decision", {}).get("ALLOW", 0)
                denied = stats.get("by_decision", {}).get("DENY", 0)

                if total > 0:
                    # Higher score = more allowed requests (policies working as expected)
                    data["compliance_score"] = (allowed / total) * 100

                # Get rule trigger counts
                rule_stats = stats.get("by_rule", {})
                data["rule_effectiveness"] = [
                    {"rule": rule, "triggers": count}
                    for rule, count in sorted(rule_stats.items(), key=lambda x: -x[1])
                ]
            except Exception as e:
                logger.warning(f"Failed to get enforcement stats: {e}")

        return data

    def _collect_usage_cost_data(
        self,
        since: datetime,
        until: datetime,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        """Collect data for usage and cost report."""
        data: dict[str, Any] = {
            "period": {"start": since, "end": until},
            "deployment_id": deployment_id,
            "total_requests": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
            "by_deployment": [],
            "by_model": [],
            "by_department": [],
            "daily_usage": [],
        }

        if self._audit_repo:
            try:
                # Get usage statistics
                stats = self._audit_repo.get_enforcement_stats(since, until)
                data["total_requests"] = stats.get("total_requests", 0)

                # Get detailed breakdowns
                if hasattr(self._audit_repo, "get_usage_by_deployment"):
                    data["by_deployment"] = self._audit_repo.get_usage_by_deployment(
                        since, until
                    )

                if hasattr(self._audit_repo, "get_usage_by_model"):
                    data["by_model"] = self._audit_repo.get_usage_by_model(since, until)

                if hasattr(self._audit_repo, "get_usage_by_department"):
                    data["by_department"] = self._audit_repo.get_usage_by_department(
                        since, until
                    )

                # Calculate daily usage trend
                days = (until - since).days
                if hasattr(self._audit_repo, "get_daily_counts"):
                    data["daily_usage"] = self._audit_repo.get_daily_counts(since, until)
                else:
                    # Estimate daily average
                    avg_daily = data["total_requests"] / days if days > 0 else 0
                    data["average_daily_requests"] = avg_daily

            except Exception as e:
                logger.warning(f"Failed to get usage stats: {e}")

        # Get token budget usage
        if self._token_mgr:
            try:
                if hasattr(self._token_mgr, "get_budget_summary"):
                    data["budget_summary"] = self._token_mgr.get_budget_summary(since, until)
            except Exception as e:
                logger.warning(f"Failed to get budget summary: {e}")

        return data

    def _collect_incident_summary_data(
        self,
        since: datetime,
        until: datetime,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        """Collect data for incident summary report."""
        data: dict[str, Any] = {
            "period": {"start": since, "end": until},
            "deployment_id": deployment_id,
            "total_incidents": 0,
            "by_severity": {},
            "by_type": {},
            "by_status": {},
            "resolution_rate": 0.0,
            "mttr_hours": None,
            "recent_incidents": [],
            "unresolved": [],
        }

        if self._incident_mgr:
            try:
                metrics = self._incident_mgr.get_metrics(since, until, deployment_id)
                data["total_incidents"] = metrics.total_count
                data["by_severity"] = metrics.by_severity
                data["by_type"] = metrics.by_type
                data["mttr_hours"] = metrics.mean_time_to_resolve_hours

                data["by_status"] = {
                    "OPEN": metrics.open_count,
                    "INVESTIGATING": metrics.investigating_count,
                    "RESOLVED": metrics.resolved_count,
                    "CLOSED": metrics.closed_count,
                }

                # Calculate resolution rate
                if data["total_incidents"] > 0:
                    resolved = metrics.resolved_count + metrics.closed_count
                    data["resolution_rate"] = (resolved / data["total_incidents"]) * 100

                # Get recent incidents
                recent = self._incident_mgr.list_incidents(limit=10)
                data["recent_incidents"] = [
                    {
                        "id": i.incident_id,
                        "title": i.title,
                        "severity": i.severity.value,
                        "status": i.status.value,
                        "created_at": i.created_at.isoformat(),
                    }
                    for i in recent
                ]

                # Get unresolved incidents
                all_incidents = self._incident_mgr.list_incidents(limit=1000)
                unresolved = [
                    i for i in all_incidents
                    if i.status.value in ("OPEN", "INVESTIGATING")
                ]
                data["unresolved"] = [
                    {
                        "id": i.incident_id,
                        "title": i.title,
                        "severity": i.severity.value,
                        "created_at": i.created_at.isoformat(),
                        "age_hours": (utc_now() - i.created_at).total_seconds() / 3600,
                    }
                    for i in unresolved
                ]

            except Exception as e:
                logger.warning(f"Failed to get incident metrics: {e}")

        return data

    def _collect_audit_trail_data(
        self,
        since: datetime,
        until: datetime,
        deployment_id: str | None = None,
        limit: int = 1000,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Collect data for audit trail report."""
        data: dict[str, Any] = {
            "period": {"start": since, "end": until},
            "deployment_id": deployment_id,
            "total_entries": 0,
            "entries": [],
            "summary": {},
        }

        if self._audit_repo:
            try:
                # Get enforcement logs
                logs = self._audit_repo.query_enforcement_logs(
                    start_date=since,
                    end_date=until,
                    deployment_id=deployment_id,
                    limit=limit,
                )
                data["entries"] = logs
                data["total_entries"] = len(logs)

                # Get summary statistics
                stats = self._audit_repo.get_enforcement_stats(since, until)
                data["summary"] = {
                    "total_requests": stats.get("total_requests", 0),
                    "by_decision": stats.get("by_decision", {}),
                    "by_department": stats.get("by_department", {}),
                }

            except Exception as e:
                logger.warning(f"Failed to get audit logs: {e}")

        return data

    def _collect_risk_assessment_data(
        self,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        """Collect data for risk assessment report."""
        data: dict[str, Any] = {
            "deployment_id": deployment_id,
            "deployments": [],
            "risk_summary": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
            "compliance_gaps": [],
            "recommendations": [],
        }

        if self._registry_repo:
            try:
                if deployment_id:
                    deployment = self._registry_repo.get(deployment_id)
                    if deployment:
                        data["deployments"] = [self._deployment_to_dict(deployment)]
                else:
                    deployments = self._registry_repo.list_deployments(limit=1000)
                    data["deployments"] = [
                        self._deployment_to_dict(d) for d in deployments
                    ]

                # Calculate risk summary
                for dep in data["deployments"]:
                    risk = dep.get("risk_level", "MEDIUM")
                    data["risk_summary"][risk] = data["risk_summary"].get(risk, 0) + 1

                # Generate recommendations based on risk
                high_risk = [d for d in data["deployments"] if d.get("risk_level") in ("CRITICAL", "HIGH")]
                if high_risk:
                    data["recommendations"].append({
                        "priority": "HIGH",
                        "message": f"{len(high_risk)} deployments require immediate review",
                        "affected": [d["deployment_id"] for d in high_risk[:5]],
                    })

                # Check for compliance gaps
                for dep in data["deployments"]:
                    if dep.get("approval_status") == "PENDING":
                        data["compliance_gaps"].append({
                            "deployment_id": dep["deployment_id"],
                            "gap": "Pending approval",
                            "severity": "MEDIUM",
                        })
                    if not dep.get("last_review_date"):
                        data["compliance_gaps"].append({
                            "deployment_id": dep["deployment_id"],
                            "gap": "Never reviewed",
                            "severity": "HIGH",
                        })

            except Exception as e:
                logger.warning(f"Failed to get registry data: {e}")

        return data

    def _collect_registry_status_data(self) -> dict[str, Any]:
        """Collect data for registry status report."""
        data: dict[str, Any] = {
            "total_deployments": 0,
            "by_status": {},
            "by_risk_level": {},
            "by_provider": {},
            "deployments": [],
            "pending_approvals": [],
            "recently_updated": [],
        }

        if self._registry_repo:
            try:
                deployments = self._registry_repo.list_deployments(limit=1000)
                data["total_deployments"] = len(deployments)

                for dep in deployments:
                    dep_dict = self._deployment_to_dict(dep)
                    data["deployments"].append(dep_dict)

                    # Count by status
                    status = dep_dict.get("approval_status", "UNKNOWN")
                    data["by_status"][status] = data["by_status"].get(status, 0) + 1

                    # Count by risk level
                    risk = dep_dict.get("risk_level", "MEDIUM")
                    data["by_risk_level"][risk] = data["by_risk_level"].get(risk, 0) + 1

                    # Count by provider
                    provider = dep_dict.get("model_provider", "unknown")
                    data["by_provider"][provider] = data["by_provider"].get(provider, 0) + 1

                    # Track pending approvals
                    if status == "PENDING":
                        data["pending_approvals"].append(dep_dict)

                # Get recently updated
                sorted_deps = sorted(
                    data["deployments"],
                    key=lambda x: x.get("updated_at", ""),
                    reverse=True,
                )
                data["recently_updated"] = sorted_deps[:10]

            except Exception as e:
                logger.warning(f"Failed to get registry data: {e}")

        return data

    def _deployment_to_dict(self, deployment: Any) -> dict[str, Any]:
        """Convert a deployment to a dictionary."""
        if hasattr(deployment, "to_dict"):
            return deployment.to_dict()

        return {
            "deployment_id": getattr(deployment, "deployment_id", None),
            "name": getattr(deployment, "name", None),
            "model_provider": getattr(deployment, "model_provider", None),
            "model_name": getattr(deployment, "model_name", None),
            "owner": getattr(deployment, "owner", None),
            "risk_level": getattr(deployment, "risk_level", None),
            "approval_status": getattr(deployment, "approval_status", None),
            "last_review_date": getattr(deployment, "last_review_date", None),
            "created_at": getattr(deployment, "created_at", None),
            "updated_at": getattr(deployment, "updated_at", None),
        }

    # -------------------------------------------------------------------------
    # Formatting Methods
    # -------------------------------------------------------------------------

    def _format_json(
        self,
        report_type: ReportType,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Format report as JSON."""
        output = {
            "metadata": metadata.to_dict(),
            "data": self._serialize_data(data),
        }
        return json.dumps(output, indent=2, default=str)

    def _serialize_data(self, data: Any) -> Any:
        """Recursively serialize data for JSON output."""
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._serialize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._serialize_data(item) for item in data]
        elif hasattr(data, "to_dict"):
            return self._serialize_data(data.to_dict())
        elif hasattr(data, "value"):  # Enum
            return data.value
        return data

    def _format_markdown(
        self,
        report_type: ReportType,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Format report as Markdown."""
        if report_type == ReportType.POLICY_COMPLIANCE:
            return self._policy_compliance_markdown(data, metadata)
        elif report_type == ReportType.USAGE_COST:
            return self._usage_cost_markdown(data, metadata)
        elif report_type == ReportType.INCIDENT_SUMMARY:
            return self._incident_summary_markdown(data, metadata)
        elif report_type == ReportType.AUDIT_TRAIL:
            return self._audit_trail_markdown(data, metadata)
        elif report_type == ReportType.RISK_ASSESSMENT:
            return self._risk_assessment_markdown(data, metadata)
        elif report_type == ReportType.REGISTRY_STATUS:
            return self._registry_status_markdown(data, metadata)
        else:
            return self._generic_markdown(data, metadata)

    def _format_html(
        self,
        report_type: ReportType,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Format report as HTML with embedded CSS."""
        # Convert markdown to HTML and wrap with styling
        markdown_content = self._format_markdown(report_type, data, metadata)
        return self._wrap_html(markdown_content, metadata)

    def _format_text(
        self,
        report_type: ReportType,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Format report as plain text."""
        if report_type == ReportType.POLICY_COMPLIANCE:
            return self._policy_compliance_text(data, metadata)
        elif report_type == ReportType.USAGE_COST:
            return self._usage_cost_text(data, metadata)
        elif report_type == ReportType.INCIDENT_SUMMARY:
            return self._incident_summary_text(data, metadata)
        elif report_type == ReportType.AUDIT_TRAIL:
            return self._audit_trail_text(data, metadata)
        elif report_type == ReportType.RISK_ASSESSMENT:
            return self._risk_assessment_text(data, metadata)
        elif report_type == ReportType.REGISTRY_STATUS:
            return self._registry_status_text(data, metadata)
        else:
            return self._generic_text(data, metadata)

    # -------------------------------------------------------------------------
    # Policy Compliance Report Formatting
    # -------------------------------------------------------------------------

    def _policy_compliance_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate Markdown policy compliance report."""
        lines = []

        lines.append("# Policy Compliance Report")
        lines.append("")
        lines.append(f"**Organization:** {self._branding.organization_name}")
        period = data.get("period", {})
        if period:
            start = period.get("start")
            end = period.get("end")
            if start and end:
                lines.append(f"**Period:** {self._format_date(start)} to {self._format_date(end)}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        score = data.get("compliance_score", 0)
        total_rules = data.get("total_rules", 0)
        enabled_rules = data.get("enabled_rules", 0)
        lines.append(f"- **Compliance Score:** {score:.1f}%")
        lines.append(f"- **Active Policies:** {enabled_rules} of {total_rules}")
        stats = data.get("enforcement_stats", {})
        total_requests = stats.get("total_requests", 0)
        lines.append(f"- **Total Requests Processed:** {total_requests:,}")
        lines.append("")

        # Decision Breakdown
        lines.append("## Enforcement Decisions")
        lines.append("")
        by_decision = stats.get("by_decision", {})
        if by_decision:
            lines.append("| Decision | Count | Percentage |")
            lines.append("|----------|-------|------------|")
            for decision, count in sorted(by_decision.items()):
                pct = (count / total_requests * 100) if total_requests > 0 else 0
                lines.append(f"| {decision} | {count:,} | {pct:.1f}% |")
            lines.append("")

        # Rule Effectiveness
        rule_effectiveness = data.get("rule_effectiveness", [])
        if rule_effectiveness:
            lines.append("## Most Triggered Rules")
            lines.append("")
            lines.append("| Rule | Triggers |")
            lines.append("|------|----------|")
            for rule in rule_effectiveness[:10]:
                lines.append(f"| {rule['rule']} | {rule['triggers']:,} |")
            lines.append("")

        # Active Policies
        policies = data.get("policies", [])
        if policies:
            lines.append("## Active Policies")
            lines.append("")
            for policy in policies[:20]:
                status = "Enabled" if policy.get("enabled") else "Disabled"
                lines.append(f"- **{policy['name']}** ({status})")
                if policy.get("description"):
                    lines.append(f"  - {policy['description']}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")
        lines.append(f"*{self._branding.footer_text or 'Generated by PolicyBind'}*")

        return "\n".join(lines)

    def _policy_compliance_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate plain text policy compliance report."""
        lines = []

        lines.append("=" * 60)
        lines.append("POLICY COMPLIANCE REPORT")
        lines.append("=" * 60)
        lines.append(f"Organization: {self._branding.organization_name}")
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append(f"Compliance Score: {data.get('compliance_score', 0):.1f}%")
        lines.append(f"Active Rules: {data.get('enabled_rules', 0)} of {data.get('total_rules', 0)}")
        stats = data.get("enforcement_stats", {})
        lines.append(f"Total Requests: {stats.get('total_requests', 0):,}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Usage and Cost Report Formatting
    # -------------------------------------------------------------------------

    def _usage_cost_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate Markdown usage and cost report."""
        lines = []

        lines.append("# Usage and Cost Report")
        lines.append("")
        lines.append(f"**Organization:** {self._branding.organization_name}")
        period = data.get("period", {})
        if period:
            start = period.get("start")
            end = period.get("end")
            if start and end:
                lines.append(f"**Period:** {self._format_date(start)} to {self._format_date(end)}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Requests:** {data.get('total_requests', 0):,}")
        lines.append(f"- **Total Tokens:** {data.get('total_tokens', 0):,}")
        lines.append(f"- **Estimated Cost:** ${data.get('estimated_cost', 0):,.2f}")
        if data.get("average_daily_requests"):
            lines.append(f"- **Average Daily Requests:** {data['average_daily_requests']:.1f}")
        lines.append("")

        # By Deployment
        by_deployment = data.get("by_deployment", [])
        if by_deployment:
            lines.append("## Usage by Deployment")
            lines.append("")
            lines.append("| Deployment | Requests | Cost |")
            lines.append("|------------|----------|------|")
            for dep in by_deployment[:10]:
                lines.append(
                    f"| {dep.get('deployment_id', 'N/A')[:20]} | "
                    f"{dep.get('requests', 0):,} | "
                    f"${dep.get('cost', 0):,.2f} |"
                )
            lines.append("")

        # By Model
        by_model = data.get("by_model", [])
        if by_model:
            lines.append("## Usage by Model")
            lines.append("")
            lines.append("| Model | Requests | Cost |")
            lines.append("|-------|----------|------|")
            for model in by_model[:10]:
                lines.append(
                    f"| {model.get('model', 'N/A')} | "
                    f"{model.get('requests', 0):,} | "
                    f"${model.get('cost', 0):,.2f} |"
                )
            lines.append("")

        # By Department
        by_department = data.get("by_department", [])
        if by_department:
            lines.append("## Usage by Department")
            lines.append("")
            lines.append("| Department | Requests | Cost |")
            lines.append("|------------|----------|------|")
            for dept in by_department[:10]:
                lines.append(
                    f"| {dept.get('department', 'N/A')} | "
                    f"{dept.get('requests', 0):,} | "
                    f"${dept.get('cost', 0):,.2f} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")

        return "\n".join(lines)

    def _usage_cost_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate plain text usage and cost report."""
        lines = []

        lines.append("=" * 60)
        lines.append("USAGE AND COST REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append(f"Total Requests: {data.get('total_requests', 0):,}")
        lines.append(f"Total Tokens:   {data.get('total_tokens', 0):,}")
        lines.append(f"Estimated Cost: ${data.get('estimated_cost', 0):,.2f}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Incident Summary Report Formatting
    # -------------------------------------------------------------------------

    def _incident_summary_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate Markdown incident summary report."""
        lines = []

        lines.append("# Incident Summary Report")
        lines.append("")
        lines.append(f"**Organization:** {self._branding.organization_name}")
        period = data.get("period", {})
        if period:
            start = period.get("start")
            end = period.get("end")
            if start and end:
                lines.append(f"**Period:** {self._format_date(start)} to {self._format_date(end)}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Incidents:** {data.get('total_incidents', 0)}")
        lines.append(f"- **Resolution Rate:** {data.get('resolution_rate', 0):.1f}%")
        if data.get("mttr_hours"):
            lines.append(f"- **Mean Time to Resolve:** {data['mttr_hours']:.1f} hours")
        lines.append("")

        # By Severity
        by_severity = data.get("by_severity", {})
        if by_severity:
            lines.append("## Incidents by Severity")
            lines.append("")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = by_severity.get(sev, 0)
                lines.append(f"- **{sev}:** {count}")
            lines.append("")

        # By Status
        by_status = data.get("by_status", {})
        if by_status:
            lines.append("## Incidents by Status")
            lines.append("")
            for status, count in by_status.items():
                lines.append(f"- **{status}:** {count}")
            lines.append("")

        # Unresolved Incidents
        unresolved = data.get("unresolved", [])
        if unresolved:
            lines.append("## Unresolved Incidents")
            lines.append("")
            lines.append("| ID | Title | Severity | Age (hours) |")
            lines.append("|----|-------|----------|-------------|")
            for inc in unresolved[:10]:
                lines.append(
                    f"| {inc['id'][:8]} | {inc['title'][:30]} | "
                    f"{inc['severity']} | {inc['age_hours']:.0f} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")

        return "\n".join(lines)

    def _incident_summary_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate plain text incident summary report."""
        lines = []

        lines.append("=" * 60)
        lines.append("INCIDENT SUMMARY REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append(f"Total Incidents:  {data.get('total_incidents', 0)}")
        lines.append(f"Resolution Rate:  {data.get('resolution_rate', 0):.1f}%")
        lines.append(f"Unresolved:       {len(data.get('unresolved', []))}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Audit Trail Report Formatting
    # -------------------------------------------------------------------------

    def _audit_trail_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate Markdown audit trail report."""
        lines = []

        lines.append("# Audit Trail Report")
        lines.append("")
        lines.append(f"**Organization:** {self._branding.organization_name}")
        period = data.get("period", {})
        if period:
            start = period.get("start")
            end = period.get("end")
            if start and end:
                lines.append(f"**Period:** {self._format_date(start)} to {self._format_date(end)}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append("")

        # Summary
        summary = data.get("summary", {})
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Entries:** {data.get('total_entries', 0):,}")
        lines.append(f"- **Total Requests:** {summary.get('total_requests', 0):,}")
        lines.append("")

        # Decision breakdown
        by_decision = summary.get("by_decision", {})
        if by_decision:
            lines.append("## Decisions")
            lines.append("")
            for decision, count in sorted(by_decision.items()):
                lines.append(f"- **{decision}:** {count:,}")
            lines.append("")

        # Recent entries (sample)
        entries = data.get("entries", [])
        if entries:
            lines.append("## Sample Entries")
            lines.append("")
            lines.append("| Timestamp | Decision | User | Deployment |")
            lines.append("|-----------|----------|------|------------|")
            for entry in entries[:20]:
                ts = entry.get("timestamp", "N/A")
                if isinstance(ts, datetime):
                    ts = ts.isoformat()
                lines.append(
                    f"| {ts[:19]} | {entry.get('decision', 'N/A')} | "
                    f"{entry.get('user_id', 'N/A')[:15]} | "
                    f"{entry.get('deployment_id', 'N/A')[:15]} |"
                )
            if len(entries) > 20:
                lines.append(f"| ... | ({len(entries) - 20} more entries) | ... | ... |")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")
        lines.append("*This report is intended for compliance and audit purposes.*")

        return "\n".join(lines)

    def _audit_trail_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate plain text audit trail report."""
        lines = []

        lines.append("=" * 60)
        lines.append("AUDIT TRAIL REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append(f"Total Entries: {data.get('total_entries', 0):,}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Risk Assessment Report Formatting
    # -------------------------------------------------------------------------

    def _risk_assessment_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate Markdown risk assessment report."""
        lines = []

        lines.append("# Risk Assessment Report")
        lines.append("")
        lines.append(f"**Organization:** {self._branding.organization_name}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        if data.get("deployment_id"):
            lines.append(f"**Deployment:** {data['deployment_id']}")
        lines.append("")

        # Risk Summary
        risk_summary = data.get("risk_summary", {})
        lines.append("## Risk Summary")
        lines.append("")
        total = sum(risk_summary.values())
        lines.append(f"**Total Deployments:** {total}")
        lines.append("")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = risk_summary.get(level, 0)
            pct = (count / total * 100) if total > 0 else 0
            lines.append(f"- **{level}:** {count} ({pct:.1f}%)")
        lines.append("")

        # Compliance Gaps
        gaps = data.get("compliance_gaps", [])
        if gaps:
            lines.append("## Compliance Gaps")
            lines.append("")
            lines.append("| Deployment | Gap | Severity |")
            lines.append("|------------|-----|----------|")
            for gap in gaps[:20]:
                lines.append(
                    f"| {gap['deployment_id'][:20]} | "
                    f"{gap['gap']} | {gap['severity']} |"
                )
            lines.append("")

        # Recommendations
        recommendations = data.get("recommendations", [])
        if recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for rec in recommendations:
                lines.append(f"### {rec['priority']} Priority")
                lines.append("")
                lines.append(rec["message"])
                if rec.get("affected"):
                    lines.append("")
                    lines.append("Affected deployments:")
                    for dep_id in rec["affected"]:
                        lines.append(f"- {dep_id}")
                lines.append("")

        # High Risk Deployments
        deployments = data.get("deployments", [])
        high_risk = [d for d in deployments if d.get("risk_level") in ("CRITICAL", "HIGH")]
        if high_risk:
            lines.append("## High Risk Deployments")
            lines.append("")
            lines.append("| ID | Name | Risk | Status |")
            lines.append("|----|------|------|--------|")
            for dep in high_risk[:10]:
                lines.append(
                    f"| {dep.get('deployment_id', 'N/A')[:15]} | "
                    f"{dep.get('name', 'N/A')[:20]} | "
                    f"{dep.get('risk_level', 'N/A')} | "
                    f"{dep.get('approval_status', 'N/A')} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")

        return "\n".join(lines)

    def _risk_assessment_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate plain text risk assessment report."""
        lines = []

        lines.append("=" * 60)
        lines.append("RISK ASSESSMENT REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        risk = data.get("risk_summary", {})
        lines.append(f"Critical: {risk.get('CRITICAL', 0)}")
        lines.append(f"High:     {risk.get('HIGH', 0)}")
        lines.append(f"Medium:   {risk.get('MEDIUM', 0)}")
        lines.append(f"Low:      {risk.get('LOW', 0)}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Registry Status Report Formatting
    # -------------------------------------------------------------------------

    def _registry_status_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate Markdown registry status report."""
        lines = []

        lines.append("# Registry Status Report")
        lines.append("")
        lines.append(f"**Organization:** {self._branding.organization_name}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"**Total Deployments:** {data.get('total_deployments', 0)}")
        lines.append("")

        # By Status
        by_status = data.get("by_status", {})
        if by_status:
            lines.append("### By Approval Status")
            lines.append("")
            for status, count in sorted(by_status.items()):
                lines.append(f"- **{status}:** {count}")
            lines.append("")

        # By Risk Level
        by_risk = data.get("by_risk_level", {})
        if by_risk:
            lines.append("### By Risk Level")
            lines.append("")
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = by_risk.get(level, 0)
                lines.append(f"- **{level}:** {count}")
            lines.append("")

        # By Provider
        by_provider = data.get("by_provider", {})
        if by_provider:
            lines.append("### By Provider")
            lines.append("")
            for provider, count in sorted(by_provider.items(), key=lambda x: -x[1]):
                lines.append(f"- **{provider}:** {count}")
            lines.append("")

        # Pending Approvals
        pending = data.get("pending_approvals", [])
        if pending:
            lines.append("## Pending Approvals")
            lines.append("")
            lines.append("| ID | Name | Owner | Risk |")
            lines.append("|----|------|-------|------|")
            for dep in pending[:10]:
                lines.append(
                    f"| {dep.get('deployment_id', 'N/A')[:15]} | "
                    f"{dep.get('name', 'N/A')[:20]} | "
                    f"{dep.get('owner', 'N/A')[:15]} | "
                    f"{dep.get('risk_level', 'N/A')} |"
                )
            lines.append("")

        # Recently Updated
        recent = data.get("recently_updated", [])
        if recent:
            lines.append("## Recently Updated")
            lines.append("")
            lines.append("| ID | Name | Status | Updated |")
            lines.append("|----|------|--------|---------|")
            for dep in recent[:10]:
                updated = dep.get("updated_at", "N/A")
                if isinstance(updated, datetime):
                    updated = updated.strftime("%Y-%m-%d")
                lines.append(
                    f"| {dep.get('deployment_id', 'N/A')[:15]} | "
                    f"{dep.get('name', 'N/A')[:20]} | "
                    f"{dep.get('approval_status', 'N/A')} | "
                    f"{updated} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")

        return "\n".join(lines)

    def _registry_status_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate plain text registry status report."""
        lines = []

        lines.append("=" * 60)
        lines.append("REGISTRY STATUS REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append(f"Total Deployments: {data.get('total_deployments', 0)}")
        lines.append(f"Pending Approvals: {len(data.get('pending_approvals', []))}")
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Generic Formatters
    # -------------------------------------------------------------------------

    def _generic_markdown(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate generic Markdown report."""
        lines = []

        lines.append(f"# {metadata.report_type.value.replace('_', ' ').title()} Report")
        lines.append("")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append("## Data")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(self._serialize_data(data), indent=2))
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append(f"*Report ID: {metadata.report_id}*")

        return "\n".join(lines)

    def _generic_text(
        self,
        data: dict[str, Any],
        metadata: ReportMetadata,
    ) -> str:
        """Generate generic plain text report."""
        lines = []

        lines.append("=" * 60)
        lines.append(f"{metadata.report_type.value.upper().replace('_', ' ')} REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append("")
        lines.append(json.dumps(self._serialize_data(data), indent=2))
        lines.append("")
        lines.append("-" * 40)
        lines.append(f"Report ID: {metadata.report_id}")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # HTML Formatting
    # -------------------------------------------------------------------------

    def _wrap_html(self, markdown_content: str, metadata: ReportMetadata) -> str:
        """Wrap content in HTML with embedded CSS styling."""
        # Convert basic markdown to HTML
        html_content = self._markdown_to_html(markdown_content)

        template = Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        :root {
            --primary-color: ${primary_color};
            --secondary-color: ${secondary_color};
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f8fafc;
        }

        .report-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        h1 {
            color: var(--primary-color);
            border-bottom: 3px solid var(--primary-color);
            padding-bottom: 10px;
            margin-top: 0;
        }

        h2 {
            color: var(--secondary-color);
            margin-top: 30px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
        }

        h3 {
            color: #475569;
            margin-top: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }

        th {
            background: #f1f5f9;
            font-weight: 600;
            color: var(--secondary-color);
        }

        tr:hover {
            background: #f8fafc;
        }

        code {
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
        }

        pre {
            background: #1e293b;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
        }

        pre code {
            background: none;
            padding: 0;
            color: inherit;
        }

        ul {
            padding-left: 20px;
        }

        li {
            margin: 8px 0;
        }

        strong {
            color: #1e293b;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            color: #64748b;
            font-size: 0.9em;
        }

        .header-logo {
            max-height: 60px;
            margin-bottom: 20px;
        }

        @media print {
            body {
                background: white;
            }
            .report-container {
                box-shadow: none;
                padding: 0;
            }
        }
    </style>
</head>
<body>
    <div class="report-container">
        ${logo_html}
        ${content}
        <div class="footer">
            <p>${footer_text}</p>
            <p>Report ID: ${report_id}</p>
        </div>
    </div>
</body>
</html>""")

        logo_html = ""
        if self._branding.logo_base64:
            logo_html = f'<img src="data:image/png;base64,{self._branding.logo_base64}" class="header-logo" alt="Logo">'

        return template.substitute(
            title=f"{metadata.report_type.value.replace('_', ' ').title()} Report",
            primary_color=self._branding.primary_color,
            secondary_color=self._branding.secondary_color,
            logo_html=logo_html,
            content=html_content,
            footer_text=self._branding.footer_text or f"Generated by {self._branding.organization_name}",
            report_id=metadata.report_id,
        )

    def _markdown_to_html(self, markdown: str) -> str:
        """Convert basic Markdown to HTML."""
        lines = markdown.split("\n")
        html_lines = []
        in_code_block = False
        in_table = False
        in_list = False

        for line in lines:
            # Code blocks
            if line.startswith("```"):
                if in_code_block:
                    html_lines.append("</code></pre>")
                    in_code_block = False
                else:
                    lang = line[3:].strip()
                    html_lines.append(f"<pre><code class='language-{lang}'>")
                    in_code_block = True
                continue

            if in_code_block:
                # Escape HTML in code blocks
                escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html_lines.append(escaped)
                continue

            # Headers
            if line.startswith("# "):
                html_lines.append(f"<h1>{self._escape_html(line[2:])}</h1>")
                continue
            if line.startswith("## "):
                html_lines.append(f"<h2>{self._escape_html(line[3:])}</h2>")
                continue
            if line.startswith("### "):
                html_lines.append(f"<h3>{self._escape_html(line[4:])}</h3>")
                continue

            # Tables
            if line.startswith("|"):
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                    # Header row
                    cells = [c.strip() for c in line.split("|")[1:-1]]
                    html_lines.append("<tr>" + "".join(f"<th>{self._escape_html(c)}</th>" for c in cells) + "</tr>")
                elif line.startswith("|--") or line.startswith("|-"):
                    # Separator row - skip
                    pass
                else:
                    cells = [c.strip() for c in line.split("|")[1:-1]]
                    html_lines.append("<tr>" + "".join(f"<td>{self._format_inline(c)}</td>" for c in cells) + "</tr>")
                continue
            elif in_table:
                html_lines.append("</table>")
                in_table = False

            # Lists
            if line.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                html_lines.append(f"<li>{self._format_inline(line[2:])}</li>")
                continue
            elif in_list and line.strip() == "":
                html_lines.append("</ul>")
                in_list = False

            # Horizontal rules
            if line.startswith("---"):
                html_lines.append("<hr>")
                continue

            # Emphasis patterns
            if line.startswith("*") and line.endswith("*") and not line.startswith("**"):
                html_lines.append(f"<p><em>{self._escape_html(line[1:-1])}</em></p>")
                continue

            # Regular paragraphs
            if line.strip():
                html_lines.append(f"<p>{self._format_inline(line)}</p>")
            else:
                html_lines.append("")

        # Close any open tags
        if in_table:
            html_lines.append("</table>")
        if in_list:
            html_lines.append("</ul>")

        return "\n".join(html_lines)

    def _format_inline(self, text: str) -> str:
        """Format inline markdown elements."""
        import re

        # Escape HTML first
        text = self._escape_html(text)

        # Bold
        text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)

        # Inline code
        text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)

        # Italic
        text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)

        return text

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _format_date(self, dt: datetime | str | None) -> str:
        """Format a date for display."""
        if dt is None:
            return "N/A"
        if isinstance(dt, str):
            return dt[:10]
        return dt.strftime("%Y-%m-%d")
