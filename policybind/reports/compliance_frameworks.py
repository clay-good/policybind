"""
Compliance framework mappings for PolicyBind.

This module provides mappings between PolicyBind capabilities and various
compliance frameworks, including:
- EU AI Act requirements
- NIST AI Risk Management Framework (AI RMF)
- SOC 2 Trust Service Criteria
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from policybind.models.base import utc_now

logger = logging.getLogger("policybind.reports.compliance")


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    EU_AI_ACT = "eu_ai_act"
    """European Union Artificial Intelligence Act."""

    NIST_AI_RMF = "nist_ai_rmf"
    """NIST AI Risk Management Framework."""

    SOC2 = "soc2"
    """SOC 2 Trust Service Criteria."""

    ISO_27001 = "iso_27001"
    """ISO/IEC 27001 Information Security."""

    GDPR = "gdpr"
    """General Data Protection Regulation."""


class CoverageLevel(Enum):
    """Level of coverage for a requirement."""

    FULL = "full"
    """Requirement is fully addressed."""

    PARTIAL = "partial"
    """Requirement is partially addressed."""

    MINIMAL = "minimal"
    """Requirement has minimal coverage."""

    NONE = "none"
    """Requirement is not addressed."""


@dataclass
class Requirement:
    """
    A compliance requirement.

    Attributes:
        id: Unique identifier for the requirement.
        name: Short name for the requirement.
        description: Detailed description.
        category: Category within the framework.
        policybind_features: PolicyBind features that address this requirement.
        coverage: Level of coverage provided.
        notes: Additional notes about compliance.
        evidence_sources: Where to find evidence of compliance.
    """

    id: str
    name: str
    description: str
    category: str
    policybind_features: list[str] = field(default_factory=list)
    coverage: CoverageLevel = CoverageLevel.NONE
    notes: str = ""
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "policybind_features": self.policybind_features,
            "coverage": self.coverage.value,
            "notes": self.notes,
            "evidence_sources": self.evidence_sources,
        }


@dataclass
class ComplianceMapping:
    """
    Mapping between a compliance framework and PolicyBind capabilities.

    Attributes:
        framework: The compliance framework.
        version: Framework version.
        requirements: List of requirements with mappings.
        last_updated: When the mapping was last updated.
    """

    framework: ComplianceFramework
    version: str
    requirements: list[Requirement] = field(default_factory=list)
    last_updated: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "version": self.version,
            "requirements": [r.to_dict() for r in self.requirements],
            "last_updated": self.last_updated.isoformat(),
        }

    def get_coverage_summary(self) -> dict[str, int]:
        """Get a summary of coverage levels."""
        summary = {level.value: 0 for level in CoverageLevel}
        for req in self.requirements:
            summary[req.coverage.value] += 1
        return summary

    def get_coverage_score(self) -> float:
        """
        Calculate overall coverage score (0-100).

        Full coverage = 100%, Partial = 66%, Minimal = 33%, None = 0%
        """
        if not self.requirements:
            return 0.0

        weights = {
            CoverageLevel.FULL: 1.0,
            CoverageLevel.PARTIAL: 0.66,
            CoverageLevel.MINIMAL: 0.33,
            CoverageLevel.NONE: 0.0,
        }

        total = sum(weights[req.coverage] for req in self.requirements)
        return (total / len(self.requirements)) * 100


class ComplianceMapper:
    """
    Maps PolicyBind capabilities to compliance framework requirements.

    Provides pre-built mappings for major AI governance frameworks and
    generates compliance matrices showing coverage.

    Example:
        Using the ComplianceMapper::

            from policybind.reports.compliance_frameworks import (
                ComplianceMapper,
                ComplianceFramework,
            )

            mapper = ComplianceMapper()

            # Get EU AI Act mapping
            eu_mapping = mapper.get_mapping(ComplianceFramework.EU_AI_ACT)

            # Generate compliance matrix
            matrix = mapper.generate_compliance_matrix(
                frameworks=[ComplianceFramework.EU_AI_ACT, ComplianceFramework.NIST_AI_RMF]
            )

            # Export as report
            report = mapper.generate_compliance_report(
                frameworks=[ComplianceFramework.EU_AI_ACT],
                format="markdown",
            )
    """

    def __init__(self) -> None:
        """Initialize the compliance mapper with built-in mappings."""
        self._mappings: dict[ComplianceFramework, ComplianceMapping] = {}
        self._load_builtin_mappings()

    def _load_builtin_mappings(self) -> None:
        """Load all built-in compliance mappings."""
        self._load_eu_ai_act_mapping()
        self._load_nist_ai_rmf_mapping()
        self._load_soc2_mapping()

    def _load_eu_ai_act_mapping(self) -> None:
        """Load EU AI Act mapping."""
        requirements = [
            # Article 9 - Risk Management System
            Requirement(
                id="eu_ai_art9_1",
                name="Risk Management System",
                description="Establish, implement, document, and maintain a risk management system",
                category="Risk Management",
                policybind_features=[
                    "Model Registry",
                    "Risk Level Classification",
                    "Approval Workflows",
                    "Incident Tracking",
                ],
                coverage=CoverageLevel.FULL,
                notes="PolicyBind provides comprehensive risk management through model registry, risk classification, and incident tracking.",
                evidence_sources=["Registry Status Report", "Risk Assessment Report"],
            ),
            Requirement(
                id="eu_ai_art9_2a",
                name="Risk Identification",
                description="Identify and analyze known and foreseeable risks",
                category="Risk Management",
                policybind_features=[
                    "Data Classification",
                    "Risk Level Assessment",
                    "Policy Rules",
                ],
                coverage=CoverageLevel.FULL,
                notes="Data classification and risk assessment features identify potential risks.",
                evidence_sources=["Risk Assessment Report", "Policy Compliance Report"],
            ),
            Requirement(
                id="eu_ai_art9_4",
                name="Risk Mitigation",
                description="Adopt risk mitigation measures",
                category="Risk Management",
                policybind_features=[
                    "Policy Enforcement",
                    "Request Modification",
                    "Deployment Suspension",
                ],
                coverage=CoverageLevel.FULL,
                notes="Enforcement actions (DENY, MODIFY) and deployment controls mitigate risks.",
                evidence_sources=["Audit Trail Report", "Incident Summary Report"],
            ),

            # Article 10 - Data Governance
            Requirement(
                id="eu_ai_art10_1",
                name="Data Governance",
                description="High-quality training, validation, and testing data sets",
                category="Data Governance",
                policybind_features=[
                    "Data Classification",
                    "Data Access Policies",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="PolicyBind enforces data classification policies but does not manage training data.",
                evidence_sources=["Policy Compliance Report"],
            ),
            Requirement(
                id="eu_ai_art10_3",
                name="Data Quality",
                description="Ensure training data is relevant, representative, and free of errors",
                category="Data Governance",
                policybind_features=["Data Classification Policies"],
                coverage=CoverageLevel.MINIMAL,
                notes="PolicyBind focuses on runtime enforcement, not training data quality.",
                evidence_sources=[],
            ),

            # Article 11 - Technical Documentation
            Requirement(
                id="eu_ai_art11_1",
                name="Technical Documentation",
                description="Draw up technical documentation before placing on market",
                category="Documentation",
                policybind_features=[
                    "Model Registry Metadata",
                    "Policy Documentation",
                    "Audit Logs",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="Registry captures model metadata; policies are documented in YAML.",
                evidence_sources=["Registry Status Report"],
            ),

            # Article 12 - Record-Keeping
            Requirement(
                id="eu_ai_art12_1",
                name="Automatic Logging",
                description="Enable automatic recording of events (logs)",
                category="Logging",
                policybind_features=[
                    "Enforcement Audit Logs",
                    "Policy Change History",
                    "Incident Timeline",
                ],
                coverage=CoverageLevel.FULL,
                notes="Comprehensive logging of all enforcement decisions and system events.",
                evidence_sources=["Audit Trail Report"],
            ),
            Requirement(
                id="eu_ai_art12_2",
                name="Traceability",
                description="Ensure traceability throughout the AI system's lifecycle",
                category="Logging",
                policybind_features=[
                    "Request Tracking",
                    "Enforcement Chain",
                    "Policy Version History",
                ],
                coverage=CoverageLevel.FULL,
                notes="Full traceability from request to decision to policy version.",
                evidence_sources=["Audit Trail Report"],
            ),

            # Article 13 - Transparency
            Requirement(
                id="eu_ai_art13_1",
                name="Transparency",
                description="Design to enable understanding by deployers",
                category="Transparency",
                policybind_features=[
                    "Enforcement Decisions with Reasons",
                    "Applied Rules Visibility",
                    "Warning Messages",
                ],
                coverage=CoverageLevel.FULL,
                notes="Every enforcement decision includes the reason and rules applied.",
                evidence_sources=["Enforcement Logs", "API Responses"],
            ),

            # Article 14 - Human Oversight
            Requirement(
                id="eu_ai_art14_1",
                name="Human Oversight Design",
                description="Design to be effectively overseen by natural persons",
                category="Human Oversight",
                policybind_features=[
                    "Approval Workflows",
                    "Manual Review Flags",
                    "Deployment Suspension",
                    "Incident Management",
                ],
                coverage=CoverageLevel.FULL,
                notes="Multi-step approval workflows and manual override capabilities.",
                evidence_sources=["Registry Status Report", "Incident Summary Report"],
            ),
            Requirement(
                id="eu_ai_art14_4",
                name="Intervention Capability",
                description="Enable human operators to intervene or interrupt",
                category="Human Oversight",
                policybind_features=[
                    "Deployment Suspension",
                    "Token Revocation",
                    "Policy Hot Reload",
                ],
                coverage=CoverageLevel.FULL,
                notes="Immediate suspension and policy change capabilities.",
                evidence_sources=["Audit Trail Report"],
            ),

            # Article 17 - Quality Management
            Requirement(
                id="eu_ai_art17_1",
                name="Quality Management System",
                description="Put a quality management system in place",
                category="Quality Management",
                policybind_features=[
                    "Policy Validation",
                    "Compliance Checks",
                    "Review Workflows",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="PolicyBind provides policy validation and compliance checking.",
                evidence_sources=["Policy Compliance Report"],
            ),
        ]

        self._mappings[ComplianceFramework.EU_AI_ACT] = ComplianceMapping(
            framework=ComplianceFramework.EU_AI_ACT,
            version="2024 Final",
            requirements=requirements,
        )

    def _load_nist_ai_rmf_mapping(self) -> None:
        """Load NIST AI RMF mapping."""
        requirements = [
            # GOVERN Function
            Requirement(
                id="nist_gov_1",
                name="Govern 1",
                description="Policies, processes, procedures, and practices are in place to map, measure, and manage AI risks",
                category="GOVERN",
                policybind_features=[
                    "Policy Engine",
                    "Risk Classification",
                    "Approval Workflows",
                ],
                coverage=CoverageLevel.FULL,
                notes="Core PolicyBind functionality addresses governance requirements.",
                evidence_sources=["Policy Compliance Report", "Registry Status Report"],
            ),
            Requirement(
                id="nist_gov_2",
                name="Govern 2",
                description="Accountability structures are in place",
                category="GOVERN",
                policybind_features=[
                    "Deployment Ownership",
                    "Approval Records",
                    "Audit Logging",
                ],
                coverage=CoverageLevel.FULL,
                notes="Clear ownership and approval chains with full audit trails.",
                evidence_sources=["Audit Trail Report"],
            ),
            Requirement(
                id="nist_gov_3",
                name="Govern 3",
                description="Workforce diversity, equity, inclusion, and accessibility considerations",
                category="GOVERN",
                policybind_features=[],
                coverage=CoverageLevel.NONE,
                notes="Outside PolicyBind scope - organizational policy matter.",
                evidence_sources=[],
            ),
            Requirement(
                id="nist_gov_4",
                name="Govern 4",
                description="Organizational teams are committed to a culture that considers AI risk management",
                category="GOVERN",
                policybind_features=[
                    "Incident Tracking",
                    "Policy Visibility",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="Tools support risk culture but culture itself is organizational.",
                evidence_sources=["Incident Summary Report"],
            ),
            Requirement(
                id="nist_gov_5",
                name="Govern 5",
                description="Processes are in place for third-party AI entities",
                category="GOVERN",
                policybind_features=[
                    "Provider Tracking",
                    "Model Registry",
                    "API Gateway Enforcement",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="Registry tracks third-party providers; enforcement applies to all.",
                evidence_sources=["Registry Status Report"],
            ),

            # MAP Function
            Requirement(
                id="nist_map_1",
                name="Map 1",
                description="Context is established and understood",
                category="MAP",
                policybind_features=[
                    "Deployment Metadata",
                    "Use Case Classification",
                    "Department Tracking",
                ],
                coverage=CoverageLevel.FULL,
                notes="Rich context captured for each deployment and request.",
                evidence_sources=["Registry Status Report"],
            ),
            Requirement(
                id="nist_map_2",
                name="Map 2",
                description="Categorization of the AI system is performed",
                category="MAP",
                policybind_features=[
                    "Risk Level Classification",
                    "Data Classification",
                    "Use Case Categories",
                ],
                coverage=CoverageLevel.FULL,
                notes="Multiple classification dimensions supported.",
                evidence_sources=["Risk Assessment Report"],
            ),
            Requirement(
                id="nist_map_3",
                name="Map 3",
                description="AI capabilities, targeted usage, goals, and expected benefits are understood",
                category="MAP",
                policybind_features=[
                    "Deployment Purpose",
                    "Model Metadata",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="Captured at deployment registration.",
                evidence_sources=["Registry Status Report"],
            ),

            # MEASURE Function
            Requirement(
                id="nist_mea_1",
                name="Measure 1",
                description="Appropriate methods and metrics are identified and applied",
                category="MEASURE",
                policybind_features=[
                    "Enforcement Metrics",
                    "Incident Metrics",
                    "Usage Statistics",
                ],
                coverage=CoverageLevel.FULL,
                notes="Comprehensive metrics on enforcement, incidents, and usage.",
                evidence_sources=["Usage and Cost Report", "Incident Summary Report"],
            ),
            Requirement(
                id="nist_mea_2",
                name="Measure 2",
                description="AI systems are evaluated for trustworthy characteristics",
                category="MEASURE",
                policybind_features=[
                    "Compliance Checks",
                    "Policy Testing",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="Policy testing validates expected behavior.",
                evidence_sources=["Policy Compliance Report"],
            ),
            Requirement(
                id="nist_mea_3",
                name="Measure 3",
                description="Mechanisms for tracking identified AI risks over time are in place",
                category="MEASURE",
                policybind_features=[
                    "Incident Tracking",
                    "Trend Analysis",
                    "Historical Audit Logs",
                ],
                coverage=CoverageLevel.FULL,
                notes="Full historical tracking and trend analysis.",
                evidence_sources=["Incident Summary Report", "Audit Trail Report"],
            ),

            # MANAGE Function
            Requirement(
                id="nist_man_1",
                name="Manage 1",
                description="AI risks and benefits are managed",
                category="MANAGE",
                policybind_features=[
                    "Policy Enforcement",
                    "Request Modification",
                    "Budget Controls",
                ],
                coverage=CoverageLevel.FULL,
                notes="Active management through enforcement and controls.",
                evidence_sources=["Policy Compliance Report"],
            ),
            Requirement(
                id="nist_man_2",
                name="Manage 2",
                description="Strategies for maximizing benefits and minimizing negative impacts",
                category="MANAGE",
                policybind_features=[
                    "Policy Rules",
                    "Guardrails",
                    "Approval Gates",
                ],
                coverage=CoverageLevel.FULL,
                notes="Comprehensive policy rules enable benefit/risk balancing.",
                evidence_sources=["Policy Compliance Report"],
            ),
            Requirement(
                id="nist_man_3",
                name="Manage 3",
                description="AI risks and benefits from third-party resources are managed",
                category="MANAGE",
                policybind_features=[
                    "Provider Controls",
                    "Model Access Policies",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="Policies can control third-party model access.",
                evidence_sources=["Policy Compliance Report"],
            ),
            Requirement(
                id="nist_man_4",
                name="Manage 4",
                description="Risk treatments are documented, monitored, and tracked",
                category="MANAGE",
                policybind_features=[
                    "Incident Resolution",
                    "Policy History",
                    "Audit Logs",
                ],
                coverage=CoverageLevel.FULL,
                notes="Full documentation of risk treatments and outcomes.",
                evidence_sources=["Incident Summary Report", "Audit Trail Report"],
            ),
        ]

        self._mappings[ComplianceFramework.NIST_AI_RMF] = ComplianceMapping(
            framework=ComplianceFramework.NIST_AI_RMF,
            version="1.0",
            requirements=requirements,
        )

    def _load_soc2_mapping(self) -> None:
        """Load SOC 2 mapping."""
        requirements = [
            # Security - CC6
            Requirement(
                id="soc2_cc6_1",
                name="CC6.1 - Logical and Physical Access",
                description="Logical access security software, infrastructure, and architectures are implemented",
                category="Security",
                policybind_features=[
                    "Token Authentication",
                    "API Key Management",
                    "Role-Based Access",
                ],
                coverage=CoverageLevel.FULL,
                notes="Comprehensive access control through tokens and API keys.",
                evidence_sources=["Audit Trail Report"],
            ),
            Requirement(
                id="soc2_cc6_2",
                name="CC6.2 - User Authentication",
                description="Prior to issuing system credentials and granting access, users are registered and authorized",
                category="Security",
                policybind_features=[
                    "Token Issuance",
                    "Deployment Registration",
                    "Approval Workflows",
                ],
                coverage=CoverageLevel.FULL,
                notes="Registration and approval required before access granted.",
                evidence_sources=["Registry Status Report", "Audit Trail Report"],
            ),
            Requirement(
                id="soc2_cc6_3",
                name="CC6.3 - Access Removal",
                description="Access to credentials is revoked when access is no longer appropriate",
                category="Security",
                policybind_features=[
                    "Token Revocation",
                    "Deployment Suspension",
                    "Bulk Revocation",
                ],
                coverage=CoverageLevel.FULL,
                notes="Immediate revocation capabilities with audit logging.",
                evidence_sources=["Audit Trail Report"],
            ),
            Requirement(
                id="soc2_cc6_6",
                name="CC6.6 - System Boundaries",
                description="Logical access to system components is restricted",
                category="Security",
                policybind_features=[
                    "Policy Rules",
                    "Department Restrictions",
                    "Model Access Controls",
                ],
                coverage=CoverageLevel.FULL,
                notes="Fine-grained access controls through policy rules.",
                evidence_sources=["Policy Compliance Report"],
            ),

            # Availability - CC7
            Requirement(
                id="soc2_cc7_1",
                name="CC7.1 - Infrastructure Monitoring",
                description="Changes to infrastructure and software are authorized, designed, developed, tested, and implemented",
                category="Availability",
                policybind_features=[
                    "Health Checks",
                    "Metrics Endpoint",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="PolicyBind provides health and metrics endpoints.",
                evidence_sources=[],
            ),
            Requirement(
                id="soc2_cc7_2",
                name="CC7.2 - System Monitoring",
                description="System components are monitored for anomalies",
                category="Availability",
                policybind_features=[
                    "Request Monitoring",
                    "Incident Detection",
                    "Rate Limiting",
                ],
                coverage=CoverageLevel.FULL,
                notes="Monitoring and automatic incident creation for anomalies.",
                evidence_sources=["Incident Summary Report"],
            ),

            # Processing Integrity - CC8
            Requirement(
                id="soc2_cc8_1",
                name="CC8.1 - Input Completeness",
                description="Procedures exist to validate the completeness and accuracy of inputs",
                category="Processing Integrity",
                policybind_features=[
                    "Request Validation",
                    "Policy Matching",
                ],
                coverage=CoverageLevel.FULL,
                notes="All requests validated before processing.",
                evidence_sources=["Audit Trail Report"],
            ),

            # Confidentiality - CC9
            Requirement(
                id="soc2_cc9_1",
                name="CC9.1 - Confidential Information",
                description="Confidential information is identified and protected",
                category="Confidentiality",
                policybind_features=[
                    "Data Classification",
                    "PII Detection",
                    "Content Filtering",
                ],
                coverage=CoverageLevel.FULL,
                notes="Data classification and content policies protect confidential data.",
                evidence_sources=["Policy Compliance Report"],
            ),
            Requirement(
                id="soc2_cc9_2",
                name="CC9.2 - Confidential Information Disposal",
                description="Confidential information is disposed of securely",
                category="Confidentiality",
                policybind_features=[
                    "Prompt Hashing",
                    "No Content Storage",
                ],
                coverage=CoverageLevel.PARTIAL,
                notes="PolicyBind does not store prompt content, only hashes.",
                evidence_sources=[],
            ),

            # Change Management - CC10
            Requirement(
                id="soc2_cc10_1",
                name="CC10.1 - Changes to System Components",
                description="Changes to system components are authorized",
                category="Change Management",
                policybind_features=[
                    "Policy Version Control",
                    "Approval Workflows",
                    "Audit Logging",
                ],
                coverage=CoverageLevel.FULL,
                notes="All policy changes versioned and logged.",
                evidence_sources=["Policy Compliance Report", "Audit Trail Report"],
            ),
        ]

        self._mappings[ComplianceFramework.SOC2] = ComplianceMapping(
            framework=ComplianceFramework.SOC2,
            version="2017",
            requirements=requirements,
        )

    def get_mapping(
        self,
        framework: ComplianceFramework,
    ) -> ComplianceMapping | None:
        """
        Get the mapping for a compliance framework.

        Args:
            framework: The framework to get mapping for.

        Returns:
            The mapping if found, None otherwise.
        """
        return self._mappings.get(framework)

    def list_frameworks(self) -> list[ComplianceFramework]:
        """List all available frameworks."""
        return list(self._mappings.keys())

    def generate_compliance_matrix(
        self,
        frameworks: list[ComplianceFramework] | None = None,
    ) -> dict[str, Any]:
        """
        Generate a compliance matrix for specified frameworks.

        Args:
            frameworks: Frameworks to include (all if None).

        Returns:
            Compliance matrix as dictionary.
        """
        if frameworks is None:
            frameworks = list(self._mappings.keys())

        matrix: dict[str, Any] = {
            "generated_at": utc_now().isoformat(),
            "frameworks": {},
            "summary": {},
        }

        for framework in frameworks:
            mapping = self._mappings.get(framework)
            if not mapping:
                continue

            framework_data = {
                "version": mapping.version,
                "total_requirements": len(mapping.requirements),
                "coverage_summary": mapping.get_coverage_summary(),
                "coverage_score": mapping.get_coverage_score(),
                "requirements": [r.to_dict() for r in mapping.requirements],
            }
            matrix["frameworks"][framework.value] = framework_data
            matrix["summary"][framework.value] = {
                "score": framework_data["coverage_score"],
                "full": framework_data["coverage_summary"]["full"],
                "partial": framework_data["coverage_summary"]["partial"],
                "minimal": framework_data["coverage_summary"]["minimal"],
                "none": framework_data["coverage_summary"]["none"],
            }

        return matrix

    def generate_compliance_report(
        self,
        frameworks: list[ComplianceFramework] | None = None,
        format: str = "markdown",
    ) -> str:
        """
        Generate a compliance report.

        Args:
            frameworks: Frameworks to include.
            format: Output format (markdown, json, text).

        Returns:
            The formatted report.
        """
        matrix = self.generate_compliance_matrix(frameworks)

        if format == "json":
            return json.dumps(matrix, indent=2)
        elif format == "text":
            return self._format_compliance_text(matrix)
        else:
            return self._format_compliance_markdown(matrix)

    def _format_compliance_markdown(self, matrix: dict[str, Any]) -> str:
        """Format compliance matrix as Markdown."""
        lines = []

        lines.append("# Compliance Coverage Report")
        lines.append("")
        lines.append(f"**Generated:** {matrix['generated_at']}")
        lines.append("")

        # Summary table
        lines.append("## Executive Summary")
        lines.append("")
        lines.append("| Framework | Coverage Score | Full | Partial | Minimal | None |")
        lines.append("|-----------|----------------|------|---------|---------|------|")

        for framework, summary in matrix["summary"].items():
            lines.append(
                f"| {framework.upper().replace('_', ' ')} | "
                f"{summary['score']:.1f}% | "
                f"{summary['full']} | "
                f"{summary['partial']} | "
                f"{summary['minimal']} | "
                f"{summary['none']} |"
            )
        lines.append("")

        # Detailed sections
        for framework_name, framework_data in matrix["frameworks"].items():
            lines.append(f"## {framework_name.upper().replace('_', ' ')}")
            lines.append("")
            lines.append(f"**Version:** {framework_data['version']}")
            lines.append(f"**Coverage Score:** {framework_data['coverage_score']:.1f}%")
            lines.append("")

            # Group by category
            requirements = framework_data["requirements"]
            categories: dict[str, list] = {}
            for req in requirements:
                cat = req["category"]
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(req)

            for category, reqs in categories.items():
                lines.append(f"### {category}")
                lines.append("")
                lines.append("| ID | Name | Coverage | Features |")
                lines.append("|----|------|----------|----------|")
                for req in reqs:
                    features = ", ".join(req["policybind_features"][:3])
                    if len(req["policybind_features"]) > 3:
                        features += "..."
                    coverage_badge = self._get_coverage_badge(req["coverage"])
                    lines.append(
                        f"| {req['id']} | {req['name']} | "
                        f"{coverage_badge} | {features} |"
                    )
                lines.append("")

        # Footer
        lines.append("---")
        lines.append("*This report shows how PolicyBind capabilities map to compliance requirements.*")
        lines.append("*Coverage levels: Full (100%), Partial (66%), Minimal (33%), None (0%)*")

        return "\n".join(lines)

    def _format_compliance_text(self, matrix: dict[str, Any]) -> str:
        """Format compliance matrix as plain text."""
        lines = []

        lines.append("=" * 60)
        lines.append("COMPLIANCE COVERAGE REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {matrix['generated_at']}")
        lines.append("")

        for framework, summary in matrix["summary"].items():
            lines.append(f"{framework.upper()}: {summary['score']:.1f}% coverage")
            lines.append(
                f"  Full: {summary['full']}, Partial: {summary['partial']}, "
                f"Minimal: {summary['minimal']}, None: {summary['none']}"
            )
        lines.append("")
        lines.append("-" * 40)

        return "\n".join(lines)

    def _get_coverage_badge(self, coverage: str) -> str:
        """Get a text badge for coverage level."""
        badges = {
            "full": "FULL",
            "partial": "PARTIAL",
            "minimal": "MINIMAL",
            "none": "NONE",
        }
        return badges.get(coverage, coverage.upper())

    def get_requirements_by_feature(
        self,
        feature: str,
        frameworks: list[ComplianceFramework] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Find all requirements addressed by a PolicyBind feature.

        Args:
            feature: The feature name to search for.
            frameworks: Frameworks to search (all if None).

        Returns:
            List of matching requirements with framework info.
        """
        if frameworks is None:
            frameworks = list(self._mappings.keys())

        results = []
        feature_lower = feature.lower()

        for framework in frameworks:
            mapping = self._mappings.get(framework)
            if not mapping:
                continue

            for req in mapping.requirements:
                for feat in req.policybind_features:
                    if feature_lower in feat.lower():
                        results.append({
                            "framework": framework.value,
                            "requirement": req.to_dict(),
                        })
                        break

        return results

    def get_gaps(
        self,
        frameworks: list[ComplianceFramework] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get all requirements with no or minimal coverage.

        Args:
            frameworks: Frameworks to check (all if None).

        Returns:
            List of gap requirements with framework info.
        """
        if frameworks is None:
            frameworks = list(self._mappings.keys())

        gaps = []

        for framework in frameworks:
            mapping = self._mappings.get(framework)
            if not mapping:
                continue

            for req in mapping.requirements:
                if req.coverage in (CoverageLevel.NONE, CoverageLevel.MINIMAL):
                    gaps.append({
                        "framework": framework.value,
                        "requirement": req.to_dict(),
                    })

        return gaps
