"""
Compliance checking for PolicyBind registry.

This module provides the ComplianceChecker class for checking deployments
against various compliance frameworks and generating compliance reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from policybind.models.base import utc_now
from policybind.models.registry import ModelDeployment, RiskLevel


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    EU_AI_ACT = "eu_ai_act"
    """EU Artificial Intelligence Act."""

    NIST_AI_RMF = "nist_ai_rmf"
    """NIST AI Risk Management Framework."""

    SOC2 = "soc2"
    """SOC 2 Trust Service Criteria."""

    INTERNAL = "internal"
    """Internal organizational policies."""

    HIPAA = "hipaa"
    """HIPAA for healthcare data."""

    GDPR = "gdpr"
    """GDPR for personal data."""

    PCI_DSS = "pci_dss"
    """PCI DSS for payment card data."""


class ComplianceStatus(Enum):
    """Compliance status for a framework."""

    COMPLIANT = "compliant"
    """Fully compliant with the framework."""

    PARTIAL = "partial"
    """Partially compliant; some gaps exist."""

    NON_COMPLIANT = "non_compliant"
    """Not compliant; significant gaps."""

    NOT_APPLICABLE = "not_applicable"
    """Framework does not apply to this deployment."""

    UNKNOWN = "unknown"
    """Compliance status cannot be determined."""


@dataclass
class ComplianceGap:
    """
    A single compliance gap or finding.

    Attributes:
        framework: The compliance framework this gap relates to.
        requirement: The specific requirement not met.
        description: Detailed description of the gap.
        severity: Severity level (critical, high, medium, low).
        remediation: Suggested remediation steps.
        reference: Reference to framework documentation.
    """

    framework: ComplianceFramework
    requirement: str
    description: str
    severity: str = "medium"
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "requirement": self.requirement,
            "description": self.description,
            "severity": self.severity,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclass
class ComplianceReport:
    """
    Complete compliance report for a deployment.

    Attributes:
        deployment_id: ID of the assessed deployment.
        generated_at: When the report was generated.
        frameworks_checked: List of frameworks that were checked.
        overall_status: Overall compliance status.
        framework_statuses: Status for each framework.
        gaps: List of compliance gaps found.
        documentation_required: List of documentation requirements.
        metadata: Additional report metadata.
    """

    deployment_id: str
    generated_at: datetime = field(default_factory=utc_now)
    frameworks_checked: list[ComplianceFramework] = field(default_factory=list)
    overall_status: ComplianceStatus = ComplianceStatus.UNKNOWN
    framework_statuses: dict[ComplianceFramework, ComplianceStatus] = field(default_factory=dict)
    gaps: list[ComplianceGap] = field(default_factory=list)
    documentation_required: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "generated_at": self.generated_at.isoformat(),
            "frameworks_checked": [f.value for f in self.frameworks_checked],
            "overall_status": self.overall_status.value,
            "framework_statuses": {
                f.value: s.value for f, s in self.framework_statuses.items()
            },
            "gaps": [g.to_dict() for g in self.gaps],
            "gap_count": len(self.gaps),
            "documentation_required": self.documentation_required,
            "metadata": self.metadata,
        }

    @property
    def critical_gaps(self) -> list[ComplianceGap]:
        """Get only critical gaps."""
        return [g for g in self.gaps if g.severity == "critical"]

    @property
    def high_gaps(self) -> list[ComplianceGap]:
        """Get only high severity gaps."""
        return [g for g in self.gaps if g.severity == "high"]

    def is_compliant(self, framework: ComplianceFramework | None = None) -> bool:
        """Check if compliant with a framework or overall."""
        if framework:
            status = self.framework_statuses.get(framework, ComplianceStatus.UNKNOWN)
            return status == ComplianceStatus.COMPLIANT
        return self.overall_status == ComplianceStatus.COMPLIANT


# Type alias for framework checkers
FrameworkChecker = Callable[[ModelDeployment], tuple[ComplianceStatus, list[ComplianceGap]]]


class ComplianceChecker:
    """
    Checks deployments against compliance frameworks.

    The ComplianceChecker evaluates deployments against multiple
    compliance frameworks including EU AI Act, NIST AI RMF, SOC 2,
    HIPAA, GDPR, and internal policies.

    Example:
        Checking compliance::

            checker = ComplianceChecker()
            report = checker.check(deployment)

            print(f"Overall Status: {report.overall_status.value}")
            for gap in report.gaps:
                print(f"  Gap: {gap.requirement} - {gap.description}")
    """

    def __init__(
        self,
        enabled_frameworks: list[ComplianceFramework] | None = None,
        custom_checkers: dict[ComplianceFramework, FrameworkChecker] | None = None,
    ) -> None:
        """
        Initialize the compliance checker.

        Args:
            enabled_frameworks: Frameworks to check. Defaults to all.
            custom_checkers: Custom checker functions per framework.
        """
        if enabled_frameworks is None:
            self._enabled_frameworks = list(ComplianceFramework)
        else:
            self._enabled_frameworks = enabled_frameworks

        self._custom_checkers = custom_checkers or {}

        # Built-in checkers
        self._checkers: dict[ComplianceFramework, FrameworkChecker] = {
            ComplianceFramework.EU_AI_ACT: self._check_eu_ai_act,
            ComplianceFramework.NIST_AI_RMF: self._check_nist_ai_rmf,
            ComplianceFramework.SOC2: self._check_soc2,
            ComplianceFramework.INTERNAL: self._check_internal,
            ComplianceFramework.HIPAA: self._check_hipaa,
            ComplianceFramework.GDPR: self._check_gdpr,
            ComplianceFramework.PCI_DSS: self._check_pci_dss,
        }

        # Override with custom checkers
        self._checkers.update(self._custom_checkers)

    def check(
        self,
        deployment: ModelDeployment,
        frameworks: list[ComplianceFramework] | None = None,
    ) -> ComplianceReport:
        """
        Check a deployment against compliance frameworks.

        Args:
            deployment: The deployment to check.
            frameworks: Specific frameworks to check, or all enabled.

        Returns:
            ComplianceReport with findings.
        """
        frameworks_to_check = frameworks or self._enabled_frameworks

        report = ComplianceReport(
            deployment_id=deployment.deployment_id,
            frameworks_checked=frameworks_to_check,
        )

        # Run each framework checker
        for framework in frameworks_to_check:
            checker = self._checkers.get(framework)
            if checker:
                try:
                    status, gaps = checker(deployment)
                    report.framework_statuses[framework] = status
                    report.gaps.extend(gaps)
                except Exception:
                    report.framework_statuses[framework] = ComplianceStatus.UNKNOWN

        # Determine overall status
        report.overall_status = self._compute_overall_status(report.framework_statuses)

        # Identify required documentation
        report.documentation_required = self._identify_documentation(
            deployment, frameworks_to_check
        )

        # Add metadata
        report.metadata = {
            "deployment_name": deployment.name,
            "risk_level": deployment.risk_level.value,
            "approval_status": deployment.approval_status.value,
        }

        return report

    def _compute_overall_status(
        self,
        statuses: dict[ComplianceFramework, ComplianceStatus],
    ) -> ComplianceStatus:
        """Compute overall status from individual framework statuses."""
        if not statuses:
            return ComplianceStatus.UNKNOWN

        # Filter out not applicable
        applicable = [
            s for s in statuses.values()
            if s != ComplianceStatus.NOT_APPLICABLE
        ]

        if not applicable:
            return ComplianceStatus.NOT_APPLICABLE

        # Any non-compliant = non-compliant overall
        if ComplianceStatus.NON_COMPLIANT in applicable:
            return ComplianceStatus.NON_COMPLIANT

        # Any partial = partial overall
        if ComplianceStatus.PARTIAL in applicable:
            return ComplianceStatus.PARTIAL

        # Any unknown = unknown overall
        if ComplianceStatus.UNKNOWN in applicable:
            return ComplianceStatus.UNKNOWN

        return ComplianceStatus.COMPLIANT

    def _identify_documentation(
        self,
        deployment: ModelDeployment,
        frameworks: list[ComplianceFramework],
    ) -> list[str]:
        """Identify required documentation."""
        docs = []

        # General documentation
        if not deployment.description:
            docs.append("System description and purpose documentation")

        # Risk-based documentation
        if deployment.is_high_risk():
            docs.append("Risk assessment documentation")
            docs.append("Human oversight procedures")
            docs.append("Incident response plan")

        # Framework-specific documentation
        if ComplianceFramework.EU_AI_ACT in frameworks:
            if deployment.is_high_risk():
                docs.append("EU AI Act conformity assessment")
                docs.append("Technical documentation per Annex IV")

        if ComplianceFramework.NIST_AI_RMF in frameworks:
            docs.append("AI risk management plan")

        if ComplianceFramework.SOC2 in frameworks:
            docs.append("Security policies and procedures")
            docs.append("Access control documentation")

        if ComplianceFramework.HIPAA in frameworks:
            categories = set(c.lower() for c in deployment.data_categories)
            if "phi" in categories or "healthcare" in categories:
                docs.append("Business Associate Agreement (BAA)")
                docs.append("PHI handling procedures")

        if ComplianceFramework.GDPR in frameworks:
            categories = set(c.lower() for c in deployment.data_categories)
            if "pii" in categories:
                docs.append("Data Processing Agreement")
                docs.append("Privacy Impact Assessment (PIA)")

        if ComplianceFramework.PCI_DSS in frameworks:
            categories = set(c.lower() for c in deployment.data_categories)
            if "pci" in categories or "financial" in categories:
                docs.append("PCI DSS Self-Assessment Questionnaire")

        return list(set(docs))  # Remove duplicates

    # Framework-specific checkers

    def _check_eu_ai_act(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check EU AI Act compliance."""
        gaps = []

        # Determine if high-risk under EU AI Act
        is_eu_high_risk = self._is_eu_ai_act_high_risk(deployment)

        if not is_eu_high_risk:
            return ComplianceStatus.NOT_APPLICABLE, []

        # High-risk AI system requirements

        # Risk management system (Art. 9)
        if not deployment.description:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.EU_AI_ACT,
                    requirement="Art. 9 - Risk Management",
                    description="No documented risk management system",
                    severity="high",
                    remediation="Establish and document a risk management system",
                    reference="EU AI Act Article 9",
                )
            )

        # Data governance (Art. 10)
        if not deployment.data_categories:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.EU_AI_ACT,
                    requirement="Art. 10 - Data Governance",
                    description="Data categories not documented",
                    severity="high",
                    remediation="Document data categories and governance practices",
                    reference="EU AI Act Article 10",
                )
            )

        # Technical documentation (Art. 11)
        if len(deployment.description) < 50:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.EU_AI_ACT,
                    requirement="Art. 11 - Technical Documentation",
                    description="Insufficient technical documentation",
                    severity="high",
                    remediation="Create comprehensive technical documentation per Annex IV",
                    reference="EU AI Act Article 11, Annex IV",
                )
            )

        # Human oversight (Art. 14)
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.EU_AI_ACT,
                requirement="Art. 14 - Human Oversight",
                description="Human oversight measures should be documented",
                severity="medium",
                remediation="Document human oversight procedures and controls",
                reference="EU AI Act Article 14",
            )
        )

        # Accuracy, robustness (Art. 15)
        if not deployment.model_version:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.EU_AI_ACT,
                    requirement="Art. 15 - Accuracy and Robustness",
                    description="Model version not specified for reproducibility",
                    severity="medium",
                    remediation="Document specific model version for accuracy tracking",
                    reference="EU AI Act Article 15",
                )
            )

        status = ComplianceStatus.NON_COMPLIANT if any(g.severity in ("critical", "high") for g in gaps) else (
            ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        )

        return status, gaps

    def _is_eu_ai_act_high_risk(self, deployment: ModelDeployment) -> bool:
        """Determine if deployment is high-risk under EU AI Act."""
        # Check for high-risk categories in Annex III
        high_risk_indicators = [
            "biometric", "critical infrastructure", "education", "employment",
            "essential services", "law enforcement", "immigration", "justice",
            "democratic", "safety", "medical", "healthcare", "financial",
        ]

        search_text = f"{deployment.name} {deployment.description}".lower()

        for indicator in high_risk_indicators:
            if indicator in search_text:
                return True

        # High/critical risk level triggers EU AI Act scrutiny
        return deployment.is_high_risk()

    def _check_nist_ai_rmf(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check NIST AI Risk Management Framework compliance."""
        gaps = []

        # GOVERN function
        if not deployment.owner:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.NIST_AI_RMF,
                    requirement="GOVERN 1.1 - Accountability",
                    description="No accountable owner defined",
                    severity="high",
                    remediation="Assign an accountable owner for the AI system",
                    reference="NIST AI RMF GOVERN 1.1",
                )
            )

        # MAP function
        if not deployment.data_categories:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.NIST_AI_RMF,
                    requirement="MAP 1.1 - Context",
                    description="Data context not documented",
                    severity="medium",
                    remediation="Document data categories and context",
                    reference="NIST AI RMF MAP 1.1",
                )
            )

        # MEASURE function
        if deployment.is_high_risk() and not deployment.last_review_date:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.NIST_AI_RMF,
                    requirement="MEASURE 2.1 - Monitoring",
                    description="No evidence of performance monitoring",
                    severity="medium",
                    remediation="Implement ongoing performance monitoring",
                    reference="NIST AI RMF MEASURE 2.1",
                )
            )

        # MANAGE function
        if deployment.needs_review():
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.NIST_AI_RMF,
                    requirement="MANAGE 1.1 - Risk Treatment",
                    description="Deployment is overdue for review",
                    severity="medium",
                    remediation="Complete scheduled review",
                    reference="NIST AI RMF MANAGE 1.1",
                )
            )

        status = ComplianceStatus.NON_COMPLIANT if any(g.severity == "high" for g in gaps) else (
            ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        )

        return status, gaps

    def _check_soc2(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check SOC 2 Trust Service Criteria compliance."""
        gaps = []

        # CC1 - Control Environment
        if not deployment.owner_contact:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.SOC2,
                    requirement="CC1.3 - Accountability",
                    description="No owner contact for accountability",
                    severity="medium",
                    remediation="Document owner contact information",
                    reference="SOC 2 CC1.3",
                )
            )

        # CC3 - Risk Assessment
        # Covered by risk assessment existing

        # CC5 - Control Activities
        if not deployment.model_version:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.SOC2,
                    requirement="CC5.3 - Change Management",
                    description="Model version not tracked",
                    severity="low",
                    remediation="Track and document model versions",
                    reference="SOC 2 CC5.3",
                )
            )

        # CC7 - System Operations
        if deployment.is_high_risk() and not deployment.approval_ticket:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.SOC2,
                    requirement="CC7.1 - Incident Management",
                    description="No approval/ticket reference for audit trail",
                    severity="medium",
                    remediation="Link to approval ticket or change management record",
                    reference="SOC 2 CC7.1",
                )
            )

        status = ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        return status, gaps

    def _check_internal(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check internal policy compliance."""
        gaps = []

        # Basic completeness
        if not deployment.name:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.INTERNAL,
                    requirement="Naming Convention",
                    description="Deployment must have a name",
                    severity="high",
                    remediation="Provide a descriptive deployment name",
                )
            )

        if not deployment.description:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.INTERNAL,
                    requirement="Documentation",
                    description="Deployment must have a description",
                    severity="medium",
                    remediation="Document the deployment purpose and use",
                )
            )

        # Owner requirements
        if not deployment.owner or not deployment.owner_contact:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.INTERNAL,
                    requirement="Ownership",
                    description="Deployment must have an owner and contact",
                    severity="high",
                    remediation="Assign an owner with contact information",
                )
            )

        # Data classification
        if not deployment.data_categories:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.INTERNAL,
                    requirement="Data Classification",
                    description="Data categories must be specified",
                    severity="medium",
                    remediation="Classify data handled by the deployment",
                )
            )

        status = ComplianceStatus.NON_COMPLIANT if any(g.severity == "high" for g in gaps) else (
            ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        )

        return status, gaps

    def _check_hipaa(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check HIPAA compliance for healthcare data."""
        # Check if HIPAA applies
        categories = set(c.lower() for c in deployment.data_categories)
        if "phi" not in categories and "healthcare" not in categories:
            return ComplianceStatus.NOT_APPLICABLE, []

        gaps = []

        # Privacy Rule requirements
        if not deployment.description:
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.HIPAA,
                    requirement="Privacy Rule - Use and Disclosure",
                    description="No documentation of PHI use/disclosure purpose",
                    severity="critical",
                    remediation="Document how PHI is used and disclosed",
                    reference="45 CFR 164.502",
                )
            )

        # Security Rule requirements
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.HIPAA,
                requirement="Security Rule - Access Controls",
                description="Access controls should be documented",
                severity="high",
                remediation="Document access control mechanisms",
                reference="45 CFR 164.312(a)",
            )
        )

        # Audit controls
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.HIPAA,
                requirement="Security Rule - Audit Controls",
                description="Audit logging should be implemented",
                severity="high",
                remediation="Implement comprehensive audit logging",
                reference="45 CFR 164.312(b)",
            )
        )

        status = ComplianceStatus.NON_COMPLIANT if any(g.severity == "critical" for g in gaps) else (
            ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        )

        return status, gaps

    def _check_gdpr(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check GDPR compliance for personal data."""
        # Check if GDPR applies
        categories = set(c.lower() for c in deployment.data_categories)
        pii_categories = {"pii", "personal", "customer", "employee"}
        if not categories.intersection(pii_categories):
            return ComplianceStatus.NOT_APPLICABLE, []

        gaps = []

        # Lawful basis (Art. 6)
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.GDPR,
                requirement="Art. 6 - Lawful Basis",
                description="Lawful basis for processing should be documented",
                severity="high",
                remediation="Document the lawful basis for personal data processing",
                reference="GDPR Article 6",
            )
        )

        # Data minimization (Art. 5)
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.GDPR,
                requirement="Art. 5 - Data Minimization",
                description="Data minimization practices should be documented",
                severity="medium",
                remediation="Document how data minimization is applied",
                reference="GDPR Article 5(1)(c)",
            )
        )

        # DPIA for high-risk processing (Art. 35)
        if deployment.is_high_risk():
            gaps.append(
                ComplianceGap(
                    framework=ComplianceFramework.GDPR,
                    requirement="Art. 35 - Data Protection Impact Assessment",
                    description="High-risk processing requires DPIA",
                    severity="high",
                    remediation="Conduct a Data Protection Impact Assessment",
                    reference="GDPR Article 35",
                )
            )

        status = ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        return status, gaps

    def _check_pci_dss(
        self,
        deployment: ModelDeployment,
    ) -> tuple[ComplianceStatus, list[ComplianceGap]]:
        """Check PCI DSS compliance for payment card data."""
        # Check if PCI DSS applies
        categories = set(c.lower() for c in deployment.data_categories)
        if "pci" not in categories and "payment" not in categories:
            return ComplianceStatus.NOT_APPLICABLE, []

        gaps = []

        # Requirement 3 - Protect stored data
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.PCI_DSS,
                requirement="Req 3 - Protect Stored Data",
                description="Cardholder data protection must be documented",
                severity="critical",
                remediation="Document how cardholder data is protected",
                reference="PCI DSS Requirement 3",
            )
        )

        # Requirement 7 - Restrict access
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.PCI_DSS,
                requirement="Req 7 - Restrict Access",
                description="Access restrictions must be implemented",
                severity="critical",
                remediation="Implement and document access restrictions",
                reference="PCI DSS Requirement 7",
            )
        )

        # Requirement 10 - Track and monitor
        gaps.append(
            ComplianceGap(
                framework=ComplianceFramework.PCI_DSS,
                requirement="Req 10 - Track and Monitor",
                description="All access must be tracked and monitored",
                severity="critical",
                remediation="Implement comprehensive access logging",
                reference="PCI DSS Requirement 10",
            )
        )

        status = ComplianceStatus.NON_COMPLIANT if any(g.severity == "critical" for g in gaps) else (
            ComplianceStatus.PARTIAL if gaps else ComplianceStatus.COMPLIANT
        )

        return status, gaps

    def get_framework_summary(
        self,
        framework: ComplianceFramework,
    ) -> dict[str, Any]:
        """Get summary information about a framework."""
        summaries = {
            ComplianceFramework.EU_AI_ACT: {
                "name": "EU Artificial Intelligence Act",
                "description": "European regulation for AI systems based on risk classification",
                "applies_to": "High-risk AI systems in EU market",
                "key_requirements": [
                    "Risk management system",
                    "Data governance",
                    "Technical documentation",
                    "Human oversight",
                    "Accuracy and robustness",
                ],
            },
            ComplianceFramework.NIST_AI_RMF: {
                "name": "NIST AI Risk Management Framework",
                "description": "Framework for managing AI system risks",
                "applies_to": "All AI systems",
                "key_requirements": [
                    "GOVERN - Establish accountability",
                    "MAP - Understand context",
                    "MEASURE - Assess risks",
                    "MANAGE - Prioritize and act",
                ],
            },
            ComplianceFramework.SOC2: {
                "name": "SOC 2 Trust Service Criteria",
                "description": "Security and trust criteria for service organizations",
                "applies_to": "Service organizations handling customer data",
                "key_requirements": [
                    "Control environment",
                    "Risk assessment",
                    "Control activities",
                    "System operations",
                ],
            },
            ComplianceFramework.HIPAA: {
                "name": "HIPAA",
                "description": "US regulation for protected health information",
                "applies_to": "Healthcare data handlers",
                "key_requirements": [
                    "Privacy Rule compliance",
                    "Security Rule compliance",
                    "Breach notification",
                ],
            },
            ComplianceFramework.GDPR: {
                "name": "General Data Protection Regulation",
                "description": "EU regulation for personal data protection",
                "applies_to": "Organizations processing EU personal data",
                "key_requirements": [
                    "Lawful basis for processing",
                    "Data subject rights",
                    "Data protection by design",
                    "Data Protection Impact Assessment",
                ],
            },
            ComplianceFramework.PCI_DSS: {
                "name": "PCI Data Security Standard",
                "description": "Payment card industry security standard",
                "applies_to": "Organizations handling payment card data",
                "key_requirements": [
                    "Protect stored data",
                    "Encrypt transmission",
                    "Access control",
                    "Monitoring and logging",
                ],
            },
            ComplianceFramework.INTERNAL: {
                "name": "Internal Policies",
                "description": "Organization-specific AI governance policies",
                "applies_to": "All deployments",
                "key_requirements": [
                    "Proper documentation",
                    "Owner assignment",
                    "Data classification",
                    "Approval process",
                ],
            },
        }

        return summaries.get(framework, {
            "name": framework.value,
            "description": "No description available",
            "applies_to": "Unknown",
            "key_requirements": [],
        })
