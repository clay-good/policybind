"""
Risk assessment for PolicyBind registry.

This module provides the RiskAssessor class for computing risk levels
based on deployment characteristics and suggesting mitigations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from policybind.models.registry import ModelDeployment, RiskLevel


class RiskFactorCategory(Enum):
    """Categories of risk factors."""

    DATA = "data"
    """Risks related to data handling and classification."""

    MODEL = "model"
    """Risks related to model capabilities and behavior."""

    USAGE = "usage"
    """Risks related to intended use case and exposure."""

    OPERATIONAL = "operational"
    """Risks related to operations and deployment context."""


@dataclass
class RiskFactor:
    """
    A single risk factor contributing to the overall assessment.

    Attributes:
        name: Short identifier for the risk factor.
        category: Category of risk this factor belongs to.
        description: Human-readable description of the risk.
        weight: Numeric weight indicating severity (0.0 to 1.0).
        triggered_by: What triggered this risk factor.
    """

    name: str
    category: RiskFactorCategory
    description: str
    weight: float
    triggered_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "weight": self.weight,
            "triggered_by": self.triggered_by,
        }


@dataclass
class RiskMitigation:
    """
    A suggested mitigation for identified risks.

    Attributes:
        title: Short title for the mitigation.
        description: Detailed description of the mitigation.
        priority: Priority level (high, medium, low).
        addresses: List of risk factor names this mitigation addresses.
        effort: Estimated effort level (low, medium, high).
    """

    title: str
    description: str
    priority: str = "medium"
    addresses: list[str] = field(default_factory=list)
    effort: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "addresses": self.addresses,
            "effort": self.effort,
        }


@dataclass
class RiskAssessment:
    """
    Complete risk assessment for a deployment.

    Attributes:
        deployment_id: ID of the assessed deployment.
        computed_risk_level: The computed risk level.
        risk_score: Numeric risk score (0.0 to 1.0).
        factors: List of identified risk factors.
        mitigations: Suggested mitigations.
        explanation: Human-readable explanation of the assessment.
        metadata: Additional assessment metadata.
    """

    deployment_id: str
    computed_risk_level: RiskLevel
    risk_score: float
    factors: list[RiskFactor] = field(default_factory=list)
    mitigations: list[RiskMitigation] = field(default_factory=list)
    explanation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "computed_risk_level": self.computed_risk_level.value,
            "risk_score": self.risk_score,
            "factors": [f.to_dict() for f in self.factors],
            "mitigations": [m.to_dict() for m in self.mitigations],
            "explanation": self.explanation,
            "metadata": self.metadata,
        }

    @property
    def highest_risk_factors(self) -> list[RiskFactor]:
        """Get the top risk factors by weight."""
        return sorted(self.factors, key=lambda f: f.weight, reverse=True)[:5]


# Type alias for custom risk rules
RiskRule = Callable[[ModelDeployment], list[RiskFactor]]


class RiskAssessor:
    """
    Computes risk levels based on deployment characteristics.

    The RiskAssessor evaluates multiple risk factors including:
    - Data categories and sensitivity
    - Model capabilities and provider
    - Intended use case and exposure
    - Operational context

    It provides explanations for assessments and suggests mitigations.

    Example:
        Assessing deployment risk::

            assessor = RiskAssessor()
            assessment = assessor.assess(deployment)

            print(f"Risk Level: {assessment.computed_risk_level.value}")
            print(f"Risk Score: {assessment.risk_score:.2f}")

            for factor in assessment.factors:
                print(f"  - {factor.name}: {factor.description}")
    """

    # Risk thresholds for level determination
    RISK_THRESHOLDS = {
        RiskLevel.LOW: 0.25,
        RiskLevel.MEDIUM: 0.50,
        RiskLevel.HIGH: 0.75,
        # Above 0.75 is CRITICAL
    }

    # Sensitive data categories and their weights
    SENSITIVE_DATA = {
        "pii": 0.4,
        "phi": 0.5,
        "pci": 0.5,
        "financial": 0.4,
        "healthcare": 0.5,
        "legal": 0.3,
        "trade_secret": 0.4,
        "restricted": 0.4,
        "confidential": 0.2,
        "hr": 0.3,
        "customer": 0.2,
        "employee": 0.2,
    }

    # High-risk use case patterns
    HIGH_RISK_USE_CASES = {
        "medical": 0.4,
        "health": 0.4,
        "diagnosis": 0.5,
        "financial": 0.3,
        "trading": 0.4,
        "investment": 0.3,
        "legal": 0.3,
        "compliance": 0.2,
        "hr": 0.2,
        "hiring": 0.3,
        "decision": 0.2,
        "autonomous": 0.4,
        "customer-facing": 0.2,
        "external": 0.2,
    }

    # Model capability risks by provider/model patterns
    MODEL_RISKS = {
        "gpt-4": 0.1,  # More capable = more risk potential
        "claude-3-opus": 0.1,
        "gemini-ultra": 0.1,
        "gpt-3.5": 0.05,
        "claude-3-sonnet": 0.05,
    }

    def __init__(
        self,
        custom_rules: list[RiskRule] | None = None,
        sensitivity_weights: dict[str, float] | None = None,
        use_case_weights: dict[str, float] | None = None,
    ) -> None:
        """
        Initialize the risk assessor.

        Args:
            custom_rules: Custom risk evaluation rules.
            sensitivity_weights: Custom data sensitivity weights.
            use_case_weights: Custom use case risk weights.
        """
        self._custom_rules = custom_rules or []
        self._sensitivity_weights = sensitivity_weights or self.SENSITIVE_DATA.copy()
        self._use_case_weights = use_case_weights or self.HIGH_RISK_USE_CASES.copy()

    def add_rule(self, rule: RiskRule) -> None:
        """
        Add a custom risk evaluation rule.

        Args:
            rule: Function that evaluates a deployment and returns risk factors.
        """
        self._custom_rules.append(rule)

    def assess(self, deployment: ModelDeployment) -> RiskAssessment:
        """
        Perform a complete risk assessment of a deployment.

        Args:
            deployment: The deployment to assess.

        Returns:
            RiskAssessment with computed risk and factors.
        """
        factors: list[RiskFactor] = []

        # Evaluate data risks
        factors.extend(self._assess_data_risks(deployment))

        # Evaluate model risks
        factors.extend(self._assess_model_risks(deployment))

        # Evaluate usage risks
        factors.extend(self._assess_usage_risks(deployment))

        # Evaluate operational risks
        factors.extend(self._assess_operational_risks(deployment))

        # Run custom rules
        for rule in self._custom_rules:
            try:
                factors.extend(rule(deployment))
            except Exception:
                pass  # Silently skip failed custom rules

        # Calculate total risk score
        risk_score = self._calculate_score(factors)

        # Determine risk level
        risk_level = self._score_to_level(risk_score)

        # Generate mitigations
        mitigations = self._suggest_mitigations(factors, risk_level)

        # Generate explanation
        explanation = self._generate_explanation(factors, risk_score, risk_level)

        return RiskAssessment(
            deployment_id=deployment.deployment_id,
            computed_risk_level=risk_level,
            risk_score=risk_score,
            factors=factors,
            mitigations=mitigations,
            explanation=explanation,
            metadata={
                "deployment_name": deployment.name,
                "current_risk_level": deployment.risk_level.value,
                "factor_count": len(factors),
            },
        )

    def _assess_data_risks(self, deployment: ModelDeployment) -> list[RiskFactor]:
        """Assess risks from data categories."""
        factors = []

        for category in deployment.data_categories:
            normalized = category.lower()
            if normalized in self._sensitivity_weights:
                weight = self._sensitivity_weights[normalized]
                factors.append(
                    RiskFactor(
                        name=f"sensitive_data_{normalized}",
                        category=RiskFactorCategory.DATA,
                        description=f"Handles {normalized.upper()} data",
                        weight=weight,
                        triggered_by=f"data_categories contains '{category}'",
                    )
                )

        # Multiple sensitive data types compound risk
        sensitive_count = sum(
            1 for c in deployment.data_categories
            if c.lower() in self._sensitivity_weights
        )
        if sensitive_count > 2:
            factors.append(
                RiskFactor(
                    name="multiple_sensitive_data",
                    category=RiskFactorCategory.DATA,
                    description=f"Handles {sensitive_count} types of sensitive data",
                    weight=min(0.3, sensitive_count * 0.1),
                    triggered_by=f"{sensitive_count} sensitive data categories",
                )
            )

        # No data classification is a risk
        if not deployment.data_categories:
            factors.append(
                RiskFactor(
                    name="unclassified_data",
                    category=RiskFactorCategory.DATA,
                    description="Data handling is not classified",
                    weight=0.15,
                    triggered_by="Empty data_categories",
                )
            )

        return factors

    def _assess_model_risks(self, deployment: ModelDeployment) -> list[RiskFactor]:
        """Assess risks from model characteristics."""
        factors = []

        model_key = deployment.model_name.lower()
        for pattern, weight in self.MODEL_RISKS.items():
            if pattern in model_key:
                factors.append(
                    RiskFactor(
                        name="advanced_model",
                        category=RiskFactorCategory.MODEL,
                        description=f"Uses advanced model ({deployment.model_name})",
                        weight=weight,
                        triggered_by=f"model_name matches '{pattern}'",
                    )
                )
                break

        # Unknown/unversioned models
        if not deployment.model_version:
            factors.append(
                RiskFactor(
                    name="unversioned_model",
                    category=RiskFactorCategory.MODEL,
                    description="Model version not specified",
                    weight=0.1,
                    triggered_by="Empty model_version",
                )
            )

        # Custom/internal models may have less oversight
        if deployment.model_provider.lower() in ("custom", "internal"):
            factors.append(
                RiskFactor(
                    name="custom_model",
                    category=RiskFactorCategory.MODEL,
                    description="Uses custom/internal model with potentially less oversight",
                    weight=0.2,
                    triggered_by=f"provider is '{deployment.model_provider}'",
                )
            )

        return factors

    def _assess_usage_risks(self, deployment: ModelDeployment) -> list[RiskFactor]:
        """Assess risks from intended use case."""
        factors = []

        # Check description and name for high-risk use case indicators
        search_text = f"{deployment.name} {deployment.description}".lower()

        for pattern, weight in self._use_case_weights.items():
            if pattern in search_text:
                factors.append(
                    RiskFactor(
                        name=f"use_case_{pattern.replace('-', '_')}",
                        category=RiskFactorCategory.USAGE,
                        description=f"Use case involves {pattern}",
                        weight=weight,
                        triggered_by=f"Description/name contains '{pattern}'",
                    )
                )

        return factors

    def _assess_operational_risks(self, deployment: ModelDeployment) -> list[RiskFactor]:
        """Assess operational risks."""
        factors = []

        # Missing owner contact
        if not deployment.owner_contact:
            factors.append(
                RiskFactor(
                    name="missing_contact",
                    category=RiskFactorCategory.OPERATIONAL,
                    description="No owner contact information",
                    weight=0.15,
                    triggered_by="Empty owner_contact",
                )
            )

        # Missing description
        if not deployment.description:
            factors.append(
                RiskFactor(
                    name="missing_description",
                    category=RiskFactorCategory.OPERATIONAL,
                    description="No deployment description provided",
                    weight=0.1,
                    triggered_by="Empty description",
                )
            )

        # Overdue review
        if deployment.needs_review():
            factors.append(
                RiskFactor(
                    name="overdue_review",
                    category=RiskFactorCategory.OPERATIONAL,
                    description="Deployment is overdue for review",
                    weight=0.2,
                    triggered_by="next_review_date has passed",
                )
            )

        # No review scheduled
        if deployment.next_review_date is None and deployment.is_active():
            factors.append(
                RiskFactor(
                    name="no_review_scheduled",
                    category=RiskFactorCategory.OPERATIONAL,
                    description="No periodic review scheduled",
                    weight=0.1,
                    triggered_by="No next_review_date set",
                )
            )

        return factors

    def _calculate_score(self, factors: list[RiskFactor]) -> float:
        """
        Calculate overall risk score from factors.

        Uses a weighted combination that ensures higher risk from
        multiple factors, with diminishing returns.
        """
        if not factors:
            return 0.0

        # Sum weights, but apply diminishing returns
        total_weight = sum(f.weight for f in factors)

        # Apply sigmoid-like scaling to bound score between 0 and 1
        # More factors = higher score, but bounded
        score = total_weight / (1 + total_weight * 0.5)

        return min(1.0, max(0.0, score))

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert a risk score to a risk level."""
        if score >= self.RISK_THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.CRITICAL
        elif score >= self.RISK_THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.HIGH
        elif score >= self.RISK_THRESHOLDS[RiskLevel.LOW]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _suggest_mitigations(
        self,
        factors: list[RiskFactor],
        risk_level: RiskLevel,
    ) -> list[RiskMitigation]:
        """Suggest mitigations based on identified risk factors."""
        mitigations = []
        factor_names = {f.name for f in factors}

        # Data-related mitigations
        data_factors = [f.name for f in factors if f.category == RiskFactorCategory.DATA]
        if data_factors:
            if any("pii" in f or "phi" in f or "pci" in f for f in data_factors):
                mitigations.append(
                    RiskMitigation(
                        title="Implement data anonymization",
                        description="Use data anonymization or pseudonymization "
                                    "before sending to the AI model",
                        priority="high",
                        addresses=[f for f in data_factors if "pii" in f or "phi" in f or "pci" in f],
                        effort="medium",
                    )
                )

            mitigations.append(
                RiskMitigation(
                    title="Add output filtering",
                    description="Implement output filtering to prevent "
                                "sensitive data from appearing in responses",
                    priority="high" if len(data_factors) > 2 else "medium",
                    addresses=data_factors,
                    effort="medium",
                )
            )

        # Operational mitigations
        if "missing_contact" in factor_names:
            mitigations.append(
                RiskMitigation(
                    title="Add owner contact",
                    description="Specify owner contact information for incident response",
                    priority="high",
                    addresses=["missing_contact"],
                    effort="low",
                )
            )

        if "overdue_review" in factor_names or "no_review_scheduled" in factor_names:
            mitigations.append(
                RiskMitigation(
                    title="Schedule periodic review",
                    description="Set up a recurring review schedule based on risk level",
                    priority="medium",
                    addresses=["overdue_review", "no_review_scheduled"],
                    effort="low",
                )
            )

        # Model mitigations
        if "custom_model" in factor_names:
            mitigations.append(
                RiskMitigation(
                    title="Document model evaluation",
                    description="Document the evaluation and testing performed on the custom model",
                    priority="medium",
                    addresses=["custom_model"],
                    effort="medium",
                )
            )

        # High-risk use case mitigations
        usage_factors = [f.name for f in factors if f.category == RiskFactorCategory.USAGE]
        if usage_factors:
            mitigations.append(
                RiskMitigation(
                    title="Add human oversight",
                    description="Implement human review for critical decisions",
                    priority="high" if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else "medium",
                    addresses=usage_factors,
                    effort="high",
                )
            )

        # General high-risk mitigations
        if risk_level == RiskLevel.CRITICAL:
            mitigations.append(
                RiskMitigation(
                    title="Implement comprehensive logging",
                    description="Log all inputs and outputs for audit and incident investigation",
                    priority="high",
                    addresses=[],
                    effort="medium",
                )
            )
            mitigations.append(
                RiskMitigation(
                    title="Add rate limiting",
                    description="Implement strict rate limiting to control exposure",
                    priority="high",
                    addresses=[],
                    effort="low",
                )
            )

        return mitigations

    def _generate_explanation(
        self,
        factors: list[RiskFactor],
        score: float,
        level: RiskLevel,
    ) -> str:
        """Generate a human-readable explanation of the assessment."""
        if not factors:
            return f"Risk Level: {level.value}. No significant risk factors identified."

        parts = [f"Risk Level: {level.value} (score: {score:.2f})."]

        # Group factors by category
        by_category: dict[RiskFactorCategory, list[RiskFactor]] = {}
        for factor in factors:
            by_category.setdefault(factor.category, []).append(factor)

        for category, cat_factors in by_category.items():
            cat_name = category.value.title()
            factor_descriptions = [f.description for f in cat_factors[:3]]
            parts.append(f"{cat_name} risks: {'; '.join(factor_descriptions)}.")

        if len(factors) > 5:
            parts.append(f"Plus {len(factors) - 5} additional risk factors.")

        return " ".join(parts)

    def compare(
        self,
        deployment: ModelDeployment,
        proposed: ModelDeployment,
    ) -> dict[str, Any]:
        """
        Compare risk between current and proposed deployment.

        Args:
            deployment: Current deployment.
            proposed: Proposed changes.

        Returns:
            Dictionary with comparison results.
        """
        current_assessment = self.assess(deployment)
        proposed_assessment = self.assess(proposed)

        score_change = proposed_assessment.risk_score - current_assessment.risk_score
        level_change = None

        risk_order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }

        current_order = risk_order[current_assessment.computed_risk_level]
        proposed_order = risk_order[proposed_assessment.computed_risk_level]

        if proposed_order > current_order:
            level_change = "increased"
        elif proposed_order < current_order:
            level_change = "decreased"
        else:
            level_change = "unchanged"

        # Find new and removed factors
        current_factor_names = {f.name for f in current_assessment.factors}
        proposed_factor_names = {f.name for f in proposed_assessment.factors}

        new_factors = [
            f for f in proposed_assessment.factors
            if f.name not in current_factor_names
        ]
        removed_factors = [
            f for f in current_assessment.factors
            if f.name not in proposed_factor_names
        ]

        return {
            "current_level": current_assessment.computed_risk_level.value,
            "proposed_level": proposed_assessment.computed_risk_level.value,
            "level_change": level_change,
            "current_score": current_assessment.risk_score,
            "proposed_score": proposed_assessment.risk_score,
            "score_change": score_change,
            "new_risk_factors": [f.to_dict() for f in new_factors],
            "removed_risk_factors": [f.to_dict() for f in removed_factors],
            "requires_review": level_change == "increased",
        }
