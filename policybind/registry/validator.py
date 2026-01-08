"""
Deployment validation for PolicyBind registry.

This module provides the DeploymentValidator class for validating
model deployment registrations for completeness and compliance.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel


class ValidationSeverity(Enum):
    """Severity level for validation messages."""

    ERROR = "error"
    """Critical issue that prevents registration."""

    WARNING = "warning"
    """Issue that should be addressed but doesn't block registration."""

    INFO = "info"
    """Informational message or suggestion."""


@dataclass
class ValidationMessage:
    """
    A single validation message.

    Attributes:
        severity: Severity level of the message.
        field: The field that the message relates to.
        message: Human-readable description of the issue.
        code: Machine-readable error code for programmatic handling.
    """

    severity: ValidationSeverity
    field: str
    message: str
    code: str = ""


@dataclass
class DeploymentValidationResult:
    """
    Result of validating a deployment registration.

    Attributes:
        valid: Whether the deployment passed validation (no errors).
        messages: List of validation messages.
    """

    valid: bool = True
    messages: list[ValidationMessage] = field(default_factory=list)

    def add_error(
        self,
        field: str,
        message: str,
        code: str = "",
    ) -> None:
        """Add an error message."""
        self.messages.append(
            ValidationMessage(
                severity=ValidationSeverity.ERROR,
                field=field,
                message=message,
                code=code,
            )
        )
        self.valid = False

    def add_warning(
        self,
        field: str,
        message: str,
        code: str = "",
    ) -> None:
        """Add a warning message."""
        self.messages.append(
            ValidationMessage(
                severity=ValidationSeverity.WARNING,
                field=field,
                message=message,
                code=code,
            )
        )

    def add_info(
        self,
        field: str,
        message: str,
        code: str = "",
    ) -> None:
        """Add an info message."""
        self.messages.append(
            ValidationMessage(
                severity=ValidationSeverity.INFO,
                field=field,
                message=message,
                code=code,
            )
        )

    @property
    def errors(self) -> list[ValidationMessage]:
        """Get only error messages."""
        return [m for m in self.messages if m.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationMessage]:
        """Get only warning messages."""
        return [m for m in self.messages if m.severity == ValidationSeverity.WARNING]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a dictionary."""
        return {
            "valid": self.valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "messages": [
                {
                    "severity": m.severity.value,
                    "field": m.field,
                    "message": m.message,
                    "code": m.code,
                }
                for m in self.messages
            ],
        }


# Type alias for custom validators
CustomValidator = Callable[[ModelDeployment, DeploymentValidationResult], None]


class DeploymentValidator:
    """
    Validates deployment registrations for completeness and compliance.

    The DeploymentValidator checks that:
    - Required fields are populated
    - Fields have valid formats (e.g., email addresses)
    - Data categories are from an allowed list
    - High-risk deployments have additional required fields
    - Custom validation rules are satisfied

    Example:
        Validating a deployment::

            validator = DeploymentValidator()
            result = validator.validate(deployment)

            if not result.valid:
                for error in result.errors:
                    print(f"Error in {error.field}: {error.message}")
    """

    # Default allowed data categories
    DEFAULT_DATA_CATEGORIES = frozenset([
        "public",
        "internal",
        "confidential",
        "restricted",
        "pii",
        "phi",
        "pci",
        "financial",
        "healthcare",
        "legal",
        "hr",
        "customer",
        "employee",
        "proprietary",
        "trade_secret",
    ])

    # Default allowed model providers
    DEFAULT_PROVIDERS = frozenset([
        "openai",
        "anthropic",
        "google",
        "amazon",
        "microsoft",
        "meta",
        "cohere",
        "huggingface",
        "custom",
        "internal",
    ])

    # Email pattern for validation
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    def __init__(
        self,
        allowed_data_categories: set[str] | None = None,
        allowed_providers: set[str] | None = None,
        require_owner_contact_email: bool = True,
        require_description_for_high_risk: bool = True,
        min_description_length: int = 10,
        owner_validator: Callable[[str], bool] | None = None,
    ) -> None:
        """
        Initialize the deployment validator.

        Args:
            allowed_data_categories: Set of allowed data category values.
            allowed_providers: Set of allowed model provider values.
            require_owner_contact_email: Whether owner_contact must be an email.
            require_description_for_high_risk: Whether high-risk deployments
                require a detailed description.
            min_description_length: Minimum description length for high-risk.
            owner_validator: Custom function to validate owner exists.
        """
        self._allowed_categories = allowed_data_categories or self.DEFAULT_DATA_CATEGORIES
        self._allowed_providers = allowed_providers or self.DEFAULT_PROVIDERS
        self._require_email = require_owner_contact_email
        self._require_high_risk_description = require_description_for_high_risk
        self._min_description_length = min_description_length
        self._owner_validator = owner_validator
        self._custom_validators: list[CustomValidator] = []

    def add_validator(self, validator: CustomValidator) -> None:
        """
        Add a custom validation function.

        Args:
            validator: Function that takes a deployment and result,
                and adds any validation messages to the result.
        """
        self._custom_validators.append(validator)

    def validate(self, deployment: ModelDeployment) -> DeploymentValidationResult:
        """
        Validate a deployment registration.

        Args:
            deployment: The ModelDeployment to validate.

        Returns:
            DeploymentValidationResult with validation outcome.
        """
        result = DeploymentValidationResult()

        # Required field checks
        self._validate_required_fields(deployment, result)

        # Format validation
        self._validate_formats(deployment, result)

        # Data category validation
        self._validate_data_categories(deployment, result)

        # Provider validation
        self._validate_provider(deployment, result)

        # Risk-level specific validation
        self._validate_risk_requirements(deployment, result)

        # Owner validation
        self._validate_owner(deployment, result)

        # Run custom validators
        for validator in self._custom_validators:
            validator(deployment, result)

        return result

    def _validate_required_fields(
        self,
        deployment: ModelDeployment,
        result: DeploymentValidationResult,
    ) -> None:
        """Validate that required fields are present."""
        if not deployment.name:
            result.add_error(
                "name",
                "Deployment name is required",
                "REQUIRED_FIELD",
            )

        if not deployment.model_provider:
            result.add_error(
                "model_provider",
                "Model provider is required",
                "REQUIRED_FIELD",
            )

        if not deployment.model_name:
            result.add_error(
                "model_name",
                "Model name is required",
                "REQUIRED_FIELD",
            )

        if not deployment.owner:
            result.add_error(
                "owner",
                "Owner is required",
                "REQUIRED_FIELD",
            )

        if not deployment.owner_contact:
            result.add_error(
                "owner_contact",
                "Owner contact information is required",
                "REQUIRED_FIELD",
            )

    def _validate_formats(
        self,
        deployment: ModelDeployment,
        result: DeploymentValidationResult,
    ) -> None:
        """Validate field formats."""
        # Owner contact email validation
        if deployment.owner_contact and self._require_email:
            if not self.EMAIL_PATTERN.match(deployment.owner_contact):
                result.add_error(
                    "owner_contact",
                    "Owner contact must be a valid email address",
                    "INVALID_FORMAT",
                )

        # Name format - alphanumeric with dashes/underscores
        if deployment.name:
            if len(deployment.name) > 100:
                result.add_warning(
                    "name",
                    "Deployment name is very long (>100 characters)",
                    "FIELD_TOO_LONG",
                )

        # Approval ticket format hint
        if deployment.approval_ticket:
            # Just a warning if it doesn't look like a ticket reference
            if len(deployment.approval_ticket) < 3:
                result.add_warning(
                    "approval_ticket",
                    "Approval ticket reference seems too short",
                    "SUSPICIOUS_VALUE",
                )

    def _validate_data_categories(
        self,
        deployment: ModelDeployment,
        result: DeploymentValidationResult,
    ) -> None:
        """Validate data categories."""
        if not deployment.data_categories:
            result.add_warning(
                "data_categories",
                "No data categories specified; consider classifying data handled",
                "MISSING_CLASSIFICATION",
            )
            return

        invalid_categories = []
        for category in deployment.data_categories:
            normalized = category.lower().strip()
            if normalized not in self._allowed_categories:
                invalid_categories.append(category)

        if invalid_categories:
            allowed_list = ", ".join(sorted(self._allowed_categories)[:10])
            result.add_error(
                "data_categories",
                f"Invalid data categories: {invalid_categories}. "
                f"Allowed categories include: {allowed_list}...",
                "INVALID_CATEGORY",
            )

        # Warn about sensitive data combinations
        categories_set = set(c.lower() for c in deployment.data_categories)
        if "pii" in categories_set and "public" in categories_set:
            result.add_warning(
                "data_categories",
                "Deployment handles both PII and public data; "
                "ensure proper data segregation",
                "SENSITIVE_COMBINATION",
            )

    def _validate_provider(
        self,
        deployment: ModelDeployment,
        result: DeploymentValidationResult,
    ) -> None:
        """Validate model provider."""
        if not deployment.model_provider:
            return

        normalized = deployment.model_provider.lower().strip()
        if normalized not in self._allowed_providers:
            allowed_list = ", ".join(sorted(self._allowed_providers))
            result.add_error(
                "model_provider",
                f"Unknown provider '{deployment.model_provider}'. "
                f"Allowed providers: {allowed_list}",
                "INVALID_PROVIDER",
            )

    def _validate_risk_requirements(
        self,
        deployment: ModelDeployment,
        result: DeploymentValidationResult,
    ) -> None:
        """Validate risk-level specific requirements."""
        is_high_risk = deployment.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

        if is_high_risk:
            # High-risk deployments need detailed description
            if self._require_high_risk_description:
                if not deployment.description:
                    result.add_error(
                        "description",
                        "High-risk deployments require a description",
                        "HIGH_RISK_REQUIREMENT",
                    )
                elif len(deployment.description) < self._min_description_length:
                    result.add_error(
                        "description",
                        f"High-risk deployments require a detailed description "
                        f"(minimum {self._min_description_length} characters)",
                        "HIGH_RISK_REQUIREMENT",
                    )

            # High-risk should have data categories
            if not deployment.data_categories:
                result.add_error(
                    "data_categories",
                    "High-risk deployments must specify data categories",
                    "HIGH_RISK_REQUIREMENT",
                )

            # Suggest approval ticket for high-risk
            if not deployment.approval_ticket:
                result.add_info(
                    "approval_ticket",
                    "Consider adding an approval ticket reference for audit trail",
                    "SUGGESTED_FIELD",
                )

        # Critical risk additional requirements
        if deployment.risk_level == RiskLevel.CRITICAL:
            if not deployment.model_version:
                result.add_warning(
                    "model_version",
                    "Critical-risk deployments should specify exact model version",
                    "CRITICAL_RISK_SUGGESTION",
                )

    def _validate_owner(
        self,
        deployment: ModelDeployment,
        result: DeploymentValidationResult,
    ) -> None:
        """Validate owner exists and has permission."""
        if not deployment.owner:
            return

        if self._owner_validator:
            try:
                if not self._owner_validator(deployment.owner):
                    result.add_error(
                        "owner",
                        f"Owner '{deployment.owner}' not found or lacks deploy permission",
                        "INVALID_OWNER",
                    )
            except Exception as e:
                result.add_warning(
                    "owner",
                    f"Could not validate owner: {e}",
                    "VALIDATION_ERROR",
                )

    def validate_for_approval(
        self,
        deployment: ModelDeployment,
    ) -> DeploymentValidationResult:
        """
        Validate a deployment for approval transition.

        This performs additional checks required before a deployment
        can be approved.

        Args:
            deployment: The deployment to validate.

        Returns:
            DeploymentValidationResult with validation outcome.
        """
        result = self.validate(deployment)

        # Must pass basic validation first
        if not result.valid:
            return result

        # Check current status allows approval
        if deployment.approval_status == ApprovalStatus.APPROVED:
            result.add_error(
                "approval_status",
                "Deployment is already approved",
                "ALREADY_APPROVED",
            )
        elif deployment.approval_status == ApprovalStatus.REJECTED:
            result.add_warning(
                "approval_status",
                "Deployment was previously rejected; review rejection reason",
                "PREVIOUSLY_REJECTED",
            )

        # High-risk requires approval ticket
        if deployment.is_high_risk() and not deployment.approval_ticket:
            result.add_error(
                "approval_ticket",
                "High-risk deployments require an approval ticket reference",
                "APPROVAL_REQUIREMENT",
            )

        return result

    def validate_for_update(
        self,
        current: ModelDeployment,
        updated: ModelDeployment,
    ) -> DeploymentValidationResult:
        """
        Validate an update to an existing deployment.

        Args:
            current: The current deployment state.
            updated: The proposed updated deployment.

        Returns:
            DeploymentValidationResult with validation outcome.
        """
        result = self.validate(updated)

        # Deployment ID should not change
        if current.deployment_id != updated.deployment_id:
            result.add_error(
                "deployment_id",
                "Deployment ID cannot be changed",
                "IMMUTABLE_FIELD",
            )

        # Check for risk level escalation
        risk_order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        if risk_order[updated.risk_level] > risk_order[current.risk_level]:
            result.add_warning(
                "risk_level",
                f"Risk level being escalated from {current.risk_level.value} "
                f"to {updated.risk_level.value}; may require re-approval",
                "RISK_ESCALATION",
            )

        # Warn about sensitive field changes
        if updated.model_provider != current.model_provider:
            result.add_warning(
                "model_provider",
                "Model provider change may require re-validation",
                "SIGNIFICANT_CHANGE",
            )

        if updated.model_name != current.model_name:
            result.add_warning(
                "model_name",
                "Model change may require re-approval",
                "SIGNIFICANT_CHANGE",
            )

        return result
