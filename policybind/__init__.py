"""
PolicyBind: AI Policy as Code Enforcement Platform.

PolicyBind provides a comprehensive framework for enforcing organizational
AI governance policies. It enables organizations to define, manage, and
enforce policies that control how AI systems are used within their
infrastructure.

Key Features:
    - Policy as Code: Define AI usage policies in YAML format
    - Model Registry: Track and manage AI model deployments
    - Token-Based Access Control: Fine-grained permissions for AI API access
    - Incident Management: Track and respond to policy violations
    - Compliance Reporting: Generate reports for regulatory compliance

Example:
    Basic usage of PolicyBind::

        import policybind

        # Check the version
        print(policybind.__version__)

        # Create a policy rule
        from policybind.models import PolicyRule
        rule = PolicyRule(
            name="deny-external-pii",
            description="Deny requests with PII to external models",
            match_conditions={"data_classification": ["pii"]},
            action="DENY"
        )

Public API:
    This module exports the following public API components:

    Version:
        __version__: The package version string

    Exceptions:
        PolicyBindError: Base exception for all PolicyBind errors
        ConfigurationError: Configuration-related errors
        PolicyError: Policy definition errors
        ValidationError: Data validation errors
        EnforcementError: Policy enforcement errors
        RegistryError: Model registry errors
        TokenError: Access token errors
        StorageError: Storage layer errors
        IncidentError: Incident management errors

    Models (via policybind.models):
        BaseModel: Base class for all data models
        PolicyRule: Single policy rule definition
        PolicySet: Collection of policy rules
        PolicyMatch: Result of policy matching
        AIRequest: Incoming AI API request
        AIResponse: Enforcement response
        Decision: Enforcement decision enum
        ModelDeployment: Registered model deployment
        ModelUsageStats: Usage statistics for a deployment
        RiskLevel: Deployment risk level enum
        ApprovalStatus: Deployment approval status enum
"""

from policybind.exceptions import (
    ConfigurationError,
    EnforcementError,
    IncidentError,
    PolicyBindError,
    PolicyError,
    RegistryError,
    StorageError,
    TokenError,
    ValidationError,
)
from policybind.version import __version__

__all__ = [
    # Version
    "__version__",
    # Exceptions
    "PolicyBindError",
    "ConfigurationError",
    "PolicyError",
    "ValidationError",
    "EnforcementError",
    "RegistryError",
    "TokenError",
    "StorageError",
    "IncidentError",
]
