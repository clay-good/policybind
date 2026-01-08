"""
Exception classes for PolicyBind.

This module defines the exception hierarchy used throughout PolicyBind.
All custom exceptions inherit from PolicyBindError to allow for easy
catching of any PolicyBind-specific exception.
"""

from typing import Any


class PolicyBindError(Exception):
    """
    Base exception for all PolicyBind errors.

    All custom exceptions in PolicyBind inherit from this class,
    allowing callers to catch any PolicyBind-specific exception
    with a single except clause.

    Attributes:
        message: Human-readable error description.
        details: Optional dictionary containing additional error context.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        """
        Initialize the exception.

        Args:
            message: Human-readable error description.
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return f"{self.__class__.__name__}(message={self.message!r}, details={self.details!r})"


class ConfigurationError(PolicyBindError):
    """
    Raised when there is an error in PolicyBind configuration.

    This exception is raised when configuration files are missing,
    malformed, contain invalid values, or when required configuration
    options are not provided.

    Examples:
        - Missing required configuration file
        - Invalid YAML syntax in configuration
        - Configuration value out of allowed range
        - Missing required environment variable
    """

    pass


class PolicyError(PolicyBindError):
    """
    Raised when there is an error related to policy definitions.

    This exception is raised when policies cannot be parsed, contain
    syntax errors, or have semantic issues that prevent them from
    being loaded or applied.

    Examples:
        - Invalid policy YAML syntax
        - Unknown action type in policy rule
        - Invalid condition expression
        - Circular policy includes
    """

    pass


class ValidationError(PolicyBindError):
    """
    Raised when validation of data or policies fails.

    This exception is raised when input data fails validation checks,
    such as missing required fields, invalid field values, or
    constraint violations.

    Examples:
        - Missing required field in AI request
        - Invalid data classification value
        - Model name does not match allowed pattern
        - Budget value is negative
    """

    pass


class EnforcementError(PolicyBindError):
    """
    Raised when policy enforcement encounters an error.

    This exception is raised when the enforcement pipeline fails
    to process a request, an action fails to execute, or there
    is an error in the enforcement logic.

    Examples:
        - Action execution failed
        - Pipeline middleware error
        - Unable to determine enforcement decision
        - Enforcement timeout exceeded
    """

    pass


class RegistryError(PolicyBindError):
    """
    Raised when there is an error in the model registry.

    This exception is raised when model deployment operations fail,
    such as registration, approval, or lookup failures.

    Examples:
        - Deployment not found
        - Deployment already exists
        - Invalid deployment status transition
        - Approval workflow error
    """

    pass


class TokenError(PolicyBindError):
    """
    Raised when there is an error related to access tokens.

    This exception is raised when token operations fail, such as
    creation, validation, or revocation errors.

    Examples:
        - Token not found
        - Token expired
        - Token validation failed
        - Token permission denied
        - Budget exceeded
    """

    pass


class StorageError(PolicyBindError):
    """
    Raised when there is an error in the storage layer.

    This exception is raised when database operations fail, such as
    connection errors, query failures, or data integrity issues.

    Examples:
        - Database connection failed
        - Query execution error
        - Constraint violation
        - Migration failed
    """

    pass


class IncidentError(PolicyBindError):
    """
    Raised when there is an error in incident management.

    This exception is raised when incident operations fail, such as
    creation, update, or workflow transitions.

    Examples:
        - Incident not found
        - Invalid status transition
        - Workflow error
        - Report generation failed
    """

    pass
