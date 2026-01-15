"""
Exception classes for PolicyBind.

This module defines the exception hierarchy used throughout PolicyBind.
All custom exceptions inherit from PolicyBindError to allow for easy
catching of any PolicyBind-specific exception.

Error Codes:
    E1xxx: Configuration errors
    E2xxx: Policy errors
    E3xxx: Validation errors
    E4xxx: Enforcement errors
    E5xxx: Registry errors
    E6xxx: Token errors
    E7xxx: Storage errors
    E8xxx: Incident errors
"""

from enum import Enum
from typing import Any


class ErrorCode(Enum):
    """
    Enumeration of all PolicyBind error codes.

    Error codes provide a machine-readable identifier for each error type,
    enabling automated error handling and troubleshooting.
    """

    # Configuration errors (E1xxx)
    CONFIG_FILE_NOT_FOUND = "E1001"
    CONFIG_INVALID_YAML = "E1002"
    CONFIG_MISSING_REQUIRED = "E1003"
    CONFIG_INVALID_VALUE = "E1004"
    CONFIG_ENV_VAR_MISSING = "E1005"
    CONFIG_SCHEMA_ERROR = "E1006"

    # Policy errors (E2xxx)
    POLICY_FILE_NOT_FOUND = "E2001"
    POLICY_INVALID_YAML = "E2002"
    POLICY_INVALID_SYNTAX = "E2003"
    POLICY_UNKNOWN_ACTION = "E2004"
    POLICY_INVALID_CONDITION = "E2005"
    POLICY_CIRCULAR_INCLUDE = "E2006"
    POLICY_CONFLICTING_RULES = "E2007"
    POLICY_VERSION_ERROR = "E2008"
    POLICY_RELOAD_FAILED = "E2009"

    # Validation errors (E3xxx)
    VALIDATION_REQUIRED_FIELD = "E3001"
    VALIDATION_INVALID_TYPE = "E3002"
    VALIDATION_INVALID_VALUE = "E3003"
    VALIDATION_CONSTRAINT_FAILED = "E3004"
    VALIDATION_PATTERN_MISMATCH = "E3005"

    # Enforcement errors (E4xxx)
    ENFORCEMENT_PIPELINE_ERROR = "E4001"
    ENFORCEMENT_ACTION_FAILED = "E4002"
    ENFORCEMENT_TIMEOUT = "E4003"
    ENFORCEMENT_MIDDLEWARE_ERROR = "E4004"
    ENFORCEMENT_NO_DECISION = "E4005"

    # Registry errors (E5xxx)
    REGISTRY_DEPLOYMENT_NOT_FOUND = "E5001"
    REGISTRY_DEPLOYMENT_EXISTS = "E5002"
    REGISTRY_INVALID_STATUS = "E5003"
    REGISTRY_APPROVAL_ERROR = "E5004"
    REGISTRY_WORKFLOW_ERROR = "E5005"
    REGISTRY_COMPLIANCE_ERROR = "E5006"

    # Token errors (E6xxx)
    TOKEN_NOT_FOUND = "E6001"
    TOKEN_EXPIRED = "E6002"
    TOKEN_INVALID = "E6003"
    TOKEN_REVOKED = "E6004"
    TOKEN_PERMISSION_DENIED = "E6005"
    TOKEN_BUDGET_EXCEEDED = "E6006"
    TOKEN_RATE_LIMITED = "E6007"
    TOKEN_CREATION_FAILED = "E6008"

    # Storage errors (E7xxx)
    STORAGE_CONNECTION_FAILED = "E7001"
    STORAGE_QUERY_ERROR = "E7002"
    STORAGE_INTEGRITY_ERROR = "E7003"
    STORAGE_MIGRATION_ERROR = "E7004"
    STORAGE_TRANSACTION_ERROR = "E7005"

    # Incident errors (E8xxx)
    INCIDENT_NOT_FOUND = "E8001"
    INCIDENT_INVALID_STATUS = "E8002"
    INCIDENT_WORKFLOW_ERROR = "E8003"
    INCIDENT_ALREADY_RESOLVED = "E8004"

    # General errors (E9xxx)
    UNKNOWN_ERROR = "E9999"


# Mapping of error codes to helpful suggestions
ERROR_SUGGESTIONS: dict[str, str] = {
    "E1001": "Check that the configuration file path is correct and the file exists.",
    "E1002": "Verify that the configuration file contains valid YAML syntax.",
    "E1003": "Add the missing required configuration option to your config file.",
    "E1004": "Check the allowed values for this configuration option in the documentation.",
    "E1005": "Set the required environment variable or use a configuration file instead.",
    "E2001": "Check that the policy file path is correct and the file exists.",
    "E2002": "Verify that the policy file contains valid YAML syntax.",
    "E2003": "Review the policy syntax documentation and fix the error.",
    "E2004": "Use a valid action type: ALLOW, DENY, MODIFY, REQUIRE_APPROVAL, RATE_LIMIT, AUDIT, REDIRECT.",
    "E2005": "Check the condition syntax in your policy. See the policy reference documentation.",
    "E2006": "Remove the circular include or reorganize your policy file structure.",
    "E3001": "Provide the required field in your request.",
    "E3002": "Check that the field value has the correct type.",
    "E3003": "Verify that the field value is within the allowed range or options.",
    "E5001": "Verify the deployment ID is correct. Use 'policybind registry list' to see all deployments.",
    "E5002": "Use a different deployment name or update the existing deployment.",
    "E6001": "Verify the token ID is correct. Use 'policybind token list' to see all tokens.",
    "E6002": "The token has expired. Create a new token with 'policybind token create'.",
    "E6004": "This token has been revoked. Create a new token.",
    "E6006": "Your token budget has been exceeded. Contact an administrator to increase the limit.",
    "E6007": "Rate limit exceeded. Wait before making more requests.",
    "E7001": "Check that the database file exists and is accessible. Run 'policybind init' to create it.",
    "E8001": "Verify the incident ID is correct. Use 'policybind incident list' to see all incidents.",
}


class PolicyBindError(Exception):
    """
    Base exception for all PolicyBind errors.

    All custom exceptions in PolicyBind inherit from this class,
    allowing callers to catch any PolicyBind-specific exception
    with a single except clause.

    Attributes:
        message: Human-readable error description.
        code: Machine-readable error code.
        details: Optional dictionary containing additional error context.
        suggestion: Optional suggestion for how to fix the error.
    """

    default_code: ErrorCode = ErrorCode.UNKNOWN_ERROR

    def __init__(
        self,
        message: str,
        code: ErrorCode | None = None,
        details: dict[str, Any] | None = None,
        suggestion: str | None = None,
    ) -> None:
        """
        Initialize the exception.

        Args:
            message: Human-readable error description.
            code: Machine-readable error code.
            details: Optional dictionary containing additional error context.
            suggestion: Optional suggestion for how to fix the error.
        """
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.details = details or {}
        self._suggestion = suggestion

    @property
    def suggestion(self) -> str | None:
        """Get the suggestion for how to fix this error."""
        if self._suggestion:
            return self._suggestion
        return ERROR_SUGGESTIONS.get(self.code.value)

    def __str__(self) -> str:
        """Return string representation of the error."""
        parts = [f"[{self.code.value}] {self.message}"]
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            parts[0] += f" ({details_str})"
        return parts[0]

    def format_full(self) -> str:
        """
        Return full error message with suggestion.

        Returns:
            Full error message including suggestion if available.
        """
        parts = [f"[{self.code.value}] {self.message}"]
        if self.details:
            parts.append(f"Details: {self.details}")
        if self.suggestion:
            parts.append(f"Suggestion: {self.suggestion}")
        return "\n".join(parts)

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"code={self.code!r}, "
            f"details={self.details!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the exception to a dictionary for serialization.

        Returns:
            Dictionary representation of the error.
        """
        return {
            "error": self.__class__.__name__,
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
            "suggestion": self.suggestion,
        }


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

    default_code = ErrorCode.CONFIG_INVALID_VALUE


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

    default_code = ErrorCode.POLICY_INVALID_SYNTAX


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

    default_code = ErrorCode.VALIDATION_INVALID_VALUE


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

    default_code = ErrorCode.ENFORCEMENT_PIPELINE_ERROR


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

    default_code = ErrorCode.REGISTRY_WORKFLOW_ERROR


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

    default_code = ErrorCode.TOKEN_INVALID


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

    default_code = ErrorCode.STORAGE_QUERY_ERROR


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

    default_code = ErrorCode.INCIDENT_WORKFLOW_ERROR
