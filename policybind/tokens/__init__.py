"""
Token management for PolicyBind.

This module provides token-based access control for AI API authorization,
including token creation, validation, permissions, usage tracking,
natural language parsing, permission templates, middleware, and policy integration.
"""

from policybind.tokens.manager import (
    TokenCallback,
    TokenEvent,
    TokenManager,
)
from policybind.tokens.middleware import (
    BudgetReservation,
    ReservationStatus,
    TokenAuthConfig,
    TokenAuthMiddleware,
    TokenBudgetTracker,
    TokenExtractionMethod,
    TokenUsageRecorder,
)
from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    TimeWindow,
    Token,
    TokenCreationResult,
    TokenPermissions,
    TokenStatus,
    TokenUsageStats,
)
from policybind.tokens.natural_language import (
    ConfidenceLevel,
    NaturalLanguageTokenParser,
    ParsedConstraint,
    ParseResult,
)
from policybind.tokens.policies import (
    TokenAction,
    TokenActionExecutor,
    TokenActionFactory,
    TokenActionResult,
    TokenActionType,
    TokenCondition,
    TokenConditionFactory,
    TokenField,
)
from policybind.tokens.templates import (
    BATCH_PROCESSING,
    BUSINESS_HOURS,
    DEVELOPER_TESTING,
    EMERGENCY_ACCESS,
    INTERNAL_ONLY,
    MINIMAL,
    PRODUCTION_RESTRICTED,
    READ_ONLY_ANALYTICS,
    PermissionTemplate,
    TemplateCategory,
    TemplateRegistry,
    create_from_template,
    get_default_registry,
    get_template,
    list_templates,
)
from policybind.tokens.validator import (
    CachedValidation,
    TokenValidator,
    ValidationFailureReason,
    ValidationResult,
)

__all__ = [
    # Models
    "BudgetPeriod",
    "RateLimit",
    "TimeWindow",
    "Token",
    "TokenCreationResult",
    "TokenPermissions",
    "TokenStatus",
    "TokenUsageStats",
    # Manager
    "TokenCallback",
    "TokenEvent",
    "TokenManager",
    # Validator
    "CachedValidation",
    "TokenValidator",
    "ValidationFailureReason",
    "ValidationResult",
    # Middleware
    "BudgetReservation",
    "ReservationStatus",
    "TokenAuthConfig",
    "TokenAuthMiddleware",
    "TokenBudgetTracker",
    "TokenExtractionMethod",
    "TokenUsageRecorder",
    # Policy Integration
    "TokenAction",
    "TokenActionExecutor",
    "TokenActionFactory",
    "TokenActionResult",
    "TokenActionType",
    "TokenCondition",
    "TokenConditionFactory",
    "TokenField",
    # Natural Language Parsing
    "ConfidenceLevel",
    "NaturalLanguageTokenParser",
    "ParsedConstraint",
    "ParseResult",
    # Templates
    "PermissionTemplate",
    "TemplateCategory",
    "TemplateRegistry",
    "create_from_template",
    "get_default_registry",
    "get_template",
    "list_templates",
    # Template Constants
    "BATCH_PROCESSING",
    "BUSINESS_HOURS",
    "DEVELOPER_TESTING",
    "EMERGENCY_ACCESS",
    "INTERNAL_ONLY",
    "MINIMAL",
    "PRODUCTION_RESTRICTED",
    "READ_ONLY_ANALYTICS",
]
