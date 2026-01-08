"""
Predefined permission templates for PolicyBind tokens.

This module provides a registry of common permission templates that can be
used to quickly create tokens with standard permission sets.
"""

from dataclasses import dataclass, field
from datetime import time
from enum import Enum
from typing import Any, Callable

from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    TimeWindow,
    TokenPermissions,
)


class TemplateCategory(Enum):
    """Categories for permission templates."""

    DEVELOPMENT = "development"
    """Templates for development and testing."""

    PRODUCTION = "production"
    """Templates for production environments."""

    ANALYTICS = "analytics"
    """Templates for analytics and reporting."""

    INTERNAL = "internal"
    """Templates for internal-only access."""

    CUSTOM = "custom"
    """Custom user-defined templates."""


@dataclass
class PermissionTemplate:
    """
    A predefined permission template.

    Attributes:
        name: Unique identifier for the template.
        display_name: Human-readable name.
        description: Detailed description of what this template allows.
        category: Category this template belongs to.
        permissions: The TokenPermissions this template creates.
        tags: Tags for categorization and search.
        parameters: Customizable parameters with defaults.
    """

    name: str
    display_name: str
    description: str
    category: TemplateCategory
    permissions: TokenPermissions
    tags: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category.value,
            "permissions": self.permissions.to_dict(),
            "tags": self.tags,
            "parameters": self.parameters,
        }

    def create_permissions(self, **overrides: Any) -> TokenPermissions:
        """
        Create TokenPermissions with optional overrides.

        Args:
            **overrides: Values to override from the template.

        Returns:
            TokenPermissions with template defaults and overrides applied.
        """
        # Start with template permissions as dict
        perm_dict = self.permissions.to_dict()

        # Apply any overrides
        for key, value in overrides.items():
            if key in perm_dict:
                perm_dict[key] = value

        return TokenPermissions.from_dict(perm_dict)


class TemplateRegistry:
    """
    Registry for permission templates.

    Provides registration, retrieval, and management of permission templates.
    Includes built-in templates and supports custom user templates.

    Example:
        Using the template registry::

            registry = TemplateRegistry()

            # Get built-in template
            dev_template = registry.get("DEVELOPER_TESTING")
            permissions = dev_template.create_permissions(
                budget_limit=50.0
            )

            # Register custom template
            registry.register(PermissionTemplate(
                name="MY_CUSTOM",
                display_name="My Custom Template",
                description="Custom permissions for my use case",
                category=TemplateCategory.CUSTOM,
                permissions=TokenPermissions(
                    allowed_models=["gpt-4"],
                    budget_limit=100.0,
                ),
            ))
    """

    def __init__(self, include_builtins: bool = True) -> None:
        """
        Initialize the registry.

        Args:
            include_builtins: Whether to include built-in templates.
        """
        self._templates: dict[str, PermissionTemplate] = {}
        self._callbacks: list[Callable[[str, PermissionTemplate], None]] = []

        if include_builtins:
            self._register_builtins()

    def _register_builtins(self) -> None:
        """Register built-in templates."""
        # Developer Testing - Limited budget, all models, all use cases
        self.register(PermissionTemplate(
            name="DEVELOPER_TESTING",
            display_name="Developer Testing",
            description=(
                "Limited budget for development and testing. "
                "Allows all models and use cases with low rate limits."
            ),
            category=TemplateCategory.DEVELOPMENT,
            permissions=TokenPermissions(
                allowed_models=[],  # All models
                allowed_providers=[],  # All providers
                allowed_use_cases=[],  # All use cases
                budget_limit=25.0,
                budget_period=BudgetPeriod.DAILY,
                rate_limit=RateLimit(max_requests=60, period_seconds=60),
                max_tokens_per_request=4000,
            ),
            tags=["development", "testing", "low-budget"],
            parameters={
                "budget_limit": 25.0,
                "rate_limit_requests": 60,
            },
        ))

        # Production Restricted - Specific models and use cases, higher budget
        self.register(PermissionTemplate(
            name="PRODUCTION_RESTRICTED",
            display_name="Production Restricted",
            description=(
                "Production environment with specific models and use cases. "
                "Higher budget with moderate rate limits."
            ),
            category=TemplateCategory.PRODUCTION,
            permissions=TokenPermissions(
                allowed_models=["gpt-4*", "claude-3*"],
                denied_models=["*preview*", "*experimental*"],
                allowed_providers=["openai", "anthropic"],
                allowed_use_cases=["customer-support", "content-generation", "analysis"],
                denied_use_cases=["training", "fine-tuning"],
                denied_data_classifications=["pii", "phi", "pci"],
                budget_limit=500.0,
                budget_period=BudgetPeriod.MONTHLY,
                rate_limit=RateLimit(max_requests=100, period_seconds=60),
                max_tokens_per_request=8000,
            ),
            tags=["production", "restricted", "enterprise"],
            parameters={
                "budget_limit": 500.0,
                "allowed_models": ["gpt-4*", "claude-3*"],
            },
        ))

        # Read-Only Analytics - Only summarization/analysis use cases
        self.register(PermissionTemplate(
            name="READ_ONLY_ANALYTICS",
            display_name="Read-Only Analytics",
            description=(
                "Read-only access for analytics and summarization. "
                "Cannot generate new content, only analyze existing data."
            ),
            category=TemplateCategory.ANALYTICS,
            permissions=TokenPermissions(
                allowed_models=[],  # All models
                allowed_providers=[],  # All providers
                allowed_use_cases=[
                    "embedding",
                    "classification",
                    "analysis",
                    "summarization",
                    "extraction",
                ],
                denied_use_cases=[
                    "generation",
                    "completion",
                    "chat",
                    "creation",
                    "writing",
                ],
                budget_limit=100.0,
                budget_period=BudgetPeriod.MONTHLY,
                rate_limit=RateLimit(max_requests=30, period_seconds=60),
                max_tokens_per_request=16000,
            ),
            tags=["analytics", "read-only", "summarization"],
            parameters={
                "budget_limit": 100.0,
            },
        ))

        # Internal Only - Only internal data classifications
        self.register(PermissionTemplate(
            name="INTERNAL_ONLY",
            display_name="Internal Only",
            description=(
                "Access restricted to internal data only. "
                "No customer data, PII, or external content."
            ),
            category=TemplateCategory.INTERNAL,
            permissions=TokenPermissions(
                allowed_models=[],  # All models
                allowed_providers=[],  # All providers
                allowed_use_cases=[],  # All use cases
                allowed_data_classifications=["internal", "public"],
                denied_data_classifications=[
                    "customer",
                    "pii",
                    "phi",
                    "pci",
                    "confidential",
                    "sensitive",
                    "external",
                ],
                budget_limit=200.0,
                budget_period=BudgetPeriod.MONTHLY,
                rate_limit=RateLimit(max_requests=50, period_seconds=60),
            ),
            tags=["internal", "data-restricted"],
            parameters={
                "budget_limit": 200.0,
            },
        ))

        # Business Hours Only
        self.register(PermissionTemplate(
            name="BUSINESS_HOURS",
            display_name="Business Hours Only",
            description=(
                "Access restricted to business hours (9 AM - 5 PM, Monday-Friday). "
                "Standard permissions with time-based restrictions."
            ),
            category=TemplateCategory.PRODUCTION,
            permissions=TokenPermissions(
                allowed_models=[],  # All models
                allowed_providers=[],  # All providers
                allowed_use_cases=[],  # All use cases
                budget_limit=300.0,
                budget_period=BudgetPeriod.MONTHLY,
                rate_limit=RateLimit(max_requests=60, period_seconds=60),
                valid_hours=TimeWindow.business_hours(),
            ),
            tags=["business-hours", "time-restricted"],
            parameters={
                "budget_limit": 300.0,
                "start_hour": 9,
                "end_hour": 17,
            },
        ))

        # High-Volume Batch Processing
        self.register(PermissionTemplate(
            name="BATCH_PROCESSING",
            display_name="Batch Processing",
            description=(
                "High-volume batch processing with higher rate limits. "
                "Designed for automated workflows and data pipelines."
            ),
            category=TemplateCategory.PRODUCTION,
            permissions=TokenPermissions(
                allowed_models=["gpt-3.5*", "claude-instant*", "claude-haiku*"],
                denied_models=["gpt-4*", "claude-3-opus*", "claude-opus*"],
                allowed_providers=[],  # All providers
                allowed_use_cases=["batch", "processing", "automation", "pipeline"],
                budget_limit=1000.0,
                budget_period=BudgetPeriod.MONTHLY,
                rate_limit=RateLimit(max_requests=500, period_seconds=60),
                max_tokens_per_request=2000,
            ),
            tags=["batch", "high-volume", "automation"],
            parameters={
                "budget_limit": 1000.0,
                "rate_limit_requests": 500,
            },
        ))

        # Emergency / Elevated Access
        self.register(PermissionTemplate(
            name="EMERGENCY_ACCESS",
            display_name="Emergency Access",
            description=(
                "Elevated access for emergency situations. "
                "Higher limits but with approval requirements for high costs."
            ),
            category=TemplateCategory.PRODUCTION,
            permissions=TokenPermissions(
                allowed_models=[],  # All models
                allowed_providers=[],  # All providers
                allowed_use_cases=[],  # All use cases
                budget_limit=2000.0,
                budget_period=BudgetPeriod.DAILY,
                rate_limit=RateLimit(max_requests=200, period_seconds=60),
                require_approval_above=100.0,
            ),
            tags=["emergency", "elevated", "approval-required"],
            parameters={
                "budget_limit": 2000.0,
                "approval_threshold": 100.0,
            },
        ))

        # Minimal / Restrictive
        self.register(PermissionTemplate(
            name="MINIMAL",
            display_name="Minimal Access",
            description=(
                "Highly restrictive access for limited use cases. "
                "Very low budget and rate limits."
            ),
            category=TemplateCategory.INTERNAL,
            permissions=TokenPermissions(
                allowed_models=["gpt-3.5-turbo"],
                allowed_providers=["openai"],
                allowed_use_cases=["classification"],
                budget_limit=5.0,
                budget_period=BudgetPeriod.DAILY,
                rate_limit=RateLimit(max_requests=10, period_seconds=60),
                max_tokens_per_request=500,
            ),
            tags=["minimal", "restrictive", "low-risk"],
            parameters={
                "budget_limit": 5.0,
            },
        ))

    def register(
        self,
        template: PermissionTemplate,
        overwrite: bool = False,
    ) -> None:
        """
        Register a permission template.

        Args:
            template: The template to register.
            overwrite: If True, overwrite existing template with same name.

        Raises:
            ValueError: If template name already exists and overwrite is False.
        """
        if template.name in self._templates and not overwrite:
            raise ValueError(
                f"Template '{template.name}' already exists. "
                "Use overwrite=True to replace."
            )

        self._templates[template.name] = template

        # Notify callbacks
        for callback in self._callbacks:
            callback(template.name, template)

    def unregister(self, name: str) -> bool:
        """
        Unregister a template.

        Args:
            name: Name of the template to remove.

        Returns:
            True if template was removed, False if it didn't exist.
        """
        if name in self._templates:
            del self._templates[name]
            return True
        return False

    def get(self, name: str) -> PermissionTemplate | None:
        """
        Get a template by name.

        Args:
            name: Name of the template.

        Returns:
            The template if found, None otherwise.
        """
        return self._templates.get(name)

    def get_or_raise(self, name: str) -> PermissionTemplate:
        """
        Get a template by name, raising if not found.

        Args:
            name: Name of the template.

        Returns:
            The template.

        Raises:
            KeyError: If template is not found.
        """
        template = self._templates.get(name)
        if template is None:
            raise KeyError(f"Template '{name}' not found")
        return template

    def list_all(self) -> list[PermissionTemplate]:
        """Get all registered templates."""
        return list(self._templates.values())

    def list_names(self) -> list[str]:
        """Get names of all registered templates."""
        return list(self._templates.keys())

    def list_by_category(self, category: TemplateCategory) -> list[PermissionTemplate]:
        """
        Get templates by category.

        Args:
            category: Category to filter by.

        Returns:
            List of templates in the category.
        """
        return [t for t in self._templates.values() if t.category == category]

    def list_by_tag(self, tag: str) -> list[PermissionTemplate]:
        """
        Get templates that have a specific tag.

        Args:
            tag: Tag to search for.

        Returns:
            List of templates with the tag.
        """
        return [t for t in self._templates.values() if tag in t.tags]

    def search(self, query: str) -> list[PermissionTemplate]:
        """
        Search templates by name, display name, or description.

        Args:
            query: Search query (case-insensitive).

        Returns:
            List of matching templates.
        """
        query_lower = query.lower()
        results = []

        for template in self._templates.values():
            if (
                query_lower in template.name.lower()
                or query_lower in template.display_name.lower()
                or query_lower in template.description.lower()
                or any(query_lower in tag.lower() for tag in template.tags)
            ):
                results.append(template)

        return results

    def create_permissions_from_template(
        self,
        name: str,
        **overrides: Any,
    ) -> TokenPermissions:
        """
        Create TokenPermissions from a template with overrides.

        Args:
            name: Template name.
            **overrides: Values to override from the template.

        Returns:
            TokenPermissions instance.

        Raises:
            KeyError: If template is not found.
        """
        template = self.get_or_raise(name)
        return template.create_permissions(**overrides)

    def on_register(
        self,
        callback: Callable[[str, PermissionTemplate], None],
    ) -> None:
        """
        Add a callback for template registration.

        Args:
            callback: Function to call when a template is registered.
        """
        self._callbacks.append(callback)

    def __contains__(self, name: str) -> bool:
        """Check if a template exists."""
        return name in self._templates

    def __len__(self) -> int:
        """Get number of registered templates."""
        return len(self._templates)

    def __iter__(self):
        """Iterate over templates."""
        return iter(self._templates.values())


# Global default registry instance
_default_registry: TemplateRegistry | None = None


def get_default_registry() -> TemplateRegistry:
    """
    Get the default template registry.

    Returns:
        The default TemplateRegistry instance.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = TemplateRegistry()
    return _default_registry


def get_template(name: str) -> PermissionTemplate | None:
    """
    Get a template from the default registry.

    Args:
        name: Template name.

    Returns:
        The template if found, None otherwise.
    """
    return get_default_registry().get(name)


def list_templates() -> list[str]:
    """
    List all template names in the default registry.

    Returns:
        List of template names.
    """
    return get_default_registry().list_names()


def create_from_template(name: str, **overrides: Any) -> TokenPermissions:
    """
    Create TokenPermissions from a template in the default registry.

    Args:
        name: Template name.
        **overrides: Values to override from the template.

    Returns:
        TokenPermissions instance.
    """
    return get_default_registry().create_permissions_from_template(name, **overrides)


# Convenience constants for built-in template names
DEVELOPER_TESTING = "DEVELOPER_TESTING"
PRODUCTION_RESTRICTED = "PRODUCTION_RESTRICTED"
READ_ONLY_ANALYTICS = "READ_ONLY_ANALYTICS"
INTERNAL_ONLY = "INTERNAL_ONLY"
BUSINESS_HOURS = "BUSINESS_HOURS"
BATCH_PROCESSING = "BATCH_PROCESSING"
EMERGENCY_ACCESS = "EMERGENCY_ACCESS"
MINIMAL = "MINIMAL"
