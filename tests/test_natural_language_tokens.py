"""
Tests for natural language token parsing and permission templates.

This module tests the NaturalLanguageTokenParser class for parsing
natural language descriptions into TokenPermissions, and the TemplateRegistry
for managing predefined permission templates.
"""

from datetime import time

import pytest

from policybind.tokens.models import BudgetPeriod, RateLimit, TokenPermissions
from policybind.tokens.natural_language import (
    ConfidenceLevel,
    NaturalLanguageTokenParser,
    ParsedConstraint,
    ParseResult,
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


# =============================================================================
# NaturalLanguageTokenParser Tests
# =============================================================================


class TestNaturalLanguageTokenParser:
    """Tests for the NaturalLanguageTokenParser class."""

    @pytest.fixture
    def parser(self) -> NaturalLanguageTokenParser:
        """Create a parser instance."""
        return NaturalLanguageTokenParser()

    # -------------------------------------------------------------------------
    # Basic Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_empty_description(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing an empty description."""
        result = parser.parse("")

        assert result.overall_confidence == ConfidenceLevel.LOW
        assert "Empty description provided" in result.warnings
        assert len(result.constraints) == 0

    def test_parse_whitespace_only(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing whitespace-only description."""
        result = parser.parse("   \n\t  ")

        assert result.overall_confidence == ConfidenceLevel.LOW

    def test_parse_returns_parse_result(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test that parse returns a ParseResult."""
        result = parser.parse("allow gpt-4")

        assert isinstance(result, ParseResult)
        assert isinstance(result.permissions, TokenPermissions)
        assert isinstance(result.constraints, list)

    # -------------------------------------------------------------------------
    # Model Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_allow_model(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'allow model X'."""
        result = parser.parse("allow model gpt-4")

        assert "gpt-4" in result.permissions.allowed_models
        assert result.overall_confidence == ConfidenceLevel.HIGH

    def test_parse_only_model(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'only model X'."""
        result = parser.parse("only model claude-3-opus")

        assert "claude-3-opus" in result.permissions.allowed_models

    def test_parse_use_model(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'use model X'."""
        result = parser.parse("use model gpt-3.5-turbo")

        assert "gpt-3.5-turbo" in result.permissions.allowed_models

    def test_parse_deny_model(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'deny model X' / 'block model X'."""
        result = parser.parse("deny model gpt-4-32k")

        assert "gpt-4-32k" in result.permissions.denied_models

    def test_parse_block_model(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'block model X'."""
        result = parser.parse("block model gpt-4")

        assert "gpt-4" in result.permissions.denied_models

    def test_parse_models_list(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'models: X, Y, Z'."""
        result = parser.parse("models: gpt-4, claude-3-opus, gemini-pro")

        assert "gpt-4" in result.permissions.allowed_models
        assert "claude-3-opus" in result.permissions.allowed_models
        assert "gemini-pro" in result.permissions.allowed_models

    def test_parse_model_with_wildcard(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test parsing model with wildcard pattern."""
        result = parser.parse("allow model gpt-4*")

        assert "gpt-4*" in result.permissions.allowed_models

    # -------------------------------------------------------------------------
    # Provider Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_only_provider(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'only openai'."""
        result = parser.parse("only openai")

        assert "openai" in result.permissions.allowed_providers

    def test_parse_use_provider(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'use anthropic'."""
        result = parser.parse("use anthropic")

        assert "anthropic" in result.permissions.allowed_providers

    def test_parse_deny_provider(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no openai'."""
        result = parser.parse("no openai")

        assert "openai" in result.permissions.denied_providers

    def test_parse_exclude_provider(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'exclude google'."""
        result = parser.parse("exclude google")

        assert "google" in result.permissions.denied_providers

    # -------------------------------------------------------------------------
    # Use Case Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_for_use_case(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'for X use case'."""
        result = parser.parse("for customer support use case")

        assert "customer-support" in result.permissions.allowed_use_cases

    def test_parse_only_for_purpose(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'only for X purposes'."""
        result = parser.parse("only for content generation purposes")

        assert "content-generation" in result.permissions.allowed_use_cases

    def test_parse_use_cases_list(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'use cases: X, Y'."""
        result = parser.parse("use cases: analysis, summarization")

        assert "analysis" in result.permissions.allowed_use_cases
        assert "summarization" in result.permissions.allowed_use_cases

    def test_parse_denied_use_case(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'not for X'."""
        result = parser.parse("not for training purposes")

        assert "training" in result.permissions.denied_use_cases

    # -------------------------------------------------------------------------
    # Budget Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_dollar_per_month(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing '$100 per month'."""
        result = parser.parse("$100 per month")

        assert result.permissions.budget_limit == 100.0
        assert result.permissions.budget_period == BudgetPeriod.MONTHLY

    def test_parse_dollar_per_day(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing '$50 per day'."""
        result = parser.parse("$50 per day")

        assert result.permissions.budget_limit == 50.0
        assert result.permissions.budget_period == BudgetPeriod.DAILY

    def test_parse_budget_of(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'budget of $X'."""
        result = parser.parse("budget of $75")

        assert result.permissions.budget_limit == 75.0

    def test_parse_up_to_amount(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'up to $X'."""
        result = parser.parse("up to $200 per week")

        assert result.permissions.budget_limit == 200.0
        assert result.permissions.budget_period == BudgetPeriod.WEEKLY

    def test_parse_max_budget(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'max $X' / 'maximum $X'."""
        result = parser.parse("maximum $500 per year")

        assert result.permissions.budget_limit == 500.0
        assert result.permissions.budget_period == BudgetPeriod.YEARLY

    def test_parse_dollars_hourly(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'X dollars hourly'."""
        result = parser.parse("10 dollars hourly")

        assert result.permissions.budget_limit == 10.0
        assert result.permissions.budget_period == BudgetPeriod.HOURLY

    def test_parse_budget_with_decimals(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test parsing budget with decimal amount."""
        result = parser.parse("$99.99 per month")

        assert result.permissions.budget_limit == 99.99

    # -------------------------------------------------------------------------
    # Rate Limit Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_requests_per_minute(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test parsing 'X requests per minute'."""
        result = parser.parse("10 requests per minute")

        assert result.permissions.rate_limit is not None
        assert result.permissions.rate_limit.max_requests == 10
        assert result.permissions.rate_limit.period_seconds == 60

    def test_parse_req_per_hour(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'X req/hour'."""
        result = parser.parse("100 requests per hour")

        assert result.permissions.rate_limit is not None
        assert result.permissions.rate_limit.max_requests == 100
        assert result.permissions.rate_limit.period_seconds == 3600

    def test_parse_no_more_than(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no more than X requests per minute'."""
        result = parser.parse("no more than 5 requests per second")

        assert result.permissions.rate_limit is not None
        assert result.permissions.rate_limit.max_requests == 5
        assert result.permissions.rate_limit.period_seconds == 1

    def test_parse_rate_limit_of(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'rate limit of X per minute'."""
        result = parser.parse("rate limit of 30 per minute")

        assert result.permissions.rate_limit is not None
        assert result.permissions.rate_limit.max_requests == 30

    def test_parse_limit_to_requests(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test parsing 'limit to X requests per day'."""
        result = parser.parse("limit to 1000 requests per day")

        assert result.permissions.rate_limit is not None
        assert result.permissions.rate_limit.max_requests == 1000
        assert result.permissions.rate_limit.period_seconds == 86400

    # -------------------------------------------------------------------------
    # Time Restriction Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_business_hours(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'business hours'."""
        result = parser.parse("only during business hours")

        assert result.permissions.valid_hours is not None
        assert result.permissions.valid_hours.start == time(9, 0)
        assert result.permissions.valid_hours.end == time(17, 0)
        assert result.permissions.valid_hours.days_of_week == (0, 1, 2, 3, 4)

    def test_parse_time_range_am_pm(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'Xam to Ypm'."""
        result = parser.parse("from 8am to 6pm")

        assert result.permissions.valid_hours is not None
        assert result.permissions.valid_hours.start == time(8, 0)
        assert result.permissions.valid_hours.end == time(18, 0)

    def test_parse_time_range_24h(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'X:00 to Y:00' (24-hour format)."""
        result = parser.parse("9:00 to 17:00")

        assert result.permissions.valid_hours is not None
        assert result.permissions.valid_hours.start == time(9, 0)
        assert result.permissions.valid_hours.end == time(17, 0)

    def test_parse_weekdays_only(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'weekdays only'."""
        result = parser.parse("weekdays only")

        assert result.permissions.valid_hours is not None
        assert result.permissions.valid_hours.days_of_week == (0, 1, 2, 3, 4)

    def test_parse_no_weekends(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no weekends'."""
        result = parser.parse("no weekends")

        assert result.permissions.valid_hours is not None
        assert result.permissions.valid_hours.days_of_week == (0, 1, 2, 3, 4)

    # -------------------------------------------------------------------------
    # Data Classification Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_no_pii(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no pii'."""
        result = parser.parse("no pii")

        assert "pii" in result.permissions.denied_data_classifications

    def test_parse_no_customer_data(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no customer data'."""
        result = parser.parse("no customer data")

        assert "customer" in result.permissions.denied_data_classifications

    def test_parse_no_sensitive(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no sensitive data'."""
        result = parser.parse("no sensitive data")

        assert "sensitive" in result.permissions.denied_data_classifications

    def test_parse_only_internal(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'only internal data'."""
        result = parser.parse("only internal data")

        assert "internal" in result.permissions.allowed_data_classifications

    def test_parse_data_classifications_list(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test parsing 'only internal data'."""
        result = parser.parse("only internal data, only public data")

        assert "internal" in result.permissions.allowed_data_classifications
        assert "public" in result.permissions.allowed_data_classifications

    # -------------------------------------------------------------------------
    # Read-Only Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_read_only(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'read only'."""
        result = parser.parse("read only access")

        assert "generation" in result.permissions.denied_use_cases
        assert "completion" in result.permissions.denied_use_cases
        assert "embedding" in result.permissions.allowed_use_cases

    def test_parse_cannot_modify(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'cannot modify'."""
        result = parser.parse("cannot modify anything")

        assert "generation" in result.permissions.denied_use_cases

    def test_parse_no_modifications(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'no modifications'."""
        result = parser.parse("no modifications allowed")

        assert "generation" in result.permissions.denied_use_cases

    def test_parse_only_analysis(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'only analysis'."""
        result = parser.parse("only analysis")

        # Should detect read-only pattern
        assert "analysis" in result.permissions.allowed_use_cases

    # -------------------------------------------------------------------------
    # Max Tokens Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_max_tokens(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'max X tokens'."""
        result = parser.parse("max 4000 tokens")

        assert result.permissions.max_tokens_per_request == 4000

    def test_parse_maximum_tokens(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'maximum X tokens'."""
        result = parser.parse("maximum 8000 tokens per request")

        assert result.permissions.max_tokens_per_request == 8000

    def test_parse_tokens_max(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'X tokens max'."""
        result = parser.parse("2000 tokens maximum")

        assert result.permissions.max_tokens_per_request == 2000

    def test_parse_limit_tokens(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing 'limit tokens to X'."""
        result = parser.parse("limit tokens to 1000")

        assert result.permissions.max_tokens_per_request == 1000

    # -------------------------------------------------------------------------
    # Complex Parsing Tests
    # -------------------------------------------------------------------------

    def test_parse_complex_description(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test parsing a complex multi-constraint description."""
        result = parser.parse(
            "Allow model GPT-4 for customer support use case, "
            "with a budget of $100 per month, "
            "no more than 10 requests per minute, "
            "only during business hours, "
            "no pii"
        )

        assert "GPT-4" in result.permissions.allowed_models
        assert "customer support" in result.permissions.allowed_use_cases or "customer-support" in result.permissions.allowed_use_cases
        assert result.permissions.budget_limit == 100.0
        assert result.permissions.budget_period == BudgetPeriod.MONTHLY
        assert result.permissions.rate_limit is not None
        assert result.permissions.rate_limit.max_requests == 10
        assert result.permissions.valid_hours is not None
        assert "pii" in result.permissions.denied_data_classifications

    def test_parse_multiple_models(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing multiple allowed models."""
        result = parser.parse(
            "allow model gpt-4 and allow model claude-3-opus"
        )

        assert "gpt-4" in result.permissions.allowed_models
        assert "claude-3-opus" in result.permissions.allowed_models

    def test_parse_mixed_allow_deny(self, parser: NaturalLanguageTokenParser) -> None:
        """Test parsing mixed allow and deny patterns."""
        result = parser.parse(
            "allow model gpt-4, block model gpt-4-32k, only openai, no google"
        )

        assert "gpt-4" in result.permissions.allowed_models
        assert "gpt-4-32k" in result.permissions.denied_models
        assert "openai" in result.permissions.allowed_providers
        assert "google" in result.permissions.denied_providers

    # -------------------------------------------------------------------------
    # Conflict Detection Tests
    # -------------------------------------------------------------------------

    def test_detect_model_conflict(self, parser: NaturalLanguageTokenParser) -> None:
        """Test detection of conflicting model specifications."""
        result = parser.parse("allow model gpt-4, deny model gpt-4")

        assert len(result.warnings) > 0
        assert any("Conflict" in w for w in result.warnings)
        assert result.overall_confidence == ConfidenceLevel.MEDIUM

    def test_detect_provider_conflict(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test detection of conflicting provider specifications."""
        result = parser.parse("only openai, no openai")

        assert len(result.warnings) > 0
        assert any("Conflict" in w for w in result.warnings)

    def test_detect_multiple_budgets(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test detection of multiple budget specifications."""
        result = parser.parse("$100 per month and $50 per day")

        assert len(result.warnings) > 0
        assert any("budget" in w.lower() for w in result.warnings)

    def test_detect_multiple_rate_limits(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test detection of multiple rate limit specifications."""
        result = parser.parse("10 requests per minute and 100 requests per hour")

        assert len(result.warnings) > 0
        assert any("rate limit" in w.lower() for w in result.warnings)

    # -------------------------------------------------------------------------
    # Confidence Level Tests
    # -------------------------------------------------------------------------

    def test_high_confidence_clear_specs(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test high confidence for clear specifications."""
        result = parser.parse("allow model gpt-4, $100 per month")

        assert result.overall_confidence == ConfidenceLevel.HIGH

    def test_medium_confidence_with_warnings(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test medium confidence when warnings exist."""
        result = parser.parse("allow model gpt-4, deny model gpt-4")

        assert result.overall_confidence == ConfidenceLevel.MEDIUM

    def test_low_confidence_empty(self, parser: NaturalLanguageTokenParser) -> None:
        """Test low confidence for empty input."""
        result = parser.parse("")

        assert result.overall_confidence == ConfidenceLevel.LOW

    def test_suggestions_for_low_confidence(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test suggestions are generated for low confidence."""
        result = parser.parse("something unclear")

        assert len(result.suggestions) > 0

    # -------------------------------------------------------------------------
    # Serialization Tests
    # -------------------------------------------------------------------------

    def test_parsed_constraint_to_dict(
        self, parser: NaturalLanguageTokenParser
    ) -> None:
        """Test ParsedConstraint serialization."""
        constraint = ParsedConstraint(
            constraint_type="allowed_models",
            value="gpt-4",
            original_text="allow model gpt-4",
            confidence=ConfidenceLevel.HIGH,
            notes="Test note",
        )

        data = constraint.to_dict()

        assert data["constraint_type"] == "allowed_models"
        assert data["value"] == "gpt-4"
        assert data["confidence"] == "high"
        assert data["notes"] == "Test note"

    def test_parse_result_to_dict(self, parser: NaturalLanguageTokenParser) -> None:
        """Test ParseResult serialization."""
        result = parser.parse("allow model gpt-4")
        data = result.to_dict()

        assert "permissions" in data
        assert "constraints" in data
        assert "overall_confidence" in data
        assert "warnings" in data
        assert "suggestions" in data


# =============================================================================
# PermissionTemplate Tests
# =============================================================================


class TestPermissionTemplate:
    """Tests for the PermissionTemplate class."""

    def test_create_template(self) -> None:
        """Test creating a permission template."""
        template = PermissionTemplate(
            name="TEST_TEMPLATE",
            display_name="Test Template",
            description="A test template",
            category=TemplateCategory.DEVELOPMENT,
            permissions=TokenPermissions(
                allowed_models=["gpt-4"],
                budget_limit=100.0,
            ),
            tags=["test"],
        )

        assert template.name == "TEST_TEMPLATE"
        assert template.category == TemplateCategory.DEVELOPMENT
        assert "gpt-4" in template.permissions.allowed_models

    def test_template_to_dict(self) -> None:
        """Test template serialization."""
        template = PermissionTemplate(
            name="TEST",
            display_name="Test",
            description="Test description",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(),
        )

        data = template.to_dict()

        assert data["name"] == "TEST"
        assert data["category"] == "custom"
        assert "permissions" in data

    def test_create_permissions_with_overrides(self) -> None:
        """Test creating permissions with overrides."""
        template = PermissionTemplate(
            name="TEST",
            display_name="Test",
            description="Test",
            category=TemplateCategory.DEVELOPMENT,
            permissions=TokenPermissions(
                budget_limit=100.0,
                allowed_models=["gpt-4"],
            ),
        )

        permissions = template.create_permissions(budget_limit=200.0)

        assert permissions.budget_limit == 200.0
        assert "gpt-4" in permissions.allowed_models


# =============================================================================
# TemplateRegistry Tests
# =============================================================================


class TestTemplateRegistry:
    """Tests for the TemplateRegistry class."""

    @pytest.fixture
    def empty_registry(self) -> TemplateRegistry:
        """Create an empty registry."""
        return TemplateRegistry(include_builtins=False)

    @pytest.fixture
    def registry(self) -> TemplateRegistry:
        """Create a registry with built-in templates."""
        return TemplateRegistry()

    def test_create_empty_registry(self, empty_registry: TemplateRegistry) -> None:
        """Test creating an empty registry."""
        assert len(empty_registry) == 0

    def test_create_registry_with_builtins(
        self, registry: TemplateRegistry
    ) -> None:
        """Test creating a registry with built-in templates."""
        assert len(registry) > 0
        assert DEVELOPER_TESTING in registry

    def test_register_template(self, empty_registry: TemplateRegistry) -> None:
        """Test registering a template."""
        template = PermissionTemplate(
            name="CUSTOM",
            display_name="Custom",
            description="Custom template",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(),
        )

        empty_registry.register(template)

        assert "CUSTOM" in empty_registry
        assert empty_registry.get("CUSTOM") is not None

    def test_register_duplicate_raises(self, empty_registry: TemplateRegistry) -> None:
        """Test that registering duplicate raises error."""
        template = PermissionTemplate(
            name="CUSTOM",
            display_name="Custom",
            description="Custom template",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(),
        )

        empty_registry.register(template)

        with pytest.raises(ValueError, match="already exists"):
            empty_registry.register(template)

    def test_register_with_overwrite(self, empty_registry: TemplateRegistry) -> None:
        """Test registering with overwrite flag."""
        template1 = PermissionTemplate(
            name="CUSTOM",
            display_name="Custom 1",
            description="First version",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(budget_limit=100.0),
        )
        template2 = PermissionTemplate(
            name="CUSTOM",
            display_name="Custom 2",
            description="Second version",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(budget_limit=200.0),
        )

        empty_registry.register(template1)
        empty_registry.register(template2, overwrite=True)

        assert empty_registry.get("CUSTOM").display_name == "Custom 2"

    def test_unregister_template(self, empty_registry: TemplateRegistry) -> None:
        """Test unregistering a template."""
        template = PermissionTemplate(
            name="CUSTOM",
            display_name="Custom",
            description="Custom template",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(),
        )

        empty_registry.register(template)
        assert empty_registry.unregister("CUSTOM") is True
        assert "CUSTOM" not in empty_registry

    def test_unregister_nonexistent(self, empty_registry: TemplateRegistry) -> None:
        """Test unregistering a nonexistent template."""
        assert empty_registry.unregister("NONEXISTENT") is False

    def test_get_template(self, registry: TemplateRegistry) -> None:
        """Test getting a template by name."""
        template = registry.get(DEVELOPER_TESTING)

        assert template is not None
        assert template.name == DEVELOPER_TESTING

    def test_get_nonexistent_returns_none(
        self, registry: TemplateRegistry
    ) -> None:
        """Test getting nonexistent template returns None."""
        assert registry.get("NONEXISTENT") is None

    def test_get_or_raise(self, registry: TemplateRegistry) -> None:
        """Test get_or_raise returns template."""
        template = registry.get_or_raise(DEVELOPER_TESTING)
        assert template.name == DEVELOPER_TESTING

    def test_get_or_raise_nonexistent(self, registry: TemplateRegistry) -> None:
        """Test get_or_raise raises for nonexistent."""
        with pytest.raises(KeyError, match="not found"):
            registry.get_or_raise("NONEXISTENT")

    def test_list_all(self, registry: TemplateRegistry) -> None:
        """Test listing all templates."""
        templates = registry.list_all()

        assert len(templates) > 0
        assert all(isinstance(t, PermissionTemplate) for t in templates)

    def test_list_names(self, registry: TemplateRegistry) -> None:
        """Test listing all template names."""
        names = registry.list_names()

        assert DEVELOPER_TESTING in names
        assert PRODUCTION_RESTRICTED in names

    def test_list_by_category(self, registry: TemplateRegistry) -> None:
        """Test listing templates by category."""
        dev_templates = registry.list_by_category(TemplateCategory.DEVELOPMENT)

        assert len(dev_templates) > 0
        assert all(t.category == TemplateCategory.DEVELOPMENT for t in dev_templates)

    def test_list_by_tag(self, registry: TemplateRegistry) -> None:
        """Test listing templates by tag."""
        # Developer testing template has "development" tag
        templates = registry.list_by_tag("development")

        assert len(templates) > 0
        assert all("development" in t.tags for t in templates)

    def test_search_by_name(self, registry: TemplateRegistry) -> None:
        """Test searching templates by name."""
        results = registry.search("developer")

        assert len(results) > 0
        assert any("DEVELOPER" in t.name for t in results)

    def test_search_by_description(self, registry: TemplateRegistry) -> None:
        """Test searching templates by description."""
        results = registry.search("testing")

        assert len(results) > 0

    def test_search_by_tag(self, registry: TemplateRegistry) -> None:
        """Test searching templates by tag."""
        results = registry.search("batch")

        assert len(results) > 0

    def test_create_permissions_from_template(
        self, registry: TemplateRegistry
    ) -> None:
        """Test creating permissions from a template."""
        permissions = registry.create_permissions_from_template(
            DEVELOPER_TESTING,
            budget_limit=50.0,
        )

        assert permissions.budget_limit == 50.0
        assert permissions.rate_limit is not None

    def test_contains(self, registry: TemplateRegistry) -> None:
        """Test the __contains__ method."""
        assert DEVELOPER_TESTING in registry
        assert "NONEXISTENT" not in registry

    def test_len(self, registry: TemplateRegistry) -> None:
        """Test the __len__ method."""
        assert len(registry) >= 8  # At least 8 built-in templates

    def test_iter(self, registry: TemplateRegistry) -> None:
        """Test the __iter__ method."""
        templates = list(registry)
        assert len(templates) >= 8

    def test_on_register_callback(self, empty_registry: TemplateRegistry) -> None:
        """Test registration callback."""
        registered = []

        def callback(name: str, template: PermissionTemplate) -> None:
            registered.append(name)

        empty_registry.on_register(callback)

        template = PermissionTemplate(
            name="CALLBACK_TEST",
            display_name="Callback Test",
            description="Test callback",
            category=TemplateCategory.CUSTOM,
            permissions=TokenPermissions(),
        )

        empty_registry.register(template)

        assert "CALLBACK_TEST" in registered


# =============================================================================
# Built-in Template Tests
# =============================================================================


class TestBuiltinTemplates:
    """Tests for built-in permission templates."""

    @pytest.fixture
    def registry(self) -> TemplateRegistry:
        """Create a registry with built-in templates."""
        return TemplateRegistry()

    def test_developer_testing_template(self, registry: TemplateRegistry) -> None:
        """Test DEVELOPER_TESTING template."""
        template = registry.get_or_raise(DEVELOPER_TESTING)

        assert template.category == TemplateCategory.DEVELOPMENT
        assert template.permissions.budget_limit is not None
        assert template.permissions.rate_limit is not None
        assert "development" in template.tags

    def test_production_restricted_template(
        self, registry: TemplateRegistry
    ) -> None:
        """Test PRODUCTION_RESTRICTED template."""
        template = registry.get_or_raise(PRODUCTION_RESTRICTED)

        assert template.category == TemplateCategory.PRODUCTION
        assert len(template.permissions.allowed_models) > 0
        assert len(template.permissions.denied_data_classifications) > 0
        assert "production" in template.tags

    def test_read_only_analytics_template(
        self, registry: TemplateRegistry
    ) -> None:
        """Test READ_ONLY_ANALYTICS template."""
        template = registry.get_or_raise(READ_ONLY_ANALYTICS)

        assert template.category == TemplateCategory.ANALYTICS
        assert "embedding" in template.permissions.allowed_use_cases
        assert "generation" in template.permissions.denied_use_cases

    def test_internal_only_template(self, registry: TemplateRegistry) -> None:
        """Test INTERNAL_ONLY template."""
        template = registry.get_or_raise(INTERNAL_ONLY)

        assert template.category == TemplateCategory.INTERNAL
        assert "internal" in template.permissions.allowed_data_classifications
        assert "pii" in template.permissions.denied_data_classifications

    def test_business_hours_template(self, registry: TemplateRegistry) -> None:
        """Test BUSINESS_HOURS template."""
        template = registry.get_or_raise(BUSINESS_HOURS)

        assert template.permissions.valid_hours is not None
        assert template.permissions.valid_hours.start == time(9, 0)
        assert template.permissions.valid_hours.end == time(17, 0)

    def test_batch_processing_template(self, registry: TemplateRegistry) -> None:
        """Test BATCH_PROCESSING template."""
        template = registry.get_or_raise(BATCH_PROCESSING)

        assert template.permissions.rate_limit is not None
        assert template.permissions.rate_limit.max_requests >= 500
        assert len(template.permissions.allowed_models) > 0

    def test_emergency_access_template(self, registry: TemplateRegistry) -> None:
        """Test EMERGENCY_ACCESS template."""
        template = registry.get_or_raise(EMERGENCY_ACCESS)

        assert template.permissions.require_approval_above is not None
        assert template.permissions.budget_limit is not None
        assert template.permissions.budget_period == BudgetPeriod.DAILY

    def test_minimal_template(self, registry: TemplateRegistry) -> None:
        """Test MINIMAL template."""
        template = registry.get_or_raise(MINIMAL)

        assert len(template.permissions.allowed_models) == 1
        assert template.permissions.budget_limit is not None
        assert template.permissions.budget_limit < 10


# =============================================================================
# Module-Level Function Tests
# =============================================================================


class TestModuleFunctions:
    """Tests for module-level convenience functions."""

    def test_get_default_registry(self) -> None:
        """Test getting the default registry."""
        registry = get_default_registry()

        assert isinstance(registry, TemplateRegistry)
        assert len(registry) > 0

    def test_get_default_registry_singleton(self) -> None:
        """Test that get_default_registry returns the same instance."""
        registry1 = get_default_registry()
        registry2 = get_default_registry()

        assert registry1 is registry2

    def test_get_template_function(self) -> None:
        """Test the get_template convenience function."""
        template = get_template(DEVELOPER_TESTING)

        assert template is not None
        assert template.name == DEVELOPER_TESTING

    def test_get_template_nonexistent(self) -> None:
        """Test get_template for nonexistent template."""
        template = get_template("NONEXISTENT")

        assert template is None

    def test_list_templates_function(self) -> None:
        """Test the list_templates convenience function."""
        names = list_templates()

        assert DEVELOPER_TESTING in names
        assert PRODUCTION_RESTRICTED in names

    def test_create_from_template_function(self) -> None:
        """Test the create_from_template convenience function."""
        permissions = create_from_template(DEVELOPER_TESTING, budget_limit=75.0)

        assert permissions.budget_limit == 75.0
        assert permissions.rate_limit is not None
