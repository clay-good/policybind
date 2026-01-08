"""
Natural language token permission parsing for PolicyBind.

This module provides functionality to parse natural language descriptions
into structured TokenPermissions objects, enabling intuitive token creation.
"""

import re
from dataclasses import dataclass, field
from datetime import time
from enum import Enum
from typing import Any

from policybind.tokens.models import (
    BudgetPeriod,
    RateLimit,
    TimeWindow,
    TokenPermissions,
)


class ConfidenceLevel(Enum):
    """Confidence level for parsed permissions."""

    HIGH = "high"
    """Strong confidence in the parsed interpretation."""

    MEDIUM = "medium"
    """Moderate confidence, may need verification."""

    LOW = "low"
    """Low confidence, clarification recommended."""


@dataclass
class ParsedConstraint:
    """
    A single constraint extracted from natural language.

    Attributes:
        constraint_type: Type of constraint (model, budget, rate_limit, etc.).
        value: The parsed value.
        original_text: The original text that was parsed.
        confidence: Confidence level in the parsing.
        notes: Additional notes or warnings.
    """

    constraint_type: str
    value: Any
    original_text: str
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "constraint_type": self.constraint_type,
            "value": self.value,
            "original_text": self.original_text,
            "confidence": self.confidence.value,
            "notes": self.notes,
        }


@dataclass
class ParseResult:
    """
    Result of parsing natural language into token permissions.

    Attributes:
        permissions: The parsed TokenPermissions object.
        constraints: List of individual parsed constraints.
        overall_confidence: Overall confidence in the parsing.
        warnings: List of warnings about the parsing.
        suggestions: Suggestions for clarification.
        unrecognized_parts: Parts of input that weren't recognized.
    """

    permissions: TokenPermissions
    constraints: list[ParsedConstraint] = field(default_factory=list)
    overall_confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    unrecognized_parts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "permissions": self.permissions.to_dict(),
            "constraints": [c.to_dict() for c in self.constraints],
            "overall_confidence": self.overall_confidence.value,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
            "unrecognized_parts": self.unrecognized_parts,
        }


class NaturalLanguageTokenParser:
    """
    Parses natural language descriptions into TokenPermissions.

    Uses pattern matching and keyword extraction to interpret
    natural language permission descriptions. Does not require
    external LLM calls.

    Example:
        Parsing a permission description::

            parser = NaturalLanguageTokenParser()

            result = parser.parse(
                "Allow only GPT-4 for customer support, "
                "with a budget of $100 per month, "
                "no more than 10 requests per minute, "
                "only during business hours"
            )

            if result.overall_confidence == ConfidenceLevel.HIGH:
                permissions = result.permissions
            else:
                print(f"Warnings: {result.warnings}")
                print(f"Suggestions: {result.suggestions}")
    """

    # Model patterns
    MODEL_PATTERNS = [
        # "allow model X" / "only model X" / "use model X" (must have "model" keyword)
        (r"\b(?:allow|only|use|permit)\s+model\s+([a-zA-Z0-9\-\._*]+)", "allowed_models"),
        # "allow X model" / "X model only"
        (r"\b([a-zA-Z0-9\-\._*]+)\s+model(?:\s+only)?(?:\s|$|,)", "allowed_models"),
        # "deny model X" / "block model X" (must have "model" keyword)
        (r"\b(?:deny|block|exclude)\s+model\s+([a-zA-Z0-9\-\._*]+)", "denied_models"),
        # "models: X, Y, Z" - parse comma-separated model list
        (r"\bmodels?\s*:\s*([a-zA-Z0-9\-\._*]+(?:\s*,\s*[a-zA-Z0-9\-\._*]+)*)", "allowed_models_list"),
    ]

    # Provider patterns
    PROVIDER_PATTERNS = [
        # "only openai" / "openai only" / "use openai" (provider must be explicit)
        (r"\b(?:only|use|allow)\s+(openai|anthropic|google|azure|cohere)(?:\s|$|,)", "allowed_providers"),
        (r"\b(openai|anthropic|google|azure|cohere)\s+only\b", "allowed_providers"),
        # "no openai" / "exclude anthropic"
        (r"\b(?:no|deny|block|exclude)\s+(openai|anthropic|google|azure|cohere)(?:\s|$|,)", "denied_providers"),
    ]

    # Use case patterns
    USE_CASE_PATTERNS = [
        # "for X use case" - requires "use case" at end
        (r"\bfor\s+([a-zA-Z0-9\-\_]+(?:\s+[a-zA-Z0-9\-\_]+)?)\s+use\s*case", "allowed_use_cases"),
        # "for X purposes" - requires "purposes" at end
        (r"\bfor\s+([a-zA-Z0-9\-\_]+(?:\s+[a-zA-Z0-9\-\_]+)?)\s+purposes?", "allowed_use_cases"),
        # "use case: X" / "use cases: X, Y"
        (r"\buse\s+cases?\s*:\s*([a-zA-Z0-9\-\_,\s]+?)(?:\s*,\s*(?:and|with)|$)", "allowed_use_cases_list"),
        # "not for X purposes" / "no X use case"
        (r"\b(?:not\s+for|no)\s+([a-zA-Z0-9\-\_]+)\s+(?:use\s*case|purposes?)", "denied_use_cases"),
    ]

    # Budget patterns
    BUDGET_PATTERNS = [
        # "$100 per month" / "$100/month" / "100 dollars monthly"
        (r"\$\s*(\d+(?:\.\d{2})?)\s*(?:per|/|a)?\s*(hour|day|week|month|year)", "budget"),
        (r"(\d+(?:\.\d{2})?)\s*(?:dollars?|usd)\s*(?:per|/|a)?\s*(hour|hourly|day|daily|week|weekly|month|monthly|year|yearly)", "budget"),
        # "budget of $100" / "budget: $100"
        (r"\bbudget\s*(?:of|:)?\s*\$?\s*(\d+(?:\.\d{2})?)\s*(?:per|/|a)?\s*(hour|day|week|month|year)?", "budget"),
        # "up to $100"
        (r"\bup\s+to\s+\$?\s*(\d+(?:\.\d{2})?)\s*(?:per|/|a)?\s*(hour|day|week|month|year)?", "budget"),
        # "max $100" / "maximum $100"
        (r"\b(?:max|maximum)\s*(?:of)?\s*\$?\s*(\d+(?:\.\d{2})?)\s*(?:per|/|a)?\s*(hour|day|week|month|year)?", "budget"),
    ]

    # Rate limit patterns
    RATE_LIMIT_PATTERNS = [
        # "10 requests per minute" / "10 req/min"
        (r"(\d+)\s*(?:requests?|req)\s*(?:per|/|a)\s*(second|minute|min|hour|hr|day)", "rate_limit"),
        # "no more than 10 requests per minute"
        (r"\bno\s+more\s+than\s+(\d+)\s*(?:requests?|req)\s*(?:per|/|a)\s*(second|minute|min|hour|hr|day)", "rate_limit"),
        # "rate limit: 10/min" / "rate limit of 10 per minute"
        (r"\brate\s*limit\s*(?:of|:)?\s*(\d+)\s*(?:/|per|a)?\s*(second|minute|min|hour|hr|day)?", "rate_limit"),
        # "limit to 10 requests"
        (r"\blimit\s+(?:to\s+)?(\d+)\s*(?:requests?|req)\s*(?:per|/|a)?\s*(second|minute|min|hour|hr|day)?", "rate_limit"),
    ]

    # Time restriction patterns
    TIME_PATTERNS = [
        # "business hours" / "during business hours" / "only business hours"
        (r"\b(?:during\s+|only\s+)?business\s+hours\b", "business_hours"),
        # "9am to 5pm" / "9:00 to 17:00" / "from 9am to 5pm"
        (r"\b(?:from\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:to|-)\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b", "time_range"),
        # "weekdays only" / "only on weekdays"
        (r"\b(?:only\s+(?:on\s+)?)?weekdays(?:\s+only)?\b", "weekdays"),
        # "no weekends" / "exclude weekends"
        (r"\b(?:no|exclude)\s+weekends?\b", "weekdays"),
    ]

    # Data classification patterns
    DATA_PATTERNS = [
        # "no customer data" / "no pii data" / "no sensitive data" - must have "data" word
        (r"\bno\s+(customer|pii|sensitive|confidential|internal|public|phi|pci)\s+data\b", "denied_data"),
        # "no pii allowed" / "no pii" at end of sentence
        (r"\bno\s+(pii|phi|pci)(?:\s+allowed)?(?:\s|$|,)", "denied_data"),
        # "only internal data" / "internal data only" - must have "data" word
        (r"\bonly\s+(customer|pii|sensitive|confidential|internal|public)\s+data\b", "allowed_data"),
        (r"\b(internal|public)\s+data\s+only\b", "allowed_data"),
        # "data: internal, public" / "data classifications: ..."
        (r"\bdata\s+classifications?\s*:\s*([a-zA-Z0-9\-\_,\s]+?)(?:\s|$)", "allowed_data_list"),
    ]

    # Read-only patterns
    READ_ONLY_PATTERNS = [
        (r"\bread[\s\-]?only\b", "read_only"),
        (r"\bcannot\s+(?:modify|write|change|edit)\b", "read_only"),
        (r"\bno\s+(?:modifications?|writes?|changes?|edits?)\b", "read_only"),
        (r"\b(?:only\s+)?(?:analysis|analytics|summarization|classification)\b", "read_only"),
    ]

    # Max tokens patterns
    MAX_TOKENS_PATTERNS = [
        # "max 4000 tokens" / "maximum 4000 tokens per request"
        (r"\b(?:max|maximum)\s*(?:of)?\s*(\d+)\s*tokens?\s*(?:per\s+request)?\b", "max_tokens"),
        # "4000 tokens max"
        (r"\b(\d+)\s*tokens?\s*(?:max|maximum)\b", "max_tokens"),
        # "limit tokens to 4000"
        (r"\blimit\s+tokens?\s+(?:to\s+)?(\d+)\b", "max_tokens"),
    ]

    def __init__(self) -> None:
        """Initialize the parser."""
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for efficiency."""
        self._model_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.MODEL_PATTERNS
        ]
        self._provider_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.PROVIDER_PATTERNS
        ]
        self._use_case_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.USE_CASE_PATTERNS
        ]
        self._budget_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.BUDGET_PATTERNS
        ]
        self._rate_limit_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.RATE_LIMIT_PATTERNS
        ]
        self._time_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.TIME_PATTERNS
        ]
        self._data_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.DATA_PATTERNS
        ]
        self._read_only_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.READ_ONLY_PATTERNS
        ]
        self._max_tokens_patterns = [
            (re.compile(p, re.IGNORECASE), t) for p, t in self.MAX_TOKENS_PATTERNS
        ]

    def parse(self, description: str) -> ParseResult:
        """
        Parse a natural language description into TokenPermissions.

        Args:
            description: Natural language description of desired permissions.

        Returns:
            ParseResult containing the parsed permissions and metadata.
        """
        if not description or not description.strip():
            return ParseResult(
                permissions=TokenPermissions(),
                overall_confidence=ConfidenceLevel.LOW,
                warnings=["Empty description provided"],
                suggestions=["Provide a description of the desired permissions"],
            )

        # Normalize the description
        text = self._normalize_text(description)

        # Collect all parsed constraints
        constraints: list[ParsedConstraint] = []
        warnings: list[str] = []
        suggestions: list[str] = []

        # Parse each category
        constraints.extend(self._parse_models(text))
        constraints.extend(self._parse_providers(text))
        constraints.extend(self._parse_use_cases(text))
        constraints.extend(self._parse_budget(text))
        constraints.extend(self._parse_rate_limit(text))
        constraints.extend(self._parse_time_restrictions(text))
        constraints.extend(self._parse_data_classifications(text))
        constraints.extend(self._parse_read_only(text))
        constraints.extend(self._parse_max_tokens(text))

        # Build permissions from constraints
        permissions = self._build_permissions(constraints)

        # Check for conflicts
        conflict_warnings = self._check_conflicts(constraints)
        warnings.extend(conflict_warnings)

        # Determine overall confidence
        overall_confidence = self._calculate_confidence(constraints, warnings)

        # Generate suggestions if confidence is low
        if overall_confidence != ConfidenceLevel.HIGH:
            suggestions.extend(self._generate_suggestions(constraints, text))

        # Find unrecognized parts
        unrecognized = self._find_unrecognized(text, constraints)

        return ParseResult(
            permissions=permissions,
            constraints=constraints,
            overall_confidence=overall_confidence,
            warnings=warnings,
            suggestions=suggestions,
            unrecognized_parts=unrecognized,
        )

    def _normalize_text(self, text: str) -> str:
        """Normalize text for parsing."""
        # Convert to lowercase for matching but preserve original for reporting
        text = text.strip()
        # Normalize whitespace
        text = re.sub(r"\s+", " ", text)
        # Replace semicolons with commas (but keep colons for list patterns)
        text = re.sub(r";(?=\s)", ",", text)
        return text

    def _parse_models(self, text: str) -> list[ParsedConstraint]:
        """Parse model-related constraints."""
        constraints = []

        for pattern, constraint_type in self._model_patterns:
            for match in pattern.finditer(text):
                value = match.group(1).strip()

                if constraint_type == "allowed_models_list":
                    # Split comma-separated list
                    models = [m.strip() for m in value.split(",") if m.strip()]
                    for model in models:
                        constraints.append(ParsedConstraint(
                            constraint_type="allowed_models",
                            value=model,
                            original_text=match.group(0),
                            confidence=ConfidenceLevel.HIGH,
                        ))
                else:
                    constraints.append(ParsedConstraint(
                        constraint_type=constraint_type,
                        value=value,
                        original_text=match.group(0),
                        confidence=ConfidenceLevel.HIGH,
                    ))

        return constraints

    def _parse_providers(self, text: str) -> list[ParsedConstraint]:
        """Parse provider-related constraints."""
        constraints = []

        for pattern, constraint_type in self._provider_patterns:
            for match in pattern.finditer(text):
                value = match.group(1).strip().lower()
                constraints.append(ParsedConstraint(
                    constraint_type=constraint_type,
                    value=value,
                    original_text=match.group(0),
                    confidence=ConfidenceLevel.HIGH,
                ))

        return constraints

    def _parse_use_cases(self, text: str) -> list[ParsedConstraint]:
        """Parse use case constraints."""
        constraints = []

        for pattern, constraint_type in self._use_case_patterns:
            for match in pattern.finditer(text):
                value = match.group(1).strip()

                if constraint_type == "allowed_use_cases_list":
                    # Split comma-separated list
                    use_cases = [u.strip() for u in value.split(",") if u.strip()]
                    for use_case in use_cases:
                        constraints.append(ParsedConstraint(
                            constraint_type="allowed_use_cases",
                            value=use_case.lower().replace(" ", "-"),
                            original_text=match.group(0),
                            confidence=ConfidenceLevel.MEDIUM,
                        ))
                else:
                    # Normalize use case name
                    normalized = value.lower().replace(" ", "-")
                    base_type = constraint_type.replace("_list", "")
                    constraints.append(ParsedConstraint(
                        constraint_type=base_type,
                        value=normalized,
                        original_text=match.group(0),
                        confidence=ConfidenceLevel.MEDIUM,
                        notes="Use case names are normalized to lowercase with hyphens",
                    ))

        return constraints

    def _parse_budget(self, text: str) -> list[ParsedConstraint]:
        """Parse budget constraints."""
        constraints = []

        for pattern, _ in self._budget_patterns:
            for match in pattern.finditer(text):
                amount = float(match.group(1))
                period_str = match.group(2) if len(match.groups()) > 1 and match.group(2) else "month"

                period = self._normalize_budget_period(period_str)

                constraints.append(ParsedConstraint(
                    constraint_type="budget",
                    value={"amount": amount, "period": period},
                    original_text=match.group(0),
                    confidence=ConfidenceLevel.HIGH,
                ))

        return constraints

    def _normalize_budget_period(self, period_str: str | None) -> BudgetPeriod:
        """Convert period string to BudgetPeriod enum."""
        if not period_str:
            return BudgetPeriod.MONTHLY

        period_str = period_str.lower()
        period_map = {
            "hour": BudgetPeriod.HOURLY,
            "hourly": BudgetPeriod.HOURLY,
            "day": BudgetPeriod.DAILY,
            "daily": BudgetPeriod.DAILY,
            "week": BudgetPeriod.WEEKLY,
            "weekly": BudgetPeriod.WEEKLY,
            "month": BudgetPeriod.MONTHLY,
            "monthly": BudgetPeriod.MONTHLY,
            "year": BudgetPeriod.YEARLY,
            "yearly": BudgetPeriod.YEARLY,
        }
        return period_map.get(period_str, BudgetPeriod.MONTHLY)

    def _parse_rate_limit(self, text: str) -> list[ParsedConstraint]:
        """Parse rate limit constraints."""
        constraints = []

        for pattern, _ in self._rate_limit_patterns:
            for match in pattern.finditer(text):
                requests = int(match.group(1))
                period_str = match.group(2) if len(match.groups()) > 1 and match.group(2) else "minute"

                period_seconds = self._normalize_rate_period(period_str)

                constraints.append(ParsedConstraint(
                    constraint_type="rate_limit",
                    value={"max_requests": requests, "period_seconds": period_seconds},
                    original_text=match.group(0),
                    confidence=ConfidenceLevel.HIGH,
                ))

        return constraints

    def _normalize_rate_period(self, period_str: str | None) -> int:
        """Convert period string to seconds."""
        if not period_str:
            return 60  # Default to per minute

        period_str = period_str.lower()
        period_map = {
            "second": 1,
            "sec": 1,
            "minute": 60,
            "min": 60,
            "hour": 3600,
            "hr": 3600,
            "day": 86400,
        }
        return period_map.get(period_str, 60)

    def _parse_time_restrictions(self, text: str) -> list[ParsedConstraint]:
        """Parse time-based restrictions."""
        constraints = []

        for pattern, constraint_type in self._time_patterns:
            for match in pattern.finditer(text):
                if constraint_type == "business_hours":
                    constraints.append(ParsedConstraint(
                        constraint_type="time_window",
                        value=TimeWindow.business_hours(),
                        original_text=match.group(0),
                        confidence=ConfidenceLevel.HIGH,
                    ))
                elif constraint_type == "weekdays":
                    # Weekdays only (Mon-Fri)
                    constraints.append(ParsedConstraint(
                        constraint_type="weekdays_only",
                        value=(0, 1, 2, 3, 4),
                        original_text=match.group(0),
                        confidence=ConfidenceLevel.HIGH,
                    ))
                elif constraint_type == "time_range":
                    time_window = self._parse_time_range(match)
                    if time_window:
                        constraints.append(ParsedConstraint(
                            constraint_type="time_window",
                            value=time_window,
                            original_text=match.group(0),
                            confidence=ConfidenceLevel.MEDIUM,
                            notes="Parsed time range - verify hours are correct",
                        ))

        return constraints

    def _parse_time_range(self, match: re.Match) -> TimeWindow | None:
        """Parse a time range match into a TimeWindow."""
        try:
            start_hour = int(match.group(1))
            start_min = int(match.group(2)) if match.group(2) else 0
            start_ampm = match.group(3)

            end_hour = int(match.group(4))
            end_min = int(match.group(5)) if match.group(5) else 0
            end_ampm = match.group(6)

            # Convert to 24-hour format
            if start_ampm:
                if start_ampm.lower() == "pm" and start_hour < 12:
                    start_hour += 12
                elif start_ampm.lower() == "am" and start_hour == 12:
                    start_hour = 0

            if end_ampm:
                if end_ampm.lower() == "pm" and end_hour < 12:
                    end_hour += 12
                elif end_ampm.lower() == "am" and end_hour == 12:
                    end_hour = 0

            return TimeWindow(
                start=time(start_hour, start_min),
                end=time(end_hour, end_min),
            )
        except (ValueError, IndexError):
            return None

    def _parse_data_classifications(self, text: str) -> list[ParsedConstraint]:
        """Parse data classification constraints."""
        constraints = []

        for pattern, constraint_type in self._data_patterns:
            for match in pattern.finditer(text):
                value = match.group(1).strip().lower()

                if constraint_type == "allowed_data_list":
                    # Split comma-separated list
                    classifications = [c.strip() for c in value.split(",") if c.strip()]
                    for classification in classifications:
                        constraints.append(ParsedConstraint(
                            constraint_type="allowed_data_classifications",
                            value=classification,
                            original_text=match.group(0),
                            confidence=ConfidenceLevel.HIGH,
                        ))
                else:
                    base_type = (
                        "denied_data_classifications"
                        if "denied" in constraint_type
                        else "allowed_data_classifications"
                    )
                    constraints.append(ParsedConstraint(
                        constraint_type=base_type,
                        value=value,
                        original_text=match.group(0),
                        confidence=ConfidenceLevel.HIGH,
                    ))

        return constraints

    def _parse_read_only(self, text: str) -> list[ParsedConstraint]:
        """Parse read-only constraints."""
        constraints = []

        for pattern, _ in self._read_only_patterns:
            for match in pattern.finditer(text):
                constraints.append(ParsedConstraint(
                    constraint_type="read_only",
                    value=True,
                    original_text=match.group(0),
                    confidence=ConfidenceLevel.HIGH,
                ))
                # Only need one match
                return constraints

        return constraints

    def _parse_max_tokens(self, text: str) -> list[ParsedConstraint]:
        """Parse max tokens constraints."""
        constraints = []

        for pattern, _ in self._max_tokens_patterns:
            for match in pattern.finditer(text):
                tokens = int(match.group(1))
                constraints.append(ParsedConstraint(
                    constraint_type="max_tokens_per_request",
                    value=tokens,
                    original_text=match.group(0),
                    confidence=ConfidenceLevel.HIGH,
                ))

        return constraints

    def _build_permissions(self, constraints: list[ParsedConstraint]) -> TokenPermissions:
        """Build TokenPermissions from parsed constraints."""
        allowed_models: list[str] = []
        denied_models: list[str] = []
        allowed_providers: list[str] = []
        denied_providers: list[str] = []
        allowed_use_cases: list[str] = []
        denied_use_cases: list[str] = []
        allowed_data: list[str] = []
        denied_data: list[str] = []
        budget_limit: float | None = None
        budget_period = BudgetPeriod.MONTHLY
        rate_limit: RateLimit | None = None
        valid_hours: TimeWindow | None = None
        max_tokens: int | None = None

        for constraint in constraints:
            if constraint.constraint_type == "allowed_models":
                allowed_models.append(constraint.value)
            elif constraint.constraint_type == "denied_models":
                denied_models.append(constraint.value)
            elif constraint.constraint_type == "allowed_providers":
                allowed_providers.append(constraint.value)
            elif constraint.constraint_type == "denied_providers":
                denied_providers.append(constraint.value)
            elif constraint.constraint_type == "allowed_use_cases":
                allowed_use_cases.append(constraint.value)
            elif constraint.constraint_type == "denied_use_cases":
                denied_use_cases.append(constraint.value)
            elif constraint.constraint_type == "allowed_data_classifications":
                allowed_data.append(constraint.value)
            elif constraint.constraint_type == "denied_data_classifications":
                denied_data.append(constraint.value)
            elif constraint.constraint_type == "budget":
                budget_limit = constraint.value["amount"]
                budget_period = constraint.value["period"]
            elif constraint.constraint_type == "rate_limit":
                rate_limit = RateLimit(
                    max_requests=constraint.value["max_requests"],
                    period_seconds=constraint.value["period_seconds"],
                )
            elif constraint.constraint_type == "time_window":
                valid_hours = constraint.value
            elif constraint.constraint_type == "weekdays_only":
                if valid_hours:
                    # Add days to existing window
                    valid_hours = TimeWindow(
                        start=valid_hours.start,
                        end=valid_hours.end,
                        timezone=valid_hours.timezone,
                        days_of_week=constraint.value,
                    )
                else:
                    # Create all-day window with weekday restriction
                    valid_hours = TimeWindow(
                        start=time(0, 0),
                        end=time(23, 59),
                        days_of_week=constraint.value,
                    )
            elif constraint.constraint_type == "max_tokens_per_request":
                max_tokens = constraint.value
            elif constraint.constraint_type == "read_only":
                # Add read-only use case restrictions
                denied_use_cases.extend([
                    "generation",
                    "completion",
                    "chat",
                    "creation",
                ])
                if not allowed_use_cases:
                    allowed_use_cases.extend([
                        "embedding",
                        "classification",
                        "analysis",
                        "summarization",
                    ])

        return TokenPermissions(
            allowed_models=list(set(allowed_models)),
            denied_models=list(set(denied_models)),
            allowed_providers=list(set(allowed_providers)),
            denied_providers=list(set(denied_providers)),
            allowed_use_cases=list(set(allowed_use_cases)),
            denied_use_cases=list(set(denied_use_cases)),
            allowed_data_classifications=list(set(allowed_data)),
            denied_data_classifications=list(set(denied_data)),
            budget_limit=budget_limit,
            budget_period=budget_period,
            rate_limit=rate_limit,
            valid_hours=valid_hours,
            max_tokens_per_request=max_tokens,
        )

    def _check_conflicts(self, constraints: list[ParsedConstraint]) -> list[str]:
        """Check for conflicting constraints."""
        warnings = []

        # Check for model conflicts (same model in allowed and denied)
        allowed_models = {c.value for c in constraints if c.constraint_type == "allowed_models"}
        denied_models = {c.value for c in constraints if c.constraint_type == "denied_models"}
        model_conflicts = allowed_models & denied_models
        if model_conflicts:
            warnings.append(
                f"Conflict: Models both allowed and denied: {', '.join(model_conflicts)}"
            )

        # Check for provider conflicts
        allowed_providers = {c.value for c in constraints if c.constraint_type == "allowed_providers"}
        denied_providers = {c.value for c in constraints if c.constraint_type == "denied_providers"}
        provider_conflicts = allowed_providers & denied_providers
        if provider_conflicts:
            warnings.append(
                f"Conflict: Providers both allowed and denied: {', '.join(provider_conflicts)}"
            )

        # Check for use case conflicts
        allowed_uses = {c.value for c in constraints if c.constraint_type == "allowed_use_cases"}
        denied_uses = {c.value for c in constraints if c.constraint_type == "denied_use_cases"}
        use_conflicts = allowed_uses & denied_uses
        if use_conflicts:
            warnings.append(
                f"Conflict: Use cases both allowed and denied: {', '.join(use_conflicts)}"
            )

        # Check for multiple budgets
        budget_constraints = [c for c in constraints if c.constraint_type == "budget"]
        if len(budget_constraints) > 1:
            warnings.append(
                "Multiple budget specifications found - using the last one"
            )

        # Check for multiple rate limits
        rate_constraints = [c for c in constraints if c.constraint_type == "rate_limit"]
        if len(rate_constraints) > 1:
            warnings.append(
                "Multiple rate limit specifications found - using the last one"
            )

        return warnings

    def _calculate_confidence(
        self,
        constraints: list[ParsedConstraint],
        warnings: list[str],
    ) -> ConfidenceLevel:
        """Calculate overall confidence level."""
        if not constraints:
            return ConfidenceLevel.LOW

        if warnings:
            return ConfidenceLevel.MEDIUM

        # Check individual constraint confidence
        low_confidence = sum(1 for c in constraints if c.confidence == ConfidenceLevel.LOW)
        medium_confidence = sum(1 for c in constraints if c.confidence == ConfidenceLevel.MEDIUM)

        if low_confidence > 0:
            return ConfidenceLevel.LOW
        if medium_confidence > len(constraints) / 2:
            return ConfidenceLevel.MEDIUM

        return ConfidenceLevel.HIGH

    def _generate_suggestions(
        self,
        constraints: list[ParsedConstraint],
        text: str,
    ) -> list[str]:
        """Generate suggestions for improving the description."""
        suggestions = []

        if not constraints:
            suggestions.append(
                "Try phrases like 'allow model gpt-4' or 'budget of $100 per month'"
            )

        # Check for missing common constraints
        constraint_types = {c.constraint_type for c in constraints}

        if "budget" not in constraint_types:
            suggestions.append(
                "Consider specifying a budget, e.g., 'up to $50 per month'"
            )

        if "rate_limit" not in constraint_types:
            suggestions.append(
                "Consider adding a rate limit, e.g., 'no more than 10 requests per minute'"
            )

        return suggestions

    def _find_unrecognized(
        self,
        text: str,
        constraints: list[ParsedConstraint],
    ) -> list[str]:
        """Find parts of the text that weren't recognized."""
        # Get all matched spans
        matched_spans: list[tuple[int, int]] = []
        text_lower = text.lower()

        for constraint in constraints:
            original = constraint.original_text.lower()
            start = text_lower.find(original)
            if start >= 0:
                matched_spans.append((start, start + len(original)))

        # Merge overlapping spans
        matched_spans.sort()
        merged: list[tuple[int, int]] = []
        for start, end in matched_spans:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))

        # Find unmatched parts
        unrecognized = []
        last_end = 0
        for start, end in merged:
            if start > last_end:
                part = text[last_end:start].strip()
                if part and len(part) > 3:  # Ignore small connectors
                    # Filter out common connectors
                    if part.lower() not in {"and", "with", "the", "a", "an", "for", "to", ","}:
                        unrecognized.append(part)
            last_end = end

        # Check remaining text
        if last_end < len(text):
            part = text[last_end:].strip()
            if part and len(part) > 3:
                if part.lower() not in {"and", "with", "the", "a", "an", "for", "to", ","}:
                    unrecognized.append(part)

        return unrecognized
