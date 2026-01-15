"""
Logging utilities for PolicyBind.

This module provides logging configuration, sensitive data filtering,
and structured logging support with correlation ID tracking.
"""

import logging
import re
import sys
from contextvars import ContextVar
from datetime import datetime
from typing import Any

# Context variable for correlation/request ID
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)


# Patterns for sensitive data that should be redacted
SENSITIVE_PATTERNS = [
    # API keys and tokens
    (re.compile(r"(api[_-]?key|token|secret|password|auth)[=:\s]+['\"]?[\w-]+", re.IGNORECASE), r"\1=***REDACTED***"),
    (re.compile(r"(bearer\s+)[\w.-]+", re.IGNORECASE), r"\1***REDACTED***"),
    # Email addresses (partial redaction)
    (re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"), r"***@\2"),
    # Credit card numbers (basic pattern)
    (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), r"****-****-****-****"),
    # SSN (US format)
    (re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"), r"***-**-****"),
    # Authorization headers
    (re.compile(r"(Authorization:\s*)(Basic|Bearer)\s+[\w=+/.-]+", re.IGNORECASE), r"\1\2 ***REDACTED***"),
]

# Keys that should be redacted entirely in dictionaries
SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "secret_key",
    "authorization",
    "auth",
    "credentials",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
}


def set_correlation_id(correlation_id: str | None) -> None:
    """
    Set the correlation ID for the current context.

    Args:
        correlation_id: The correlation/request ID to set.
    """
    correlation_id_var.set(correlation_id)


def get_correlation_id() -> str | None:
    """
    Get the correlation ID for the current context.

    Returns:
        The current correlation ID or None.
    """
    return correlation_id_var.get()


def redact_sensitive_string(text: str) -> str:
    """
    Redact sensitive information from a string.

    Args:
        text: The text to redact.

    Returns:
        Text with sensitive information redacted.
    """
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_sensitive_dict(data: dict[str, Any], max_depth: int = 10) -> dict[str, Any]:
    """
    Redact sensitive information from a dictionary.

    Args:
        data: The dictionary to redact.
        max_depth: Maximum recursion depth.

    Returns:
        Dictionary with sensitive values redacted.
    """
    if max_depth <= 0:
        return {"__redacted__": "max depth exceeded"}

    result = {}
    for key, value in data.items():
        key_lower = key.lower().replace("-", "_")

        # Check if key itself is sensitive
        if key_lower in SENSITIVE_KEYS:
            result[key] = "***REDACTED***"
        elif isinstance(value, dict):
            result[key] = redact_sensitive_dict(value, max_depth - 1)
        elif isinstance(value, list):
            result[key] = [
                redact_sensitive_dict(v, max_depth - 1) if isinstance(v, dict)
                else redact_sensitive_string(str(v)) if isinstance(v, str)
                else v
                for v in value
            ]
        elif isinstance(value, str):
            result[key] = redact_sensitive_string(value)
        else:
            result[key] = value

    return result


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter that redacts sensitive data from log messages.

    This filter processes both the log message and any additional
    data in the 'extra' dictionary.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter the log record, redacting sensitive data.

        Args:
            record: The log record to filter.

        Returns:
            True (always allows the record through after filtering).
        """
        # Redact sensitive data from the message
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_string(record.msg)

        # Redact sensitive data from args
        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_sensitive_dict(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_sensitive_string(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )

        return True


class CorrelationIdFilter(logging.Filter):
    """
    Logging filter that adds correlation ID to log records.

    The correlation ID is taken from the context variable, allowing
    tracking of requests across multiple log statements.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Add correlation ID to the log record.

        Args:
            record: The log record to filter.

        Returns:
            True (always allows the record through).
        """
        record.correlation_id = get_correlation_id() or "-"
        return True


class JsonFormatter(logging.Formatter):
    """
    Format log records as JSON for structured logging.

    Outputs log records as single-line JSON objects with standard
    fields and any additional data from the 'extra' dictionary.
    """

    def __init__(
        self,
        include_timestamp: bool = True,
        include_level: bool = True,
        include_logger: bool = True,
        include_correlation_id: bool = True,
    ) -> None:
        """
        Initialize the JSON formatter.

        Args:
            include_timestamp: Include ISO timestamp.
            include_level: Include log level name.
            include_logger: Include logger name.
            include_correlation_id: Include correlation ID.
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_level = include_level
        self.include_logger = include_logger
        self.include_correlation_id = include_correlation_id

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record as JSON.

        Args:
            record: The log record to format.

        Returns:
            JSON string.
        """
        import json

        log_data: dict[str, Any] = {}

        if self.include_timestamp:
            log_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

        if self.include_level:
            log_data["level"] = record.levelname

        if self.include_logger:
            log_data["logger"] = record.name

        if self.include_correlation_id:
            correlation_id = getattr(record, "correlation_id", None) or get_correlation_id()
            if correlation_id:
                log_data["correlation_id"] = correlation_id

        # Add message
        log_data["message"] = record.getMessage()

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields (excluding standard LogRecord attributes)
        standard_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "correlation_id", "message",
        }

        for key, value in record.__dict__.items():
            if key not in standard_attrs:
                if isinstance(value, dict):
                    log_data[key] = redact_sensitive_dict(value)
                elif isinstance(value, str):
                    log_data[key] = redact_sensitive_string(value)
                else:
                    log_data[key] = value

        return json.dumps(log_data, default=str)


def configure_logging(
    level: int | str = logging.INFO,
    format_type: str = "text",
    include_sensitive_filter: bool = True,
    include_correlation_id: bool = True,
    stream: Any = None,
) -> None:
    """
    Configure logging for PolicyBind.

    Args:
        level: Logging level (e.g., logging.INFO, "DEBUG").
        format_type: Output format ("text" or "json").
        include_sensitive_filter: Add filter to redact sensitive data.
        include_correlation_id: Add correlation ID to log records.
        stream: Output stream (defaults to sys.stderr).
    """
    # Convert string level to int if needed
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Get root logger for policybind
    root_logger = logging.getLogger("policybind")
    root_logger.setLevel(level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create handler
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setLevel(level)

    # Create formatter
    if format_type == "json":
        formatter = JsonFormatter(
            include_correlation_id=include_correlation_id,
        )
    else:
        # Text format with optional correlation ID
        if include_correlation_id:
            fmt = "%(asctime)s [%(levelname)s] [%(correlation_id)s] %(name)s: %(message)s"
        else:
            fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    handler.setFormatter(formatter)

    # Add filters
    if include_sensitive_filter:
        handler.addFilter(SensitiveDataFilter())

    if include_correlation_id:
        handler.addFilter(CorrelationIdFilter())

    root_logger.addHandler(handler)

    # Prevent propagation to root logger
    root_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the policybind prefix.

    Args:
        name: Logger name (will be prefixed with "policybind.").

    Returns:
        Configured logger instance.
    """
    if not name.startswith("policybind"):
        name = f"policybind.{name}"
    return logging.getLogger(name)
