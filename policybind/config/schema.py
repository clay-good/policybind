"""
Configuration schema definitions for PolicyBind.

This module defines the configuration structure using dataclasses.
All configuration options are strongly typed with validation support.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DefaultAction(Enum):
    """Default enforcement action when no policy matches."""

    ALLOW = "allow"
    DENY = "deny"


class LogLevel(Enum):
    """Logging level options."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class DatabaseConfig:
    """
    Database configuration options.

    Attributes:
        path: Path to the SQLite database file. Use ":memory:" for
            in-memory database (useful for testing).
        pool_size: Maximum number of connections in the connection pool.
            Higher values allow more concurrent database access.
        timeout_seconds: Timeout in seconds for database operations.
            Operations exceeding this will raise an error.
    """

    path: str = "policybind.db"
    pool_size: int = 5
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if self.pool_size < 1:
            raise ValueError("pool_size must be at least 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


@dataclass
class EnforcementConfig:
    """
    Policy enforcement configuration options.

    Attributes:
        default_action: Action to take when no policy rule matches.
            Should be "deny" for security-conscious deployments.
        log_all_requests: Whether to log all requests to the audit log,
            even when allowed. Set to True for complete audit trails.
        require_classification: Whether to require data classification
            on all requests. Rejecting unclassified requests improves
            policy accuracy.
        max_prompt_length: Maximum allowed prompt length in characters.
            Requests exceeding this are rejected. Set to 0 for no limit.
        fail_open: Whether to allow requests when enforcement fails.
            Set to False (fail closed) for security-critical deployments.
        enforcement_timeout_ms: Maximum time in milliseconds for
            enforcement processing before timing out.
    """

    default_action: str = "deny"
    log_all_requests: bool = True
    require_classification: bool = True
    max_prompt_length: int = 0
    fail_open: bool = False
    enforcement_timeout_ms: float = 5000.0

    def __post_init__(self) -> None:
        """Validate configuration values."""
        valid_actions = ["allow", "deny"]
        if self.default_action.lower() not in valid_actions:
            raise ValueError(f"default_action must be one of: {valid_actions}")
        if self.max_prompt_length < 0:
            raise ValueError("max_prompt_length must be non-negative")
        if self.enforcement_timeout_ms <= 0:
            raise ValueError("enforcement_timeout_ms must be positive")


@dataclass
class RegistryConfig:
    """
    Model registry configuration options.

    Attributes:
        require_approval_for_high_risk: Whether deployments with HIGH
            or CRITICAL risk level require approval before use.
        auto_suspend_on_violations: Whether to automatically suspend
            deployments that exceed the violation threshold.
        violation_threshold: Number of policy violations before
            auto-suspension is triggered (if enabled).
        review_reminder_days: Days before a scheduled review to send
            reminder notifications.
        default_review_interval_days: Default number of days between
            required reviews for deployments.
    """

    require_approval_for_high_risk: bool = True
    auto_suspend_on_violations: bool = True
    violation_threshold: int = 10
    review_reminder_days: int = 7
    default_review_interval_days: int = 90

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if self.violation_threshold < 1:
            raise ValueError("violation_threshold must be at least 1")
        if self.review_reminder_days < 0:
            raise ValueError("review_reminder_days must be non-negative")
        if self.default_review_interval_days < 1:
            raise ValueError("default_review_interval_days must be at least 1")


@dataclass
class TokenConfig:
    """
    Access token configuration options.

    Attributes:
        default_expiry_days: Default number of days until a token expires.
            Can be overridden when creating individual tokens.
        max_expiry_days: Maximum allowed token expiry in days. Tokens
            cannot be created with longer expiry than this.
        secret_key_env_var: Name of the environment variable containing
            the secret key for token signing. The key itself should
            never be stored in configuration files.
        min_token_length: Minimum length for generated token values.
        hash_algorithm: Algorithm to use for token hashing.
    """

    default_expiry_days: int = 30
    max_expiry_days: int = 365
    secret_key_env_var: str = "POLICYBIND_TOKEN_SECRET"
    min_token_length: int = 32
    hash_algorithm: str = "sha256"

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if self.default_expiry_days < 1:
            raise ValueError("default_expiry_days must be at least 1")
        if self.max_expiry_days < self.default_expiry_days:
            raise ValueError("max_expiry_days must be >= default_expiry_days")
        if self.min_token_length < 16:
            raise ValueError("min_token_length must be at least 16")


@dataclass
class LoggingConfig:
    """
    Logging configuration options.

    Attributes:
        level: Minimum log level to output. One of: DEBUG, INFO,
            WARNING, ERROR, CRITICAL.
        format: Log message format string. Supports standard Python
            logging format specifiers.
        output_path: Path to log file. If empty or None, logs are
            written to stderr only.
        include_timestamps: Whether to include timestamps in log output.
        json_format: Whether to output logs in JSON format for
            structured logging systems.
    """

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    output_path: str = ""
    include_timestamps: bool = True
    json_format: bool = False

    def __post_init__(self) -> None:
        """Validate configuration values."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.level.upper() not in valid_levels:
            raise ValueError(f"level must be one of: {valid_levels}")


@dataclass
class ServerConfig:
    """
    HTTP server configuration options.

    Attributes:
        host: Host address to bind the server to.
        port: Port number to listen on.
        workers: Number of worker processes for handling requests.
        cors_origins: List of allowed CORS origins. Empty list disables CORS.
        api_key_header: HTTP header name for API key authentication.
        rate_limit_requests: Maximum requests per rate limit window.
        rate_limit_window_seconds: Duration of the rate limit window.
    """

    host: str = "127.0.0.1"
    port: int = 8080
    workers: int = 4
    cors_origins: list[str] = field(default_factory=list)
    api_key_header: str = "X-API-Key"
    rate_limit_requests: int = 1000
    rate_limit_window_seconds: int = 60

    def __post_init__(self) -> None:
        """Validate configuration values."""
        if self.port < 1 or self.port > 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.workers < 1:
            raise ValueError("workers must be at least 1")
        if self.rate_limit_requests < 1:
            raise ValueError("rate_limit_requests must be at least 1")
        if self.rate_limit_window_seconds < 1:
            raise ValueError("rate_limit_window_seconds must be at least 1")


@dataclass
class PolicyBindConfig:
    """
    Root configuration object for PolicyBind.

    This is the main configuration class that contains all other
    configuration sections. It can be loaded from YAML files and/or
    environment variables.

    Attributes:
        environment: The environment profile name (development, staging,
            production). Used for environment-specific configuration.
        database: Database configuration options.
        enforcement: Policy enforcement configuration options.
        registry: Model registry configuration options.
        tokens: Access token configuration options.
        logging: Logging configuration options.
        server: HTTP server configuration options.
        policies_path: Path to the directory containing policy YAML files.
        metadata: Additional custom configuration as key-value pairs.
    """

    environment: str = "development"
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    registry: RegistryConfig = field(default_factory=RegistryConfig)
    tokens: TokenConfig = field(default_factory=TokenConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    policies_path: str = "policies"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate configuration values."""
        valid_environments = ["development", "staging", "production", "test"]
        if self.environment.lower() not in valid_environments:
            raise ValueError(f"environment must be one of: {valid_environments}")

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development"

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            "environment": self.environment,
            "database": {
                "path": self.database.path,
                "pool_size": self.database.pool_size,
                "timeout_seconds": self.database.timeout_seconds,
            },
            "enforcement": {
                "default_action": self.enforcement.default_action,
                "log_all_requests": self.enforcement.log_all_requests,
                "require_classification": self.enforcement.require_classification,
                "max_prompt_length": self.enforcement.max_prompt_length,
                "fail_open": self.enforcement.fail_open,
                "enforcement_timeout_ms": self.enforcement.enforcement_timeout_ms,
            },
            "registry": {
                "require_approval_for_high_risk": self.registry.require_approval_for_high_risk,
                "auto_suspend_on_violations": self.registry.auto_suspend_on_violations,
                "violation_threshold": self.registry.violation_threshold,
                "review_reminder_days": self.registry.review_reminder_days,
                "default_review_interval_days": self.registry.default_review_interval_days,
            },
            "tokens": {
                "default_expiry_days": self.tokens.default_expiry_days,
                "max_expiry_days": self.tokens.max_expiry_days,
                "secret_key_env_var": self.tokens.secret_key_env_var,
                "min_token_length": self.tokens.min_token_length,
                "hash_algorithm": self.tokens.hash_algorithm,
            },
            "logging": {
                "level": self.logging.level,
                "format": self.logging.format,
                "output_path": self.logging.output_path,
                "include_timestamps": self.logging.include_timestamps,
                "json_format": self.logging.json_format,
            },
            "server": {
                "host": self.server.host,
                "port": self.server.port,
                "workers": self.server.workers,
                "cors_origins": self.server.cors_origins,
                "api_key_header": self.server.api_key_header,
                "rate_limit_requests": self.server.rate_limit_requests,
                "rate_limit_window_seconds": self.server.rate_limit_window_seconds,
            },
            "policies_path": self.policies_path,
            "metadata": self.metadata,
        }
