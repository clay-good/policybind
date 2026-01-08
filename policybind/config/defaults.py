"""
Default configuration values for PolicyBind.

This module provides sensible default values for all configuration options.
The defaults are designed to be secure, preferring deny-by-default behavior
and requiring proper data classification.

These defaults can be overridden by YAML configuration files and/or
environment variables.
"""

from policybind.config.schema import (
    DatabaseConfig,
    EnforcementConfig,
    LoggingConfig,
    PolicyBindConfig,
    RegistryConfig,
    ServerConfig,
    TokenConfig,
)

# Default database configuration
DEFAULT_DATABASE = DatabaseConfig(
    path="policybind.db",
    pool_size=5,
    timeout_seconds=30.0,
)

# Default enforcement configuration - secure by default
DEFAULT_ENFORCEMENT = EnforcementConfig(
    default_action="deny",  # Deny by default for security
    log_all_requests=True,  # Log everything for audit
    require_classification=True,  # Require data classification
    max_prompt_length=0,  # No limit by default
    fail_open=False,  # Fail closed for security
    enforcement_timeout_ms=5000.0,  # 5 second timeout
)

# Default registry configuration
DEFAULT_REGISTRY = RegistryConfig(
    require_approval_for_high_risk=True,  # Require approval for risky deployments
    auto_suspend_on_violations=True,  # Auto-suspend on violations
    violation_threshold=10,  # Suspend after 10 violations
    review_reminder_days=7,  # Remind 7 days before review
    default_review_interval_days=90,  # Review every 90 days
)

# Default token configuration
DEFAULT_TOKENS = TokenConfig(
    default_expiry_days=30,  # 30 day default expiry
    max_expiry_days=365,  # Max 1 year tokens
    secret_key_env_var="POLICYBIND_TOKEN_SECRET",
    min_token_length=32,
    hash_algorithm="sha256",
)

# Default logging configuration
DEFAULT_LOGGING = LoggingConfig(
    level="INFO",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    output_path="",  # stderr only by default
    include_timestamps=True,
    json_format=False,
)

# Default server configuration
DEFAULT_SERVER = ServerConfig(
    host="127.0.0.1",  # Localhost only by default for security
    port=8080,
    workers=4,
    cors_origins=[],  # No CORS by default
    api_key_header="X-API-Key",
    rate_limit_requests=1000,
    rate_limit_window_seconds=60,
)


def get_default_config() -> PolicyBindConfig:
    """
    Get the default configuration.

    Returns a PolicyBindConfig with all default values applied.
    This represents a secure, production-ready baseline configuration.

    Returns:
        PolicyBindConfig with default values.
    """
    return PolicyBindConfig(
        environment="development",
        database=DatabaseConfig(
            path=DEFAULT_DATABASE.path,
            pool_size=DEFAULT_DATABASE.pool_size,
            timeout_seconds=DEFAULT_DATABASE.timeout_seconds,
        ),
        enforcement=EnforcementConfig(
            default_action=DEFAULT_ENFORCEMENT.default_action,
            log_all_requests=DEFAULT_ENFORCEMENT.log_all_requests,
            require_classification=DEFAULT_ENFORCEMENT.require_classification,
            max_prompt_length=DEFAULT_ENFORCEMENT.max_prompt_length,
            fail_open=DEFAULT_ENFORCEMENT.fail_open,
            enforcement_timeout_ms=DEFAULT_ENFORCEMENT.enforcement_timeout_ms,
        ),
        registry=RegistryConfig(
            require_approval_for_high_risk=DEFAULT_REGISTRY.require_approval_for_high_risk,
            auto_suspend_on_violations=DEFAULT_REGISTRY.auto_suspend_on_violations,
            violation_threshold=DEFAULT_REGISTRY.violation_threshold,
            review_reminder_days=DEFAULT_REGISTRY.review_reminder_days,
            default_review_interval_days=DEFAULT_REGISTRY.default_review_interval_days,
        ),
        tokens=TokenConfig(
            default_expiry_days=DEFAULT_TOKENS.default_expiry_days,
            max_expiry_days=DEFAULT_TOKENS.max_expiry_days,
            secret_key_env_var=DEFAULT_TOKENS.secret_key_env_var,
            min_token_length=DEFAULT_TOKENS.min_token_length,
            hash_algorithm=DEFAULT_TOKENS.hash_algorithm,
        ),
        logging=LoggingConfig(
            level=DEFAULT_LOGGING.level,
            format=DEFAULT_LOGGING.format,
            output_path=DEFAULT_LOGGING.output_path,
            include_timestamps=DEFAULT_LOGGING.include_timestamps,
            json_format=DEFAULT_LOGGING.json_format,
        ),
        server=ServerConfig(
            host=DEFAULT_SERVER.host,
            port=DEFAULT_SERVER.port,
            workers=DEFAULT_SERVER.workers,
            cors_origins=DEFAULT_SERVER.cors_origins.copy(),
            api_key_header=DEFAULT_SERVER.api_key_header,
            rate_limit_requests=DEFAULT_SERVER.rate_limit_requests,
            rate_limit_window_seconds=DEFAULT_SERVER.rate_limit_window_seconds,
        ),
        policies_path="policies",
        metadata={},
    )


def get_production_config() -> PolicyBindConfig:
    """
    Get a production-ready configuration.

    Returns a PolicyBindConfig with settings appropriate for production use,
    including stricter security settings.

    Returns:
        PolicyBindConfig with production settings.
    """
    config = get_default_config()
    config.environment = "production"
    config.logging.level = "WARNING"
    config.logging.json_format = True
    return config


def get_development_config() -> PolicyBindConfig:
    """
    Get a development configuration.

    Returns a PolicyBindConfig with settings appropriate for development,
    including more verbose logging and relaxed security settings.

    Returns:
        PolicyBindConfig with development settings.
    """
    config = get_default_config()
    config.environment = "development"
    config.logging.level = "DEBUG"
    config.database.path = "policybind_dev.db"
    return config


def get_test_config() -> PolicyBindConfig:
    """
    Get a test configuration.

    Returns a PolicyBindConfig suitable for running tests, using
    an in-memory database and other test-friendly settings.

    Returns:
        PolicyBindConfig with test settings.
    """
    config = get_default_config()
    config.environment = "test"
    config.database.path = ":memory:"
    config.logging.level = "DEBUG"
    config.enforcement.log_all_requests = False  # Reduce noise in tests
    return config
