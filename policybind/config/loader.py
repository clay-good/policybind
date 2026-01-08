"""
Configuration loader for PolicyBind.

This module provides the ConfigLoader class for loading configuration
from YAML files with environment variable overrides.
"""

import os
from pathlib import Path
from typing import Any

import yaml

from policybind.config.defaults import (
    get_default_config,
    get_development_config,
    get_production_config,
    get_test_config,
)
from policybind.config.schema import (
    DatabaseConfig,
    EnforcementConfig,
    LoggingConfig,
    PolicyBindConfig,
    RegistryConfig,
    ServerConfig,
    TokenConfig,
)
from policybind.exceptions import ConfigurationError


class ConfigLoader:
    """
    Loads and validates PolicyBind configuration.

    The ConfigLoader supports loading configuration from:
    1. Default values (secure baseline)
    2. YAML configuration files
    3. Environment variables (POLICYBIND_ prefix)

    Configuration sources are applied in order, with later sources
    overriding earlier ones.

    Example:
        Loading configuration::

            loader = ConfigLoader()

            # Load from file with env overrides
            config = loader.load("config/policybind.yaml")

            # Load with specific environment profile
            config = loader.load("config/policybind.yaml", environment="production")
    """

    ENV_PREFIX = "POLICYBIND_"

    def __init__(self) -> None:
        """Initialize the configuration loader."""
        self._config: PolicyBindConfig | None = None

    def load(
        self,
        config_path: str | Path | None = None,
        environment: str | None = None,
    ) -> PolicyBindConfig:
        """
        Load configuration from file and environment.

        Args:
            config_path: Path to a YAML configuration file. If None,
                only defaults and environment variables are used.
            environment: Environment profile to use. Overrides any
                environment setting in the config file.

        Returns:
            A validated PolicyBindConfig object.

        Raises:
            ConfigurationError: If configuration is invalid or file not found.
        """
        # Start with defaults for the specified environment
        if environment:
            config = self._get_environment_defaults(environment)
        else:
            config = get_default_config()

        # Load from YAML file if provided
        if config_path:
            file_config = self._load_yaml(config_path)
            config = self._merge_config(config, file_config)

        # Override with environment variables
        config = self._apply_env_overrides(config)

        # Apply final environment if specified
        if environment:
            config.environment = environment

        # Validate the final configuration
        self._validate(config)

        self._config = config
        return config

    def _get_environment_defaults(self, environment: str) -> PolicyBindConfig:
        """Get default configuration for an environment."""
        env_lower = environment.lower()
        if env_lower == "production":
            return get_production_config()
        elif env_lower == "development":
            return get_development_config()
        elif env_lower == "test":
            return get_test_config()
        else:
            config = get_default_config()
            config.environment = environment
            return config

    def _load_yaml(self, path: str | Path) -> dict[str, Any]:
        """
        Load configuration from a YAML file.

        Args:
            path: Path to the YAML file.

        Returns:
            Dictionary of configuration values.

        Raises:
            ConfigurationError: If file not found or invalid YAML.
        """
        path = Path(path)

        if not path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {path}",
                details={"path": str(path)},
            )

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data if data else {}
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML in configuration file: {e}",
                details={"path": str(path)},
            ) from e
        except OSError as e:
            raise ConfigurationError(
                f"Failed to read configuration file: {e}",
                details={"path": str(path)},
            ) from e

    def _merge_config(
        self,
        base: PolicyBindConfig,
        override: dict[str, Any],
    ) -> PolicyBindConfig:
        """
        Merge file configuration into base configuration.

        Args:
            base: Base configuration object.
            override: Dictionary of override values.

        Returns:
            Merged configuration object.
        """
        if not override:
            return base

        # Handle top-level fields
        if "environment" in override:
            base.environment = str(override["environment"])

        if "policies_path" in override:
            base.policies_path = str(override["policies_path"])

        if "metadata" in override and isinstance(override["metadata"], dict):
            base.metadata.update(override["metadata"])

        # Handle nested configuration sections
        if "database" in override:
            base.database = self._merge_database(base.database, override["database"])

        if "enforcement" in override:
            base.enforcement = self._merge_enforcement(
                base.enforcement, override["enforcement"]
            )

        if "registry" in override:
            base.registry = self._merge_registry(base.registry, override["registry"])

        if "tokens" in override:
            base.tokens = self._merge_tokens(base.tokens, override["tokens"])

        if "logging" in override:
            base.logging = self._merge_logging(base.logging, override["logging"])

        if "server" in override:
            base.server = self._merge_server(base.server, override["server"])

        return base

    def _merge_database(
        self,
        base: DatabaseConfig,
        override: dict[str, Any],
    ) -> DatabaseConfig:
        """Merge database configuration."""
        return DatabaseConfig(
            path=override.get("path", base.path),
            pool_size=override.get("pool_size", base.pool_size),
            timeout_seconds=override.get("timeout_seconds", base.timeout_seconds),
        )

    def _merge_enforcement(
        self,
        base: EnforcementConfig,
        override: dict[str, Any],
    ) -> EnforcementConfig:
        """Merge enforcement configuration."""
        return EnforcementConfig(
            default_action=override.get("default_action", base.default_action),
            log_all_requests=override.get("log_all_requests", base.log_all_requests),
            require_classification=override.get(
                "require_classification", base.require_classification
            ),
            max_prompt_length=override.get("max_prompt_length", base.max_prompt_length),
            fail_open=override.get("fail_open", base.fail_open),
            enforcement_timeout_ms=override.get(
                "enforcement_timeout_ms", base.enforcement_timeout_ms
            ),
        )

    def _merge_registry(
        self,
        base: RegistryConfig,
        override: dict[str, Any],
    ) -> RegistryConfig:
        """Merge registry configuration."""
        return RegistryConfig(
            require_approval_for_high_risk=override.get(
                "require_approval_for_high_risk", base.require_approval_for_high_risk
            ),
            auto_suspend_on_violations=override.get(
                "auto_suspend_on_violations", base.auto_suspend_on_violations
            ),
            violation_threshold=override.get(
                "violation_threshold", base.violation_threshold
            ),
            review_reminder_days=override.get(
                "review_reminder_days", base.review_reminder_days
            ),
            default_review_interval_days=override.get(
                "default_review_interval_days", base.default_review_interval_days
            ),
        )

    def _merge_tokens(
        self,
        base: TokenConfig,
        override: dict[str, Any],
    ) -> TokenConfig:
        """Merge token configuration."""
        return TokenConfig(
            default_expiry_days=override.get(
                "default_expiry_days", base.default_expiry_days
            ),
            max_expiry_days=override.get("max_expiry_days", base.max_expiry_days),
            secret_key_env_var=override.get(
                "secret_key_env_var", base.secret_key_env_var
            ),
            min_token_length=override.get("min_token_length", base.min_token_length),
            hash_algorithm=override.get("hash_algorithm", base.hash_algorithm),
        )

    def _merge_logging(
        self,
        base: LoggingConfig,
        override: dict[str, Any],
    ) -> LoggingConfig:
        """Merge logging configuration."""
        return LoggingConfig(
            level=override.get("level", base.level),
            format=override.get("format", base.format),
            output_path=override.get("output_path", base.output_path),
            include_timestamps=override.get(
                "include_timestamps", base.include_timestamps
            ),
            json_format=override.get("json_format", base.json_format),
        )

    def _merge_server(
        self,
        base: ServerConfig,
        override: dict[str, Any],
    ) -> ServerConfig:
        """Merge server configuration."""
        return ServerConfig(
            host=override.get("host", base.host),
            port=override.get("port", base.port),
            workers=override.get("workers", base.workers),
            cors_origins=override.get("cors_origins", base.cors_origins),
            api_key_header=override.get("api_key_header", base.api_key_header),
            rate_limit_requests=override.get(
                "rate_limit_requests", base.rate_limit_requests
            ),
            rate_limit_window_seconds=override.get(
                "rate_limit_window_seconds", base.rate_limit_window_seconds
            ),
        )

    def _apply_env_overrides(self, config: PolicyBindConfig) -> PolicyBindConfig:
        """
        Apply environment variable overrides to configuration.

        Environment variables use the format:
        POLICYBIND_SECTION_OPTION=value

        For example:
        - POLICYBIND_DATABASE_PATH=mydb.db
        - POLICYBIND_ENFORCEMENT_DEFAULT_ACTION=allow
        - POLICYBIND_LOGGING_LEVEL=DEBUG

        Args:
            config: Configuration object to update.

        Returns:
            Updated configuration object.
        """
        env_mapping = {
            # Top-level
            "POLICYBIND_ENVIRONMENT": ("environment", str),
            "POLICYBIND_POLICIES_PATH": ("policies_path", str),
            # Database
            "POLICYBIND_DATABASE_PATH": ("database.path", str),
            "POLICYBIND_DATABASE_POOL_SIZE": ("database.pool_size", int),
            "POLICYBIND_DATABASE_TIMEOUT_SECONDS": ("database.timeout_seconds", float),
            # Enforcement
            "POLICYBIND_ENFORCEMENT_DEFAULT_ACTION": ("enforcement.default_action", str),
            "POLICYBIND_ENFORCEMENT_LOG_ALL_REQUESTS": (
                "enforcement.log_all_requests",
                self._parse_bool,
            ),
            "POLICYBIND_ENFORCEMENT_REQUIRE_CLASSIFICATION": (
                "enforcement.require_classification",
                self._parse_bool,
            ),
            "POLICYBIND_ENFORCEMENT_MAX_PROMPT_LENGTH": (
                "enforcement.max_prompt_length",
                int,
            ),
            "POLICYBIND_ENFORCEMENT_FAIL_OPEN": (
                "enforcement.fail_open",
                self._parse_bool,
            ),
            "POLICYBIND_ENFORCEMENT_TIMEOUT_MS": (
                "enforcement.enforcement_timeout_ms",
                float,
            ),
            # Registry
            "POLICYBIND_REGISTRY_REQUIRE_APPROVAL_HIGH_RISK": (
                "registry.require_approval_for_high_risk",
                self._parse_bool,
            ),
            "POLICYBIND_REGISTRY_AUTO_SUSPEND": (
                "registry.auto_suspend_on_violations",
                self._parse_bool,
            ),
            "POLICYBIND_REGISTRY_VIOLATION_THRESHOLD": (
                "registry.violation_threshold",
                int,
            ),
            # Tokens
            "POLICYBIND_TOKENS_DEFAULT_EXPIRY_DAYS": ("tokens.default_expiry_days", int),
            "POLICYBIND_TOKENS_MAX_EXPIRY_DAYS": ("tokens.max_expiry_days", int),
            "POLICYBIND_TOKENS_SECRET_KEY_ENV_VAR": ("tokens.secret_key_env_var", str),
            # Logging
            "POLICYBIND_LOGGING_LEVEL": ("logging.level", str),
            "POLICYBIND_LOGGING_OUTPUT_PATH": ("logging.output_path", str),
            "POLICYBIND_LOGGING_JSON_FORMAT": ("logging.json_format", self._parse_bool),
            # Server
            "POLICYBIND_SERVER_HOST": ("server.host", str),
            "POLICYBIND_SERVER_PORT": ("server.port", int),
            "POLICYBIND_SERVER_WORKERS": ("server.workers", int),
        }

        for env_var, (path, converter) in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    converted = converter(value)
                    self._set_nested_attr(config, path, converted)
                except (ValueError, TypeError) as e:
                    raise ConfigurationError(
                        f"Invalid value for {env_var}: {e}",
                        details={"env_var": env_var, "value": value},
                    ) from e

        return config

    def _set_nested_attr(self, obj: Any, path: str, value: Any) -> None:
        """Set a nested attribute using dot notation."""
        parts = path.split(".")
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

    def _parse_bool(self, value: str) -> bool:
        """Parse a string to boolean."""
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        elif value.lower() in ("false", "0", "no", "off"):
            return False
        else:
            raise ValueError(f"Cannot parse '{value}' as boolean")

    def _validate(self, config: PolicyBindConfig) -> None:
        """
        Validate the complete configuration.

        Args:
            config: Configuration to validate.

        Raises:
            ConfigurationError: If configuration is invalid.
        """
        errors: list[str] = []

        # Validate each section (dataclass __post_init__ handles most validation)
        try:
            # Trigger validation by creating new instances
            DatabaseConfig(
                path=config.database.path,
                pool_size=config.database.pool_size,
                timeout_seconds=config.database.timeout_seconds,
            )
        except ValueError as e:
            errors.append(f"database: {e}")

        try:
            EnforcementConfig(
                default_action=config.enforcement.default_action,
                log_all_requests=config.enforcement.log_all_requests,
                require_classification=config.enforcement.require_classification,
                max_prompt_length=config.enforcement.max_prompt_length,
                fail_open=config.enforcement.fail_open,
                enforcement_timeout_ms=config.enforcement.enforcement_timeout_ms,
            )
        except ValueError as e:
            errors.append(f"enforcement: {e}")

        try:
            RegistryConfig(
                require_approval_for_high_risk=config.registry.require_approval_for_high_risk,
                auto_suspend_on_violations=config.registry.auto_suspend_on_violations,
                violation_threshold=config.registry.violation_threshold,
                review_reminder_days=config.registry.review_reminder_days,
                default_review_interval_days=config.registry.default_review_interval_days,
            )
        except ValueError as e:
            errors.append(f"registry: {e}")

        try:
            TokenConfig(
                default_expiry_days=config.tokens.default_expiry_days,
                max_expiry_days=config.tokens.max_expiry_days,
                secret_key_env_var=config.tokens.secret_key_env_var,
                min_token_length=config.tokens.min_token_length,
                hash_algorithm=config.tokens.hash_algorithm,
            )
        except ValueError as e:
            errors.append(f"tokens: {e}")

        try:
            LoggingConfig(
                level=config.logging.level,
                format=config.logging.format,
                output_path=config.logging.output_path,
                include_timestamps=config.logging.include_timestamps,
                json_format=config.logging.json_format,
            )
        except ValueError as e:
            errors.append(f"logging: {e}")

        try:
            ServerConfig(
                host=config.server.host,
                port=config.server.port,
                workers=config.server.workers,
                cors_origins=config.server.cors_origins,
                api_key_header=config.server.api_key_header,
                rate_limit_requests=config.server.rate_limit_requests,
                rate_limit_window_seconds=config.server.rate_limit_window_seconds,
            )
        except ValueError as e:
            errors.append(f"server: {e}")

        if errors:
            raise ConfigurationError(
                f"Configuration validation failed: {'; '.join(errors)}",
                details={"errors": errors},
            )

    @property
    def config(self) -> PolicyBindConfig:
        """Get the currently loaded configuration."""
        if self._config is None:
            raise ConfigurationError("Configuration not loaded. Call load() first.")
        return self._config


def load_config(
    config_path: str | Path | None = None,
    environment: str | None = None,
) -> PolicyBindConfig:
    """
    Convenience function to load configuration.

    Args:
        config_path: Path to a YAML configuration file.
        environment: Environment profile to use.

    Returns:
        A validated PolicyBindConfig object.
    """
    loader = ConfigLoader()
    return loader.load(config_path, environment)
