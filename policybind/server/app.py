"""
PolicyBind HTTP server application.

This module provides the main application factory and server runner for
the PolicyBind HTTP API.

Example:
    Running the server::

        from policybind.server import create_app, run_server
        from policybind.config import PolicyBindConfig

        config = PolicyBindConfig()
        app = create_app(config)
        run_server(app)
"""

import asyncio
import logging
import signal
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aiohttp import web

from policybind.config.schema import PolicyBindConfig

logger = logging.getLogger("policybind.server")


@dataclass
class ServerConfig:
    """
    Server-specific configuration.

    Attributes:
        host: Host address to bind to.
        port: Port number to listen on.
        enable_cors: Whether to enable CORS.
        cors_origins: List of allowed CORS origins.
        enable_rate_limiting: Whether to enable rate limiting.
        rate_limit_requests: Maximum requests per window.
        rate_limit_window_seconds: Rate limit window duration.
        api_key_header: Header name for API key authentication.
        require_auth: Whether authentication is required.
        enable_metrics: Whether to enable the metrics endpoint.
    """

    host: str = "127.0.0.1"
    port: int = 8080
    enable_cors: bool = False
    cors_origins: list[str] = field(default_factory=list)
    enable_rate_limiting: bool = True
    rate_limit_requests: int = 1000
    rate_limit_window_seconds: int = 60
    api_key_header: str = "X-API-Key"
    require_auth: bool = True
    enable_metrics: bool = True


class PolicyBindApplication:
    """
    PolicyBind HTTP application.

    Wraps the aiohttp application with PolicyBind-specific setup and
    lifecycle management.

    Example:
        Creating and running the application::

            from policybind.server import PolicyBindApplication
            from policybind.config import PolicyBindConfig

            config = PolicyBindConfig()
            app = PolicyBindApplication(config)
            app.run()
    """

    def __init__(
        self,
        config: PolicyBindConfig | None = None,
        server_config: ServerConfig | None = None,
    ) -> None:
        """
        Initialize the application.

        Args:
            config: PolicyBind configuration.
            server_config: Server-specific configuration.
        """
        self._config = config or PolicyBindConfig()
        self._server_config = server_config or self._create_server_config()
        self._app: "web.Application | None" = None
        self._runner: "web.AppRunner | None" = None
        self._site: "web.TCPSite | None" = None
        self._rate_limiter: Any = None
        self._shutdown_event: asyncio.Event | None = None

    def _create_server_config(self) -> ServerConfig:
        """Create server config from PolicyBind config."""
        return ServerConfig(
            host=self._config.server.host,
            port=self._config.server.port,
            cors_origins=self._config.server.cors_origins,
            enable_cors=bool(self._config.server.cors_origins),
            enable_rate_limiting=True,
            rate_limit_requests=self._config.server.rate_limit_requests,
            rate_limit_window_seconds=self._config.server.rate_limit_window_seconds,
            api_key_header=self._config.server.api_key_header,
        )

    @property
    def app(self) -> "web.Application":
        """Get the aiohttp application, creating it if needed."""
        if self._app is None:
            self._app = self._create_app()
        return self._app

    def _create_app(self) -> "web.Application":
        """Create and configure the aiohttp application."""
        from aiohttp import web

        from policybind.server.auth import (
            APIKeyAuthenticator,
            TokenAuthenticator,
            create_authentication_middleware,
            create_authorization_middleware,
        )
        from policybind.server.middleware import (
            create_cors_middleware,
            create_error_handler_middleware,
            create_rate_limit_middleware,
            create_request_id_middleware,
            create_request_logging_middleware,
        )
        from policybind.server.routes import setup_routes

        # Build middleware list
        middlewares = []

        # Request ID middleware (first, so all subsequent middleware have access)
        middlewares.append(create_request_id_middleware())

        # Error handler middleware
        middlewares.append(create_error_handler_middleware())

        # CORS middleware
        if self._server_config.enable_cors:
            middlewares.append(
                create_cors_middleware(
                    allowed_origins=self._server_config.cors_origins,
                )
            )

        # Rate limiting middleware
        if self._server_config.enable_rate_limiting:
            rate_limit_middleware, self._rate_limiter = create_rate_limit_middleware(
                max_requests=self._server_config.rate_limit_requests,
                window_seconds=self._server_config.rate_limit_window_seconds,
            )
            middlewares.append(rate_limit_middleware)

        # Request logging middleware
        middlewares.append(create_request_logging_middleware())

        # Authentication middleware
        api_key_auth = APIKeyAuthenticator(
            header_name=self._server_config.api_key_header,
        )
        token_auth = TokenAuthenticator()

        middlewares.append(
            create_authentication_middleware(
                api_key_authenticator=api_key_auth,
                token_authenticator=token_auth,
                require_auth=self._server_config.require_auth,
                exempt_paths=["/v1/health", "/v1/ready", "/v1/metrics"],
            )
        )

        # Authorization middleware
        middlewares.append(create_authorization_middleware())

        # Create application
        app = web.Application(middlewares=middlewares)

        # Store configuration
        app["config"] = self._config
        app["server_config"] = self._server_config
        app["api_key_authenticator"] = api_key_auth
        app["token_authenticator"] = token_auth

        # Set up routes
        setup_routes(app)

        # Set up startup and cleanup handlers
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)

        return app

    async def _on_startup(self, app: "web.Application") -> None:
        """Initialize application resources on startup."""
        logger.info("Starting PolicyBind server...")

        try:
            # Initialize database
            from policybind.storage.database import Database

            db_path = self._config.database.path
            database = Database(
                path=db_path,
                pool_size=self._config.database.pool_size,
                timeout=self._config.database.timeout_seconds,
            )
            app["database"] = database
            logger.info(f"Database initialized: {db_path}")

            # Initialize audit repository
            from policybind.storage.repositories import AuditRepository

            app["audit_repository"] = AuditRepository(database)

            # Load policies
            from policybind.engine.parser import PolicyParser
            from policybind.engine.reloader import PolicyReloader

            parser = PolicyParser()
            reloader = PolicyReloader(
                policies_path=self._config.policies_path,
                parser=parser,
            )

            policy_set = reloader.get_current_policy_set()
            app["policy_set"] = policy_set
            app["reloader"] = reloader

            if policy_set:
                logger.info(f"Policies loaded: {len(policy_set.rules)} rules")
            else:
                logger.warning("No policies loaded")

            # Initialize enforcement pipeline
            from policybind.engine.matcher import PolicyMatcher
            from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig

            if policy_set:
                pipeline_config = PipelineConfig(
                    enable_audit=self._config.enforcement.log_all_requests,
                    require_classification=self._config.enforcement.require_classification,
                )
                matcher = PolicyMatcher()
                pipeline = EnforcementPipeline(
                    policy_set=policy_set,
                    config=pipeline_config,
                    matcher=matcher,
                )
                app["pipeline"] = pipeline
                app["matcher"] = matcher
                logger.info("Enforcement pipeline initialized")

            # Initialize registry manager
            from policybind.registry.manager import RegistryManager
            from policybind.storage.repositories import RegistryRepository

            registry_repo = RegistryRepository(database)
            registry_manager = RegistryManager(registry_repo)
            app["registry_manager"] = registry_manager
            logger.info("Registry manager initialized")

            # Initialize token manager
            from policybind.tokens.manager import TokenManager

            token_manager = TokenManager()
            app["token_manager"] = token_manager

            # Connect token authenticator to token manager
            token_auth = app.get("token_authenticator")
            if token_auth:
                token_auth.set_token_manager(token_manager)

            logger.info("Token manager initialized")

            # Initialize incident manager
            from policybind.incidents.manager import IncidentManager
            from policybind.storage.repositories import IncidentRepository

            incident_repo = IncidentRepository(database)
            incident_manager = IncidentManager(incident_repo)
            app["incident_manager"] = incident_manager
            logger.info("Incident manager initialized")

            # Initialize compliance checker
            try:
                from policybind.registry.compliance import ComplianceChecker

                compliance_checker = ComplianceChecker()
                app["compliance_checker"] = compliance_checker
            except Exception as e:
                logger.warning(f"Could not initialize compliance checker: {e}")

            # Initialize versioning
            try:
                from policybind.engine.versioning import PolicyVersioning

                versioning = PolicyVersioning(database)
                app["versioning"] = versioning
            except Exception as e:
                logger.warning(f"Could not initialize versioning: {e}")

            logger.info("PolicyBind server started successfully")

        except Exception as e:
            logger.error(f"Failed to initialize server: {e}")
            raise

    async def _on_cleanup(self, app: "web.Application") -> None:
        """Clean up application resources on shutdown."""
        logger.info("Shutting down PolicyBind server...")

        # Close database connection
        database = app.get("database")
        if database:
            database.close()
            logger.info("Database connection closed")

        # Clean up rate limiter
        if self._rate_limiter:
            await self._rate_limiter.cleanup()

        logger.info("PolicyBind server shut down")

    def add_api_key(
        self,
        key: str,
        name: str,
        role: str = "reader",
    ) -> None:
        """
        Add an API key for authentication.

        Args:
            key: The API key value.
            name: Human-readable name for the key.
            role: Role to assign (reader, enforcer, operator, admin).
        """
        from policybind.server.auth import APIKey, Role

        api_key_auth = self.app.get("api_key_authenticator")
        if api_key_auth:
            api_key_auth.add_key(
                APIKey(
                    key=key,
                    name=name,
                    role=Role(role),
                )
            )

    async def start(self) -> None:
        """Start the server (async)."""
        from aiohttp import web

        self._runner = web.AppRunner(self.app)
        await self._runner.setup()

        self._site = web.TCPSite(
            self._runner,
            self._server_config.host,
            self._server_config.port,
        )
        await self._site.start()

        logger.info(
            f"Server listening on http://{self._server_config.host}:{self._server_config.port}"
        )

    async def stop(self) -> None:
        """Stop the server (async)."""
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()

    def run(self) -> None:
        """Run the server (blocking)."""
        from aiohttp import web

        web.run_app(
            self.app,
            host=self._server_config.host,
            port=self._server_config.port,
            print=lambda msg: logger.info(msg),
        )


def create_app(
    config: PolicyBindConfig | None = None,
    server_config: ServerConfig | None = None,
) -> "web.Application":
    """
    Create a PolicyBind HTTP application.

    This is the recommended way to create an application for deployment.

    Args:
        config: PolicyBind configuration.
        server_config: Server-specific configuration.

    Returns:
        Configured aiohttp Application.

    Example:
        Using with gunicorn::

            # In wsgi.py
            from policybind.server import create_app
            app = create_app()

        Then run with::

            gunicorn wsgi:app --worker-class aiohttp.GunicornWebWorker
    """
    pb_app = PolicyBindApplication(config, server_config)
    return pb_app.app


def run_server(
    app: "web.Application | None" = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    config: PolicyBindConfig | None = None,
) -> None:
    """
    Run the PolicyBind HTTP server.

    Args:
        app: Pre-created application (optional).
        host: Host address to bind to.
        port: Port number to listen on.
        config: PolicyBind configuration (used if app not provided).

    Example:
        Running the server::

            from policybind.server import run_server
            run_server(host="0.0.0.0", port=8080)
    """
    from aiohttp import web

    if app is None:
        server_config = ServerConfig(host=host, port=port)
        pb_app = PolicyBindApplication(config, server_config)
        app = pb_app.app
    else:
        # Update host/port in existing app
        pass

    logger.info(f"Starting PolicyBind server on http://{host}:{port}")

    web.run_app(
        app,
        host=host,
        port=port,
        print=lambda msg: logger.info(msg),
    )


async def run_server_async(
    app: "web.Application | None" = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    config: PolicyBindConfig | None = None,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """
    Run the PolicyBind HTTP server asynchronously.

    This allows the server to be run alongside other async tasks or
    to be gracefully shutdown using an event.

    Args:
        app: Pre-created application (optional).
        host: Host address to bind to.
        port: Port number to listen on.
        config: PolicyBind configuration (used if app not provided).
        shutdown_event: Event to signal shutdown.

    Example:
        Running with graceful shutdown::

            import asyncio
            from policybind.server import run_server_async

            shutdown_event = asyncio.Event()

            # In a signal handler:
            # shutdown_event.set()

            await run_server_async(shutdown_event=shutdown_event)
    """
    from aiohttp import web

    if app is None:
        server_config = ServerConfig(host=host, port=port)
        pb_app = PolicyBindApplication(config, server_config)
        app = pb_app.app

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host, port)
    await site.start()

    logger.info(f"Server listening on http://{host}:{port}")

    if shutdown_event:
        await shutdown_event.wait()
    else:
        # Wait forever
        while True:
            await asyncio.sleep(3600)

    await runner.cleanup()
