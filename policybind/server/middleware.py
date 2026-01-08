"""
HTTP middleware for PolicyBind server.

This module provides middleware components for the HTTP server including
request logging, error handling, authentication, and rate limiting.
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import (
    ConfigurationError,
    EnforcementError,
    IncidentError,
    PolicyBindError,
    PolicyError,
    RegistryError,
    StorageError,
    TokenError,
    ValidationError,
)
from policybind.models.base import generate_uuid, utc_now

# Type alias for aiohttp middleware handler
Handler = Callable[["web.Request"], Awaitable["web.StreamResponse"]]
Middleware = Callable[["web.Request", Handler], Awaitable["web.StreamResponse"]]


logger = logging.getLogger("policybind.server")


@dataclass
class RequestInfo:
    """
    Information about an HTTP request for logging.

    Attributes:
        request_id: Unique identifier for the request.
        method: HTTP method.
        path: Request path.
        remote: Remote address.
        user_agent: User-Agent header.
        start_time: Request start time.
        end_time: Request end time.
        status_code: Response status code.
        duration_ms: Request duration in milliseconds.
        authenticated_as: Authenticated user/API key identifier.
        error: Error message if request failed.
    """

    request_id: str = field(default_factory=generate_uuid)
    method: str = ""
    path: str = ""
    remote: str = ""
    user_agent: str = ""
    start_time: datetime = field(default_factory=utc_now)
    end_time: datetime | None = None
    status_code: int = 0
    duration_ms: float = 0.0
    authenticated_as: str | None = None
    error: str | None = None


def create_request_logging_middleware(
    log_level: int = logging.INFO,
    log_request_body: bool = False,
    log_response_body: bool = False,
) -> Middleware:
    """
    Create request logging middleware.

    Logs information about each request including method, path, status,
    and duration.

    Args:
        log_level: Logging level for request logs.
        log_request_body: Whether to log request body (careful with sensitive data).
        log_response_body: Whether to log response body.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    @web.middleware
    async def request_logging_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Log request and response information."""
        # Generate request ID
        request_id = generate_uuid()
        request["request_id"] = request_id

        info = RequestInfo(
            request_id=request_id,
            method=request.method,
            path=request.path,
            remote=request.remote or "unknown",
            user_agent=request.headers.get("User-Agent", ""),
            start_time=utc_now(),
        )

        start_time = time.perf_counter()

        try:
            response = await handler(request)
            info.status_code = response.status
            return response

        except web.HTTPException as e:
            info.status_code = e.status
            info.error = str(e)
            raise

        except Exception as e:
            info.status_code = 500
            info.error = str(e)
            raise

        finally:
            info.end_time = utc_now()
            info.duration_ms = (time.perf_counter() - start_time) * 1000

            # Get authenticated user if available
            info.authenticated_as = request.get("authenticated_as")

            # Log the request
            log_message = (
                f"{info.method} {info.path} "
                f"{info.status_code} "
                f"{info.duration_ms:.2f}ms "
                f"[{info.request_id[:8]}]"
            )

            if info.authenticated_as:
                log_message += f" user={info.authenticated_as}"

            if info.error:
                logger.log(log_level, f"{log_message} error={info.error}")
            else:
                logger.log(log_level, log_message)

    return request_logging_middleware


def create_error_handler_middleware() -> Middleware:
    """
    Create error handling middleware.

    Converts Python exceptions to appropriate HTTP responses with
    JSON error bodies.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    # Map exception types to HTTP status codes
    exception_status_map: dict[type[Exception], int] = {
        ValidationError: 400,
        ConfigurationError: 500,
        PolicyError: 400,
        EnforcementError: 500,
        RegistryError: 404,
        TokenError: 401,
        StorageError: 500,
        IncidentError: 404,
        PolicyBindError: 500,
    }

    @web.middleware
    async def error_handler_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Handle exceptions and convert to HTTP responses."""
        try:
            return await handler(request)

        except web.HTTPException:
            # Let aiohttp HTTP exceptions pass through
            raise

        except PolicyBindError as e:
            # Map PolicyBind exceptions to HTTP status codes
            status = 500
            for exc_type, code in exception_status_map.items():
                if isinstance(e, exc_type):
                    status = code
                    break

            request_id = request.get("request_id", "unknown")
            error_response = {
                "error": {
                    "type": e.__class__.__name__,
                    "message": e.message,
                    "details": e.details,
                    "request_id": request_id,
                }
            }

            logger.warning(
                f"PolicyBind error: {e.__class__.__name__}: {e.message}",
                extra={"request_id": request_id, "details": e.details},
            )

            return web.json_response(error_response, status=status)

        except asyncio.CancelledError:
            # Don't catch cancellation
            raise

        except Exception as e:
            # Unexpected exception - log and return 500
            request_id = request.get("request_id", "unknown")
            logger.exception(
                f"Unhandled exception: {e}",
                extra={"request_id": request_id},
            )

            error_response = {
                "error": {
                    "type": "InternalError",
                    "message": "An internal error occurred",
                    "request_id": request_id,
                }
            }

            return web.json_response(error_response, status=500)

    return error_handler_middleware


@dataclass
class RateLimitEntry:
    """Rate limit tracking entry."""

    count: int = 0
    window_start: float = field(default_factory=time.time)


class RateLimiter:
    """
    In-memory rate limiter for API requests.

    Tracks request counts per client (by API key or IP) within
    sliding time windows.

    Attributes:
        max_requests: Maximum requests per window.
        window_seconds: Duration of the rate limit window.
    """

    def __init__(
        self,
        max_requests: int = 1000,
        window_seconds: int = 60,
    ) -> None:
        """
        Initialize the rate limiter.

        Args:
            max_requests: Maximum requests per window.
            window_seconds: Duration of the rate limit window in seconds.
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._entries: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = asyncio.Lock()

    def _get_client_key(self, request: "web.Request") -> str:
        """Get a unique key for the client (API key or IP)."""
        # Prefer API key if authenticated
        auth_key = request.get("authenticated_as")
        if auth_key:
            return f"key:{auth_key}"

        # Fall back to remote IP
        remote = request.remote or "unknown"
        return f"ip:{remote}"

    async def check(self, request: "web.Request") -> tuple[bool, int]:
        """
        Check if a request is rate limited.

        Args:
            request: The HTTP request.

        Returns:
            Tuple of (is_allowed, remaining_requests).
        """
        client_key = self._get_client_key(request)
        current_time = time.time()

        async with self._lock:
            entry = self._entries[client_key]

            # Check if window has expired
            if current_time - entry.window_start >= self.window_seconds:
                # Reset window
                entry.count = 0
                entry.window_start = current_time

            # Check if rate limited
            if entry.count >= self.max_requests:
                remaining = 0
                return False, remaining

            # Increment count
            entry.count += 1
            remaining = self.max_requests - entry.count
            return True, remaining

    async def cleanup(self) -> None:
        """Remove expired entries to free memory."""
        current_time = time.time()
        async with self._lock:
            expired_keys = [
                key
                for key, entry in self._entries.items()
                if current_time - entry.window_start >= self.window_seconds * 2
            ]
            for key in expired_keys:
                del self._entries[key]


def create_rate_limit_middleware(
    max_requests: int = 1000,
    window_seconds: int = 60,
) -> tuple[Middleware, RateLimiter]:
    """
    Create rate limiting middleware.

    Returns both the middleware and the rate limiter instance so the
    limiter can be cleaned up periodically.

    Args:
        max_requests: Maximum requests per window.
        window_seconds: Duration of the rate limit window.

    Returns:
        Tuple of (middleware function, rate limiter instance).
    """
    from aiohttp import web

    limiter = RateLimiter(max_requests, window_seconds)

    @web.middleware
    async def rate_limit_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Enforce rate limiting on requests."""
        is_allowed, remaining = await limiter.check(request)

        if not is_allowed:
            request_id = request.get("request_id", "unknown")
            error_response = {
                "error": {
                    "type": "RateLimitExceeded",
                    "message": f"Rate limit exceeded. Max {limiter.max_requests} requests per {limiter.window_seconds} seconds.",
                    "request_id": request_id,
                }
            }
            response = web.json_response(error_response, status=429)
            response.headers["X-RateLimit-Limit"] = str(limiter.max_requests)
            response.headers["X-RateLimit-Remaining"] = "0"
            response.headers["X-RateLimit-Reset"] = str(limiter.window_seconds)
            return response

        response = await handler(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(limiter.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response

    return rate_limit_middleware, limiter


def create_cors_middleware(
    allowed_origins: list[str] | None = None,
    allow_credentials: bool = False,
    allowed_methods: list[str] | None = None,
    allowed_headers: list[str] | None = None,
    max_age: int = 3600,
) -> Middleware:
    """
    Create CORS middleware.

    Args:
        allowed_origins: List of allowed origins. None or empty disables CORS.
        allow_credentials: Whether to allow credentials.
        allowed_methods: Allowed HTTP methods.
        allowed_headers: Allowed request headers.
        max_age: Preflight cache duration in seconds.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    if not allowed_origins:
        # CORS disabled - return pass-through middleware
        @web.middleware
        async def noop_middleware(
            request: web.Request,
            handler: Handler,
        ) -> web.StreamResponse:
            return await handler(request)

        return noop_middleware

    allowed_methods = allowed_methods or ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    allowed_headers = allowed_headers or [
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Request-ID",
    ]

    @web.middleware
    async def cors_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Handle CORS headers."""
        origin = request.headers.get("Origin", "")

        # Check if origin is allowed
        origin_allowed = "*" in allowed_origins or origin in allowed_origins

        # Handle preflight requests
        if request.method == "OPTIONS" and origin_allowed:
            response = web.Response(status=204)
            response.headers["Access-Control-Allow-Origin"] = origin or "*"
            response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
            response.headers["Access-Control-Allow-Headers"] = ", ".join(allowed_headers)
            response.headers["Access-Control-Max-Age"] = str(max_age)
            if allow_credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"
            return response

        # Process the actual request
        response = await handler(request)

        # Add CORS headers to response
        if origin_allowed:
            response.headers["Access-Control-Allow-Origin"] = origin or "*"
            if allow_credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"

        return response

    return cors_middleware


def create_request_id_middleware() -> Middleware:
    """
    Create middleware that ensures every request has a unique ID.

    The request ID is taken from the X-Request-ID header if present,
    otherwise a new UUID is generated.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    @web.middleware
    async def request_id_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Ensure request has a unique ID."""
        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = generate_uuid()

        request["request_id"] = request_id

        response = await handler(request)
        response.headers["X-Request-ID"] = request_id

        return response

    return request_id_middleware
