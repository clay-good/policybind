"""
API authentication for PolicyBind server.

This module provides authentication and authorization middleware for
the HTTP API, supporting API key and token-based authentication.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from aiohttp import web

from policybind.exceptions import TokenError


logger = logging.getLogger("policybind.server.auth")


# Type alias for aiohttp middleware handler
Handler = Callable[["web.Request"], Awaitable["web.StreamResponse"]]
Middleware = Callable[["web.Request", Handler], Awaitable["web.StreamResponse"]]


class Role(Enum):
    """
    API roles for authorization.

    Roles define what operations a client can perform.
    """

    ANONYMOUS = "anonymous"
    """Unauthenticated access - very limited permissions."""

    READER = "reader"
    """Read-only access to policies, registry, and audit logs."""

    ENFORCER = "enforcer"
    """Can submit requests for enforcement."""

    OPERATOR = "operator"
    """Can manage registry, tokens, and incidents."""

    ADMIN = "admin"
    """Full administrative access."""


# Define permissions for each endpoint
ENDPOINT_PERMISSIONS: dict[str, set[Role]] = {
    # Health and metrics - public
    "GET /v1/health": {Role.ANONYMOUS, Role.READER, Role.ENFORCER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/ready": {Role.ANONYMOUS, Role.READER, Role.ENFORCER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/metrics": {Role.READER, Role.OPERATOR, Role.ADMIN},
    # Enforcement
    "POST /v1/enforce": {Role.ENFORCER, Role.OPERATOR, Role.ADMIN},
    # Policies - read
    "GET /v1/policies": {Role.READER, Role.ENFORCER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/policies/version": {Role.READER, Role.ENFORCER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/policies/history": {Role.READER, Role.OPERATOR, Role.ADMIN},
    # Policies - admin
    "POST /v1/policies/reload": {Role.ADMIN},
    "POST /v1/policies/test": {Role.OPERATOR, Role.ADMIN},
    # Registry - read
    "GET /v1/registry": {Role.READER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/registry/*": {Role.READER, Role.OPERATOR, Role.ADMIN},
    # Registry - write
    "POST /v1/registry": {Role.OPERATOR, Role.ADMIN},
    "PUT /v1/registry/*": {Role.OPERATOR, Role.ADMIN},
    "DELETE /v1/registry/*": {Role.ADMIN},
    "POST /v1/registry/*/approve": {Role.ADMIN},
    "POST /v1/registry/*/suspend": {Role.OPERATOR, Role.ADMIN},
    "POST /v1/registry/*/reinstate": {Role.ADMIN},
    # Tokens - read
    "GET /v1/tokens": {Role.OPERATOR, Role.ADMIN},
    "GET /v1/tokens/*": {Role.OPERATOR, Role.ADMIN},
    # Tokens - write
    "POST /v1/tokens": {Role.ADMIN},
    "PUT /v1/tokens/*": {Role.ADMIN},
    "DELETE /v1/tokens/*": {Role.ADMIN},
    "POST /v1/tokens/validate": {Role.ENFORCER, Role.OPERATOR, Role.ADMIN},
    # Incidents - read
    "GET /v1/incidents": {Role.READER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/incidents/*": {Role.READER, Role.OPERATOR, Role.ADMIN},
    # Incidents - write
    "POST /v1/incidents": {Role.OPERATOR, Role.ADMIN},
    "PUT /v1/incidents/*": {Role.OPERATOR, Role.ADMIN},
    "POST /v1/incidents/*/assign": {Role.OPERATOR, Role.ADMIN},
    "POST /v1/incidents/*/resolve": {Role.OPERATOR, Role.ADMIN},
    "POST /v1/incidents/*/close": {Role.OPERATOR, Role.ADMIN},
    # Audit - read
    "GET /v1/audit/logs": {Role.READER, Role.OPERATOR, Role.ADMIN},
    "GET /v1/audit/stats": {Role.READER, Role.OPERATOR, Role.ADMIN},
}


@dataclass
class APIKey:
    """
    API key configuration.

    Attributes:
        key: The API key value.
        name: Human-readable name for the key.
        role: Role assigned to this key.
        enabled: Whether the key is enabled.
        metadata: Additional metadata about the key.
    """

    key: str
    name: str = ""
    role: Role = Role.READER
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthContext:
    """
    Authentication context for a request.

    Attributes:
        authenticated: Whether the request is authenticated.
        role: Role of the authenticated client.
        identity: Identity string (API key name, token subject, etc.).
        auth_method: How the client was authenticated.
        metadata: Additional authentication metadata.
    """

    authenticated: bool = False
    role: Role = Role.ANONYMOUS
    identity: str = ""
    auth_method: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class APIKeyAuthenticator:
    """
    API key authenticator.

    Validates API keys from request headers and assigns roles.
    """

    def __init__(
        self,
        header_name: str = "X-API-Key",
        api_keys: list[APIKey] | None = None,
    ) -> None:
        """
        Initialize the authenticator.

        Args:
            header_name: HTTP header name for the API key.
            api_keys: List of configured API keys.
        """
        self.header_name = header_name
        self._keys: dict[str, APIKey] = {}

        if api_keys:
            for key in api_keys:
                self.add_key(key)

    def add_key(self, api_key: APIKey) -> None:
        """
        Add an API key to the authenticator.

        Args:
            api_key: The API key to add.
        """
        self._keys[api_key.key] = api_key

    def remove_key(self, key: str) -> bool:
        """
        Remove an API key.

        Args:
            key: The API key value to remove.

        Returns:
            True if the key was removed, False if not found.
        """
        if key in self._keys:
            del self._keys[key]
            return True
        return False

    def authenticate(self, request: "web.Request") -> AuthContext:
        """
        Authenticate a request using API key.

        Args:
            request: The HTTP request.

        Returns:
            AuthContext with authentication result.
        """
        # Get API key from header
        key_value = request.headers.get(self.header_name)

        if not key_value:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Look up the key
        api_key = self._keys.get(key_value)

        if not api_key:
            logger.warning(f"Invalid API key attempted: {key_value[:8]}...")
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        if not api_key.enabled:
            logger.warning(f"Disabled API key attempted: {api_key.name}")
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        return AuthContext(
            authenticated=True,
            role=api_key.role,
            identity=api_key.name,
            auth_method="api_key",
            metadata=api_key.metadata,
        )


class TokenAuthenticator:
    """
    PolicyBind token authenticator.

    Validates PolicyBind access tokens and assigns roles based on
    token permissions.
    """

    def __init__(self, token_manager: Any = None) -> None:
        """
        Initialize the authenticator.

        Args:
            token_manager: PolicyBind TokenManager instance.
        """
        self._token_manager = token_manager

    def set_token_manager(self, token_manager: Any) -> None:
        """Set the token manager instance."""
        self._token_manager = token_manager

    def authenticate(self, request: "web.Request") -> AuthContext:
        """
        Authenticate a request using PolicyBind token.

        Args:
            request: The HTTP request.

        Returns:
            AuthContext with authentication result.
        """
        if not self._token_manager:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Get token from Authorization header (Bearer token)
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        token_value = auth_header[7:]  # Remove "Bearer " prefix

        try:
            # Validate the token
            token_data = self._token_manager.validate(token_value)

            if not token_data:
                return AuthContext(authenticated=False, role=Role.ANONYMOUS)

            # Determine role based on token permissions
            role = self._determine_role(token_data)

            return AuthContext(
                authenticated=True,
                role=role,
                identity=token_data.get("subject", "unknown"),
                auth_method="bearer_token",
                metadata={"token_id": token_data.get("token_id")},
            )

        except TokenError as e:
            logger.warning(f"Token validation failed: {e}")
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        except Exception as e:
            logger.error(f"Token authentication error: {e}")
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

    def _determine_role(self, token_data: dict[str, Any]) -> Role:
        """
        Determine role based on token permissions.

        Args:
            token_data: Validated token data.

        Returns:
            Role for the token.
        """
        permissions = token_data.get("permissions", {})

        # Check for admin permission
        if permissions.get("admin"):
            return Role.ADMIN

        # Check for operator permissions
        if permissions.get("manage_registry") or permissions.get("manage_tokens"):
            return Role.OPERATOR

        # Check for enforcer permission
        if permissions.get("enforce"):
            return Role.ENFORCER

        # Default to reader
        return Role.READER


def create_authentication_middleware(
    api_key_authenticator: APIKeyAuthenticator | None = None,
    token_authenticator: TokenAuthenticator | None = None,
    require_auth: bool = True,
    exempt_paths: list[str] | None = None,
) -> Middleware:
    """
    Create authentication middleware.

    Authenticates requests using API keys or bearer tokens and stores
    the authentication context in the request.

    Args:
        api_key_authenticator: API key authenticator instance.
        token_authenticator: Token authenticator instance.
        require_auth: Whether authentication is required.
        exempt_paths: Paths that don't require authentication.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    exempt_paths = exempt_paths or ["/v1/health", "/v1/ready"]

    @web.middleware
    async def authentication_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Authenticate requests."""
        # Check if path is exempt
        if request.path in exempt_paths:
            request["auth_context"] = AuthContext(authenticated=False, role=Role.ANONYMOUS)
            return await handler(request)

        auth_context = AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Try API key authentication first
        if api_key_authenticator:
            auth_context = api_key_authenticator.authenticate(request)

        # If not authenticated, try token authentication
        if not auth_context.authenticated and token_authenticator:
            auth_context = token_authenticator.authenticate(request)

        # Store auth context in request
        request["auth_context"] = auth_context
        if auth_context.authenticated:
            request["authenticated_as"] = auth_context.identity

        # Check if authentication is required
        if require_auth and not auth_context.authenticated:
            request_id = request.get("request_id", "unknown")
            error_response = {
                "error": {
                    "type": "Unauthorized",
                    "message": "Authentication required",
                    "request_id": request_id,
                }
            }
            return web.json_response(error_response, status=401)

        return await handler(request)

    return authentication_middleware


def create_authorization_middleware(
    endpoint_permissions: dict[str, set[Role]] | None = None,
) -> Middleware:
    """
    Create authorization middleware.

    Checks that authenticated clients have permission to access
    the requested endpoint.

    Args:
        endpoint_permissions: Map of endpoint patterns to allowed roles.

    Returns:
        Middleware function.
    """
    from aiohttp import web

    permissions = endpoint_permissions or ENDPOINT_PERMISSIONS

    def _match_endpoint(method: str, path: str) -> set[Role] | None:
        """Find matching endpoint permissions."""
        # Try exact match first
        endpoint = f"{method} {path}"
        if endpoint in permissions:
            return permissions[endpoint]

        # Try wildcard match (e.g., "GET /v1/registry/*")
        path_parts = path.split("/")
        for pattern, roles in permissions.items():
            pattern_method, pattern_path = pattern.split(" ", 1)
            if pattern_method != method:
                continue

            if pattern_path.endswith("/*"):
                # Wildcard match
                prefix = pattern_path[:-1]  # Remove trailing *
                if path.startswith(prefix):
                    return roles

        # No match found
        return None

    @web.middleware
    async def authorization_middleware(
        request: web.Request,
        handler: Handler,
    ) -> web.StreamResponse:
        """Check authorization for requests."""
        auth_context: AuthContext = request.get("auth_context", AuthContext())

        # Get required roles for this endpoint
        allowed_roles = _match_endpoint(request.method, request.path)

        if allowed_roles is None:
            # No explicit permissions defined - deny by default
            request_id = request.get("request_id", "unknown")
            error_response = {
                "error": {
                    "type": "Forbidden",
                    "message": "Access denied - endpoint not configured",
                    "request_id": request_id,
                }
            }
            return web.json_response(error_response, status=403)

        # Check if client's role is allowed
        if auth_context.role not in allowed_roles:
            request_id = request.get("request_id", "unknown")
            logger.warning(
                f"Authorization denied: {auth_context.identity} "
                f"with role {auth_context.role.value} "
                f"attempted {request.method} {request.path}"
            )
            error_response = {
                "error": {
                    "type": "Forbidden",
                    "message": f"Insufficient permissions for this operation",
                    "request_id": request_id,
                }
            }
            return web.json_response(error_response, status=403)

        return await handler(request)

    return authorization_middleware
