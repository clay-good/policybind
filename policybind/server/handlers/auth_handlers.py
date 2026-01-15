"""
Authentication API handlers for PolicyBind.

This module provides HTTP handlers for authentication endpoints
including SAML SSO flows and authentication status.
"""

import json
import logging
from typing import TYPE_CHECKING, Any

from policybind.server.auth import AuthContext, Role
from policybind.server.auth_providers import (
    LDAPAuthenticator,
    LDAPConfig,
    SAMLAuthenticator,
    SAMLConfig,
)

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.handlers.auth")

# Global authenticator instances
_ldap_authenticator: LDAPAuthenticator | None = None
_saml_authenticator: SAMLAuthenticator | None = None


def get_ldap_authenticator() -> LDAPAuthenticator | None:
    """Get the global LDAP authenticator."""
    return _ldap_authenticator


def set_ldap_authenticator(authenticator: LDAPAuthenticator | None) -> None:
    """Set the global LDAP authenticator."""
    global _ldap_authenticator
    _ldap_authenticator = authenticator


def get_saml_authenticator() -> SAMLAuthenticator | None:
    """Get the global SAML authenticator."""
    return _saml_authenticator


def set_saml_authenticator(authenticator: SAMLAuthenticator | None) -> None:
    """Set the global SAML authenticator."""
    global _saml_authenticator
    _saml_authenticator = authenticator


async def auth_status(request: "web.Request") -> "web.Response":
    """
    Get current authentication status.

    GET /v1/auth/status

    Returns:
        JSON with authentication status and user info.
    """
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())

    response_data = {
        "authenticated": auth_context.authenticated,
        "role": auth_context.role.value,
        "identity": auth_context.identity,
        "auth_method": auth_context.auth_method,
    }

    # Include safe metadata
    if auth_context.metadata:
        safe_metadata = {}
        for key, value in auth_context.metadata.items():
            if key not in ("token_id", "session_id"):  # Exclude sensitive IDs
                safe_metadata[key] = value
        if safe_metadata:
            response_data["metadata"] = safe_metadata

    return web.json_response(response_data)


async def auth_providers(request: "web.Request") -> "web.Response":
    """
    List available authentication providers.

    GET /v1/auth/providers

    Returns:
        JSON list of enabled authentication providers.
    """
    from aiohttp import web

    providers = []

    # API key is always available
    providers.append({
        "name": "api_key",
        "type": "api_key",
        "enabled": True,
        "description": "API key authentication via X-API-Key header",
    })

    # Bearer token is always available
    providers.append({
        "name": "bearer_token",
        "type": "bearer_token",
        "enabled": True,
        "description": "PolicyBind token authentication via Bearer header",
    })

    # LDAP
    if _ldap_authenticator and _ldap_authenticator.enabled:
        config = _ldap_authenticator.get_config()
        providers.append({
            "name": "ldap",
            "type": "ldap",
            "enabled": True,
            "description": "LDAP/Active Directory authentication via Basic auth",
            "server": config.server_uri,
        })

    # SAML
    if _saml_authenticator and _saml_authenticator.enabled:
        config = _saml_authenticator.get_config()
        providers.append({
            "name": "saml",
            "type": "saml",
            "enabled": True,
            "description": "SAML 2.0 SSO authentication",
            "login_url": "/v1/auth/saml/login",
            "idp_entity_id": config.idp_entity_id,
        })

    return web.json_response({
        "providers": providers,
        "total": len(providers),
    })


# =============================================================================
# SAML Endpoints
# =============================================================================


async def saml_login(request: "web.Request") -> "web.Response":
    """
    Initiate SAML login flow.

    GET /v1/auth/saml/login

    Query params:
        return_url: URL to redirect to after login (optional)

    Returns:
        Redirect to IdP.
    """
    from aiohttp import web

    if not _saml_authenticator or not _saml_authenticator.enabled:
        return web.json_response(
            {"error": "SAML authentication is not enabled"},
            status=400,
        )

    # Get return URL from query params
    return_url = request.query.get("return_url", "/")

    # Create authentication request
    redirect_url, request_id = _saml_authenticator.create_authn_request(
        relay_state=return_url
    )

    logger.info(f"SAML login initiated, request_id={request_id}")

    # Redirect to IdP
    raise web.HTTPFound(location=redirect_url)


async def saml_acs(request: "web.Request") -> "web.Response":
    """
    SAML Assertion Consumer Service (ACS) endpoint.

    POST /v1/auth/saml/acs

    Body (form-encoded):
        SAMLResponse: Base64-encoded SAML response
        RelayState: Optional return URL

    Returns:
        Redirect with session cookie on success, error on failure.
    """
    from aiohttp import web

    if not _saml_authenticator or not _saml_authenticator.enabled:
        return web.json_response(
            {"error": "SAML authentication is not enabled"},
            status=400,
        )

    try:
        # Parse form data
        data = await request.post()
        saml_response = data.get("SAMLResponse", "")
        relay_state = data.get("RelayState", "/")

        if not saml_response:
            return web.json_response(
                {"error": "Missing SAMLResponse"},
                status=400,
            )

        # Process the SAML response
        session = _saml_authenticator.process_response(
            saml_response=str(saml_response),
            relay_state=str(relay_state),
        )

        if not session:
            return web.json_response(
                {"error": "SAML authentication failed"},
                status=401,
            )

        logger.info(f"SAML authentication successful for: {session.name_id}")

        # Create redirect response with session cookie
        response = web.HTTPFound(location=str(relay_state))
        response.set_cookie(
            "policybind_saml_session",
            session.session_id,
            httponly=True,
            secure=request.secure,
            samesite="Lax",
            max_age=_saml_authenticator.get_config().session_ttl_seconds,
        )

        raise response

    except web.HTTPFound:
        raise
    except Exception as e:
        logger.error(f"SAML ACS error: {e}")
        return web.json_response(
            {"error": "Failed to process SAML response"},
            status=500,
        )


async def saml_logout(request: "web.Request") -> "web.Response":
    """
    SAML logout endpoint.

    POST /v1/auth/saml/logout

    Returns:
        Success message and clears session.
    """
    from aiohttp import web

    if not _saml_authenticator or not _saml_authenticator.enabled:
        return web.json_response(
            {"error": "SAML authentication is not enabled"},
            status=400,
        )

    # Get session ID from cookie
    session_id = request.cookies.get("policybind_saml_session")

    if session_id:
        # Delete session
        _saml_authenticator.delete_session(session_id)
        logger.info(f"SAML session logged out: {session_id}")

    # Clear cookie
    response = web.json_response({"message": "Logged out successfully"})
    response.del_cookie("policybind_saml_session")

    return response


async def saml_metadata(request: "web.Request") -> "web.Response":
    """
    Get SAML SP metadata.

    GET /v1/auth/saml/metadata

    Returns:
        SP metadata XML.
    """
    from aiohttp import web

    if not _saml_authenticator or not _saml_authenticator.enabled:
        return web.json_response(
            {"error": "SAML authentication is not enabled"},
            status=400,
        )

    metadata = _saml_authenticator.get_sp_metadata()

    return web.Response(
        text=metadata,
        content_type="application/xml",
    )


async def saml_session(request: "web.Request") -> "web.Response":
    """
    Get current SAML session information.

    GET /v1/auth/saml/session

    Returns:
        Session information if authenticated via SAML.
    """
    from aiohttp import web

    if not _saml_authenticator or not _saml_authenticator.enabled:
        return web.json_response(
            {"error": "SAML authentication is not enabled"},
            status=400,
        )

    # Get session ID from cookie or header
    session_id = request.cookies.get("policybind_saml_session")
    if not session_id:
        session_id = request.headers.get("X-SAML-Session")

    if not session_id:
        return web.json_response(
            {"error": "No SAML session found"},
            status=401,
        )

    session = _saml_authenticator.get_session(session_id)
    if not session:
        return web.json_response(
            {"error": "SAML session not found or expired"},
            status=401,
        )

    return web.json_response({
        "session_id": session.session_id,
        "name_id": session.name_id,
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
        "attributes": {
            k: v for k, v in session.attributes.items()
            if not k.startswith("http://")  # Simplify attribute names
        },
    })


# =============================================================================
# LDAP Endpoints
# =============================================================================


async def ldap_login(request: "web.Request") -> "web.Response":
    """
    LDAP login endpoint.

    POST /v1/auth/ldap/login

    Body:
        {
            "username": "user",
            "password": "pass"
        }

    Returns:
        Authentication result with user info.
    """
    from aiohttp import web

    if not _ldap_authenticator or not _ldap_authenticator.enabled:
        return web.json_response(
            {"error": "LDAP authentication is not enabled"},
            status=400,
        )

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response(
            {"error": "Invalid JSON body"},
            status=400,
        )

    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return web.json_response(
            {"error": "Username and password are required"},
            status=400,
        )

    # Authenticate
    result = _ldap_authenticator.authenticate_user(username, password)

    if not result.success:
        logger.warning(f"LDAP login failed for: {username}")
        return web.json_response(
            {"error": "Authentication failed", "detail": result.error},
            status=401,
        )

    logger.info(f"LDAP login successful for: {username}")

    # Return user info (but not create a session - use for API key/token exchange)
    return web.json_response({
        "authenticated": True,
        "username": result.user.username if result.user else username,
        "email": result.user.email if result.user else "",
        "display_name": result.user.display_name if result.user else "",
        "groups": result.user.groups if result.user else [],
        "dn": result.user.dn if result.user else "",
    })


async def ldap_status(request: "web.Request") -> "web.Response":
    """
    Get LDAP configuration status.

    GET /v1/auth/ldap/status

    Returns:
        LDAP configuration status (admin only).
    """
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())
    if auth_context.role != Role.ADMIN:
        return web.json_response(
            {"error": "Admin access required"},
            status=403,
        )

    if not _ldap_authenticator:
        return web.json_response({
            "enabled": False,
            "configured": False,
        })

    config = _ldap_authenticator.get_config()

    return web.json_response({
        "enabled": config.enabled,
        "configured": True,
        "config": config.to_dict(),
    })


# =============================================================================
# Admin Endpoints
# =============================================================================


async def auth_config(request: "web.Request") -> "web.Response":
    """
    Get authentication configuration (admin only).

    GET /v1/auth/config

    Returns:
        Current authentication configuration.
    """
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())
    if auth_context.role != Role.ADMIN:
        return web.json_response(
            {"error": "Admin access required"},
            status=403,
        )

    config = {}

    if _ldap_authenticator:
        config["ldap"] = _ldap_authenticator.get_config().to_dict()

    if _saml_authenticator:
        config["saml"] = _saml_authenticator.get_config().to_dict()

    return web.json_response({"config": config})


async def clear_auth_cache(request: "web.Request") -> "web.Response":
    """
    Clear authentication caches (admin only).

    POST /v1/auth/cache/clear

    Returns:
        Success message.
    """
    from aiohttp import web

    auth_context: AuthContext = request.get("auth_context", AuthContext())
    if auth_context.role != Role.ADMIN:
        return web.json_response(
            {"error": "Admin access required"},
            status=403,
        )

    cleared = {}

    if _ldap_authenticator:
        _ldap_authenticator.clear_cache()
        cleared["ldap"] = True

    if _saml_authenticator:
        count = _saml_authenticator.cleanup_expired_sessions()
        cleared["saml_sessions_removed"] = count

    return web.json_response({
        "message": "Authentication caches cleared",
        "cleared": cleared,
    })
