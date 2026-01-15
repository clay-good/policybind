"""
Enterprise authentication providers for PolicyBind.

This module provides LDAP and SAML authentication providers for
enterprise single sign-on (SSO) integration.
"""

import base64
import hashlib
import hmac
import logging
import re
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse

from policybind.models.base import generate_uuid, utc_now
from policybind.server.auth import AuthContext, Role

if TYPE_CHECKING:
    from aiohttp import web

logger = logging.getLogger("policybind.server.auth_providers")


# =============================================================================
# LDAP Authentication
# =============================================================================


class LDAPConnectionState(Enum):
    """LDAP connection states."""

    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    BOUND = "bound"
    ERROR = "error"


@dataclass
class LDAPConfig:
    """
    LDAP authentication configuration.

    Attributes:
        enabled: Whether LDAP authentication is enabled.
        server_uri: LDAP server URI (ldap://host:389 or ldaps://host:636).
        base_dn: Base DN for user searches.
        bind_dn: DN for service account bind (optional, for search).
        bind_password: Password for service account.
        user_search_filter: LDAP filter for finding users ({username} placeholder).
        user_search_base: Base DN for user searches (defaults to base_dn).
        group_search_filter: LDAP filter for finding groups ({username} or {dn} placeholder).
        group_search_base: Base DN for group searches.
        group_attribute: Attribute containing group membership.
        username_attribute: Attribute for username (uid, sAMAccountName, etc.).
        email_attribute: Attribute for email address.
        display_name_attribute: Attribute for display name.
        role_mapping: Mapping of LDAP groups to PolicyBind roles.
        default_role: Role for authenticated users without group mapping.
        timeout_seconds: Connection timeout.
        use_ssl: Use LDAPS (SSL).
        use_tls: Use STARTTLS after connecting.
        validate_cert: Validate server certificate.
        cache_ttl_seconds: Cache authentication results for this duration.
    """

    enabled: bool = False
    server_uri: str = ""
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    user_search_filter: str = "(uid={username})"
    user_search_base: str = ""
    group_search_filter: str = "(memberUid={username})"
    group_search_base: str = ""
    group_attribute: str = "memberOf"
    username_attribute: str = "uid"
    email_attribute: str = "mail"
    display_name_attribute: str = "cn"
    role_mapping: dict[str, str] = field(default_factory=dict)
    default_role: str = "reader"
    timeout_seconds: float = 10.0
    use_ssl: bool = False
    use_tls: bool = True
    validate_cert: bool = True
    cache_ttl_seconds: int = 300

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes sensitive data)."""
        return {
            "enabled": self.enabled,
            "server_uri": self.server_uri,
            "base_dn": self.base_dn,
            "user_search_filter": self.user_search_filter,
            "group_search_filter": self.group_search_filter,
            "username_attribute": self.username_attribute,
            "role_mapping": self.role_mapping,
            "default_role": self.default_role,
            "timeout_seconds": self.timeout_seconds,
            "use_ssl": self.use_ssl,
            "use_tls": self.use_tls,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LDAPConfig":
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", False),
            server_uri=data.get("server_uri", ""),
            base_dn=data.get("base_dn", ""),
            bind_dn=data.get("bind_dn", ""),
            bind_password=data.get("bind_password", ""),
            user_search_filter=data.get("user_search_filter", "(uid={username})"),
            user_search_base=data.get("user_search_base", ""),
            group_search_filter=data.get("group_search_filter", "(memberUid={username})"),
            group_search_base=data.get("group_search_base", ""),
            group_attribute=data.get("group_attribute", "memberOf"),
            username_attribute=data.get("username_attribute", "uid"),
            email_attribute=data.get("email_attribute", "mail"),
            display_name_attribute=data.get("display_name_attribute", "cn"),
            role_mapping=data.get("role_mapping", {}),
            default_role=data.get("default_role", "reader"),
            timeout_seconds=data.get("timeout_seconds", 10.0),
            use_ssl=data.get("use_ssl", False),
            use_tls=data.get("use_tls", True),
            validate_cert=data.get("validate_cert", True),
            cache_ttl_seconds=data.get("cache_ttl_seconds", 300),
        )


@dataclass
class LDAPUser:
    """
    User information from LDAP.

    Attributes:
        dn: Distinguished name.
        username: Username (uid, sAMAccountName).
        email: Email address.
        display_name: Display name.
        groups: List of group DNs or names.
        attributes: Raw LDAP attributes.
    """

    dn: str = ""
    username: str = ""
    email: str = ""
    display_name: str = ""
    groups: list[str] = field(default_factory=list)
    attributes: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class LDAPAuthResult:
    """
    LDAP authentication result.

    Attributes:
        success: Whether authentication succeeded.
        user: User information if successful.
        error: Error message if failed.
        cached: Whether result was from cache.
    """

    success: bool = False
    user: LDAPUser | None = None
    error: str = ""
    cached: bool = False


class LDAPAuthenticator:
    """
    LDAP authentication provider.

    Authenticates users against an LDAP directory (Active Directory,
    OpenLDAP, etc.) and maps LDAP groups to PolicyBind roles.

    Example:
        Setting up LDAP authentication::

            config = LDAPConfig(
                enabled=True,
                server_uri="ldap://ldap.example.com:389",
                base_dn="dc=example,dc=com",
                user_search_filter="(sAMAccountName={username})",
                role_mapping={
                    "cn=admins,ou=groups,dc=example,dc=com": "admin",
                    "cn=operators,ou=groups,dc=example,dc=com": "operator",
                },
            )

            authenticator = LDAPAuthenticator(config)
    """

    def __init__(self, config: LDAPConfig) -> None:
        """
        Initialize the LDAP authenticator.

        Args:
            config: LDAP configuration.
        """
        self._config = config
        self._cache: dict[str, tuple[LDAPAuthResult, datetime]] = {}
        self._ldap_module: Any = None

    @property
    def enabled(self) -> bool:
        """Check if LDAP authentication is enabled."""
        return self._config.enabled

    def get_config(self) -> LDAPConfig:
        """Get the current configuration."""
        return self._config

    def _get_ldap_module(self) -> Any:
        """Get the ldap module, importing on first use."""
        if self._ldap_module is None:
            try:
                import ldap

                self._ldap_module = ldap
            except ImportError as err:
                logger.error(
                    "python-ldap not installed. Install with: pip install python-ldap"
                )
                raise ImportError(
                    "LDAP authentication requires python-ldap. "
                    "Install with: pip install python-ldap"
                ) from err
        return self._ldap_module

    def authenticate(self, request: "web.Request") -> AuthContext:
        """
        Authenticate a request using LDAP.

        Extracts credentials from Basic authentication header and
        validates against the LDAP server.

        Args:
            request: The HTTP request.

        Returns:
            AuthContext with authentication result.
        """
        if not self._config.enabled:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Extract Basic auth credentials
        credentials = self._extract_basic_auth(request)
        if not credentials:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        username, password = credentials

        # Authenticate against LDAP
        result = self.authenticate_user(username, password)

        if not result.success:
            logger.warning(f"LDAP authentication failed for user: {username}")
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Map groups to role
        role = self._map_groups_to_role(result.user.groups if result.user else [])

        return AuthContext(
            authenticated=True,
            role=role,
            identity=username,
            auth_method="ldap",
            metadata={
                "email": result.user.email if result.user else "",
                "display_name": result.user.display_name if result.user else "",
                "groups": result.user.groups if result.user else [],
                "dn": result.user.dn if result.user else "",
                "cached": result.cached,
            },
        )

    def authenticate_user(self, username: str, password: str) -> LDAPAuthResult:
        """
        Authenticate a user against LDAP.

        Args:
            username: The username.
            password: The password.

        Returns:
            LDAPAuthResult with authentication result.
        """
        # Check cache
        cache_key = f"{username}:{hashlib.sha256(password.encode()).hexdigest()}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            ldap = self._get_ldap_module()

            # Connect to LDAP server
            conn = ldap.initialize(self._config.server_uri)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self._config.timeout_seconds)
            conn.set_option(ldap.OPT_REFERRALS, 0)

            if self._config.use_tls and not self._config.use_ssl:
                if not self._config.validate_cert:
                    conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                conn.start_tls_s()

            # Try direct bind first (user DN)
            user_dn = self._find_user_dn(conn, username)

            if not user_dn:
                return LDAPAuthResult(
                    success=False,
                    error=f"User not found: {username}",
                )

            # Bind as the user to verify password
            try:
                conn.simple_bind_s(user_dn, password)
            except ldap.INVALID_CREDENTIALS:
                return LDAPAuthResult(
                    success=False,
                    error="Invalid credentials",
                )

            # Get user attributes
            user = self._get_user_info(conn, user_dn, username)

            conn.unbind_s()

            result = LDAPAuthResult(success=True, user=user)

            # Cache the result
            self._set_cached(cache_key, result)

            return result

        except ImportError:
            return LDAPAuthResult(
                success=False,
                error="LDAP module not available",
            )
        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            return LDAPAuthResult(
                success=False,
                error=str(e),
            )

    def _extract_basic_auth(self, request: "web.Request") -> tuple[str, str] | None:
        """Extract username and password from Basic auth header."""
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Basic "):
            return None

        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode("utf-8")
            parts = decoded.split(":", 1)
            if len(parts) != 2:
                return None
            return (parts[0], parts[1])
        except Exception:
            return None

    def _find_user_dn(self, conn: Any, username: str) -> str | None:
        """Find the user's DN by searching."""
        ldap = self._get_ldap_module()

        # If bind DN is configured, bind as service account first
        if self._config.bind_dn and self._config.bind_password:
            try:
                conn.simple_bind_s(self._config.bind_dn, self._config.bind_password)
            except Exception as e:
                logger.error(f"Service account bind failed: {e}")
                return None

        # Search for the user
        search_base = self._config.user_search_base or self._config.base_dn
        search_filter = self._config.user_search_filter.replace("{username}", username)

        try:
            result = conn.search_s(
                search_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                [self._config.username_attribute],
            )

            if result and len(result) > 0:
                return result[0][0]  # Return the DN

            return None

        except Exception as e:
            logger.error(f"User search failed: {e}")
            return None

    def _get_user_info(self, conn: Any, user_dn: str, username: str) -> LDAPUser:
        """Get user information from LDAP."""
        ldap = self._get_ldap_module()

        user = LDAPUser(dn=user_dn, username=username)

        try:
            # Get user attributes
            result = conn.search_s(
                user_dn,
                ldap.SCOPE_BASE,
                "(objectClass=*)",
                [
                    self._config.email_attribute,
                    self._config.display_name_attribute,
                    self._config.group_attribute,
                ],
            )

            if result and len(result) > 0:
                attrs = result[0][1]

                # Extract email
                if self._config.email_attribute in attrs:
                    values = attrs[self._config.email_attribute]
                    if values:
                        user.email = values[0].decode("utf-8") if isinstance(values[0], bytes) else values[0]

                # Extract display name
                if self._config.display_name_attribute in attrs:
                    values = attrs[self._config.display_name_attribute]
                    if values:
                        user.display_name = values[0].decode("utf-8") if isinstance(values[0], bytes) else values[0]

                # Extract groups from memberOf
                if self._config.group_attribute in attrs:
                    for group in attrs[self._config.group_attribute]:
                        group_str = group.decode("utf-8") if isinstance(group, bytes) else group
                        user.groups.append(group_str)

            # Also search for groups using group filter if configured
            if self._config.group_search_filter and self._config.group_search_base:
                group_filter = self._config.group_search_filter.replace(
                    "{username}", username
                ).replace("{dn}", user_dn)

                try:
                    group_result = conn.search_s(
                        self._config.group_search_base,
                        ldap.SCOPE_SUBTREE,
                        group_filter,
                        ["dn"],
                    )

                    for group_entry in group_result:
                        if group_entry[0] and group_entry[0] not in user.groups:
                            user.groups.append(group_entry[0])

                except Exception as e:
                    logger.warning(f"Group search failed: {e}")

        except Exception as e:
            logger.warning(f"Failed to get user attributes: {e}")

        return user

    def _map_groups_to_role(self, groups: list[str]) -> Role:
        """Map LDAP groups to PolicyBind role."""
        # Check each group against role mapping
        for group in groups:
            # Check exact match
            if group in self._config.role_mapping:
                role_name = self._config.role_mapping[group]
                try:
                    return Role(role_name)
                except ValueError:
                    logger.warning(f"Invalid role in mapping: {role_name}")

            # Check case-insensitive CN match
            group_cn = self._extract_cn(group).lower()
            for mapping_group, role_name in self._config.role_mapping.items():
                mapping_cn = self._extract_cn(mapping_group).lower()
                if group_cn == mapping_cn:
                    try:
                        return Role(role_name)
                    except ValueError:
                        logger.warning(f"Invalid role in mapping: {role_name}")

        # Return default role
        try:
            return Role(self._config.default_role)
        except ValueError:
            return Role.READER

    def _extract_cn(self, dn: str) -> str:
        """Extract CN from a DN string."""
        match = re.match(r"cn=([^,]+)", dn, re.IGNORECASE)
        if match:
            return match.group(1)
        return dn

    def _get_cached(self, cache_key: str) -> LDAPAuthResult | None:
        """Get cached authentication result."""
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if utc_now() - timestamp < timedelta(seconds=self._config.cache_ttl_seconds):
                result.cached = True
                return result
            else:
                del self._cache[cache_key]
        return None

    def _set_cached(self, cache_key: str, result: LDAPAuthResult) -> None:
        """Cache an authentication result."""
        self._cache[cache_key] = (result, utc_now())

    def clear_cache(self) -> None:
        """Clear the authentication cache."""
        self._cache.clear()


# =============================================================================
# SAML Authentication
# =============================================================================


class SAMLBindingType(Enum):
    """SAML binding types."""

    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


@dataclass
class SAMLConfig:
    """
    SAML authentication configuration.

    Attributes:
        enabled: Whether SAML authentication is enabled.
        idp_entity_id: Identity provider entity ID.
        idp_sso_url: IdP SSO URL (for redirects).
        idp_slo_url: IdP SLO URL (for logout).
        idp_cert: IdP certificate (PEM format) for signature validation.
        idp_cert_path: Path to IdP certificate file.
        sp_entity_id: Service provider entity ID.
        sp_acs_url: Assertion Consumer Service URL.
        sp_slo_url: Service provider logout URL.
        sp_cert: SP certificate for signing (optional).
        sp_key: SP private key for signing (optional).
        attribute_mapping: Map SAML attributes to user fields.
        role_attribute: SAML attribute containing roles/groups.
        role_mapping: Map SAML role values to PolicyBind roles.
        default_role: Default role for authenticated users.
        sign_requests: Sign authentication requests.
        want_assertions_signed: Require signed assertions.
        want_response_signed: Require signed responses.
        allow_clock_skew_seconds: Allowed clock skew for time validation.
        session_ttl_seconds: Session duration.
    """

    enabled: bool = False
    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_slo_url: str = ""
    idp_cert: str = ""
    idp_cert_path: str = ""
    sp_entity_id: str = ""
    sp_acs_url: str = ""
    sp_slo_url: str = ""
    sp_cert: str = ""
    sp_key: str = ""
    attribute_mapping: dict[str, str] = field(default_factory=lambda: {
        "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "display_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "username": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
    })
    role_attribute: str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    role_mapping: dict[str, str] = field(default_factory=dict)
    default_role: str = "reader"
    sign_requests: bool = False
    want_assertions_signed: bool = True
    want_response_signed: bool = True
    allow_clock_skew_seconds: int = 120
    session_ttl_seconds: int = 3600

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excludes sensitive data)."""
        return {
            "enabled": self.enabled,
            "idp_entity_id": self.idp_entity_id,
            "idp_sso_url": self.idp_sso_url,
            "sp_entity_id": self.sp_entity_id,
            "sp_acs_url": self.sp_acs_url,
            "attribute_mapping": self.attribute_mapping,
            "role_attribute": self.role_attribute,
            "role_mapping": self.role_mapping,
            "default_role": self.default_role,
            "session_ttl_seconds": self.session_ttl_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SAMLConfig":
        """Create from dictionary."""
        return cls(
            enabled=data.get("enabled", False),
            idp_entity_id=data.get("idp_entity_id", ""),
            idp_sso_url=data.get("idp_sso_url", ""),
            idp_slo_url=data.get("idp_slo_url", ""),
            idp_cert=data.get("idp_cert", ""),
            idp_cert_path=data.get("idp_cert_path", ""),
            sp_entity_id=data.get("sp_entity_id", ""),
            sp_acs_url=data.get("sp_acs_url", ""),
            sp_slo_url=data.get("sp_slo_url", ""),
            sp_cert=data.get("sp_cert", ""),
            sp_key=data.get("sp_key", ""),
            attribute_mapping=data.get("attribute_mapping", {}),
            role_attribute=data.get("role_attribute", ""),
            role_mapping=data.get("role_mapping", {}),
            default_role=data.get("default_role", "reader"),
            sign_requests=data.get("sign_requests", False),
            want_assertions_signed=data.get("want_assertions_signed", True),
            want_response_signed=data.get("want_response_signed", True),
            allow_clock_skew_seconds=data.get("allow_clock_skew_seconds", 120),
            session_ttl_seconds=data.get("session_ttl_seconds", 3600),
        )


@dataclass
class SAMLAssertion:
    """
    Parsed SAML assertion.

    Attributes:
        assertion_id: Unique identifier for the assertion.
        issuer: Entity that issued the assertion.
        subject: Subject (user) identifier.
        attributes: SAML attributes.
        conditions_not_before: Conditions validity start.
        conditions_not_on_or_after: Conditions validity end.
        authn_instant: Authentication timestamp.
        session_index: Session identifier.
        valid: Whether the assertion is valid.
        error: Validation error message.
    """

    assertion_id: str = ""
    issuer: str = ""
    subject: str = ""
    attributes: dict[str, list[str]] = field(default_factory=dict)
    conditions_not_before: datetime | None = None
    conditions_not_on_or_after: datetime | None = None
    authn_instant: datetime | None = None
    session_index: str = ""
    valid: bool = False
    error: str = ""


@dataclass
class SAMLSession:
    """
    SAML session information.

    Attributes:
        session_id: Local session identifier.
        name_id: SAML NameID (user identifier).
        session_index: IdP session index.
        attributes: User attributes from SAML.
        created_at: Session creation time.
        expires_at: Session expiration time.
    """

    session_id: str = field(default_factory=generate_uuid)
    name_id: str = ""
    session_index: str = ""
    attributes: dict[str, list[str]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None


class SAMLAuthenticator:
    """
    SAML 2.0 authentication provider.

    Provides SAML Service Provider (SP) functionality for enterprise
    SSO integration.

    Example:
        Setting up SAML authentication::

            config = SAMLConfig(
                enabled=True,
                idp_entity_id="https://idp.example.com",
                idp_sso_url="https://idp.example.com/sso",
                idp_cert="-----BEGIN CERTIFICATE-----...",
                sp_entity_id="https://policybind.example.com",
                sp_acs_url="https://policybind.example.com/saml/acs",
                role_mapping={
                    "admins": "admin",
                    "operators": "operator",
                },
            )

            authenticator = SAMLAuthenticator(config)
    """

    # SAML namespaces
    SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
    SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

    NAMESPACES = {
        "saml": SAML_NS,
        "samlp": SAMLP_NS,
        "ds": DSIG_NS,
    }

    def __init__(self, config: SAMLConfig) -> None:
        """
        Initialize the SAML authenticator.

        Args:
            config: SAML configuration.
        """
        self._config = config
        self._sessions: dict[str, SAMLSession] = {}
        self._pending_requests: dict[str, datetime] = {}
        self._idp_cert: str | None = None

        # Load IdP certificate
        if config.idp_cert:
            self._idp_cert = config.idp_cert
        elif config.idp_cert_path:
            try:
                with open(config.idp_cert_path, "r") as f:
                    self._idp_cert = f.read()
            except Exception as e:
                logger.error(f"Failed to load IdP certificate: {e}")

    @property
    def enabled(self) -> bool:
        """Check if SAML authentication is enabled."""
        return self._config.enabled

    def get_config(self) -> SAMLConfig:
        """Get the current configuration."""
        return self._config

    def authenticate(self, request: "web.Request") -> AuthContext:
        """
        Authenticate a request using SAML session.

        Checks for existing SAML session via cookie or header.

        Args:
            request: The HTTP request.

        Returns:
            AuthContext with authentication result.
        """
        if not self._config.enabled:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Get session ID from cookie or header
        session_id = self._get_session_id(request)
        if not session_id:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Look up session
        session = self._sessions.get(session_id)
        if not session:
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Check session expiry
        if session.expires_at and utc_now() > session.expires_at:
            del self._sessions[session_id]
            return AuthContext(authenticated=False, role=Role.ANONYMOUS)

        # Map attributes to role
        role = self._map_attributes_to_role(session.attributes)

        # Extract user info from attributes
        username = self._get_attribute(session.attributes, "username") or session.name_id
        email = self._get_attribute(session.attributes, "email") or ""
        display_name = self._get_attribute(session.attributes, "display_name") or ""

        return AuthContext(
            authenticated=True,
            role=role,
            identity=username,
            auth_method="saml",
            metadata={
                "email": email,
                "display_name": display_name,
                "name_id": session.name_id,
                "session_index": session.session_index,
                "session_id": session_id,
            },
        )

    def create_authn_request(self, relay_state: str = "") -> tuple[str, str]:
        """
        Create a SAML authentication request.

        Returns:
            Tuple of (redirect_url, request_id).
        """
        request_id = f"_pb_{generate_uuid()}"
        issue_instant = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build AuthnRequest XML
        authn_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="{self.SAMLP_NS}"
    xmlns:saml="{self.SAML_NS}"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self._config.idp_sso_url}"
    AssertionConsumerServiceURL="{self._config.sp_acs_url}"
    ProtocolBinding="{SAMLBindingType.HTTP_POST.value}">
    <saml:Issuer>{self._config.sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"""

        # Store pending request
        self._pending_requests[request_id] = utc_now()

        # Compress and encode for redirect binding
        compressed = zlib.compress(authn_request.encode("utf-8"))[2:-4]
        encoded = base64.b64encode(compressed).decode("utf-8")

        # Build redirect URL
        params = {"SAMLRequest": encoded}
        if relay_state:
            params["RelayState"] = relay_state

        redirect_url = f"{self._config.idp_sso_url}?{urlencode(params)}"

        return redirect_url, request_id

    def process_response(self, saml_response: str, relay_state: str = "") -> SAMLSession | None:
        """
        Process a SAML response from the IdP.

        Args:
            saml_response: Base64-encoded SAML response.
            relay_state: Optional relay state.

        Returns:
            SAMLSession if successful, None otherwise.
        """
        try:
            # Decode response
            decoded = base64.b64decode(saml_response)
            response_xml = decoded.decode("utf-8")

            # Parse and validate
            assertion = self._parse_response(response_xml)

            if not assertion.valid:
                logger.warning(f"SAML assertion validation failed: {assertion.error}")
                return None

            # Create session
            session = SAMLSession(
                name_id=assertion.subject,
                session_index=assertion.session_index,
                attributes=assertion.attributes,
                expires_at=utc_now() + timedelta(seconds=self._config.session_ttl_seconds),
            )

            self._sessions[session.session_id] = session
            logger.info(f"SAML session created for: {assertion.subject}")

            return session

        except Exception as e:
            logger.error(f"Failed to process SAML response: {e}")
            return None

    def _parse_response(self, response_xml: str) -> SAMLAssertion:
        """Parse and validate SAML response."""
        assertion = SAMLAssertion()

        try:
            root = ET.fromstring(response_xml)

            # Check response status
            status = root.find(".//samlp:StatusCode", self.NAMESPACES)
            if status is not None:
                status_value = status.get("Value", "")
                if "Success" not in status_value:
                    assertion.error = f"SAML status: {status_value}"
                    return assertion

            # Find assertion
            assertion_elem = root.find(".//saml:Assertion", self.NAMESPACES)
            if assertion_elem is None:
                assertion.error = "No assertion found in response"
                return assertion

            # Get assertion ID
            assertion.assertion_id = assertion_elem.get("ID", "")

            # Get issuer
            issuer_elem = assertion_elem.find("saml:Issuer", self.NAMESPACES)
            if issuer_elem is not None and issuer_elem.text:
                assertion.issuer = issuer_elem.text

            # Get subject
            name_id = assertion_elem.find(".//saml:NameID", self.NAMESPACES)
            if name_id is not None and name_id.text:
                assertion.subject = name_id.text

            # Get conditions
            conditions = assertion_elem.find("saml:Conditions", self.NAMESPACES)
            if conditions is not None:
                not_before = conditions.get("NotBefore")
                not_on_or_after = conditions.get("NotOnOrAfter")

                if not_before:
                    assertion.conditions_not_before = self._parse_saml_datetime(not_before)
                if not_on_or_after:
                    assertion.conditions_not_on_or_after = self._parse_saml_datetime(not_on_or_after)

            # Get session index
            authn_statement = assertion_elem.find("saml:AuthnStatement", self.NAMESPACES)
            if authn_statement is not None:
                assertion.session_index = authn_statement.get("SessionIndex", "")
                authn_instant = authn_statement.get("AuthnInstant")
                if authn_instant:
                    assertion.authn_instant = self._parse_saml_datetime(authn_instant)

            # Get attributes
            attr_statement = assertion_elem.find("saml:AttributeStatement", self.NAMESPACES)
            if attr_statement is not None:
                for attr in attr_statement.findall("saml:Attribute", self.NAMESPACES):
                    attr_name = attr.get("Name", "")
                    values = []
                    for value_elem in attr.findall("saml:AttributeValue", self.NAMESPACES):
                        if value_elem.text:
                            values.append(value_elem.text)
                    if attr_name:
                        assertion.attributes[attr_name] = values

            # Validate time conditions
            now = utc_now()
            skew = timedelta(seconds=self._config.allow_clock_skew_seconds)

            if assertion.conditions_not_before:
                if now < assertion.conditions_not_before - skew:
                    assertion.error = "Assertion not yet valid"
                    return assertion

            if assertion.conditions_not_on_or_after:
                if now > assertion.conditions_not_on_or_after + skew:
                    assertion.error = "Assertion has expired"
                    return assertion

            # Validate issuer
            if assertion.issuer != self._config.idp_entity_id:
                assertion.error = f"Invalid issuer: {assertion.issuer}"
                return assertion

            assertion.valid = True
            return assertion

        except ET.ParseError as e:
            assertion.error = f"XML parse error: {e}"
            return assertion
        except Exception as e:
            assertion.error = f"Parse error: {e}"
            return assertion

    def _parse_saml_datetime(self, dt_str: str) -> datetime:
        """Parse SAML datetime string (returns timezone-aware UTC datetime)."""
        from datetime import timezone

        # Handle both formats: with and without fractional seconds
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ]
        for fmt in formats:
            try:
                naive_dt = datetime.strptime(dt_str, fmt)
                # Make timezone-aware (SAML Z suffix means UTC)
                return naive_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        raise ValueError(f"Unable to parse datetime: {dt_str}")

    def _get_session_id(self, request: "web.Request") -> str | None:
        """Get session ID from request."""
        # Try cookie first
        session_id = request.cookies.get("policybind_saml_session")
        if session_id:
            return session_id

        # Try header
        return request.headers.get("X-SAML-Session")

    def _map_attributes_to_role(self, attributes: dict[str, list[str]]) -> Role:
        """Map SAML attributes to PolicyBind role."""
        # Get role/group values
        role_values = attributes.get(self._config.role_attribute, [])

        # Check each value against role mapping
        for value in role_values:
            if value in self._config.role_mapping:
                role_name = self._config.role_mapping[value]
                try:
                    return Role(role_name)
                except ValueError:
                    logger.warning(f"Invalid role in mapping: {role_name}")

            # Also check lowercase
            value_lower = value.lower()
            for mapping_key, role_name in self._config.role_mapping.items():
                if mapping_key.lower() == value_lower:
                    try:
                        return Role(role_name)
                    except ValueError:
                        logger.warning(f"Invalid role in mapping: {role_name}")

        # Return default role
        try:
            return Role(self._config.default_role)
        except ValueError:
            return Role.READER

    def _get_attribute(self, attributes: dict[str, list[str]], field: str) -> str | None:
        """Get a user attribute using the attribute mapping."""
        attr_name = self._config.attribute_mapping.get(field)
        if attr_name and attr_name in attributes:
            values = attributes[attr_name]
            if values:
                return values[0]
        return None

    def get_session(self, session_id: str) -> SAMLSession | None:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions. Returns count removed."""
        now = utc_now()
        expired = [
            sid for sid, session in self._sessions.items()
            if session.expires_at and now > session.expires_at
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def get_sp_metadata(self) -> str:
        """
        Generate SP metadata XML.

        Returns:
            SP metadata XML string.
        """
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{self._config.sp_entity_id}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="{str(self._config.sign_requests).lower()}"
        WantAssertionsSigned="{str(self._config.want_assertions_signed).lower()}"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="{SAMLBindingType.HTTP_POST.value}"
            Location="{self._config.sp_acs_url}"
            index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""
