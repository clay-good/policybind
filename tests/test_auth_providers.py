"""
Tests for PolicyBind LDAP and SAML authentication providers.
"""

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from policybind.server.auth import AuthContext, Role
from policybind.server.auth_providers import (
    LDAPAuthenticator,
    LDAPAuthResult,
    LDAPConfig,
    LDAPUser,
    SAMLAssertion,
    SAMLAuthenticator,
    SAMLBindingType,
    SAMLConfig,
    SAMLSession,
)
from policybind.models.base import utc_now


class TestLDAPConfig:
    """Tests for LDAPConfig dataclass."""

    def test_default_config(self):
        """Test default config values."""
        config = LDAPConfig()

        assert config.enabled is False
        assert config.server_uri == ""
        assert config.base_dn == ""
        assert config.user_search_filter == "(uid={username})"
        assert config.default_role == "reader"
        assert config.use_tls is True
        assert config.cache_ttl_seconds == 300

    def test_custom_config(self):
        """Test custom config values."""
        config = LDAPConfig(
            enabled=True,
            server_uri="ldap://ldap.example.com:389",
            base_dn="dc=example,dc=com",
            user_search_filter="(sAMAccountName={username})",
            role_mapping={"cn=admins,dc=example,dc=com": "admin"},
        )

        assert config.enabled is True
        assert config.server_uri == "ldap://ldap.example.com:389"
        assert config.base_dn == "dc=example,dc=com"
        assert "admins" in str(config.role_mapping)

    def test_to_dict(self):
        """Test converting to dictionary."""
        config = LDAPConfig(
            enabled=True,
            server_uri="ldap://localhost:389",
            bind_password="secret",
        )

        result = config.to_dict()
        assert result["enabled"] is True
        assert result["server_uri"] == "ldap://localhost:389"
        assert "bind_password" not in result  # Sensitive data excluded

    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "enabled": True,
            "server_uri": "ldaps://ldap.example.com:636",
            "base_dn": "dc=example,dc=com",
            "role_mapping": {"admins": "admin"},
        }

        config = LDAPConfig.from_dict(data)
        assert config.enabled is True
        assert config.server_uri == "ldaps://ldap.example.com:636"
        assert config.role_mapping == {"admins": "admin"}


class TestLDAPUser:
    """Tests for LDAPUser dataclass."""

    def test_create_user(self):
        """Test creating an LDAP user."""
        user = LDAPUser(
            dn="cn=john,ou=users,dc=example,dc=com",
            username="john",
            email="john@example.com",
            display_name="John Doe",
            groups=["cn=developers,dc=example,dc=com"],
        )

        assert user.dn == "cn=john,ou=users,dc=example,dc=com"
        assert user.username == "john"
        assert user.email == "john@example.com"
        assert user.display_name == "John Doe"
        assert len(user.groups) == 1


class TestLDAPAuthResult:
    """Tests for LDAPAuthResult dataclass."""

    def test_success_result(self):
        """Test successful auth result."""
        user = LDAPUser(username="john")
        result = LDAPAuthResult(success=True, user=user)

        assert result.success is True
        assert result.user is not None
        assert result.error == ""

    def test_failure_result(self):
        """Test failed auth result."""
        result = LDAPAuthResult(success=False, error="Invalid credentials")

        assert result.success is False
        assert result.user is None
        assert result.error == "Invalid credentials"


class TestLDAPAuthenticator:
    """Tests for LDAPAuthenticator class."""

    @pytest.fixture
    def config(self):
        """Create a test LDAP config."""
        return LDAPConfig(
            enabled=True,
            server_uri="ldap://ldap.example.com:389",
            base_dn="dc=example,dc=com",
            user_search_filter="(uid={username})",
            role_mapping={
                "cn=admins,ou=groups,dc=example,dc=com": "admin",
                "cn=operators,ou=groups,dc=example,dc=com": "operator",
            },
            default_role="reader",
        )

    @pytest.fixture
    def authenticator(self, config):
        """Create an LDAP authenticator."""
        return LDAPAuthenticator(config)

    def test_create_authenticator(self, authenticator, config):
        """Test creating an authenticator."""
        assert authenticator.enabled is True
        assert authenticator.get_config() == config

    def test_authenticator_disabled(self):
        """Test authenticator when disabled."""
        config = LDAPConfig(enabled=False)
        authenticator = LDAPAuthenticator(config)

        request = MagicMock()
        result = authenticator.authenticate(request)

        assert result.authenticated is False
        assert result.role == Role.ANONYMOUS

    def test_extract_basic_auth(self, authenticator):
        """Test extracting Basic auth credentials."""
        request = MagicMock()

        # Valid Basic auth
        credentials = base64.b64encode(b"john:password123").decode()
        request.headers.get.return_value = f"Basic {credentials}"

        result = authenticator._extract_basic_auth(request)
        assert result == ("john", "password123")

    def test_extract_basic_auth_missing(self, authenticator):
        """Test missing Basic auth header."""
        request = MagicMock()
        request.headers.get.return_value = ""

        result = authenticator._extract_basic_auth(request)
        assert result is None

    def test_extract_basic_auth_invalid(self, authenticator):
        """Test invalid Basic auth format."""
        request = MagicMock()
        request.headers.get.return_value = "Bearer token123"

        result = authenticator._extract_basic_auth(request)
        assert result is None

    def test_map_groups_to_role_admin(self, authenticator):
        """Test mapping admin group to role."""
        groups = ["cn=admins,ou=groups,dc=example,dc=com"]
        role = authenticator._map_groups_to_role(groups)
        assert role == Role.ADMIN

    def test_map_groups_to_role_operator(self, authenticator):
        """Test mapping operator group to role."""
        groups = ["cn=operators,ou=groups,dc=example,dc=com"]
        role = authenticator._map_groups_to_role(groups)
        assert role == Role.OPERATOR

    def test_map_groups_to_role_default(self, authenticator):
        """Test mapping to default role."""
        groups = ["cn=users,ou=groups,dc=example,dc=com"]
        role = authenticator._map_groups_to_role(groups)
        assert role == Role.READER

    def test_map_groups_case_insensitive(self, authenticator):
        """Test case-insensitive CN matching."""
        groups = ["CN=ADMINS,OU=groups,DC=example,DC=com"]
        role = authenticator._map_groups_to_role(groups)
        assert role == Role.ADMIN

    def test_extract_cn(self, authenticator):
        """Test extracting CN from DN."""
        dn = "cn=admins,ou=groups,dc=example,dc=com"
        cn = authenticator._extract_cn(dn)
        assert cn == "admins"

    def test_cache(self, authenticator):
        """Test authentication caching."""
        result = LDAPAuthResult(
            success=True,
            user=LDAPUser(username="john"),
        )

        cache_key = "test_key"
        authenticator._set_cached(cache_key, result)

        cached = authenticator._get_cached(cache_key)
        assert cached is not None
        assert cached.success is True
        assert cached.cached is True

    def test_clear_cache(self, authenticator):
        """Test clearing cache."""
        result = LDAPAuthResult(success=True)
        authenticator._set_cached("test", result)

        authenticator.clear_cache()
        assert authenticator._get_cached("test") is None


class TestSAMLConfig:
    """Tests for SAMLConfig dataclass."""

    def test_default_config(self):
        """Test default config values."""
        config = SAMLConfig()

        assert config.enabled is False
        assert config.idp_entity_id == ""
        assert config.sp_entity_id == ""
        assert config.default_role == "reader"
        assert config.session_ttl_seconds == 3600
        assert config.allow_clock_skew_seconds == 120

    def test_custom_config(self):
        """Test custom config values."""
        config = SAMLConfig(
            enabled=True,
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            sp_entity_id="https://policybind.example.com",
            sp_acs_url="https://policybind.example.com/saml/acs",
            role_mapping={"admins": "admin"},
        )

        assert config.enabled is True
        assert config.idp_entity_id == "https://idp.example.com"
        assert config.role_mapping == {"admins": "admin"}

    def test_to_dict(self):
        """Test converting to dictionary."""
        config = SAMLConfig(
            enabled=True,
            idp_entity_id="https://idp.example.com",
            sp_key="-----BEGIN PRIVATE KEY-----...",  # Sensitive
        )

        result = config.to_dict()
        assert result["enabled"] is True
        assert result["idp_entity_id"] == "https://idp.example.com"
        # Sensitive fields should not be in the result
        assert "sp_key" not in result

    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "enabled": True,
            "idp_entity_id": "https://idp.example.com",
            "idp_sso_url": "https://idp.example.com/sso",
            "sp_entity_id": "https://policybind.example.com",
            "role_mapping": {"admins": "admin", "operators": "operator"},
        }

        config = SAMLConfig.from_dict(data)
        assert config.enabled is True
        assert config.idp_entity_id == "https://idp.example.com"
        assert config.role_mapping["admins"] == "admin"


class TestSAMLAssertion:
    """Tests for SAMLAssertion dataclass."""

    def test_create_assertion(self):
        """Test creating a SAML assertion."""
        assertion = SAMLAssertion(
            assertion_id="_abc123",
            issuer="https://idp.example.com",
            subject="john@example.com",
            valid=True,
        )

        assert assertion.assertion_id == "_abc123"
        assert assertion.issuer == "https://idp.example.com"
        assert assertion.subject == "john@example.com"
        assert assertion.valid is True

    def test_invalid_assertion(self):
        """Test invalid assertion."""
        assertion = SAMLAssertion(
            valid=False,
            error="Assertion has expired",
        )

        assert assertion.valid is False
        assert "expired" in assertion.error


class TestSAMLSession:
    """Tests for SAMLSession dataclass."""

    def test_create_session(self):
        """Test creating a SAML session."""
        session = SAMLSession(
            name_id="john@example.com",
            session_index="_session123",
            attributes={"email": ["john@example.com"]},
        )

        assert session.session_id is not None
        assert session.name_id == "john@example.com"
        assert session.session_index == "_session123"
        assert session.created_at is not None


class TestSAMLAuthenticator:
    """Tests for SAMLAuthenticator class."""

    @pytest.fixture
    def config(self):
        """Create a test SAML config."""
        return SAMLConfig(
            enabled=True,
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            sp_entity_id="https://policybind.example.com",
            sp_acs_url="https://policybind.example.com/v1/auth/saml/acs",
            role_mapping={
                "admins": "admin",
                "operators": "operator",
            },
            role_attribute="groups",
            default_role="reader",
        )

    @pytest.fixture
    def authenticator(self, config):
        """Create a SAML authenticator."""
        return SAMLAuthenticator(config)

    def test_create_authenticator(self, authenticator, config):
        """Test creating an authenticator."""
        assert authenticator.enabled is True
        assert authenticator.get_config() == config

    def test_authenticator_disabled(self):
        """Test authenticator when disabled."""
        config = SAMLConfig(enabled=False)
        authenticator = SAMLAuthenticator(config)

        request = MagicMock()
        result = authenticator.authenticate(request)

        assert result.authenticated is False
        assert result.role == Role.ANONYMOUS

    def test_create_authn_request(self, authenticator):
        """Test creating authentication request."""
        redirect_url, request_id = authenticator.create_authn_request(
            relay_state="/dashboard"
        )

        assert redirect_url.startswith("https://idp.example.com/sso")
        assert "SAMLRequest=" in redirect_url
        assert request_id.startswith("_pb_")

    def test_create_authn_request_with_relay_state(self, authenticator):
        """Test authentication request with relay state."""
        redirect_url, _ = authenticator.create_authn_request(relay_state="/my-page")

        assert "RelayState=" in redirect_url

    def test_get_sp_metadata(self, authenticator):
        """Test generating SP metadata."""
        metadata = authenticator.get_sp_metadata()

        assert "<?xml version" in metadata
        assert "EntityDescriptor" in metadata
        assert "https://policybind.example.com" in metadata
        assert "SPSSODescriptor" in metadata
        assert "AssertionConsumerService" in metadata

    def test_map_attributes_to_role_admin(self, authenticator):
        """Test mapping admin group to role."""
        attributes = {"groups": ["admins"]}
        role = authenticator._map_attributes_to_role(attributes)
        assert role == Role.ADMIN

    def test_map_attributes_to_role_operator(self, authenticator):
        """Test mapping operator group to role."""
        attributes = {"groups": ["operators"]}
        role = authenticator._map_attributes_to_role(attributes)
        assert role == Role.OPERATOR

    def test_map_attributes_to_role_default(self, authenticator):
        """Test mapping to default role."""
        attributes = {"groups": ["users"]}
        role = authenticator._map_attributes_to_role(attributes)
        assert role == Role.READER

    def test_map_attributes_case_insensitive(self, authenticator):
        """Test case-insensitive role matching."""
        attributes = {"groups": ["ADMINS"]}
        role = authenticator._map_attributes_to_role(attributes)
        assert role == Role.ADMIN

    def test_session_management(self, authenticator):
        """Test session CRUD operations."""
        # Create session
        session = SAMLSession(
            name_id="john@example.com",
            expires_at=utc_now() + timedelta(hours=1),
        )
        authenticator._sessions[session.session_id] = session

        # Get session
        retrieved = authenticator.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.name_id == "john@example.com"

        # Delete session
        result = authenticator.delete_session(session.session_id)
        assert result is True

        # Session should be gone
        assert authenticator.get_session(session.session_id) is None

    def test_cleanup_expired_sessions(self, authenticator):
        """Test cleaning up expired sessions."""
        # Create expired session
        expired_session = SAMLSession(
            name_id="expired@example.com",
            expires_at=utc_now() - timedelta(hours=1),
        )
        authenticator._sessions[expired_session.session_id] = expired_session

        # Create valid session
        valid_session = SAMLSession(
            name_id="valid@example.com",
            expires_at=utc_now() + timedelta(hours=1),
        )
        authenticator._sessions[valid_session.session_id] = valid_session

        # Cleanup
        count = authenticator.cleanup_expired_sessions()
        assert count == 1
        assert len(authenticator._sessions) == 1
        assert valid_session.session_id in authenticator._sessions

    def test_get_session_id_from_cookie(self, authenticator):
        """Test getting session ID from cookie."""
        request = MagicMock()
        request.cookies.get.return_value = "session_123"

        session_id = authenticator._get_session_id(request)
        assert session_id == "session_123"

    def test_get_session_id_from_header(self, authenticator):
        """Test getting session ID from header."""
        request = MagicMock()
        request.cookies.get.return_value = None
        request.headers.get.return_value = "session_456"

        session_id = authenticator._get_session_id(request)
        assert session_id == "session_456"

    def test_authenticate_with_valid_session(self, authenticator):
        """Test authentication with valid session."""
        # Create a session
        session = SAMLSession(
            name_id="john@example.com",
            attributes={"groups": ["admins"]},
            expires_at=utc_now() + timedelta(hours=1),
        )
        authenticator._sessions[session.session_id] = session

        # Mock request with session cookie
        request = MagicMock()
        request.cookies.get.return_value = session.session_id

        result = authenticator.authenticate(request)

        assert result.authenticated is True
        assert result.role == Role.ADMIN
        assert result.auth_method == "saml"

    def test_authenticate_with_expired_session(self, authenticator):
        """Test authentication with expired session."""
        # Create expired session
        session = SAMLSession(
            name_id="john@example.com",
            expires_at=utc_now() - timedelta(hours=1),
        )
        authenticator._sessions[session.session_id] = session

        # Mock request
        request = MagicMock()
        request.cookies.get.return_value = session.session_id

        result = authenticator.authenticate(request)

        assert result.authenticated is False
        assert result.role == Role.ANONYMOUS

    def test_parse_saml_datetime(self, authenticator):
        """Test parsing SAML datetime strings."""
        # Format without fractional seconds
        dt1 = authenticator._parse_saml_datetime("2024-01-15T10:30:00Z")
        assert dt1.year == 2024
        assert dt1.month == 1
        assert dt1.day == 15

        # Format with fractional seconds
        dt2 = authenticator._parse_saml_datetime("2024-01-15T10:30:00.123Z")
        assert dt2.year == 2024


class TestAuthenticatorIntegration:
    """Integration tests for authenticators."""

    def test_ldap_to_auth_context(self):
        """Test LDAP authentication returns proper AuthContext."""
        config = LDAPConfig(
            enabled=True,
            server_uri="ldap://localhost:389",
            base_dn="dc=example,dc=com",
            role_mapping={"cn=admins,dc=example,dc=com": "admin"},
        )
        authenticator = LDAPAuthenticator(config)

        # Mock successful LDAP response
        with patch.object(authenticator, "authenticate_user") as mock_auth:
            mock_auth.return_value = LDAPAuthResult(
                success=True,
                user=LDAPUser(
                    dn="cn=john,dc=example,dc=com",
                    username="john",
                    email="john@example.com",
                    display_name="John Doe",
                    groups=["cn=admins,dc=example,dc=com"],
                ),
            )

            request = MagicMock()
            credentials = base64.b64encode(b"john:password").decode()
            request.headers.get.return_value = f"Basic {credentials}"

            result = authenticator.authenticate(request)

            assert result.authenticated is True
            assert result.role == Role.ADMIN
            assert result.identity == "john"
            assert result.auth_method == "ldap"
            assert result.metadata["email"] == "john@example.com"

    def test_saml_session_to_auth_context(self):
        """Test SAML session returns proper AuthContext."""
        config = SAMLConfig(
            enabled=True,
            idp_entity_id="https://idp.example.com",
            sp_entity_id="https://policybind.example.com",
            sp_acs_url="https://policybind.example.com/saml/acs",
            role_attribute="groups",
            role_mapping={"operators": "operator"},
            attribute_mapping={
                "email": "email",
                "display_name": "name",
                "username": "upn",
            },
        )
        authenticator = SAMLAuthenticator(config)

        # Create session
        session = SAMLSession(
            name_id="john@example.com",
            attributes={
                "groups": ["operators"],
                "email": ["john@example.com"],
                "name": ["John Doe"],
                "upn": ["john"],
            },
            expires_at=utc_now() + timedelta(hours=1),
        )
        authenticator._sessions[session.session_id] = session

        # Mock request
        request = MagicMock()
        request.cookies.get.return_value = session.session_id

        result = authenticator.authenticate(request)

        assert result.authenticated is True
        assert result.role == Role.OPERATOR
        assert result.auth_method == "saml"
        assert result.metadata["email"] == "john@example.com"
        assert result.metadata["display_name"] == "John Doe"


class TestSAMLResponseParsing:
    """Tests for SAML response parsing."""

    @pytest.fixture
    def authenticator(self):
        """Create a SAML authenticator."""
        config = SAMLConfig(
            enabled=True,
            idp_entity_id="https://idp.example.com",
            sp_entity_id="https://policybind.example.com",
            sp_acs_url="https://policybind.example.com/saml/acs",
        )
        return SAMLAuthenticator(config)

    def test_parse_valid_response(self, authenticator):
        """Test parsing a valid SAML response."""
        # Minimal valid SAML response XML
        now = datetime.now(timezone.utc)
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_on_or_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

        response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response123"
                Version="2.0">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assertion456" Version="2.0">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID>john@example.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}"/>
        <saml:AuthnStatement SessionIndex="_session789"/>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>john@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">
                <saml:AttributeValue>admins</saml:AttributeValue>
                <saml:AttributeValue>developers</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"""

        assertion = authenticator._parse_response(response_xml)

        assert assertion.valid is True
        assert assertion.assertion_id == "_assertion456"
        assert assertion.issuer == "https://idp.example.com"
        assert assertion.subject == "john@example.com"
        assert assertion.session_index == "_session789"
        assert "email" in assertion.attributes
        assert assertion.attributes["email"] == ["john@example.com"]
        assert "groups" in assertion.attributes
        assert len(assertion.attributes["groups"]) == 2

    def test_parse_failed_status(self, authenticator):
        """Test parsing response with failed status."""
        response_xml = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
    </samlp:Status>
</samlp:Response>"""

        assertion = authenticator._parse_response(response_xml)

        assert assertion.valid is False
        assert "Requester" in assertion.error

    def test_parse_expired_assertion(self, authenticator):
        """Test parsing expired assertion."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

        response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assertion">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID>john@example.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotOnOrAfter="{past}"/>
    </saml:Assertion>
</samlp:Response>"""

        assertion = authenticator._parse_response(response_xml)

        assert assertion.valid is False
        assert "expired" in assertion.error

    def test_parse_wrong_issuer(self, authenticator):
        """Test parsing assertion with wrong issuer."""
        now = datetime.now(timezone.utc)
        not_on_or_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

        response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assertion">
        <saml:Issuer>https://wrong-idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID>john@example.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotOnOrAfter="{not_on_or_after}"/>
    </saml:Assertion>
</samlp:Response>"""

        assertion = authenticator._parse_response(response_xml)

        assert assertion.valid is False
        assert "issuer" in assertion.error.lower()
