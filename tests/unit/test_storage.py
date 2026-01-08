"""
Unit tests for PolicyBind storage layer.

This module tests database operations, repositories, and data persistence
using in-memory SQLite databases.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from policybind.models.base import generate_uuid, utc_now
from policybind.storage.database import Database
from policybind.storage.repositories import (
    AuditRepository,
    IncidentRepository,
    PolicyRepository,
    RegistryRepository,
    TokenRepository,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def db() -> Database:
    """Create an in-memory database for testing."""
    database = Database(":memory:")
    database.initialize()
    return database


@pytest.fixture
def policy_repo(db: Database) -> PolicyRepository:
    """Create a policy repository."""
    return PolicyRepository(db)


@pytest.fixture
def registry_repo(db: Database) -> RegistryRepository:
    """Create a registry repository."""
    return RegistryRepository(db)


@pytest.fixture
def audit_repo(db: Database) -> AuditRepository:
    """Create an audit repository."""
    return AuditRepository(db)


@pytest.fixture
def token_repo(db: Database) -> TokenRepository:
    """Create a token repository."""
    return TokenRepository(db)


@pytest.fixture
def incident_repo(db: Database) -> IncidentRepository:
    """Create an incident repository."""
    return IncidentRepository(db)


# =============================================================================
# Database Tests
# =============================================================================


class TestDatabase:
    """Tests for Database class."""

    def test_create_in_memory(self) -> None:
        """Test creating an in-memory database."""
        db = Database(":memory:")
        assert db.path == ":memory:"

    def test_initialize(self) -> None:
        """Test database initialization."""
        db = Database(":memory:")
        db.initialize()
        assert db._initialized is True

    def test_connection_context_manager(self, db: Database) -> None:
        """Test using connection as context manager."""
        with db.connection() as conn:
            cursor = conn.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1

    def test_execute(self, db: Database) -> None:
        """Test execute method."""
        results = db.execute("SELECT 1 as value")
        assert len(results) == 1
        assert results[0]["value"] == 1

    def test_execute_one(self, db: Database) -> None:
        """Test execute_one method."""
        result = db.execute_one("SELECT 1 as value")
        assert result is not None
        assert result["value"] == 1

    def test_execute_one_no_result(self, db: Database) -> None:
        """Test execute_one with no results."""
        result = db.execute_one(
            "SELECT * FROM policies WHERE id = ?",
            ("nonexistent",),
        )
        assert result is None

    def test_execute_insert(self, db: Database) -> None:
        """Test execute_insert method."""
        db.execute_insert(
            """
            INSERT INTO policies (id, name, version, content, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("test-id", "test", "1.0.0", "{}", 1, utc_now().isoformat(), utc_now().isoformat()),
        )

        result = db.execute_one("SELECT * FROM policies WHERE id = ?", ("test-id",))
        assert result is not None

    def test_execute_write(self, db: Database) -> None:
        """Test execute_write method."""
        # First insert a record
        db.execute_insert(
            """
            INSERT INTO policies (id, name, version, content, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("test-id", "test", "1.0.0", "{}", 1, utc_now().isoformat(), utc_now().isoformat()),
        )

        # Then update it
        rows = db.execute_write(
            "UPDATE policies SET version = ? WHERE id = ?",
            ("2.0.0", "test-id"),
        )

        assert rows == 1

    def test_close(self, db: Database) -> None:
        """Test closing database connections."""
        # Add a connection to the pool
        conn = db._get_connection()
        db._return_connection(conn)

        assert len(db._pool) == 1

        db.close()

        assert len(db._pool) == 0


# =============================================================================
# PolicyRepository Tests
# =============================================================================


class TestPolicyRepository:
    """Tests for PolicyRepository class."""

    def test_create_policy(self, policy_repo: PolicyRepository) -> None:
        """Test creating a policy."""
        policy_id = policy_repo.create(
            name="test-policy",
            version="1.0.0",
            content={"rules": []},
            description="Test policy",
            created_by="admin",
        )

        assert policy_id is not None
        assert len(policy_id) > 0

    def test_get_by_id(self, policy_repo: PolicyRepository) -> None:
        """Test getting a policy by ID."""
        policy_id = policy_repo.create(
            name="test-policy",
            version="1.0.0",
            content={"rules": [{"name": "rule1"}]},
        )

        policy = policy_repo.get_by_id(policy_id)

        assert policy is not None
        assert policy["name"] == "test-policy"
        assert policy["content"]["rules"][0]["name"] == "rule1"

    def test_get_by_id_not_found(self, policy_repo: PolicyRepository) -> None:
        """Test getting a policy that doesn't exist."""
        policy = policy_repo.get_by_id("nonexistent")
        assert policy is None

    def test_get_by_name(self, policy_repo: PolicyRepository) -> None:
        """Test getting a policy by name."""
        policy_repo.create(
            name="unique-policy",
            version="1.0.0",
            content={},
        )

        policy = policy_repo.get_by_name("unique-policy")

        assert policy is not None
        assert policy["name"] == "unique-policy"

    def test_get_active(self, policy_repo: PolicyRepository) -> None:
        """Test getting active policies."""
        policy_repo.create(name="active-1", version="1.0.0", content={})
        policy_repo.create(name="active-2", version="1.0.0", content={})

        policies = policy_repo.get_active()

        assert len(policies) >= 2

    def test_update_policy(self, policy_repo: PolicyRepository) -> None:
        """Test updating a policy."""
        policy_id = policy_repo.create(
            name="to-update",
            version="1.0.0",
            content={"old": "content"},
        )

        result = policy_repo.update(
            policy_id,
            version="2.0.0",
            content={"new": "content"},
        )

        assert result is True

        policy = policy_repo.get_by_id(policy_id)
        assert policy["version"] == "2.0.0"
        assert policy["content"]["new"] == "content"

    def test_update_nonexistent(self, policy_repo: PolicyRepository) -> None:
        """Test updating a policy that doesn't exist."""
        result = policy_repo.update("nonexistent", content={}, version="2.0.0")
        assert result is False

    def test_delete_policy(self, policy_repo: PolicyRepository) -> None:
        """Test deleting a policy."""
        policy_id = policy_repo.create(
            name="to-delete",
            version="1.0.0",
            content={},
        )

        result = policy_repo.delete(policy_id)
        assert result is True

        policy = policy_repo.get_by_id(policy_id)
        assert policy is None

    def test_delete_nonexistent(self, policy_repo: PolicyRepository) -> None:
        """Test deleting a policy that doesn't exist."""
        result = policy_repo.delete("nonexistent")
        assert result is False


# =============================================================================
# RegistryRepository Tests
# =============================================================================


class TestRegistryRepository:
    """Tests for RegistryRepository class."""

    def test_create_deployment(self, registry_repo: RegistryRepository) -> None:
        """Test creating a deployment."""
        deployment_id = registry_repo.create(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-a",
        )

        assert deployment_id is not None

    def test_get_by_id(self, registry_repo: RegistryRepository) -> None:
        """Test getting a deployment by ID."""
        deployment_id = registry_repo.create(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
        )

        deployment = registry_repo.get_by_id(deployment_id)

        assert deployment is not None
        assert deployment["name"] == "test"
        assert deployment["model_provider"] == "openai"

    def test_get_by_name(self, registry_repo: RegistryRepository) -> None:
        """Test getting a deployment by name."""
        registry_repo.create(
            name="unique-deployment",
            model_provider="anthropic",
            model_name="claude-3",
            owner="team",
        )

        deployment = registry_repo.get_by_name("unique-deployment")

        assert deployment is not None
        assert deployment["model_provider"] == "anthropic"

    def test_list_all(self, registry_repo: RegistryRepository) -> None:
        """Test listing all deployments."""
        registry_repo.create(
            name="deploy-1",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-a",
        )
        registry_repo.create(
            name="deploy-2",
            model_provider="anthropic",
            model_name="claude-3",
            owner="team-b",
        )

        deployments = registry_repo.list_all()

        assert len(deployments) >= 2

    def test_list_by_status(self, registry_repo: RegistryRepository) -> None:
        """Test listing deployments by status."""
        registry_repo.create(
            name="pending",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
        )

        deployments = registry_repo.list_all(status="PENDING")

        assert len(deployments) >= 1
        assert all(d["approval_status"] == "PENDING" for d in deployments)

    def test_list_by_risk_level(self, registry_repo: RegistryRepository) -> None:
        """Test listing deployments by risk level."""
        registry_repo.create(
            name="high-risk",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
            risk_level="HIGH",
        )

        deployments = registry_repo.list_all(risk_level="HIGH")

        assert len(deployments) >= 1
        assert all(d["risk_level"] == "HIGH" for d in deployments)

    def test_update_deployment(self, registry_repo: RegistryRepository) -> None:
        """Test updating a deployment."""
        deployment_id = registry_repo.create(
            name="to-update",
            model_provider="openai",
            model_name="gpt-4",
            owner="old-team",
        )

        result = registry_repo.update(
            deployment_id,
            owner="new-team",
            description="Updated description",
        )

        assert result is True

        deployment = registry_repo.get_by_id(deployment_id)
        assert deployment["owner"] == "new-team"

    def test_update_status(self, registry_repo: RegistryRepository) -> None:
        """Test updating deployment status."""
        deployment_id = registry_repo.create(
            name="to-approve",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
        )

        result = registry_repo.update_status(
            deployment_id,
            status="APPROVED",
            ticket="TICKET-123",
        )

        assert result is True

        deployment = registry_repo.get_by_id(deployment_id)
        assert deployment["approval_status"] == "APPROVED"
        assert deployment["approval_ticket"] == "TICKET-123"

    def test_delete_deployment(self, registry_repo: RegistryRepository) -> None:
        """Test deleting a deployment."""
        deployment_id = registry_repo.create(
            name="to-delete",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
        )

        result = registry_repo.delete(deployment_id)
        assert result is True

        deployment = registry_repo.get_by_id(deployment_id)
        assert deployment is None

    def test_get_pending_approval(self, registry_repo: RegistryRepository) -> None:
        """Test getting deployments pending approval."""
        registry_repo.create(
            name="pending-1",
            model_provider="openai",
            model_name="gpt-4",
            owner="team",
        )

        pending = registry_repo.get_pending_approval()

        assert len(pending) >= 1
        assert all(d["approval_status"] == "PENDING" for d in pending)


# =============================================================================
# AuditRepository Tests
# =============================================================================


class TestAuditRepository:
    """Tests for AuditRepository class."""

    def test_log_enforcement(self, audit_repo: AuditRepository) -> None:
        """Test logging an enforcement decision."""
        log_id = audit_repo.log_enforcement(
            request_id="req-1",
            provider="openai",
            model="gpt-4",
            user_id="user-1",
            department="engineering",
            decision="ALLOW",
            applied_rules=["rule-1"],
            reason="Request allowed",
        )

        assert log_id is not None

    def test_query_enforcement_logs(self, audit_repo: AuditRepository) -> None:
        """Test querying enforcement logs."""
        # Create some logs
        for i in range(5):
            audit_repo.log_enforcement(
                request_id=f"req-{i}",
                provider="openai",
                model="gpt-4",
                user_id=f"user-{i}",
                department="engineering",
                decision="ALLOW" if i % 2 == 0 else "DENY",
                applied_rules=[f"rule-{i}"],
                reason="Test",
            )

        logs = audit_repo.query_enforcement_logs(limit=10)

        assert len(logs) >= 5

    def test_query_by_date_range(self, audit_repo: AuditRepository) -> None:
        """Test querying logs by date range."""
        audit_repo.log_enforcement(
            request_id="req-date",
            provider="openai",
            model="gpt-4",
            user_id="user",
            department="eng",
            decision="ALLOW",
            applied_rules=[],
            reason="Test",
        )

        start_date = utc_now() - timedelta(hours=1)
        end_date = utc_now() + timedelta(hours=1)

        logs = audit_repo.query_enforcement_logs(
            start_date=start_date,
            end_date=end_date,
        )

        assert len(logs) >= 1

    def test_query_by_user(self, audit_repo: AuditRepository) -> None:
        """Test querying logs by user."""
        audit_repo.log_enforcement(
            request_id="req-user",
            provider="openai",
            model="gpt-4",
            user_id="specific-user",
            department="eng",
            decision="ALLOW",
            applied_rules=[],
            reason="Test",
        )

        logs = audit_repo.query_enforcement_logs(user_id="specific-user")

        assert len(logs) >= 1
        assert all(log["user_id"] == "specific-user" for log in logs)

    def test_query_by_decision(self, audit_repo: AuditRepository) -> None:
        """Test querying logs by decision."""
        audit_repo.log_enforcement(
            request_id="req-deny",
            provider="openai",
            model="gpt-4",
            user_id="user",
            department="eng",
            decision="DENY",
            applied_rules=["deny-rule"],
            reason="Denied",
        )

        logs = audit_repo.query_enforcement_logs(decision="DENY")

        assert len(logs) >= 1
        assert all(log["decision"] == "DENY" for log in logs)

    def test_get_enforcement_stats(self, audit_repo: AuditRepository) -> None:
        """Test getting enforcement statistics."""
        # Create some logs
        for i in range(10):
            audit_repo.log_enforcement(
                request_id=f"req-stat-{i}",
                provider="openai",
                model="gpt-4",
                user_id="user",
                department="eng",
                decision="ALLOW" if i < 7 else "DENY",
                applied_rules=[],
                reason="Test",
            )

        start_date = utc_now() - timedelta(hours=1)
        end_date = utc_now() + timedelta(hours=1)

        stats = audit_repo.get_enforcement_stats(start_date, end_date)

        assert stats["total_requests"] >= 10
        assert "by_decision" in stats


# =============================================================================
# TokenRepository Tests
# =============================================================================


class TestTokenRepository:
    """Tests for TokenRepository class."""

    def test_create_token(self, token_repo: TokenRepository) -> None:
        """Test creating a token."""
        token_id = token_repo.create(
            token_hash="abc123hash",
            subject="user-1",
            permissions={"models": ["gpt-4"]},
            issuer="admin",
        )

        assert token_id is not None

    def test_get_by_hash(self, token_repo: TokenRepository) -> None:
        """Test getting a token by hash."""
        token_hash = "unique-hash-123"
        token_repo.create(
            token_hash=token_hash,
            subject="user-1",
            permissions={"models": ["gpt-4"]},
        )

        token = token_repo.get_by_hash(token_hash)

        assert token is not None
        assert token["subject"] == "user-1"

    def test_get_by_hash_not_found(self, token_repo: TokenRepository) -> None:
        """Test getting a token that doesn't exist."""
        token = token_repo.get_by_hash("nonexistent")
        assert token is None

    def test_list_by_subject(self, token_repo: TokenRepository) -> None:
        """Test listing tokens by subject."""
        token_repo.create(
            token_hash="hash-1",
            subject="target-user",
            permissions={},
        )
        token_repo.create(
            token_hash="hash-2",
            subject="target-user",
            permissions={},
        )
        token_repo.create(
            token_hash="hash-3",
            subject="other-user",
            permissions={},
        )

        tokens = token_repo.list_by_subject("target-user")

        assert len(tokens) == 2
        assert all(t["subject"] == "target-user" for t in tokens)

    def test_update_usage(self, token_repo: TokenRepository) -> None:
        """Test updating token usage."""
        token_id = token_repo.create(
            token_hash="usage-hash",
            subject="user",
            permissions={},
        )

        result = token_repo.update_usage(token_id)

        assert result is True

        token = token_repo.get_by_id(token_id)
        assert token is not None
        assert token["use_count"] == 1

    def test_revoke_token(self, token_repo: TokenRepository) -> None:
        """Test revoking a token."""
        token_id = token_repo.create(
            token_hash="revoke-hash",
            subject="user",
            permissions={},
        )

        result = token_repo.revoke(token_id, reason="Test revocation")
        assert result is True

        token = token_repo.get_by_id(token_id)
        assert token is not None
        assert token["revoked_at"] is not None


# =============================================================================
# IncidentRepository Tests
# =============================================================================


class TestIncidentRepository:
    """Tests for IncidentRepository class."""

    def test_create_incident(self, incident_repo: IncidentRepository) -> None:
        """Test creating an incident."""
        incident_id = incident_repo.create(
            title="Test Incident",
            description="Test description",
            severity="HIGH",
            incident_type="POLICY_VIOLATION",
        )

        assert incident_id is not None

    def test_get_by_id(self, incident_repo: IncidentRepository) -> None:
        """Test getting an incident by ID."""
        incident_id = incident_repo.create(
            title="Get By ID Test",
            description="Description",
            severity="MEDIUM",
            incident_type="ABUSE",
        )

        incident = incident_repo.get_by_id(incident_id)

        assert incident is not None
        assert incident["title"] == "Get By ID Test"
        assert incident["severity"] == "MEDIUM"

    def test_get_by_id_not_found(self, incident_repo: IncidentRepository) -> None:
        """Test getting an incident that doesn't exist."""
        incident = incident_repo.get_by_id("nonexistent")
        assert incident is None

    def test_list_all(self, incident_repo: IncidentRepository) -> None:
        """Test listing all incidents."""
        incident_repo.create(
            title="Incident 1",
            description="Desc",
            severity="LOW",
            incident_type="ABUSE",
        )
        incident_repo.create(
            title="Incident 2",
            description="Desc",
            severity="HIGH",
            incident_type="DATA_LEAK",
        )

        incidents = incident_repo.list_all()

        assert len(incidents) >= 2

    def test_list_by_status(self, incident_repo: IncidentRepository) -> None:
        """Test listing incidents by status."""
        incident_repo.create(
            title="Open Incident",
            description="Desc",
            severity="MEDIUM",
            incident_type="JAILBREAK",
        )

        incidents = incident_repo.list_all(status="OPEN")

        assert len(incidents) >= 1
        assert all(i["status"] == "OPEN" for i in incidents)

    def test_list_by_severity(self, incident_repo: IncidentRepository) -> None:
        """Test listing incidents by severity."""
        incident_repo.create(
            title="Critical Incident",
            description="Desc",
            severity="CRITICAL",
            incident_type="DATA_LEAK",
        )

        incidents = incident_repo.list_all(severity="CRITICAL")

        assert len(incidents) >= 1
        assert all(i["severity"] == "CRITICAL" for i in incidents)

    def test_update_incident(self, incident_repo: IncidentRepository) -> None:
        """Test updating an incident."""
        incident_id = incident_repo.create(
            title="To Update",
            description="Original",
            severity="LOW",
            incident_type="ABUSE",
        )

        result = incident_repo.update(
            incident_id,
            title="Updated Title",
            description="Updated description",
        )

        assert result is True

        incident = incident_repo.get_by_id(incident_id)
        assert incident["title"] == "Updated Title"
        assert incident["description"] == "Updated description"

    def test_update_incident_status(self, incident_repo: IncidentRepository) -> None:
        """Test updating incident status."""
        incident_id = incident_repo.create(
            title="Status Test",
            description="Desc",
            severity="MEDIUM",
            incident_type="POLICY_VIOLATION",
        )

        result = incident_repo.update_status(
            incident_id=incident_id,
            status="INVESTIGATING",
            actor="admin",
        )

        assert result is True

        incident = incident_repo.get_by_id(incident_id)
        assert incident["status"] == "INVESTIGATING"


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestStorageEdgeCases:
    """Tests for edge cases and error handling."""

    def test_policy_with_complex_content(self, policy_repo: PolicyRepository) -> None:
        """Test policy with complex nested content."""
        complex_content = {
            "rules": [
                {
                    "name": "rule1",
                    "conditions": {
                        "and": [
                            {"provider": "openai"},
                            {"or": [
                                {"model": "gpt-4"},
                                {"model": "gpt-3.5-turbo"},
                            ]},
                        ],
                    },
                    "nested": {"deep": {"structure": [1, 2, 3]}},
                },
            ],
        }

        policy_id = policy_repo.create(
            name="complex-policy",
            version="1.0.0",
            content=complex_content,
        )

        policy = policy_repo.get_by_id(policy_id)
        assert policy["content"]["rules"][0]["nested"]["deep"]["structure"] == [1, 2, 3]

    def test_unicode_in_content(self, policy_repo: PolicyRepository) -> None:
        """Test handling of unicode content."""
        policy_id = policy_repo.create(
            name="unicode-policy",
            version="1.0.0",
            content={"description": "Japanese: \u65e5\u672c\u8a9e, Chinese: \u4e2d\u6587"},
            description="Policy with unicode: \u00e9\u00e0\u00fc",
        )

        policy = policy_repo.get_by_id(policy_id)
        assert "\u65e5\u672c\u8a9e" in policy["content"]["description"]

    def test_empty_collections(self, policy_repo: PolicyRepository) -> None:
        """Test handling of empty collections."""
        policy_id = policy_repo.create(
            name="empty-policy",
            version="1.0.0",
            content={"rules": [], "metadata": {}},
        )

        policy = policy_repo.get_by_id(policy_id)
        assert policy["content"]["rules"] == []

    def test_large_content(self, policy_repo: PolicyRepository) -> None:
        """Test handling of large content."""
        large_content = {
            "rules": [{"name": f"rule-{i}", "data": "x" * 1000} for i in range(100)],
        }

        policy_id = policy_repo.create(
            name="large-policy",
            version="1.0.0",
            content=large_content,
        )

        policy = policy_repo.get_by_id(policy_id)
        assert len(policy["content"]["rules"]) == 100

    def test_concurrent_operations(self, db: Database) -> None:
        """Test basic concurrent operations (simplified)."""
        policy_repo = PolicyRepository(db)

        # Create multiple policies in sequence (simulates concurrent access)
        for i in range(10):
            policy_repo.create(
                name=f"concurrent-{i}",
                version="1.0.0",
                content={},
            )

        policies = policy_repo.get_active()
        assert len([p for p in policies if "concurrent" in p["name"]]) == 10

    def test_special_characters_in_strings(
        self,
        registry_repo: RegistryRepository,
    ) -> None:
        """Test handling of special characters."""
        deployment_id = registry_repo.create(
            name="test-'quotes'-and-\"double\"",
            model_provider="provider's-name",
            model_name="model<>name",
            owner="team",
            description="Has 'single' and \"double\" quotes",
        )

        deployment = registry_repo.get_by_id(deployment_id)
        assert "'" in deployment["name"]
        assert "\"" in deployment["description"]
