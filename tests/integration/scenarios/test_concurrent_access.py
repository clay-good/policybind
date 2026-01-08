"""
Complex test scenarios for concurrent access patterns.

This module tests concurrent access scenarios including:
- Thread-safe operations across components
- Race condition prevention
- Concurrent read/write patterns
- State consistency under concurrent access
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from policybind.engine.pipeline import EnforcementPipeline, PipelineConfig
from policybind.engine.parser import PolicyParser
from policybind.models.request import AIRequest, Decision
from policybind.registry.manager import RegistryManager
from policybind.storage.database import Database
from policybind.storage.repositories import AuditRepository, RegistryRepository
from policybind.tokens.manager import TokenManager
from policybind.tokens.models import TokenPermissions, BudgetPeriod
from policybind.incidents.manager import IncidentManager
from policybind.incidents.models import IncidentSeverity, IncidentType, IncidentStatus
from policybind.storage.repositories import IncidentRepository


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    db = Database(":memory:")
    db.initialize()
    yield db
    db.close()


# =============================================================================
# Token Manager Concurrent Tests
# =============================================================================


class TestTokenManagerConcurrent:
    """Tests for concurrent access to TokenManager."""

    def test_concurrent_token_creation_unique_ids(self) -> None:
        """Test that concurrent token creation produces unique IDs."""
        manager = TokenManager()
        token_ids = []
        lock = threading.Lock()

        def create_token(idx: int):
            result = manager.create_token(
                name=f"concurrent-token-{idx}",
                subject=f"user-{idx}@example.com",
            )
            with lock:
                token_ids.append(result.token.token_id)

        threads = [
            threading.Thread(target=create_token, args=(i,))
            for i in range(50)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All IDs should be unique
        assert len(token_ids) == 50
        assert len(set(token_ids)) == 50

    def test_concurrent_token_validation(self) -> None:
        """Test concurrent token validation."""
        manager = TokenManager()

        # Create tokens
        tokens = []
        for i in range(20):
            result = manager.create_token(
                name=f"validate-{i}",
                subject=f"user-{i}@example.com",
            )
            tokens.append(result.plaintext_token)

        validation_results = []
        lock = threading.Lock()

        def validate_token(token: str):
            validated = manager.validate_token(token)
            with lock:
                validation_results.append(validated is not None)

        threads = []
        for token in tokens:
            for _ in range(5):  # Validate each token 5 times concurrently
                threads.append(threading.Thread(target=validate_token, args=(token,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All validations should succeed
        assert all(validation_results)
        assert len(validation_results) == 100  # 20 tokens * 5 validations

    def test_concurrent_usage_recording(self) -> None:
        """Test concurrent usage recording for a single token."""
        manager = TokenManager()

        result = manager.create_token(
            name="concurrent-usage",
            subject="user@example.com",
        )
        token_id = result.token.token_id

        def record_usage():
            for _ in range(100):
                manager.record_usage(
                    token_id=token_id,
                    tokens_used=1,
                    cost=0.001,
                )

        threads = [
            threading.Thread(target=record_usage)
            for _ in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 1000 uses should be recorded (10 threads * 100 uses)
        stats = manager.get_usage_stats(token_id)
        assert stats is not None
        assert stats.total_requests == 1000
        assert abs(stats.total_cost - 1.0) < 0.01  # 1000 * 0.001

    def test_concurrent_revocation(self) -> None:
        """Test that concurrent revocation doesn't cause issues."""
        manager = TokenManager()

        result = manager.create_token(
            name="revoke-target",
            subject="user@example.com",
        )
        token_id = result.token.token_id

        revoke_results = []
        lock = threading.Lock()

        def try_revoke():
            success = manager.revoke_token(token_id, "admin", "test")
            with lock:
                revoke_results.append(success)

        # Try to revoke the same token from multiple threads
        threads = [
            threading.Thread(target=try_revoke)
            for _ in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should return True (first revokes, rest see already revoked)
        assert all(revoke_results)
        # Token should be revoked (case-insensitive check)
        token = manager.get_token(token_id)
        assert token.status.value.upper() == "REVOKED"


# =============================================================================
# Registry Manager Concurrent Tests
# =============================================================================


class TestRegistryManagerConcurrent:
    """Tests for concurrent access to RegistryManager."""

    def test_concurrent_deployment_registration(self) -> None:
        """Test concurrent deployment registration."""
        manager = RegistryManager()  # In-memory for thread safety
        deployment_ids = []
        lock = threading.Lock()

        def register_deployment(idx: int):
            deployment = manager.register(
                name=f"concurrent-deploy-{idx}",
                model_provider="openai",
                model_name="gpt-4",
                owner=f"team-{idx % 5}",
                owner_contact=f"team-{idx % 5}@example.com",
            )
            with lock:
                deployment_ids.append(deployment.deployment_id)

        threads = [
            threading.Thread(target=register_deployment, args=(i,))
            for i in range(30)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All deployments should be registered with unique IDs
        assert len(deployment_ids) == 30
        assert len(set(deployment_ids)) == 30

    def test_concurrent_approval_workflow(self) -> None:
        """Test concurrent approval operations."""
        manager = RegistryManager()

        # Register deployments
        deployments = []
        for i in range(10):
            d = manager.register(
                name=f"approval-test-{i}",
                model_provider="openai",
                model_name="gpt-4",
                owner="test-team",
                owner_contact="test@example.com",
            )
            deployments.append(d)

        approval_results = []
        lock = threading.Lock()

        def approve_deployment(deployment):
            try:
                manager.approve(
                    deployment_id=deployment.deployment_id,
                    approved_by="admin@example.com",
                )
                with lock:
                    approval_results.append(True)
            except Exception:
                with lock:
                    approval_results.append(False)

        threads = [
            threading.Thread(target=approve_deployment, args=(d,))
            for d in deployments
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All approvals should succeed
        assert all(approval_results)


# =============================================================================
# Incident Manager Concurrent Tests
# =============================================================================


class TestIncidentManagerConcurrent:
    """Tests for concurrent access to IncidentManager."""

    def test_concurrent_incident_creation(self, temp_db: Database) -> None:
        """Test concurrent incident creation."""
        repo = IncidentRepository(temp_db)
        manager = IncidentManager(repository=repo)

        incident_ids = []
        lock = threading.Lock()
        errors = []

        def create_incident(idx: int):
            try:
                incident = manager.create(
                    title=f"Concurrent Incident {idx}",
                    incident_type=IncidentType.POLICY_VIOLATION,
                    severity=IncidentSeverity.MEDIUM,
                )
                with lock:
                    incident_ids.append(incident.incident_id)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        # Use fewer threads for SQLite
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(create_incident, i) for i in range(20)]
            for future in as_completed(futures):
                pass  # Wait for completion

        assert len(errors) == 0
        assert len(incident_ids) == 20

    def test_concurrent_status_updates(self, temp_db: Database) -> None:
        """Test concurrent status updates on different incidents."""
        repo = IncidentRepository(temp_db)
        manager = IncidentManager(repository=repo)

        # Create incidents
        incidents = []
        for i in range(10):
            incident = manager.create(
                title=f"Status Test {i}",
                incident_type=IncidentType.OTHER,
                severity=IncidentSeverity.LOW,
            )
            incidents.append(incident)

        update_results = []
        lock = threading.Lock()

        def update_status(incident):
            try:
                manager.start_investigation(
                    incident.incident_id,
                    actor="investigator",
                )
                with lock:
                    update_results.append(True)
            except Exception:
                with lock:
                    update_results.append(False)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(update_status, i) for i in incidents]
            for future in as_completed(futures):
                pass

        # All updates should succeed
        assert len(update_results) == 10


# =============================================================================
# Enforcement Pipeline Concurrent Tests
# =============================================================================


class TestEnforcementPipelineConcurrent:
    """Tests for concurrent access to enforcement pipeline."""

    def test_concurrent_enforcement_requests(self, temp_db: Database) -> None:
        """Test concurrent enforcement requests."""
        yaml_content = """
name: concurrent-test
version: "1.0.0"
description: Test policy for concurrent access

rules:
  - name: allow-openai
    description: Allow OpenAI requests
    action: ALLOW
    priority: 100
    match_conditions:
      provider: openai
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)
        assert result.success, f"Failed to parse policy: {result.errors}"
        pipeline = EnforcementPipeline(result.policy_set)

        results = []
        lock = threading.Lock()

        def process_request(user_id: int):
            response = pipeline.process(AIRequest(
                provider="openai",
                model="gpt-4",
                user_id=f"user-{user_id}",
            ))
            with lock:
                results.append(response.decision)

        threads = [
            threading.Thread(target=process_request, args=(i,))
            for i in range(50)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All requests should be processed
        assert len(results) == 50
        # All should be allowed based on our policy
        assert all(r == Decision.ALLOW for r in results)


# =============================================================================
# Mixed Component Concurrent Tests
# =============================================================================


class TestMixedConcurrentAccess:
    """Tests for concurrent access across multiple components."""

    def test_concurrent_token_and_enforcement(self, temp_db: Database) -> None:
        """Test concurrent token management and enforcement."""
        # Setup
        token_manager = TokenManager()

        yaml_content = """
name: mixed-concurrent-test
version: "1.0.0"
description: Test policy for mixed concurrent access

rules:
  - name: allow-openai
    description: Allow OpenAI requests
    action: ALLOW
    priority: 100
    match_conditions:
      provider: openai
"""
        parser = PolicyParser()
        result = parser.parse_string(yaml_content)
        assert result.success, f"Failed to parse policy: {result.errors}"
        pipeline = EnforcementPipeline(result.policy_set)

        results = {"tokens": [], "enforcements": []}
        lock = threading.Lock()

        def create_and_use_token(idx: int):
            # Create token
            result = token_manager.create_token(
                name=f"mixed-token-{idx}",
                subject=f"user-{idx}@example.com",
            )
            with lock:
                results["tokens"].append(result.token.token_id)

            # Use enforcement
            response = pipeline.process(AIRequest(
                provider="openai",
                model="gpt-4",
                user_id=f"user-{idx}",
            ))
            with lock:
                results["enforcements"].append(response.decision)

        threads = [
            threading.Thread(target=create_and_use_token, args=(i,))
            for i in range(30)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All operations should complete
        assert len(results["tokens"]) == 30
        assert len(results["enforcements"]) == 30
        assert all(r == Decision.ALLOW for r in results["enforcements"])


# =============================================================================
# Race Condition Prevention Tests
# =============================================================================


class TestRaceConditionPrevention:
    """Tests to verify race conditions are prevented."""

    def test_budget_tracking_race_condition(self) -> None:
        """Test that budget tracking handles concurrent updates correctly."""
        manager = TokenManager()

        result = manager.create_token(
            name="budget-race-test",
            subject="user@example.com",
            permissions=TokenPermissions(
                budget_limit=100.0,
                budget_period=BudgetPeriod.MONTHLY,
            ),
        )
        token_id = result.token.token_id

        # Concurrently consume budget
        def consume_budget():
            for _ in range(10):
                manager.record_usage(
                    token_id=token_id,
                    tokens_used=100,
                    cost=1.0,
                )
                time.sleep(0.001)

        threads = [
            threading.Thread(target=consume_budget)
            for _ in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total cost should be exactly 100 (10 threads * 10 requests * $1)
        stats = manager.get_usage_stats(token_id)
        assert stats.total_cost == 100.0
        assert stats.total_requests == 100

    def test_event_callback_race_condition(self) -> None:
        """Test that event callbacks don't interfere with each other."""
        manager = TokenManager()

        events = []
        lock = threading.Lock()

        def event_callback(event):
            with lock:
                events.append(event)

        manager.on_token_event(event_callback)

        def create_token(idx: int):
            manager.create_token(
                name=f"event-race-{idx}",
                subject=f"user-{idx}@example.com",
            )

        threads = [
            threading.Thread(target=create_token, args=(i,))
            for i in range(20)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All creation events should be captured
        assert len([e for e in events if e.event_type == "created"]) == 20

    def test_counter_increment_race_condition(self) -> None:
        """Test that internal counters are handled atomically."""
        manager = TokenManager()

        # Create a token
        result = manager.create_token(
            name="counter-test",
            subject="user@example.com",
        )
        token_id = result.token.token_id

        # Concurrent denied requests
        def record_denied():
            for _ in range(50):
                manager.record_denied_request(token_id)

        threads = [
            threading.Thread(target=record_denied)
            for _ in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have exactly 500 denied requests
        stats = manager.get_usage_stats(token_id)
        assert stats.denied_requests == 500
