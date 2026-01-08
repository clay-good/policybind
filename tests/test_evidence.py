"""
Tests for evidence collection and chain of custody.

This module tests the EvidenceCollector, IntegrityManager, and related
functionality for audit evidence export.
"""

import hashlib
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from policybind.models.base import utc_now
from policybind.reports.chain_of_custody import (
    CustodyChain,
    CustodyEvent,
    HashAlgorithm,
    IntegrityManager,
    IntegrityManifest,
    SignatureType,
    create_evidence_hash,
    verify_evidence_hash,
)
from policybind.reports.evidence import (
    CollectionScope,
    EvidenceCollector,
    EvidenceFormat,
    EvidenceItem,
    EvidencePackage,
    EvidenceType,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_policy_repo() -> MagicMock:
    """Create a mock policy repository."""
    repo = MagicMock()
    repo.get_active.return_value = [
        {
            "id": "policy-1",
            "name": "security-policy",
            "version": "1.0.0",
            "description": "Security controls",
            "is_active": True,
            "created_at": utc_now().isoformat(),
            "created_by": "admin",
            "content": {"rules": []},
        },
        {
            "id": "policy-2",
            "name": "data-policy",
            "version": "2.0.0",
            "description": "Data handling",
            "is_active": True,
            "created_at": utc_now().isoformat(),
            "created_by": "admin",
            "content": {"rules": []},
        },
    ]
    return repo


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    """Create a mock audit repository."""
    repo = MagicMock()
    repo.query_enforcement_logs.return_value = [
        {
            "id": "log-1",
            "request_id": "req-1",
            "timestamp": utc_now().isoformat(),
            "provider": "openai",
            "model": "gpt-4",
            "user_id": "user-1",
            "department": "engineering",
            "decision": "ALLOW",
            "applied_rules": ["rule-1"],
            "reason": "Request allowed",
            "deployment_id": "dep-1",
            "estimated_tokens": 100,
            "estimated_cost": 0.01,
            "enforcement_time_ms": 15.5,
            "warnings": [],
        },
        {
            "id": "log-2",
            "request_id": "req-2",
            "timestamp": utc_now().isoformat(),
            "provider": "anthropic",
            "model": "claude-3",
            "user_id": "user-2",
            "department": "sales",
            "decision": "DENY",
            "applied_rules": ["rule-2"],
            "reason": "PII detected",
            "deployment_id": "dep-2",
            "estimated_tokens": 200,
            "estimated_cost": 0.02,
            "enforcement_time_ms": 20.0,
            "warnings": ["Sensitive data detected"],
        },
    ]
    return repo


@pytest.fixture
def mock_registry_repo() -> MagicMock:
    """Create a mock registry repository."""
    repo = MagicMock()
    repo.list_all.return_value = [
        {
            "deployment_id": "dep-1",
            "name": "GPT-4 Deployment",
            "description": "Production GPT-4",
            "model_provider": "openai",
            "model_name": "gpt-4",
            "model_version": "0613",
            "owner": "team-a",
            "owner_contact": "team-a@example.com",
            "risk_level": "HIGH",
            "approval_status": "APPROVED",
            "approval_ticket": "TICKET-123",
            "deployment_date": utc_now().isoformat(),
            "last_review_date": utc_now().isoformat(),
            "next_review_date": (utc_now() + timedelta(days=90)).isoformat(),
            "data_categories": ["general"],
            "created_at": utc_now().isoformat(),
            "updated_at": utc_now().isoformat(),
        },
    ]
    repo.get_by_id.return_value = repo.list_all.return_value[0]
    return repo


@pytest.fixture
def mock_incident_manager() -> MagicMock:
    """Create a mock incident manager."""
    manager = MagicMock()
    manager.list_incidents.return_value = [
        {
            "incident_id": "inc-1",
            "title": "Policy Violation",
            "description": "User violated PII policy",
            "severity": "HIGH",
            "status": "CLOSED",
            "incident_type": "POLICY_VIOLATION",
            "created_at": utc_now().isoformat(),
            "resolved_at": utc_now().isoformat(),
            "closed_at": utc_now().isoformat(),
            "assigned_to": "security-team",
            "resolution": "User warned",
            "root_cause": "User error",
            "related_request_id": "req-2",
            "related_deployment_id": "dep-2",
            "tags": ["pii", "violation"],
            "timeline": [],
            "comments": [],
        },
    ]
    return manager


@pytest.fixture
def evidence_collector(
    mock_policy_repo: MagicMock,
    mock_audit_repo: MagicMock,
    mock_registry_repo: MagicMock,
    mock_incident_manager: MagicMock,
) -> EvidenceCollector:
    """Create an evidence collector with mocked dependencies."""
    return EvidenceCollector(
        policy_repository=mock_policy_repo,
        audit_repository=mock_audit_repo,
        registry_repository=mock_registry_repo,
        incident_manager=mock_incident_manager,
    )


# =============================================================================
# EvidenceItem Tests
# =============================================================================


class TestEvidenceItem:
    """Tests for EvidenceItem class."""

    def test_create_evidence_item(self) -> None:
        """Test creating an evidence item."""
        item = EvidenceItem(
            evidence_id="evid-1",
            evidence_type=EvidenceType.ENFORCEMENT_DECISION,
            timestamp=utc_now(),
            source="enforcement_log",
            content={"decision": "ALLOW", "user_id": "user-1"},
        )

        assert item.evidence_id == "evid-1"
        assert item.evidence_type == EvidenceType.ENFORCEMENT_DECISION
        assert item.checksum != ""

    def test_checksum_calculated_on_creation(self) -> None:
        """Test that checksum is calculated automatically."""
        content = {"key": "value", "number": 42}
        item = EvidenceItem(
            evidence_id="evid-2",
            evidence_type=EvidenceType.POLICY_CONFIGURATION,
            timestamp=utc_now(),
            source="test",
            content=content,
        )

        # Verify checksum matches expected
        content_str = json.dumps(content, sort_keys=True, default=str)
        expected = hashlib.sha256(content_str.encode()).hexdigest()
        assert item.checksum == expected

    def test_to_dict(self) -> None:
        """Test serializing an evidence item."""
        item = EvidenceItem(
            evidence_id="evid-3",
            evidence_type=EvidenceType.INCIDENT_RECORD,
            timestamp=utc_now(),
            source="incident_manager",
            content={"incident_id": "inc-1"},
            metadata={"collected_by": "test"},
        )

        data = item.to_dict()

        assert data["evidence_id"] == "evid-3"
        assert data["evidence_type"] == "incident_record"
        assert data["source"] == "incident_manager"
        assert "checksum" in data


# =============================================================================
# EvidencePackage Tests
# =============================================================================


class TestEvidencePackage:
    """Tests for EvidencePackage class."""

    def test_create_package(self) -> None:
        """Test creating an evidence package."""
        package = EvidencePackage(
            package_id="pkg-1",
            created_at=utc_now(),
            created_by="auditor",
            period_start=utc_now() - timedelta(days=30),
            period_end=utc_now(),
            scope={"include_policies": True},
        )

        assert package.package_id == "pkg-1"
        assert len(package.items) == 0

    def test_add_items(self) -> None:
        """Test adding items to a package."""
        package = EvidencePackage(
            package_id="pkg-2",
            created_at=utc_now(),
            created_by="test",
            period_start=utc_now(),
            period_end=utc_now(),
            scope={},
        )

        item = EvidenceItem(
            evidence_id="evid-1",
            evidence_type=EvidenceType.ENFORCEMENT_DECISION,
            timestamp=utc_now(),
            source="test",
            content={"test": "data"},
        )
        package.items.append(item)

        assert len(package.items) == 1

    def test_calculate_manifest_checksum(self) -> None:
        """Test manifest checksum calculation."""
        package = EvidencePackage(
            package_id="pkg-3",
            created_at=utc_now(),
            created_by="test",
            period_start=utc_now(),
            period_end=utc_now(),
            scope={},
        )

        item = EvidenceItem(
            evidence_id="evid-1",
            evidence_type=EvidenceType.POLICY_CONFIGURATION,
            timestamp=utc_now(),
            source="test",
            content={"data": "value"},
        )
        package.items.append(item)

        checksum = package.calculate_manifest_checksum()
        assert len(checksum) == 64  # SHA-256 hex length

    def test_get_summary(self) -> None:
        """Test getting package summary."""
        package = EvidencePackage(
            package_id="pkg-4",
            created_at=utc_now(),
            created_by="test",
            period_start=utc_now(),
            period_end=utc_now(),
            scope={},
        )

        # Add items of different types
        for i, etype in enumerate([
            EvidenceType.POLICY_CONFIGURATION,
            EvidenceType.ENFORCEMENT_DECISION,
            EvidenceType.ENFORCEMENT_DECISION,
        ]):
            package.items.append(EvidenceItem(
                evidence_id=f"evid-{i}",
                evidence_type=etype,
                timestamp=utc_now(),
                source="test",
                content={"i": i},
            ))

        summary = package.get_summary()

        assert summary["item_count"] == 3
        assert summary["items_by_type"]["policy_configuration"] == 1
        assert summary["items_by_type"]["enforcement_decision"] == 2


# =============================================================================
# CollectionScope Tests
# =============================================================================


class TestCollectionScope:
    """Tests for CollectionScope class."""

    def test_default_scope(self) -> None:
        """Test default collection scope."""
        scope = CollectionScope()

        assert scope.deployment_id is None
        assert scope.include_policies is True
        assert scope.include_enforcement is True
        assert scope.include_incidents is True

    def test_filtered_scope(self) -> None:
        """Test filtered collection scope."""
        scope = CollectionScope(
            deployment_id="dep-1",
            user_id="user-1",
            include_policies=False,
            include_incidents=False,
        )

        assert scope.deployment_id == "dep-1"
        assert scope.include_policies is False
        assert scope.include_incidents is False

    def test_to_dict(self) -> None:
        """Test scope serialization."""
        scope = CollectionScope(
            department="engineering",
            include_changes=False,
        )

        data = scope.to_dict()

        assert data["department"] == "engineering"
        assert data["include_changes"] is False


# =============================================================================
# EvidenceCollector Tests
# =============================================================================


class TestEvidenceCollector:
    """Tests for EvidenceCollector class."""

    def test_collect_all_evidence(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test collecting all types of evidence."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=30),
            end_date=utc_now(),
            created_by="test-auditor",
        )

        assert package.package_id is not None
        assert len(package.items) > 0
        assert package.manifest_checksum != ""

    def test_collect_with_scope(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test collecting with filtered scope."""
        scope = CollectionScope(
            include_policies=True,
            include_enforcement=False,
            include_incidents=False,
            include_approvals=False,
            include_changes=False,
        )

        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=7),
            end_date=utc_now(),
            scope=scope,
        )

        # Should only have policy evidence
        for item in package.items:
            assert item.evidence_type == EvidenceType.POLICY_CONFIGURATION

    def test_collect_without_repos(self) -> None:
        """Test collecting without any repositories configured."""
        collector = EvidenceCollector()

        package = collector.collect(
            start_date=utc_now() - timedelta(days=1),
            end_date=utc_now(),
        )

        assert package.package_id is not None
        assert len(package.items) == 0

    def test_export_json(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test exporting package as JSON."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=1),
            end_date=utc_now(),
        )

        json_output = evidence_collector.export_json(package)
        data = json.loads(json_output)

        assert data["package_id"] == package.package_id
        assert "items" in data

    def test_export_zip(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test exporting package as ZIP archive."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=1),
            end_date=utc_now(),
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "evidence.zip"
            result = evidence_collector.export_zip(package, output_path)

            assert Path(result).exists()
            assert Path(result).suffix == ".zip"

    def test_export_to_bytes(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test exporting package as bytes."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=1),
            end_date=utc_now(),
        )

        zip_bytes = evidence_collector.export_to_bytes(package)

        assert isinstance(zip_bytes, bytes)
        assert len(zip_bytes) > 0

    def test_verify_package(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test package verification."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=1),
            end_date=utc_now(),
        )

        result = evidence_collector.verify_package(package)

        assert result["is_valid"] is True
        assert result["verified_items"] == len(package.items)

    def test_verify_tampered_package(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test verification detects tampering."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=1),
            end_date=utc_now(),
        )

        # Tamper with an item
        if package.items:
            package.items[0].content["tampered"] = True

        result = evidence_collector.verify_package(package)

        assert result["is_valid"] is False
        assert len(result["issues"]) > 0


# =============================================================================
# CustodyEvent Tests
# =============================================================================


class TestCustodyEvent:
    """Tests for CustodyEvent class."""

    def test_create_event(self) -> None:
        """Test creating a custody event."""
        event = CustodyEvent(
            event_id="event-1",
            timestamp=utc_now(),
            action="CREATED",
            actor="admin",
            details={"source": "test"},
            previous_hash="genesis",
        )

        assert event.event_id == "event-1"
        assert event.event_hash != ""

    def test_event_hash_calculation(self) -> None:
        """Test that event hash includes all fields."""
        event1 = CustodyEvent(
            event_id="event-1",
            timestamp=utc_now(),
            action="ACTION_A",
            actor="admin",
            details={},
            previous_hash="genesis",
        )

        event2 = CustodyEvent(
            event_id="event-1",
            timestamp=utc_now(),
            action="ACTION_B",  # Different action
            actor="admin",
            details={},
            previous_hash="genesis",
        )

        # Different actions should produce different hashes
        assert event1.event_hash != event2.event_hash

    def test_to_dict(self) -> None:
        """Test event serialization."""
        event = CustodyEvent(
            event_id="event-2",
            timestamp=utc_now(),
            action="EXPORTED",
            actor="auditor",
            details={"format": "zip"},
            previous_hash="abc123",
        )

        data = event.to_dict()

        assert data["event_id"] == "event-2"
        assert data["action"] == "EXPORTED"
        assert data["previous_hash"] == "abc123"


# =============================================================================
# CustodyChain Tests
# =============================================================================


class TestCustodyChain:
    """Tests for CustodyChain class."""

    def test_create_chain(self) -> None:
        """Test creating a custody chain."""
        chain = CustodyChain(
            chain_id="chain-1",
            package_id="pkg-1",
            created_at=utc_now(),
        )

        assert chain.chain_id == "chain-1"
        assert len(chain.events) == 0

    def test_add_events(self) -> None:
        """Test adding events to chain."""
        chain = CustodyChain(
            chain_id="chain-2",
            package_id="pkg-2",
            created_at=utc_now(),
        )

        event1 = chain.add_event("CREATED", "admin", {"test": 1})
        event2 = chain.add_event("EXPORTED", "auditor", {"format": "zip"})

        assert len(chain.events) == 2
        assert event2.previous_hash == event1.event_hash

    def test_verify_valid_chain(self) -> None:
        """Test verifying a valid chain."""
        chain = CustodyChain(
            chain_id="chain-3",
            package_id="pkg-3",
            created_at=utc_now(),
        )

        chain.add_event("CREATED", "admin")
        chain.add_event("VIEWED", "auditor")
        chain.add_event("EXPORTED", "auditor")

        result = chain.verify_chain()

        assert result["is_valid"] is True
        assert result["verified_events"] == 3

    def test_verify_broken_chain(self) -> None:
        """Test verifying a broken chain."""
        chain = CustodyChain(
            chain_id="chain-4",
            package_id="pkg-4",
            created_at=utc_now(),
        )

        chain.add_event("CREATED", "admin")
        chain.add_event("VIEWED", "auditor")

        # Tamper with chain linkage
        chain.events[1].previous_hash = "tampered"

        result = chain.verify_chain()

        assert result["is_valid"] is False
        assert any(i["type"] == "chain_linkage_broken" for i in result["issues"])

    def test_get_latest_hash(self) -> None:
        """Test getting latest hash."""
        chain = CustodyChain(
            chain_id="chain-5",
            package_id="pkg-5",
            created_at=utc_now(),
        )

        assert chain.get_latest_hash() == "genesis"

        event = chain.add_event("CREATED", "admin")
        assert chain.get_latest_hash() == event.event_hash


# =============================================================================
# IntegrityManifest Tests
# =============================================================================


class TestIntegrityManifest:
    """Tests for IntegrityManifest class."""

    def test_create_manifest(self) -> None:
        """Test creating an integrity manifest."""
        manifest = IntegrityManifest(
            manifest_id="manifest-1",
            package_id="pkg-1",
            created_at=utc_now(),
            created_by="test",
            algorithm=HashAlgorithm.SHA256,
            item_hashes={"item-1": "hash1", "item-2": "hash2"},
            root_hash="roothash",
        )

        assert manifest.manifest_id == "manifest-1"
        assert len(manifest.item_hashes) == 2

    def test_to_dict(self) -> None:
        """Test manifest serialization."""
        manifest = IntegrityManifest(
            manifest_id="manifest-2",
            package_id="pkg-2",
            created_at=utc_now(),
            created_by="auditor",
            algorithm=HashAlgorithm.SHA384,
            item_hashes={},
            root_hash="abc",
            signature="sig123",
            signature_type=SignatureType.HMAC,
        )

        data = manifest.to_dict()

        assert data["algorithm"] == "sha384"
        assert data["signature_type"] == "hmac"


# =============================================================================
# IntegrityManager Tests
# =============================================================================


class TestIntegrityManager:
    """Tests for IntegrityManager class."""

    @pytest.fixture
    def manager(self) -> IntegrityManager:
        """Create an integrity manager."""
        return IntegrityManager()

    @pytest.fixture
    def sample_package(self) -> EvidencePackage:
        """Create a sample evidence package."""
        package = EvidencePackage(
            package_id="pkg-test",
            created_at=utc_now(),
            created_by="test",
            period_start=utc_now() - timedelta(days=7),
            period_end=utc_now(),
            scope={},
        )

        for i in range(3):
            package.items.append(EvidenceItem(
                evidence_id=f"evid-{i}",
                evidence_type=EvidenceType.ENFORCEMENT_DECISION,
                timestamp=utc_now(),
                source="test",
                content={"index": i, "data": f"value-{i}"},
            ))

        package.manifest_checksum = package.calculate_manifest_checksum()
        return package

    def test_create_manifest(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test creating an integrity manifest."""
        manifest = manager.create_manifest(sample_package, created_by="test")

        assert manifest.package_id == sample_package.package_id
        assert len(manifest.item_hashes) == 3
        assert manifest.root_hash != ""

    def test_sign_manifest(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test signing a manifest."""
        manifest = manager.create_manifest(sample_package)
        key = manager.generate_signing_key()

        signed = manager.sign_manifest(manifest, key)

        assert signed.signature != ""
        assert signed.signature_type == SignatureType.HMAC

    def test_verify_manifest(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test verifying a manifest."""
        manifest = manager.create_manifest(sample_package)

        result = manager.verify_manifest(manifest, sample_package)

        assert result["is_valid"] is True
        assert result["verified_items"] == 3

    def test_verify_signed_manifest(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test verifying a signed manifest."""
        manifest = manager.create_manifest(sample_package)
        key = manager.generate_signing_key()
        signed = manager.sign_manifest(manifest, key)

        result = manager.verify_manifest(signed, sample_package, key)

        assert result["is_valid"] is True
        assert result["signature_verified"] is True

    def test_verify_invalid_signature(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test that invalid signature is detected."""
        manifest = manager.create_manifest(sample_package)
        key = manager.generate_signing_key()
        signed = manager.sign_manifest(manifest, key)

        # Use wrong key for verification
        wrong_key = manager.generate_signing_key()
        result = manager.verify_manifest(signed, sample_package, wrong_key)

        assert result["signature_verified"] is False

    def test_create_custody_chain(
        self,
        manager: IntegrityManager,
    ) -> None:
        """Test creating a custody chain."""
        chain = manager.create_custody_chain("pkg-1")

        assert chain.package_id == "pkg-1"
        assert chain.chain_id is not None

    def test_record_custody_event(
        self,
        manager: IntegrityManager,
    ) -> None:
        """Test recording custody events."""
        chain = manager.create_custody_chain("pkg-1")

        event = manager.record_custody_event(
            chain,
            action="CREATED",
            actor="admin",
            details={"reason": "test"},
        )

        assert event.action == "CREATED"
        assert len(chain.events) == 1

    def test_generate_and_export_key(
        self,
        manager: IntegrityManager,
    ) -> None:
        """Test key generation and export/import."""
        key = manager.generate_signing_key()
        assert len(key) == 32

        exported = manager.export_key(key)
        assert isinstance(exported, str)

        imported = manager.import_key(exported)
        assert imported == key

    def test_create_tamper_evident_package(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test creating a complete tamper-evident package."""
        key = manager.generate_signing_key()

        result = manager.create_tamper_evident_package(
            sample_package,
            created_by="auditor",
            signing_key=key,
        )

        assert "package" in result
        assert "manifest" in result
        assert "custody_chain" in result
        assert result["manifest"]["signature"] != ""

    def test_verify_tamper_evident_package(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test verifying a tamper-evident package."""
        key = manager.generate_signing_key()

        tamper_evident = manager.create_tamper_evident_package(
            sample_package,
            signing_key=key,
        )

        result = manager.verify_tamper_evident_package(tamper_evident, key)

        assert result["is_valid"] is True
        assert result["item_count"] == 3

    def test_detect_tampered_package(
        self,
        manager: IntegrityManager,
        sample_package: EvidencePackage,
    ) -> None:
        """Test that tampering is detected."""
        key = manager.generate_signing_key()

        tamper_evident = manager.create_tamper_evident_package(
            sample_package,
            signing_key=key,
        )

        # Tamper with package
        tamper_evident["package"]["items"][0]["content"]["tampered"] = True

        result = manager.verify_tamper_evident_package(tamper_evident, key)

        assert result["is_valid"] is False

    def test_sha384_algorithm(
        self,
        sample_package: EvidencePackage,
    ) -> None:
        """Test using SHA-384 algorithm."""
        manager = IntegrityManager(algorithm=HashAlgorithm.SHA384)
        manifest = manager.create_manifest(sample_package)

        assert manifest.algorithm == HashAlgorithm.SHA384
        # SHA-384 produces 96-character hex hash
        assert len(manifest.root_hash) == 96

    def test_sha512_algorithm(
        self,
        sample_package: EvidencePackage,
    ) -> None:
        """Test using SHA-512 algorithm."""
        manager = IntegrityManager(algorithm=HashAlgorithm.SHA512)
        manifest = manager.create_manifest(sample_package)

        assert manifest.algorithm == HashAlgorithm.SHA512
        # SHA-512 produces 128-character hex hash
        assert len(manifest.root_hash) == 128


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_create_evidence_hash(self) -> None:
        """Test creating an evidence hash."""
        content = {"key": "value", "number": 42}
        hash_result = create_evidence_hash(content)

        assert len(hash_result) == 64  # SHA-256

    def test_create_evidence_hash_sha384(self) -> None:
        """Test creating a SHA-384 hash."""
        content = {"test": "data"}
        hash_result = create_evidence_hash(content, HashAlgorithm.SHA384)

        assert len(hash_result) == 96  # SHA-384

    def test_verify_evidence_hash(self) -> None:
        """Test verifying an evidence hash."""
        content = {"important": "data"}
        hash_value = create_evidence_hash(content)

        assert verify_evidence_hash(content, hash_value) is True
        assert verify_evidence_hash(content, "wrong_hash") is False

    def test_hash_determinism(self) -> None:
        """Test that hashing is deterministic."""
        content = {"a": 1, "b": 2, "c": 3}

        hash1 = create_evidence_hash(content)
        hash2 = create_evidence_hash(content)

        assert hash1 == hash2

    def test_hash_order_independence(self) -> None:
        """Test that key order doesn't affect hash."""
        content1 = {"a": 1, "b": 2, "c": 3}
        content2 = {"c": 3, "a": 1, "b": 2}

        hash1 = create_evidence_hash(content1)
        hash2 = create_evidence_hash(content2)

        assert hash1 == hash2


# =============================================================================
# Integration Tests
# =============================================================================


class TestEvidenceIntegration:
    """Integration tests for evidence collection and verification."""

    def test_full_evidence_workflow(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test complete evidence collection and verification workflow."""
        # Collect evidence
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=30),
            end_date=utc_now(),
            created_by="auditor@example.com",
        )

        assert len(package.items) > 0

        # Create integrity manager
        manager = IntegrityManager()

        # Create manifest
        manifest = manager.create_manifest(package, created_by="auditor")

        # Sign manifest
        key = manager.generate_signing_key()
        signed_manifest = manager.sign_manifest(manifest, key)

        # Create custody chain
        chain = manager.create_custody_chain(package.package_id)
        manager.record_custody_event(chain, "COLLECTED", "auditor")
        manager.record_custody_event(chain, "SIGNED", "auditor")

        # Verify everything
        manifest_result = manager.verify_manifest(signed_manifest, package, key)
        chain_result = chain.verify_chain()

        assert manifest_result["is_valid"] is True
        assert manifest_result["signature_verified"] is True
        assert chain_result["is_valid"] is True

    def test_export_and_verify(
        self,
        evidence_collector: EvidenceCollector,
    ) -> None:
        """Test exporting and verifying evidence."""
        package = evidence_collector.collect(
            start_date=utc_now() - timedelta(days=7),
            end_date=utc_now(),
        )

        # Export to ZIP
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "evidence.zip"
            evidence_collector.export_zip(package, output_path)

            assert output_path.exists()

            # Verify the original package
            verify_result = evidence_collector.verify_package(package)
            assert verify_result["is_valid"] is True
