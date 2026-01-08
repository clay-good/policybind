"""
Chain of custody and integrity verification for PolicyBind evidence.

This module provides cryptographic features for ensuring the integrity
and authenticity of evidence packages, including hash generation,
signature support, and tamper-evident packaging.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from policybind.models.base import generate_uuid, utc_now
from policybind.reports.evidence import EvidenceItem, EvidencePackage

logger = logging.getLogger("policybind.reports.chain_of_custody")


class HashAlgorithm(Enum):
    """Supported hash algorithms for integrity verification."""

    SHA256 = "sha256"
    """SHA-256 hash (default)."""

    SHA384 = "sha384"
    """SHA-384 hash for higher security requirements."""

    SHA512 = "sha512"
    """SHA-512 hash for maximum security."""


class SignatureType(Enum):
    """Types of signatures supported."""

    HMAC = "hmac"
    """HMAC-based signature using shared secret."""

    NONE = "none"
    """No signature (checksums only)."""


@dataclass
class CustodyEvent:
    """
    A single event in the chain of custody.

    Attributes:
        event_id: Unique identifier for this event.
        timestamp: When the event occurred.
        action: What action was taken.
        actor: Who performed the action.
        details: Additional event details.
        previous_hash: Hash of the previous event.
        event_hash: Hash of this event.
    """

    event_id: str
    timestamp: datetime
    action: str
    actor: str
    details: dict[str, Any]
    previous_hash: str
    event_hash: str = ""

    def __post_init__(self) -> None:
        """Calculate event hash if not provided."""
        if not self.event_hash:
            self.event_hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """Calculate the hash of this event."""
        content = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "actor": self.actor,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "actor": self.actor,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


@dataclass
class CustodyChain:
    """
    A chain of custody for an evidence package.

    Maintains an immutable, tamper-evident record of all actions
    taken on the evidence package.

    Attributes:
        chain_id: Unique identifier for this chain.
        package_id: ID of the evidence package.
        created_at: When the chain was created.
        events: List of custody events.
        algorithm: Hash algorithm used.
    """

    chain_id: str
    package_id: str
    created_at: datetime
    events: list[CustodyEvent] = field(default_factory=list)
    algorithm: HashAlgorithm = HashAlgorithm.SHA256

    def add_event(
        self,
        action: str,
        actor: str,
        details: dict[str, Any] | None = None,
    ) -> CustodyEvent:
        """
        Add an event to the chain.

        Args:
            action: The action being recorded.
            actor: Who is performing the action.
            details: Additional details.

        Returns:
            The created custody event.
        """
        previous_hash = (
            self.events[-1].event_hash if self.events else "genesis"
        )

        event = CustodyEvent(
            event_id=generate_uuid(),
            timestamp=utc_now(),
            action=action,
            actor=actor,
            details=details or {},
            previous_hash=previous_hash,
        )

        self.events.append(event)
        return event

    def get_latest_hash(self) -> str:
        """Get the hash of the latest event."""
        if not self.events:
            return "genesis"
        return self.events[-1].event_hash

    def verify_chain(self) -> dict[str, Any]:
        """
        Verify the integrity of the custody chain.

        Returns:
            Verification results with any issues found.
        """
        issues = []
        verified_events = 0

        for i, event in enumerate(self.events):
            # Verify event hash
            expected_hash = event._calculate_hash()
            if event.event_hash != expected_hash:
                issues.append({
                    "type": "event_hash_mismatch",
                    "event_id": event.event_id,
                    "index": i,
                    "expected": expected_hash,
                    "actual": event.event_hash,
                })
            else:
                verified_events += 1

            # Verify chain linkage (skip first event)
            if i > 0:
                expected_previous = self.events[i - 1].event_hash
                if event.previous_hash != expected_previous:
                    issues.append({
                        "type": "chain_linkage_broken",
                        "event_id": event.event_id,
                        "index": i,
                        "expected_previous": expected_previous,
                        "actual_previous": event.previous_hash,
                    })

        return {
            "chain_id": self.chain_id,
            "verified_at": utc_now().isoformat(),
            "is_valid": len(issues) == 0,
            "total_events": len(self.events),
            "verified_events": verified_events,
            "issues": issues,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain_id": self.chain_id,
            "package_id": self.package_id,
            "created_at": self.created_at.isoformat(),
            "algorithm": self.algorithm.value,
            "event_count": len(self.events),
            "latest_hash": self.get_latest_hash(),
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class IntegrityManifest:
    """
    A cryptographic manifest for an evidence package.

    Provides tamper-evident packaging with cryptographic verification.

    Attributes:
        manifest_id: Unique identifier.
        package_id: ID of the evidence package.
        created_at: When the manifest was created.
        created_by: Who created the manifest.
        algorithm: Hash algorithm used.
        item_hashes: Hashes of individual evidence items.
        root_hash: Merkle root hash of all items.
        signature: Optional signature of the manifest.
        signature_type: Type of signature used.
    """

    manifest_id: str
    package_id: str
    created_at: datetime
    created_by: str
    algorithm: HashAlgorithm
    item_hashes: dict[str, str]
    root_hash: str
    signature: str = ""
    signature_type: SignatureType = SignatureType.NONE

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "manifest_id": self.manifest_id,
            "package_id": self.package_id,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "algorithm": self.algorithm.value,
            "item_count": len(self.item_hashes),
            "item_hashes": self.item_hashes,
            "root_hash": self.root_hash,
            "signature": self.signature,
            "signature_type": self.signature_type.value,
        }


class IntegrityManager:
    """
    Manages cryptographic integrity for evidence packages.

    Provides functionality for:
    - Generating cryptographic hashes of evidence
    - Creating tamper-evident audit packages
    - Signing and verifying evidence integrity
    - Maintaining chain of custody

    Example:
        Using the IntegrityManager::

            from policybind.reports.chain_of_custody import IntegrityManager
            from policybind.reports.evidence import EvidenceCollector

            collector = EvidenceCollector(...)
            package = collector.collect(...)

            manager = IntegrityManager()

            # Create integrity manifest
            manifest = manager.create_manifest(package, created_by="auditor")

            # Sign the manifest
            secret = manager.generate_signing_key()
            signed = manager.sign_manifest(manifest, secret)

            # Verify integrity
            result = manager.verify_manifest(signed, package)
            if result["is_valid"]:
                print("Evidence integrity verified")

            # Create chain of custody
            chain = manager.create_custody_chain(package.package_id)
            manager.record_custody_event(
                chain,
                action="CREATED",
                actor="auditor",
                details={"source": "automated_collection"}
            )
    """

    def __init__(
        self,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> None:
        """
        Initialize the integrity manager.

        Args:
            algorithm: Hash algorithm to use.
        """
        self._algorithm = algorithm

    def create_manifest(
        self,
        package: EvidencePackage,
        created_by: str = "system",
    ) -> IntegrityManifest:
        """
        Create an integrity manifest for an evidence package.

        Args:
            package: The evidence package.
            created_by: Who is creating the manifest.

        Returns:
            An IntegrityManifest with hashes of all evidence.
        """
        item_hashes: dict[str, str] = {}

        for item in package.items:
            item_hashes[item.evidence_id] = self._hash_item(item)

        root_hash = self._calculate_root_hash(item_hashes)

        manifest = IntegrityManifest(
            manifest_id=generate_uuid(),
            package_id=package.package_id,
            created_at=utc_now(),
            created_by=created_by,
            algorithm=self._algorithm,
            item_hashes=item_hashes,
            root_hash=root_hash,
        )

        logger.info(
            f"Created manifest {manifest.manifest_id} for package {package.package_id}"
        )

        return manifest

    def sign_manifest(
        self,
        manifest: IntegrityManifest,
        signing_key: bytes,
    ) -> IntegrityManifest:
        """
        Sign a manifest with HMAC.

        Args:
            manifest: The manifest to sign.
            signing_key: The HMAC signing key.

        Returns:
            The manifest with signature added.
        """
        # Create signature content
        content = {
            "manifest_id": manifest.manifest_id,
            "package_id": manifest.package_id,
            "root_hash": manifest.root_hash,
            "item_hashes": manifest.item_hashes,
            "algorithm": manifest.algorithm.value,
        }
        content_str = json.dumps(content, sort_keys=True)

        # Calculate HMAC
        hmac_digest = hmac.new(
            signing_key,
            content_str.encode(),
            hashlib.sha256,
        ).digest()

        manifest.signature = base64.b64encode(hmac_digest).decode()
        manifest.signature_type = SignatureType.HMAC

        logger.info(f"Signed manifest {manifest.manifest_id}")

        return manifest

    def verify_manifest(
        self,
        manifest: IntegrityManifest,
        package: EvidencePackage,
        signing_key: bytes | None = None,
    ) -> dict[str, Any]:
        """
        Verify the integrity of a manifest against an evidence package.

        Args:
            manifest: The manifest to verify.
            package: The evidence package.
            signing_key: The signing key (if manifest is signed).

        Returns:
            Verification results.
        """
        issues = []
        verified_items = 0

        # Verify each item hash
        for item in package.items:
            expected_hash = manifest.item_hashes.get(item.evidence_id)
            if expected_hash is None:
                issues.append({
                    "type": "missing_from_manifest",
                    "evidence_id": item.evidence_id,
                })
            else:
                actual_hash = self._hash_item(item)
                if actual_hash != expected_hash:
                    issues.append({
                        "type": "hash_mismatch",
                        "evidence_id": item.evidence_id,
                        "expected": expected_hash,
                        "actual": actual_hash,
                    })
                else:
                    verified_items += 1

        # Check for items in manifest but not in package
        package_ids = {item.evidence_id for item in package.items}
        for evidence_id in manifest.item_hashes:
            if evidence_id not in package_ids:
                issues.append({
                    "type": "extra_in_manifest",
                    "evidence_id": evidence_id,
                })

        # Verify root hash
        expected_root = self._calculate_root_hash(manifest.item_hashes)
        if manifest.root_hash != expected_root:
            issues.append({
                "type": "root_hash_mismatch",
                "expected": expected_root,
                "actual": manifest.root_hash,
            })

        # Verify signature if present and key provided
        if manifest.signature_type == SignatureType.HMAC:
            if signing_key is None:
                issues.append({
                    "type": "signature_not_verified",
                    "reason": "signing_key_not_provided",
                })
            else:
                if not self._verify_signature(manifest, signing_key):
                    issues.append({
                        "type": "signature_invalid",
                    })

        return {
            "manifest_id": manifest.manifest_id,
            "package_id": manifest.package_id,
            "verified_at": utc_now().isoformat(),
            "is_valid": len(issues) == 0,
            "total_items": len(package.items),
            "verified_items": verified_items,
            "signature_verified": (
                manifest.signature_type == SignatureType.HMAC
                and signing_key is not None
                and self._verify_signature(manifest, signing_key)
            ),
            "issues": issues,
        }

    def create_custody_chain(
        self,
        package_id: str,
    ) -> CustodyChain:
        """
        Create a new chain of custody for a package.

        Args:
            package_id: The package ID.

        Returns:
            A new CustodyChain.
        """
        chain = CustodyChain(
            chain_id=generate_uuid(),
            package_id=package_id,
            created_at=utc_now(),
            algorithm=self._algorithm,
        )

        logger.info(f"Created custody chain {chain.chain_id} for package {package_id}")

        return chain

    def record_custody_event(
        self,
        chain: CustodyChain,
        action: str,
        actor: str,
        details: dict[str, Any] | None = None,
    ) -> CustodyEvent:
        """
        Record an event in the custody chain.

        Args:
            chain: The custody chain.
            action: The action being recorded.
            actor: Who performed the action.
            details: Additional details.

        Returns:
            The created custody event.
        """
        event = chain.add_event(action, actor, details)

        logger.debug(
            f"Recorded custody event {event.event_id}: {action} by {actor}"
        )

        return event

    def generate_signing_key(self) -> bytes:
        """
        Generate a new random signing key.

        Returns:
            A 32-byte random key.
        """
        return secrets.token_bytes(32)

    def export_key(self, key: bytes) -> str:
        """
        Export a signing key as base64.

        Args:
            key: The key bytes.

        Returns:
            Base64-encoded key string.
        """
        return base64.b64encode(key).decode()

    def import_key(self, key_str: str) -> bytes:
        """
        Import a signing key from base64.

        Args:
            key_str: Base64-encoded key string.

        Returns:
            The key bytes.
        """
        return base64.b64decode(key_str)

    def create_tamper_evident_package(
        self,
        package: EvidencePackage,
        created_by: str = "system",
        signing_key: bytes | None = None,
    ) -> dict[str, Any]:
        """
        Create a complete tamper-evident package.

        Combines the evidence package, integrity manifest, and custody chain
        into a single verifiable package.

        Args:
            package: The evidence package.
            created_by: Who is creating the package.
            signing_key: Optional signing key for HMAC.

        Returns:
            A dictionary containing all components.
        """
        # Create manifest
        manifest = self.create_manifest(package, created_by)

        # Sign if key provided
        if signing_key:
            manifest = self.sign_manifest(manifest, signing_key)

        # Create custody chain with initial event
        chain = self.create_custody_chain(package.package_id)
        self.record_custody_event(
            chain,
            action="PACKAGE_CREATED",
            actor=created_by,
            details={
                "item_count": len(package.items),
                "period_start": package.period_start.isoformat(),
                "period_end": package.period_end.isoformat(),
                "signed": signing_key is not None,
            },
        )

        return {
            "package": package.to_dict(),
            "manifest": manifest.to_dict(),
            "custody_chain": chain.to_dict(),
            "created_at": utc_now().isoformat(),
            "created_by": created_by,
        }

    def verify_tamper_evident_package(
        self,
        tamper_evident: dict[str, Any],
        signing_key: bytes | None = None,
    ) -> dict[str, Any]:
        """
        Verify a complete tamper-evident package.

        Args:
            tamper_evident: The package to verify.
            signing_key: The signing key if package was signed.

        Returns:
            Comprehensive verification results.
        """
        issues = []

        # Reconstruct package from dict
        package_dict = tamper_evident.get("package", {})
        manifest_dict = tamper_evident.get("manifest", {})
        chain_dict = tamper_evident.get("custody_chain", {})

        # Verify package integrity
        package_checksum = package_dict.get("manifest_checksum", "")
        items = package_dict.get("items", [])

        # Reconstruct items to verify checksums
        for item_dict in items:
            content = item_dict.get("content", {})
            content_str = json.dumps(content, sort_keys=True, default=str)
            expected_checksum = hashlib.sha256(content_str.encode()).hexdigest()
            actual_checksum = item_dict.get("checksum", "")

            if expected_checksum != actual_checksum:
                issues.append({
                    "component": "package",
                    "type": "item_checksum_mismatch",
                    "evidence_id": item_dict.get("evidence_id"),
                })

        # Verify manifest root hash
        item_hashes = manifest_dict.get("item_hashes", {})
        expected_root = self._calculate_root_hash(item_hashes)
        actual_root = manifest_dict.get("root_hash", "")

        if expected_root != actual_root:
            issues.append({
                "component": "manifest",
                "type": "root_hash_mismatch",
            })

        # Verify signature if present
        if manifest_dict.get("signature_type") == "hmac":
            if signing_key is None:
                issues.append({
                    "component": "manifest",
                    "type": "signature_not_verified",
                })
            else:
                # Reconstruct manifest for verification
                content = {
                    "manifest_id": manifest_dict.get("manifest_id"),
                    "package_id": manifest_dict.get("package_id"),
                    "root_hash": manifest_dict.get("root_hash"),
                    "item_hashes": manifest_dict.get("item_hashes"),
                    "algorithm": manifest_dict.get("algorithm"),
                }
                content_str = json.dumps(content, sort_keys=True)

                expected_sig = hmac.new(
                    signing_key,
                    content_str.encode(),
                    hashlib.sha256,
                ).digest()
                expected_sig_b64 = base64.b64encode(expected_sig).decode()

                if manifest_dict.get("signature") != expected_sig_b64:
                    issues.append({
                        "component": "manifest",
                        "type": "signature_invalid",
                    })

        # Verify custody chain
        events = chain_dict.get("events", [])
        for i, event in enumerate(events):
            # Verify event hash
            event_content = {
                "event_id": event.get("event_id"),
                "timestamp": event.get("timestamp"),
                "action": event.get("action"),
                "actor": event.get("actor"),
                "details": event.get("details"),
                "previous_hash": event.get("previous_hash"),
            }
            content_str = json.dumps(event_content, sort_keys=True, default=str)
            expected_hash = hashlib.sha256(content_str.encode()).hexdigest()

            if event.get("event_hash") != expected_hash:
                issues.append({
                    "component": "custody_chain",
                    "type": "event_hash_mismatch",
                    "event_id": event.get("event_id"),
                })

            # Verify chain linkage
            if i > 0:
                expected_previous = events[i - 1].get("event_hash")
                if event.get("previous_hash") != expected_previous:
                    issues.append({
                        "component": "custody_chain",
                        "type": "chain_linkage_broken",
                        "event_id": event.get("event_id"),
                    })

        return {
            "verified_at": utc_now().isoformat(),
            "is_valid": len(issues) == 0,
            "package_id": package_dict.get("package_id"),
            "manifest_id": manifest_dict.get("manifest_id"),
            "chain_id": chain_dict.get("chain_id"),
            "item_count": len(items),
            "event_count": len(events),
            "issues": issues,
        }

    def _hash_item(self, item: EvidenceItem) -> str:
        """Hash an evidence item using the configured algorithm."""
        content_str = json.dumps(item.content, sort_keys=True, default=str)

        if self._algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(content_str.encode()).hexdigest()
        elif self._algorithm == HashAlgorithm.SHA384:
            return hashlib.sha384(content_str.encode()).hexdigest()
        elif self._algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(content_str.encode()).hexdigest()
        else:
            return hashlib.sha256(content_str.encode()).hexdigest()

    def _calculate_root_hash(self, item_hashes: dict[str, str]) -> str:
        """Calculate a Merkle root hash from item hashes."""
        if not item_hashes:
            return hashlib.sha256(b"empty").hexdigest()

        # Sort hashes for deterministic ordering
        sorted_hashes = [
            item_hashes[key] for key in sorted(item_hashes.keys())
        ]

        # Simple concatenation-based root (simplified Merkle)
        combined = "".join(sorted_hashes)

        if self._algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(combined.encode()).hexdigest()
        elif self._algorithm == HashAlgorithm.SHA384:
            return hashlib.sha384(combined.encode()).hexdigest()
        elif self._algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(combined.encode()).hexdigest()
        else:
            return hashlib.sha256(combined.encode()).hexdigest()

    def _verify_signature(
        self,
        manifest: IntegrityManifest,
        signing_key: bytes,
    ) -> bool:
        """Verify an HMAC signature."""
        content = {
            "manifest_id": manifest.manifest_id,
            "package_id": manifest.package_id,
            "root_hash": manifest.root_hash,
            "item_hashes": manifest.item_hashes,
            "algorithm": manifest.algorithm.value,
        }
        content_str = json.dumps(content, sort_keys=True)

        expected_digest = hmac.new(
            signing_key,
            content_str.encode(),
            hashlib.sha256,
        ).digest()

        try:
            actual_digest = base64.b64decode(manifest.signature)
            return hmac.compare_digest(expected_digest, actual_digest)
        except Exception:
            return False


# Convenience functions for common operations


def create_evidence_hash(content: Any, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
    """
    Create a hash of evidence content.

    Args:
        content: The content to hash.
        algorithm: Hash algorithm to use.

    Returns:
        The hex-encoded hash.
    """
    content_str = json.dumps(content, sort_keys=True, default=str)

    if algorithm == HashAlgorithm.SHA256:
        return hashlib.sha256(content_str.encode()).hexdigest()
    elif algorithm == HashAlgorithm.SHA384:
        return hashlib.sha384(content_str.encode()).hexdigest()
    elif algorithm == HashAlgorithm.SHA512:
        return hashlib.sha512(content_str.encode()).hexdigest()
    else:
        return hashlib.sha256(content_str.encode()).hexdigest()


def verify_evidence_hash(
    content: Any,
    expected_hash: str,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> bool:
    """
    Verify a hash against content.

    Args:
        content: The content to verify.
        expected_hash: The expected hash.
        algorithm: Hash algorithm used.

    Returns:
        True if the hash matches.
    """
    actual_hash = create_evidence_hash(content, algorithm)
    return hmac.compare_digest(actual_hash, expected_hash)
