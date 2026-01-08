"""
Evidence collection and export for PolicyBind.

This module provides functionality to collect and package audit evidence
for compliance purposes, including enforcement decisions, incident records,
policy configurations, and approval records.
"""

import hashlib
import io
import json
import logging
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from policybind.models.base import generate_uuid, utc_now

if TYPE_CHECKING:
    from policybind.incidents import IncidentManager
    from policybind.storage import AuditRepository, PolicyRepository, RegistryRepository

logger = logging.getLogger("policybind.reports.evidence")


class EvidenceType(Enum):
    """Types of evidence that can be collected."""

    POLICY_CONFIGURATION = "policy_configuration"
    """Active policy configurations during the period."""

    ENFORCEMENT_DECISION = "enforcement_decision"
    """Individual enforcement decisions and their details."""

    INCIDENT_RECORD = "incident_record"
    """Incident reports and their resolutions."""

    APPROVAL_RECORD = "approval_record"
    """Model deployment approval records."""

    CONFIGURATION_CHANGE = "configuration_change"
    """Policy and system configuration changes."""

    AUDIT_LOG = "audit_log"
    """General audit log entries."""


class EvidenceFormat(Enum):
    """Output formats for evidence packages."""

    JSON = "json"
    """Structured JSON for machine processing."""

    ZIP = "zip"
    """ZIP archive with organized files."""


@dataclass
class EvidenceItem:
    """
    A single piece of evidence.

    Attributes:
        evidence_id: Unique identifier for this evidence item.
        evidence_type: Type of evidence.
        timestamp: When the evidence was recorded.
        source: Where the evidence came from.
        content: The actual evidence data.
        checksum: SHA-256 hash of the content.
        metadata: Additional context about the evidence.
    """

    evidence_id: str
    evidence_type: EvidenceType
    timestamp: datetime
    source: str
    content: dict[str, Any]
    checksum: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Calculate checksum if not provided."""
        if not self.checksum:
            content_str = json.dumps(self.content, sort_keys=True, default=str)
            self.checksum = hashlib.sha256(content_str.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "content": self.content,
            "checksum": self.checksum,
            "metadata": self.metadata,
        }


@dataclass
class EvidencePackage:
    """
    A package of collected evidence.

    Attributes:
        package_id: Unique identifier for this package.
        created_at: When the package was created.
        created_by: Who created the package.
        period_start: Start of the evidence collection period.
        period_end: End of the evidence collection period.
        scope: Description of what evidence was collected.
        items: List of evidence items.
        manifest_checksum: Checksum of the manifest.
        metadata: Additional package metadata.
    """

    package_id: str
    created_at: datetime
    created_by: str
    period_start: datetime
    period_end: datetime
    scope: dict[str, Any]
    items: list[EvidenceItem] = field(default_factory=list)
    manifest_checksum: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def calculate_manifest_checksum(self) -> str:
        """Calculate a checksum of the entire manifest."""
        manifest = {
            "package_id": self.package_id,
            "created_at": self.created_at.isoformat(),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "item_checksums": [item.checksum for item in self.items],
        }
        manifest_str = json.dumps(manifest, sort_keys=True)
        return hashlib.sha256(manifest_str.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "package_id": self.package_id,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "scope": self.scope,
            "item_count": len(self.items),
            "items": [item.to_dict() for item in self.items],
            "manifest_checksum": self.manifest_checksum,
            "metadata": self.metadata,
        }

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of the package without all items."""
        type_counts: dict[str, int] = {}
        for item in self.items:
            type_name = item.evidence_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "package_id": self.package_id,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "scope": self.scope,
            "item_count": len(self.items),
            "items_by_type": type_counts,
            "manifest_checksum": self.manifest_checksum,
        }


@dataclass
class CollectionScope:
    """
    Defines what evidence to collect.

    Attributes:
        deployment_id: Filter by specific deployment.
        user_id: Filter by specific user.
        department: Filter by specific department.
        include_policies: Include policy configurations.
        include_enforcement: Include enforcement decisions.
        include_incidents: Include incident records.
        include_approvals: Include approval records.
        include_changes: Include configuration changes.
    """

    deployment_id: str | None = None
    user_id: str | None = None
    department: str | None = None
    include_policies: bool = True
    include_enforcement: bool = True
    include_incidents: bool = True
    include_approvals: bool = True
    include_changes: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "user_id": self.user_id,
            "department": self.department,
            "include_policies": self.include_policies,
            "include_enforcement": self.include_enforcement,
            "include_incidents": self.include_incidents,
            "include_approvals": self.include_approvals,
            "include_changes": self.include_changes,
        }


class EvidenceCollector:
    """
    Collects evidence from PolicyBind systems for audit purposes.

    The EvidenceCollector gathers evidence from various sources and packages
    it in formats suitable for auditors and compliance reviews.

    Example:
        Using the EvidenceCollector::

            from policybind.reports.evidence import EvidenceCollector, CollectionScope
            from datetime import datetime, timedelta

            collector = EvidenceCollector(
                policy_repository=policy_repo,
                audit_repository=audit_repo,
                registry_repository=registry_repo,
                incident_manager=incident_manager,
            )

            # Define collection scope
            scope = CollectionScope(
                deployment_id="deploy-123",
                include_policies=True,
                include_enforcement=True,
                include_incidents=True,
            )

            # Collect evidence for the last 30 days
            package = collector.collect(
                start_date=datetime.now() - timedelta(days=30),
                end_date=datetime.now(),
                scope=scope,
                created_by="auditor@example.com",
            )

            # Export as JSON
            json_output = collector.export_json(package)

            # Export as ZIP archive
            collector.export_zip(package, "/path/to/output.zip")
    """

    def __init__(
        self,
        policy_repository: "PolicyRepository | None" = None,
        audit_repository: "AuditRepository | None" = None,
        registry_repository: "RegistryRepository | None" = None,
        incident_manager: "IncidentManager | None" = None,
    ) -> None:
        """
        Initialize the evidence collector.

        Args:
            policy_repository: Repository for policy data.
            audit_repository: Repository for audit logs.
            registry_repository: Repository for registry data.
            incident_manager: Manager for incident data.
        """
        self._policy_repo = policy_repository
        self._audit_repo = audit_repository
        self._registry_repo = registry_repository
        self._incident_manager = incident_manager

    def collect(
        self,
        start_date: datetime,
        end_date: datetime,
        scope: CollectionScope | None = None,
        created_by: str = "system",
        metadata: dict[str, Any] | None = None,
    ) -> EvidencePackage:
        """
        Collect evidence for the specified period and scope.

        Args:
            start_date: Start of the collection period.
            end_date: End of the collection period.
            scope: What evidence to collect.
            created_by: Who is creating the package.
            metadata: Additional metadata.

        Returns:
            An EvidencePackage containing all collected evidence.
        """
        if scope is None:
            scope = CollectionScope()

        package = EvidencePackage(
            package_id=generate_uuid(),
            created_at=utc_now(),
            created_by=created_by,
            period_start=start_date,
            period_end=end_date,
            scope=scope.to_dict(),
            metadata=metadata or {},
        )

        logger.info(
            f"Collecting evidence from {start_date} to {end_date} "
            f"(package {package.package_id})"
        )

        # Collect each type of evidence
        if scope.include_policies:
            self._collect_policies(package, start_date, end_date, scope)

        if scope.include_enforcement:
            self._collect_enforcement(package, start_date, end_date, scope)

        if scope.include_incidents:
            self._collect_incidents(package, start_date, end_date, scope)

        if scope.include_approvals:
            self._collect_approvals(package, start_date, end_date, scope)

        if scope.include_changes:
            self._collect_changes(package, start_date, end_date, scope)

        # Calculate the manifest checksum
        package.manifest_checksum = package.calculate_manifest_checksum()

        logger.info(
            f"Collected {len(package.items)} evidence items "
            f"(checksum: {package.manifest_checksum[:16]}...)"
        )

        return package

    def _collect_policies(
        self,
        package: EvidencePackage,
        start_date: datetime,
        end_date: datetime,
        scope: CollectionScope,
    ) -> None:
        """Collect policy configuration evidence."""
        if not self._policy_repo:
            logger.debug("No policy repository configured, skipping policies")
            return

        try:
            # Get all active policies
            policies = self._policy_repo.get_active()

            for policy in policies:
                item = EvidenceItem(
                    evidence_id=generate_uuid(),
                    evidence_type=EvidenceType.POLICY_CONFIGURATION,
                    timestamp=utc_now(),
                    source="policy_repository",
                    content={
                        "policy_id": policy.get("id"),
                        "name": policy.get("name"),
                        "version": policy.get("version"),
                        "description": policy.get("description"),
                        "is_active": policy.get("is_active"),
                        "created_at": policy.get("created_at"),
                        "created_by": policy.get("created_by"),
                        "content_hash": self._hash_content(policy.get("content", {})),
                    },
                    metadata={
                        "collection_period_start": start_date.isoformat(),
                        "collection_period_end": end_date.isoformat(),
                    },
                )
                package.items.append(item)

            logger.debug(f"Collected {len(policies)} policy configurations")

        except Exception as e:
            logger.error(f"Error collecting policies: {e}")

    def _collect_enforcement(
        self,
        package: EvidencePackage,
        start_date: datetime,
        end_date: datetime,
        scope: CollectionScope,
    ) -> None:
        """Collect enforcement decision evidence."""
        if not self._audit_repo:
            logger.debug("No audit repository configured, skipping enforcement")
            return

        try:
            logs = self._audit_repo.query_enforcement_logs(
                start_date=start_date,
                end_date=end_date,
                user_id=scope.user_id,
                department=scope.department,
                deployment_id=scope.deployment_id,
                limit=10000,  # High limit for audit purposes
            )

            for log in logs:
                item = EvidenceItem(
                    evidence_id=generate_uuid(),
                    evidence_type=EvidenceType.ENFORCEMENT_DECISION,
                    timestamp=self._parse_timestamp(log.get("timestamp")),
                    source="enforcement_log",
                    content={
                        "log_id": log.get("id"),
                        "request_id": log.get("request_id"),
                        "timestamp": log.get("timestamp"),
                        "provider": log.get("provider"),
                        "model": log.get("model"),
                        "user_id": log.get("user_id"),
                        "department": log.get("department"),
                        "decision": log.get("decision"),
                        "applied_rules": log.get("applied_rules"),
                        "reason": log.get("reason"),
                        "deployment_id": log.get("deployment_id"),
                        "estimated_tokens": log.get("estimated_tokens"),
                        "estimated_cost": log.get("estimated_cost"),
                        "enforcement_time_ms": log.get("enforcement_time_ms"),
                        "warnings": log.get("warnings"),
                    },
                )
                package.items.append(item)

            logger.debug(f"Collected {len(logs)} enforcement decisions")

        except Exception as e:
            logger.error(f"Error collecting enforcement logs: {e}")

    def _collect_incidents(
        self,
        package: EvidencePackage,
        start_date: datetime,
        end_date: datetime,
        scope: CollectionScope,
    ) -> None:
        """Collect incident record evidence."""
        if not self._incident_manager:
            logger.debug("No incident manager configured, skipping incidents")
            return

        try:
            # Get incidents for the period
            incidents = self._incident_manager.list_incidents(
                start_date=start_date,
                end_date=end_date,
                deployment_id=scope.deployment_id,
            )

            for incident in incidents:
                # Get incident as dict
                if hasattr(incident, "to_dict"):
                    incident_data = incident.to_dict()
                else:
                    incident_data = incident

                item = EvidenceItem(
                    evidence_id=generate_uuid(),
                    evidence_type=EvidenceType.INCIDENT_RECORD,
                    timestamp=self._parse_timestamp(incident_data.get("created_at")),
                    source="incident_manager",
                    content={
                        "incident_id": incident_data.get("incident_id"),
                        "title": incident_data.get("title"),
                        "description": incident_data.get("description"),
                        "severity": incident_data.get("severity"),
                        "status": incident_data.get("status"),
                        "incident_type": incident_data.get("incident_type"),
                        "created_at": incident_data.get("created_at"),
                        "resolved_at": incident_data.get("resolved_at"),
                        "closed_at": incident_data.get("closed_at"),
                        "assigned_to": incident_data.get("assigned_to"),
                        "resolution": incident_data.get("resolution"),
                        "root_cause": incident_data.get("root_cause"),
                        "related_request_id": incident_data.get("related_request_id"),
                        "related_deployment_id": incident_data.get("related_deployment_id"),
                        "tags": incident_data.get("tags"),
                    },
                    metadata={
                        "timeline_count": len(incident_data.get("timeline", [])),
                        "comment_count": len(incident_data.get("comments", [])),
                    },
                )
                package.items.append(item)

            logger.debug(f"Collected {len(incidents)} incident records")

        except Exception as e:
            logger.error(f"Error collecting incidents: {e}")

    def _collect_approvals(
        self,
        package: EvidencePackage,
        start_date: datetime,
        end_date: datetime,
        scope: CollectionScope,
    ) -> None:
        """Collect approval record evidence."""
        if not self._registry_repo:
            logger.debug("No registry repository configured, skipping approvals")
            return

        try:
            # Get all deployments (optionally filtered by ID)
            if scope.deployment_id:
                deployment = self._registry_repo.get_by_id(scope.deployment_id)
                deployments = [deployment] if deployment else []
            else:
                deployments = self._registry_repo.list_all(limit=1000)

            for deployment in deployments:
                item = EvidenceItem(
                    evidence_id=generate_uuid(),
                    evidence_type=EvidenceType.APPROVAL_RECORD,
                    timestamp=self._parse_timestamp(deployment.get("created_at")),
                    source="registry_repository",
                    content={
                        "deployment_id": deployment.get("deployment_id"),
                        "name": deployment.get("name"),
                        "description": deployment.get("description"),
                        "model_provider": deployment.get("model_provider"),
                        "model_name": deployment.get("model_name"),
                        "model_version": deployment.get("model_version"),
                        "owner": deployment.get("owner"),
                        "owner_contact": deployment.get("owner_contact"),
                        "risk_level": deployment.get("risk_level"),
                        "approval_status": deployment.get("approval_status"),
                        "approval_ticket": deployment.get("approval_ticket"),
                        "deployment_date": deployment.get("deployment_date"),
                        "last_review_date": deployment.get("last_review_date"),
                        "next_review_date": deployment.get("next_review_date"),
                        "data_categories": deployment.get("data_categories"),
                        "created_at": deployment.get("created_at"),
                        "updated_at": deployment.get("updated_at"),
                    },
                )
                package.items.append(item)

            logger.debug(f"Collected {len(deployments)} approval records")

        except Exception as e:
            logger.error(f"Error collecting approvals: {e}")

    def _collect_changes(
        self,
        package: EvidencePackage,
        start_date: datetime,
        end_date: datetime,
        scope: CollectionScope,
    ) -> None:
        """Collect configuration change evidence."""
        if not self._policy_repo:
            logger.debug("No policy repository configured, skipping changes")
            return

        try:
            # Get policy history (if available)
            if hasattr(self._policy_repo, "get_history"):
                history = self._policy_repo.get_history(
                    start_date=start_date,
                    end_date=end_date,
                )

                for entry in history:
                    item = EvidenceItem(
                        evidence_id=generate_uuid(),
                        evidence_type=EvidenceType.CONFIGURATION_CHANGE,
                        timestamp=self._parse_timestamp(entry.get("timestamp")),
                        source="policy_history",
                        content={
                            "policy_id": entry.get("policy_id"),
                            "policy_name": entry.get("policy_name"),
                            "action": entry.get("action"),
                            "version_before": entry.get("version_before"),
                            "version_after": entry.get("version_after"),
                            "changed_by": entry.get("changed_by"),
                            "timestamp": entry.get("timestamp"),
                            "changes_summary": entry.get("changes_summary"),
                        },
                    )
                    package.items.append(item)

                logger.debug(f"Collected {len(history)} configuration changes")

        except Exception as e:
            logger.error(f"Error collecting configuration changes: {e}")

    def export_json(
        self,
        package: EvidencePackage,
        pretty: bool = True,
    ) -> str:
        """
        Export an evidence package as JSON.

        Args:
            package: The evidence package to export.
            pretty: Whether to format the JSON.

        Returns:
            JSON string representation of the package.
        """
        indent = 2 if pretty else None
        return json.dumps(package.to_dict(), indent=indent, default=str)

    def export_zip(
        self,
        package: EvidencePackage,
        output_path: str | Path,
    ) -> str:
        """
        Export an evidence package as a ZIP archive.

        The archive structure:
        - manifest.json: Package metadata and checksums
        - summary.json: Package summary without full content
        - evidence/: Directory containing individual evidence files
          - policies/: Policy configuration evidence
          - enforcement/: Enforcement decision evidence
          - incidents/: Incident record evidence
          - approvals/: Approval record evidence
          - changes/: Configuration change evidence

        Args:
            package: The evidence package to export.
            output_path: Where to save the ZIP file.

        Returns:
            The path to the created ZIP file.
        """
        output_path = Path(output_path)

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write manifest
            manifest = {
                "package_id": package.package_id,
                "created_at": package.created_at.isoformat(),
                "created_by": package.created_by,
                "period_start": package.period_start.isoformat(),
                "period_end": package.period_end.isoformat(),
                "scope": package.scope,
                "item_count": len(package.items),
                "manifest_checksum": package.manifest_checksum,
                "metadata": package.metadata,
                "items": [
                    {
                        "evidence_id": item.evidence_id,
                        "evidence_type": item.evidence_type.value,
                        "checksum": item.checksum,
                        "file_path": self._get_evidence_path(item),
                    }
                    for item in package.items
                ],
            }
            zf.writestr(
                "manifest.json",
                json.dumps(manifest, indent=2, default=str),
            )

            # Write summary
            zf.writestr(
                "summary.json",
                json.dumps(package.get_summary(), indent=2, default=str),
            )

            # Write individual evidence files
            for item in package.items:
                file_path = self._get_evidence_path(item)
                zf.writestr(
                    file_path,
                    json.dumps(item.to_dict(), indent=2, default=str),
                )

            # Write verification instructions
            verification_doc = self._create_verification_doc(package)
            zf.writestr("VERIFICATION.md", verification_doc)

        logger.info(f"Exported evidence package to {output_path}")
        return str(output_path)

    def export_to_bytes(self, package: EvidencePackage) -> bytes:
        """
        Export an evidence package as ZIP bytes (in-memory).

        Args:
            package: The evidence package to export.

        Returns:
            ZIP archive as bytes.
        """
        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write manifest
            manifest = {
                "package_id": package.package_id,
                "created_at": package.created_at.isoformat(),
                "created_by": package.created_by,
                "period_start": package.period_start.isoformat(),
                "period_end": package.period_end.isoformat(),
                "scope": package.scope,
                "item_count": len(package.items),
                "manifest_checksum": package.manifest_checksum,
                "metadata": package.metadata,
            }
            zf.writestr(
                "manifest.json",
                json.dumps(manifest, indent=2, default=str),
            )

            # Write summary
            zf.writestr(
                "summary.json",
                json.dumps(package.get_summary(), indent=2, default=str),
            )

            # Write individual evidence files
            for item in package.items:
                file_path = self._get_evidence_path(item)
                zf.writestr(
                    file_path,
                    json.dumps(item.to_dict(), indent=2, default=str),
                )

        return buffer.getvalue()

    def verify_package(self, package: EvidencePackage) -> dict[str, Any]:
        """
        Verify the integrity of an evidence package.

        Args:
            package: The evidence package to verify.

        Returns:
            Verification results with any integrity issues found.
        """
        issues = []
        verified_items = 0

        # Verify each item's checksum
        for item in package.items:
            content_str = json.dumps(item.content, sort_keys=True, default=str)
            expected_checksum = hashlib.sha256(content_str.encode()).hexdigest()

            if item.checksum != expected_checksum:
                issues.append({
                    "type": "checksum_mismatch",
                    "evidence_id": item.evidence_id,
                    "expected": expected_checksum,
                    "actual": item.checksum,
                })
            else:
                verified_items += 1

        # Verify manifest checksum
        expected_manifest = package.calculate_manifest_checksum()
        if package.manifest_checksum != expected_manifest:
            issues.append({
                "type": "manifest_checksum_mismatch",
                "expected": expected_manifest,
                "actual": package.manifest_checksum,
            })

        return {
            "package_id": package.package_id,
            "verified_at": utc_now().isoformat(),
            "is_valid": len(issues) == 0,
            "total_items": len(package.items),
            "verified_items": verified_items,
            "issues": issues,
        }

    def _get_evidence_path(self, item: EvidenceItem) -> str:
        """Get the file path for an evidence item in the ZIP archive."""
        type_dirs = {
            EvidenceType.POLICY_CONFIGURATION: "evidence/policies",
            EvidenceType.ENFORCEMENT_DECISION: "evidence/enforcement",
            EvidenceType.INCIDENT_RECORD: "evidence/incidents",
            EvidenceType.APPROVAL_RECORD: "evidence/approvals",
            EvidenceType.CONFIGURATION_CHANGE: "evidence/changes",
            EvidenceType.AUDIT_LOG: "evidence/audit_logs",
        }
        directory = type_dirs.get(item.evidence_type, "evidence/other")
        return f"{directory}/{item.evidence_id}.json"

    def _hash_content(self, content: Any) -> str:
        """Generate a hash of content for tracking."""
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def _parse_timestamp(self, value: str | datetime | None) -> datetime:
        """Parse a timestamp value to datetime."""
        if value is None:
            return utc_now()
        if isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)

    def _create_verification_doc(self, package: EvidencePackage) -> str:
        """Create a verification documentation file."""
        return f"""# Evidence Package Verification

## Package Information
- **Package ID:** {package.package_id}
- **Created At:** {package.created_at.isoformat()}
- **Created By:** {package.created_by}
- **Period:** {package.period_start.isoformat()} to {package.period_end.isoformat()}
- **Total Items:** {len(package.items)}
- **Manifest Checksum:** {package.manifest_checksum}

## Verification Instructions

### 1. Verify Manifest Checksum

The manifest checksum is a SHA-256 hash of the package metadata and all item checksums.
To verify:

1. Extract the manifest.json file
2. Compute the SHA-256 hash of the manifest structure
3. Compare with the manifest_checksum field

### 2. Verify Individual Evidence Items

Each evidence item has a checksum of its content:

1. Extract each evidence JSON file from the evidence/ directory
2. Compute the SHA-256 hash of the "content" field
3. Compare with the "checksum" field in the evidence item

### 3. Cross-Reference with Source Systems

For complete verification, cross-reference evidence items with:
- PolicyBind enforcement logs
- Incident tracking system
- Model registry records
- Policy version control

## Integrity Statement

This evidence package was generated by PolicyBind and contains cryptographic
checksums for tamper detection. Any modification to the evidence content
will result in checksum verification failure.

## Contact

For questions about this evidence package, contact your PolicyBind administrator.
"""
