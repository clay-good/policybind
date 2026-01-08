"""
Registry manager for PolicyBind.

This module provides the RegistryManager class for managing the lifecycle
of AI model deployments in the registry.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from policybind.config.schema import RegistryConfig
from policybind.exceptions import RegistryError, ValidationError
from policybind.models.base import generate_uuid, utc_now
from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel
from policybind.registry.compliance import ComplianceChecker, ComplianceReport
from policybind.registry.risk import RiskAssessment, RiskAssessor
from policybind.registry.validator import DeploymentValidationResult, DeploymentValidator
from policybind.storage.repositories import RegistryRepository


class DeploymentEventType(Enum):
    """Types of deployment events."""

    REGISTERED = "registered"
    """A new deployment was registered."""

    UPDATED = "updated"
    """A deployment was updated."""

    APPROVED = "approved"
    """A deployment was approved."""

    REJECTED = "rejected"
    """A deployment was rejected."""

    SUSPENDED = "suspended"
    """A deployment was suspended."""

    REINSTATED = "reinstated"
    """A suspended deployment was reinstated."""

    DELETED = "deleted"
    """A deployment was deleted."""

    REVIEW_DUE = "review_due"
    """A deployment is due for review."""

    VIOLATION = "violation"
    """A policy violation was recorded."""


@dataclass
class DeploymentEvent:
    """
    An event that occurred on a deployment.

    Attributes:
        event_id: Unique identifier for the event.
        event_type: Type of event.
        deployment_id: ID of the deployment.
        timestamp: When the event occurred.
        actor: Who triggered the event.
        details: Additional event details.
        metadata: Extra metadata.
    """

    event_id: str
    event_type: DeploymentEventType
    deployment_id: str
    timestamp: datetime
    actor: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "deployment_id": self.deployment_id,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "details": self.details,
            "metadata": self.metadata,
        }


# Type alias for event callbacks
EventCallback = Callable[[DeploymentEvent], None]


class RegistryManager:
    """
    Manages the lifecycle of AI model deployments.

    The RegistryManager provides:
    - Registration of new deployments with validation
    - Updating deployment metadata and status
    - Querying deployments by various criteria
    - Enforcement of business rules
    - Event emission on status changes

    Example:
        Managing deployments::

            manager = RegistryManager(repository)

            # Register a new deployment
            deployment = manager.register(
                name="Customer Support Bot",
                model_provider="openai",
                model_name="gpt-4",
                owner="team-support",
                owner_contact="support@example.com",
            )

            # Approve the deployment
            manager.approve(deployment.deployment_id, approved_by="admin")

            # Query deployments
            pending = manager.find_pending()
    """

    def __init__(
        self,
        repository: RegistryRepository | None = None,
        config: RegistryConfig | None = None,
        validator: DeploymentValidator | None = None,
        risk_assessor: RiskAssessor | None = None,
        compliance_checker: ComplianceChecker | None = None,
    ) -> None:
        """
        Initialize the registry manager.

        Args:
            repository: Repository for persistence. If None, uses in-memory.
            config: Registry configuration.
            validator: Custom deployment validator.
            risk_assessor: Custom risk assessor.
            compliance_checker: Custom compliance checker.
        """
        self._repository = repository
        self._config = config or RegistryConfig()
        self._validator = validator or DeploymentValidator()
        self._risk_assessor = risk_assessor or RiskAssessor()
        self._compliance_checker = compliance_checker or ComplianceChecker()

        # In-memory storage if no repository
        self._deployments: dict[str, ModelDeployment] = {}

        # Event callbacks
        self._event_callbacks: list[EventCallback] = []

        # Violation tracking (in-memory)
        self._violations: dict[str, int] = {}

    def on_event(self, callback: EventCallback) -> None:
        """
        Register a callback for deployment events.

        Args:
            callback: Function to call when events occur.
        """
        self._event_callbacks.append(callback)

    def register(
        self,
        name: str,
        model_provider: str,
        model_name: str,
        owner: str,
        owner_contact: str,
        description: str = "",
        model_version: str = "",
        data_categories: list[str] | None = None,
        risk_level: RiskLevel | None = None,
        metadata: dict[str, Any] | None = None,
        registered_by: str = "",
    ) -> ModelDeployment:
        """
        Register a new model deployment.

        Args:
            name: Deployment name.
            model_provider: AI provider (openai, anthropic, etc.).
            model_name: Model name.
            owner: Owner identifier.
            owner_contact: Owner contact info.
            description: Deployment description.
            model_version: Model version.
            data_categories: Data categories handled.
            risk_level: Risk level (auto-assessed if None).
            metadata: Additional metadata.
            registered_by: Who is registering.

        Returns:
            The created ModelDeployment.

        Raises:
            ValidationError: If validation fails.
            RegistryError: If registration fails.
        """
        deployment_id = generate_uuid()

        # Create deployment object
        deployment = ModelDeployment(
            deployment_id=deployment_id,
            name=name,
            description=description,
            model_provider=model_provider,
            model_name=model_name,
            model_version=model_version,
            owner=owner,
            owner_contact=owner_contact,
            data_categories=tuple(data_categories or []),
            risk_level=risk_level or RiskLevel.MEDIUM,
            approval_status=ApprovalStatus.PENDING,
            metadata=metadata or {},
        )

        # Validate
        validation_result = self._validator.validate(deployment)
        if not validation_result.valid:
            errors = "; ".join(e.message for e in validation_result.errors)
            raise ValidationError(f"Deployment validation failed: {errors}")

        # Auto-assess risk if not provided
        if risk_level is None:
            assessment = self._risk_assessor.assess(deployment)
            deployment = self._update_deployment_field(
                deployment, "risk_level", assessment.computed_risk_level
            )

        # Calculate next review date
        next_review = utc_now() + timedelta(
            days=self._config.default_review_interval_days
        )
        deployment = self._update_deployment_field(
            deployment, "next_review_date", next_review
        )

        # Store
        self._store_deployment(deployment)

        # Emit event
        self._emit_event(
            DeploymentEventType.REGISTERED,
            deployment.deployment_id,
            registered_by,
            {"name": name, "risk_level": deployment.risk_level.value},
        )

        return deployment

    def get(self, deployment_id: str) -> ModelDeployment | None:
        """
        Get a deployment by ID.

        Args:
            deployment_id: The deployment ID.

        Returns:
            The deployment, or None if not found.
        """
        if self._repository:
            data = self._repository.get_by_id(deployment_id)
            return self._dict_to_deployment(data) if data else None
        return self._deployments.get(deployment_id)

    def get_by_name(self, name: str) -> ModelDeployment | None:
        """
        Get a deployment by name.

        Args:
            name: The deployment name.

        Returns:
            The deployment, or None if not found.
        """
        if self._repository:
            data = self._repository.get_by_name(name)
            return self._dict_to_deployment(data) if data else None

        for deployment in self._deployments.values():
            if deployment.name == name:
                return deployment
        return None

    def update(
        self,
        deployment_id: str,
        updated_by: str = "",
        **updates: Any,
    ) -> ModelDeployment:
        """
        Update a deployment.

        Args:
            deployment_id: The deployment to update.
            updated_by: Who is making the update.
            **updates: Fields to update.

        Returns:
            The updated deployment.

        Raises:
            RegistryError: If deployment not found or update fails.
            ValidationError: If validation fails.
        """
        current = self.get(deployment_id)
        if not current:
            raise RegistryError(f"Deployment {deployment_id} not found")

        # Build updated deployment
        updated_fields = {}
        for field_name, value in updates.items():
            if hasattr(current, field_name):
                updated_fields[field_name] = value

        # Can't change certain fields
        immutable_fields = {"deployment_id", "id", "created_at"}
        for field_name in immutable_fields:
            if field_name in updated_fields:
                raise RegistryError(f"Cannot modify immutable field: {field_name}")

        # Create updated deployment
        updated = self._create_updated_deployment(current, updated_fields)

        # Validate update
        validation_result = self._validator.validate_for_update(current, updated)
        if not validation_result.valid:
            errors = "; ".join(e.message for e in validation_result.errors)
            raise ValidationError(f"Update validation failed: {errors}")

        # Check for risk level changes requiring re-approval
        if updated.risk_level != current.risk_level:
            risk_order = {
                RiskLevel.LOW: 0,
                RiskLevel.MEDIUM: 1,
                RiskLevel.HIGH: 2,
                RiskLevel.CRITICAL: 3,
            }
            if risk_order[updated.risk_level] > risk_order[current.risk_level]:
                if self._config.require_approval_for_high_risk:
                    if updated.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                        updated = self._update_deployment_field(
                            updated, "approval_status", ApprovalStatus.PENDING
                        )

        # Store
        self._store_deployment(updated)

        # Emit event
        self._emit_event(
            DeploymentEventType.UPDATED,
            deployment_id,
            updated_by,
            {"changes": list(updates.keys())},
        )

        return updated

    def approve(
        self,
        deployment_id: str,
        approved_by: str,
        approval_ticket: str = "",
        notes: str = "",
    ) -> ModelDeployment:
        """
        Approve a deployment.

        Args:
            deployment_id: The deployment to approve.
            approved_by: Who is approving.
            approval_ticket: Ticket reference.
            notes: Approval notes.

        Returns:
            The approved deployment.

        Raises:
            RegistryError: If deployment not found or approval fails.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        # Validate for approval
        validation_result = self._validator.validate_for_approval(deployment)
        if not validation_result.valid:
            errors = "; ".join(e.message for e in validation_result.errors)
            raise RegistryError(f"Cannot approve: {errors}")

        # Update status
        updated = self._update_deployment_field(
            deployment, "approval_status", ApprovalStatus.APPROVED
        )
        updated = self._update_deployment_field(
            updated, "deployment_date", utc_now()
        )
        if approval_ticket:
            updated = self._update_deployment_field(
                updated, "approval_ticket", approval_ticket
            )

        # Store
        self._store_deployment(updated)

        # Emit event
        self._emit_event(
            DeploymentEventType.APPROVED,
            deployment_id,
            approved_by,
            {"approval_ticket": approval_ticket, "notes": notes},
        )

        return updated

    def reject(
        self,
        deployment_id: str,
        rejected_by: str,
        reason: str = "",
    ) -> ModelDeployment:
        """
        Reject a deployment.

        Args:
            deployment_id: The deployment to reject.
            rejected_by: Who is rejecting.
            reason: Rejection reason.

        Returns:
            The rejected deployment.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        updated = self._update_deployment_field(
            deployment, "approval_status", ApprovalStatus.REJECTED
        )

        # Store
        self._store_deployment(updated)

        # Emit event
        self._emit_event(
            DeploymentEventType.REJECTED,
            deployment_id,
            rejected_by,
            {"reason": reason},
        )

        return updated

    def suspend(
        self,
        deployment_id: str,
        suspended_by: str,
        reason: str = "",
    ) -> ModelDeployment:
        """
        Suspend an active deployment.

        Args:
            deployment_id: The deployment to suspend.
            suspended_by: Who is suspending.
            reason: Suspension reason.

        Returns:
            The suspended deployment.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        updated = self._update_deployment_field(
            deployment, "approval_status", ApprovalStatus.SUSPENDED
        )

        # Store
        self._store_deployment(updated)

        # Emit event
        self._emit_event(
            DeploymentEventType.SUSPENDED,
            deployment_id,
            suspended_by,
            {"reason": reason},
        )

        return updated

    def reinstate(
        self,
        deployment_id: str,
        reinstated_by: str,
        notes: str = "",
    ) -> ModelDeployment:
        """
        Reinstate a suspended deployment.

        Args:
            deployment_id: The deployment to reinstate.
            reinstated_by: Who is reinstating.
            notes: Reinstatement notes.

        Returns:
            The reinstated deployment.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        if deployment.approval_status != ApprovalStatus.SUSPENDED:
            raise RegistryError("Only suspended deployments can be reinstated")

        updated = self._update_deployment_field(
            deployment, "approval_status", ApprovalStatus.APPROVED
        )

        # Store
        self._store_deployment(updated)

        # Emit event
        self._emit_event(
            DeploymentEventType.REINSTATED,
            deployment_id,
            reinstated_by,
            {"notes": notes},
        )

        # Reset violations
        self._violations.pop(deployment_id, None)

        return updated

    def delete(
        self,
        deployment_id: str,
        deleted_by: str,
    ) -> bool:
        """
        Delete a deployment.

        Args:
            deployment_id: The deployment to delete.
            deleted_by: Who is deleting.

        Returns:
            True if deleted.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            return False

        if self._repository:
            self._repository.delete(deployment_id)
        else:
            self._deployments.pop(deployment_id, None)

        # Emit event
        self._emit_event(
            DeploymentEventType.DELETED,
            deployment_id,
            deleted_by,
            {"name": deployment.name},
        )

        return True

    def record_violation(
        self,
        deployment_id: str,
        reason: str = "",
    ) -> int:
        """
        Record a policy violation for a deployment.

        Args:
            deployment_id: The deployment that violated policy.
            reason: Violation reason.

        Returns:
            Total violation count.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        # Increment violation count
        self._violations[deployment_id] = self._violations.get(deployment_id, 0) + 1
        count = self._violations[deployment_id]

        # Emit event
        self._emit_event(
            DeploymentEventType.VIOLATION,
            deployment_id,
            "",
            {"reason": reason, "total_count": count},
        )

        # Auto-suspend if threshold exceeded
        if self._config.auto_suspend_on_violations:
            if count >= self._config.violation_threshold:
                self.suspend(
                    deployment_id,
                    "system",
                    f"Exceeded violation threshold ({count} violations)",
                )

        return count

    def get_violation_count(self, deployment_id: str) -> int:
        """Get the violation count for a deployment."""
        return self._violations.get(deployment_id, 0)

    def find_pending(self) -> list[ModelDeployment]:
        """Find all pending deployments."""
        return self._find_by_status(ApprovalStatus.PENDING)

    def find_active(self) -> list[ModelDeployment]:
        """Find all active (approved) deployments."""
        return self._find_by_status(ApprovalStatus.APPROVED)

    def find_suspended(self) -> list[ModelDeployment]:
        """Find all suspended deployments."""
        return self._find_by_status(ApprovalStatus.SUSPENDED)

    def find_by_risk_level(self, risk_level: RiskLevel) -> list[ModelDeployment]:
        """Find deployments by risk level."""
        if self._repository:
            results = self._repository.get_by_risk_level(risk_level.value)
            return [self._dict_to_deployment(r) for r in results]

        return [
            d for d in self._deployments.values()
            if d.risk_level == risk_level
        ]

    def find_by_owner(self, owner: str) -> list[ModelDeployment]:
        """Find deployments by owner."""
        if self._repository:
            results = self._repository.list_all(owner=owner)
            return [self._dict_to_deployment(r) for r in results]

        return [
            d for d in self._deployments.values()
            if d.owner == owner
        ]

    def find_needing_review(self) -> list[ModelDeployment]:
        """Find deployments needing review."""
        if self._repository:
            results = self._repository.get_needing_review()
            return [self._dict_to_deployment(r) for r in results]

        now = utc_now()
        return [
            d for d in self._deployments.values()
            if d.needs_review(now)
        ]

    def find_high_risk(self) -> list[ModelDeployment]:
        """Find all high-risk and critical deployments."""
        all_deployments = self._get_all_deployments()
        return [d for d in all_deployments if d.is_high_risk()]

    def list_all(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ModelDeployment]:
        """List all deployments with pagination."""
        if self._repository:
            results = self._repository.list_all(limit=limit, offset=offset)
            return [self._dict_to_deployment(r) for r in results]

        deployments = list(self._deployments.values())
        return deployments[offset : offset + limit]

    def assess_risk(self, deployment_id: str) -> RiskAssessment:
        """
        Perform a risk assessment on a deployment.

        Args:
            deployment_id: The deployment to assess.

        Returns:
            RiskAssessment with findings.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        return self._risk_assessor.assess(deployment)

    def check_compliance(
        self,
        deployment_id: str,
    ) -> ComplianceReport:
        """
        Check compliance for a deployment.

        Args:
            deployment_id: The deployment to check.

        Returns:
            ComplianceReport with findings.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        return self._compliance_checker.check(deployment)

    def validate(
        self,
        deployment_id: str,
    ) -> DeploymentValidationResult:
        """
        Validate a deployment.

        Args:
            deployment_id: The deployment to validate.

        Returns:
            DeploymentValidationResult with findings.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        return self._validator.validate(deployment)

    def mark_reviewed(
        self,
        deployment_id: str,
        reviewed_by: str,
        next_review_days: int | None = None,
    ) -> ModelDeployment:
        """
        Mark a deployment as reviewed.

        Args:
            deployment_id: The deployment that was reviewed.
            reviewed_by: Who performed the review.
            next_review_days: Days until next review. Uses default if None.

        Returns:
            The updated deployment.
        """
        deployment = self.get(deployment_id)
        if not deployment:
            raise RegistryError(f"Deployment {deployment_id} not found")

        now = utc_now()
        days = next_review_days or self._config.default_review_interval_days

        updated = self._update_deployment_field(
            deployment, "last_review_date", now
        )
        updated = self._update_deployment_field(
            updated, "next_review_date", now + timedelta(days=days)
        )

        self._store_deployment(updated)

        return updated

    def get_statistics(self) -> dict[str, Any]:
        """Get registry statistics."""
        all_deployments = self._get_all_deployments()

        by_status: dict[str, int] = {}
        by_risk: dict[str, int] = {}

        for deployment in all_deployments:
            status = deployment.approval_status.value
            by_status[status] = by_status.get(status, 0) + 1

            risk = deployment.risk_level.value
            by_risk[risk] = by_risk.get(risk, 0) + 1

        needing_review = len([d for d in all_deployments if d.needs_review()])

        return {
            "total_deployments": len(all_deployments),
            "by_status": by_status,
            "by_risk_level": by_risk,
            "needing_review": needing_review,
            "high_risk_count": by_risk.get("HIGH", 0) + by_risk.get("CRITICAL", 0),
        }

    # Helper methods

    def _store_deployment(self, deployment: ModelDeployment) -> None:
        """Store a deployment."""
        if self._repository:
            existing = self._repository.get_by_id(deployment.deployment_id)
            if existing:
                self._repository.update(
                    deployment.deployment_id,
                    name=deployment.name,
                    description=deployment.description,
                    model_version=deployment.model_version,
                    owner=deployment.owner,
                    owner_contact=deployment.owner_contact,
                    data_categories=list(deployment.data_categories),
                    risk_level=deployment.risk_level.value,
                    approval_status=deployment.approval_status.value,
                    approval_ticket=deployment.approval_ticket,
                    deployment_date=deployment.deployment_date,
                    last_review_date=deployment.last_review_date,
                    next_review_date=deployment.next_review_date,
                    metadata=deployment.metadata,
                )
            else:
                self._repository.create(
                    name=deployment.name,
                    model_provider=deployment.model_provider,
                    model_name=deployment.model_name,
                    owner=deployment.owner,
                    description=deployment.description,
                    model_version=deployment.model_version,
                    owner_contact=deployment.owner_contact,
                    data_categories=list(deployment.data_categories),
                    risk_level=deployment.risk_level.value,
                    approval_status=deployment.approval_status.value,
                    metadata=deployment.metadata,
                )
        else:
            self._deployments[deployment.deployment_id] = deployment

    def _find_by_status(self, status: ApprovalStatus) -> list[ModelDeployment]:
        """Find deployments by status."""
        if self._repository:
            results = self._repository.list_all(status=status.value)
            return [self._dict_to_deployment(r) for r in results]

        return [
            d for d in self._deployments.values()
            if d.approval_status == status
        ]

    def _get_all_deployments(self) -> list[ModelDeployment]:
        """Get all deployments."""
        if self._repository:
            results = self._repository.list_all(limit=10000)
            return [self._dict_to_deployment(r) for r in results]
        return list(self._deployments.values())

    def _update_deployment_field(
        self,
        deployment: ModelDeployment,
        field_name: str,
        value: Any,
    ) -> ModelDeployment:
        """Create a new deployment with an updated field."""
        data = deployment.to_dict()
        data[field_name] = value
        data["updated_at"] = utc_now()

        # Handle enums
        if "risk_level" in data and isinstance(data["risk_level"], str):
            data["risk_level"] = RiskLevel(data["risk_level"])
        if "approval_status" in data and isinstance(data["approval_status"], str):
            data["approval_status"] = ApprovalStatus(data["approval_status"])

        # Handle tuples
        if "data_categories" in data and isinstance(data["data_categories"], list):
            data["data_categories"] = tuple(data["data_categories"])
        if "tags" in data and isinstance(data.get("tags"), list):
            data["tags"] = tuple(data["tags"])

        # Handle datetime strings
        for date_field in ["created_at", "updated_at", "deployment_date",
                          "last_review_date", "next_review_date"]:
            if date_field in data and isinstance(data[date_field], str):
                data[date_field] = datetime.fromisoformat(data[date_field])

        return ModelDeployment(**data)

    def _create_updated_deployment(
        self,
        current: ModelDeployment,
        updates: dict[str, Any],
    ) -> ModelDeployment:
        """Create a new deployment with updates applied."""
        data = current.to_dict()
        data.update(updates)
        data["updated_at"] = utc_now()

        # Handle enums
        if "risk_level" in data and isinstance(data["risk_level"], str):
            data["risk_level"] = RiskLevel(data["risk_level"])
        if "approval_status" in data and isinstance(data["approval_status"], str):
            data["approval_status"] = ApprovalStatus(data["approval_status"])

        # Handle tuples
        if "data_categories" in data:
            if isinstance(data["data_categories"], list):
                data["data_categories"] = tuple(data["data_categories"])

        # Handle datetime strings
        for date_field in ["created_at", "updated_at", "deployment_date",
                          "last_review_date", "next_review_date"]:
            if date_field in data and isinstance(data[date_field], str):
                data[date_field] = datetime.fromisoformat(data[date_field])

        return ModelDeployment(**data)

    def _dict_to_deployment(self, data: dict[str, Any]) -> ModelDeployment:
        """Convert a dictionary to a ModelDeployment."""
        # Handle enums
        if "risk_level" in data and isinstance(data["risk_level"], str):
            data["risk_level"] = RiskLevel(data["risk_level"])
        if "approval_status" in data and isinstance(data["approval_status"], str):
            data["approval_status"] = ApprovalStatus(data["approval_status"])

        # Handle tuples
        if "data_categories" in data:
            if isinstance(data["data_categories"], list):
                data["data_categories"] = tuple(data["data_categories"])

        # Handle datetime strings
        for field_name in ["created_at", "updated_at", "deployment_date",
                          "last_review_date", "next_review_date"]:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.fromisoformat(data[field_name])

        # Remove extra fields
        valid_fields = {
            "id", "created_at", "updated_at", "deployment_id", "name",
            "description", "model_provider", "model_name", "model_version",
            "owner", "owner_contact", "data_categories", "risk_level",
            "approval_status", "approval_ticket", "deployment_date",
            "last_review_date", "next_review_date", "metadata",
        }
        data = {k: v for k, v in data.items() if k in valid_fields}

        return ModelDeployment(**data)

    def _emit_event(
        self,
        event_type: DeploymentEventType,
        deployment_id: str,
        actor: str,
        details: dict[str, Any],
    ) -> None:
        """Emit a deployment event."""
        event = DeploymentEvent(
            event_id=generate_uuid(),
            event_type=event_type,
            deployment_id=deployment_id,
            timestamp=utc_now(),
            actor=actor,
            details=details,
        )

        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Don't let callback errors break the manager
