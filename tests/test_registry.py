"""
Tests for the model registry system.

This module tests the RegistryManager, DeploymentValidator,
RiskAssessor, and ComplianceChecker classes.
"""

from datetime import datetime, timedelta, timezone

import pytest

from policybind.models.registry import ApprovalStatus, ModelDeployment, RiskLevel
from policybind.registry.compliance import (
    ComplianceChecker,
    ComplianceFramework,
    ComplianceGap,
    ComplianceReport,
    ComplianceStatus,
)
from policybind.registry.manager import (
    DeploymentEvent,
    DeploymentEventType,
    RegistryManager,
)
from policybind.registry.risk import (
    RiskAssessment,
    RiskAssessor,
    RiskFactor,
    RiskFactorCategory,
    RiskMitigation,
)
from policybind.registry.validator import (
    DeploymentValidationResult,
    DeploymentValidator,
    ValidationSeverity,
)


# =============================================================================
# DeploymentValidator Tests
# =============================================================================


class TestDeploymentValidator:
    """Tests for the DeploymentValidator class."""

    @pytest.fixture
    def validator(self) -> DeploymentValidator:
        """Create a validator instance."""
        return DeploymentValidator()

    @pytest.fixture
    def valid_deployment(self) -> ModelDeployment:
        """Create a valid deployment for testing."""
        return ModelDeployment(
            name="test-deployment",
            description="A test deployment for validation",
            model_provider="openai",
            model_name="gpt-4",
            model_version="2024-01-01",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("internal", "customer"),
            risk_level=RiskLevel.MEDIUM,
        )

    def test_validate_valid_deployment(
        self,
        validator: DeploymentValidator,
        valid_deployment: ModelDeployment,
    ) -> None:
        """Test validating a fully valid deployment."""
        result = validator.validate(valid_deployment)
        assert result.valid
        assert len(result.errors) == 0

    def test_validate_missing_name(self, validator: DeploymentValidator) -> None:
        """Test validation fails for missing name."""
        deployment = ModelDeployment(
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "name" for e in result.errors)

    def test_validate_missing_provider(self, validator: DeploymentValidator) -> None:
        """Test validation fails for missing provider."""
        deployment = ModelDeployment(
            name="test",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "model_provider" for e in result.errors)

    def test_validate_missing_owner(self, validator: DeploymentValidator) -> None:
        """Test validation fails for missing owner."""
        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner_contact="test@example.com",
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "owner" for e in result.errors)

    def test_validate_invalid_email(self, validator: DeploymentValidator) -> None:
        """Test validation fails for invalid email format."""
        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="not-an-email",
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "owner_contact" for e in result.errors)

    def test_validate_invalid_data_category(
        self,
        validator: DeploymentValidator,
    ) -> None:
        """Test validation fails for invalid data category."""
        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("invalid_category",),
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "data_categories" for e in result.errors)

    def test_validate_invalid_provider(
        self,
        validator: DeploymentValidator,
    ) -> None:
        """Test validation fails for invalid provider."""
        deployment = ModelDeployment(
            name="test",
            model_provider="unknown_provider",
            model_name="some-model",
            owner="test-team",
            owner_contact="test@example.com",
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "model_provider" for e in result.errors)

    def test_validate_high_risk_requires_description(
        self,
        validator: DeploymentValidator,
    ) -> None:
        """Test that high-risk deployments require description."""
        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            risk_level=RiskLevel.HIGH,
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(
            e.field == "description" and "HIGH" in e.code.upper()
            for e in result.errors
        )

    def test_validate_high_risk_requires_data_categories(
        self,
        validator: DeploymentValidator,
    ) -> None:
        """Test that high-risk deployments require data categories."""
        deployment = ModelDeployment(
            name="test",
            description="A high-risk deployment that does something",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            risk_level=RiskLevel.HIGH,
        )
        result = validator.validate(deployment)
        assert not result.valid
        assert any(e.field == "data_categories" for e in result.errors)

    def test_validate_for_approval(
        self,
        validator: DeploymentValidator,
        valid_deployment: ModelDeployment,
    ) -> None:
        """Test validation for approval transition."""
        result = validator.validate_for_approval(valid_deployment)
        assert result.valid

    def test_validate_for_approval_already_approved(
        self,
        validator: DeploymentValidator,
    ) -> None:
        """Test validation fails for already approved deployment."""
        deployment = ModelDeployment(
            name="test",
            description="Test deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            approval_status=ApprovalStatus.APPROVED,
        )
        result = validator.validate_for_approval(deployment)
        assert not result.valid
        assert any(e.field == "approval_status" for e in result.errors)

    def test_validate_for_update(
        self,
        validator: DeploymentValidator,
        valid_deployment: ModelDeployment,
    ) -> None:
        """Test validation for update."""
        data = valid_deployment.to_dict()
        data["description"] = "Updated description"
        # Ensure risk_level is an enum
        if isinstance(data.get("risk_level"), str):
            data["risk_level"] = RiskLevel(data["risk_level"])
        if isinstance(data.get("approval_status"), str):
            data["approval_status"] = ApprovalStatus(data["approval_status"])
        updated = ModelDeployment(**data)
        result = validator.validate_for_update(valid_deployment, updated)
        assert result.valid

    def test_validate_for_update_changed_deployment_id(
        self,
        validator: DeploymentValidator,
        valid_deployment: ModelDeployment,
    ) -> None:
        """Test validation fails if deployment_id changes."""
        data = valid_deployment.to_dict()
        data["deployment_id"] = "different-id"
        # Ensure risk_level is an enum
        if isinstance(data.get("risk_level"), str):
            data["risk_level"] = RiskLevel(data["risk_level"])
        if isinstance(data.get("approval_status"), str):
            data["approval_status"] = ApprovalStatus(data["approval_status"])
        updated = ModelDeployment(**data)
        result = validator.validate_for_update(valid_deployment, updated)
        assert not result.valid
        assert any(e.field == "deployment_id" for e in result.errors)

    def test_validate_warnings_for_missing_categories(
        self,
        validator: DeploymentValidator,
    ) -> None:
        """Test warning is generated for missing data categories."""
        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        result = validator.validate(deployment)
        assert any(e.field == "data_categories" for e in result.warnings)

    def test_custom_validator(self, validator: DeploymentValidator) -> None:
        """Test adding a custom validator."""

        def check_name_prefix(
            deployment: ModelDeployment,
            result: DeploymentValidationResult,
        ) -> None:
            if not deployment.name.startswith("prod-"):
                result.add_warning("name", "Name should start with 'prod-'")

        validator.add_validator(check_name_prefix)

        deployment = ModelDeployment(
            name="test",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        result = validator.validate(deployment)
        assert any("prod-" in w.message for w in result.warnings)


# =============================================================================
# RiskAssessor Tests
# =============================================================================


class TestRiskAssessor:
    """Tests for the RiskAssessor class."""

    @pytest.fixture
    def assessor(self) -> RiskAssessor:
        """Create an assessor instance."""
        return RiskAssessor()

    def test_assess_low_risk(self, assessor: RiskAssessor) -> None:
        """Test assessment of low-risk deployment."""
        deployment = ModelDeployment(
            name="simple-bot",
            description="Internal documentation helper",
            model_provider="openai",
            model_name="gpt-3.5-turbo",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("public", "internal"),
        )
        assessment = assessor.assess(deployment)

        assert assessment.risk_score < 0.5
        assert assessment.computed_risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_assess_high_risk_pii(self, assessor: RiskAssessor) -> None:
        """Test assessment with PII data category."""
        deployment = ModelDeployment(
            name="customer-service-bot",
            description="Handles customer inquiries",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("pii", "customer"),
        )
        assessment = assessor.assess(deployment)

        assert any(f.name == "sensitive_data_pii" for f in assessment.factors)
        assert assessment.risk_score > 0.2

    def test_assess_high_risk_multiple_sensitive(self, assessor: RiskAssessor) -> None:
        """Test assessment with multiple sensitive data types."""
        deployment = ModelDeployment(
            name="healthcare-assistant",
            description="Medical information assistant",
            model_provider="anthropic",
            model_name="claude-3-opus",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("pii", "phi", "healthcare"),
        )
        assessment = assessor.assess(deployment)

        assert assessment.risk_score > 0.5
        assert assessment.computed_risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert any(f.name == "multiple_sensitive_data" for f in assessment.factors)

    def test_assess_unclassified_data(self, assessor: RiskAssessor) -> None:
        """Test that unclassified data adds risk."""
        deployment = ModelDeployment(
            name="mystery-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=(),  # No classification
        )
        assessment = assessor.assess(deployment)

        assert any(f.name == "unclassified_data" for f in assessment.factors)

    def test_assess_unversioned_model(self, assessor: RiskAssessor) -> None:
        """Test that unversioned model adds risk."""
        deployment = ModelDeployment(
            name="test-bot",
            model_provider="openai",
            model_name="gpt-4",
            model_version="",  # No version
            owner="test-team",
            owner_contact="test@example.com",
        )
        assessment = assessor.assess(deployment)

        assert any(f.name == "unversioned_model" for f in assessment.factors)

    def test_assess_custom_model(self, assessor: RiskAssessor) -> None:
        """Test that custom models add risk."""
        deployment = ModelDeployment(
            name="custom-bot",
            model_provider="custom",
            model_name="my-model",
            owner="test-team",
            owner_contact="test@example.com",
        )
        assessment = assessor.assess(deployment)

        assert any(f.name == "custom_model" for f in assessment.factors)

    def test_assess_high_risk_use_case(self, assessor: RiskAssessor) -> None:
        """Test assessment of high-risk use cases."""
        deployment = ModelDeployment(
            name="medical-advisor",
            description="Provides medical diagnosis suggestions",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        assessment = assessor.assess(deployment)

        assert any(
            f.category == RiskFactorCategory.USAGE
            for f in assessment.factors
        )

    def test_assess_missing_contact(self, assessor: RiskAssessor) -> None:
        """Test that missing contact adds risk."""
        deployment = ModelDeployment(
            name="test-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="",
        )
        assessment = assessor.assess(deployment)

        assert any(f.name == "missing_contact" for f in assessment.factors)

    def test_assess_mitigations_for_pii(self, assessor: RiskAssessor) -> None:
        """Test that mitigations are suggested for PII."""
        deployment = ModelDeployment(
            name="pii-handler",
            description="Handles personal information",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("pii",),
        )
        assessment = assessor.assess(deployment)

        assert len(assessment.mitigations) > 0
        assert any("anonymization" in m.title.lower() for m in assessment.mitigations)

    def test_assess_custom_rule(self, assessor: RiskAssessor) -> None:
        """Test custom risk rule."""

        def check_name_length(deployment: ModelDeployment) -> list[RiskFactor]:
            if len(deployment.name) < 5:
                return [
                    RiskFactor(
                        name="short_name",
                        category=RiskFactorCategory.OPERATIONAL,
                        description="Deployment name is very short",
                        weight=0.1,
                    )
                ]
            return []

        assessor.add_rule(check_name_length)

        deployment = ModelDeployment(
            name="bot",  # Short name
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        assessment = assessor.assess(deployment)

        assert any(f.name == "short_name" for f in assessment.factors)

    def test_compare_deployments(self, assessor: RiskAssessor) -> None:
        """Test comparing two deployments."""
        current = ModelDeployment(
            name="test-bot",
            description="Test bot",
            model_provider="openai",
            model_name="gpt-3.5-turbo",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("internal",),
        )
        proposed = ModelDeployment(
            name="test-bot",
            description="Test bot with PII",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("internal", "pii"),
        )

        comparison = assessor.compare(current, proposed)

        assert comparison["score_change"] > 0  # Risk increased
        assert len(comparison["new_risk_factors"]) > 0


# =============================================================================
# ComplianceChecker Tests
# =============================================================================


class TestComplianceChecker:
    """Tests for the ComplianceChecker class."""

    @pytest.fixture
    def checker(self) -> ComplianceChecker:
        """Create a checker instance."""
        return ComplianceChecker()

    def test_check_basic_deployment(self, checker: ComplianceChecker) -> None:
        """Test checking a basic deployment."""
        deployment = ModelDeployment(
            name="test-bot",
            description="A test deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("internal",),
        )
        report = checker.check(deployment)

        assert isinstance(report, ComplianceReport)
        assert report.deployment_id == deployment.deployment_id
        assert len(report.frameworks_checked) > 0

    def test_check_hipaa_not_applicable(self, checker: ComplianceChecker) -> None:
        """Test HIPAA is not applicable without healthcare data."""
        deployment = ModelDeployment(
            name="test-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("internal",),
        )
        report = checker.check(deployment)

        if ComplianceFramework.HIPAA in report.framework_statuses:
            assert report.framework_statuses[ComplianceFramework.HIPAA] == ComplianceStatus.NOT_APPLICABLE

    def test_check_hipaa_applicable(self, checker: ComplianceChecker) -> None:
        """Test HIPAA checks for healthcare data."""
        deployment = ModelDeployment(
            name="healthcare-bot",
            description="Handles PHI",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("phi", "healthcare"),
        )
        report = checker.check(deployment)

        assert ComplianceFramework.HIPAA in report.framework_statuses
        status = report.framework_statuses[ComplianceFramework.HIPAA]
        assert status != ComplianceStatus.NOT_APPLICABLE

        # Should have HIPAA gaps
        hipaa_gaps = [g for g in report.gaps if g.framework == ComplianceFramework.HIPAA]
        assert len(hipaa_gaps) > 0

    def test_check_gdpr_applicable(self, checker: ComplianceChecker) -> None:
        """Test GDPR checks for personal data."""
        deployment = ModelDeployment(
            name="customer-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("pii", "customer"),
        )
        report = checker.check(deployment)

        assert ComplianceFramework.GDPR in report.framework_statuses
        status = report.framework_statuses[ComplianceFramework.GDPR]
        assert status != ComplianceStatus.NOT_APPLICABLE

    def test_check_pci_applicable(self, checker: ComplianceChecker) -> None:
        """Test PCI DSS checks for payment data."""
        deployment = ModelDeployment(
            name="payment-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("pci",),
        )
        report = checker.check(deployment)

        assert ComplianceFramework.PCI_DSS in report.framework_statuses
        status = report.framework_statuses[ComplianceFramework.PCI_DSS]
        assert status != ComplianceStatus.NOT_APPLICABLE

    def test_check_internal_policies(self, checker: ComplianceChecker) -> None:
        """Test internal policy checks."""
        deployment = ModelDeployment(
            name="",  # Missing name
            model_provider="openai",
            model_name="gpt-4",
            owner="",  # Missing owner
            owner_contact="",
        )
        report = checker.check(
            deployment, frameworks=[ComplianceFramework.INTERNAL]
        )

        assert report.framework_statuses[ComplianceFramework.INTERNAL] == ComplianceStatus.NON_COMPLIANT
        internal_gaps = [g for g in report.gaps if g.framework == ComplianceFramework.INTERNAL]
        assert len(internal_gaps) > 0

    def test_check_eu_ai_act_high_risk(self, checker: ComplianceChecker) -> None:
        """Test EU AI Act checks for high-risk systems."""
        deployment = ModelDeployment(
            name="medical-diagnostic",
            description="AI for medical diagnosis",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("healthcare",),
            risk_level=RiskLevel.HIGH,
        )
        report = checker.check(deployment)

        eu_gaps = [g for g in report.gaps if g.framework == ComplianceFramework.EU_AI_ACT]
        assert len(eu_gaps) > 0  # Should have gaps

    def test_check_nist_ai_rmf(self, checker: ComplianceChecker) -> None:
        """Test NIST AI RMF checks."""
        deployment = ModelDeployment(
            name="test-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="",  # Missing owner
            owner_contact="test@example.com",
        )
        report = checker.check(
            deployment, frameworks=[ComplianceFramework.NIST_AI_RMF]
        )

        nist_gaps = [g for g in report.gaps if g.framework == ComplianceFramework.NIST_AI_RMF]
        assert len(nist_gaps) > 0
        assert any("accountab" in g.requirement.lower() for g in nist_gaps)

    def test_overall_status_non_compliant(self, checker: ComplianceChecker) -> None:
        """Test overall status is non-compliant when any framework is."""
        deployment = ModelDeployment(
            name="",  # Invalid
            model_provider="openai",
            model_name="gpt-4",
            owner="",  # Invalid
            owner_contact="",
        )
        report = checker.check(deployment)

        assert report.overall_status in (
            ComplianceStatus.NON_COMPLIANT,
            ComplianceStatus.PARTIAL,
        )

    def test_documentation_required(self, checker: ComplianceChecker) -> None:
        """Test documentation requirements are identified."""
        deployment = ModelDeployment(
            name="test-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            risk_level=RiskLevel.HIGH,
        )
        report = checker.check(deployment)

        assert len(report.documentation_required) > 0

    def test_framework_summary(self, checker: ComplianceChecker) -> None:
        """Test getting framework summary."""
        summary = checker.get_framework_summary(ComplianceFramework.EU_AI_ACT)

        assert "name" in summary
        assert "description" in summary
        assert "key_requirements" in summary

    def test_is_compliant_method(self, checker: ComplianceChecker) -> None:
        """Test the is_compliant method on reports."""
        deployment = ModelDeployment(
            name="test-bot",
            description="A simple test bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=("internal",),
        )
        report = checker.check(deployment)

        # Test the method works
        _ = report.is_compliant()
        _ = report.is_compliant(ComplianceFramework.INTERNAL)


# =============================================================================
# RegistryManager Tests
# =============================================================================


class TestRegistryManager:
    """Tests for the RegistryManager class."""

    @pytest.fixture
    def manager(self) -> RegistryManager:
        """Create a manager instance."""
        return RegistryManager()

    def test_register_deployment(self, manager: RegistryManager) -> None:
        """Test registering a new deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            description="A test deployment",
            data_categories=["internal"],
        )

        assert deployment is not None
        assert deployment.name == "test-deployment"
        assert deployment.approval_status == ApprovalStatus.PENDING
        assert deployment.next_review_date is not None

    def test_register_auto_risk_assessment(self, manager: RegistryManager) -> None:
        """Test that risk level is auto-assessed if not provided."""
        deployment = manager.register(
            name="pii-handler",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            description="Handles personal data",
            data_categories=["pii", "customer"],
        )

        # Risk should have been assessed based on data categories
        assert deployment.risk_level is not None

    def test_register_validation_fails(self, manager: RegistryManager) -> None:
        """Test registration fails for invalid deployment."""
        with pytest.raises(Exception):  # ValidationError
            manager.register(
                name="",  # Invalid
                model_provider="openai",
                model_name="gpt-4",
                owner="test-team",
                owner_contact="test@example.com",
            )

    def test_get_deployment(self, manager: RegistryManager) -> None:
        """Test getting a deployment by ID."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        retrieved = manager.get(deployment.deployment_id)
        assert retrieved is not None
        assert retrieved.deployment_id == deployment.deployment_id

    def test_get_by_name(self, manager: RegistryManager) -> None:
        """Test getting a deployment by name."""
        manager.register(
            name="unique-name",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        retrieved = manager.get_by_name("unique-name")
        assert retrieved is not None
        assert retrieved.name == "unique-name"

    def test_update_deployment(self, manager: RegistryManager) -> None:
        """Test updating a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        updated = manager.update(
            deployment.deployment_id,
            description="Updated description",
        )

        assert updated.description == "Updated description"

    def test_approve_deployment(self, manager: RegistryManager) -> None:
        """Test approving a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        approved = manager.approve(
            deployment.deployment_id,
            approved_by="admin",
            approval_ticket="TICKET-123",
        )

        assert approved.approval_status == ApprovalStatus.APPROVED
        assert approved.deployment_date is not None
        assert approved.approval_ticket == "TICKET-123"

    def test_reject_deployment(self, manager: RegistryManager) -> None:
        """Test rejecting a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        rejected = manager.reject(
            deployment.deployment_id,
            rejected_by="admin",
            reason="Not approved",
        )

        assert rejected.approval_status == ApprovalStatus.REJECTED

    def test_suspend_deployment(self, manager: RegistryManager) -> None:
        """Test suspending a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        manager.approve(deployment.deployment_id, "admin")

        suspended = manager.suspend(
            deployment.deployment_id,
            suspended_by="admin",
            reason="Policy violation",
        )

        assert suspended.approval_status == ApprovalStatus.SUSPENDED

    def test_reinstate_deployment(self, manager: RegistryManager) -> None:
        """Test reinstating a suspended deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        manager.approve(deployment.deployment_id, "admin")
        manager.suspend(deployment.deployment_id, "admin")

        reinstated = manager.reinstate(
            deployment.deployment_id,
            reinstated_by="admin",
        )

        assert reinstated.approval_status == ApprovalStatus.APPROVED

    def test_delete_deployment(self, manager: RegistryManager) -> None:
        """Test deleting a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        result = manager.delete(deployment.deployment_id, "admin")
        assert result is True

        # Should not be findable
        assert manager.get(deployment.deployment_id) is None

    def test_record_violation(self, manager: RegistryManager) -> None:
        """Test recording violations."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        count = manager.record_violation(deployment.deployment_id, "Test violation")
        assert count == 1

        count = manager.record_violation(deployment.deployment_id, "Another violation")
        assert count == 2

        assert manager.get_violation_count(deployment.deployment_id) == 2

    def test_auto_suspend_on_violations(self, manager: RegistryManager) -> None:
        """Test auto-suspension when violation threshold is exceeded."""
        # Create manager with low threshold for testing
        from policybind.config.schema import RegistryConfig
        config = RegistryConfig(violation_threshold=3, auto_suspend_on_violations=True)
        manager = RegistryManager(config=config)

        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        manager.approve(deployment.deployment_id, "admin")

        # Record violations up to threshold
        for i in range(3):
            manager.record_violation(deployment.deployment_id, f"Violation {i + 1}")

        # Should be suspended now
        current = manager.get(deployment.deployment_id)
        assert current is not None
        assert current.approval_status == ApprovalStatus.SUSPENDED

    def test_find_pending(self, manager: RegistryManager) -> None:
        """Test finding pending deployments."""
        manager.register(
            name="pending-1",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        d2 = manager.register(
            name="approved-1",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        manager.approve(d2.deployment_id, "admin")

        pending = manager.find_pending()
        assert len(pending) == 1
        assert pending[0].name == "pending-1"

    def test_find_by_owner(self, manager: RegistryManager) -> None:
        """Test finding deployments by owner."""
        manager.register(
            name="team-a-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-a",
            owner_contact="a@example.com",
        )
        manager.register(
            name="team-b-bot",
            model_provider="openai",
            model_name="gpt-4",
            owner="team-b",
            owner_contact="b@example.com",
        )

        team_a = manager.find_by_owner("team-a")
        assert len(team_a) == 1
        assert team_a[0].owner == "team-a"

    def test_find_by_risk_level(self, manager: RegistryManager) -> None:
        """Test finding deployments by risk level."""
        manager.register(
            name="low-risk",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            risk_level=RiskLevel.LOW,
        )
        manager.register(
            name="high-risk",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=["pii"],
            description="Handles sensitive data",
            risk_level=RiskLevel.HIGH,
        )

        high_risk = manager.find_by_risk_level(RiskLevel.HIGH)
        assert len(high_risk) == 1
        assert high_risk[0].name == "high-risk"

    def test_mark_reviewed(self, manager: RegistryManager) -> None:
        """Test marking a deployment as reviewed."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        updated = manager.mark_reviewed(
            deployment.deployment_id,
            reviewed_by="reviewer",
            next_review_days=30,
        )

        assert updated.last_review_date is not None
        assert updated.next_review_date is not None
        assert updated.next_review_date > updated.last_review_date

    def test_assess_risk(self, manager: RegistryManager) -> None:
        """Test assessing risk for a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
            data_categories=["pii"],
        )

        assessment = manager.assess_risk(deployment.deployment_id)
        assert isinstance(assessment, RiskAssessment)
        assert assessment.deployment_id == deployment.deployment_id

    def test_check_compliance(self, manager: RegistryManager) -> None:
        """Test checking compliance for a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        report = manager.check_compliance(deployment.deployment_id)
        assert isinstance(report, ComplianceReport)
        assert report.deployment_id == deployment.deployment_id

    def test_validate_deployment(self, manager: RegistryManager) -> None:
        """Test validating a deployment."""
        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        result = manager.validate(deployment.deployment_id)
        assert isinstance(result, DeploymentValidationResult)

    def test_get_statistics(self, manager: RegistryManager) -> None:
        """Test getting registry statistics."""
        manager.register(
            name="bot-1",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        d2 = manager.register(
            name="bot-2",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )
        manager.approve(d2.deployment_id, "admin")

        stats = manager.get_statistics()

        assert stats["total_deployments"] == 2
        assert "by_status" in stats
        assert "by_risk_level" in stats

    def test_event_callback(self, manager: RegistryManager) -> None:
        """Test event callbacks are called."""
        events: list[DeploymentEvent] = []

        def callback(event: DeploymentEvent) -> None:
            events.append(event)

        manager.on_event(callback)

        deployment = manager.register(
            name="test-deployment",
            model_provider="openai",
            model_name="gpt-4",
            owner="test-team",
            owner_contact="test@example.com",
        )

        assert len(events) == 1
        assert events[0].event_type == DeploymentEventType.REGISTERED

        manager.approve(deployment.deployment_id, "admin")
        assert len(events) == 2
        assert events[1].event_type == DeploymentEventType.APPROVED


class TestDeploymentEvent:
    """Tests for the DeploymentEvent dataclass."""

    def test_event_to_dict(self) -> None:
        """Test converting event to dictionary."""
        event = DeploymentEvent(
            event_id="test-id",
            event_type=DeploymentEventType.REGISTERED,
            deployment_id="deploy-id",
            timestamp=datetime.now(timezone.utc),
            actor="user",
            details={"key": "value"},
        )

        data = event.to_dict()
        assert data["event_id"] == "test-id"
        assert data["event_type"] == "registered"
        assert data["deployment_id"] == "deploy-id"
        assert data["actor"] == "user"
