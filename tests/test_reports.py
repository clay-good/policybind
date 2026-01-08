"""
Tests for report generation.

This module tests the ReportGenerator, TemplateManager, ReportScheduler,
and ComplianceMapper functionality.
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from policybind.models.base import utc_now
from policybind.reports import ReportFormat, ReportGenerator, ReportType
from policybind.reports.compliance_frameworks import (
    ComplianceFramework,
    ComplianceMapper,
    ComplianceMapping,
    CoverageLevel,
    Requirement,
)
from policybind.reports.generator import BrandingConfig, ReportMetadata
from policybind.reports.scheduled import (
    EmailConfig,
    ReportDeliveryResult,
    ReportScheduler,
    ScheduledReport,
    ScheduleFrequency,
)
from policybind.reports.templates.base import (
    ReportTemplate,
    TemplateManager,
    TemplateType,
    get_template,
    get_template_manager,
    list_templates,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def branding_config() -> BrandingConfig:
    """Create a test branding configuration."""
    return BrandingConfig(
        organization_name="Test Organization",
        primary_color="#007bff",
        secondary_color="#6c757d",
        footer_text="Test Footer",
    )


@pytest.fixture
def mock_policy_repo() -> MagicMock:
    """Create a mock policy repository."""
    repo = MagicMock()
    policy_set = MagicMock()
    policy_set.version = "1.0.0"

    # Create rule mocks with proper attribute configuration
    rule1 = MagicMock()
    rule1.name = "test-rule"
    rule1.description = "Test description"
    rule1.enabled = True
    rule1.priority = 10
    rule1.tags = ["security"]
    # Ensure to_dict doesn't exist to avoid serialization issues
    del rule1.to_dict

    rule2 = MagicMock()
    rule2.name = "disabled-rule"
    rule2.description = "Disabled rule"
    rule2.enabled = False
    rule2.priority = 5
    rule2.tags = []
    del rule2.to_dict

    policy_set.rules = [rule1, rule2]
    repo.get_current.return_value = policy_set
    return repo


@pytest.fixture
def mock_audit_repo() -> MagicMock:
    """Create a mock audit repository."""
    repo = MagicMock()
    repo.get_enforcement_stats.return_value = {
        "total_requests": 1000,
        "by_decision": {
            "ALLOW": 800,
            "DENY": 150,
            "MODIFY": 50,
        },
        "by_rule": {
            "test-rule": 500,
            "other-rule": 300,
        },
        "by_department": {
            "engineering": 600,
            "sales": 400,
        },
    }
    repo.query_enforcement_logs.return_value = [
        {
            "request_id": "req-1",
            "timestamp": utc_now(),
            "decision": "ALLOW",
            "user_id": "user1",
            "deployment_id": "dep-1",
        },
        {
            "request_id": "req-2",
            "timestamp": utc_now(),
            "decision": "DENY",
            "user_id": "user2",
            "deployment_id": "dep-2",
        },
    ]
    return repo


@pytest.fixture
def mock_registry_repo() -> MagicMock:
    """Create a mock registry repository."""
    repo = MagicMock()

    # Create deployment mocks with proper configuration
    dep1 = MagicMock()
    dep1.deployment_id = "dep-1"
    dep1.name = "Test Deployment"
    dep1.model_provider = "openai"
    dep1.model_name = "gpt-4"
    dep1.owner = "team-a"
    dep1.risk_level = "HIGH"
    dep1.approval_status = "APPROVED"
    dep1.last_review_date = utc_now()
    dep1.created_at = utc_now()
    dep1.updated_at = utc_now()
    # Remove to_dict to prevent serialization issues
    del dep1.to_dict

    dep2 = MagicMock()
    dep2.deployment_id = "dep-2"
    dep2.name = "Pending Deployment"
    dep2.model_provider = "anthropic"
    dep2.model_name = "claude-3"
    dep2.owner = "team-b"
    dep2.risk_level = "MEDIUM"
    dep2.approval_status = "PENDING"
    dep2.last_review_date = None
    dep2.created_at = utc_now()
    dep2.updated_at = utc_now()
    del dep2.to_dict

    deployments = [dep1, dep2]
    repo.list_deployments.return_value = deployments
    repo.get.return_value = dep1
    return repo


@pytest.fixture
def mock_incident_manager() -> MagicMock:
    """Create a mock incident manager."""
    manager = MagicMock()
    metrics = MagicMock()
    metrics.total_count = 25
    metrics.open_count = 5
    metrics.investigating_count = 3
    metrics.resolved_count = 10
    metrics.closed_count = 7
    metrics.by_severity = {"HIGH": 8, "MEDIUM": 12, "LOW": 5}
    metrics.by_type = {"POLICY_VIOLATION": 15, "HARMFUL_OUTPUT": 10}
    metrics.mean_time_to_resolve_hours = 4.5
    manager.get_metrics.return_value = metrics
    manager.list_incidents.return_value = []
    return manager


@pytest.fixture
def report_generator(
    mock_policy_repo: MagicMock,
    mock_audit_repo: MagicMock,
    mock_registry_repo: MagicMock,
    mock_incident_manager: MagicMock,
    branding_config: BrandingConfig,
) -> ReportGenerator:
    """Create a report generator with mocked dependencies."""
    return ReportGenerator(
        policy_repository=mock_policy_repo,
        registry_repository=mock_registry_repo,
        audit_repository=mock_audit_repo,
        incident_manager=mock_incident_manager,
        branding=branding_config,
    )


# =============================================================================
# ReportGenerator Tests
# =============================================================================


class TestReportGenerator:
    """Tests for ReportGenerator class."""

    def test_generate_policy_compliance_markdown(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a policy compliance report in Markdown."""
        report = report_generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Policy Compliance Report" in report
        assert "Test Organization" in report
        assert "Compliance Score:" in report
        assert "Active Policies:" in report
        assert "test-rule" in report

    def test_generate_policy_compliance_json(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a policy compliance report in JSON."""
        report = report_generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.JSON,
        )

        data = json.loads(report)
        assert "metadata" in data
        assert "data" in data
        assert data["metadata"]["report_type"] == "policy_compliance"
        assert data["data"]["total_rules"] == 2
        assert data["data"]["enabled_rules"] == 1

    def test_generate_policy_compliance_html(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a policy compliance report in HTML."""
        report = report_generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.HTML,
        )

        assert "<!DOCTYPE html>" in report
        assert "<title>" in report
        assert "Policy Compliance Report" in report
        assert "style>" in report

    def test_generate_policy_compliance_text(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a policy compliance report in plain text."""
        report = report_generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.TEXT,
        )

        assert "POLICY COMPLIANCE REPORT" in report
        assert "Compliance Score:" in report

    def test_generate_usage_cost_report(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a usage and cost report."""
        report = report_generator.generate(
            report_type=ReportType.USAGE_COST,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Usage and Cost Report" in report
        assert "Total Requests:" in report

    def test_generate_incident_summary_report(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating an incident summary report."""
        report = report_generator.generate(
            report_type=ReportType.INCIDENT_SUMMARY,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Incident Summary Report" in report
        assert "Total Incidents:" in report
        assert "Resolution Rate:" in report

    def test_generate_audit_trail_report(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating an audit trail report."""
        report = report_generator.generate(
            report_type=ReportType.AUDIT_TRAIL,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Audit Trail Report" in report
        assert "Total Entries:" in report

    def test_generate_risk_assessment_report(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a risk assessment report."""
        report = report_generator.generate(
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Risk Assessment Report" in report
        assert "Risk Summary" in report

    def test_generate_registry_status_report(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a registry status report."""
        report = report_generator.generate(
            report_type=ReportType.REGISTRY_STATUS,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Registry Status Report" in report
        assert "Total Deployments:" in report

    def test_generate_with_custom_period(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a report with custom date range."""
        since = utc_now() - timedelta(days=7)
        until = utc_now()

        report = report_generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.JSON,
            since=since,
            until=until,
        )

        data = json.loads(report)
        assert data["metadata"]["period_start"] is not None
        assert data["metadata"]["period_end"] is not None

    def test_generate_with_deployment_filter(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test generating a report filtered by deployment."""
        report = report_generator.generate(
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.JSON,
            deployment_id="dep-1",
        )

        data = json.loads(report)
        assert data["metadata"]["parameters"]["deployment_id"] == "dep-1"

    def test_report_metadata_checksum(
        self,
        report_generator: ReportGenerator,
    ) -> None:
        """Test that reports include a checksum."""
        report = report_generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.JSON,
        )

        data = json.loads(report)
        assert data["metadata"]["report_id"] is not None

    def test_generator_without_repos(self) -> None:
        """Test generator without any repositories configured."""
        generator = ReportGenerator()

        report = generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
        )

        assert "# Policy Compliance Report" in report


class TestReportMetadata:
    """Tests for ReportMetadata class."""

    def test_metadata_creation(self) -> None:
        """Test creating report metadata."""
        metadata = ReportMetadata(
            report_id="test-123",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
            generated_at=utc_now(),
            generated_by="test-user",
        )

        assert metadata.report_id == "test-123"
        assert metadata.report_type == ReportType.POLICY_COMPLIANCE
        assert metadata.generated_by == "test-user"

    def test_metadata_to_dict(self) -> None:
        """Test metadata serialization."""
        metadata = ReportMetadata(
            report_id="test-123",
            report_type=ReportType.USAGE_COST,
            format=ReportFormat.JSON,
            generated_at=utc_now(),
            period_start=utc_now() - timedelta(days=30),
            period_end=utc_now(),
        )

        data = metadata.to_dict()
        assert data["report_id"] == "test-123"
        assert data["report_type"] == "usage_cost"
        assert data["format"] == "json"
        assert data["period_start"] is not None
        assert data["period_end"] is not None


class TestBrandingConfig:
    """Tests for BrandingConfig class."""

    def test_default_branding(self) -> None:
        """Test default branding values."""
        config = BrandingConfig()

        assert config.organization_name == "PolicyBind"
        assert config.primary_color == "#2563eb"
        assert config.logo_base64 is None

    def test_custom_branding(self) -> None:
        """Test custom branding configuration."""
        config = BrandingConfig(
            organization_name="Acme Corp",
            primary_color="#ff0000",
            secondary_color="#00ff00",
            footer_text="Confidential",
        )

        assert config.organization_name == "Acme Corp"
        assert config.primary_color == "#ff0000"
        assert config.footer_text == "Confidential"


# =============================================================================
# TemplateManager Tests
# =============================================================================


class TestTemplateManager:
    """Tests for TemplateManager class."""

    def test_manager_initialization(self) -> None:
        """Test template manager initializes with builtin templates."""
        manager = TemplateManager()
        templates = manager.list_templates()

        assert len(templates) > 0

    def test_get_template_markdown_header(self) -> None:
        """Test getting a markdown header template."""
        manager = TemplateManager()
        template = manager.get_template(TemplateType.HEADER, format="markdown")

        assert template is not None
        assert template.format == "markdown"
        assert template.template_type == TemplateType.HEADER

    def test_get_template_html(self) -> None:
        """Test getting an HTML template."""
        manager = TemplateManager()
        template = manager.get_template(TemplateType.SECTION, format="html")

        assert template is not None
        assert template.format == "html"

    def test_get_template_by_name(self) -> None:
        """Test getting a template by specific name."""
        manager = TemplateManager()
        template = manager.get_template(
            TemplateType.HEADER,
            format="markdown",
            name="header_markdown",
        )

        assert template is not None
        assert template.name == "header_markdown"

    def test_register_custom_template(self) -> None:
        """Test registering a custom template."""
        manager = TemplateManager()

        manager.register_template(
            name="custom_test",
            template_type=TemplateType.SECTION,
            format="markdown",
            content="## ${title}\n\n${content}",
            description="Custom test template",
            variables=["title", "content"],
        )

        template = manager.get_template(
            TemplateType.SECTION,
            name="custom_test",
        )

        assert template is not None
        assert template.name == "custom_test"

    def test_list_templates_by_type(self) -> None:
        """Test listing templates filtered by type."""
        manager = TemplateManager()
        headers = manager.list_templates(template_type=TemplateType.HEADER)

        assert all(t.template_type == TemplateType.HEADER for t in headers)

    def test_list_templates_by_format(self) -> None:
        """Test listing templates filtered by format."""
        manager = TemplateManager()
        html_templates = manager.list_templates(format="html")

        assert all(t.format == "html" for t in html_templates)

    def test_remove_template(self) -> None:
        """Test removing a template."""
        manager = TemplateManager()

        manager.register_template(
            name="temp_test",
            template_type=TemplateType.SECTION,
            format="markdown",
            content="test",
        )

        removed = manager.remove_template("temp_test")
        assert removed is True

        template = manager.get_template(
            TemplateType.SECTION,
            name="temp_test",
        )
        assert template is None

    def test_remove_nonexistent_template(self) -> None:
        """Test removing a template that doesn't exist."""
        manager = TemplateManager()
        removed = manager.remove_template("nonexistent")

        assert removed is False


class TestReportTemplate:
    """Tests for ReportTemplate class."""

    def test_template_render(self) -> None:
        """Test template rendering."""
        template = ReportTemplate(
            name="test",
            template_type=TemplateType.SECTION,
            format="markdown",
            content="# ${title}\n\n${content}",
        )

        result = template.render(title="Test Title", content="Test content")

        assert "# Test Title" in result
        assert "Test content" in result

    def test_template_render_missing_variable(self) -> None:
        """Test template rendering with missing variables uses safe_substitute."""
        template = ReportTemplate(
            name="test",
            template_type=TemplateType.SECTION,
            format="markdown",
            content="# ${title}\n\n${missing}",
        )

        result = template.render(title="Test Title")

        assert "# Test Title" in result
        assert "${missing}" in result  # safe_substitute keeps missing vars


class TestModuleLevelFunctions:
    """Tests for module-level convenience functions."""

    def test_get_template_manager(self) -> None:
        """Test getting the default template manager."""
        manager = get_template_manager()
        assert manager is not None
        assert isinstance(manager, TemplateManager)

    def test_get_template_function(self) -> None:
        """Test the get_template convenience function."""
        template = get_template(TemplateType.HEADER, format="markdown")
        assert template is not None

    def test_list_templates_function(self) -> None:
        """Test the list_templates convenience function."""
        templates = list_templates()
        assert len(templates) > 0


# =============================================================================
# ReportScheduler Tests
# =============================================================================


class TestReportScheduler:
    """Tests for ReportScheduler class."""

    @pytest.fixture
    def scheduler(self, report_generator: ReportGenerator) -> ReportScheduler:
        """Create a report scheduler."""
        return ReportScheduler(generator=report_generator)

    def test_create_schedule(self, scheduler: ReportScheduler) -> None:
        """Test creating a report schedule."""
        schedule = scheduler.create_schedule(
            name="Weekly Compliance",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.HTML,
            frequency=ScheduleFrequency.WEEKLY,
            recipients=["test@example.com"],
        )

        assert schedule.schedule_id is not None
        assert schedule.name == "Weekly Compliance"
        assert schedule.frequency == ScheduleFrequency.WEEKLY
        assert schedule.next_run is not None
        assert schedule.enabled is True

    def test_get_schedule(self, scheduler: ReportScheduler) -> None:
        """Test getting a schedule by ID."""
        created = scheduler.create_schedule(
            name="Test",
            report_type=ReportType.USAGE_COST,
            format=ReportFormat.JSON,
            frequency=ScheduleFrequency.DAILY,
        )

        retrieved = scheduler.get_schedule(created.schedule_id)

        assert retrieved is not None
        assert retrieved.schedule_id == created.schedule_id

    def test_list_schedules(self, scheduler: ReportScheduler) -> None:
        """Test listing all schedules."""
        scheduler.create_schedule(
            name="Test 1",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
            frequency=ScheduleFrequency.DAILY,
        )
        scheduler.create_schedule(
            name="Test 2",
            report_type=ReportType.INCIDENT_SUMMARY,
            format=ReportFormat.HTML,
            frequency=ScheduleFrequency.WEEKLY,
        )

        schedules = scheduler.list_schedules()
        assert len(schedules) == 2

    def test_list_schedules_enabled_only(self, scheduler: ReportScheduler) -> None:
        """Test listing only enabled schedules."""
        s1 = scheduler.create_schedule(
            name="Enabled",
            report_type=ReportType.USAGE_COST,
            format=ReportFormat.JSON,
            frequency=ScheduleFrequency.DAILY,
        )
        s2 = scheduler.create_schedule(
            name="Disabled",
            report_type=ReportType.AUDIT_TRAIL,
            format=ReportFormat.JSON,
            frequency=ScheduleFrequency.DAILY,
        )
        scheduler.update_schedule(s2.schedule_id, enabled=False)

        enabled = scheduler.list_schedules(enabled_only=True)
        assert len(enabled) == 1
        assert enabled[0].schedule_id == s1.schedule_id

    def test_list_schedules_by_type(self, scheduler: ReportScheduler) -> None:
        """Test listing schedules filtered by report type."""
        scheduler.create_schedule(
            name="Compliance",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
            frequency=ScheduleFrequency.WEEKLY,
        )
        scheduler.create_schedule(
            name="Usage",
            report_type=ReportType.USAGE_COST,
            format=ReportFormat.JSON,
            frequency=ScheduleFrequency.DAILY,
        )

        compliance = scheduler.list_schedules(
            report_type=ReportType.POLICY_COMPLIANCE
        )
        assert len(compliance) == 1
        assert compliance[0].name == "Compliance"

    def test_update_schedule(self, scheduler: ReportScheduler) -> None:
        """Test updating a schedule."""
        schedule = scheduler.create_schedule(
            name="Original",
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.MARKDOWN,
            frequency=ScheduleFrequency.MONTHLY,
        )

        updated = scheduler.update_schedule(
            schedule.schedule_id,
            name="Updated",
            recipients=["new@example.com"],
        )

        assert updated is not None
        assert updated.name == "Updated"
        assert "new@example.com" in updated.recipients

    def test_update_nonexistent_schedule(self, scheduler: ReportScheduler) -> None:
        """Test updating a schedule that doesn't exist."""
        result = scheduler.update_schedule("nonexistent", name="Test")
        assert result is None

    def test_delete_schedule(self, scheduler: ReportScheduler) -> None:
        """Test deleting a schedule."""
        schedule = scheduler.create_schedule(
            name="ToDelete",
            report_type=ReportType.REGISTRY_STATUS,
            format=ReportFormat.TEXT,
            frequency=ScheduleFrequency.QUARTERLY,
        )

        deleted = scheduler.delete_schedule(schedule.schedule_id)
        assert deleted is True

        retrieved = scheduler.get_schedule(schedule.schedule_id)
        assert retrieved is None

    def test_delete_nonexistent_schedule(self, scheduler: ReportScheduler) -> None:
        """Test deleting a schedule that doesn't exist."""
        deleted = scheduler.delete_schedule("nonexistent")
        assert deleted is False

    def test_get_due_schedules(self, scheduler: ReportScheduler) -> None:
        """Test getting schedules that are due to run."""
        # Create a schedule with next_run in the past
        schedule = scheduler.create_schedule(
            name="Overdue",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
            frequency=ScheduleFrequency.DAILY,
        )
        # Manually set next_run to the past
        schedule.next_run = utc_now() - timedelta(hours=1)

        due = scheduler.get_due_schedules()
        assert len(due) == 1
        assert due[0].schedule_id == schedule.schedule_id

    def test_execute_schedule(self, scheduler: ReportScheduler) -> None:
        """Test executing a schedule immediately."""
        schedule = scheduler.create_schedule(
            name="Execute Now",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.MARKDOWN,
            frequency=ScheduleFrequency.DAILY,
        )

        result = scheduler.execute_schedule(schedule.schedule_id)

        assert result.success is True
        assert result.schedule_id == schedule.schedule_id
        assert result.checksum != ""

    def test_execute_nonexistent_schedule(self, scheduler: ReportScheduler) -> None:
        """Test executing a schedule that doesn't exist."""
        result = scheduler.execute_schedule("nonexistent")

        assert result.success is False
        assert "not found" in result.error.lower()

    def test_load_and_export_schedules(self, scheduler: ReportScheduler) -> None:
        """Test loading and exporting schedules."""
        scheduler.create_schedule(
            name="Test 1",
            report_type=ReportType.USAGE_COST,
            format=ReportFormat.JSON,
            frequency=ScheduleFrequency.WEEKLY,
        )

        exported = scheduler.export_schedules()
        assert len(exported) == 1

        # Create new scheduler and load
        new_scheduler = ReportScheduler(generator=scheduler._generator)
        new_scheduler.load_schedules(exported)

        loaded = new_scheduler.list_schedules()
        assert len(loaded) == 1
        assert loaded[0].name == "Test 1"


class TestScheduledReport:
    """Tests for ScheduledReport class."""

    def test_scheduled_report_creation(self) -> None:
        """Test creating a scheduled report."""
        schedule = ScheduledReport(
            schedule_id="sched-123",
            name="Weekly Report",
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.HTML,
            frequency=ScheduleFrequency.WEEKLY,
            recipients=["admin@example.com"],
        )

        assert schedule.schedule_id == "sched-123"
        assert schedule.enabled is True
        assert schedule.created_at is not None

    def test_scheduled_report_to_dict(self) -> None:
        """Test serializing a scheduled report."""
        schedule = ScheduledReport(
            schedule_id="sched-456",
            name="Monthly Summary",
            report_type=ReportType.INCIDENT_SUMMARY,
            format=ReportFormat.MARKDOWN,
            frequency=ScheduleFrequency.MONTHLY,
            recipients=["team@example.com"],
            last_run=utc_now() - timedelta(days=7),
            next_run=utc_now() + timedelta(days=23),
        )

        data = schedule.to_dict()

        assert data["schedule_id"] == "sched-456"
        assert data["name"] == "Monthly Summary"
        assert data["report_type"] == "incident_summary"
        assert data["frequency"] == "monthly"
        assert data["last_run"] is not None

    def test_scheduled_report_from_dict(self) -> None:
        """Test deserializing a scheduled report."""
        data = {
            "schedule_id": "sched-789",
            "name": "Daily Audit",
            "report_type": "audit_trail",
            "format": "json",
            "frequency": "daily",
            "recipients": ["audit@example.com"],
            "enabled": True,
            "created_at": utc_now().isoformat(),
        }

        schedule = ScheduledReport.from_dict(data)

        assert schedule.schedule_id == "sched-789"
        assert schedule.report_type == ReportType.AUDIT_TRAIL
        assert schedule.frequency == ScheduleFrequency.DAILY


class TestEmailConfig:
    """Tests for EmailConfig class."""

    def test_email_config_is_configured(self) -> None:
        """Test checking if email is configured."""
        unconfigured = EmailConfig(smtp_host="")
        assert unconfigured.is_configured() is False

        configured = EmailConfig(
            smtp_host="smtp.example.com",
            from_address="reports@example.com",
        )
        assert configured.is_configured() is True

    def test_email_config_partial(self) -> None:
        """Test partially configured email."""
        partial = EmailConfig(
            smtp_host="smtp.example.com",
            from_address="",
        )
        assert partial.is_configured() is False


class TestReportDeliveryResult:
    """Tests for ReportDeliveryResult class."""

    def test_success_result(self) -> None:
        """Test creating a successful delivery result."""
        result = ReportDeliveryResult(
            schedule_id="sched-123",
            success=True,
            report_path="/path/to/report.html",
            delivered_to=["user@example.com"],
            checksum="abc123",
        )

        assert result.success is True
        assert result.error is None
        assert len(result.delivered_to) == 1

    def test_failure_result(self) -> None:
        """Test creating a failure delivery result."""
        result = ReportDeliveryResult(
            schedule_id="sched-456",
            success=False,
            error="SMTP connection failed",
            failed_recipients=["user@example.com"],
        )

        assert result.success is False
        assert result.error is not None
        assert len(result.failed_recipients) == 1

    def test_to_dict(self) -> None:
        """Test serializing a delivery result."""
        result = ReportDeliveryResult(
            schedule_id="sched-789",
            success=True,
            delivered_to=["a@example.com", "b@example.com"],
        )

        data = result.to_dict()

        assert data["schedule_id"] == "sched-789"
        assert data["success"] is True
        assert len(data["delivered_to"]) == 2


class TestSchedulerWithArchive:
    """Tests for ReportScheduler with archive functionality."""

    def test_archive_report(self, report_generator: ReportGenerator) -> None:
        """Test archiving reports to disk."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            scheduler = ReportScheduler(
                generator=report_generator,
                archive_dir=tmp_dir,
            )

            schedule = scheduler.create_schedule(
                name="Archived",
                report_type=ReportType.POLICY_COMPLIANCE,
                format=ReportFormat.HTML,
                frequency=ScheduleFrequency.DAILY,
            )

            result = scheduler.execute_schedule(schedule.schedule_id)

            assert result.success is True
            assert result.report_path is not None
            assert Path(result.report_path).exists()


# =============================================================================
# ComplianceMapper Tests
# =============================================================================


class TestComplianceMapper:
    """Tests for ComplianceMapper class."""

    @pytest.fixture
    def mapper(self) -> ComplianceMapper:
        """Create a compliance mapper."""
        return ComplianceMapper()

    def test_list_frameworks(self, mapper: ComplianceMapper) -> None:
        """Test listing available frameworks."""
        frameworks = mapper.list_frameworks()

        assert ComplianceFramework.EU_AI_ACT in frameworks
        assert ComplianceFramework.NIST_AI_RMF in frameworks
        assert ComplianceFramework.SOC2 in frameworks

    def test_get_eu_ai_act_mapping(self, mapper: ComplianceMapper) -> None:
        """Test getting EU AI Act mapping."""
        mapping = mapper.get_mapping(ComplianceFramework.EU_AI_ACT)

        assert mapping is not None
        assert mapping.framework == ComplianceFramework.EU_AI_ACT
        assert len(mapping.requirements) > 0

    def test_get_nist_ai_rmf_mapping(self, mapper: ComplianceMapper) -> None:
        """Test getting NIST AI RMF mapping."""
        mapping = mapper.get_mapping(ComplianceFramework.NIST_AI_RMF)

        assert mapping is not None
        assert mapping.framework == ComplianceFramework.NIST_AI_RMF

    def test_get_soc2_mapping(self, mapper: ComplianceMapper) -> None:
        """Test getting SOC 2 mapping."""
        mapping = mapper.get_mapping(ComplianceFramework.SOC2)

        assert mapping is not None
        assert mapping.framework == ComplianceFramework.SOC2

    def test_get_nonexistent_mapping(self, mapper: ComplianceMapper) -> None:
        """Test getting a mapping that doesn't exist."""
        # GDPR is defined in the enum but not loaded
        mapping = mapper.get_mapping(ComplianceFramework.GDPR)
        assert mapping is None

    def test_generate_compliance_matrix(self, mapper: ComplianceMapper) -> None:
        """Test generating a compliance matrix."""
        matrix = mapper.generate_compliance_matrix()

        assert "generated_at" in matrix
        assert "frameworks" in matrix
        assert "summary" in matrix
        assert "eu_ai_act" in matrix["frameworks"]

    def test_generate_compliance_matrix_specific_frameworks(
        self,
        mapper: ComplianceMapper,
    ) -> None:
        """Test generating a matrix for specific frameworks."""
        matrix = mapper.generate_compliance_matrix(
            frameworks=[ComplianceFramework.SOC2]
        )

        assert "soc2" in matrix["frameworks"]
        assert "eu_ai_act" not in matrix["frameworks"]

    def test_generate_compliance_report_markdown(
        self,
        mapper: ComplianceMapper,
    ) -> None:
        """Test generating a markdown compliance report."""
        report = mapper.generate_compliance_report(
            frameworks=[ComplianceFramework.EU_AI_ACT],
            format="markdown",
        )

        assert "# Compliance Coverage Report" in report
        assert "EU AI ACT" in report
        assert "Coverage Score" in report

    def test_generate_compliance_report_json(
        self,
        mapper: ComplianceMapper,
    ) -> None:
        """Test generating a JSON compliance report."""
        report = mapper.generate_compliance_report(
            frameworks=[ComplianceFramework.NIST_AI_RMF],
            format="json",
        )

        data = json.loads(report)
        assert "frameworks" in data
        assert "nist_ai_rmf" in data["frameworks"]

    def test_generate_compliance_report_text(
        self,
        mapper: ComplianceMapper,
    ) -> None:
        """Test generating a text compliance report."""
        report = mapper.generate_compliance_report(
            format="text",
        )

        assert "COMPLIANCE COVERAGE REPORT" in report

    def test_get_requirements_by_feature(self, mapper: ComplianceMapper) -> None:
        """Test finding requirements by PolicyBind feature."""
        results = mapper.get_requirements_by_feature("Token")

        assert len(results) > 0
        for result in results:
            assert "Token" in str(result["requirement"]["policybind_features"])

    def test_get_gaps(self, mapper: ComplianceMapper) -> None:
        """Test getting compliance gaps."""
        gaps = mapper.get_gaps()

        # Should have some gaps (NONE or MINIMAL coverage)
        for gap in gaps:
            coverage = gap["requirement"]["coverage"]
            assert coverage in ("none", "minimal")


class TestComplianceMapping:
    """Tests for ComplianceMapping class."""

    def test_get_coverage_summary(self) -> None:
        """Test getting coverage summary."""
        mapping = ComplianceMapping(
            framework=ComplianceFramework.EU_AI_ACT,
            version="2024",
            requirements=[
                Requirement(
                    id="1", name="Full", description="", category="Test",
                    coverage=CoverageLevel.FULL,
                ),
                Requirement(
                    id="2", name="Partial", description="", category="Test",
                    coverage=CoverageLevel.PARTIAL,
                ),
                Requirement(
                    id="3", name="None", description="", category="Test",
                    coverage=CoverageLevel.NONE,
                ),
            ],
        )

        summary = mapping.get_coverage_summary()

        assert summary["full"] == 1
        assert summary["partial"] == 1
        assert summary["none"] == 1

    def test_get_coverage_score(self) -> None:
        """Test calculating coverage score."""
        mapping = ComplianceMapping(
            framework=ComplianceFramework.NIST_AI_RMF,
            version="1.0",
            requirements=[
                Requirement(
                    id="1", name="Full", description="", category="Test",
                    coverage=CoverageLevel.FULL,
                ),
                Requirement(
                    id="2", name="Full", description="", category="Test",
                    coverage=CoverageLevel.FULL,
                ),
            ],
        )

        score = mapping.get_coverage_score()
        assert score == 100.0

    def test_get_coverage_score_empty(self) -> None:
        """Test coverage score with no requirements."""
        mapping = ComplianceMapping(
            framework=ComplianceFramework.SOC2,
            version="2017",
            requirements=[],
        )

        score = mapping.get_coverage_score()
        assert score == 0.0

    def test_to_dict(self) -> None:
        """Test serializing a compliance mapping."""
        mapping = ComplianceMapping(
            framework=ComplianceFramework.EU_AI_ACT,
            version="2024",
            requirements=[
                Requirement(
                    id="test-1",
                    name="Test Req",
                    description="Description",
                    category="Category",
                    coverage=CoverageLevel.FULL,
                ),
            ],
        )

        data = mapping.to_dict()

        assert data["framework"] == "eu_ai_act"
        assert data["version"] == "2024"
        assert len(data["requirements"]) == 1


class TestRequirement:
    """Tests for Requirement class."""

    def test_requirement_creation(self) -> None:
        """Test creating a requirement."""
        req = Requirement(
            id="test-001",
            name="Test Requirement",
            description="A test requirement",
            category="Testing",
            policybind_features=["Feature A", "Feature B"],
            coverage=CoverageLevel.FULL,
            notes="Some notes",
            evidence_sources=["Report 1"],
        )

        assert req.id == "test-001"
        assert len(req.policybind_features) == 2
        assert req.coverage == CoverageLevel.FULL

    def test_requirement_to_dict(self) -> None:
        """Test serializing a requirement."""
        req = Requirement(
            id="test-002",
            name="Another Req",
            description="Description",
            category="Category",
            coverage=CoverageLevel.PARTIAL,
        )

        data = req.to_dict()

        assert data["id"] == "test-002"
        assert data["coverage"] == "partial"
        assert isinstance(data["policybind_features"], list)


# =============================================================================
# Integration Tests
# =============================================================================


class TestReportIntegration:
    """Integration tests for the reporting system."""

    def test_full_report_workflow(self) -> None:
        """Test a complete report generation workflow."""
        # Create generator without dependencies (simpler test)
        generator = ReportGenerator(
            branding=BrandingConfig(
                organization_name="Integration Test Corp",
            ),
        )

        # Generate a few representative report types in markdown and JSON
        test_cases = [
            (ReportType.POLICY_COMPLIANCE, ReportFormat.MARKDOWN),
            (ReportType.POLICY_COMPLIANCE, ReportFormat.JSON),
            (ReportType.USAGE_COST, ReportFormat.MARKDOWN),
            (ReportType.INCIDENT_SUMMARY, ReportFormat.JSON),
        ]

        for report_type, format in test_cases:
            report = generator.generate(
                report_type=report_type,
                format=format,
            )
            assert report is not None
            assert len(report) > 0

    def test_scheduler_with_generator(self) -> None:
        """Test scheduler integration with generator."""
        # Create generator without dependencies
        generator = ReportGenerator()

        with tempfile.TemporaryDirectory() as tmp_dir:
            scheduler = ReportScheduler(
                generator=generator,
                archive_dir=tmp_dir,
            )

            # Create a single schedule
            schedule = scheduler.create_schedule(
                name="Test Compliance",
                report_type=ReportType.POLICY_COMPLIANCE,
                format=ReportFormat.MARKDOWN,
                frequency=ScheduleFrequency.WEEKLY,
            )

            # Execute the schedule
            result = scheduler.execute_schedule(schedule.schedule_id)
            assert result.success is True

    def test_compliance_report_integration(self) -> None:
        """Test compliance report with all frameworks."""
        mapper = ComplianceMapper()

        # Generate reports for all frameworks
        for framework in mapper.list_frameworks():
            mapping = mapper.get_mapping(framework)
            if mapping:
                report = mapper.generate_compliance_report(
                    frameworks=[framework],
                    format="markdown",
                )
                assert len(report) > 0
                assert framework.value.replace("_", " ").upper() in report.upper()
