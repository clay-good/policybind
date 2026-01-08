"""
Scheduled report generation for PolicyBind.

This module provides functionality for scheduling report generation,
email delivery, and report archival.
"""

import hashlib
import json
import logging
import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from policybind.models.base import utc_now
from policybind.reports.generator import ReportFormat, ReportGenerator, ReportType

logger = logging.getLogger("policybind.reports.scheduled")


class ScheduleFrequency(Enum):
    """Frequency options for scheduled reports."""

    DAILY = "daily"
    """Generate report daily."""

    WEEKLY = "weekly"
    """Generate report weekly."""

    MONTHLY = "monthly"
    """Generate report monthly."""

    QUARTERLY = "quarterly"
    """Generate report quarterly."""


@dataclass
class EmailConfig:
    """
    Email configuration for report delivery.

    Attributes:
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port.
        smtp_user: SMTP authentication username.
        smtp_password: SMTP authentication password.
        use_tls: Whether to use TLS encryption.
        from_address: Sender email address.
        from_name: Sender display name.
    """

    smtp_host: str
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    from_address: str = ""
    from_name: str = "PolicyBind Reports"

    def is_configured(self) -> bool:
        """Check if email is properly configured."""
        return bool(self.smtp_host and self.from_address)


@dataclass
class ScheduledReport:
    """
    A scheduled report configuration.

    Attributes:
        schedule_id: Unique identifier for the schedule.
        name: Human-readable name for the schedule.
        report_type: Type of report to generate.
        format: Output format for the report.
        frequency: How often to generate the report.
        recipients: List of email addresses to send to.
        enabled: Whether the schedule is active.
        deployment_id: Optional filter by deployment.
        parameters: Additional report parameters.
        last_run: When the report was last generated.
        next_run: When the report is next scheduled to run.
        created_at: When the schedule was created.
        created_by: Who created the schedule.
        archive_path: Path for archiving reports.
    """

    schedule_id: str
    name: str
    report_type: ReportType
    format: ReportFormat
    frequency: ScheduleFrequency
    recipients: list[str] = field(default_factory=list)
    enabled: bool = True
    deployment_id: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    last_run: datetime | None = None
    next_run: datetime | None = None
    created_at: datetime = field(default_factory=utc_now)
    created_by: str = "system"
    archive_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schedule_id": self.schedule_id,
            "name": self.name,
            "report_type": self.report_type.value,
            "format": self.format.value,
            "frequency": self.frequency.value,
            "recipients": self.recipients,
            "enabled": self.enabled,
            "deployment_id": self.deployment_id,
            "parameters": self.parameters,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "archive_path": self.archive_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScheduledReport":
        """Create from dictionary."""
        return cls(
            schedule_id=data["schedule_id"],
            name=data["name"],
            report_type=ReportType(data["report_type"]),
            format=ReportFormat(data["format"]),
            frequency=ScheduleFrequency(data["frequency"]),
            recipients=data.get("recipients", []),
            enabled=data.get("enabled", True),
            deployment_id=data.get("deployment_id"),
            parameters=data.get("parameters", {}),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else utc_now(),
            created_by=data.get("created_by", "system"),
            archive_path=data.get("archive_path"),
        )


@dataclass
class ReportDeliveryResult:
    """
    Result of a report delivery attempt.

    Attributes:
        schedule_id: The schedule that was executed.
        success: Whether delivery was successful.
        report_path: Path where the report was archived.
        delivered_to: List of recipients who received the report.
        failed_recipients: List of recipients who failed to receive.
        error: Error message if delivery failed.
        generated_at: When the report was generated.
        checksum: SHA-256 checksum of the report.
    """

    schedule_id: str
    success: bool
    report_path: str | None = None
    delivered_to: list[str] = field(default_factory=list)
    failed_recipients: list[str] = field(default_factory=list)
    error: str | None = None
    generated_at: datetime = field(default_factory=utc_now)
    checksum: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schedule_id": self.schedule_id,
            "success": self.success,
            "report_path": self.report_path,
            "delivered_to": self.delivered_to,
            "failed_recipients": self.failed_recipients,
            "error": self.error,
            "generated_at": self.generated_at.isoformat(),
            "checksum": self.checksum,
        }


class ReportScheduler:
    """
    Manages scheduled report generation and delivery.

    Provides functionality for:
    - Creating and managing report schedules
    - Generating reports on schedule
    - Delivering reports via email
    - Archiving generated reports

    Example:
        Using the ReportScheduler::

            from policybind.reports.scheduled import (
                ReportScheduler,
                ScheduleFrequency,
                EmailConfig,
            )
            from policybind.reports import ReportGenerator, ReportType, ReportFormat

            # Create the scheduler
            generator = ReportGenerator(...)
            email_config = EmailConfig(
                smtp_host="smtp.example.com",
                smtp_port=587,
                from_address="reports@example.com",
            )
            scheduler = ReportScheduler(
                generator=generator,
                email_config=email_config,
                archive_dir="/var/policybind/reports",
            )

            # Create a schedule
            schedule = scheduler.create_schedule(
                name="Weekly Compliance Report",
                report_type=ReportType.POLICY_COMPLIANCE,
                format=ReportFormat.HTML,
                frequency=ScheduleFrequency.WEEKLY,
                recipients=["security@example.com"],
            )

            # Run due schedules
            results = scheduler.run_due_schedules()
    """

    def __init__(
        self,
        generator: ReportGenerator,
        email_config: EmailConfig | None = None,
        archive_dir: str | Path | None = None,
        storage_callback: Callable[[ScheduledReport], None] | None = None,
    ) -> None:
        """
        Initialize the report scheduler.

        Args:
            generator: ReportGenerator instance for creating reports.
            email_config: Email configuration for delivery.
            archive_dir: Directory for archiving reports.
            storage_callback: Callback for persisting schedule changes.
        """
        self._generator = generator
        self._email_config = email_config or EmailConfig(smtp_host="")
        self._archive_dir = Path(archive_dir) if archive_dir else None
        self._storage_callback = storage_callback
        self._schedules: dict[str, ScheduledReport] = {}

        # Create archive directory if specified
        if self._archive_dir:
            self._archive_dir.mkdir(parents=True, exist_ok=True)

    def create_schedule(
        self,
        name: str,
        report_type: ReportType,
        format: ReportFormat,
        frequency: ScheduleFrequency,
        recipients: list[str] | None = None,
        deployment_id: str | None = None,
        parameters: dict[str, Any] | None = None,
        created_by: str = "system",
    ) -> ScheduledReport:
        """
        Create a new report schedule.

        Args:
            name: Human-readable name for the schedule.
            report_type: Type of report to generate.
            format: Output format.
            frequency: Generation frequency.
            recipients: Email recipients.
            deployment_id: Optional deployment filter.
            parameters: Additional report parameters.
            created_by: Creator identifier.

        Returns:
            The created schedule.
        """
        import uuid

        schedule_id = str(uuid.uuid4())
        next_run = self._calculate_next_run(frequency)

        schedule = ScheduledReport(
            schedule_id=schedule_id,
            name=name,
            report_type=report_type,
            format=format,
            frequency=frequency,
            recipients=recipients or [],
            deployment_id=deployment_id,
            parameters=parameters or {},
            next_run=next_run,
            created_by=created_by,
            archive_path=str(self._archive_dir) if self._archive_dir else None,
        )

        self._schedules[schedule_id] = schedule

        if self._storage_callback:
            self._storage_callback(schedule)

        logger.info(f"Created schedule: {schedule_id} ({name})")
        return schedule

    def get_schedule(self, schedule_id: str) -> ScheduledReport | None:
        """Get a schedule by ID."""
        return self._schedules.get(schedule_id)

    def list_schedules(
        self,
        enabled_only: bool = False,
        report_type: ReportType | None = None,
    ) -> list[ScheduledReport]:
        """
        List all schedules.

        Args:
            enabled_only: Only return enabled schedules.
            report_type: Filter by report type.

        Returns:
            List of matching schedules.
        """
        schedules = list(self._schedules.values())

        if enabled_only:
            schedules = [s for s in schedules if s.enabled]

        if report_type:
            schedules = [s for s in schedules if s.report_type == report_type]

        return schedules

    def update_schedule(
        self,
        schedule_id: str,
        name: str | None = None,
        recipients: list[str] | None = None,
        enabled: bool | None = None,
        frequency: ScheduleFrequency | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> ScheduledReport | None:
        """
        Update a schedule.

        Args:
            schedule_id: Schedule to update.
            name: New name.
            recipients: New recipients.
            enabled: New enabled state.
            frequency: New frequency.
            parameters: New parameters.

        Returns:
            Updated schedule or None if not found.
        """
        schedule = self._schedules.get(schedule_id)
        if not schedule:
            return None

        if name is not None:
            schedule.name = name
        if recipients is not None:
            schedule.recipients = recipients
        if enabled is not None:
            schedule.enabled = enabled
        if frequency is not None:
            schedule.frequency = frequency
            schedule.next_run = self._calculate_next_run(frequency)
        if parameters is not None:
            schedule.parameters = parameters

        if self._storage_callback:
            self._storage_callback(schedule)

        return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        """
        Delete a schedule.

        Args:
            schedule_id: Schedule to delete.

        Returns:
            True if deleted, False if not found.
        """
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            logger.info(f"Deleted schedule: {schedule_id}")
            return True
        return False

    def get_due_schedules(self) -> list[ScheduledReport]:
        """
        Get all schedules that are due to run.

        Returns:
            List of schedules that should be executed.
        """
        now = utc_now()
        due = []

        for schedule in self._schedules.values():
            if not schedule.enabled:
                continue
            if schedule.next_run and schedule.next_run <= now:
                due.append(schedule)

        return due

    def run_due_schedules(self) -> list[ReportDeliveryResult]:
        """
        Run all due schedules.

        Returns:
            List of delivery results.
        """
        results = []
        due_schedules = self.get_due_schedules()

        for schedule in due_schedules:
            result = self.execute_schedule(schedule.schedule_id)
            results.append(result)

        return results

    def execute_schedule(self, schedule_id: str) -> ReportDeliveryResult:
        """
        Execute a single schedule immediately.

        Args:
            schedule_id: Schedule to execute.

        Returns:
            Delivery result.
        """
        schedule = self._schedules.get(schedule_id)
        if not schedule:
            return ReportDeliveryResult(
                schedule_id=schedule_id,
                success=False,
                error="Schedule not found",
            )

        try:
            # Determine report period based on frequency
            until = utc_now()
            if schedule.frequency == ScheduleFrequency.DAILY:
                since = until - timedelta(days=1)
            elif schedule.frequency == ScheduleFrequency.WEEKLY:
                since = until - timedelta(days=7)
            elif schedule.frequency == ScheduleFrequency.MONTHLY:
                since = until - timedelta(days=30)
            elif schedule.frequency == ScheduleFrequency.QUARTERLY:
                since = until - timedelta(days=90)
            else:
                since = until - timedelta(days=30)

            # Generate the report
            report_content = self._generator.generate(
                report_type=schedule.report_type,
                format=schedule.format,
                since=since,
                until=until,
                deployment_id=schedule.deployment_id,
                generated_by=f"schedule:{schedule_id}",
                **schedule.parameters,
            )

            # Calculate checksum
            checksum = hashlib.sha256(report_content.encode()).hexdigest()

            # Archive the report
            report_path = None
            if self._archive_dir:
                report_path = self._archive_report(schedule, report_content)

            # Deliver via email
            delivered_to = []
            failed_recipients = []

            if schedule.recipients and self._email_config.is_configured():
                for recipient in schedule.recipients:
                    try:
                        self._send_email(
                            recipient=recipient,
                            schedule=schedule,
                            report_content=report_content,
                        )
                        delivered_to.append(recipient)
                    except Exception as e:
                        logger.error(f"Failed to deliver to {recipient}: {e}")
                        failed_recipients.append(recipient)

            # Update schedule
            schedule.last_run = utc_now()
            schedule.next_run = self._calculate_next_run(schedule.frequency)

            if self._storage_callback:
                self._storage_callback(schedule)

            success = not failed_recipients or delivered_to
            logger.info(
                f"Executed schedule {schedule_id}: delivered to {len(delivered_to)}, "
                f"failed {len(failed_recipients)}"
            )

            return ReportDeliveryResult(
                schedule_id=schedule_id,
                success=success,
                report_path=report_path,
                delivered_to=delivered_to,
                failed_recipients=failed_recipients,
                checksum=checksum,
            )

        except Exception as e:
            logger.exception(f"Failed to execute schedule {schedule_id}: {e}")
            return ReportDeliveryResult(
                schedule_id=schedule_id,
                success=False,
                error=str(e),
            )

    def _calculate_next_run(self, frequency: ScheduleFrequency) -> datetime:
        """Calculate the next run time based on frequency."""
        now = utc_now()

        if frequency == ScheduleFrequency.DAILY:
            # Next day at midnight
            next_run = (now + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        elif frequency == ScheduleFrequency.WEEKLY:
            # Next Monday at midnight
            days_until_monday = (7 - now.weekday()) % 7 or 7
            next_run = (now + timedelta(days=days_until_monday)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        elif frequency == ScheduleFrequency.MONTHLY:
            # First of next month
            if now.month == 12:
                next_run = now.replace(
                    year=now.year + 1, month=1, day=1,
                    hour=0, minute=0, second=0, microsecond=0
                )
            else:
                next_run = now.replace(
                    month=now.month + 1, day=1,
                    hour=0, minute=0, second=0, microsecond=0
                )
        elif frequency == ScheduleFrequency.QUARTERLY:
            # First of next quarter
            current_quarter = (now.month - 1) // 3
            next_quarter = (current_quarter + 1) % 4
            next_year = now.year + (1 if next_quarter == 0 else 0)
            next_month = next_quarter * 3 + 1
            next_run = now.replace(
                year=next_year, month=next_month, day=1,
                hour=0, minute=0, second=0, microsecond=0
            )
        else:
            next_run = now + timedelta(days=1)

        return next_run

    def _archive_report(
        self,
        schedule: ScheduledReport,
        content: str,
    ) -> str:
        """Archive a report to the file system."""
        if not self._archive_dir:
            raise ValueError("Archive directory not configured")

        # Create directory structure: archive_dir/report_type/year/month/
        now = utc_now()
        report_dir = (
            self._archive_dir
            / schedule.report_type.value
            / str(now.year)
            / f"{now.month:02d}"
        )
        report_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        extension = self._get_file_extension(schedule.format)
        filename = f"{schedule.schedule_id}_{now.strftime('%Y%m%d_%H%M%S')}.{extension}"
        report_path = report_dir / filename

        # Write the report
        report_path.write_text(content, encoding="utf-8")

        # Write metadata
        metadata_path = report_path.with_suffix(".meta.json")
        metadata = {
            "schedule_id": schedule.schedule_id,
            "schedule_name": schedule.name,
            "report_type": schedule.report_type.value,
            "format": schedule.format.value,
            "generated_at": now.isoformat(),
            "checksum": hashlib.sha256(content.encode()).hexdigest(),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        logger.info(f"Archived report: {report_path}")
        return str(report_path)

    def _get_file_extension(self, format: ReportFormat) -> str:
        """Get file extension for a report format."""
        extensions = {
            ReportFormat.JSON: "json",
            ReportFormat.MARKDOWN: "md",
            ReportFormat.HTML: "html",
            ReportFormat.TEXT: "txt",
        }
        return extensions.get(format, "txt")

    def _send_email(
        self,
        recipient: str,
        schedule: ScheduledReport,
        report_content: str,
    ) -> None:
        """Send a report via email."""
        if not self._email_config.is_configured():
            raise ValueError("Email not configured")

        msg = MIMEMultipart()
        msg["From"] = f"{self._email_config.from_name} <{self._email_config.from_address}>"
        msg["To"] = recipient
        msg["Subject"] = f"PolicyBind Report: {schedule.name}"

        # Email body
        body = f"""
PolicyBind Scheduled Report

Report: {schedule.name}
Type: {schedule.report_type.value}
Generated: {utc_now().isoformat()}

Please find the attached report.

---
This is an automated message from PolicyBind.
"""
        msg.attach(MIMEText(body, "plain"))

        # Attach the report
        extension = self._get_file_extension(schedule.format)
        filename = f"report_{utc_now().strftime('%Y%m%d')}.{extension}"

        if schedule.format == ReportFormat.HTML:
            attachment = MIMEText(report_content, "html")
        else:
            attachment = MIMEText(report_content, "plain")

        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=filename,
        )
        msg.attach(attachment)

        # Send the email
        with smtplib.SMTP(
            self._email_config.smtp_host,
            self._email_config.smtp_port,
        ) as server:
            if self._email_config.use_tls:
                server.starttls()
            if self._email_config.smtp_user:
                server.login(
                    self._email_config.smtp_user,
                    self._email_config.smtp_password,
                )
            server.send_message(msg)

        logger.info(f"Sent report to {recipient}")

    def load_schedules(self, schedules: list[dict[str, Any]]) -> None:
        """
        Load schedules from serialized data.

        Args:
            schedules: List of schedule dictionaries.
        """
        for schedule_data in schedules:
            try:
                schedule = ScheduledReport.from_dict(schedule_data)
                self._schedules[schedule.schedule_id] = schedule
            except Exception as e:
                logger.error(f"Failed to load schedule: {e}")

    def export_schedules(self) -> list[dict[str, Any]]:
        """
        Export all schedules as serializable data.

        Returns:
            List of schedule dictionaries.
        """
        return [s.to_dict() for s in self._schedules.values()]
