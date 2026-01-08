"""
Tests for PolicyBind CLI audit and incident commands.

Tests the audit and incident management CLI commands including
query, stats, export, list, show, create, and resolve.
"""

import json
import os
from pathlib import Path

import pytest

from policybind.cli.main import (
    EXIT_ERROR,
    EXIT_SUCCESS,
    main,
)


class TestAuditQuery:
    """Tests for the audit query command."""

    def test_audit_query_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test querying when no logs exist."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["audit", "query"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "No enforcement logs" in captured.out or "Enforcement Logs" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_audit_query_with_filters(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test querying with filters."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "audit", "query",
                "--user", "test-user",
                "--decision", "ALLOW",
                "--limit", "10",
            ])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_audit_query_with_dates(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test querying with date filters."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "audit", "query",
                "--start", "7d",
            ])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)


class TestAuditStats:
    """Tests for the audit stats command."""

    def test_audit_stats_basic(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test basic statistics."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["audit", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Enforcement Statistics" in captured.out or "total_requests" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_audit_stats_with_period(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics with custom period."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["audit", "stats", "--start", "30d"])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_audit_stats_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()  # Clear init output

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["--format", "json", "audit", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "total_requests" in data
            assert "by_decision" in data
        finally:
            os.chdir(original_cwd)


class TestAuditExport:
    """Tests for the audit export command."""

    def test_audit_export_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test exporting to JSON."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["audit", "export", "--export-format", "json"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
        finally:
            os.chdir(original_cwd)

    def test_audit_export_to_file(self, tmp_path: Path) -> None:
        """Test exporting to a file."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        output_file = tmp_path / "audit-export.json"

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "audit", "export",
                "--export-format", "json",
                "--output", str(output_file),
            ])
            assert result == EXIT_SUCCESS
            assert output_file.exists()
        finally:
            os.chdir(original_cwd)


class TestAuditShow:
    """Tests for the audit show command."""

    def test_audit_show_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing non-existent log entry."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["audit", "show", "nonexistent-id"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)


class TestAuditNoCommand:
    """Tests for audit without subcommand."""

    def test_audit_no_subcommand(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test audit command without subcommand shows error."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["audit"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "No audit command" in captured.err
        finally:
            os.chdir(original_cwd)


class TestIncidentList:
    """Tests for the incident list command."""

    def test_incident_list_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing when no incidents exist."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["incident", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "No incidents found" in captured.out or "Incidents" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_incident_list_with_filters(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing with filters."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "incident", "list",
                "--status", "OPEN",
                "--severity", "HIGH",
            ])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)


class TestIncidentCreate:
    """Tests for the incident create command."""

    def test_incident_create_basic(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a basic incident."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "incident", "create",
                "--title", "Test Incident",
                "--type", "POLICY_VIOLATION",
                "--description", "A test incident",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Created incident" in captured.out
            assert "Test Incident" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_incident_create_with_severity(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating an incident with severity."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "incident", "create",
                "--title", "High Severity Incident",
                "--type", "DATA_LEAK",
                "--severity", "HIGH",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "HIGH" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_incident_create_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating an incident with JSON output."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "--format", "json",
                "incident", "create",
                "--title", "JSON Incident",
                "--type", "ABUSE",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "incident_id" in data
            assert data["title"] == "JSON Incident"
        finally:
            os.chdir(original_cwd)


class TestIncidentShow:
    """Tests for the incident show command."""

    def test_incident_show_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing non-existent incident."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["incident", "show", "nonexistent-id"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)

    def test_incident_show_created_incident(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing a created incident."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create an incident first
            main([
                "--format", "json",
                "incident", "create",
                "--title", "Show Test Incident",
                "--type", "POLICY_VIOLATION",
            ])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            incident_id = data["incident_id"]

            # Show the incident
            result = main(["incident", "show", incident_id])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Show Test Incident" in captured.out
        finally:
            os.chdir(original_cwd)


class TestIncidentAssign:
    """Tests for the incident assign command."""

    def test_incident_assign(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test assigning an incident."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create an incident first
            main([
                "--format", "json",
                "incident", "create",
                "--title", "Assign Test",
                "--type", "ABUSE",
            ])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            incident_id = data["incident_id"]

            # Assign the incident
            result = main([
                "incident", "assign", incident_id,
                "--assignee", "security-team",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "security-team" in captured.out
        finally:
            os.chdir(original_cwd)


class TestIncidentInvestigate:
    """Tests for the incident investigate command."""

    def test_incident_investigate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test starting investigation."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create an incident
            main([
                "--format", "json",
                "incident", "create",
                "--title", "Investigate Test",
                "--type", "JAILBREAK",
            ])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            incident_id = data["incident_id"]

            # Start investigation
            result = main(["incident", "investigate", incident_id])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "investigation" in captured.out.lower() or "INVESTIGATING" in captured.out
        finally:
            os.chdir(original_cwd)


class TestIncidentResolve:
    """Tests for the incident resolve command."""

    def test_incident_resolve(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test resolving an incident."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create and investigate
            main([
                "--format", "json",
                "incident", "create",
                "--title", "Resolve Test",
                "--type", "POLICY_VIOLATION",
            ])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            incident_id = data["incident_id"]

            main(["incident", "investigate", incident_id])
            capsys.readouterr()

            # Resolve
            result = main([
                "incident", "resolve", incident_id,
                "--resolution", "Fixed the issue",
                "--root-cause", "User misconfiguration",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Resolved" in captured.out or "RESOLVED" in captured.out
        finally:
            os.chdir(original_cwd)


class TestIncidentClose:
    """Tests for the incident close command."""

    def test_incident_close(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test closing an incident."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create, investigate, and resolve
            main([
                "--format", "json",
                "incident", "create",
                "--title", "Close Test",
                "--type", "OTHER",
            ])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            incident_id = data["incident_id"]

            main(["incident", "investigate", incident_id])
            main([
                "incident", "resolve", incident_id,
                "--resolution", "Resolved",
            ])
            capsys.readouterr()

            # Close
            result = main([
                "incident", "close", incident_id,
                "--reason", "All actions complete",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Closed" in captured.out or "CLOSED" in captured.out
        finally:
            os.chdir(original_cwd)


class TestIncidentComment:
    """Tests for the incident comment command."""

    def test_incident_comment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test adding a comment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create an incident
            main([
                "--format", "json",
                "incident", "create",
                "--title", "Comment Test",
                "--type", "ABUSE",
            ])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            incident_id = data["incident_id"]

            # Add comment
            result = main([
                "incident", "comment", incident_id,
                "--message", "This is a test comment",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "comment" in captured.out.lower() or "Added" in captured.out
        finally:
            os.chdir(original_cwd)


class TestIncidentStats:
    """Tests for the incident stats command."""

    def test_incident_stats_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics with no incidents."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["incident", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Incident Statistics" in captured.out or "total_incidents" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_incident_stats_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["--format", "json", "incident", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "total_count" in data
            assert "open_count" in data
        finally:
            os.chdir(original_cwd)


class TestIncidentExport:
    """Tests for the incident export command."""

    def test_incident_export_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test exporting incidents to JSON."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create an incident
            main([
                "incident", "create",
                "--title", "Export Test",
                "--type", "POLICY_VIOLATION",
            ])
            capsys.readouterr()

            # Export
            result = main(["incident", "export"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
            assert len(data) >= 1
        finally:
            os.chdir(original_cwd)


class TestIncidentNoCommand:
    """Tests for incident without subcommand."""

    def test_incident_no_subcommand(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test incident command without subcommand shows error."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["incident"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "No incident command" in captured.err
        finally:
            os.chdir(original_cwd)
