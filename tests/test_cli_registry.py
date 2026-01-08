"""
Tests for PolicyBind CLI registry commands.

Tests the registry management CLI commands including add, list,
show, update, suspend, approve, compliance, and export.
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


class TestRegistryAdd:
    """Tests for the registry add command."""

    def test_registry_add_basic(self, tmp_path: Path) -> None:
        """Test adding a basic deployment."""
        # Initialize project
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "registry", "add",
                "--name", "Test Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_registry_add_with_risk_level(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test adding a deployment with explicit risk level."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            # High-risk deployments require data categories and description
            result = main([
                "registry", "add",
                "--name", "High Risk Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-risk",
                "--owner-contact", "risk@example.com",
                "--risk-level", "HIGH",
                "--description", "A high-risk deployment for processing sensitive data",
                "--data-categories", "pii", "financial",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "HIGH" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_add_with_data_categories(self, tmp_path: Path) -> None:
        """Test adding a deployment with data categories."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "registry", "add",
                "--name", "Data Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-data",
                "--owner-contact", "data@example.com",
                "--data-categories", "pii", "financial",
            ])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_registry_add_missing_required(self, tmp_path: Path) -> None:
        """Test adding a deployment with missing required fields."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            # Missing --owner-contact
            result = main([
                "registry", "add",
                "--name", "Test Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
            ])
            # Should fail due to missing required argument
            assert result != EXIT_SUCCESS
        except SystemExit:
            # argparse exits on missing required args
            pass
        finally:
            os.chdir(original_cwd)


class TestRegistryList:
    """Tests for the registry list command."""

    def test_registry_list_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing when no deployments exist."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["registry", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "No deployments found" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_list_with_deployments(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing deployments."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add a deployment
            main([
                "registry", "add",
                "--name", "Test Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()  # Clear output

            # List deployments
            result = main(["registry", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Test Bot" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_list_with_status_filter(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing with status filter."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add a deployment (starts as PENDING)
            main([
                "registry", "add",
                "--name", "Pending Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            # List only PENDING
            result = main(["registry", "list", "--status", "PENDING"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Pending Bot" in captured.out

            # List only APPROVED (should find nothing)
            result = main(["registry", "list", "--status", "APPROVED"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "No deployments found" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_list_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add a deployment
            main([
                "registry", "add",
                "--name", "JSON Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            # List in JSON format
            result = main(["--format", "json", "registry", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
            assert len(data) >= 1
            assert any(d["name"] == "JSON Bot" for d in data)
        finally:
            os.chdir(original_cwd)


class TestRegistryShow:
    """Tests for the registry show command."""

    def test_registry_show_by_name(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing deployment by name."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add a deployment
            main([
                "registry", "add",
                "--name", "Show Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
                "--description", "A test bot for showing",
            ])
            capsys.readouterr()

            # Show the deployment
            result = main(["registry", "show", "Show Bot"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Show Bot" in captured.out
            assert "gpt-4" in captured.out
            assert "openai" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_show_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing non-existent deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["registry", "show", "nonexistent"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)

    def test_registry_show_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing deployment in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "JSON Show Bot",
                "--model", "claude-3-opus",
                "--provider", "anthropic",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            result = main(["--format", "json", "registry", "show", "JSON Show Bot"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["name"] == "JSON Show Bot"
            assert data["model_name"] == "claude-3-opus"
            assert data["model_provider"] == "anthropic"
        finally:
            os.chdir(original_cwd)


class TestRegistryUpdate:
    """Tests for the registry update command."""

    def test_registry_update_description(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test updating deployment description."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add a deployment
            main([
                "registry", "add",
                "--name", "Update Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            # Update description
            result = main([
                "registry", "update", "Update Bot",
                "--description", "Updated description",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "updated" in captured.out.lower()
        finally:
            os.chdir(original_cwd)

    def test_registry_update_risk_level(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test updating risk level."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Start with LOW risk with description and data categories
            # so it can be upgraded to HIGH
            main([
                "registry", "add",
                "--name", "Risk Update Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
                "--risk-level", "LOW",
                "--description", "A bot that may be upgraded to high-risk",
                "--data-categories", "internal", "pii",
            ])
            capsys.readouterr()

            # Update risk level to HIGH (allowed because we have description and data categories)
            result = main([
                "registry", "update", "Risk Update Bot",
                "--risk-level", "HIGH",
            ])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_registry_update_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test updating non-existent deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "registry", "update", "nonexistent",
                "--description", "New desc",
            ])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)


class TestRegistrySuspend:
    """Tests for the registry suspend command."""

    def test_registry_suspend(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test suspending a deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "Suspend Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            result = main([
                "registry", "suspend", "Suspend Bot",
                "--reason", "Policy violation",
                "--force",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Suspended" in captured.out or "suspend" in captured.out.lower()
        finally:
            os.chdir(original_cwd)

    def test_registry_suspend_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test suspending non-existent deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "registry", "suspend", "nonexistent",
                "--reason", "Test",
                "--force",
            ])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)


class TestRegistryApprove:
    """Tests for the registry approve command."""

    def test_registry_approve(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test approving a deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "Approve Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            result = main([
                "registry", "approve", "Approve Bot",
                "--ticket", "TICKET-123",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Approved" in captured.out or "approve" in captured.out.lower()
            assert "TICKET-123" in captured.out
        finally:
            os.chdir(original_cwd)


class TestRegistryReject:
    """Tests for the registry reject command."""

    def test_registry_reject(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test rejecting a deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "Reject Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            result = main([
                "registry", "reject", "Reject Bot",
                "--reason", "Does not meet requirements",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Rejected" in captured.out or "reject" in captured.out.lower()
        finally:
            os.chdir(original_cwd)


class TestRegistryReinstate:
    """Tests for the registry reinstate command."""

    def test_registry_reinstate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test reinstating a suspended deployment."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add and approve first
            main([
                "registry", "add",
                "--name", "Reinstate Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            main(["registry", "approve", "Reinstate Bot", "--ticket", "T-1"])

            # Suspend
            main([
                "registry", "suspend", "Reinstate Bot",
                "--reason", "Temporary issue",
                "--force",
            ])
            capsys.readouterr()

            # Reinstate
            result = main([
                "registry", "reinstate", "Reinstate Bot",
                "--notes", "Issue resolved",
                "--force",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Reinstated" in captured.out or "reinstate" in captured.out.lower()
        finally:
            os.chdir(original_cwd)


class TestRegistryCompliance:
    """Tests for the registry compliance command."""

    def test_registry_compliance_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test running compliance check."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "Compliance Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
                "--description", "A compliance-ready bot",
            ])
            capsys.readouterr()

            result = main(["registry", "compliance", "Compliance Bot"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Compliance" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_compliance_specific_framework(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test checking specific compliance framework."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "NIST Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            result = main([
                "registry", "compliance", "NIST Bot",
                "--framework", "nist_ai_rmf",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "nist" in captured.out.lower()
        finally:
            os.chdir(original_cwd)

    def test_registry_compliance_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test compliance check with JSON output."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "JSON Compliance Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-test",
                "--owner-contact", "test@example.com",
            ])
            capsys.readouterr()

            result = main([
                "--format", "json",
                "registry", "compliance", "JSON Compliance Bot",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "overall_status" in data
            assert "gaps" in data
        finally:
            os.chdir(original_cwd)


class TestRegistryExport:
    """Tests for the registry export command."""

    def test_registry_export_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test exporting registry to JSON."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add some deployments
            main([
                "registry", "add",
                "--name", "Export Bot 1",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-a",
                "--owner-contact", "a@example.com",
            ])
            main([
                "registry", "add",
                "--name", "Export Bot 2",
                "--model", "claude-3",
                "--provider", "anthropic",
                "--owner", "team-b",
                "--owner-contact", "b@example.com",
            ])
            capsys.readouterr()

            result = main(["registry", "export", "--export-format", "json"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
            assert len(data) >= 2
        finally:
            os.chdir(original_cwd)

    def test_registry_export_csv(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test exporting registry to CSV."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "CSV Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-csv",
                "--owner-contact", "csv@example.com",
            ])
            capsys.readouterr()

            result = main(["registry", "export", "--export-format", "csv"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            # Check CSV headers
            assert "deployment_id" in captured.out
            assert "name" in captured.out
            assert "CSV Bot" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_export_to_file(self, tmp_path: Path) -> None:
        """Test exporting registry to a file."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        output_file = tmp_path / "export.json"

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "File Export Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-file",
                "--owner-contact", "file@example.com",
            ])

            result = main([
                "registry", "export",
                "--export-format", "json",
                "--output", str(output_file),
            ])
            assert result == EXIT_SUCCESS

            # Verify file exists and contains data
            assert output_file.exists()
            with open(output_file) as f:
                data = json.load(f)
            assert isinstance(data, list)
            assert len(data) >= 1
        finally:
            os.chdir(original_cwd)


class TestRegistryStats:
    """Tests for the registry stats command."""

    def test_registry_stats_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics with no deployments."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["registry", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Statistics" in captured.out
            assert "Total Deployments" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_stats_with_deployments(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics with deployments."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Add deployments with different risk levels
            main([
                "registry", "add",
                "--name", "Low Risk Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-low",
                "--owner-contact", "low@example.com",
                "--risk-level", "LOW",
            ])
            main([
                "registry", "add",
                "--name", "High Risk Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-high",
                "--owner-contact", "high@example.com",
                "--risk-level", "HIGH",
            ])
            capsys.readouterr()

            result = main(["registry", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Total Deployments" in captured.out
            assert "By Status" in captured.out
            assert "By Risk Level" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_registry_stats_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            main([
                "registry", "add",
                "--name", "Stats Bot",
                "--model", "gpt-4",
                "--provider", "openai",
                "--owner", "team-stats",
                "--owner-contact", "stats@example.com",
            ])
            capsys.readouterr()

            result = main(["--format", "json", "registry", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "total_deployments" in data
            assert "by_status" in data
            assert "by_risk_level" in data
        finally:
            os.chdir(original_cwd)


class TestRegistryNoCommand:
    """Tests for registry without subcommand."""

    def test_registry_no_subcommand(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test registry command without subcommand shows error."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["registry"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "No registry command" in captured.err
        finally:
            os.chdir(original_cwd)
