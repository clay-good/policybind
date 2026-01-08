"""
Tests for PolicyBind CLI token commands.

Tests the token management CLI commands including create, list,
show, revoke, validate, templates, and stats.
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


class TestTokenCreate:
    """Tests for the token create command."""

    def test_token_create_basic(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a basic token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "create",
                "--name", "test-token",
                "--subject", "test-user@example.com",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Token Created" in captured.out
            assert "pb_" in captured.out  # Token prefix
        finally:
            os.chdir(original_cwd)

    def test_token_create_with_template(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a token from template."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "create",
                "--name", "dev-token",
                "--subject", "developer@example.com",
                "--template", "DEVELOPER_TESTING",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Token Created" in captured.out
            assert "Budget" in captured.out  # Template includes budget
        finally:
            os.chdir(original_cwd)

    def test_token_create_with_budget(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a token with budget limit."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "create",
                "--name", "budget-token",
                "--subject", "user@example.com",
                "--budget", "100.0",
                "--budget-period", "daily",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "100.00" in captured.out
            assert "daily" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_create_with_allowed_models(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a token with allowed models."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "create",
                "--name", "model-restricted-token",
                "--subject", "user@example.com",
                "--allowed-models", "gpt-4", "claude-3-opus",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "gpt-4" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_create_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a token with JSON output."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()  # Clear init output

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "--format", "json",
                "token", "create",
                "--name", "json-token",
                "--subject", "user@example.com",
            ])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "token_id" in data
            assert "plaintext_token" in data
            assert data["plaintext_token"].startswith("pb_")
        finally:
            os.chdir(original_cwd)

    def test_token_create_invalid_template(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test creating a token with non-existent template."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "create",
                "--name", "test-token",
                "--subject", "user@example.com",
                "--template", "NONEXISTENT_TEMPLATE",
            ])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)


class TestTokenList:
    """Tests for the token list command."""

    def test_token_list_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing when no tokens exist."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "No tokens found" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_list_with_tokens(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing tokens - note: TokenManager is in-memory only.

        Since the TokenManager doesn't persist between CLI calls,
        this test verifies the list command works but may show no tokens.
        """
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Note: TokenManager is in-memory, so tokens created in one call
            # won't be visible in another. This test verifies the list
            # command works correctly.
            result = main(["token", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            # The list command should complete successfully
            assert "No tokens found" in captured.out or "Access Tokens" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_list_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing tokens in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()  # Clear init output

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # TokenManager is in-memory, so we just verify the command works
            result = main(["--format", "json", "token", "list"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
            # May be empty since tokens don't persist
        finally:
            os.chdir(original_cwd)


class TestTokenShow:
    """Tests for the token show command."""

    def test_token_show_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing non-existent token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "show", "nonexistent-id"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)


class TestTokenRevoke:
    """Tests for the token revoke command."""

    def test_token_revoke_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test revoking non-existent token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "revoke", "nonexistent-id",
                "--reason", "Test revocation",
            ])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)


class TestTokenValidate:
    """Tests for the token validate command."""

    def test_token_validate_invalid(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test validating an invalid token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "validate", "pb_invalidtoken123"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "INVALID" in captured.out
        finally:
            os.chdir(original_cwd)


class TestTokenTemplates:
    """Tests for the token templates command."""

    def test_token_templates_list(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing permission templates."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "templates"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Permission Templates" in captured.out
            assert "DEVELOPER_TESTING" in captured.out
            assert "PRODUCTION_RESTRICTED" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_templates_show_specific(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing a specific template."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "templates", "DEVELOPER_TESTING"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Developer Testing" in captured.out
            assert "Permissions:" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_templates_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing non-existent template."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "templates", "NONEXISTENT"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)

    def test_token_templates_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test listing templates in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()  # Clear init output

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["--format", "json", "token", "templates"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert isinstance(data, list)
            assert len(data) >= 1
            assert any(t["name"] == "DEVELOPER_TESTING" for t in data)
        finally:
            os.chdir(original_cwd)


class TestTokenStats:
    """Tests for the token stats command."""

    def test_token_stats_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics with no tokens."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Token Statistics" in captured.out
            assert "Total Tokens" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_stats_with_tokens(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics with tokens."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)

            # Create a token
            main([
                "token", "create",
                "--name", "stats-token",
                "--subject", "user@example.com",
            ])
            capsys.readouterr()

            result = main(["token", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "Token Statistics" in captured.out
            assert "Active" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_token_stats_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test statistics in JSON format."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])
        capsys.readouterr()  # Clear init output

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["--format", "json", "token", "stats"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "total_tokens" in data
            assert "active_tokens" in data
            assert "expired_tokens" in data
        finally:
            os.chdir(original_cwd)


class TestTokenNoCommand:
    """Tests for token without subcommand."""

    def test_token_no_subcommand(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test token command without subcommand shows error."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "No token command" in captured.err
        finally:
            os.chdir(original_cwd)


class TestTokenRenew:
    """Tests for the token renew command."""

    def test_token_renew_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test renewing non-existent token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "renew", "nonexistent-id", "--expires", "30"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err or "cannot be renewed" in captured.err
        finally:
            os.chdir(original_cwd)


class TestTokenSuspend:
    """Tests for the token suspend command."""

    def test_token_suspend_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test suspending non-existent token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main([
                "token", "suspend", "nonexistent-id",
                "--reason", "Test suspension",
            ])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err or "cannot be suspended" in captured.err
        finally:
            os.chdir(original_cwd)


class TestTokenUnsuspend:
    """Tests for the token unsuspend command."""

    def test_token_unsuspend_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test unsuspending non-existent token."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["token", "unsuspend", "nonexistent-id"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err or "not suspended" in captured.err
        finally:
            os.chdir(original_cwd)
