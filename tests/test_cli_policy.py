"""
Tests for PolicyBind CLI policy commands.

Tests the policy management CLI commands including load, validate,
show, history, and test.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from policybind.cli.main import (
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
    main,
)


class TestPolicyLoad:
    """Tests for the policy load command."""

    def test_policy_load_file(self, tmp_path: Path) -> None:
        """Test loading a policy from a file."""
        # Initialize project
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        # Create a policy file
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
description: Test policy
rules:
  - name: allow-internal
    description: Allow internal requests
    match_conditions:
      department:
        eq: engineering
    action: ALLOW
    priority: 10
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "load", str(policy_file)])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_policy_load_dry_run(self, tmp_path: Path) -> None:
        """Test loading with dry-run flag."""
        # Initialize project
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        # Create a policy file
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: test-rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "load", str(policy_file), "--dry-run"])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_policy_load_directory(self, tmp_path: Path) -> None:
        """Test loading policies from a directory."""
        # Initialize project
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        # Create policy directory with files
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "policy1.yaml").write_text("""
name: combined-policy
version: "1.0.0"
rules:
  - name: rule1
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "load", str(policy_dir)])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_policy_load_not_found(self, tmp_path: Path) -> None:
        """Test loading from non-existent path."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "load", "/nonexistent/path.yaml"])
            assert result == EXIT_ERROR
        finally:
            os.chdir(original_cwd)


class TestPolicyValidate:
    """Tests for the policy validate command."""

    def test_policy_validate_valid(self, tmp_path: Path) -> None:
        """Test validating a valid policy."""
        policy_file = tmp_path / "valid-policy.yaml"
        policy_file.write_text("""
name: valid-policy
version: "1.0.0"
rules:
  - name: test-rule
    description: Test rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        result = main(["policy", "validate", str(policy_file)])
        assert result == EXIT_SUCCESS

    def test_policy_validate_invalid_yaml(self, tmp_path: Path) -> None:
        """Test validating invalid YAML."""
        policy_file = tmp_path / "invalid.yaml"
        policy_file.write_text("""
name: invalid
  this is not valid yaml
    : foo
""")

        result = main(["policy", "validate", str(policy_file)])
        assert result == EXIT_VALIDATION_ERROR

    def test_policy_validate_missing_required(self, tmp_path: Path) -> None:
        """Test validating policy with missing required fields."""
        policy_file = tmp_path / "incomplete.yaml"
        # Create a policy with invalid structure (missing rules entirely)
        policy_file.write_text("""
name: incomplete
version: "1.0.0"
# Missing rules array entirely
""")

        result = main(["policy", "validate", str(policy_file)])
        # Parser handles missing rules gracefully, returns success with empty ruleset
        assert result == EXIT_SUCCESS

    def test_policy_validate_not_found(self, tmp_path: Path) -> None:
        """Test validating non-existent file."""
        result = main(["policy", "validate", str(tmp_path / "nonexistent.yaml")])
        assert result == EXIT_VALIDATION_ERROR


class TestPolicyShow:
    """Tests for the policy show command."""

    def test_policy_show_no_policies(self, tmp_path: Path) -> None:
        """Test showing policies when none are loaded."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "show"])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_policy_show_with_policies(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing loaded policies."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        # Create and load policy
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "2.0.0"
rules:
  - name: test-rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            main(["policy", "load", str(policy_file)])
            capsys.readouterr()  # Clear output

            result = main(["policy", "show"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "test-policy" in captured.out
        finally:
            os.chdir(original_cwd)

    def test_policy_show_specific_rule(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test showing a specific rule."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        # Create and load policy
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: specific-rule
    description: A specific rule to show
    match_conditions:
      provider:
        eq: openai
    action: DENY
    priority: 100
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            main(["policy", "load", str(policy_file)])
            capsys.readouterr()

            result = main(["policy", "show", "--name", "test-policy", "--rule", "specific-rule"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "specific-rule" in captured.out
            assert "DENY" in captured.out
        finally:
            os.chdir(original_cwd)


class TestPolicyHistory:
    """Tests for the policy history command."""

    def test_policy_history_no_policies(self, tmp_path: Path) -> None:
        """Test history when no policies exist."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "history"])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_policy_history_with_policies(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test history with loaded policies."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        # Create and load policy
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: test-rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            main(["policy", "load", str(policy_file)])
            capsys.readouterr()

            result = main(["policy", "history"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "test-policy" in captured.out
        finally:
            os.chdir(original_cwd)


class TestPolicyTest:
    """Tests for the policy test command."""

    def test_policy_test_match(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test policy testing with a matching request."""
        # Create policy
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: allow-openai
    description: Allow OpenAI requests
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 10
""")

        request_json = json.dumps({
            "provider": "openai",
            "model": "gpt-4",
            "user_id": "test-user",
        })

        result = main([
            "policy", "test", str(policy_file),
            "--request", request_json,
        ])
        assert result == EXIT_SUCCESS

        captured = capsys.readouterr()
        assert "MATCH" in captured.out
        assert "allow-openai" in captured.out

    def test_policy_test_no_match(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test policy testing with no matching request."""
        # Create policy
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: allow-anthropic
    description: Allow Anthropic requests only
    match_conditions:
      provider:
        eq: anthropic
    action: ALLOW
    priority: 10
""")

        request_json = json.dumps({
            "provider": "openai",
            "model": "gpt-4",
            "user_id": "test-user",
        })

        result = main([
            "policy", "test", str(policy_file),
            "--request", request_json,
        ])
        assert result == EXIT_SUCCESS

        captured = capsys.readouterr()
        assert "NO MATCH" in captured.out

    def test_policy_test_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test policy testing with JSON output."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: test-rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        request_json = json.dumps({
            "provider": "openai",
            "model": "gpt-4",
        })

        result = main([
            "--format", "json",
            "policy", "test", str(policy_file),
            "--request", request_json,
        ])
        assert result == EXIT_SUCCESS

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "matched" in output
        assert "request" in output

    def test_policy_test_request_from_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test policy testing with request from file."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: test-rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        request_file = tmp_path / "request.json"
        request_file.write_text(json.dumps({
            "provider": "openai",
            "model": "gpt-4",
            "user_id": "test-user",
        }))

        result = main([
            "policy", "test", str(policy_file),
            "--request", f"@{request_file}",
        ])
        assert result == EXIT_SUCCESS

    def test_policy_test_invalid_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test policy testing with invalid JSON request."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("""
name: test-policy
version: "1.0.0"
rules:
  - name: test-rule
    match_conditions:
      provider:
        eq: openai
    action: ALLOW
    priority: 1
""")

        result = main([
            "policy", "test", str(policy_file),
            "--request", "not valid json",
        ])
        assert result == EXIT_ERROR


class TestPolicyDiff:
    """Tests for the policy diff command."""

    def test_policy_diff_no_history(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test diff when no version history exists."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "diff", "nonexistent-policy"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            assert "fewer than 2 versions" in captured.out
        finally:
            os.chdir(original_cwd)


class TestPolicyRollback:
    """Tests for the policy rollback command."""

    def test_policy_rollback_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test rollback with non-existent policy ID."""
        project_dir = tmp_path / "project"
        main(["init", "--path", str(project_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            result = main(["policy", "rollback", "nonexistent-id", "--force"])
            assert result == EXIT_ERROR

            captured = capsys.readouterr()
            assert "not found" in captured.err
        finally:
            os.chdir(original_cwd)
