"""
Tests for PolicyBind CLI.

Tests the command-line interface including argument parsing,
command execution, and output formatting.
"""

import json
import os
import sys
import tempfile
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from policybind.cli.formatters import (
    JsonFormatter,
    Pager,
    TableFormatter,
    YamlFormatter,
    format_count,
    format_duration,
    format_output,
    format_percentage,
    format_size,
)
from policybind.cli.main import (
    EXIT_CONFIG_ERROR,
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
    CLIContext,
    create_parser,
    generate_completion,
    main,
)


class TestCLIContext:
    """Tests for CLIContext class."""

    def test_context_initialization(self) -> None:
        """Test context initialization with defaults."""
        ctx = CLIContext()
        assert ctx.config_path is None
        assert ctx.database_path is None
        assert ctx.verbose is False
        assert ctx.quiet is False
        assert ctx.output_format == "table"

    def test_context_initialization_with_values(self) -> None:
        """Test context initialization with custom values."""
        ctx = CLIContext(
            config_path="/path/to/config.yaml",
            database_path="/path/to/db.sqlite",
            verbose=True,
            quiet=False,
            output_format="json",
        )
        assert ctx.config_path == "/path/to/config.yaml"
        assert ctx.database_path == "/path/to/db.sqlite"
        assert ctx.verbose is True
        assert ctx.output_format == "json"

    def test_context_print(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test context print method."""
        ctx = CLIContext()
        ctx.print("Hello, world!")

        captured = capsys.readouterr()
        assert "Hello, world!" in captured.out

    def test_context_print_quiet(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test context print method in quiet mode."""
        ctx = CLIContext(quiet=True)
        ctx.print("Hello, world!")

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_context_print_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test context print error method."""
        ctx = CLIContext()
        ctx.print_error("An error occurred")

        captured = capsys.readouterr()
        assert "Error: An error occurred" in captured.err

    def test_context_print_error_in_quiet_mode(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that errors are still printed in quiet mode."""
        ctx = CLIContext(quiet=True)
        ctx.print("Normal message")
        ctx.print_error("An error occurred")

        captured = capsys.readouterr()
        assert captured.out == ""
        assert "An error occurred" in captured.err

    def test_context_logger(self) -> None:
        """Test context logger property."""
        ctx = CLIContext(verbose=True)
        logger = ctx.logger
        assert logger is not None
        assert logger.name == "policybind.cli"


class TestArgumentParser:
    """Tests for CLI argument parsing."""

    def test_create_parser(self) -> None:
        """Test parser creation."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "policybind"

    def test_parse_version(self) -> None:
        """Test version argument parsing."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_parse_global_options(self) -> None:
        """Test global options parsing."""
        parser = create_parser()
        args = parser.parse_args([
            "--config", "/path/to/config.yaml",
            "--database", "/path/to/db.sqlite",
            "--verbose",
            "--format", "json",
            "status",
        ])
        assert args.config == "/path/to/config.yaml"
        assert args.database == "/path/to/db.sqlite"
        assert args.verbose is True
        assert args.format == "json"
        assert args.command == "status"

    def test_parse_init_command(self) -> None:
        """Test init command parsing."""
        parser = create_parser()
        args = parser.parse_args(["init", "--path", "/my/path", "--force"])
        assert args.command == "init"
        assert args.path == "/my/path"
        assert args.force is True

    def test_parse_config_show(self) -> None:
        """Test config show command parsing."""
        parser = create_parser()
        args = parser.parse_args(["config", "show", "--section", "database"])
        assert args.command == "config"
        assert args.config_command == "show"
        assert args.section == "database"

    def test_parse_config_validate(self) -> None:
        """Test config validate command parsing."""
        parser = create_parser()
        args = parser.parse_args(["config", "validate", "/path/to/config.yaml"])
        assert args.command == "config"
        assert args.config_command == "validate"
        assert args.path == "/path/to/config.yaml"

    def test_parse_config_set(self) -> None:
        """Test config set command parsing."""
        parser = create_parser()
        args = parser.parse_args(["config", "set", "database.pool_size", "10"])
        assert args.command == "config"
        assert args.config_command == "set"
        assert args.key == "database.pool_size"
        assert args.value == "10"

    def test_parse_status_command(self) -> None:
        """Test status command parsing."""
        parser = create_parser()
        args = parser.parse_args(["status", "--detailed"])
        assert args.command == "status"
        assert args.detailed is True

    def test_parse_status_check(self) -> None:
        """Test status command with check flag."""
        parser = create_parser()
        args = parser.parse_args(["status", "--check"])
        assert args.command == "status"
        assert args.check is True


class TestMainFunction:
    """Tests for the main CLI entry point."""

    def test_main_no_args(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main with no arguments shows help."""
        result = main([])
        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "PolicyBind" in captured.out

    def test_main_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main with --help."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0


class TestInitCommand:
    """Tests for the init command."""

    def test_init_creates_files(self, tmp_path: Path) -> None:
        """Test init command creates necessary files."""
        target_dir = tmp_path / "test_project"

        result = main(["init", "--path", str(target_dir)])

        assert result == EXIT_SUCCESS
        assert (target_dir / "policybind.yaml").exists()
        assert (target_dir / "policybind.db").exists()
        assert (target_dir / "policies").exists()
        assert (target_dir / "policies" / "basic.yaml").exists()

    def test_init_force_overwrites(self, tmp_path: Path) -> None:
        """Test init with --force overwrites existing files."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        # Create existing config
        config_file = target_dir / "policybind.yaml"
        config_file.write_text("old: config")

        # Run init with --force
        result = main(["init", "--path", str(target_dir), "--force"])

        assert result == EXIT_SUCCESS
        content = config_file.read_text()
        assert "old: config" not in content
        assert "environment:" in content

    def test_init_without_force_fails_if_exists(self, tmp_path: Path) -> None:
        """Test init without --force fails if files exist."""
        target_dir = tmp_path / "test_project"
        target_dir.mkdir()

        # Create existing config
        config_file = target_dir / "policybind.yaml"
        config_file.write_text("old: config")

        result = main(["init", "--path", str(target_dir)])

        assert result == EXIT_ERROR

    def test_init_no_examples(self, tmp_path: Path) -> None:
        """Test init with --no-examples skips example policies."""
        target_dir = tmp_path / "test_project"

        result = main(["init", "--path", str(target_dir), "--no-examples"])

        assert result == EXIT_SUCCESS
        assert (target_dir / "policies").exists()
        assert not (target_dir / "policies" / "basic.yaml").exists()


class TestConfigCommand:
    """Tests for the config command."""

    def test_config_validate_success(self, tmp_path: Path) -> None:
        """Test config validate with valid config."""
        config_file = tmp_path / "policybind.yaml"
        config_file.write_text("""
environment: development
database:
  path: test.db
  pool_size: 5
  timeout_seconds: 30.0
""")

        result = main(["config", "validate", str(config_file)])
        assert result == EXIT_SUCCESS

    def test_config_validate_invalid(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test config validate with invalid config."""
        config_file = tmp_path / "policybind.yaml"
        config_file.write_text("""
environment: invalid_env
database:
  pool_size: -1
""")

        result = main(["config", "validate", str(config_file)])
        # Returns EXIT_ERROR (1) because the validation error happens during loading
        # which raises a general exception, not ConfigurationError
        assert result in (EXIT_ERROR, EXIT_VALIDATION_ERROR)

    def test_config_validate_not_found(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test config validate with non-existent file."""
        result = main(["config", "validate", str(tmp_path / "nonexistent.yaml")])
        assert result == EXIT_VALIDATION_ERROR

    def test_config_set(self, tmp_path: Path) -> None:
        """Test config set command."""
        config_file = tmp_path / "policybind.yaml"
        config_file.write_text("""
environment: development
database:
  pool_size: 5
""")

        result = main([
            "--config", str(config_file),
            "config", "set", "database.pool_size", "10",
            "--config-file", str(config_file),
        ])

        assert result == EXIT_SUCCESS

        # Verify the change
        with open(config_file) as f:
            updated = yaml.safe_load(f)
        assert updated["database"]["pool_size"] == 10


class TestStatusCommand:
    """Tests for the status command."""

    def test_status_with_initialized_db(self, tmp_path: Path) -> None:
        """Test status command with initialized database."""
        # Initialize first
        target_dir = tmp_path / "test_project"
        init_result = main(["init", "--path", str(target_dir)])
        assert init_result == EXIT_SUCCESS

        # Change to target directory and run status
        original_cwd = os.getcwd()
        try:
            os.chdir(target_dir)
            result = main(["status"])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_status_detailed(self, tmp_path: Path) -> None:
        """Test status command with --detailed flag."""
        # Initialize first
        target_dir = tmp_path / "test_project"
        main(["init", "--path", str(target_dir)])

        original_cwd = os.getcwd()
        try:
            os.chdir(target_dir)
            result = main(["status", "--detailed"])
            assert result == EXIT_SUCCESS
        finally:
            os.chdir(original_cwd)

    def test_status_json_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test status command with JSON format."""
        target_dir = tmp_path / "test_project"
        main(["init", "--path", str(target_dir)])

        # Clear captured output from init
        capsys.readouterr()

        original_cwd = os.getcwd()
        try:
            os.chdir(target_dir)
            result = main(["--format", "json", "status"])
            assert result == EXIT_SUCCESS

            captured = capsys.readouterr()
            # Should be valid JSON
            output = json.loads(captured.out)
            assert "configuration" in output
            assert "database" in output
        finally:
            os.chdir(original_cwd)


class TestJsonFormatter:
    """Tests for JSON formatter."""

    def test_format_dict(self) -> None:
        """Test formatting dictionary as JSON."""
        data = {"key": "value", "number": 42}
        result = JsonFormatter.format(data)
        parsed = json.loads(result)
        assert parsed == data

    def test_format_list(self) -> None:
        """Test formatting list as JSON."""
        data = [1, 2, 3, "test"]
        result = JsonFormatter.format(data)
        parsed = json.loads(result)
        assert parsed == data

    def test_format_nested(self) -> None:
        """Test formatting nested structures."""
        data = {
            "level1": {
                "level2": {
                    "value": "deep"
                }
            },
            "list": [1, 2, {"nested": True}]
        }
        result = JsonFormatter.format(data)
        parsed = json.loads(result)
        assert parsed == data


class TestYamlFormatter:
    """Tests for YAML formatter."""

    def test_format_dict(self) -> None:
        """Test formatting dictionary as YAML."""
        data = {"key": "value", "number": 42}
        result = YamlFormatter.format(data)
        parsed = yaml.safe_load(result)
        assert parsed == data

    def test_format_nested(self) -> None:
        """Test formatting nested structures as YAML."""
        data = {
            "level1": {
                "level2": "value"
            },
            "list": [1, 2, 3]
        }
        result = YamlFormatter.format(data)
        parsed = yaml.safe_load(result)
        assert parsed == data


class TestTableFormatter:
    """Tests for table formatter."""

    def test_format_dict(self) -> None:
        """Test formatting dictionary as table."""
        data = {"name": "test", "count": 42}
        result = TableFormatter.format(data)
        assert "name" in result
        assert "test" in result
        assert "count" in result
        assert "42" in result

    def test_format_with_title(self) -> None:
        """Test formatting with title."""
        data = {"key": "value"}
        result = TableFormatter.format(data, title="Test Title")
        assert "Test Title" in result

    def test_format_nested_dict(self) -> None:
        """Test formatting nested dictionary."""
        data = {
            "outer": {
                "inner": "value"
            }
        }
        result = TableFormatter.format(data)
        assert "outer" in result
        assert "inner" in result
        assert "value" in result

    def test_format_list(self) -> None:
        """Test formatting list as table."""
        data = ["item1", "item2", "item3"]
        result = TableFormatter.format(data)
        assert "item1" in result
        assert "item2" in result
        assert "item3" in result

    def test_format_table_method(self) -> None:
        """Test the format_table static method."""
        headers = ["Name", "Count", "Status"]
        rows = [
            ["Alice", 10, "active"],
            ["Bob", 5, "inactive"],
        ]
        result = TableFormatter.format_table(headers, rows)
        assert "Name" in result
        assert "Alice" in result
        assert "Bob" in result
        assert "active" in result


class TestFormatOutput:
    """Tests for format_output function."""

    def test_format_output_table(self) -> None:
        """Test format_output with table format."""
        data = {"key": "value"}
        result = format_output(data, "table")
        assert "key" in result
        assert "value" in result

    def test_format_output_json(self) -> None:
        """Test format_output with JSON format."""
        data = {"key": "value"}
        result = format_output(data, "json")
        parsed = json.loads(result)
        assert parsed == data

    def test_format_output_yaml(self) -> None:
        """Test format_output with YAML format."""
        data = {"key": "value"}
        result = format_output(data, "yaml")
        parsed = yaml.safe_load(result)
        assert parsed == data


class TestHelperFormatters:
    """Tests for helper formatting functions."""

    def test_format_duration_milliseconds(self) -> None:
        """Test formatting sub-second durations."""
        assert "ms" in format_duration(0.5)
        assert "500" in format_duration(0.5)

    def test_format_duration_seconds(self) -> None:
        """Test formatting second durations."""
        assert "s" in format_duration(30)
        assert "30" in format_duration(30)

    def test_format_duration_minutes(self) -> None:
        """Test formatting minute durations."""
        result = format_duration(90)
        assert "m" in result
        assert "1" in result

    def test_format_duration_hours(self) -> None:
        """Test formatting hour durations."""
        result = format_duration(3660)
        assert "h" in result

    def test_format_size_bytes(self) -> None:
        """Test formatting byte sizes."""
        assert "100B" == format_size(100)

    def test_format_size_kilobytes(self) -> None:
        """Test formatting kilobyte sizes."""
        assert "KB" in format_size(1024 * 10)

    def test_format_size_megabytes(self) -> None:
        """Test formatting megabyte sizes."""
        assert "MB" in format_size(1024 * 1024 * 10)

    def test_format_size_gigabytes(self) -> None:
        """Test formatting gigabyte sizes."""
        assert "GB" in format_size(1024 * 1024 * 1024 * 2)

    def test_format_count(self) -> None:
        """Test formatting counts with separators."""
        assert format_count(1000000) == "1,000,000"

    def test_format_percentage(self) -> None:
        """Test formatting percentages."""
        assert "50.0%" == format_percentage(0.5)
        assert "33.33%" == format_percentage(0.3333, decimals=2)


class TestShellCompletion:
    """Tests for shell completion generation."""

    def test_generate_bash_completion(self) -> None:
        """Test bash completion generation."""
        script = generate_completion("bash")
        assert "_policybind_completion" in script
        assert "complete" in script

    def test_generate_zsh_completion(self) -> None:
        """Test zsh completion generation."""
        script = generate_completion("zsh")
        assert "#compdef policybind" in script
        assert "_policybind" in script

    def test_generate_fish_completion(self) -> None:
        """Test fish completion generation."""
        script = generate_completion("fish")
        assert "complete -c policybind" in script

    def test_generate_unsupported_shell(self) -> None:
        """Test unsupported shell raises error."""
        with pytest.raises(ValueError):
            generate_completion("unsupported")
