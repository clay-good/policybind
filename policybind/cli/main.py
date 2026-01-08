"""
Main entry point for the PolicyBind CLI.

This module provides the main command-line interface for PolicyBind
using argparse for argument parsing. It supports global options,
subcommands, and proper exit codes.

Exit Codes:
    0: Success
    1: General error
    2: Policy violation or validation error
    3: Configuration error
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Callable

from policybind import __version__
from policybind.exceptions import (
    ConfigurationError,
    PolicyBindError,
    PolicyError,
    ValidationError,
)

# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_VALIDATION_ERROR = 2
EXIT_CONFIG_ERROR = 3


class CLIContext:
    """
    Context object that holds CLI state and configuration.

    Attributes:
        config_path: Path to the configuration file.
        database_path: Path to the database file.
        verbose: Enable verbose output.
        quiet: Suppress non-essential output.
        output_format: Output format (table, json, yaml).
        config: Loaded configuration object.
        database: Database connection.
    """

    def __init__(
        self,
        config_path: str | None = None,
        database_path: str | None = None,
        verbose: bool = False,
        quiet: bool = False,
        output_format: str = "table",
    ) -> None:
        """
        Initialize the CLI context.

        Args:
            config_path: Path to configuration file.
            database_path: Path to database file.
            verbose: Enable verbose output.
            quiet: Suppress non-essential output.
            output_format: Output format.
        """
        self.config_path = config_path
        self.database_path = database_path
        self.verbose = verbose
        self.quiet = quiet
        self.output_format = output_format
        self._config: Any = None
        self._database: Any = None
        self._logger: logging.Logger | None = None
        self._registry_repository: Any = None

    @property
    def config(self) -> Any:
        """
        Load and return configuration.

        Returns:
            PolicyBindConfig object.

        Raises:
            ConfigurationError: If configuration cannot be loaded.
        """
        if self._config is None:
            from policybind.config.loader import ConfigLoader

            loader = ConfigLoader()
            self._config = loader.load(self.config_path)

            # Override database path if specified
            if self.database_path:
                self._config.database.path = self.database_path

        return self._config

    @property
    def database(self) -> Any:
        """
        Get database connection.

        Returns:
            Database instance.

        Raises:
            StorageError: If database connection fails.
        """
        if self._database is None:
            from policybind.storage.database import Database

            db_path = self.database_path or self.config.database.path
            self._database = Database(
                path=db_path,
                pool_size=self.config.database.pool_size,
                timeout=self.config.database.timeout_seconds,
            )
        return self._database

    @property
    def registry_repository(self) -> Any:
        """
        Get registry repository.

        Returns:
            RegistryRepository instance, or None if database not available.
        """
        if self._registry_repository is None:
            try:
                from policybind.storage.repositories import RegistryRepository

                self._registry_repository = RegistryRepository(self.database)
            except Exception:
                # Return None if database is not available
                pass
        return self._registry_repository

    @property
    def logger(self) -> logging.Logger:
        """Get configured logger."""
        if self._logger is None:
            self._logger = logging.getLogger("policybind.cli")
            level = logging.DEBUG if self.verbose else logging.INFO
            if self.quiet:
                level = logging.WARNING
            self._logger.setLevel(level)

            if not self._logger.handlers:
                handler = logging.StreamHandler(sys.stderr)
                handler.setFormatter(
                    logging.Formatter("%(levelname)s: %(message)s")
                )
                self._logger.addHandler(handler)

        return self._logger

    def print(self, message: str, error: bool = False) -> None:
        """
        Print a message to stdout or stderr.

        Args:
            message: The message to print.
            error: If True, print to stderr.
        """
        if self.quiet and not error:
            return
        output = sys.stderr if error else sys.stdout
        print(message, file=output)

    def print_error(self, message: str) -> None:
        """Print an error message to stderr."""
        print(f"Error: {message}", file=sys.stderr)

    def cleanup(self) -> None:
        """Clean up resources."""
        if self._database is not None:
            self._database.close()


def create_parser() -> argparse.ArgumentParser:
    """
    Create the argument parser for the CLI.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="policybind",
        description="PolicyBind: AI Policy as Code Enforcement Platform",
        epilog="Use 'policybind <command> --help' for more information on a command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global options
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"policybind {__version__}",
    )
    parser.add_argument(
        "-c",
        "--config",
        metavar="PATH",
        help="Path to configuration file",
    )
    parser.add_argument(
        "-d",
        "--database",
        metavar="PATH",
        help="Path to database file (overrides config)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential output",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["table", "json", "yaml"],
        default="table",
        help="Output format (default: table)",
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="<command>",
    )

    # Import and register command modules
    _register_commands(subparsers)

    return parser


def _register_commands(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """
    Register all command modules with the parser.

    Args:
        subparsers: Subparsers action to add commands to.
    """
    # Import command modules
    from policybind.cli.commands import audit as audit_cmd
    from policybind.cli.commands import config as config_cmd
    from policybind.cli.commands import incident as incident_cmd
    from policybind.cli.commands import init as init_cmd
    from policybind.cli.commands import policy as policy_cmd
    from policybind.cli.commands import registry as registry_cmd
    from policybind.cli.commands import status as status_cmd
    from policybind.cli.commands import tokens as tokens_cmd

    # Register each command
    init_cmd.register(subparsers)
    config_cmd.register(subparsers)
    status_cmd.register(subparsers)
    policy_cmd.register(subparsers)
    registry_cmd.register(subparsers)
    tokens_cmd.register(subparsers)
    audit_cmd.register(subparsers)
    incident_cmd.register(subparsers)


def run_command(
    args: argparse.Namespace,
    ctx: CLIContext,
) -> int:
    """
    Execute the selected command.

    Args:
        args: Parsed command-line arguments.
        ctx: CLI context object.

    Returns:
        Exit code.
    """
    if not hasattr(args, "func"):
        return EXIT_ERROR

    try:
        return args.func(args, ctx)
    except ConfigurationError as e:
        ctx.print_error(str(e))
        if ctx.verbose and hasattr(e, "details") and e.details:
            ctx.print_error(f"Details: {e.details}")
        return EXIT_CONFIG_ERROR
    except (PolicyError, ValidationError) as e:
        ctx.print_error(str(e))
        if ctx.verbose and hasattr(e, "details") and e.details:
            ctx.print_error(f"Details: {e.details}")
        return EXIT_VALIDATION_ERROR
    except PolicyBindError as e:
        ctx.print_error(str(e))
        if ctx.verbose and hasattr(e, "details") and e.details:
            ctx.print_error(f"Details: {e.details}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        ctx.print("\nOperation cancelled.", error=True)
        return EXIT_ERROR
    except Exception as e:
        ctx.print_error(f"Unexpected error: {e}")
        if ctx.verbose:
            import traceback

            traceback.print_exc()
        return EXIT_ERROR


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code.
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # Check if a command was specified
    if args.command is None:
        parser.print_help()
        return EXIT_SUCCESS

    # Create context
    ctx = CLIContext(
        config_path=args.config,
        database_path=args.database,
        verbose=args.verbose,
        quiet=args.quiet,
        output_format=args.format,
    )

    try:
        return run_command(args, ctx)
    finally:
        ctx.cleanup()


def generate_completion(shell: str) -> str:
    """
    Generate shell completion script.

    Args:
        shell: Shell type (bash, zsh, fish).

    Returns:
        Completion script as string.
    """
    if shell == "bash":
        return _generate_bash_completion()
    elif shell == "zsh":
        return _generate_zsh_completion()
    elif shell == "fish":
        return _generate_fish_completion()
    else:
        raise ValueError(f"Unsupported shell: {shell}")


def _generate_bash_completion() -> str:
    """Generate bash completion script."""
    return '''# Bash completion for policybind
_policybind_completion() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="init config status policy registry token audit incident"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        --config|-c)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --database|-d)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --format|-f)
            COMPREPLY=( $(compgen -W "table json yaml" -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _policybind_completion policybind
'''


def _generate_zsh_completion() -> str:
    """Generate zsh completion script."""
    return '''#compdef policybind

_policybind() {
    local -a commands
    commands=(
        'init:Initialize a new PolicyBind database and config'
        'config:Configuration management'
        'status:Show system status'
        'policy:Policy management'
        'registry:Model registry management'
        'token:Access token management'
        'audit:Audit log queries'
        'incident:Incident management'
    )

    _arguments -C \\
        '-V[Show version]' \\
        '--version[Show version]' \\
        '-c[Config file]:file:_files' \\
        '--config[Config file]:file:_files' \\
        '-d[Database file]:file:_files' \\
        '--database[Database file]:file:_files' \\
        '-v[Verbose output]' \\
        '--verbose[Verbose output]' \\
        '-q[Quiet output]' \\
        '--quiet[Quiet output]' \\
        '-f[Output format]:format:(table json yaml)' \\
        '--format[Output format]:format:(table json yaml)' \\
        '1: :->command' \\
        '*::arg:->args'

    case $state in
        command)
            _describe -t commands 'policybind commands' commands
            ;;
    esac
}

_policybind
'''


def _generate_fish_completion() -> str:
    """Generate fish completion script."""
    return '''# Fish completion for policybind

complete -c policybind -n "__fish_use_subcommand" -a init -d "Initialize database and config"
complete -c policybind -n "__fish_use_subcommand" -a config -d "Configuration management"
complete -c policybind -n "__fish_use_subcommand" -a status -d "Show system status"
complete -c policybind -n "__fish_use_subcommand" -a policy -d "Policy management"
complete -c policybind -n "__fish_use_subcommand" -a registry -d "Model registry management"
complete -c policybind -n "__fish_use_subcommand" -a token -d "Access token management"
complete -c policybind -n "__fish_use_subcommand" -a audit -d "Audit log queries"
complete -c policybind -n "__fish_use_subcommand" -a incident -d "Incident management"

complete -c policybind -s V -l version -d "Show version"
complete -c policybind -s c -l config -r -d "Config file"
complete -c policybind -s d -l database -r -d "Database file"
complete -c policybind -s v -l verbose -d "Verbose output"
complete -c policybind -s q -l quiet -d "Quiet output"
complete -c policybind -s f -l format -xa "table json yaml" -d "Output format"
'''


if __name__ == "__main__":
    sys.exit(main())
