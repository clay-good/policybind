"""
Console utilities for PolicyBind CLI.

This module provides color support, progress indicators, and styled output
for terminal interfaces with graceful fallback for non-TTY environments.
"""

import os
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum
from typing import Any


class Color(Enum):
    """ANSI color codes."""

    # Reset
    RESET = "\033[0m"

    # Regular colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"


class Style(Enum):
    """Semantic styles for different message types."""

    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    HEADER = "header"
    MUTED = "muted"
    HIGHLIGHT = "highlight"
    CODE = "code"


# Style to color mapping
STYLE_COLORS: dict[Style, list[Color]] = {
    Style.SUCCESS: [Color.GREEN],
    Style.ERROR: [Color.RED, Color.BOLD],
    Style.WARNING: [Color.YELLOW],
    Style.INFO: [Color.CYAN],
    Style.HEADER: [Color.BOLD, Color.WHITE],
    Style.MUTED: [Color.BRIGHT_BLACK],
    Style.HIGHLIGHT: [Color.BOLD, Color.CYAN],
    Style.CODE: [Color.YELLOW],
}


class Console:
    """
    Terminal console with color and progress support.

    Provides styled output, progress indicators, and spinners
    with automatic fallback for non-TTY environments.
    """

    def __init__(
        self,
        force_color: bool | None = None,
        quiet: bool = False,
        file: Any = None,
    ) -> None:
        """
        Initialize the console.

        Args:
            force_color: Force color on/off (None for auto-detect).
            quiet: Suppress non-essential output.
            file: Output file (defaults to sys.stdout).
        """
        self._file = file or sys.stdout
        self._quiet = quiet
        self._force_color = force_color
        self._color_enabled: bool | None = None

    @property
    def color_enabled(self) -> bool:
        """Check if color output is enabled."""
        if self._color_enabled is not None:
            return self._color_enabled

        if self._force_color is not None:
            self._color_enabled = self._force_color
            return self._color_enabled

        # Auto-detect color support
        self._color_enabled = self._detect_color_support()
        return self._color_enabled

    def _detect_color_support(self) -> bool:
        """Detect if the terminal supports colors."""
        # Check for explicit NO_COLOR environment variable
        if os.environ.get("NO_COLOR"):
            return False

        # Check for explicit FORCE_COLOR environment variable
        if os.environ.get("FORCE_COLOR"):
            return True

        # Check if output is a TTY
        if not hasattr(self._file, "isatty") or not self._file.isatty():
            return False

        # Check TERM environment variable
        term = os.environ.get("TERM", "")
        if term == "dumb":
            return False

        # Windows-specific checks
        if sys.platform == "win32":
            # Windows 10+ supports ANSI colors
            try:
                import ctypes

                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(
                    kernel32.GetStdHandle(-11), 7
                )
                return True
            except Exception:
                return False

        return True

    def _apply_style(self, text: str, style: Style) -> str:
        """Apply a semantic style to text."""
        if not self.color_enabled:
            return text

        colors = STYLE_COLORS.get(style, [])
        if not colors:
            return text

        color_codes = "".join(c.value for c in colors)
        return f"{color_codes}{text}{Color.RESET.value}"

    def _apply_color(self, text: str, *colors: Color) -> str:
        """Apply colors directly to text."""
        if not self.color_enabled:
            return text

        color_codes = "".join(c.value for c in colors)
        return f"{color_codes}{text}{Color.RESET.value}"

    def write(self, text: str, style: Style | None = None) -> None:
        """
        Write text to output.

        Args:
            text: Text to write.
            style: Optional style to apply.
        """
        if style:
            text = self._apply_style(text, style)
        self._file.write(text)
        self._file.flush()

    def writeln(self, text: str = "", style: Style | None = None) -> None:
        """
        Write a line to output.

        Args:
            text: Text to write.
            style: Optional style to apply.
        """
        self.write(text + "\n", style)

    def print(
        self,
        *args: Any,
        style: Style | None = None,
        sep: str = " ",
        end: str = "\n",
    ) -> None:
        """
        Print with optional styling.

        Args:
            args: Values to print.
            style: Optional style to apply.
            sep: Separator between values.
            end: String to append at end.
        """
        if self._quiet and style not in (Style.ERROR,):
            return

        text = sep.join(str(arg) for arg in args)
        if style:
            text = self._apply_style(text, style)
        self._file.write(text + end)
        self._file.flush()

    def success(self, message: str) -> None:
        """Print a success message."""
        prefix = self._apply_color("✓", Color.GREEN) if self.color_enabled else "[OK]"
        self.writeln(f"{prefix} {message}")

    def error(self, message: str) -> None:
        """Print an error message to stderr."""
        prefix = self._apply_color("✗", Color.RED) if self.color_enabled else "[ERROR]"
        output = f"{prefix} {self._apply_style(message, Style.ERROR)}"
        sys.stderr.write(output + "\n")
        sys.stderr.flush()

    def warning(self, message: str) -> None:
        """Print a warning message."""
        if self._quiet:
            return
        prefix = (
            self._apply_color("⚠", Color.YELLOW)
            if self.color_enabled
            else "[WARNING]"
        )
        self.writeln(f"{prefix} {self._apply_style(message, Style.WARNING)}")

    def info(self, message: str) -> None:
        """Print an info message."""
        if self._quiet:
            return
        prefix = self._apply_color("ℹ", Color.CYAN) if self.color_enabled else "[INFO]"
        self.writeln(f"{prefix} {message}")

    def header(self, text: str, char: str = "=") -> None:
        """Print a section header."""
        if self._quiet:
            return
        styled_text = self._apply_style(text, Style.HEADER)
        self.writeln(styled_text)
        self.writeln(char * len(text))

    def muted(self, message: str) -> None:
        """Print muted/dimmed text."""
        if self._quiet:
            return
        self.writeln(message, style=Style.MUTED)

    def code(self, text: str) -> None:
        """Print code/command text."""
        self.writeln(text, style=Style.CODE)

    def table(
        self,
        headers: list[str],
        rows: list[list[Any]],
        max_col_width: int = 40,
    ) -> None:
        """
        Print a formatted table.

        Args:
            headers: Column headers.
            rows: Data rows.
            max_col_width: Maximum column width.
        """
        if not headers:
            return

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    cell_str = str(cell) if cell is not None else ""
                    cell_len = min(len(cell_str), max_col_width)
                    col_widths[i] = max(col_widths[i], cell_len)

        # Build format string
        row_format = " | ".join(f"{{:<{w}}}" for w in col_widths)
        separator = "-+-".join("-" * w for w in col_widths)

        # Print header
        header_row = row_format.format(*headers)
        if self.color_enabled:
            self.writeln(self._apply_color(header_row, Color.BOLD))
        else:
            self.writeln(header_row)
        self.writeln(separator)

        # Print rows
        for row in rows:
            padded_row = list(row) + [""] * (len(headers) - len(row))
            formatted_cells = []
            for i, cell in enumerate(padded_row):
                cell_str = str(cell) if cell is not None else ""
                if len(cell_str) > max_col_width:
                    cell_str = cell_str[: max_col_width - 3] + "..."
                formatted_cells.append(cell_str)
            self.writeln(row_format.format(*formatted_cells))

    def rule(self, char: str = "-", width: int = 40) -> None:
        """Print a horizontal rule."""
        if self._quiet:
            return
        self.writeln(char * width, style=Style.MUTED)

    @contextmanager
    def status(self, message: str) -> Iterator[None]:
        """
        Context manager for status messages with automatic completion.

        Args:
            message: Status message to display.

        Yields:
            None

        Example:
            with console.status("Processing..."):
                do_work()
            # Automatically prints "done" or "failed"
        """
        if self._quiet:
            yield
            return

        self.write(f"{message}... ")
        try:
            yield
            self.writeln(self._apply_style("done", Style.SUCCESS))
        except Exception:
            self.writeln(self._apply_style("failed", Style.ERROR))
            raise

    def progress_bar(
        self,
        current: int,
        total: int,
        width: int = 30,
        prefix: str = "",
        suffix: str = "",
    ) -> None:
        """
        Print a progress bar.

        Args:
            current: Current progress value.
            total: Total value.
            width: Bar width in characters.
            prefix: Text before the bar.
            suffix: Text after the bar.
        """
        if self._quiet:
            return

        if total == 0:
            percentage = 100.0
        else:
            percentage = (current / total) * 100

        filled = int(width * current // max(total, 1))
        bar = "█" * filled + "░" * (width - filled)

        if self.color_enabled:
            bar = self._apply_color(bar, Color.CYAN)

        line = f"\r{prefix}[{bar}] {percentage:5.1f}% {suffix}"
        self._file.write(line)
        self._file.flush()

        if current >= total:
            self._file.write("\n")
            self._file.flush()


class Spinner:
    """
    Animated spinner for long-running operations.

    Shows an animated spinner with a message while a task is running.
    Falls back to simple dots for non-TTY environments.
    """

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    FALLBACK_FRAMES = [".", "..", "...", "...."]

    def __init__(
        self,
        message: str = "Working",
        console: Console | None = None,
    ) -> None:
        """
        Initialize the spinner.

        Args:
            message: Message to display with the spinner.
            console: Console instance (creates new if not provided).
        """
        self._message = message
        self._console = console or Console()
        self._running = False
        self._thread: threading.Thread | None = None
        self._frame_index = 0

    def _get_frames(self) -> list[str]:
        """Get appropriate frames based on terminal capability."""
        if self._console.color_enabled:
            return self.FRAMES
        return self.FALLBACK_FRAMES

    def _spin(self) -> None:
        """Spin animation loop."""
        frames = self._get_frames()
        while self._running:
            frame = frames[self._frame_index % len(frames)]
            if self._console.color_enabled:
                frame = f"\033[36m{frame}\033[0m"
            sys.stdout.write(f"\r{frame} {self._message}")
            sys.stdout.flush()
            self._frame_index += 1
            time.sleep(0.1)

    def start(self) -> "Spinner":
        """Start the spinner animation."""
        if self._console._quiet:
            return self
        if not sys.stdout.isatty():
            sys.stdout.write(f"{self._message}...")
            sys.stdout.flush()
            return self

        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def stop(self, success: bool = True, message: str | None = None) -> None:
        """
        Stop the spinner.

        Args:
            success: Whether the operation succeeded.
            message: Optional completion message.
        """
        if self._console._quiet:
            return

        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)

        if sys.stdout.isatty():
            # Clear the spinner line
            sys.stdout.write("\r" + " " * (len(self._message) + 10) + "\r")

        if message:
            if success:
                self._console.success(message)
            else:
                self._console.error(message)
        elif sys.stdout.isatty():
            if success:
                self._console.success(self._message)
            else:
                self._console.error(self._message)
        else:
            # Non-TTY fallback
            status = "done" if success else "failed"
            sys.stdout.write(f" {status}\n")
            sys.stdout.flush()

    def __enter__(self) -> "Spinner":
        """Context manager entry."""
        return self.start()

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: Exception | None,
        exc_tb: Any,
    ) -> None:
        """Context manager exit."""
        self.stop(success=exc_type is None)


@contextmanager
def spinner(message: str, console: Console | None = None) -> Iterator[Spinner]:
    """
    Context manager for spinner.

    Args:
        message: Message to display.
        console: Console instance.

    Yields:
        Spinner instance.

    Example:
        with spinner("Loading data"):
            load_data()
    """
    s = Spinner(message, console)
    try:
        s.start()
        yield s
    except Exception:
        s.stop(success=False)
        raise
    else:
        s.stop(success=True)


def format_error_with_code(
    code: str,
    message: str,
    suggestion: str | None = None,
    console: Console | None = None,
) -> str:
    """
    Format an error message with code and suggestion.

    Args:
        code: Error code (e.g., "E1001").
        message: Error message.
        suggestion: Optional suggestion for fixing the error.
        console: Console instance for color support.

    Returns:
        Formatted error string.
    """
    console = console or Console()

    parts = []

    # Format code
    if console.color_enabled:
        code_str = f"\033[1;31m[{code}]\033[0m"
    else:
        code_str = f"[{code}]"

    parts.append(f"{code_str} {message}")

    if suggestion:
        if console.color_enabled:
            suggestion_str = f"\033[33m→ {suggestion}\033[0m"
        else:
            suggestion_str = f"Suggestion: {suggestion}"
        parts.append(suggestion_str)

    return "\n".join(parts)


def confirm(prompt: str, default: bool = False) -> bool:
    """
    Ask for user confirmation.

    Args:
        prompt: Prompt text.
        default: Default value if user presses Enter.

    Returns:
        True if confirmed, False otherwise.
    """
    suffix = " [Y/n]" if default else " [y/N]"
    response = input(prompt + suffix + " ").strip().lower()

    if not response:
        return default

    return response in ("y", "yes")
