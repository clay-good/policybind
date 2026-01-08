"""
Output formatters for PolicyBind CLI.

This module provides formatting utilities for displaying data
in various formats: table, JSON, and YAML.
"""

import json
import sys
from datetime import datetime
from typing import Any

import yaml


def format_output(
    data: Any,
    output_format: str = "table",
    title: str | None = None,
) -> str:
    """
    Format data for output in the specified format.

    Args:
        data: Data to format.
        output_format: Output format (table, json, yaml).
        title: Optional title for table format.

    Returns:
        Formatted string.
    """
    if output_format == "json":
        return JsonFormatter.format(data)
    elif output_format == "yaml":
        return YamlFormatter.format(data)
    else:
        return TableFormatter.format(data, title=title)


class JsonFormatter:
    """Format data as JSON."""

    @staticmethod
    def format(data: Any, indent: int = 2) -> str:
        """
        Format data as JSON.

        Args:
            data: Data to format.
            indent: Indentation level.

        Returns:
            JSON string.
        """
        return json.dumps(
            data,
            indent=indent,
            default=_json_serializer,
            ensure_ascii=False,
        )


class YamlFormatter:
    """Format data as YAML."""

    @staticmethod
    def format(data: Any) -> str:
        """
        Format data as YAML.

        Args:
            data: Data to format.

        Returns:
            YAML string.
        """
        # Convert datetime objects
        converted = _convert_for_yaml(data)
        return yaml.dump(
            converted,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )


class TableFormatter:
    """Format data as a human-readable table."""

    @staticmethod
    def format(
        data: Any,
        title: str | None = None,
        max_width: int = 80,
    ) -> str:
        """
        Format data as a table.

        Args:
            data: Data to format.
            title: Optional title.
            max_width: Maximum column width.

        Returns:
            Formatted table string.
        """
        lines: list[str] = []

        if title:
            lines.append(title)
            lines.append("-" * len(title))
            lines.append("")

        if isinstance(data, dict):
            lines.extend(TableFormatter._format_dict(data, max_width))
        elif isinstance(data, list):
            lines.extend(TableFormatter._format_list(data, max_width))
        else:
            lines.append(str(data))

        return "\n".join(lines)

    @staticmethod
    def _format_dict(
        data: dict[str, Any],
        max_width: int,
        indent: int = 0,
    ) -> list[str]:
        """Format a dictionary."""
        lines: list[str] = []
        prefix = "  " * indent

        # Find longest key for alignment
        if data:
            max_key_len = max(len(str(k)) for k in data.keys())
        else:
            max_key_len = 0

        for key, value in data.items():
            key_str = str(key).ljust(max_key_len)

            if isinstance(value, dict):
                lines.append(f"{prefix}{key_str}:")
                lines.extend(
                    TableFormatter._format_dict(value, max_width, indent + 1)
                )
            elif isinstance(value, list):
                if not value:
                    lines.append(f"{prefix}{key_str}: []")
                elif all(isinstance(v, (str, int, float, bool)) for v in value):
                    # Simple list on one line
                    list_str = ", ".join(str(v) for v in value)
                    if len(list_str) > max_width - len(key_str) - 4:
                        lines.append(f"{prefix}{key_str}:")
                        for item in value:
                            lines.append(f"{prefix}  - {item}")
                    else:
                        lines.append(f"{prefix}{key_str}: [{list_str}]")
                else:
                    lines.append(f"{prefix}{key_str}:")
                    lines.extend(
                        TableFormatter._format_list(value, max_width, indent + 1)
                    )
            else:
                value_str = str(value) if value is not None else ""
                lines.append(f"{prefix}{key_str}: {value_str}")

        return lines

    @staticmethod
    def _format_list(
        data: list[Any],
        max_width: int,
        indent: int = 0,
    ) -> list[str]:
        """Format a list."""
        lines: list[str] = []
        prefix = "  " * indent

        for i, item in enumerate(data):
            if isinstance(item, dict):
                if i > 0:
                    lines.append("")  # Blank line between dict items
                lines.append(f"{prefix}[{i + 1}]")
                lines.extend(
                    TableFormatter._format_dict(item, max_width, indent + 1)
                )
            elif isinstance(item, list):
                lines.append(f"{prefix}- ")
                lines.extend(
                    TableFormatter._format_list(item, max_width, indent + 1)
                )
            else:
                lines.append(f"{prefix}- {item}")

        return lines

    @staticmethod
    def format_table(
        headers: list[str],
        rows: list[list[Any]],
        max_col_width: int = 40,
    ) -> str:
        """
        Format data as an ASCII table.

        Args:
            headers: Column headers.
            rows: Data rows.
            max_col_width: Maximum column width.

        Returns:
            Formatted table string.
        """
        if not headers:
            return ""

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    cell_len = len(_truncate(str(cell), max_col_width))
                    col_widths[i] = max(col_widths[i], cell_len)

        # Build format string
        row_format = " | ".join(f"{{:<{w}}}" for w in col_widths)
        separator = "-+-".join("-" * w for w in col_widths)

        lines = []
        lines.append(row_format.format(*headers))
        lines.append(separator)

        for row in rows:
            # Pad row to header length
            padded_row = list(row) + [""] * (len(headers) - len(row))
            formatted_cells = [
                _truncate(str(cell), max_col_width) for cell in padded_row
            ]
            lines.append(row_format.format(*formatted_cells))

        return "\n".join(lines)


class Pager:
    """
    Simple pager for long output.

    Supports paging output similar to 'less' or 'more'.
    """

    @staticmethod
    def page(text: str, page_size: int = 25) -> None:
        """
        Page through text output.

        Args:
            text: Text to page.
            page_size: Lines per page.
        """
        lines = text.split("\n")

        if len(lines) <= page_size:
            print(text)
            return

        for i in range(0, len(lines), page_size):
            page_lines = lines[i : i + page_size]
            print("\n".join(page_lines))

            if i + page_size < len(lines):
                try:
                    response = input(
                        "\n-- Press Enter for more, 'q' to quit --"
                    )
                    if response.lower() == "q":
                        break
                except EOFError:
                    break


def _json_serializer(obj: Any) -> Any:
    """
    JSON serializer for non-standard types.

    Args:
        obj: Object to serialize.

    Returns:
        Serializable representation.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _convert_for_yaml(data: Any) -> Any:
    """
    Convert data for YAML serialization.

    Args:
        data: Data to convert.

    Returns:
        YAML-compatible data.
    """
    if isinstance(data, datetime):
        return data.isoformat()
    if isinstance(data, dict):
        return {k: _convert_for_yaml(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_convert_for_yaml(v) for v in data]
    if hasattr(data, "to_dict"):
        return _convert_for_yaml(data.to_dict())
    return data


def _truncate(text: str, max_length: int) -> str:
    """
    Truncate text to maximum length.

    Args:
        text: Text to truncate.
        max_length: Maximum length.

    Returns:
        Truncated text.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to human-readable format.

    Args:
        seconds: Duration in seconds.

    Returns:
        Human-readable duration string.
    """
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"

    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    return f"{hours}h {minutes}m"


def format_size(bytes_count: int) -> str:
    """
    Format a byte count to human-readable format.

    Args:
        bytes_count: Number of bytes.

    Returns:
        Human-readable size string.
    """
    if bytes_count < 1024:
        return f"{bytes_count}B"
    if bytes_count < 1024 * 1024:
        return f"{bytes_count / 1024:.1f}KB"
    if bytes_count < 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 * 1024):.1f}MB"
    return f"{bytes_count / (1024 * 1024 * 1024):.1f}GB"


def format_count(count: int) -> str:
    """
    Format a count with thousand separators.

    Args:
        count: Number to format.

    Returns:
        Formatted number string.
    """
    return f"{count:,}"


def format_percentage(value: float, decimals: int = 1) -> str:
    """
    Format a value as a percentage.

    Args:
        value: Value between 0 and 1.
        decimals: Number of decimal places.

    Returns:
        Percentage string.
    """
    return f"{value * 100:.{decimals}f}%"
