"""
Base templates for PolicyBind reports.

This module provides template management using Python's string.Template
for generating reports in various formats without external dependencies.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from string import Template
from typing import Any

logger = logging.getLogger("policybind.reports.templates")


class TemplateType(Enum):
    """Types of report templates."""

    # Report section templates
    HEADER = "header"
    FOOTER = "footer"
    SECTION = "section"
    TABLE = "table"
    SUMMARY = "summary"

    # Full report templates
    POLICY_COMPLIANCE = "policy_compliance"
    USAGE_COST = "usage_cost"
    INCIDENT_SUMMARY = "incident_summary"
    AUDIT_TRAIL = "audit_trail"
    RISK_ASSESSMENT = "risk_assessment"
    REGISTRY_STATUS = "registry_status"


@dataclass
class ReportTemplate:
    """
    A report template definition.

    Attributes:
        name: Template name/identifier.
        template_type: Type of template.
        format: Output format (markdown, html, text).
        content: The template content with placeholders.
        description: Human-readable description.
        variables: List of expected variables.
    """

    name: str
    template_type: TemplateType
    format: str
    content: str
    description: str = ""
    variables: list[str] = field(default_factory=list)

    def render(self, **kwargs: Any) -> str:
        """
        Render the template with the provided variables.

        Args:
            **kwargs: Template variables.

        Returns:
            Rendered template string.
        """
        template = Template(self.content)
        return template.safe_substitute(**kwargs)


class TemplateManager:
    """
    Manages report templates for PolicyBind.

    Provides access to built-in templates and supports custom templates
    for organizational branding.

    Example:
        Using the TemplateManager::

            from policybind.reports.templates import TemplateManager, TemplateType

            manager = TemplateManager()

            # Get a template
            header = manager.get_template(TemplateType.HEADER, format="markdown")

            # Render the template
            output = header.render(
                title="My Report",
                organization="ACME Corp",
                generated_at="2024-01-15",
            )

            # Register a custom template
            manager.register_template(
                name="custom_header",
                template_type=TemplateType.HEADER,
                format="markdown",
                content="# ${title}\\n\\nCustom header for ${organization}",
            )
    """

    def __init__(self) -> None:
        """Initialize the template manager with built-in templates."""
        self._templates: dict[str, ReportTemplate] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self) -> None:
        """Load all built-in templates."""
        # Markdown templates
        self._register_markdown_templates()
        # HTML templates
        self._register_html_templates()
        # Text templates
        self._register_text_templates()

    def _register_markdown_templates(self) -> None:
        """Register built-in Markdown templates."""
        # Header template
        self._templates["header_markdown"] = ReportTemplate(
            name="header_markdown",
            template_type=TemplateType.HEADER,
            format="markdown",
            content="""# ${title}

**Organization:** ${organization}
**Generated:** ${generated_at}
${period_line}
""",
            description="Standard Markdown report header",
            variables=["title", "organization", "generated_at", "period_line"],
        )

        # Footer template
        self._templates["footer_markdown"] = ReportTemplate(
            name="footer_markdown",
            template_type=TemplateType.FOOTER,
            format="markdown",
            content="""---

*Report ID: ${report_id}*
*${footer_text}*
""",
            description="Standard Markdown report footer",
            variables=["report_id", "footer_text"],
        )

        # Section template
        self._templates["section_markdown"] = ReportTemplate(
            name="section_markdown",
            template_type=TemplateType.SECTION,
            format="markdown",
            content="""## ${title}

${content}
""",
            description="Standard Markdown section",
            variables=["title", "content"],
        )

        # Summary section template
        self._templates["summary_markdown"] = ReportTemplate(
            name="summary_markdown",
            template_type=TemplateType.SUMMARY,
            format="markdown",
            content="""## Executive Summary

${summary_text}

### Key Metrics

${metrics_list}
""",
            description="Executive summary section",
            variables=["summary_text", "metrics_list"],
        )

        # Table template
        self._templates["table_markdown"] = ReportTemplate(
            name="table_markdown",
            template_type=TemplateType.TABLE,
            format="markdown",
            content="""| ${header_row} |
|${separator_row}|
${data_rows}
""",
            description="Markdown table template",
            variables=["header_row", "separator_row", "data_rows"],
        )

    def _register_html_templates(self) -> None:
        """Register built-in HTML templates."""
        # HTML document template
        self._templates["document_html"] = ReportTemplate(
            name="document_html",
            template_type=TemplateType.HEADER,
            format="html",
            content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        ${styles}
    </style>
</head>
<body>
    <div class="report-container">
        ${logo_html}
        <h1>${title}</h1>
        <div class="report-meta">
            <p><strong>Organization:</strong> ${organization}</p>
            <p><strong>Generated:</strong> ${generated_at}</p>
            ${period_html}
        </div>
        <main>
            ${content}
        </main>
        <footer>
            <p>${footer_text}</p>
            <p>Report ID: ${report_id}</p>
        </footer>
    </div>
</body>
</html>""",
            description="Full HTML document template",
            variables=[
                "title",
                "styles",
                "logo_html",
                "organization",
                "generated_at",
                "period_html",
                "content",
                "footer_text",
                "report_id",
            ],
        )

        # Default CSS styles
        self._templates["styles_html"] = ReportTemplate(
            name="styles_html",
            template_type=TemplateType.SECTION,
            format="html",
            content="""
        :root {
            --primary-color: ${primary_color};
            --secondary-color: ${secondary_color};
            --background-color: #f8fafc;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background: var(--background-color);
        }

        .report-container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        h1 {
            color: var(--primary-color);
            font-size: 2em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid var(--primary-color);
        }

        h2 {
            color: var(--secondary-color);
            font-size: 1.5em;
            margin: 30px 0 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
        }

        h3 {
            color: var(--text-color);
            font-size: 1.2em;
            margin: 20px 0 10px;
        }

        .report-meta {
            background: var(--background-color);
            padding: 15px 20px;
            border-radius: 6px;
            margin-bottom: 30px;
        }

        .report-meta p {
            margin: 5px 0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background: var(--background-color);
            font-weight: 600;
            color: var(--secondary-color);
        }

        tr:hover {
            background: var(--background-color);
        }

        ul, ol {
            margin: 15px 0;
            padding-left: 25px;
        }

        li {
            margin: 8px 0;
        }

        code {
            background: var(--background-color);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
            font-size: 0.9em;
        }

        pre {
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 15px 0;
        }

        pre code {
            background: none;
            padding: 0;
        }

        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            color: var(--secondary-color);
            font-size: 0.9em;
        }

        .metric-card {
            display: inline-block;
            background: var(--background-color);
            padding: 15px 25px;
            border-radius: 8px;
            margin: 10px 10px 10px 0;
            text-align: center;
        }

        .metric-value {
            font-size: 2em;
            font-weight: 700;
            color: var(--primary-color);
        }

        .metric-label {
            font-size: 0.9em;
            color: var(--secondary-color);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }

        .status-critical { background: #fee2e2; color: #dc2626; }
        .status-high { background: #ffedd5; color: #ea580c; }
        .status-medium { background: #fef3c7; color: #d97706; }
        .status-low { background: #dcfce7; color: #16a34a; }

        @media print {
            body {
                background: white;
            }
            .report-container {
                box-shadow: none;
                max-width: none;
            }
        }

        @media (max-width: 768px) {
            .report-container {
                padding: 20px;
            }
            table {
                font-size: 0.9em;
            }
        }
""",
            description="Default CSS styles for HTML reports",
            variables=["primary_color", "secondary_color"],
        )

        # Section template
        self._templates["section_html"] = ReportTemplate(
            name="section_html",
            template_type=TemplateType.SECTION,
            format="html",
            content="""<section>
    <h2>${title}</h2>
    ${content}
</section>""",
            description="HTML section template",
            variables=["title", "content"],
        )

        # Table template
        self._templates["table_html"] = ReportTemplate(
            name="table_html",
            template_type=TemplateType.TABLE,
            format="html",
            content="""<table>
    <thead>
        <tr>${header_cells}</tr>
    </thead>
    <tbody>
        ${body_rows}
    </tbody>
</table>""",
            description="HTML table template",
            variables=["header_cells", "body_rows"],
        )

        # Metric card template
        self._templates["metric_card_html"] = ReportTemplate(
            name="metric_card_html",
            template_type=TemplateType.SUMMARY,
            format="html",
            content="""<div class="metric-card">
    <div class="metric-value">${value}</div>
    <div class="metric-label">${label}</div>
</div>""",
            description="Metric display card",
            variables=["value", "label"],
        )

    def _register_text_templates(self) -> None:
        """Register built-in plain text templates."""
        # Header template
        self._templates["header_text"] = ReportTemplate(
            name="header_text",
            template_type=TemplateType.HEADER,
            format="text",
            content="""${'=' * 60}
${title}
${'=' * 60}
Organization: ${organization}
Generated:    ${generated_at}
${period_line}
""",
            description="Plain text report header",
            variables=["title", "organization", "generated_at", "period_line"],
        )

        # Footer template
        self._templates["footer_text"] = ReportTemplate(
            name="footer_text",
            template_type=TemplateType.FOOTER,
            format="text",
            content="""${'-' * 40}
Report ID: ${report_id}
${footer_text}
""",
            description="Plain text report footer",
            variables=["report_id", "footer_text"],
        )

        # Section template
        self._templates["section_text"] = ReportTemplate(
            name="section_text",
            template_type=TemplateType.SECTION,
            format="text",
            content="""
${title}
${'-' * len(title)}
${content}
""",
            description="Plain text section",
            variables=["title", "content"],
        )

    def get_template(
        self,
        template_type: TemplateType,
        format: str = "markdown",
        name: str | None = None,
    ) -> ReportTemplate | None:
        """
        Get a template by type and format.

        Args:
            template_type: Type of template to retrieve.
            format: Output format (markdown, html, text).
            name: Specific template name (optional).

        Returns:
            The template if found, None otherwise.
        """
        if name:
            return self._templates.get(name)

        # Try to find a matching template
        key = f"{template_type.value}_{format}"
        return self._templates.get(key)

    def register_template(
        self,
        name: str,
        template_type: TemplateType,
        format: str,
        content: str,
        description: str = "",
        variables: list[str] | None = None,
    ) -> None:
        """
        Register a custom template.

        Args:
            name: Template name/identifier.
            template_type: Type of template.
            format: Output format.
            content: Template content with ${variable} placeholders.
            description: Human-readable description.
            variables: List of expected variables.
        """
        template = ReportTemplate(
            name=name,
            template_type=template_type,
            format=format,
            content=content,
            description=description,
            variables=variables or [],
        )
        self._templates[name] = template
        logger.debug(f"Registered template: {name}")

    def list_templates(
        self,
        template_type: TemplateType | None = None,
        format: str | None = None,
    ) -> list[ReportTemplate]:
        """
        List available templates.

        Args:
            template_type: Filter by template type.
            format: Filter by format.

        Returns:
            List of matching templates.
        """
        templates = list(self._templates.values())

        if template_type:
            templates = [t for t in templates if t.template_type == template_type]

        if format:
            templates = [t for t in templates if t.format == format]

        return templates

    def remove_template(self, name: str) -> bool:
        """
        Remove a template.

        Args:
            name: Template name to remove.

        Returns:
            True if removed, False if not found.
        """
        if name in self._templates:
            del self._templates[name]
            return True
        return False


# Module-level convenience functions
_default_manager: TemplateManager | None = None


def get_template_manager() -> TemplateManager:
    """Get the default template manager instance."""
    global _default_manager
    if _default_manager is None:
        _default_manager = TemplateManager()
    return _default_manager


def get_template(
    template_type: TemplateType,
    format: str = "markdown",
    name: str | None = None,
) -> ReportTemplate | None:
    """Get a template from the default manager."""
    return get_template_manager().get_template(template_type, format, name)


def list_templates(
    template_type: TemplateType | None = None,
    format: str | None = None,
) -> list[ReportTemplate]:
    """List templates from the default manager."""
    return get_template_manager().list_templates(template_type, format)
