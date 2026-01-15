#!/usr/bin/env python3
"""
PolicyBind Example: Compliance Reporting

This script demonstrates the compliance reporting system in PolicyBind,
including:

1. Generating various report types (compliance, usage, incidents, audit)
2. Outputting reports in different formats (Markdown, HTML, JSON, Text)
3. Compliance framework mapping (EU AI Act, NIST AI RMF, SOC 2)
4. Identifying compliance gaps and coverage
5. Custom branding for reports
6. Automated compliance matrix generation

The reporting system helps organizations demonstrate AI governance
compliance to auditors and stakeholders.

Prerequisites:
    - PolicyBind installed: pip install policybind

Usage:
    python 06_compliance_report.py
"""

import sys
from datetime import datetime, timedelta

from policybind.reports.generator import (
    ReportGenerator,
    ReportFormat,
    ReportType,
    BrandingConfig,
)
from policybind.reports.compliance_frameworks import (
    ComplianceMapper,
    ComplianceFramework,
    CoverageLevel,
)


def main() -> int:
    """
    Main function demonstrating compliance reporting.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: Compliance Reporting")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 1: Initialize Report Generator
    # -------------------------------------------------------------------------
    print("Step 1: Initializing Report Generator...")
    print("-" * 60)

    # Create branding configuration
    branding = BrandingConfig(
        organization_name="Acme Corporation",
        primary_color="#1e40af",  # Deep blue
        secondary_color="#475569",  # Slate
        footer_text="Confidential - AI Governance Report",
    )

    # Initialize report generator
    # In production, you would pass actual repositories
    generator = ReportGenerator(
        branding=branding,
    )

    print(f"  Organization: {branding.organization_name}")
    print(f"  Primary Color: {branding.primary_color}")
    print("  Report generator initialized")
    print()

    # -------------------------------------------------------------------------
    # Step 2: Generate Policy Compliance Report
    # -------------------------------------------------------------------------
    print("Step 2: Generating Policy Compliance Report...")
    print("-" * 60)

    # Generate report for last 30 days
    since = datetime.now() - timedelta(days=30)
    until = datetime.now()

    print(f"\n  Period: {since.strftime('%Y-%m-%d')} to {until.strftime('%Y-%m-%d')}")

    # Generate in different formats
    formats = [
        (ReportFormat.MARKDOWN, "markdown"),
        (ReportFormat.TEXT, "text"),
        (ReportFormat.JSON, "json"),
    ]

    for fmt, name in formats:
        try:
            report = generator.generate(
                report_type=ReportType.POLICY_COMPLIANCE,
                format=fmt,
                since=since,
                until=until,
                generated_by="compliance-example",
            )
            print(f"\n  {name.upper()} format ({len(report)} characters):")
            # Show first few lines
            preview_lines = report.split('\n')[:5]
            for line in preview_lines:
                print(f"    {line[:70]}...")
        except Exception as e:
            print(f"  Error generating {name}: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 3: Generate Different Report Types
    # -------------------------------------------------------------------------
    print("Step 3: Generating Different Report Types...")
    print("-" * 60)

    report_types = [
        (ReportType.INCIDENT_SUMMARY, "Incident Summary"),
        (ReportType.USAGE_COST, "Usage and Cost"),
        (ReportType.RISK_ASSESSMENT, "Risk Assessment"),
        (ReportType.REGISTRY_STATUS, "Registry Status"),
        (ReportType.AUDIT_TRAIL, "Audit Trail"),
    ]

    for report_type, name in report_types:
        print(f"\n  Generating: {name} Report")
        try:
            report = generator.generate(
                report_type=report_type,
                format=ReportFormat.TEXT,
                since=since,
                until=until,
            )
            # Show summary
            lines = [l for l in report.split('\n') if l.strip()]
            print(f"    Type: {report_type.value}")
            print(f"    Length: {len(report)} characters")
            if len(lines) >= 2:
                print(f"    Preview: {lines[2][:50]}...")
        except Exception as e:
            print(f"    Error: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 4: Initialize Compliance Mapper
    # -------------------------------------------------------------------------
    print("Step 4: Initializing Compliance Framework Mapper...")
    print("-" * 60)

    mapper = ComplianceMapper()

    # List available frameworks
    print("\n  Available compliance frameworks:")
    for framework in mapper.list_frameworks():
        mapping = mapper.get_mapping(framework)
        if mapping:
            score = mapping.get_coverage_score()
            print(f"    - {framework.value}: {len(mapping.requirements)} requirements, {score:.1f}% coverage")

    print()

    # -------------------------------------------------------------------------
    # Step 5: Explore EU AI Act Compliance
    # -------------------------------------------------------------------------
    print("Step 5: EU AI Act Compliance Mapping...")
    print("-" * 60)

    eu_mapping = mapper.get_mapping(ComplianceFramework.EU_AI_ACT)

    if eu_mapping:
        print(f"\n  Framework: {eu_mapping.framework.value}")
        print(f"  Version: {eu_mapping.version}")
        print(f"  Total Requirements: {len(eu_mapping.requirements)}")

        # Coverage summary
        summary = eu_mapping.get_coverage_summary()
        print("\n  Coverage Summary:")
        for level, count in summary.items():
            print(f"    - {level.upper()}: {count}")

        print(f"\n  Overall Coverage Score: {eu_mapping.get_coverage_score():.1f}%")

        # Show sample requirements
        print("\n  Sample Requirements:")
        for req in eu_mapping.requirements[:5]:
            print(f"\n    [{req.id}] {req.name}")
            print(f"    Category: {req.category}")
            print(f"    Coverage: {req.coverage.value}")
            if req.policybind_features:
                features = ", ".join(req.policybind_features[:3])
                print(f"    Features: {features}")

    print()

    # -------------------------------------------------------------------------
    # Step 6: Explore NIST AI RMF Compliance
    # -------------------------------------------------------------------------
    print("Step 6: NIST AI RMF Compliance Mapping...")
    print("-" * 60)

    nist_mapping = mapper.get_mapping(ComplianceFramework.NIST_AI_RMF)

    if nist_mapping:
        print(f"\n  Framework: {nist_mapping.framework.value}")
        print(f"  Version: {nist_mapping.version}")
        print(f"  Coverage Score: {nist_mapping.get_coverage_score():.1f}%")

        # Group by category (GOVERN, MAP, MEASURE, MANAGE)
        categories = {}
        for req in nist_mapping.requirements:
            if req.category not in categories:
                categories[req.category] = []
            categories[req.category].append(req)

        print("\n  Requirements by Function:")
        for category, reqs in sorted(categories.items()):
            full_count = sum(1 for r in reqs if r.coverage == CoverageLevel.FULL)
            partial_count = sum(1 for r in reqs if r.coverage == CoverageLevel.PARTIAL)
            print(f"    {category}: {len(reqs)} requirements ({full_count} full, {partial_count} partial)")

    print()

    # -------------------------------------------------------------------------
    # Step 7: Explore SOC 2 Compliance
    # -------------------------------------------------------------------------
    print("Step 7: SOC 2 Compliance Mapping...")
    print("-" * 60)

    soc2_mapping = mapper.get_mapping(ComplianceFramework.SOC2)

    if soc2_mapping:
        print(f"\n  Framework: {soc2_mapping.framework.value}")
        print(f"  Version: {soc2_mapping.version}")
        print(f"  Coverage Score: {soc2_mapping.get_coverage_score():.1f}%")

        # Trust Service Categories
        categories = {}
        for req in soc2_mapping.requirements:
            if req.category not in categories:
                categories[req.category] = []
            categories[req.category].append(req)

        print("\n  Trust Service Criteria:")
        for category, reqs in sorted(categories.items()):
            full_coverage = sum(1 for r in reqs if r.coverage == CoverageLevel.FULL)
            print(f"    {category}: {len(reqs)} criteria ({full_coverage}/{len(reqs)} fully covered)")

    print()

    # -------------------------------------------------------------------------
    # Step 8: Generate Compliance Matrix
    # -------------------------------------------------------------------------
    print("Step 8: Generating Compliance Matrix...")
    print("-" * 60)

    # Generate matrix for all frameworks
    matrix = mapper.generate_compliance_matrix()

    print(f"\n  Generated at: {matrix['generated_at']}")
    print("\n  Framework Summary:")
    print("  " + "-" * 50)
    print(f"  {'Framework':<20} {'Score':>10} {'Full':>6} {'Partial':>8} {'None':>6}")
    print("  " + "-" * 50)

    for framework, summary in matrix["summary"].items():
        print(
            f"  {framework:<20} {summary['score']:>9.1f}% "
            f"{summary['full']:>6} {summary['partial']:>8} {summary['none']:>6}"
        )
    print("  " + "-" * 50)

    print()

    # -------------------------------------------------------------------------
    # Step 9: Identify Compliance Gaps
    # -------------------------------------------------------------------------
    print("Step 9: Identifying Compliance Gaps...")
    print("-" * 60)

    gaps = mapper.get_gaps()

    print(f"\n  Total gaps (none or minimal coverage): {len(gaps)}")

    if gaps:
        print("\n  Gaps by framework:")
        gap_by_framework = {}
        for gap in gaps:
            fw = gap["framework"]
            if fw not in gap_by_framework:
                gap_by_framework[fw] = []
            gap_by_framework[fw].append(gap["requirement"])

        for framework, reqs in gap_by_framework.items():
            print(f"\n  {framework.upper()}:")
            for req in reqs[:3]:  # Show first 3 per framework
                coverage = req["coverage"]
                print(f"    - [{req['id']}] {req['name']} ({coverage})")
                if req["notes"]:
                    print(f"      Note: {req['notes'][:60]}...")

    print()

    # -------------------------------------------------------------------------
    # Step 10: Find Requirements by Feature
    # -------------------------------------------------------------------------
    print("Step 10: Finding Requirements by Feature...")
    print("-" * 60)

    # Find all requirements that mention "Token" or "Audit"
    features_to_search = ["Token", "Audit", "Policy"]

    for feature in features_to_search:
        print(f"\n  Feature: '{feature}'")
        requirements = mapper.get_requirements_by_feature(feature)
        print(f"    Found in {len(requirements)} requirements:")
        for req_info in requirements[:3]:
            framework = req_info["framework"]
            req = req_info["requirement"]
            print(f"      - [{framework}] {req['name']}")

    print()

    # -------------------------------------------------------------------------
    # Step 11: Generate Formatted Compliance Report
    # -------------------------------------------------------------------------
    print("Step 11: Generating Formatted Compliance Report...")
    print("-" * 60)

    # Generate Markdown compliance report
    print("\n  Generating Markdown compliance report...")
    md_report = mapper.generate_compliance_report(
        frameworks=[ComplianceFramework.EU_AI_ACT, ComplianceFramework.NIST_AI_RMF],
        format="markdown",
    )
    print(f"    Length: {len(md_report)} characters")

    # Show excerpt
    print("\n  Report Excerpt:")
    lines = md_report.split('\n')[:15]
    for line in lines:
        print(f"    {line[:65]}")

    # Generate JSON compliance report
    print("\n  Generating JSON compliance report...")
    json_report = mapper.generate_compliance_report(
        frameworks=[ComplianceFramework.SOC2],
        format="json",
    )
    print(f"    Length: {len(json_report)} characters")

    # Generate text compliance report
    print("\n  Generating text compliance report...")
    text_report = mapper.generate_compliance_report(format="text")
    print(f"    Length: {len(text_report)} characters")
    print("\n  Text Report Preview:")
    for line in text_report.split('\n')[:10]:
        print(f"    {line}")

    print()

    # -------------------------------------------------------------------------
    # Step 12: HTML Report with Branding
    # -------------------------------------------------------------------------
    print("Step 12: Generating HTML Report with Branding...")
    print("-" * 60)

    # Generate HTML policy compliance report
    print("\n  Generating branded HTML report...")
    try:
        html_report = generator.generate(
            report_type=ReportType.POLICY_COMPLIANCE,
            format=ReportFormat.HTML,
            since=since,
            until=until,
            generated_by="compliance-demo",
        )
        print(f"    Length: {len(html_report)} characters")
        print(f"    Contains organization name: {'Acme Corporation' in html_report}")
        print(f"    Contains primary color: {branding.primary_color in html_report}")

        # Show structure
        if "<!DOCTYPE html>" in html_report:
            print("    Format: Valid HTML5 document")
        if "<style>" in html_report:
            print("    Styling: Embedded CSS included")
        if "<table>" in html_report:
            print("    Tables: HTML tables present")

    except Exception as e:
        print(f"    Error: {e}")

    print()

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. Generate reports in multiple formats (Markdown, HTML, JSON, Text)")
    print("  2. Multiple report types for different stakeholders")
    print("  3. Built-in compliance framework mappings (EU AI Act, NIST, SOC 2)")
    print("  4. Identify compliance gaps and coverage levels")
    print("  5. Custom branding for professional reports")
    print("  6. Feature-to-requirement tracing for auditors")
    print()
    print("Report Types Available:")
    for rt in ReportType:
        print(f"  - {rt.value}: {rt.name.replace('_', ' ').title()}")
    print()
    print("Next Steps:")
    print("  - Save reports to files for distribution")
    print("  - Schedule automated report generation")
    print("  - Integrate with CI/CD for continuous compliance")
    print("  - Customize framework mappings for your organization")

    return 0


if __name__ == "__main__":
    sys.exit(main())
