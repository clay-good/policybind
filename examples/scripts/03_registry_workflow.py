#!/usr/bin/env python3
"""
PolicyBind Example: Model Registry Workflow

This script demonstrates the model registry lifecycle in PolicyBind, including:

1. Registering new AI model deployments
2. Running risk assessments
3. Managing approval workflows
4. Tracking compliance status
5. Handling suspension and reinstatement
6. Querying and filtering deployments

The model registry is a core component of AI governance, providing visibility
into what AI models are deployed, who owns them, and their risk profiles.

Prerequisites:
    - PolicyBind installed: pip install policybind

Usage:
    python 03_registry_workflow.py
"""

import sys
from datetime import datetime

from policybind.registry.manager import RegistryManager, DeploymentEventType
from policybind.registry.risk import RiskAssessor
from policybind.registry.compliance import ComplianceChecker, ComplianceFramework
from policybind.models.registry import RiskLevel, ApprovalStatus
from policybind.exceptions import RegistryError, ValidationError


def print_deployment(deployment, prefix="  "):
    """Helper to print deployment details."""
    print(f"{prefix}ID: {deployment.deployment_id[:8]}...")
    print(f"{prefix}Name: {deployment.name}")
    print(f"{prefix}Model: {deployment.model_provider}/{deployment.model_name}")
    print(f"{prefix}Owner: {deployment.owner}")
    print(f"{prefix}Risk Level: {deployment.risk_level.value}")
    print(f"{prefix}Status: {deployment.approval_status.value}")
    if deployment.data_categories:
        print(f"{prefix}Data Categories: {', '.join(deployment.data_categories)}")


def main() -> int:
    """
    Main function demonstrating registry workflow.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    print("=" * 60)
    print("PolicyBind Example: Model Registry Workflow")
    print("=" * 60)
    print()

    # -------------------------------------------------------------------------
    # Step 1: Initialize the Registry Manager
    # -------------------------------------------------------------------------
    print("Step 1: Initializing Registry Manager...")
    print("-" * 60)

    # Create manager (in-memory for this example)
    # In production, you would pass a RegistryRepository backed by a database
    manager = RegistryManager()

    # Set up an event listener to track what happens
    events_received = []

    def event_listener(event):
        events_received.append(event)
        print(f"  [EVENT] {event.event_type.value}: {event.deployment_id[:8]}...")

    manager.on_deployment_event(event_listener)

    print("  Registry manager initialized")
    print("  Event listener registered")
    print()

    # -------------------------------------------------------------------------
    # Step 2: Register New Deployments
    # -------------------------------------------------------------------------
    print("Step 2: Registering AI Model Deployments...")
    print("-" * 60)

    # Deployment 1: Low-risk GPT-3.5 for internal use
    print("\nRegistering: Customer Support Chatbot (Low Risk)")
    try:
        deployment1 = manager.register(
            name="Customer Support Chatbot",
            model_provider="openai",
            model_name="gpt-3.5-turbo",
            owner="support-team",
            owner_contact="support@company.com",
            description="AI chatbot for handling customer inquiries",
            data_categories=["public"],
            metadata={
                "use_case": "customer-support",
                "environment": "production",
                "cost_center": "CC-SUP-001",
            },
        )
        print_deployment(deployment1)
    except ValidationError as e:
        print(f"  ERROR: Validation failed - {e}")
        return 1

    # Deployment 2: Medium-risk GPT-4 for internal analysis
    print("\nRegistering: Financial Analysis Tool (Medium Risk)")
    try:
        deployment2 = manager.register(
            name="Financial Analysis Tool",
            model_provider="openai",
            model_name="gpt-4",
            owner="finance-team",
            owner_contact="finance@company.com",
            description="AI tool for financial document analysis",
            data_categories=["confidential", "internal"],
            metadata={
                "use_case": "financial-analysis",
                "environment": "production",
                "compliance": ["SOC2", "SOX"],
            },
        )
        print_deployment(deployment2)
    except ValidationError as e:
        print(f"  ERROR: Validation failed - {e}")
        return 1

    # Deployment 3: High-risk deployment with PII handling
    print("\nRegistering: HR Document Processor (High Risk)")
    try:
        deployment3 = manager.register(
            name="HR Document Processor",
            model_provider="openai",
            model_name="gpt-4-turbo",
            owner="hr-team",
            owner_contact="hr@company.com",
            description="AI processor for HR documents and employee records",
            data_categories=["pii", "confidential"],
            metadata={
                "use_case": "hr-automation",
                "environment": "production",
                "compliance": ["GDPR", "CCPA"],
                "data_retention_days": 30,
            },
        )
        print_deployment(deployment3)
    except ValidationError as e:
        print(f"  ERROR: Validation failed - {e}")
        return 1

    print()

    # -------------------------------------------------------------------------
    # Step 3: Run Risk Assessments
    # -------------------------------------------------------------------------
    print("Step 3: Running Risk Assessments...")
    print("-" * 60)

    risk_assessor = RiskAssessor()

    for deployment in [deployment1, deployment2, deployment3]:
        print(f"\nAssessing: {deployment.name}")
        assessment = risk_assessor.assess(deployment)
        print(f"  Computed Risk Level: {assessment.risk_level.value}")
        print(f"  Risk Score: {assessment.risk_score:.2f}/10.0")
        print(f"  Factors:")
        for factor in assessment.risk_factors[:3]:  # Show top 3 factors
            print(f"    - {factor}")
        if assessment.mitigations:
            print(f"  Suggested Mitigations:")
            for mitigation in assessment.mitigations[:2]:
                print(f"    - {mitigation}")

    print()

    # -------------------------------------------------------------------------
    # Step 4: Approval Workflow
    # -------------------------------------------------------------------------
    print("Step 4: Managing Approval Workflow...")
    print("-" * 60)

    # Low-risk deployments can be auto-approved
    print(f"\nApproving: {deployment1.name} (Low Risk - Auto-approval)")
    try:
        manager.approve(
            deployment_id=deployment1.deployment_id,
            approved_by="auto-approver@company.com",
            approval_notes="Auto-approved: Low risk, public data only",
        )
        print("  Status: APPROVED")
    except RegistryError as e:
        print(f"  ERROR: {e}")

    # Medium-risk needs manager approval
    print(f"\nApproving: {deployment2.name} (Medium Risk - Manager Approval)")
    try:
        manager.approve(
            deployment_id=deployment2.deployment_id,
            approved_by="cfo@company.com",
            approval_notes="Approved by CFO for financial analysis use case",
            approval_ticket="TICKET-12345",
        )
        print("  Status: APPROVED")
    except RegistryError as e:
        print(f"  ERROR: {e}")

    # High-risk needs additional review - let's simulate rejection first
    print(f"\nReviewing: {deployment3.name} (High Risk - Requires Review)")
    print("  Initial review identified missing DPA documentation...")

    # For demo, we'll approve after "addressing concerns"
    try:
        manager.approve(
            deployment_id=deployment3.deployment_id,
            approved_by="dpo@company.com",
            approval_notes="Approved after DPA signed with OpenAI",
            approval_ticket="TICKET-67890",
        )
        print("  Status: APPROVED (after documentation complete)")
    except RegistryError as e:
        print(f"  ERROR: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 5: Compliance Checking
    # -------------------------------------------------------------------------
    print("Step 5: Running Compliance Checks...")
    print("-" * 60)

    compliance_checker = ComplianceChecker()

    # Check GDPR compliance for HR deployment
    print(f"\nChecking GDPR compliance for: {deployment3.name}")
    try:
        # Get fresh deployment data
        deployment3_updated = manager.get(deployment3.deployment_id)
        report = compliance_checker.check(
            deployment3_updated,
            framework=ComplianceFramework.GDPR,
        )
        print(f"  Framework: {report.framework.value}")
        print(f"  Compliant: {report.is_compliant}")
        print(f"  Score: {report.compliance_score:.0%}")
        if report.gaps:
            print(f"  Gaps identified:")
            for gap in report.gaps[:3]:
                print(f"    - {gap}")
        if report.recommendations:
            print(f"  Recommendations:")
            for rec in report.recommendations[:3]:
                print(f"    - {rec}")
    except Exception as e:
        print(f"  Compliance check failed: {e}")

    # Check SOC2 compliance for finance deployment
    print(f"\nChecking SOC2 compliance for: {deployment2.name}")
    try:
        deployment2_updated = manager.get(deployment2.deployment_id)
        report = compliance_checker.check(
            deployment2_updated,
            framework=ComplianceFramework.SOC2,
        )
        print(f"  Framework: {report.framework.value}")
        print(f"  Compliant: {report.is_compliant}")
        print(f"  Score: {report.compliance_score:.0%}")
    except Exception as e:
        print(f"  Compliance check failed: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 6: Simulate Suspension (Policy Violation)
    # -------------------------------------------------------------------------
    print("Step 6: Handling Suspension Scenario...")
    print("-" * 60)

    print(f"\nSimulating policy violations for: {deployment3.name}")

    # Record some violations
    for i in range(3):
        manager.record_violation(
            deployment_id=deployment3.deployment_id,
            violation_type="data_leak_attempt",
            details={"attempt": i + 1, "blocked": True},
        )
        print(f"  Violation {i + 1} recorded")

    # Check if suspension threshold reached
    deployment3_updated = manager.get(deployment3.deployment_id)
    print(f"  Total violations: {deployment3_updated.metadata.get('violation_count', 0)}")

    # Suspend the deployment
    print(f"\nSuspending deployment due to violations...")
    try:
        manager.suspend(
            deployment_id=deployment3.deployment_id,
            suspended_by="security@company.com",
            reason="Multiple policy violations detected - pending investigation",
        )
        deployment3_suspended = manager.get(deployment3.deployment_id)
        print(f"  Status: {deployment3_suspended.approval_status.value}")
    except RegistryError as e:
        print(f"  ERROR: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 7: Reinstatement
    # -------------------------------------------------------------------------
    print("Step 7: Reinstating Suspended Deployment...")
    print("-" * 60)

    print(f"\nAfter investigation, reinstating: {deployment3.name}")
    try:
        manager.reinstate(
            deployment_id=deployment3.deployment_id,
            reinstated_by="ciso@company.com",
            reason="Investigation complete - false positives confirmed",
        )
        deployment3_reinstated = manager.get(deployment3.deployment_id)
        print(f"  Status: {deployment3_reinstated.approval_status.value}")
    except RegistryError as e:
        print(f"  ERROR: {e}")

    print()

    # -------------------------------------------------------------------------
    # Step 8: Query Deployments
    # -------------------------------------------------------------------------
    print("Step 8: Querying Registry...")
    print("-" * 60)

    # List all deployments
    print("\nAll registered deployments:")
    all_deployments = manager.list_deployments()
    for d in all_deployments:
        print(f"  - {d.name}: {d.approval_status.value}")

    # Filter by status
    print("\nApproved deployments only:")
    approved = manager.list_deployments(status=ApprovalStatus.APPROVED)
    for d in approved:
        print(f"  - {d.name} ({d.model_provider}/{d.model_name})")

    # Filter by risk level
    print("\nHigh-risk deployments:")
    high_risk = manager.list_deployments(risk_level=RiskLevel.HIGH)
    for d in high_risk:
        print(f"  - {d.name} (Owner: {d.owner})")

    # Get statistics
    print("\nRegistry Statistics:")
    stats = manager.get_statistics()
    print(f"  Total deployments: {stats.get('total', 0)}")
    print(f"  By status: {stats.get('by_status', {})}")
    print(f"  By risk level: {stats.get('by_risk_level', {})}")

    print()

    # -------------------------------------------------------------------------
    # Step 9: Event Summary
    # -------------------------------------------------------------------------
    print("Step 9: Event History Summary...")
    print("-" * 60)

    print(f"\nTotal events recorded: {len(events_received)}")
    event_counts = {}
    for event in events_received:
        event_type = event.event_type.value
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    print("Events by type:")
    for event_type, count in sorted(event_counts.items()):
        print(f"  - {event_type}: {count}")

    print()
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print()
    print("Key Takeaways:")
    print("  1. Register all AI deployments for visibility and control")
    print("  2. Run risk assessments to determine approval requirements")
    print("  3. Use compliance checks to ensure regulatory adherence")
    print("  4. Monitor for violations and suspend when necessary")
    print("  5. Query the registry for governance reporting")

    return 0


if __name__ == "__main__":
    sys.exit(main())
