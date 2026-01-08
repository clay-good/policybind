"""
PolicyBind reporting system.

This package provides comprehensive reporting functionality for PolicyBind,
including policy compliance reports, usage reports, incident summaries,
audit trail reports, risk assessments, and registry status reports.

Modules:
    generator: Main ReportGenerator class for creating reports.
    templates: Report templates for different formats.
    scheduled: Scheduled report generation and delivery.
    compliance_frameworks: Compliance framework mappings (EU AI Act, NIST, SOC 2).
    evidence: Evidence collection and export for compliance audits.
    chain_of_custody: Cryptographic integrity and tamper-evident packaging.
"""

from policybind.reports.chain_of_custody import (
    CustodyChain,
    CustodyEvent,
    HashAlgorithm,
    IntegrityManager,
    IntegrityManifest,
    SignatureType,
    create_evidence_hash,
    verify_evidence_hash,
)
from policybind.reports.evidence import (
    CollectionScope,
    EvidenceCollector,
    EvidenceFormat,
    EvidenceItem,
    EvidencePackage,
    EvidenceType,
)
from policybind.reports.generator import (
    ReportFormat,
    ReportGenerator,
    ReportType,
)

__all__ = [
    # Generator
    "ReportFormat",
    "ReportGenerator",
    "ReportType",
    # Evidence
    "CollectionScope",
    "EvidenceCollector",
    "EvidenceFormat",
    "EvidenceItem",
    "EvidencePackage",
    "EvidenceType",
    # Chain of Custody
    "CustodyChain",
    "CustodyEvent",
    "HashAlgorithm",
    "IntegrityManager",
    "IntegrityManifest",
    "SignatureType",
    "create_evidence_hash",
    "verify_evidence_hash",
]
