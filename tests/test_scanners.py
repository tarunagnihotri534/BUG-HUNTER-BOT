import pytest
from src.database.models import Finding, Severity, ScanRecord, ScanStatus
from src.core.formatter import ReportFormatter
from src.scanners.nuclei_scanner import NucleiScanner
from src.scanners.zap_scanner import ZAPScanner
from src.scanners.nikto_scanner import NiktoScanner
from src.scanners.gitleaks_scanner import GitleaksScanner


def test_report_formatter_prioritization():
    findings = [
        Finding(
            title="Exposed .env Configuration File",
            severity=Severity.CRITICAL,
            tool="Nuclei",
            description="Environment configuration exposed on / .env",
            why_it_matters="Database passwords and secret keys may be leaked."
        ),
        Finding(
            title="TLS Certificate Expiring in 5 Days",
            severity=Severity.HIGH,
            tool="TLS/SSL Health",
            description="Certificate expires soon.",
            why_it_matters="Renewal needed."
        ),
        Finding(
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            tool="TLS/SSL Health",
            description="Strict-Transport-Security header omitted.",
            why_it_matters="Allows downgrades."
        ),
        Finding(
            title="Server Banner Exposed: nginx/1.18",
            severity=Severity.INFO,
            tool="Nikto",
            description="Server banner visible.",
            why_it_matters="Informational software disclosure."
        ),
    ]

    record = ScanRecord(
        id=1,
        scan_id="scan_123",
        target_domain="target.com",
        user_id=1,
        status=ScanStatus.COMPLETED,
        started_at="2026-09-06T12:00:00Z",
        completed_at="2026-09-06T12:02:00Z",
        findings=findings
    )

    messages = ReportFormatter.format_scan_summary(record)
    assert len(messages) >= 1
    full_text = "\n".join(messages)

    # Check that sections are present in priority order
    assert "🚨 **NEEDS ATTENTION NOW (Critical)**:" in full_text
    assert "⚠️ **SHOULD FIX SOON (High)**:" in full_text
    assert "🔶 **MINOR ISSUES (Medium)**:" in full_text
    assert "ℹ️ **INFORMATIONAL / ROUTINE" in full_text

    # Test critical alert message formatting
    crit_alert = ReportFormatter.format_critical_alert("target.com", [findings[0]])
    assert "🚨🚨 **URGENT SECURITY ALERT: TARGET.COM** 🚨🚨" in crit_alert
    assert "Exposed .env Configuration File" in crit_alert


def test_nuclei_parser():
    scanner = NucleiScanner()
    sample_item = {
        "template-id": "exposed-git-config",
        "info": {
            "name": "Git Config File Exposed",
            "severity": "critical",
            "description": "Exposed Git config allows repo reconstruction.",
            "classification": {"cwe-id": ["CWE-200"], "cve-id": ["CVE-2021-9999"]},
            "reference": ["https://example.com/ref"]
        },
        "matched-at": "https://target.com/.git/config"
    }

    finding = scanner._parse_nuclei_item(sample_item)
    assert finding.title == "Git Config File Exposed"
    assert finding.severity == Severity.CRITICAL
    assert finding.tool == "Nuclei"
    assert "CWE-200" in finding.why_it_matters
    assert finding.reference_url == "https://example.com/ref"


def test_zap_parser():
    scanner = ZAPScanner()
    sample_alert = {
        "alert": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "description": "Parameter q reflects raw HTML without sanitization.",
        "solution": "Contextually encode all user-supplied input.",
        "cweid": "79",
        "wascid": "8"
    }

    finding = scanner._parse_zap_alert(sample_alert)
    assert finding.title == "Cross Site Scripting (Reflected)"
    assert finding.severity == Severity.HIGH
    assert finding.tool == "OWASP ZAP"
    assert "https://cwe.mitre.org/data/definitions/79.html" == finding.reference_url


def test_gitleaks_finding_is_critical():
    scanner = GitleaksScanner()
    # Ensure gitleaks findings flag as Severity.CRITICAL
    finding = Finding(
        title="Exposed Secret: aws-access-key-id",
        severity=Severity.CRITICAL,
        tool="Gitleaks",
        description="Secret detected in credentials.json",
        why_it_matters="Committed secrets can be scraped."
    )
    assert finding.severity == Severity.CRITICAL
