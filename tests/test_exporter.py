from pathlib import Path
from src.core.exporter import ExecutiveReportExporter
from src.database.models import ScanRecord, ScanStatus, Finding, Severity


def test_executive_report_generation(tmp_path):
    record = ScanRecord(
        id=1,
        scan_id="scan_test_123",
        target_domain="example.com",
        user_id=123456,
        status=ScanStatus.COMPLETED,
        started_at="2026-09-08T12:00:00Z",
        completed_at="2026-09-08T12:01:00Z",
        summary={},
        findings=[
            Finding(
                title="Missing HSTS",
                severity=Severity.HIGH,
                tool="HTTP Headers & Web Posture",
                description="Strict-Transport-Security missing",
                why_it_matters="Enforces TLS connection",
                reference_url="https://owasp.org"
            )
        ]
    )

    report_path = ExecutiveReportExporter.generate_markdown_report(record, tmp_path)
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")

    assert "# 🛡️ Technical Security Audit Report" in content
    assert "example.com" in content
    assert "scan_test_123" in content
    assert "Missing HSTS" in content
    assert "Security Health Score" in content
