import pytest
from src.scanners.tls_scanner import TLSScanner
from src.database.models import Severity


@pytest.mark.asyncio
async def test_tls_scanner_on_live_domain():
    scanner = TLSScanner()
    assert scanner.is_available() is True

    # Run check against google.com
    findings = await scanner.scan("google.com")
    assert len(findings) > 0

    # Ensure findings have required fields and valid severities
    for f in findings:
        assert f.title
        assert isinstance(f.severity, Severity)
        assert f.tool == "TLS/SSL Health"
        assert f.why_it_matters


@pytest.mark.asyncio
async def test_tls_scanner_connection_failure():
    scanner = TLSScanner()
    # Port 12345 should fail to connect gracefully without throwing an uncaught exception
    findings = await scanner.scan("127.0.0.1", port=12345)
    assert len(findings) >= 1
    assert any("TLS Connection Failed" in f.title for f in findings)
