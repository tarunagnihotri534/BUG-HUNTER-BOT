import pytest
from src.scanners.headers_scanner import HeadersScanner
from src.database.models import Severity


@pytest.mark.asyncio
async def test_headers_scanner_is_available():
    scanner = HeadersScanner()
    assert scanner.is_available() is True
    assert scanner.name == "HTTP Headers & Web Posture"


@pytest.mark.asyncio
async def test_headers_scanner_live_domain():
    scanner = HeadersScanner()
    findings = await scanner.scan("google.com")
    assert isinstance(findings, list)
    for f in findings:
        assert f.title
        assert isinstance(f.severity, Severity)
        assert f.tool == "HTTP Headers & Web Posture"
        assert f.why_it_matters


@pytest.mark.asyncio
async def test_headers_scanner_unreachable_domain():
    scanner = HeadersScanner()
    findings = await scanner.scan("nonexistent-test-domain-invalid-99999.xyz")
    assert len(findings) >= 1
    assert any("Unreachable" in f.title or "Failed" in f.title for f in findings)
