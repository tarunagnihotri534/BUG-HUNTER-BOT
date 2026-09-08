import pytest
from src.scanners.dns_scanner import DNSScanner
from src.database.models import Severity


@pytest.mark.asyncio
async def test_dns_scanner_is_available():
    scanner = DNSScanner()
    assert scanner.is_available() is True
    assert scanner.name == "DNS & Email Security"


@pytest.mark.asyncio
async def test_dns_scanner_live_google():
    scanner = DNSScanner()
    findings = await scanner.scan("google.com")
    assert isinstance(findings, list)
    assert len(findings) > 0

    # google.com should have MX and SPF records
    for f in findings:
        assert f.title
        assert isinstance(f.severity, Severity)
        assert f.tool == "DNS & Email Security"
        assert f.why_it_matters


@pytest.mark.asyncio
async def test_dns_scanner_nonexistent_domain():
    scanner = DNSScanner()
    findings = await scanner.scan("nonexistent-domain-xyz-neverexists-999.com")
    assert isinstance(findings, list)
    # Should flag missing SPF and DMARC without crashing
    titles = [f.title for f in findings]
    assert "Missing SPF Record" in titles or "Missing DMARC Record" in titles
