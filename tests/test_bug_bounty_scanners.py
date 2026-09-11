import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from src.scanners.js_scanner import JSBundleScanner, shannon_entropy, SECRET_PATTERNS
from src.scanners.subdomain_scanner import SubdomainScanner, HIGH_VALUE_PREFIXES
from src.scanners.archive_scanner import ArchiveScanner
from src.scanners.param_fuzzer import ParamFuzzerScanner
from src.scanners.ratelimit_scanner import RateLimitScanner
from src.scanners.bucket_scanner import BucketExposureScanner
from src.scanners.api_exposure_scanner import APIExposureScanner, extract_all_keys
from src.scanners.headers_scanner import HeadersScanner
from src.core.exporter import ExecutiveReportExporter
from src.database.models import Finding, Severity, ScanRecord


def test_shannon_entropy():
    # Uniform text has lower entropy, high-random string has high entropy
    low = shannon_entropy("aaaaaaaaaa")
    assert low == 0.0
    high = shannon_entropy("a8b7C!9z@K3pL0#x")
    assert high > 3.0


def test_js_secret_regex_patterns():
    # Test AWS Key regex
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    aws_rule = next(p for p in SECRET_PATTERNS if "AWS Access Key" in p[0])
    import re
    assert re.search(aws_rule[1], f"const key = '{aws_key}';") is not None

    # Test Google API Key regex (AIza + 35 alphanumeric/dash/underscore chars)
    gkey = "AIza" + "A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7r"
    gkey_rule = next(p for p in SECRET_PATTERNS if "Google API Key" in p[0])
    assert re.search(gkey_rule[1], f"apiKey: '{gkey}'") is not None


@pytest.mark.asyncio
async def test_subdomain_scanner_wildcard_detection():
    scanner = SubdomainScanner()
    assert scanner.is_available() is True
    # Test classify staging
    assert any(kw in "staging-api.example.com" for kw in HIGH_VALUE_PREFIXES)


@pytest.mark.asyncio
async def test_archive_scanner_is_available():
    scanner = ArchiveScanner()
    assert scanner.is_available() is True


@pytest.mark.asyncio
async def test_param_fuzzer_safety_gate():
    scanner = ParamFuzzerScanner()
    assert scanner.is_available() is True
    # Without authorized_consent=True, MUST return empty findings
    findings = await scanner.scan("example.com", authorized_consent=False)
    assert findings == []


@pytest.mark.asyncio
async def test_ratelimit_scanner_safety_gate():
    scanner = RateLimitScanner()
    assert scanner.is_available() is True
    # Without authorized_consent=True, MUST return empty findings
    findings = await scanner.scan("example.com", authorized_consent=False)
    assert findings == []


def test_api_exposure_extract_all_keys():
    payload = {
        "user": {
            "name": "Alice",
            "account": {
                "password_hash": "$2a$12$e8w",
                "internal_id": 1042
            }
        },
        "tags": ["admin"]
    }
    keys = extract_all_keys(payload)
    assert "user" in keys
    assert "password_hash" in keys
    assert "internal_id" in keys


@pytest.mark.asyncio
async def test_bucket_exposure_scanner():
    scanner = BucketExposureScanner()
    assert scanner.is_available() is True


@pytest.mark.asyncio
async def test_deep_cors_probe_headers_scanner():
    scanner = HeadersScanner()
    # Mock httpx response with insecure CORS reflection
    fake_cors_headers = {
        "access-control-allow-origin": "https://evil-attacker.com",
        "access-control-allow-credentials": "true"
    }
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = httpx.Headers(fake_cors_headers)
    mock_resp.url = "https://example.com"
    mock_resp.text = "OK"
    mock_resp.cookies.jar = []

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        findings = await scanner.scan("example.com")
        cors_findings = [f for f in findings if "CORS" in f.title]
        assert len(cors_findings) >= 1
        assert cors_findings[0].severity == Severity.CRITICAL


def test_bug_bounty_draft_generation(tmp_path: Path):
    finding = Finding(
        title="Hardcoded AWS Secret Key in Frontend JS Bundle",
        severity=Severity.CRITICAL,
        tool="JS Bundles & Source Maps",
        description="Found exposed AWS credentials directly inside app.min.js.",
        why_it_matters="Allows full read/write compromise of cloud infrastructure.",
        remediation="Rotate AWS credentials immediately and inject keys via backend env vars.",
        endpoint="https://example.com/assets/app.min.js",
        steps_to_reproduce="1. Navigate to target URL\n2. Inspect bundle\n3. Observe secret"
    )

    draft_file = ExecutiveReportExporter.generate_bug_bounty_draft(
        finding=finding,
        target_domain="example.com",
        output_dir=tmp_path
    )

    assert draft_file.exists()
    content = draft_file.read_text(encoding="utf-8")
    assert "# [Vulnerability Report] Hardcoded AWS Secret Key in Frontend JS Bundle" in content
    assert "- **Target Domain / Asset**: `example.com`" in content
    assert "## 3. Steps to Reproduce" in content
    assert "## 5. Suggested Remediation" in content
