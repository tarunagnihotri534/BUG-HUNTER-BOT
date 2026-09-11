import logging
import math
import re
from typing import List, Any, Set, Tuple
from urllib.parse import urljoin, urlparse
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

# Sensitive secret regex patterns (similar to Gitleaks rules)
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", Severity.CRITICAL),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", Severity.CRITICAL),
    ("GitHub Personal Access Token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}", Severity.CRITICAL),
    ("Generic High-Value Private Key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("Stripe Secret Key", r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,34}", Severity.CRITICAL),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,34}", Severity.CRITICAL),
    ("Slack Webhook URL", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", Severity.HIGH),
    ("Slack API Token", r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", Severity.CRITICAL),
    ("Bearer / Hardcoded JWT Token", r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*", Severity.HIGH),
    ("Firebase Database URL / Secret", r"(?i)firebaseio\.com.*auth=[a-zA-Z0-9_\-]+", Severity.CRITICAL),
    ("Generic Hardcoded Password in JS", r"(?i)(?:password|passwd|api_secret|auth_token)\s*[:=]\s*['\"][A-Za-z0-9!@#$%^&*()_+=-]{8,64}['\"]", Severity.HIGH),
]


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class JSBundleScanner(BaseScanner):
    """
    Crawls deployed frontend HTML, extracts linked JavaScript bundles,
    probes for exposed source maps (.js.map), and scans bundle contents
    for committed/leaked API secrets and high-entropy strings.
    """

    def __init__(self):
        super().__init__(name="JS Bundles & Source Maps")

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()
        base_url = f"https://{domain}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSentinel-SecurityAudit/2.0"
        }

        async with httpx.AsyncClient(headers=headers, timeout=10.0, verify=False, follow_redirects=True) as client:
            try:
                res = await client.get(base_url)
                html = res.text
            except Exception as e:
                logger.debug(f"Could not load root page for JS crawl on {domain}: {e}")
                return []

            # 1. Discover linked JavaScript bundles
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            # Filter internal or relative JS bundles
            js_urls: Set[str] = set()
            for src in script_srcs:
                full_url = urljoin(base_url, src)
                parsed = urlparse(full_url)
                if parsed.netloc == domain or not parsed.netloc or domain in parsed.netloc:
                    if full_url.endswith(".js") or ".js?" in full_url:
                        js_urls.add(full_url)

            # Limit to first 10 bundles to maintain reasonable scan speeds
            sampled_urls = list(js_urls)[:10]

            for js_url in sampled_urls:
                # 2. Check for exposed source maps (.map)
                map_url = js_url.split("?")[0] + ".map"
                try:
                    map_res = await client.get(map_url, timeout=5.0)
                    if map_res.status_code == 200 and ("sources" in map_res.text[:500] or "mappings" in map_res.text[:500]):
                        findings.append(Finding(
                            title="Publicly Accessible JavaScript Source Map (.map)",
                            severity=Severity.CRITICAL,
                            tool=self.name,
                            description=f"Source map file is publicly downloadable at `{map_url}`.",
                            why_it_matters=(
                                "Exposes original, unminified application source code, internal folder structures, "
                                "developer comments, and unredacted endpoints."
                            ),
                            reference_url="https://cwe.mitre.org/data/definitions/540.html",
                            endpoint=map_url,
                            steps_to_reproduce=(
                                f"1. Send an HTTP GET request to `{map_url}`.\n"
                                f"2. Verify HTTP 200 with valid JSON containing original uncompiled source code."
                            ),
                            remediation="Ensure production build pipelines remove .map files or configure web server / CDN to forbid access to *.map files."
                        ))
                except Exception:
                    pass

                # 3. Analyze JS Bundle contents for leaked secrets
                try:
                    js_res = await client.get(js_url, timeout=8.0)
                    if js_res.status_code == 200:
                        content = js_res.text
                        # Pattern matching
                        for rule_name, pattern, sev in SECRET_PATTERNS:
                            matches = re.findall(pattern, content)
                            if matches:
                                matched_val = str(matches[0])[:15] + "..."
                                # Check entropy to filter trivial/placeholder matches
                                if shannon_entropy(str(matches[0])) >= 3.2:
                                    findings.append(Finding(
                                        title=f"Hardcoded Secret in Deployed JS Bundle: {rule_name}",
                                        severity=sev,
                                        tool=self.name,
                                        description=(
                                            f"Detected apparent credential matching `{rule_name}` in `{js_url}` "
                                            f"(token preview: `{matched_val}`)."
                                        ),
                                        why_it_matters=(
                                            "Bundled secrets are publicly visible to any client loading the page, "
                                            "allowing unauthorized API usage or privilege escalation."
                                        ),
                                        reference_url="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                                        endpoint=js_url,
                                        steps_to_reproduce=(
                                            f"1. Download JavaScript bundle `{js_url}`.\n"
                                            f"2. Search for token pattern `{rule_name}`.\n"
                                            f"3. Verify presence of hardcoded credentials."
                                        ),
                                        remediation="Extract credentials from frontend assets into secure backend environment variables. Rotate the exposed token immediately."
                                    ))
                except Exception as fetch_err:
                    logger.debug(f"Failed to fetch JS bundle {js_url}: {fetch_err}")

        return findings
