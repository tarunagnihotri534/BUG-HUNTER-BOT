import hashlib
import logging
from typing import List, Any, Set
from urllib.parse import urlparse
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

SENSITIVE_KEYWORDS = ["api", "admin", "debug", "test", "staging", "internal", "config", "backup", "v1", "v2", "export"]


class ArchiveScanner(BaseScanner):
    """
    Historical Endpoint Discovery via Wayback Machine / web archives.
    Retrieves archived endpoints for the target domain, tests if they remain alive,
    and flags unlinked, forgotten, or sensitive endpoints (comparing against soft 404s).
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="Historical Archive Discovery", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()
        archived_urls: Set[str] = set()

        # 1. Fetch archived endpoints from Wayback Machine API
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=50"
                res = await client.get(url)
                if res.status_code == 200:
                    rows = res.json()
                    for row in rows[1:]:  # skip header
                        if row and isinstance(row, list) and len(row) > 0:
                            u = row[0]
                            parsed = urlparse(u)
                            if domain in parsed.netloc:
                                archived_urls.add(u)
        except Exception as e:
            logger.debug(f"Wayback Machine query failed for {domain}: {e}")

        # If gau is present on host
        exe = self.get_executable("gau")
        if exe:
            try:
                cmd = [exe, "--subs", "--providers", "wayback", domain]
                code, stdout, stderr = await self.run_subprocess(cmd, timeout=30)
                for line in stdout.splitlines()[:50]:
                    archived_urls.add(line.strip())
            except Exception as e:
                logger.debug(f"gau failed: {e}")

        if not archived_urls:
            return findings

        # 2. Check for Soft-404 baseline hash
        root_hash = ""
        headers = {"User-Agent": "CyberSentinel-SecurityAudit/2.0"}
        async with httpx.AsyncClient(headers=headers, timeout=6.0, verify=False, follow_redirects=True) as client:
            try:
                root_res = await client.get(f"https://{domain}")
                root_hash = hashlib.md5(root_res.content).hexdigest()
            except Exception:
                pass

            # 3. Test archived endpoints
            live_endpoints = []
            sensitive_endpoints = []

            for u in list(archived_urls)[:15]:
                try:
                    r = await client.get(u)
                    if r.status_code in (200, 201, 301, 302):
                        content_hash = hashlib.md5(r.content).hexdigest()
                        # Exclude soft 404s matching the root page
                        if content_hash != root_hash:
                            live_endpoints.append((u, r.status_code))
                            parsed_path = urlparse(u).path.lower()
                            if any(k in parsed_path for k in SENSITIVE_KEYWORDS):
                                sensitive_endpoints.append((u, r.status_code))
                except Exception:
                    continue

        if sensitive_endpoints:
            sample_endpoints = [f"`{ep}` (HTTP {code})" for ep, code in sensitive_endpoints[:5]]
            findings.append(Finding(
                title=f"Discovered {len(sensitive_endpoints)} Historical Sensitive Live Endpoint(s)",
                severity=Severity.HIGH,
                tool=self.name,
                description=(
                    f"Historical web archives revealed live endpoints containing sensitive path keywords: "
                    f"{', '.join(sample_endpoints)}."
                ),
                why_it_matters=(
                    "Historical or legacy endpoints that remain active without current UI links "
                    "often lack modern authentication checks, input sanitization, or rate-limiting."
                ),
                reference_url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                endpoint=sensitive_endpoints[0][0],
                steps_to_reproduce=f"Send GET request to `{sensitive_endpoints[0][0]}` and observe HTTP {sensitive_endpoints[0][1]}.",
                remediation="Deprecate and remove unlinked endpoints or implement explicit access control and authentication."
            ))
        elif live_endpoints:
            findings.append(Finding(
                title=f"Verified {len(live_endpoints)} Historical Unlinked Live URL(s)",
                severity=Severity.INFO,
                tool=self.name,
                description=f"Archived routes still responding on server: {', '.join([e[0] for e in live_endpoints[:5]])}...",
                why_it_matters="Legacy routes discovered via archive enumeration."
            ))

        return findings
