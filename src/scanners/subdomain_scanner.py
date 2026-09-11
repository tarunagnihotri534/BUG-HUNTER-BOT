import json
import logging
import random
import string
from typing import List, Any, Set
import dns.asyncresolver
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

HIGH_VALUE_PREFIXES = ["staging", "dev", "test", "internal", "admin", "api", "v1", "v2", "corp", "vpn", "jenkins", "gitlab"]


class SubdomainScanner(BaseScanner):
    """
    Performs passive and active subdomain asset discovery.
    Queries Certificate Transparency (crt.sh) logs, verifies live DNS resolutions,
    filters DNS wildcards using randomized canaries, and highlights high-risk
    staging / development subdomains.
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="Subdomain Discovery", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        return True

    async def _has_wildcard_dns(self, domain: str) -> bool:
        """Test if target domain uses a wildcard DNS catch-all."""
        canary = f"canary-{''.join(random.choices(string.ascii_lowercase + string.digits, k=10))}.{domain}"
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = await resolver.resolve(canary, "A")
            return len(answers) > 0
        except Exception:
            return False

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()

        # 1. Test for Wildcard DNS
        is_wildcard = await self._has_wildcard_dns(domain)
        if is_wildcard:
            findings.append(Finding(
                title="Wildcard DNS Catch-All Active",
                severity=Severity.INFO,
                tool=self.name,
                description=f"Domain `*.{domain}` resolves non-existent subdomains to live IPs.",
                why_it_matters="Wildcard resolution can complicate attack surface management and obscure rogue service deployments.",
                reference_url="https://en.wikipedia.org/wiki/Wildcard_DNS_record"
            ))

        discovered_subs: Set[str] = set()

        # 2. Query Certificate Transparency (crt.sh) for subdomains
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for item in name_val.split("\n"):
                            clean_sub = item.strip().lower()
                            if clean_sub.endswith(f".{domain}") and "*" not in clean_sub:
                                discovered_subs.add(clean_sub)
        except Exception as e:
            logger.debug(f"crt.sh query timed out or failed for {domain}: {e}")

        # If subfinder binary exists, try executing it
        exe = self.get_executable("subfinder")
        if exe:
            try:
                cmd = [exe, "-d", domain, "-silent", "-timeout", "10"]
                code, stdout, stderr = await self.run_subprocess(cmd, timeout=30)
                for line in stdout.splitlines():
                    clean_line = line.strip().lower()
                    if clean_line.endswith(domain) and clean_line != domain:
                        discovered_subs.add(clean_line)
            except Exception as e:
                logger.debug(f"subfinder execution failed: {e}")

        if not discovered_subs:
            return findings

        # 3. Verify DNS resolution for discovered subdomains
        live_subdomains = []
        high_risk_subdomains = []
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        for sub in list(discovered_subs)[:30]:  # Limit top 30
            try:
                ans = await resolver.resolve(sub, "A")
                if ans:
                    live_subdomains.append(sub)
                    # Check if priority / forgotten environment
                    first_part = sub.replace(f".{domain}", "")
                    if any(kw in first_part for kw in HIGH_VALUE_PREFIXES):
                        high_risk_subdomains.append(sub)
            except Exception:
                continue

        if high_risk_subdomains:
            findings.append(Finding(
                title=f"Discovered {len(high_risk_subdomains)} Staging/Pre-Production Subdomain(s)",
                severity=Severity.HIGH,
                tool=self.name,
                description=(
                    f"Identified active pre-production / internal subdomains: "
                    f"`{', '.join(high_risk_subdomains[:8])}`."
                ),
                why_it_matters=(
                    "Staging, development, and test environments frequently run outdated codebases, "
                    "lack WAF protections, or use default test credentials."
                ),
                reference_url="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                endpoint=f"https://{high_risk_subdomains[0]}",
                steps_to_reproduce=f"Resolve DNS and visit `{high_risk_subdomains[0]}`.",
                remediation="Decommission forgotten testing environments or restrict access using VPN/IP whitelisting."
            ))

        if live_subdomains:
            findings.append(Finding(
                title=f"Active Subdomain Asset Inventory ({len(live_subdomains)} Live Hosts)",
                severity=Severity.INFO,
                tool=self.name,
                description=f"Resolved live hosts: {', '.join(live_subdomains[:12])}...",
                why_it_matters="Expanded attack surface enumeration for defensive inventory tracking.",
                raw_data={"live_subdomains": live_subdomains}
            ))

        return findings
