import logging
from typing import List, Any
import httpx

from ..database.models import Finding, Severity
from .base import BaseScanner

logger = logging.getLogger(__name__)


class HeadersScanner(BaseScanner):
    """
    Scans HTTP security headers, TLS redirect enforcement, cookie flags,
    and checks for sensitive file exposure (e.g. .env, .git) using standard HTTP requests.
    Zero external binary dependencies.
    """

    def __init__(self):
        super().__init__(name="HTTP Headers & Web Posture")

    def is_available(self) -> bool:
        # Relies entirely on built-in httpx library
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()

        # Follow redirects up to 5 hops
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityHealthBot/1.0 (Defensive Audit)"
        }

        async with httpx.AsyncClient(headers=headers, timeout=10.0, verify=False, follow_redirects=True) as client:
            # 1. Test HTTPS endpoint
            https_url = f"https://{domain}"
            response: httpx.Response | None = None
            try:
                response = await client.get(https_url)
            except Exception as e:
                # Fallback to HTTP if HTTPS refused/errored
                http_url = f"http://{domain}"
                try:
                    response = await client.get(http_url)
                    findings.append(Finding(
                        title="HTTPS Not Enforced / Failed",
                        severity=Severity.HIGH,
                        tool=self.name,
                        description=f"Direct HTTPS connection to {domain} failed ({str(e)[:100]}). Target only responded over insecure HTTP.",
                        why_it_matters="All web traffic should be encrypted in transit using TLS/HTTPS to prevent interception or tampering.",
                        reference_url="https://owasp.org/www-project-secure-headers/"
                    ))
                except Exception as e2:
                    findings.append(Finding(
                        title="Web Service Unreachable",
                        severity=Severity.INFO,
                        tool=self.name,
                        description=f"Could not reach {domain} on port 80 or 443: {str(e2)[:100]}.",
                        why_it_matters="The target web server is either offline, firewalled, or blocking audit requests."
                    ))
                    return findings

            if response is not None:
                # 2. Check Security Headers
                resp_headers = {k.lower(): v for k, v in response.headers.items()}

                # HSTS
                hsts = resp_headers.get("strict-transport-security")
                if not hsts:
                    findings.append(Finding(
                        title="Missing HSTS (Strict-Transport-Security)",
                        severity=Severity.HIGH,
                        tool=self.name,
                        description="Strict-Transport-Security header is absent on HTTPS responses.",
                        why_it_matters="Without HSTS, browsers may connect over unencrypted HTTP, exposing users to SSL stripping attacks.",
                        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                    ))
                elif "max-age" in hsts.lower():
                    # Parse max-age
                    try:
                        parts = [p.strip() for p in hsts.split(";")]
                        for p in parts:
                            if p.lower().startswith("max-age="):
                                age = int(p.split("=")[1])
                                if age < 15768000:  # 6 months
                                    findings.append(Finding(
                                        title="HSTS Max-Age Too Short",
                                        severity=Severity.LOW,
                                        tool=self.name,
                                        description=f"HSTS max-age is set to {age}s, which is less than the recommended 6 months (15,768,000s).",
                                        why_it_matters="Short HSTS durations leave windows where user connections can be downgraded.",
                                        reference_url="https://hstspreload.org/"
                                    ))
                    except Exception:
                        pass

                # Content-Security-Policy
                csp = resp_headers.get("content-security-policy")
                if not csp:
                    findings.append(Finding(
                        title="Missing Content-Security-Policy (CSP)",
                        severity=Severity.MEDIUM,
                        tool=self.name,
                        description="No Content-Security-Policy header defined.",
                        why_it_matters="CSP provides defense-in-depth against Cross-Site Scripting (XSS) and data injection vulnerabilities.",
                        reference_url="https://owasp.org/www-project-secure-headers/#content-security-policy"
                    ))
                else:
                    if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                        findings.append(Finding(
                            title="Permissive Directives in CSP",
                            severity=Severity.LOW,
                            tool=self.name,
                            description="CSP contains 'unsafe-inline' or 'unsafe-eval' directives.",
                            why_it_matters="Allowing inline scripts or eval weakens protection against script execution exploits.",
                            reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                        ))

                # X-Frame-Options (Clickjacking)
                xfo = resp_headers.get("x-frame-options")
                if not xfo and (not csp or "frame-ancestors" not in csp.lower()):
                    findings.append(Finding(
                        title="Missing Anti-Clickjacking Protection",
                        severity=Severity.MEDIUM,
                        tool=self.name,
                        description="Neither X-Frame-Options nor CSP frame-ancestors header is configured.",
                        why_it_matters="Attackers can embed the target site in an iframe to trick users into unintended clicks (clickjacking).",
                        reference_url="https://owasp.org/www-community/attacks/Clickjacking"
                    ))

                # X-Content-Type-Options
                xcto = resp_headers.get("x-content-type-options")
                if not xcto or xcto.lower() != "nosniff":
                    findings.append(Finding(
                        title="Missing X-Content-Type-Options: nosniff",
                        severity=Severity.LOW,
                        tool=self.name,
                        description="X-Content-Type-Options header is missing or not set to 'nosniff'.",
                        why_it_matters="Browsers may execute uploaded non-script files as scripts via MIME type sniffing.",
                        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                    ))

                # Referrer-Policy
                ref_policy = resp_headers.get("referrer-policy")
                if not ref_policy:
                    findings.append(Finding(
                        title="Missing Referrer-Policy Header",
                        severity=Severity.INFO,
                        tool=self.name,
                        description="Referrer-Policy header is omitted.",
                        why_it_matters="May leak internal URL parameters, IDs, or tokens in Referer headers when linking external assets.",
                        reference_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                    ))

                # Permissions-Policy
                perm_policy = resp_headers.get("permissions-policy")
                if not perm_policy:
                    findings.append(Finding(
                        title="Missing Permissions-Policy Header",
                        severity=Severity.INFO,
                        tool=self.name,
                        description="Permissions-Policy header is absent.",
                        why_it_matters="Controls access to sensitive browser features (camera, microphone, geolocation) by third parties."
                    ))

                # Server banner / Technology disclosure
                server = resp_headers.get("server")
                x_powered = resp_headers.get("x-powered-by")
                leaks = []
                if server and any(char.isdigit() for char in server):
                    leaks.append(f"Server: {server}")
                if x_powered:
                    leaks.append(f"X-Powered-By: {x_powered}")
                if leaks:
                    findings.append(Finding(
                        title="Server Technology & Version Disclosure",
                        severity=Severity.LOW,
                        tool=self.name,
                        description=f"Headers disclose server components: {', '.join(leaks)}",
                        why_it_matters="Revealing explicit software versions allows adversaries to target known CVEs against that release."
                    ))

                # 3. Cookie Security Checks
                for cookie in response.cookies.jar:
                    cookie_name = cookie.name
                    issues = []
                    if not cookie.secure:
                        issues.append("Missing Secure flag (can transmit over plaintext HTTP)")
                    # Check HttpOnly & SameSite if available
                    # httpx cookies might expose attributes
                    is_httponly = getattr(cookie, "_rest", {}).get("HttpOnly") or getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly")
                    if not is_httponly:
                        issues.append("Missing HttpOnly flag (accessible to client-side JS / XSS)")
                    if issues:
                        findings.append(Finding(
                            title=f"Insecure Cookie Flags: `{cookie_name}`",
                            severity=Severity.MEDIUM if not cookie.secure else Severity.LOW,
                            tool=self.name,
                            description=f"Cookie `{cookie_name}` has weak flags: {'; '.join(issues)}.",
                            why_it_matters="Insecure cookies risk session hijacking if stolen via MITM or cross-site scripting."
                        ))

            # 4. Sensitive File Exposure Passive Probe (.env, /.git/HEAD)
            exposure_paths = [
                ("/.env", "Exposed Environment Configuration (.env)", Severity.CRITICAL, "Contains plaintext credentials, database passwords, or secret API keys!"),
                ("/.git/HEAD", "Exposed Git Repository (/.git/HEAD)", Severity.CRITICAL, "Allows complete source code reconstruction and credential extraction!"),
                ("/robots.txt", "Robots.txt Analysis", Severity.INFO, "Standard crawler file; inspected for disclosed admin or private directories.")
            ]

            for path, title, sev, impact in exposure_paths:
                try:
                    probe_url = f"https://{domain}{path}"
                    res = await client.get(probe_url, timeout=5.0)
                    if res.status_code == 200:
                        content = res.text
                        # Verify .env looks like env file (has key=val, not HTML 404 page)
                        if path == "/.env":
                            if ("=" in content or "SECRET" in content or "KEY" in content) and "<html" not in content.lower():
                                findings.append(Finding(
                                    title=title,
                                    severity=sev,
                                    tool=self.name,
                                    description=f"The endpoint `{probe_url}` returned HTTP 200 with apparent configuration data.",
                                    why_it_matters=impact
                                ))
                        elif path == "/.git/HEAD":
                            if content.startswith("ref:") or "refs/" in content:
                                findings.append(Finding(
                                    title=title,
                                    severity=sev,
                                    tool=self.name,
                                    description=f"The endpoint `{probe_url}` returned HTTP 200 containing valid Git HEAD pointer.",
                                    why_it_matters=impact
                                ))
                        elif path == "/robots.txt":
                            disallowed = [line.strip() for line in content.splitlines() if line.lower().startswith("disallow:")]
                            sensitive_hints = [d for d in disallowed if any(kw in d.lower() for kw in ["admin", "secret", "private", "backup", "staging", "api"])]
                            if sensitive_hints:
                                findings.append(Finding(
                                    title="Sensitive Endpoints Listed in robots.txt",
                                    severity=Severity.LOW,
                                    tool=self.name,
                                    description=f"robots.txt publicly advertises disallowed paths: {', '.join(sensitive_hints[:5])}",
                                    why_it_matters="Adversaries scan robots.txt to discover hidden admin panels, staging routes, or backup folders."
                                ))
                except Exception:
                    pass

        return findings
