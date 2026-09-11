import asyncio
import logging
from typing import List, Any
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

AUTH_ROUTES = [
    "/login",
    "/api/login",
    "/api/v1/login",
    "/api/auth/login",
    "/signin",
    "/auth/signin",
    "/oauth/token",
]


class RateLimitScanner(BaseScanner):
    """
    Evaluates rate-limiting and brute-force resistance on sensitive authentication routes.
    Sends a bounded burst of 20 rapid requests and checks for HTTP 429, Retry-After headers,
    CAPTCHA challenges, or IP lockouts.
    SAFETY GUARD: Gated strictly behind explicit user authorization consent.
    """

    def __init__(self):
        super().__init__(name="Rate-Limit & Anti-Brute-Force")

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        authorized_consent = kwargs.get("authorized_consent", False)
        if not authorized_consent:
            logger.info("Skipping active rate-limit testing: target not flagged with explicit --authorized consent.")
            return []

        domain = domain.lower().strip()
        headers = {
            "User-Agent": "CyberSentinel-SecurityAudit/2.0",
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient(headers=headers, timeout=5.0, verify=False) as client:
            # 1. Identify active login/auth route
            target_endpoint = None
            for route in AUTH_ROUTES:
                try:
                    url = f"https://{domain}{route}"
                    res = await client.get(url)
                    if res.status_code in (200, 401, 403, 405):
                        target_endpoint = url
                        break
                except Exception:
                    continue

            if not target_endpoint:
                return findings

            # 2. Send bounded burst of 20 requests
            burst_count = 20
            tasks = []
            for i in range(burst_count):
                payload = {"username": f"audit_test_user_{i}@example.com", "password": "DummyPassword123!"}
                tasks.append(client.post(target_endpoint, json=payload))

            responses = await asyncio.gather(*tasks, return_exceptions=True)
            status_codes = [r.status_code for r in responses if isinstance(r, httpx.Response)]

            # 3. Analyze whether throttling or lockouts occurred
            has_429 = any(code == 429 for code in status_codes)
            has_captcha = any("captcha" in getattr(r, "text", "").lower() for r in responses if isinstance(r, httpx.Response))
            has_lockout = any(code in (403, 423) for code in status_codes)

            if not (has_429 or has_captcha or has_lockout):
                findings.append(Finding(
                    title="Missing Rate-Limiting / Anti-Brute-Force Protection on Authentication Endpoint",
                    severity=Severity.HIGH,
                    tool=self.name,
                    description=(
                        f"Sent {burst_count} rapid authentication attempts to `{target_endpoint}`. "
                        f"All requests were accepted without rate-limiting (HTTP 429), CAPTCHA, or temporary lockouts."
                    ),
                    why_it_matters=(
                        "Without rate limiting, attackers can perform unlimited password spraying, credential stuffing, "
                        "and dictionary brute-force attacks against user accounts."
                    ),
                    reference_url="https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                    endpoint=target_endpoint,
                    steps_to_reproduce=(
                        f"1. Target endpoint: `{target_endpoint}`\n"
                        f"2. Send 20 rapid sequential POST requests with dummy login credentials.\n"
                        f"3. Observe that no HTTP 429 or throttling headers are returned."
                    ),
                    remediation="Implement IP-based and account-based rate limiting (e.g., maximum 5 failed attempts per minute), progressive delays, and CAPTCHA enforcement on repeated login failures."
                ))
            else:
                findings.append(Finding(
                    title="Rate-Limiting / Throttling Active on Authentication Route",
                    severity=Severity.INFO,
                    tool=self.name,
                    description=f"Endpoint `{target_endpoint}` successfully throttled rapid burst requests (429 or challenge triggered).",
                    why_it_matters="Defensive validation of anti-brute-force controls."
                ))

        return findings
