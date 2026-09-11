import logging
import re
from typing import List, Any
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

# Common parameter dictionary for hidden parameter discovery
COMMON_PARAMS = [
    "id", "user_id", "account_id", "uid", "profile_id", "org_id",
    "admin", "debug", "test", "role", "access", "token", "key",
    "secret", "redirect", "url", "next", "file", "path", "view",
    "cmd", "exec", "query", "search", "filter", "sort", "limit"
]

IDOR_PARAMS = ["id", "user_id", "account_id", "uid", "profile_id", "order_id", "doc_id"]


class ParamFuzzerScanner(BaseScanner):
    """
    Active parameter-level fuzzing and hidden parameter discovery.
    Tests discovered/known endpoints for unlinked parameters and heuristic IDOR indicators.
    SAFETY GUARD: Gated strictly behind explicit user authorization consent.
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="Parameter Fuzzing & IDOR Review", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        # SAFETY CONSTRAINT: Check explicit authorization consent
        authorized_consent = kwargs.get("authorized_consent", False)
        if not authorized_consent:
            logger.info("Skipping active parameter fuzzing: target not flagged with explicit --authorized consent.")
            return []

        domain = domain.lower().strip()
        base_url = f"https://{domain}"

        # If arjun binary exists on host system
        exe = self.get_executable("arjun")
        if exe:
            try:
                cmd = [exe, "-u", base_url, "--stable", "-t", "5", "--json"]
                code, stdout, stderr = await self.run_subprocess(cmd, timeout=45)
                logger.info(f"Arjun output: {stdout[:200]}")
            except Exception as e:
                logger.debug(f"Arjun run failed: {e}")

        # Native asynchronous parameter discovery & IDOR heuristic check
        headers = {"User-Agent": "CyberSentinel-SecurityAudit/2.0"}
        async with httpx.AsyncClient(headers=headers, timeout=6.0, verify=False, follow_redirects=True) as client:
            # Baseline request
            try:
                base_res = await client.get(base_url)
                base_len = len(base_res.content)
            except Exception as e:
                logger.debug(f"Could not reach {base_url} for param fuzzing: {e}")
                return []

            discovered_params = []
            idor_candidates = []

            for param in COMMON_PARAMS[:18]:
                test_val = "101" if param in IDOR_PARAMS else "cs_test_probe"
                try:
                    res = await client.get(f"{base_url}/?{param}={test_val}")
                    # If response code differs or response length changes significantly (>15%)
                    if abs(len(res.content) - base_len) > (base_len * 0.15) or res.status_code != base_res.status_code:
                        discovered_params.append(param)
                        if param in IDOR_PARAMS:
                            idor_candidates.append(param)
                except Exception:
                    continue

            if idor_candidates:
                findings.append(Finding(
                    title=f"Potential IDOR Parameter Pattern Discovered (`{', '.join(idor_candidates)}`)",
                    severity=Severity.HIGH,
                    tool=self.name,
                    description=(
                        f"Discovered parameters accepting sequential/predictable numeric object references: "
                        f"`{', '.join(idor_candidates)}`. The endpoint returned distinct responses to varied values."
                    ),
                    why_it_matters=(
                        "Insecure Direct Object References (IDOR) occur when an application provides direct access to objects "
                        "based on user-supplied input without verifying authorization for the requested object."
                    ),
                    reference_url="https://portswigger.net/web-security/access-control/idor",
                    endpoint=f"{base_url}/?{idor_candidates[0]}=101",
                    steps_to_reproduce=(
                        f"1. Send request: `GET {base_url}/?{idor_candidates[0]}=101`\n"
                        f"2. Send request: `GET {base_url}/?{idor_candidates[0]}=102`\n"
                        f"3. Verify whether records belonging to different users or entities are returned without authorization checks."
                    ),
                    remediation="Flagged for manual review. Implement server-side authorization checks verifying the requesting user possesses rights to the requested object reference before returning data."
                ))
            elif discovered_params:
                findings.append(Finding(
                    title=f"Hidden/Unlinked Parameter(s) Accepted: `{', '.join(discovered_params)}`",
                    severity=Severity.MEDIUM,
                    tool=self.name,
                    description=(
                        f"Endpoint `{base_url}` yielded response state changes when injected with: "
                        f"`{', '.join(discovered_params)}`."
                    ),
                    why_it_matters=(
                        "Unadvertised query parameters can access hidden application features, debug modes, "
                        "or unauthenticated administrative routines."
                    ),
                    reference_url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
                    endpoint=f"{base_url}/?{discovered_params[0]}=test",
                    remediation="Review accepted query parameters and validate strict schema enforcement."
                ))

        return findings
