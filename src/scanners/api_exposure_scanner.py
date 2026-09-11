import json
import logging
import re
from typing import List, Any
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)

# Sensitive object keys that indicate API data over-exposure
CRITICAL_SENSITIVE_KEYS = [
    "password", "password_hash", "passwd", "salt", "secret", "secret_key",
    "private_key", "priv_key", "auth_token", "access_token", "jwt",
    "ssn", "social_security", "credit_card", "cvv"
]

SUSPICIOUS_INTERNAL_KEYS = [
    "internal_id", "is_admin", "role_id", "permissions", "user_role",
    "deleted_at", "db_id", "schema_version"
]

COMMON_API_ENDPOINTS = [
    "/api/user",
    "/api/users",
    "/api/profile",
    "/api/v1/user",
    "/api/v1/profile",
    "/api/v1/users",
    "/api/v1/me",
    "/api/me",
    "/api/config",
    "/api/v1/config",
    "/api/settings"
]


def extract_all_keys(obj: Any) -> List[str]:
    """Recursively extract all dictionary keys from a JSON structure."""
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(str(k))
            keys.extend(extract_all_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(extract_all_keys(item))
    return keys


class APIExposureScanner(BaseScanner):
    """
    API Over-Exposure Scanner.
    Inspects accessible API endpoints for excessive data exposure (OWASP API3:2023),
    flagging endpoints returning password hashes, salts, internal IDs, or credentials
    not intended for public consumption.
    """

    def __init__(self):
        super().__init__(name="API Over-Exposure & Sensitive Fields")

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        findings: List[Finding] = []
        domain = domain.lower().strip()
        headers = {
            "User-Agent": "CyberSentinel-SecurityAudit/2.0",
            "Accept": "application/json"
        }

        async with httpx.AsyncClient(headers=headers, timeout=6.0, verify=False) as client:
            for route in COMMON_API_ENDPOINTS:
                endpoint_url = f"https://{domain}{route}"
                try:
                    res = await client.get(endpoint_url)
                    if res.status_code == 200 and "application/json" in res.headers.get("content-type", "").lower():
                        try:
                            data = res.json()
                            keys = extract_all_keys(data)
                            keys_lower = [k.lower().strip() for k in keys]

                            # 1. Check for Critical Sensitive Keys (hashes, secrets, tokens)
                            leaked_critical = [k for k in keys_lower if any(crit == k or crit in k for crit in CRITICAL_SENSITIVE_KEYS)]
                            if leaked_critical:
                                findings.append(Finding(
                                    title=f"Critical API Data Over-Exposure on `{route}`",
                                    severity=Severity.CRITICAL,
                                    tool=self.name,
                                    description=(
                                        f"Endpoint `{endpoint_url}` returned JSON containing high-risk credential fields: "
                                        f"`{', '.join(set(leaked_critical))}`."
                                    ),
                                    why_it_matters=(
                                        "OWASP API3:2023 Broken Object Property Level Authorization / Excessive Data Exposure. "
                                        "Backend models are serialized directly into API responses without field filtering."
                                    ),
                                    reference_url="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                                    endpoint=endpoint_url,
                                    steps_to_reproduce=(
                                        f"1. Send GET request: `curl -H 'Accept: application/json' {endpoint_url}`\n"
                                        f"2. Inspect JSON response and verify presence of sensitive keys: `{', '.join(set(leaked_critical))}`."
                                    ),
                                    remediation="Implement Data Transfer Objects (DTOs) or explicit serializer field whitelists to restrict outbound API responses."
                                ))
                                continue

                            # 2. Check for Internal State / Suspicious Metadata Keys
                            leaked_internal = [k for k in keys_lower if any(sus == k for sus in SUSPICIOUS_INTERNAL_KEYS)]
                            if leaked_internal:
                                findings.append(Finding(
                                    title=f"Internal Application Metadata Exposed in API Response (`{route}`)",
                                    severity=Severity.MEDIUM,
                                    tool=self.name,
                                    description=(
                                        f"Endpoint `{endpoint_url}` disclosed internal database or permission flags: "
                                        f"`{', '.join(set(leaked_internal))}`."
                                    ),
                                    why_it_matters="Disclosing internal authorization flags (e.g. is_admin, role_id) aids adversaries in privilege escalation and parameter tampering attacks.",
                                    reference_url="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                                    endpoint=endpoint_url,
                                    remediation="Exclude internal system fields and permission flags from public API representations."
                                ))
                        except Exception:
                            pass
                except Exception:
                    continue

        return findings
