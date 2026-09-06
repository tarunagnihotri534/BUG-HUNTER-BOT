import logging
from typing import List, Any
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class HIBPScanner(BaseScanner):
    """
    HaveIBeenPwned API integration.
    Checks whether domain-associated project email addresses appear in public breach datasets.
    This queries public breach repositories without sending any traffic or attacks against the target.
    """

    def __init__(self, api_key: str = ""):
        super().__init__(name="HaveIBeenPwned")
        self.api_key = api_key.strip()

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        if not self.api_key:
            logger.info("No HaveIBeenPwned API key configured. Skipping breach checks.")
            return []

        # Emails to check: either provided explicitly or standard project contacts
        emails_to_check = kwargs.get("emails", [
            f"admin@{domain}",
            f"security@{domain}",
            f"contact@{domain}",
            f"webmaster@{domain}"
        ])

        findings: List[Finding] = []
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": "SecurityHealthCheckBot-Telegram/1.0"
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            for email in emails_to_check:
                try:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
                    res = await client.get(url, headers=headers)

                    if res.status_code == 200:
                        breaches = res.json()
                        for b in breaches:
                            b_name = b.get("Name", "Unknown Breach")
                            b_date = b.get("BreachDate", "Unknown date")
                            data_classes = ", ".join(b.get("DataClasses", []))
                            pwn_count = b.get("PwnCount", 0)

                            has_passwords = "Passwords" in b.get("DataClasses", [])
                            sev = Severity.HIGH if has_passwords else Severity.MEDIUM

                            findings.append(Finding(
                                title=f"Compromised Account: {email} in {b_name}",
                                severity=sev,
                                tool=self.name,
                                description=(
                                    f"The address `{email}` was identified in the public '{b_name}' breach ({b_date}). "
                                    f"Exposed data fields: {data_classes}. Total accounts compromised in breach: {pwn_count:,}."
                                ),
                                why_it_matters=(
                                    "Credentials or personal data from this address have been publicly leaked. "
                                    "If credentials were reused on the target site or administrative portals, accounts may be susceptible to credential stuffing."
                                ),
                                reference_url="https://haveibeenpwned.com",
                                raw_data=b
                            ))
                    elif res.status_code == 404:
                        # 404 means no breach found for this email address = good!
                        pass
                    elif res.status_code == 429:
                        logger.warning("HaveIBeenPwned rate limit exceeded. Pausing checks.")
                        break
                    else:
                        logger.warning(f"HIBP returned status {res.status_code} for {email}")

                except Exception as e:
                    logger.error(f"Error querying HIBP for {email}: {e}")

        return findings
