import logging
from typing import List, Any, Optional
import httpx

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class ZAPScanner(BaseScanner):
    """
    OWASP ZAP integration via REST API.
    Audits common web application vulnerabilities (XSS, security headers, injection patterns).
    """

    def __init__(self, base_url: str = "http://localhost:8080", api_key: str = ""):
        super().__init__(name="OWASP ZAP")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def is_available(self) -> bool:
        """Synchronous check is conservative; async availability check is done before scan."""
        return bool(self.base_url)

    async def check_connection(self) -> bool:
        """Verify ZAP REST API daemon is up and responsive."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                params = {"apikey": self.api_key} if self.api_key else {}
                res = await client.get(f"{self.base_url}/JSON/core/view/version/", params=params)
                return res.status_code == 200
        except Exception:
            return False

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        if not await self.check_connection():
            logger.info(f"OWASP ZAP daemon is not reachable at {self.base_url}. Skipping ZAP scan.")
            return []

        target_url = f"https://{domain}"
        findings: List[Finding] = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                params = {
                    "baseurl": target_url,
                    "apikey": self.api_key
                } if self.api_key else {"baseurl": target_url}

                # Query alerts already discovered or triggered for this target
                res = await client.get(f"{self.base_url}/JSON/core/view/alerts/", params=params)
                if res.status_code == 200:
                    data = res.json()
                    alerts = data.get("alerts", [])
                    for alert in alerts:
                        finding = self._parse_zap_alert(alert)
                        if finding:
                            findings.append(finding)
                else:
                    logger.warning(f"ZAP API returned status {res.status_code}: {res.text}")

        except Exception as e:
            logger.error(f"Error communicating with ZAP REST API: {e}")

        return findings

    def _parse_zap_alert(self, alert: dict) -> Finding:
        raw_risk = str(alert.get("risk", "")).lower()
        confidence = alert.get("confidence", "")

        severity_map = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
            "info": Severity.INFO,
        }
        severity = severity_map.get(raw_risk, Severity.INFO)

        cwe_id = alert.get("cweid")
        wasc_id = alert.get("wascid")
        ref_url = None
        if cwe_id and str(cwe_id) != "-1" and str(cwe_id) != "0":
            ref_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        elif alert.get("reference"):
            refs = alert["reference"].split("\n")
            ref_url = refs[0].strip() if refs else None

        why = alert.get("solution") or "Configuration issue or vulnerability identified by OWASP ZAP baseline scanner."
        why_it_matters = f"Risk: {raw_risk.title()} (Confidence: {confidence}). Remediation: {why}"

        return Finding(
            title=alert.get("alert", alert.get("name", "OWASP ZAP Finding")),
            severity=severity,
            tool=self.name,
            description=alert.get("description", "No description provided."),
            why_it_matters=why_it_matters,
            reference_url=ref_url,
            raw_data={
                "pluginId": alert.get("pluginId"),
                "url": alert.get("url"),
                "method": alert.get("method"),
                "param": alert.get("param"),
                "evidence": alert.get("evidence"),
                "cweid": cwe_id,
                "wascid": wasc_id,
            }
        )
