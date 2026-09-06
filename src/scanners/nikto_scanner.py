import json
import logging
from typing import List, Any
import tempfile
import os

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class NiktoScanner(BaseScanner):
    """
    Nikto web server scanner integration.
    Identifies outdated server software, dangerous files/programs, and configuration weaknesses.
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="Nikto", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        return self.get_executable("nikto") is not None or self.get_executable("nikto.pl") is not None

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        exe = self.get_executable("nikto") or self.get_executable("nikto.pl")
        if not exe:
            logger.info("Nikto is not available on host system. Skipping.")
            return []

        # Use temporary file to capture JSON report from Nikto
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                exe,
                "-h", f"https://{domain}",
                "-Format", "json",
                "-output", tmp_path,
                "-Tuning", "1,2,3,b", # Software, misconfig, info, headers (defensive baseline checks)
                "-timeout", "15"
            ]

            logger.info(f"Executing Nikto scan on {domain}")
            code, stdout, stderr = await self.run_subprocess(cmd, timeout=300)

            findings: List[Finding] = []
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                    try:
                        data = json.load(f)
                        findings.extend(self._parse_nikto_json(data))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse Nikto JSON: {e}")

            return findings
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def _parse_nikto_json(self, data: dict) -> List[Finding]:
        findings: List[Finding] = []
        items = data.get("vulnerabilities", [])
        if not items and "niktoscan" in data:
            items = data.get("niktoscan", {}).get("item", [])

        for item in items:
            msg = item.get("msg") or item.get("description", "")
            if not msg:
                continue

            msg_lower = msg.lower()
            severity = Severity.LOW
            if any(k in msg_lower for k in ["remote code", "command execution", "sql injection", "admin password"]):
                severity = Severity.CRITICAL
            elif any(k in msg_lower for k in ["directory traversal", "file disclosure", "unprotected", "vulnerable"]):
                severity = Severity.HIGH
            elif any(k in msg_lower for k in ["outdated", "deprecated", "misconfiguration", "missing header"]):
                severity = Severity.MEDIUM
            elif any(k in msg_lower for k in ["retrieved", "server banner", "apache", "nginx"]):
                severity = Severity.INFO

            findings.append(Finding(
                title=msg[:80] + ("..." if len(msg) > 80 else ""),
                severity=severity,
                tool=self.name,
                description=msg,
                why_it_matters="Server misconfigurations and outdated components can expose sensitive paths or known defects.",
                reference_url="https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/",
                raw_data=item
            ))

        return findings
