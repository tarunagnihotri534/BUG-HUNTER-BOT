import json
import logging
from typing import List, Any

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class NucleiScanner(BaseScanner):
    """
    ProjectDiscovery Nuclei scanner integration.
    Performs fast, template-driven vulnerability and configuration health checks.
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="Nuclei", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        return self.get_executable("nuclei") is not None

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        exe = self.get_executable("nuclei")
        if not exe:
            logger.info("Nuclei is not available on host system. Skipping.")
            return []

        target_url = f"https://{domain}"
        # Standard health check tags (misconfigurations, exposed panels, CVEs)
        cmd = [
            exe,
            "-target", target_url,
            "-jsonl",
            "-silent",
            "-tags", "cve,misconfig,exposure,tech",
            "-timeout", "10",
            "-retries", "1"
        ]

        logger.info(f"Executing Nuclei scan on {domain}")
        code, stdout, stderr = await self.run_subprocess(cmd, timeout=300)

        findings: List[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                finding = self._parse_nuclei_item(data)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Error parsing Nuclei output line: {e}")

        return findings

    def _parse_nuclei_item(self, data: dict) -> Finding:
        info = data.get("info", {})
        title = info.get("name", data.get("template-id", "Nuclei Finding"))
        raw_sev = str(info.get("severity", "info")).upper()

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        severity = severity_map.get(raw_sev, Severity.INFO)

        description = info.get("description") or f"Issue flagged by template {data.get('template-id')}"
        
        # Determine why it matters
        cwe_ids = info.get("classification", {}).get("cwe-id", [])
        cve_ids = info.get("classification", {}).get("cve-id", [])
        
        why_parts = []
        if cve_ids:
            why_parts.append(f"Associated with {', '.join(cve_ids) if isinstance(cve_ids, list) else cve_ids}.")
        if cwe_ids:
            why_parts.append(f"Classified under {', '.join(cwe_ids) if isinstance(cwe_ids, list) else cwe_ids}.")
        if not why_parts:
            why_parts.append("Potential security misconfiguration or exposed asset that should be reviewed.")
        
        why_it_matters = " ".join(why_parts)

        # Reference
        refs = info.get("reference", [])
        reference_url = refs[0] if isinstance(refs, list) and refs else None

        return Finding(
            title=title,
            severity=severity,
            tool=self.name,
            description=description,
            why_it_matters=why_it_matters,
            reference_url=reference_url,
            raw_data={
                "template_id": data.get("template-id"),
                "matched_at": data.get("matched-at"),
                "type": data.get("type"),
                "curl_command": data.get("curl-command"),
            }
        )
