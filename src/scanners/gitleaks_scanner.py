import json
import logging
from pathlib import Path
from typing import List, Any
import tempfile
import os

from .base import BaseScanner
from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class GitleaksScanner(BaseScanner):
    """
    Gitleaks secret scanner integration.
    Audits connected Git repositories for committed secrets, API tokens, and private keys.
    """

    def __init__(self, custom_bin_path: str = ""):
        super().__init__(name="Gitleaks", custom_bin_path=custom_bin_path)

    def is_available(self) -> bool:
        return self.get_executable("gitleaks") is not None

    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        exe = self.get_executable("gitleaks")
        repo_path = kwargs.get("repo_path")

        if not exe:
            logger.info("Gitleaks is not available on host system. Skipping.")
            return []

        if not repo_path or not Path(repo_path).exists():
            logger.info(f"No connected repository path provided for target {domain}. Skipping Gitleaks.")
            return []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_report = tmp.name

        try:
            cmd = [
                exe,
                "detect",
                "--source", str(repo_path),
                "--report-format", "json",
                "--report-path", tmp_report,
                "--redact", # Redact raw secret values for safe handling
                "--no-banner"
            ]

            logger.info(f"Executing Gitleaks on repo: {repo_path}")
            code, stdout, stderr = await self.run_subprocess(cmd, timeout=180)

            findings: List[Finding] = []
            if os.path.exists(tmp_report) and os.path.getsize(tmp_report) > 0:
                with open(tmp_report, "r", encoding="utf-8", errors="replace") as f:
                    try:
                        data = json.load(f)
                        for leak in data:
                            rule_id = leak.get("RuleID", "Secret Exposure")
                            file_path = leak.get("File", "unknown file")
                            commit = leak.get("Commit", "")
                            author = leak.get("Author", "")
                            
                            desc = f"Secret detected by rule '{rule_id}' in file `{file_path}` (Commit: {commit[:8]} by {author})."
                            findings.append(Finding(
                                title=f"Exposed Secret: {rule_id}",
                                severity=Severity.CRITICAL, # Credentials leaked in git are always Critical
                                tool=self.name,
                                description=desc,
                                why_it_matters="Committed secrets can be scraped and exploited to access cloud infrastructure, APIs, and databases. Immediate key rotation is required.",
                                reference_url="https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures/",
                                raw_data={
                                    "rule_id": rule_id,
                                    "file": file_path,
                                    "commit": commit,
                                    "author": author,
                                    "date": leak.get("Date")
                                }
                            ))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Error parsing Gitleaks report: {e}")

            return findings
        finally:
            if os.path.exists(tmp_report):
                try:
                    os.remove(tmp_report)
                except Exception:
                    pass
