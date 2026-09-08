import asyncio
import datetime
import json
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any

from ..config import Settings
from ..database.db import Database
from ..database.models import Finding, ScanRecord, ScanStatus, Severity
from ..scanners.base import BaseScanner
from ..scanners.tls_scanner import TLSScanner
from ..scanners.headers_scanner import HeadersScanner
from ..scanners.dns_scanner import DNSScanner
from ..scanners.nuclei_scanner import NucleiScanner
from ..scanners.zap_scanner import ZAPScanner
from ..scanners.nikto_scanner import NiktoScanner
from ..scanners.gitleaks_scanner import GitleaksScanner
from ..scanners.hibp_scanner import HIBPScanner
from .formatter import ReportFormatter
from .scorer import SecurityScorer

logger = logging.getLogger(__name__)


@dataclass
class RunningJob:
    scan_id: str
    domain: str
    user_id: int
    started_at: datetime.datetime
    active_tools: List[str]


class ScanOrchestrator:
    """
    Coordinates execution of established security scanners as background tasks.
    Enforces concurrency limits, persists raw tool outputs, extracts priority findings,
    and dispatches immediate alerts for critical issues.
    """

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self.semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        self.running_jobs: Dict[str, RunningJob] = {}

        # Initialize scanners
        self.scanners: List[BaseScanner] = [
            TLSScanner(custom_bin_path=settings.sslyze_bin),
            HeadersScanner(),
            DNSScanner(),
            NucleiScanner(custom_bin_path=settings.nuclei_bin),
            ZAPScanner(base_url=settings.zap_base_url, api_key=settings.zap_api_key),
            NiktoScanner(custom_bin_path=settings.nikto_bin),
            GitleaksScanner(custom_bin_path=settings.gitleaks_bin),
            HIBPScanner(api_key=settings.hibp_api_key),
        ]

    def get_active_jobs(self) -> List[RunningJob]:
        """Return list of currently active scan jobs."""
        return list(self.running_jobs.values())

    async def start_scan_job(
        self,
        domain: str,
        user_id: int,
        alert_callback: Optional[Callable[[str], Any]] = None,
        completion_callback: Optional[Callable[[ScanRecord, List[str], Optional[Path]], Any]] = None,
        **scan_kwargs: Any
    ) -> str:
        """
        Creates a new scan job and launches it in the background.
        Returns the unique scan_id immediately.
        """
        scan_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        await self.db.create_scan(scan_id=scan_id, target_domain=domain, user_id=user_id)

        # Launch background task
        asyncio.create_task(
            self._execute_scan(
                scan_id=scan_id,
                domain=domain,
                user_id=user_id,
                alert_callback=alert_callback,
                completion_callback=completion_callback,
                **scan_kwargs
            )
        )
        return scan_id

    async def _execute_scan(
        self,
        scan_id: str,
        domain: str,
        user_id: int,
        alert_callback: Optional[Callable[[str], Any]],
        completion_callback: Optional[Callable[[ScanRecord, List[str], Optional[Path]], Any]],
        **scan_kwargs: Any
    ) -> None:
        async with self.semaphore:
            available_scanners = [s for s in self.scanners if s.is_available()]
            active_tool_names = [s.name for s in available_scanners]

            job = RunningJob(
                scan_id=scan_id,
                domain=domain,
                user_id=user_id,
                started_at=datetime.datetime.now(datetime.timezone.utc),
                active_tools=active_tool_names
            )
            self.running_jobs[scan_id] = job

            all_findings: List[Finding] = []
            raw_reports: Dict[str, Any] = {
                "scan_id": scan_id,
                "domain": domain,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "tools_executed": active_tool_names,
                "tool_results": {}
            }

            try:
                # Run available scanners concurrently
                tasks = [scanner.scan(domain, **scan_kwargs) for scanner in available_scanners]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for scanner, res in zip(available_scanners, results):
                    if isinstance(res, Exception):
                        logger.error(f"Scanner {scanner.name} raised exception: {res}")
                        raw_reports["tool_results"][scanner.name] = {"error": str(res)}
                    else:
                        all_findings.extend(res)
                        raw_reports["tool_results"][scanner.name] = [
                            {
                                "title": f.title,
                                "severity": f.severity.value,
                                "description": f.description,
                                "why_it_matters": f.why_it_matters,
                                "raw_data": f.raw_data
                            }
                            for f in res
                        ]

                # Sort findings by urgency (Critical first)
                all_findings.sort(key=lambda x: x.severity.priority_rank)

                # Check for critical items to send immediate alert
                critical_findings = [f for f in all_findings if f.severity == Severity.CRITICAL]
                if critical_findings and alert_callback:
                    alert_text = ReportFormatter.format_critical_alert(domain, critical_findings)
                    try:
                        await alert_callback(alert_text)
                    except Exception as e:
                        logger.error(f"Error sending critical alert callback: {e}")

                # Persist raw report file
                output_dir = Path(self.settings.raw_output_dir) / domain
                output_dir.mkdir(parents=True, exist_ok=True)
                raw_file = output_dir / f"{scan_id}_raw.json"
                with open(raw_file, "w", encoding="utf-8") as f:
                    json.dump(raw_reports, f, indent=2)

                # Update database
                score, grade, badge, progress_bar = SecurityScorer.calculate_score(all_findings)
                summary_data = {
                    "score": score,
                    "grade": grade,
                    "badge": badge,
                    "progress_bar": progress_bar,
                    "critical": len(critical_findings),
                    "high": len([f for f in all_findings if f.severity == Severity.HIGH]),
                    "medium": len([f for f in all_findings if f.severity == Severity.MEDIUM]),
                    "low_info": len([f for f in all_findings if f.severity in (Severity.LOW, Severity.INFO)]),
                    "total": len(all_findings),
                    "tools_run": active_tool_names
                }
                await self.db.save_findings(scan_id, all_findings)
                await self.db.update_scan_status(
                    scan_id=scan_id,
                    status=ScanStatus.COMPLETED,
                    summary=summary_data,
                    raw_output_path=str(raw_file)
                )

                scan_record = await self.db.get_scan(scan_id)
                if scan_record and completion_callback:
                    summary_messages = ReportFormatter.format_scan_summary(scan_record)
                    try:
                        await completion_callback(scan_record, summary_messages, raw_file)
                    except Exception as e:
                        logger.error(f"Error in scan completion callback: {e}")

            except Exception as e:
                logger.error(f"Unexpected error in scan job {scan_id}: {e}", exc_info=True)
                await self.db.update_scan_status(scan_id=scan_id, status=ScanStatus.FAILED)
            finally:
                self.running_jobs.pop(scan_id, None)
