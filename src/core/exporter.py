import datetime
from pathlib import Path
from typing import Optional

from ..database.models import ScanRecord, Severity
from .scorer import SecurityScorer


class ExecutiveReportExporter:
    """Generates comprehensive executive security audit reports as standalone Markdown files."""

    @staticmethod
    def generate_markdown_report(scan_record: ScanRecord, output_dir: Path) -> Path:
        """
        Builds and saves a full technical security audit report.
        Returns the path to the created report.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        report_file = output_dir / f"{scan_record.scan_id}_audit_report.md"

        score, grade, badge, progress_bar = SecurityScorer.calculate_score(scan_record.findings)

        crit_list = [f for f in scan_record.findings if f.severity == Severity.CRITICAL]
        high_list = [f for f in scan_record.findings if f.severity == Severity.HIGH]
        med_list = [f for f in scan_record.findings if f.severity == Severity.MEDIUM]
        low_list = [f for f in scan_record.findings if f.severity in (Severity.LOW, Severity.INFO)]

        lines = [
            f"# 🛡️ Technical Security Audit Report",
            f"",
            f"**Target Host**: `{scan_record.target_domain}`  ",
            f"**Audit ID**: `{scan_record.scan_id}`  ",
            f"**Generated**: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Status**: `{scan_record.status.value}`  ",
            f"",
            f"---",
            f"",
            f"## 📊 Executive Posture Summary",
            f"",
            f"| Metric | Assessment |",
            f"| :--- | :--- |",
            f"| **Security Health Score** | **{score} / 100** |",
            f"| **Security Grade** | **{badge}** |",
            f"| **Posture Gauge** | `{progress_bar}` |",
            f"| **Total Findings** | **{len(scan_record.findings)} issues evaluated** |",
            f"",
            f"### Vulnerability Density Breakdown",
            f"- 🚨 **Critical (Immediate Attention)**: {len(crit_list)}",
            f"- ⚠️ **High (Fix Soon)**: {len(high_list)}",
            f"- 🔶 **Medium (Moderate Risk)**: {len(med_list)}",
            f"- ℹ️ **Low / Informational**: {len(low_list)}",
            f"",
            f"---",
            f"",
            f"## 📋 Findings Registry",
            f"",
            f"| # | Severity | Finding | Tool | Remediation |",
            f"| :-: | :--- | :--- | :--- | :--- |",
        ]

        for idx, f in enumerate(scan_record.findings, 1):
            remedy = f.why_it_matters.split(".")[0] if f.why_it_matters else "Review and harden configuration"
            lines.append(f"| {idx} | {f.severity.badge} | {f.title} | `{f.tool}` | {remedy} |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 🔬 In-Depth Analysis & Action Plan",
            f""
        ])

        if not scan_record.findings:
            lines.append("✅ *No security anomalies or exposures detected during this routine health check.*")
        else:
            for idx, f in enumerate(scan_record.findings, 1):
                lines.append(f"### {idx}. {f.severity.badge}: {f.title}")
                lines.append(f"- **Detector**: `{f.tool}`")
                lines.append(f"- **Observation**: {f.description}")
                lines.append(f"- **Risk & Impact**: {f.why_it_matters}")
                if f.reference_url:
                    lines.append(f"- **Standard / Reference**: [{f.reference_url}]({f.reference_url})")
                lines.append("")

        lines.extend([
            f"---",
            f"",
            f"## 🔒 Guardrails & Defensive Audit Notice",
            f"This automated audit was conducted using non-destructive, read-only defensive scanners in compliance with organizational authorization policies.",
            f"Target domain `{scan_record.target_domain}` was verified against the cryptographic allowlist prior to scan initiation.",
            f"",
            f"*Report generated automatically by Website Security Health-Check Bot.*"
        ])

        with open(report_file, "w", encoding="utf-8") as out:
            out.write("\n".join(lines))

        return report_file
