import datetime
from pathlib import Path
from typing import Optional

from ..database.models import Finding, ScanRecord, Severity
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

        score, grade, badge, progress_bar, active_leak = SecurityScorer.calculate_score(scan_record.findings)

        crit_list = [f for f in scan_record.findings if f.severity == Severity.CRITICAL]
        high_list = [f for f in scan_record.findings if f.severity == Severity.HIGH]
        med_list = [f for f in scan_record.findings if f.severity == Severity.MEDIUM]
        low_list = [f for f in scan_record.findings if f.severity in (Severity.LOW, Severity.INFO)]

        leak_status_row = "| **Active Critical Leak** | **🚨 YES (Critical Action Required)** |" if active_leak else "| **Active Critical Leak** | **🛡️ NO** |"

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
            f"{leak_status_row}",
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

    @staticmethod
    def generate_bug_bounty_draft(finding: Finding, target_domain: str, output_dir: Path) -> Path:
        """
        Generates a professional bug-bounty platform submission template
        (HackerOne / Bugcrowd style) for a confirmed vulnerability finding.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_title = "".join(c for c in finding.title if c.isalnum() or c in ("-", "_")).lower()
        report_file = output_dir / f"bounty_draft_{safe_title}.md"

        endpoint_str = finding.endpoint or f"https://{target_domain}"
        reproduction_str = finding.steps_to_reproduce or (
            f"1. Open terminal or browser.\n"
            f"2. Send an HTTP request to `{endpoint_str}`.\n"
            f"3. Observe response and verify finding behavior: {finding.description}."
        )
        remediation_str = finding.remediation or finding.why_it_matters

        draft = [
            f"# [Vulnerability Report] {finding.title} on {target_domain}",
            f"",
            f"## 1. Summary",
            f"{finding.description}",
            f"",
            f"## 2. Vulnerability Details",
            f"- **Target Domain / Asset**: `{target_domain}`",
            f"- **Affected Endpoint / Asset**: `{endpoint_str}`",
            f"- **Reported Severity**: **{finding.severity.value}**",
            f"- **Detection Component**: `{finding.tool}`",
            f"",
            f"## 3. Steps to Reproduce",
            f"{reproduction_str}",
            f"",
            f"## 4. Impact Assessment",
            f"{finding.why_it_matters}",
            f"",
            f"## 5. Suggested Remediation",
            f"{remediation_str}",
            f"",
            f"## 6. References & Standards",
            f"{finding.reference_url or 'https://owasp.org/www-project-top-ten/'}",
            f"",
            f"---",
            f"*Auto-drafted by CyberSentinel Security Operations Agent.*"
        ]

        with open(report_file, "w", encoding="utf-8") as out:
            out.write("\n".join(draft))

        return report_file
