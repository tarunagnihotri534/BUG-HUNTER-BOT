from typing import List, Dict, Any
from ..database.models import Finding, Severity, ScanRecord


class ReportFormatter:
    """Formats security health check findings into clear, prioritized Telegram messages."""

    @staticmethod
    def format_critical_alert(domain: str, critical_findings: List[Finding]) -> str:
        """Immediate high-priority alert for critical vulnerabilities or exposures."""
        lines = [
            f"🚨🚨 **URGENT SECURITY ALERT: {domain.upper()}** 🚨🚨",
            f"Immediate attention is required! {len(critical_findings)} critical issue(s) detected during automated health check:\n"
        ]

        for idx, f in enumerate(critical_findings, 1):
            lines.append(f"**{idx}. {f.title}**")
            lines.append(f"• **Tool**: `{f.tool}`")
            lines.append(f"• **Details**: {f.description}")
            lines.append(f"• **Action Required**: {f.why_it_matters}")
            if f.reference_url:
                lines.append(f"• **Reference**: {f.reference_url}")
            lines.append("")

        lines.append("⚠️ *Please take immediate containment or remediation actions.*")
        return "\n".join(lines)

    @staticmethod
    def format_scan_summary(scan_record: ScanRecord) -> List[str]:
        """
        Builds prioritized summary report, grouped by urgency:
        - Needs attention now (Critical)
        - Should fix soon (High)
        - Minor (Medium)
        - Informational (Low / Info)
        Returns list of message chunks to respect Telegram's 4096-character limit.
        """
        findings = scan_record.findings
        # Group findings
        critical_list = [f for f in findings if f.severity == Severity.CRITICAL]
        high_list = [f for f in findings if f.severity == Severity.HIGH]
        medium_list = [f for f in findings if f.severity == Severity.MEDIUM]
        low_info_list = [f for f in findings if f.severity in (Severity.LOW, Severity.INFO)]

        header = (
            f"🛡️ **Security Health-Check Report**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"• **Target**: `{scan_record.target_domain}`\n"
            f"• **Scan ID**: `{scan_record.scan_id}`\n"
            f"• **Status**: `{scan_record.status.value}`\n"
            f"• **Completed**: `{scan_record.completed_at or 'Just now'}`\n\n"
            f"📊 **Executive Findings Summary**:\n"
            f"• 🚨 Needs attention now (Critical): **{len(critical_list)}**\n"
            f"• ⚠️ Should fix soon (High): **{len(high_list)}**\n"
            f"• 🔶 Minor (Medium): **{len(medium_list)}**\n"
            f"• ℹ️ Informational / Low: **{len(low_info_list)}**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
        )

        sections = []

        if critical_list:
            sec = ["🚨 **NEEDS ATTENTION NOW (Critical)**:\n"]
            for f in critical_list:
                sec.append(f"• **{f.title}** (`{f.tool}`)")
                sec.append(f"  {f.description}")
                sec.append(f"  *Why it matters*: {f.why_it_matters}")
                if f.reference_url:
                    sec.append(f"  *Ref*: {f.reference_url}")
                sec.append("")
            sections.append("\n".join(sec))

        if high_list:
            sec = ["⚠️ **SHOULD FIX SOON (High)**:\n"]
            for f in high_list:
                sec.append(f"• **{f.title}** (`{f.tool}`)")
                sec.append(f"  {f.description}")
                sec.append(f"  *Why it matters*: {f.why_it_matters}")
                if f.reference_url:
                    sec.append(f"  *Ref*: {f.reference_url}")
                sec.append("")
            sections.append("\n".join(sec))

        if medium_list:
            sec = ["🔶 **MINOR ISSUES (Medium)**:\n"]
            for f in medium_list:
                sec.append(f"• **{f.title}** (`{f.tool}`)")
                sec.append(f"  {f.description}")
                sec.append(f"  *Why it matters*: {f.why_it_matters}")
                sec.append("")
            sections.append("\n".join(sec))

        if low_info_list:
            sec = ["ℹ️ **INFORMATIONAL / ROUTINE (Low & Info)**:\n"]
            for f in low_info_list[:8]: # Show first 8 routine items
                sec.append(f"• **{f.title}** (`{f.tool}`): {f.description[:120]}")
            if len(low_info_list) > 8:
                sec.append(f"\n*(+ {len(low_info_list) - 8} additional informational items)*")
            sections.append("\n".join(sec))

        if not findings:
            sections.append("✅ **All Checks Passed**: No vulnerabilities or misconfigurations flagged.")

        # Chunk into Telegram-safe messages (<= 3800 chars to allow safety margin)
        messages: List[str] = []
        current_msg = header

        for section in sections:
            if len(current_msg) + len(section) + 2 > 3800:
                messages.append(current_msg.strip())
                current_msg = section
            else:
                current_msg += "\n" + section

        if current_msg.strip():
            messages.append(current_msg.strip())

        return messages
