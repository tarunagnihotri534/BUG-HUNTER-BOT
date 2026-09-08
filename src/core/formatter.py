from typing import List, Dict, Any, Tuple
from ..database.models import Finding, Severity, ScanRecord, ScheduledScan, ApprovedSite
from .scorer import SecurityScorer


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
        # Calculate objective posture score
        score, grade, badge, progress_bar = SecurityScorer.calculate_score(findings)

        # Group findings
        critical_list = [f for f in findings if f.severity == Severity.CRITICAL]
        high_list = [f for f in findings if f.severity == Severity.HIGH]
        medium_list = [f for f in findings if f.severity == Severity.MEDIUM]
        low_info_list = [f for f in findings if f.severity in (Severity.LOW, Severity.INFO)]

        header = (
            f"🛡️ **Security Health-Check Report**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"• **Target**: `{scan_record.target_domain}`\n"
            f"• **Audit ID**: `{scan_record.scan_id}`\n"
            f"• **Health Grade**: **{badge}**\n"
            f"• **Posture Gauge**: `{progress_bar}`\n\n"
            f"📊 **Executive Breakdown**:\n"
            f"• 🚨 Critical (Immediate): **{len(critical_list)}**\n"
            f"• ⚠️ High (Fix Soon): **{len(high_list)}**\n"
            f"• 🔶 Medium (Minor): **{len(medium_list)}**\n"
            f"• ℹ️ Low / Info: **{len(low_info_list)}**\n"
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
            for f in low_info_list[:8]:  # Show first 8 routine items
                sec.append(f"• **{f.title}** (`{f.tool}`): {f.description[:120]}")
            if len(low_info_list) > 8:
                sec.append(f"\n*(+ {len(low_info_list) - 8} additional informational items)*")
            sections.append("\n".join(sec))

        if not findings:
            sections.append("✅ **All Checks Passed**: Zero vulnerabilities or misconfigurations flagged.")

        sections.append(f"📄 *To download full audit file, type:* `/export {scan_record.scan_id}`")

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

    @staticmethod
    def format_scheduled_scans_list(schedules: List[ScheduledScan]) -> str:
        """Formats active scheduled monitoring jobs."""
        if not schedules:
            return "ℹ️ *No active automated monitoring schedules configured.*\nUse `/schedule <domain> <daily|weekly>` to enroll a domain."

        lines = [
            "⏰ **Active Automated Monitoring Schedules**:",
            "━━━━━━━━━━━━━━━━━━━━"
        ]
        for s in schedules:
            interval_str = "Daily (24h)" if s.interval_hours == 24 else ("Weekly (168h)" if s.interval_hours == 168 else f"Every {s.interval_hours}h")
            last_run = s.last_run_at[:16].replace("T", " ") if s.last_run_at else "Never"
            lines.append(f"• `{s.domain}` — **{interval_str}**")
            lines.append(f"  Last check: `{last_run}` | Scheduled by User ID: `{s.user_id}`")
        lines.append("━━━━━━━━━━━━━━━━━━━━")
        lines.append("💡 *To remove a schedule*: `/unschedule <domain>`")
        return "\n".join(lines)

    @staticmethod
    def format_sites_status_list(sites: List[ApprovedSite], site_scores: Dict[str, Tuple[int, str]]) -> str:
        """Formats allowlist sites with their latest known security grades."""
        if not sites:
            return "ℹ️ *No approved domains registered.*\nAdd one with `/addsite <domain> <note>`."

        lines = [
            "🛡️ **Authorized Target Domains & Security Posture**:",
            "━━━━━━━━━━━━━━━━━━━━"
        ]
        for s in sites:
            score_info = site_scores.get(s.domain.lower())
            if score_info:
                score, grade = score_info
                status_str = f"Score: **{score}/100** ({grade})"
            else:
                status_str = "_Not scanned yet_"

            lines.append(f"• **`{s.domain}`** — {status_str}")
            lines.append(f"  Basis: _{s.note}_ (Added: {s.created_at[:10]})")
        lines.append("━━━━━━━━━━━━━━━━━━━━")
        lines.append("💡 *To scan all authorized domains*: `/checkall`")
        return "\n".join(lines)
