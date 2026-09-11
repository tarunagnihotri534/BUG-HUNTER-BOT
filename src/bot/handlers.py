import datetime
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from telegram import Update
from telegram.ext import ContextTypes, CommandHandler, MessageHandler, filters

from ..config import Settings
from ..database.db import Database
from ..database.models import ScanRecord, ScheduledScan
from ..security.allowlist import AllowlistService, normalize_domain
from ..security.auth_filter import restricted_access
from ..core.orchestrator import ScanOrchestrator
from ..core.formatter import ReportFormatter
from ..core.exporter import ExecutiveReportExporter
from ..core.scorer import SecurityScorer
from ..agent.gemini_service import GeminiService, split_telegram_message

logger = logging.getLogger(__name__)


class BotHandlers:
    """Telegram command handlers for the Security Health-Check Bot."""

    def __init__(
        self,
        settings: Settings,
        db: Database,
        allowlist: AllowlistService,
        orchestrator: ScanOrchestrator,
        gemini_service: Optional[GeminiService] = None,
    ):
        self.settings = settings
        self.db = db
        self.allowlist = allowlist
        self.orchestrator = orchestrator
        self.gemini_service = gemini_service

    def register_handlers(self, application) -> None:
        """Register command and message handlers with the Telegram application."""
        guard = restricted_access(self.settings, self.db)

        application.add_handler(CommandHandler(["start", "help"], guard(self.cmd_help)))
        application.add_handler(CommandHandler(["check", "scan"], guard(self.cmd_check)))
        application.add_handler(CommandHandler("checkall", guard(self.cmd_checkall)))
        application.add_handler(CommandHandler("status", guard(self.cmd_status)))
        application.add_handler(CommandHandler("history", guard(self.cmd_history)))
        application.add_handler(CommandHandler("history_detail", guard(self.cmd_history_detail)))
        application.add_handler(CommandHandler("export", guard(self.cmd_export)))
        application.add_handler(CommandHandler("schedule", guard(self.cmd_schedule)))
        application.add_handler(CommandHandler("unschedule", guard(self.cmd_unschedule)))
        application.add_handler(CommandHandler("schedules", guard(self.cmd_schedules)))
        application.add_handler(CommandHandler("addsite", guard(self.cmd_addsite)))
        application.add_handler(CommandHandler("removesite", guard(self.cmd_removesite)))
        application.add_handler(CommandHandler("listsites", guard(self.cmd_listsites)))
        application.add_handler(CommandHandler("audit", guard(self.cmd_audit)))
        application.add_handler(CommandHandler("reset", guard(self.cmd_reset_chat)))
        application.add_handler(CommandHandler("bounty", guard(self.cmd_bounty)))

        # Natural language conversational chat via Gemini AI Assistant
        application.add_handler(
            MessageHandler(
                filters.TEXT & ~filters.COMMAND,
                guard(self.cmd_natural_chat)
            )
        )

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Display help and operational manual."""
        user_id = update.effective_user.id
        msg = (
            "🛡️ **Website Security Health-Check & AI Assistant**\n\n"
            "Automated defensive security health checks using TLS audit, HTTP security headers, "
            "DNS/SPF/DMARC posture, and optional external engines (Nuclei, ZAP, Nikto, Gitleaks, HIBP).\n\n"
            "💬 **Conversational AI Assistant (Gemini Pro)**:\n"
            "• Simply send any message to chat! Ask security questions, request remediation code, or ask to check approved domains.\n"
            "• `/reset` — Clear your conversation memory with Gemini\n\n"
            "⚠️ **Hard Authorization Rule**: Scans are strictly restricted to pre-approved domains.\n\n"
            "📋 **Core Scan Commands**:\n"
            "• `/check <domain> [--authorized]` — Run comprehensive health check on an approved target (add `--authorized` to enable active parameter fuzzing & anti-brute-force testing)\n"
            "• `/checkall` — Queue health checks across all authorized domains\n"
            "• `/status` — View currently running background scans\n"
            "• `/history <domain>` — View past scan trends and grades\n"
            "• `/history_detail <scan_id>` — View technical breakdown for a scan\n"
            "• `/export <scan_id>` — Generate & download executive Markdown audit report\n"
            "• `/bounty <scan_id>` — Auto-draft vulnerability writeups in Bug Bounty submission format (HackerOne/Bugcrowd)\n\n"
            "⏰ **Automated Continuous Monitoring**:\n"
            "• `/schedule <domain> <daily|weekly>` — Set automated periodic scan with diff-based delta alerts\n"
            "• `/unschedule <domain>` — Remove recurring scan schedule\n"
            "• `/schedules` — List active monitoring schedules\n\n"
            "🔐 **Allowlist & Audit Management**:\n"
            "• `/addsite <domain> <note>` — Authorize domain with signed justification\n"
            "• `/removesite <domain>` — Revoke authorization for a domain\n"
            "• `/listsites` — Display all approved domains & their latest scores\n"
            "• `/audit` — Review authorization & security access logs\n\n"
            "👨‍💻 *Creator: TARUN*"
        )
        await update.effective_message.reply_text(msg, parse_mode="Markdown")

    async def _launch_scan_for_chat(
        self,
        domain: str,
        user_id: int,
        chat_id: int,
        bot,
        initial_note: Optional[str] = None,
        authorized_consent: bool = False
    ) -> str:
        """Helper to launch a scan and wire delivery callbacks to a specific chat."""
        async def alert_callback(alert_text: str):
            try:
                await bot.send_message(
                    chat_id=chat_id,
                    text=alert_text,
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Failed to deliver critical alert message: {e}")

        async def completion_callback(scan_record: ScanRecord, summary_messages: List[str], raw_file: Optional[Path]):
            try:
                for part in summary_messages:
                    await bot.send_message(
                        chat_id=chat_id,
                        text=part,
                        parse_mode="Markdown"
                    )

                if raw_file and raw_file.exists():
                    try:
                        with open(raw_file, "rb") as f:
                            await bot.send_document(
                                chat_id=chat_id,
                                document=f,
                                filename=raw_file.name,
                                caption=f"📄 Full raw output for scan `{scan_record.scan_id}`"
                            )
                    except Exception as doc_err:
                        logger.warning(f"Could not upload raw report document: {doc_err}")
            except Exception as e:
                logger.error(f"Failed to deliver completion message: {e}")

        scan_id = await self.orchestrator.start_scan_job(
            domain=domain,
            user_id=user_id,
            alert_callback=alert_callback,
            completion_callback=completion_callback,
            authorized_consent=authorized_consent
        )
        return scan_id

    async def cmd_check(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Trigger a security health check against an authorized domain."""
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id

        if not context.args:
            await update.effective_message.reply_text(
                "ℹ️ **Usage**: `/check <domain>`\nExample: `/check example.com`",
                parse_mode="Markdown"
            )
            return

        raw_target = context.args[0]
        has_authorized_flag = any(arg.lower() in ("--authorized", "-a", "--active") for arg in context.args[1:])

        is_allowed, domain_or_err, site = await self.allowlist.check_and_authorize(raw_target, user_id)
        if not is_allowed:
            await update.effective_message.reply_text(domain_or_err, parse_mode="Markdown")
            return

        domain = domain_or_err

        # Log timestamped consent if active testing requested
        if has_authorized_flag:
            await self.db.log_consent(
                target_domain=domain,
                user_id=user_id,
                action="ACTIVE_SECURITY_TESTING_CONSENT",
                details=f"User {user_id} explicitly supplied --authorized flag for parameter fuzzing & rate-limit testing."
            )
            mode_desc = "⚡ **Mode**: Deep Bug-Bounty Audit (Active Parameter Fuzzing & Anti-Brute-Force Enabled with Signed Consent)\n"
        else:
            mode_desc = "🛡️ **Mode**: Passive Defensive Audit (To enable active fuzzing & rate-limit checks, pass `--authorized`)\n"

        await update.effective_message.reply_text(
            f"🔍 **Health Check Initiated for `{domain}`**\n\n"
            f"• **Basis**: _{site.note}_\n"
            f"• {mode_desc}"
            f"• **Engines**: TLS, HTTP Headers & CORS, DNS, JS Bundles & Maps, Subdomains, Archive URLs, Cloud Buckets, API Exposure\n"
            f"• **ETA**: ~30 to 90 seconds\n\n"
            f"⚡ *Immediate alerts will be dispatched if Critical issues or continuous monitoring deltas are discovered.*",
            parse_mode="Markdown"
        )

        scan_id = await self._launch_scan_for_chat(
            domain=domain,
            user_id=user_id,
            chat_id=chat_id,
            bot=context.bot,
            authorized_consent=has_authorized_flag
        )
        logger.info(f"Scan {scan_id} initiated for {domain} by user {user_id} (active_consent={has_authorized_flag})")

    async def cmd_checkall(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Queue security health checks across all approved domains."""
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id

        sites = await self.db.get_all_active_approved_sites()
        if not sites:
            await update.effective_message.reply_text(
                "ℹ️ No approved domains registered.\nAdd domains with `/addsite <domain> <note>` first."
            )
            return

        await update.effective_message.reply_text(
            f"🚀 **Batch Audit Initiated**: Queuing health checks for **{len(sites)}** authorized domain(s):\n" +
            "\n".join([f"• `{s.domain}`" for s in sites]) +
            "\n\n*Reports will arrive asynchronously as each audit finishes.*",
            parse_mode="Markdown"
        )

        for site in sites:
            await self._launch_scan_for_chat(site.domain, user_id, chat_id, context.bot)

    async def cmd_export(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Generate and send a standalone executive Markdown audit report."""
        if not context.args:
            await update.effective_message.reply_text(
                "ℹ️ **Usage**: `/export <scan_id>`\nExample: `/export scan_20260908_120000_abc123`",
                parse_mode="Markdown"
            )
            return

        scan_id = context.args[0].strip()
        scan_record = await self.db.get_scan(scan_id)
        if not scan_record:
            await update.effective_message.reply_text(f"❌ Scan ID `{scan_id}` was not found.")
            return

        status_msg = await update.effective_message.reply_text(
            f"📄 *Compiling Executive Audit Report for `{scan_record.target_domain}`...*",
            parse_mode="Markdown"
        )

        report_path = ExecutiveReportExporter.generate_markdown_report(
            scan_record,
            self.settings.reports_dir
        )

        try:
            with open(report_path, "rb") as f:
                await update.effective_message.reply_document(
                    document=f,
                    filename=report_path.name,
                    caption=f"🛡️ **Executive Security Audit Report**\n• Target: `{scan_record.target_domain}`\n• Audit ID: `{scan_id}`",
                    parse_mode="Markdown"
                )
            await status_msg.delete()
        except Exception as e:
            logger.error(f"Error sending export document: {e}")
            await update.effective_message.reply_text(f"⚠️ Report generated at `{report_path}` but could not be transmitted: {e}")

    async def cmd_bounty(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Generate and export auto-drafted Bug Bounty submission writeups for a scan."""
        if not context.args:
            await update.effective_message.reply_text(
                "ℹ️ **Usage**: `/bounty <scan_id>`\n"
                "Generates submission-ready Markdown vulnerability reports (HackerOne / Bugcrowd format).",
                parse_mode="Markdown"
            )
            return

        scan_id = context.args[0].strip()
        scan_record = await self.db.get_scan(scan_id)
        if not scan_record:
            await update.effective_message.reply_text(f"❌ Scan ID `{scan_id}` was not found.")
            return

        # Prioritize Critical and High findings for bug bounty draft export
        actionable_findings = [f for f in scan_record.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
        if not actionable_findings:
            await update.effective_message.reply_text(
                f"ℹ️ Scan `{scan_id}` has no Medium/High/Critical findings to export for bug bounty submissions."
            )
            return

        status_msg = await update.effective_message.reply_text(
            f"📝 *Drafting {len(actionable_findings)} Bug Bounty Submission Report(s)...*",
            parse_mode="Markdown"
        )

        for f in actionable_findings[:3]:  # Top 3 most urgent
            bounty_path = ExecutiveReportExporter.generate_bug_bounty_draft(
                finding=f,
                target_domain=scan_record.target_domain,
                output_dir=self.settings.reports_dir
            )
            try:
                with open(bounty_path, "rb") as bf:
                    await update.effective_message.reply_document(
                        document=bf,
                        filename=bounty_path.name,
                        caption=f"🎯 **Bug Bounty Submission Draft**\n• Finding: `{f.title}`\n• Severity: **{f.severity.value}**",
                        parse_mode="Markdown"
                    )
            except Exception as doc_err:
                logger.warning(f"Failed to transmit bounty draft: {doc_err}")

        await status_msg.delete()

    async def cmd_schedule(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Enroll a domain in automated periodic health monitoring."""
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id

        if len(context.args) < 2:
            await update.effective_message.reply_text(
                "ℹ️ **Usage**: `/schedule <domain> <daily|weekly>`\nExample: `/schedule example.com daily`",
                parse_mode="Markdown"
            )
            return

        raw_target = context.args[0]
        freq = context.args[1].lower().strip()

        if freq in ("daily", "24h", "24"):
            interval_hours = 24
        elif freq in ("weekly", "168h", "168"):
            interval_hours = 168
        elif freq.isdigit():
            interval_hours = max(1, int(freq))
        else:
            await update.effective_message.reply_text("❌ Frequency must be `daily`, `weekly`, or number of hours.")
            return

        is_allowed, domain_or_err, site = await self.allowlist.check_and_authorize(raw_target, user_id)
        if not is_allowed:
            await update.effective_message.reply_text(domain_or_err, parse_mode="Markdown")
            return

        domain = domain_or_err
        await self.db.add_scheduled_scan(domain, user_id, chat_id, interval_hours)

        # Register or update in Telegram JobQueue if active
        job_name = f"sched_{domain}_{chat_id}"
        if context.application and context.application.job_queue:
            # Remove any existing job
            for j in context.application.job_queue.get_jobs_by_name(job_name):
                j.schedule_removal()

            # Schedule recurring check
            interval_sec = interval_hours * 3600
            context.application.job_queue.run_repeating(
                self._scheduled_job_callback,
                interval=interval_sec,
                first=interval_sec,
                data={"domain": domain, "user_id": user_id, "chat_id": chat_id},
                name=job_name
            )

        interval_label = "daily (every 24h)" if interval_hours == 24 else f"every {interval_hours} hour(s)"
        await update.effective_message.reply_text(
            f"⏰ **Automated Monitoring Scheduled**\n\n"
            f"• **Target**: `{domain}`\n"
            f"• **Frequency**: {interval_label}\n"
            f"• **Notifications**: Dispatched directly to this chat\n\n"
            f"Use `/schedules` to inspect active monitoring jobs.",
            parse_mode="Markdown"
        )

    async def _scheduled_job_callback(self, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Callback fired by PTB JobQueue to execute recurring scan."""
        data = context.job.data
        domain = data["domain"]
        user_id = data["user_id"]
        chat_id = data["chat_id"]

        logger.info(f"Executing scheduled scan for {domain} in chat {chat_id}")
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"⏰ *Running scheduled security check for `{domain}`...*",
            parse_mode="Markdown"
        )
        await self._launch_scan_for_chat(domain, user_id, chat_id, context.bot)

    async def cmd_unschedule(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Remove recurring scan schedule for a domain."""
        chat_id = update.effective_chat.id
        if not context.args:
            await update.effective_message.reply_text("ℹ️ **Usage**: `/unschedule <domain>`")
            return

        domain = normalize_domain(context.args[0])
        removed = await self.db.remove_scheduled_scan(domain, chat_id)

        job_name = f"sched_{domain}_{chat_id}"
        if context.application and context.application.job_queue:
            for j in context.application.job_queue.get_jobs_by_name(job_name):
                j.schedule_removal()

        if removed:
            await update.effective_message.reply_text(f"✅ Recurring schedule removed for `{domain}`.")
        else:
            await update.effective_message.reply_text(f"ℹ️ No active schedule found for `{domain}` in this chat.")

    async def cmd_schedules(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """List all active automated schedules."""
        schedules = await self.db.get_active_scheduled_scans()
        msg = ReportFormatter.format_scheduled_scans_list(schedules)
        await update.effective_message.reply_text(msg, parse_mode="Markdown")

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """List active background scans."""
        jobs = self.orchestrator.get_active_jobs()
        if not jobs:
            await update.effective_message.reply_text("💤 No security checks are currently running.")
            return

        lines = ["🔄 **Active Security Checks**:\n"]
        now = datetime.datetime.now(datetime.timezone.utc)
        for j in jobs:
            elapsed = int((now - j.started_at).total_seconds())
            tools_str = ", ".join(j.active_tools) if j.active_tools else "initializing"
            lines.append(
                f"• `{j.domain}` (`{j.scan_id}`)\n"
                f"  Elapsed: `{elapsed}s` | Tools running: {tools_str}\n"
            )
        await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_history(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """View recent scan history for a target domain."""
        if not context.args:
            await update.effective_message.reply_text("ℹ️ **Usage**: `/history <domain>`")
            return

        domain = normalize_domain(context.args[0])
        history = await self.db.get_domain_history(domain, limit=5)

        if not history:
            await update.effective_message.reply_text(f"ℹ️ No past scans found for domain `{domain}`.")
            return

        lines = [f"📜 **Scan History for `{domain}`**:\n"]
        for record in history:
            summary = record.summary
            crit = summary.get("critical", 0)
            high = summary.get("high", 0)
            med = summary.get("medium", 0)
            low = summary.get("low_info", 0)
            grade = summary.get("grade", "N/A")
            score = summary.get("score", "N/A")

            lines.append(
                f"• `{record.started_at[:16]}` | Grade: **{grade}** ({score}/100)\n"
                f"  ID: `{record.scan_id}`\n"
                f"  🚨 {crit} | ⚠️ {high} | 🔶 {med} | ℹ️ {low}\n"
                f"  _Details_: `/history_detail {record.scan_id}`\n"
            )
        await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_history_detail(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Retrieve full findings for a specific scan."""
        if not context.args:
            await update.effective_message.reply_text("ℹ️ **Usage**: `/history_detail <scan_id>`")
            return

        scan_id = context.args[0].strip()
        record = await self.db.get_scan(scan_id)

        if not record:
            await update.effective_message.reply_text(f"❌ Scan ID `{scan_id}` not found.")
            return

        messages = ReportFormatter.format_scan_summary(record)
        for msg in messages:
            await update.effective_message.reply_text(msg, parse_mode="Markdown")

    async def cmd_addsite(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Add or update an approved site in the allowlist."""
        if len(context.args) < 2:
            await update.effective_message.reply_text(
                "ℹ️ **Usage**: `/addsite <domain> <authorization note/reason>`\n"
                "Example: `/addsite mysite.com Client production security audit`"
            )
            return

        domain = normalize_domain(context.args[0])
        note = " ".join(context.args[1:])
        user_id = update.effective_user.id

        await self.db.add_approved_site(domain=domain, note=note, added_by=user_id)
        await self.db.add_audit_log(
            target_domain=domain,
            user_id=user_id,
            action="ADD_APPROVED_SITE",
            allowed=True,
            reason=f"Added with note: {note}"
        )

        await update.effective_message.reply_text(
            f"✅ **Site Successfully Added to Allowlist**\n\n"
            f"• **Domain**: `{domain}`\n"
            f"• **Authorization Note**: _{note}_\n\n"
            f"You may now trigger checks using: `/check {domain}`",
            parse_mode="Markdown"
        )

    async def cmd_removesite(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Revoke approval for a domain."""
        if not context.args:
            await update.effective_message.reply_text("ℹ️ **Usage**: `/removesite <domain>`")
            return

        domain = normalize_domain(context.args[0])
        user_id = update.effective_user.id

        removed = await self.db.remove_approved_site(domain)
        await self.db.add_audit_log(
            target_domain=domain,
            user_id=user_id,
            action="REMOVE_APPROVED_SITE",
            allowed=True,
            reason="Deactivated by admin"
        )

        if removed:
            await update.effective_message.reply_text(
                f"🗑️ Authorization revoked for `{domain}`. Further scans are now forbidden."
            )
        else:
            await update.effective_message.reply_text(
                f"ℹ️ Domain `{domain}` was not found in active approved sites."
            )

    async def cmd_listsites(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Display all currently approved sites with their latest security score."""
        sites = await self.db.list_approved_sites(active_only=True)
        if not sites:
            await update.effective_message.reply_text(
                "📋 No domains are currently approved for scanning.\n"
                "Use `/addsite <domain> <note>` to authorize your first project."
            )
            return

        site_scores: Dict[str, Tuple[int, str]] = {}
        for s in sites:
            latest = await self.db.get_latest_scan_for_domain(s.domain)
            if latest and latest.summary:
                score = latest.summary.get("score")
                grade = latest.summary.get("grade")
                if score is not None and grade:
                    site_scores[s.domain.lower()] = (score, grade)

        msg = ReportFormatter.format_sites_status_list(sites, site_scores)
        await update.effective_message.reply_text(msg, parse_mode="Markdown")

    async def cmd_audit(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Show recent authorization and scan audit records."""
        logs = await self.db.get_recent_audit_logs(limit=10)
        if not logs:
            await update.effective_message.reply_text("ℹ️ No audit records found.")
            return

        lines = ["🛡️ **Recent Security & Allowlist Audit Trail**:\n"]
        for log in logs:
            status_icon = "🟢 ALLOWED" if log.allowed else "🔴 DENIED"
            lines.append(
                f"• `{log.timestamp[:19]}` | {status_icon}\n"
                f"  Target: `{log.target_domain}` | Action: `{log.action}`\n"
                f"  User: `{log.user_id}` | Reason: _{log.reason}_\n"
            )
        await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_reset_chat(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Reset the active conversation history with Gemini AI assistant."""
        user_id = update.effective_user.id
        if self.gemini_service:
            self.gemini_service.reset_chat(user_id)
        await update.effective_message.reply_text("🔄 AI chat session history has been cleared.")

    async def cmd_natural_chat(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Process conversational natural language messages with the Gemini AI assistant."""
        if not update.effective_message or not update.effective_message.text:
            return

        user_id = update.effective_user.id
        user_text = update.effective_message.text.strip()
        if not user_text:
            return

        # Send typing action to Telegram chat
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id,
            action="typing"
        )

        if not self.gemini_service:
            await update.effective_message.reply_text(
                "🤖 AI Assistant service is not initialized.\n"
                "Use `/help` to see available commands."
            )
            return

        reply_text = await self.gemini_service.chat(user_id, user_text)
        chunks = split_telegram_message(reply_text)
        for chunk in chunks:
            try:
                await update.effective_message.reply_text(chunk, parse_mode="Markdown")
            except Exception:
                # If Telegram fails to parse Markdown, fallback to raw text
                await update.effective_message.reply_text(chunk)
