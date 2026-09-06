import datetime
import logging
from pathlib import Path
from typing import List, Optional
from telegram import Update
from telegram.ext import ContextTypes

from ..config import Settings
from ..database.db import Database
from ..database.models import ScanRecord
from ..security.allowlist import AllowlistService, normalize_domain
from ..security.auth_filter import restricted_access
from ..core.orchestrator import ScanOrchestrator
from ..core.formatter import ReportFormatter

logger = logging.getLogger(__name__)


class BotHandlers:
    """Telegram command handlers for the Security Health-Check Bot."""

    def __init__(
        self,
        settings: Settings,
        db: Database,
        allowlist: AllowlistService,
        orchestrator: ScanOrchestrator
    ):
        self.settings = settings
        self.db = db
        self.allowlist = allowlist
        self.orchestrator = orchestrator

    def register_handlers(self, application) -> None:
        """Register command handlers with the Telegram application."""
        from telegram.ext import CommandHandler

        guard = restricted_access(self.settings, self.db)

        application.add_handler(CommandHandler(["start", "help"], guard(self.cmd_help)))
        application.add_handler(CommandHandler(["check", "scan"], guard(self.cmd_check)))
        application.add_handler(CommandHandler("status", guard(self.cmd_status)))
        application.add_handler(CommandHandler("history", guard(self.cmd_history)))
        application.add_handler(CommandHandler("history_detail", guard(self.cmd_history_detail)))
        application.add_handler(CommandHandler("addsite", guard(self.cmd_addsite)))
        application.add_handler(CommandHandler("removesite", guard(self.cmd_removesite)))
        application.add_handler(CommandHandler("listsites", guard(self.cmd_listsites)))
        application.add_handler(CommandHandler("audit", guard(self.cmd_audit)))

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Display help and operational manual."""
        user_id = update.effective_user.id
        msg = (
            "🛡️ **Website Security Health-Check Assistant**\n\n"
            "This bot executes defensive security health checks using established open-source tools "
            "(OWASP ZAP, Nuclei, SSL/TLS audit, Nikto, Gitleaks, HaveIBeenPwned).\n\n"
            "⚠️ **Hard Authorization Rule**: Scans are strictly restricted to pre-approved domains.\n\n"
            "📋 **Core Commands**:\n"
            "• `/check <domain>` — Run automated health check on an approved target\n"
            "• `/status` — View currently running background scans\n"
            "• `/history <domain>` — View past scan trends and findings\n"
            "• `/history_detail <scan_id>` — View details or raw log for a scan\n\n"
            "🔐 **Allowlist Management**:\n"
            "• `/addsite <domain> <note>` — Authorize domain with signed justification\n"
            "• `/removesite <domain>` — Revoke authorization for a domain\n"
            "• `/listsites` — Display all approved domains\n"
            "• `/audit` — Review recent authorization & access logs\n\n"
            f"👤 *Authenticated as Telegram User ID: `{user_id}`*"
        )
        await update.effective_message.reply_text(msg, parse_mode="Markdown")

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
        
        # 1. Enforce strict authorization check before touching any scanner
        is_allowed, domain_or_err, site = await self.allowlist.check_and_authorize(raw_target, user_id)
        if not is_allowed:
            await update.effective_message.reply_text(domain_or_err, parse_mode="Markdown")
            return

        domain = domain_or_err

        # Immediate responsive confirmation
        init_msg = await update.effective_message.reply_text(
            f"🔍 **Health Check Initiated for `{domain}`**\n\n"
            f"• **Basis**: _{site.note}_\n"
            f"• **Status**: Scanners launched in background\n"
            f"• **ETA**: ~1 to 3 minutes\n\n"
            f"⚡ *Immediate alerts will be dispatched if Critical issues are discovered.*",
            parse_mode="Markdown"
        )

        # Callbacks for asynchronous updates
        async def alert_callback(alert_text: str):
            try:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=alert_text,
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Failed to deliver critical alert message: {e}")

        async def completion_callback(scan_record: ScanRecord, summary_messages: List[str], raw_file: Optional[Path]):
            try:
                for part in summary_messages:
                    await context.bot.send_message(
                        chat_id=chat_id,
                        text=part,
                        parse_mode="Markdown"
                    )
                
                # If raw log exists and has findings, send document
                if raw_file and raw_file.exists():
                    try:
                        with open(raw_file, "rb") as f:
                            await context.bot.send_document(
                                chat_id=chat_id,
                                document=f,
                                filename=raw_file.name,
                                caption=f"📄 Full raw output for scan `{scan_record.scan_id}`"
                            )
                    except Exception as doc_err:
                        logger.warning(f"Could not upload raw report document: {doc_err}")
            except Exception as e:
                logger.error(f"Failed to deliver completion message: {e}")

        # Launch background scan
        scan_id = await self.orchestrator.start_scan_job(
            domain=domain,
            user_id=user_id,
            alert_callback=alert_callback,
            completion_callback=completion_callback
        )

        logger.info(f"Scan {scan_id} initiated for {domain} by user {user_id}")

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
                f"• **Target**: `{j.domain}`\n"
                f"  Scan ID: `{j.scan_id}`\n"
                f"  Elapsed: `{elapsed}s`\n"
                f"  Active Toolset: `{tools_str}`\n"
            )

        await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_history(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Display past scans for a given target domain."""
        if not context.args:
            await update.effective_message.reply_text("ℹ️ **Usage**: `/history <domain>`")
            return

        domain = normalize_domain(context.args[0])
        history = await self.db.get_domain_history(domain, limit=5)
        if not history:
            await update.effective_message.reply_text(f"ℹ️ No past scan records found for `{domain}`.")
            return

        lines = [f"📜 **Scan History for `{domain}`** (Recent 5):\n"]
        for s in history:
            sum_data = s.summary or {}
            crit = sum_data.get("critical", 0)
            high = sum_data.get("high", 0)
            med = sum_data.get("medium", 0)
            low = sum_data.get("low_info", 0)
            status_emoji = "✅" if s.status.value == "COMPLETED" else "❌"

            lines.append(
                f"{status_emoji} `{s.scan_id}` ({s.started_at[:10]})\n"
                f"  Status: {s.status.value} | Findings: 🚨{crit} ⚠️{high} 🔶{med} ℹ️{low}\n"
                f"  Inspect: `/history_detail {s.scan_id}`\n"
            )

        await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

    async def cmd_history_detail(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Retrieve full details or raw log for a specific scan."""
        if not context.args:
            await update.effective_message.reply_text("ℹ️ **Usage**: `/history_detail <scan_id>`")
            return

        scan_id = context.args[0].strip()
        record = await self.db.get_scan(scan_id)
        if not record:
            await update.effective_message.reply_text(f"❌ Scan ID `{scan_id}` not found.")
            return

        summary_msgs = ReportFormatter.format_scan_summary(record)
        for msg in summary_msgs:
            await update.effective_message.reply_text(msg, parse_mode="Markdown")

        if record.raw_output_path and Path(record.raw_output_path).exists():
            try:
                with open(record.raw_output_path, "rb") as f:
                    await update.effective_message.reply_document(
                        document=f,
                        filename=Path(record.raw_output_path).name,
                        caption=f"📄 Raw scanner dump for `{scan_id}`"
                    )
            except Exception as e:
                logger.warning(f"Failed to attach raw dump: {e}")

    async def cmd_addsite(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Authorize a domain with a descriptive note on authorization basis."""
        if len(context.args) < 2:
            await update.effective_message.reply_text(
                "ℹ️ **Usage**: `/addsite <domain> <authorization note>`\n"
                "Example: `/addsite myblog.org Personal blog project`\n"
                "Example: `/addsite clientcorp.com Client engagement signed 2026-09-01`",
                parse_mode="Markdown"
            )
            return

        domain = normalize_domain(context.args[0])
        note = " ".join(context.args[1:]).strip()
        user_id = update.effective_user.id

        if not domain or "." not in domain:
            await update.effective_message.reply_text("❌ Invalid domain format.")
            return

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
        """Display all currently approved sites."""
        sites = await self.db.list_approved_sites(active_only=True)
        if not sites:
            await update.effective_message.reply_text(
                "📋 No domains are currently approved for scanning.\n"
                "Use `/addsite <domain> <note>` to authorize your first project."
            )
            return

        lines = ["📋 **Pre-Approved Targets Allowlist**:\n"]
        for s in sites:
            lines.append(
                f"• `{s.domain}`\n"
                f"  Note: _{s.note}_\n"
                f"  Added: `{s.created_at[:10]}` by user `{s.added_by}`\n"
            )
        await update.effective_message.reply_text("\n".join(lines), parse_mode="Markdown")

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
