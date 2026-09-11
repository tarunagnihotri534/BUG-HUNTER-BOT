import asyncio
import logging
import sys
from pathlib import Path
from telegram.ext import ApplicationBuilder
from telegram.request import HTTPXRequest

from ..config import get_settings
from ..database.db import Database
from ..security.allowlist import AllowlistService
from ..core.orchestrator import ScanOrchestrator
from ..agent.gemini_service import GeminiService
from .handlers import BotHandlers

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("security_bot")


async def async_init_and_run() -> None:
    settings = get_settings()

    if not settings.telegram_bot_token:
        logger.error(
            "CRITICAL: TELEGRAM_BOT_TOKEN is not configured!\n"
            "Please create a .env file from .env.example and specify your token from @BotFather."
        )
        sys.exit(1)

    if not settings.allowed_telegram_user_ids:
        logger.warning(
            "WARNING: ALLOWED_TELEGRAM_USER_IDS is empty! No users will be authorized to run commands.\n"
            "Please set your numeric Telegram User ID in .env (obtain via @userinfobot)."
        )

    # Initialize persistence
    db = Database(settings.db_path)
    await db.init_db()
    logger.info(f"Database initialized at {settings.db_path}")

    # Initialize services
    allowlist_svc = AllowlistService(db)
    orchestrator = ScanOrchestrator(settings, db)
    gemini_svc = GeminiService(settings, allowlist_svc, orchestrator, db)
    handlers = BotHandlers(settings, db, allowlist_svc, orchestrator, gemini_svc)

    # Build Telegram Application with resilient timeouts
    trequest = HTTPXRequest(
        connect_timeout=30.0,
        read_timeout=30.0,
        write_timeout=30.0,
        pool_timeout=30.0,
    )
    app = ApplicationBuilder().token(settings.telegram_bot_token).request(trequest).build()
    handlers.register_handlers(app)

    logger.info("Security Health-Check Telegram Bot started. Listening for commands...")
    await app.initialize()
    await app.start()

    # Restore active scheduled scans from database
    active_schedules = await db.get_active_scheduled_scans()
    if app.job_queue:
        for sched in active_schedules:
            job_name = f"sched_{sched.domain}_{sched.chat_id}"
            interval_sec = sched.interval_hours * 3600
            app.job_queue.run_repeating(
                handlers._scheduled_job_callback,
                interval=interval_sec,
                first=interval_sec,
                data={"domain": sched.domain, "user_id": sched.user_id, "chat_id": sched.chat_id},
                name=job_name
            )
        logger.info(f"Loaded {len(active_schedules)} automated monitoring schedule(s).")

    await app.updater.start_polling()

    # Keep running until interrupted
    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutdown signal received...")
    finally:
        logger.info("Stopping bot updater and application...")
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        logger.info("Bot cleanly shut down.")


def main() -> None:
    """Entry point for launching the bot."""
    try:
        asyncio.run(async_init_and_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
