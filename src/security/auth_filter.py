import functools
import logging
from typing import Callable, Any
from telegram import Update
from telegram.ext import ContextTypes

from ..config import Settings

logger = logging.getLogger(__name__)


def restricted_access(settings: Settings, db=None) -> Callable:
    """
    Decorator for python-telegram-bot handler callbacks.
    Restricts access strictly to telegram user IDs listed in Settings.allowed_telegram_user_ids.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args: Any, **kwargs: Any) -> Any:
            user = update.effective_user
            user_id = user.id if user else None

            if not settings.is_user_authorized(user_id):
                user_name = user.username if user else "unknown"
                logger.warning(
                    f"Unauthorized access attempt blocked from user_id={user_id} (@{user_name})"
                )
                if db and user_id:
                    try:
                        await db.add_audit_log(
                            target_domain="<bot_access>",
                            user_id=user_id,
                            action="COMMAND_EXECUTION_BLOCKED",
                            allowed=False,
                            reason=f"Unauthorized Telegram user_id: {user_id} (@{user_name})"
                        )
                    except Exception as e:
                        logger.error(f"Failed to record audit log for blocked user: {e}")

                if update.effective_message:
                    await update.effective_message.reply_text(
                        "⛔ **Access Denied**: Your Telegram account is not authorized to interact with this security audit bot."
                    )
                return None

            return await func(update, context, *args, **kwargs)
        return wrapper
    return decorator
