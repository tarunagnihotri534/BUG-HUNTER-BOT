import pytest
from unittest.mock import AsyncMock, MagicMock
from src.config import Settings
from src.security.auth_filter import restricted_access
from src.database.db import Database


def test_settings_user_authorization():
    settings = Settings(
        TELEGRAM_BOT_TOKEN="fake_token",
        ALLOWED_TELEGRAM_USER_IDS="11111,22222"
    )
    assert settings.is_user_authorized(11111) is True
    assert settings.is_user_authorized(22222) is True
    assert settings.is_user_authorized(99999) is False
    assert settings.is_user_authorized(None) is False


@pytest.mark.asyncio
async def test_restricted_access_decorator_blocks_unauthorized(tmp_path):
    settings = Settings(
        TELEGRAM_BOT_TOKEN="fake_token",
        ALLOWED_TELEGRAM_USER_IDS="100"
    )
    db = Database(tmp_path / "auth_test.db")
    await db.init_db()

    dummy_handler = AsyncMock()
    decorated = restricted_access(settings, db)(dummy_handler)

    # Mock an unauthorized update
    unauth_update = MagicMock()
    unauth_update.effective_user.id = 999
    unauth_update.effective_user.username = "intruder"
    unauth_update.effective_message.reply_text = AsyncMock()

    context = MagicMock()

    # Call decorated handler
    result = await decorated(unauth_update, context)

    # Assert wrapped handler was NOT executed
    dummy_handler.assert_not_called()
    unauth_update.effective_message.reply_text.assert_called_once()
    assert "Access Denied" in unauth_update.effective_message.reply_text.call_args[0][0]

    # Check audit log contains blocked attempt
    logs = await db.get_recent_audit_logs()
    assert len(logs) == 1
    assert logs[0].action == "COMMAND_EXECUTION_BLOCKED"
    assert logs[0].allowed is False


@pytest.mark.asyncio
async def test_restricted_access_decorator_allows_authorized(tmp_path):
    settings = Settings(
        TELEGRAM_BOT_TOKEN="fake_token",
        ALLOWED_TELEGRAM_USER_IDS="100"
    )
    dummy_handler = AsyncMock(return_value="executed_ok")
    decorated = restricted_access(settings)(dummy_handler)

    auth_update = MagicMock()
    auth_update.effective_user.id = 100
    auth_update.effective_user.username = "owner"

    context = MagicMock()
    result = await decorated(auth_update, context)

    assert result == "executed_ok"
    dummy_handler.assert_called_once_with(auth_update, context)
