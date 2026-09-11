import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from src.config import Settings
from src.agent.gemini_service import GeminiService, split_telegram_message
from src.database.models import ApprovedSite, ScanRecord, ScanStatus


def test_split_telegram_message():
    # Short message
    text = "Hello world"
    assert split_telegram_message(text, max_length=100) == ["Hello world"]

    # Empty message
    assert split_telegram_message("", max_length=100) == [""]

    # Multiline message exceeding limit
    lines = ["Line " + str(i) for i in range(50)]
    long_text = "\n".join(lines)
    chunks = split_telegram_message(long_text, max_length=100)
    assert len(chunks) > 1
    # Check that all content is preserved
    reconstructed = "\n".join(chunks)
    assert reconstructed == long_text


@pytest.mark.asyncio
async def test_gemini_service_unconfigured():
    settings = Settings(gemini_api_key="")
    mock_allowlist = MagicMock()
    mock_orchestrator = MagicMock()
    mock_db = MagicMock()

    service = GeminiService(settings, mock_allowlist, mock_orchestrator, mock_db)
    assert not service.is_configured

    reply = await service.chat(user_id=12345, user_message="Hello, can you check example.com?")
    assert "Gemini AI Assistant is not configured" in reply
    assert "GEMINI_API_KEY" in reply


@pytest.mark.asyncio
async def test_gemini_service_reset_chat():
    settings = Settings(gemini_api_key="mock_key")
    mock_allowlist = MagicMock()
    mock_orchestrator = MagicMock()
    mock_db = MagicMock()

    with patch("google.genai.Client"):
        service = GeminiService(settings, mock_allowlist, mock_orchestrator, mock_db)
        service._chats[12345] = MagicMock()
        assert 12345 in service._chats

        service.reset_chat(12345)
        assert 12345 not in service._chats


@pytest.mark.asyncio
async def test_gemini_service_tools():
    settings = Settings(gemini_api_key="")
    mock_allowlist = MagicMock()
    mock_allowlist.is_authorized = AsyncMock(return_value=(True, "Allowed"))
    mock_orchestrator = MagicMock()
    mock_db = MagicMock()
    
    mock_db.list_approved_sites = AsyncMock(return_value=[
        ApprovedSite(id=1, domain="example.com", note="Testing", added_by=100, created_at="2026-01-01T00:00:00", is_active=True)
    ])
    mock_db.get_scan_history = AsyncMock(return_value=[
        ScanRecord(id=1, scan_id="scan-1", target_domain="example.com", user_id=100, status=ScanStatus.COMPLETED, started_at="2026-01-01T00:00:00", completed_at="2026-01-01T00:01:00", summary={"grade": "A", "score": 95})
    ])

    service = GeminiService(settings, mock_allowlist, mock_orchestrator, mock_db)
    tools = service._build_tools(user_id=100)
    assert len(tools) == 3
    
    list_tool, auth_tool, hist_tool = tools

    # Test list_approved_domains
    res_list = await list_tool()
    assert "example.com" in res_list

    # Test check_domain_authorization
    res_auth = await auth_tool("example.com")
    assert "AUTHORIZED" in res_auth

    # Test get_site_audit_history
    res_hist = await hist_tool("example.com")
    assert "Grade: A" in res_hist
    assert "95/100" in res_hist


@pytest.mark.asyncio
async def test_gemini_service_chat_flow():
    settings = Settings(gemini_api_key="mock_key")
    mock_allowlist = MagicMock()
    mock_orchestrator = MagicMock()
    mock_db = MagicMock()

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_chat = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Here is how to configure Content-Security-Policy..."
        mock_chat.send_message = AsyncMock(return_value=mock_response)
        mock_client.aio.chats.create.return_value = mock_chat

        service = GeminiService(settings, mock_allowlist, mock_orchestrator, mock_db)
        assert service.is_configured

        reply = await service.chat(user_id=999, user_message="How do I fix CSP?")
        assert "Content-Security-Policy" in reply
        mock_chat.send_message.assert_awaited_once_with("How do I fix CSP?")


@pytest.mark.asyncio
async def test_bot_handlers_natural_chat_and_reset():
    from src.bot.handlers import BotHandlers

    settings = Settings(gemini_api_key="mock_key", ALLOWED_TELEGRAM_USER_IDS="123")
    mock_allowlist = MagicMock()
    mock_orchestrator = MagicMock()
    mock_db = MagicMock()
    mock_gemini = MagicMock()
    mock_gemini.chat = AsyncMock(return_value="*Here is a security analysis*")

    handlers = BotHandlers(settings, mock_db, mock_allowlist, mock_orchestrator, mock_gemini)

    update = MagicMock()
    update.effective_user.id = 123
    update.effective_chat.id = 456
    update.effective_message.text = "Tell me about DMARC"
    update.effective_message.reply_text = AsyncMock()

    context = MagicMock()
    context.bot.send_chat_action = AsyncMock()

    # Test cmd_natural_chat
    await handlers.cmd_natural_chat(update, context)
    context.bot.send_chat_action.assert_awaited_once_with(chat_id=456, action="typing")
    mock_gemini.chat.assert_awaited_once_with(123, "Tell me about DMARC")
    update.effective_message.reply_text.assert_awaited()

    # Test cmd_reset_chat
    await handlers.cmd_reset_chat(update, context)
    mock_gemini.reset_chat.assert_called_once_with(123)
