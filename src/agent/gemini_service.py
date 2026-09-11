import logging
from typing import Dict, List, Optional, Any
from ..config import Settings
from ..database.db import Database
from ..security.allowlist import AllowlistService, normalize_domain
from ..core.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

SYSTEM_INSTRUCTION = """You are an expert Cybersecurity & Defensive Audit Assistant integrated directly into the Website Security Health-Check Telegram Bot.

Your primary mission:
1. Provide authoritative, concise, and practical defensive cybersecurity guidance.
2. Explain web security mechanisms:
   - SSL/TLS protocols, certificate expirations, cipher suites, forward secrecy.
   - HTTP Security Headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   - DNS email defense: SPF, DMARC policies, DKIM, CAA records.
   - Vulnerabilities discovered by scanners (Nuclei, Nikto, OWASP ZAP, Gitleaks, HIBP).
3. Offer concrete remediation configs (e.g. Nginx, Apache, Cloudflare, DNS records) when asked how to fix issues.
4. Use your tools to check domain authorization, fetch site history, and initiate scans when the user requests a security check for a domain.

Important Rules:
- STRICT AUTHORIZATION: Scans are only conducted on authorized domains pre-approved in the allowlist.
- CREATOR: You were created and developed by TARUN. When asked who created you or who made this bot, proudly state you were created by TARUN.
- Format responses clearly using Telegram-compatible Markdown (e.g. `code`, **bold**, bullet points).
- Keep explanations punchy and practical.
"""


def split_telegram_message(text: str, max_length: int = 4000) -> List[str]:
    """Split a long message into chunks that respect Telegram's 4096-character limit."""
    if not text or len(text) <= max_length:
        return [text] if text else [""]

    chunks = []
    lines = text.split("\n")
    current_chunk: List[str] = []
    current_length = 0

    for line in lines:
        line_len = len(line) + 1  # include newline
        if current_length + line_len > max_length:
            if current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = [line]
                current_length = line_len
            else:
                # Single line exceeds max_length, force split
                for i in range(0, len(line), max_length):
                    chunks.append(line[i : i + max_length])
                current_chunk = []
                current_length = 0
        else:
            current_chunk.append(line)
            current_length += line_len

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks


class GeminiService:
    """Conversational AI Assistant service powered by Google Gemini."""

    def __init__(
        self,
        settings: Settings,
        allowlist: AllowlistService,
        orchestrator: ScanOrchestrator,
        db: Database,
    ):
        self.settings = settings
        self.allowlist = allowlist
        self.orchestrator = orchestrator
        self.db = db
        self.client = None
        self._chats: Dict[int, Any] = {}

        if settings.gemini_api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=settings.gemini_api_key)
                logger.info(
                    f"Gemini AI Assistant initialized with model '{settings.gemini_model}'"
                )
            except Exception as e:
                logger.error(f"Failed to initialize Gemini Client: {e}")
                self.client = None
        else:
            logger.warning(
                "GEMINI_API_KEY is not configured. Conversational AI chat will be in advisory fallback mode."
            )

    @property
    def is_configured(self) -> bool:
        """Return whether Gemini API client is available."""
        return self.client is not None

    def reset_chat(self, user_id: int) -> None:
        """Clear conversation history for a given user."""
        if user_id in self._chats:
            del self._chats[user_id]

    def _build_tools(self, user_id: int):
        """Build callable tools/functions that Gemini can invoke."""

        async def list_approved_domains() -> str:
            """Retrieve the list of authorized domains in the allowlist."""
            sites = await self.db.list_approved_sites(active_only=True)
            if not sites:
                return "No domains are currently approved in the allowlist."
            domains = [s.domain for s in sites]
            return f"Approved domains ({len(domains)}): " + ", ".join(domains)

        async def check_domain_authorization(domain: str) -> str:
            """Check if a domain is approved for security scanning. domain should be a clean hostname like example.com."""
            norm = normalize_domain(domain)
            is_auth, reason = await self.allowlist.is_authorized(norm, user_id)
            if is_auth:
                return f"Domain '{norm}' is AUTHORIZED for security scanning."
            return f"Domain '{norm}' is NOT authorized: {reason}. To add it, use /addsite {norm} <reason>."

        async def get_site_audit_history(domain: str) -> str:
            """Retrieve past security scan scores and grades for a domain."""
            norm = normalize_domain(domain)
            history = await self.db.get_scan_history(norm, limit=5)
            if not history:
                return f"No scan history found for domain '{norm}'."
            summary = []
            for h in history:
                score = h.summary.get("score", "N/A") if h.summary else "N/A"
                grade = h.summary.get("grade", "N/A") if h.summary else "N/A"
                summary.append(f"- Date: {h.started_at[:19]}, Status: {h.status}, Grade: {grade}, Score: {score}/100")
            return f"Scan history for {norm}:\n" + "\n".join(summary)

        return [list_approved_domains, check_domain_authorization, get_site_audit_history]

    async def _get_or_create_chat(self, user_id: int):
        """Get existing chat session or create a new AsyncChat instance."""
        if user_id in self._chats:
            return self._chats[user_id]

        from google.genai import types

        tools = self._build_tools(user_id)
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            temperature=0.7,
            tools=tools,
        )

        chat = self.client.aio.chats.create(
            model=self.settings.gemini_model,
            config=config,
        )
        self._chats[user_id] = chat
        return chat

    async def chat(self, user_id: int, user_message: str) -> str:
        """Send message to Gemini assistant and return the model's text response."""
        if not self.is_configured:
            return (
                "🤖 **Gemini AI Assistant is not configured yet.**\n\n"
                "To enable conversational intelligence, add your Gemini API Key in your `.env` file:\n"
                "```env\n"
                "GEMINI_API_KEY=your_gemini_api_key\n"
                "GEMINI_MODEL=gemini-3.5-flash\n"
                "```\n"
                "You can still use all regular slash commands like `/help`, `/check <domain>`, `/status`, and `/listsites`!"
            )

        try:
            chat = await self._get_or_create_chat(user_id)
            response = await chat.send_message(user_message)

            if response and response.text:
                return response.text.strip()
            return "I received your message, but I didn't generate any text response. Please try rephrasing."

        except Exception as e:
            logger.error(f"Error during Gemini chat generation for user {user_id}: {e}", exc_info=True)
            # If session is corrupted, reset it
            self.reset_chat(user_id)
            return (
                f"⚠️ **Gemini Assistant encountered an error**:\n"
                f"`{str(e)}`\n\n"
                "_Chat session has been reset. Please try again._"
            )
