import os
from pathlib import Path
from typing import Set, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables or .env file."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Telegram configuration
    telegram_bot_token: str = Field(default="", alias="TELEGRAM_BOT_TOKEN")
    allowed_telegram_user_ids: Set[int] = Field(default_factory=set, alias="ALLOWED_TELEGRAM_USER_IDS")

    # Local persistence paths
    db_path: Path = Field(default=Path("data/security_bot.db"), alias="DB_PATH")
    raw_output_dir: Path = Field(default=Path("data/scans"), alias="RAW_OUTPUT_DIR")
    reports_dir: Path = Field(default=Path("data/reports"), alias="REPORTS_DIR")

    # Scanner configurations
    zap_base_url: str = Field(default="http://localhost:8080", alias="ZAP_BASE_URL")
    zap_api_key: str = Field(default="", alias="ZAP_API_KEY")

    nuclei_bin: str = Field(default="", alias="NUCLEI_BIN")
    nikto_bin: str = Field(default="", alias="NIKTO_BIN")
    gitleaks_bin: str = Field(default="", alias="GITLEAKS_BIN")
    sslyze_bin: str = Field(default="", alias="SSLYZE_BIN")

    hibp_api_key: str = Field(default="", alias="HIBP_API_KEY")
    max_concurrent_scans: int = Field(default=2, alias="MAX_CONCURRENT_SCANS")

    # Gemini AI Assistant configuration
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-2.5-pro", alias="GEMINI_MODEL")

    @field_validator("allowed_telegram_user_ids", mode="before")
    @classmethod
    def parse_user_ids(cls, v):
        if not v:
            return set()
        if isinstance(v, set):
            return v
        if isinstance(v, (int, float)):
            return {int(v)}
        if isinstance(v, (list, tuple)):
            return {int(x) for x in v if str(x).strip().isdigit()}
        if isinstance(v, str):
            ids = set()
            for part in v.split(","):
                part = part.strip()
                if part.isdigit():
                    ids.add(int(part))
            return ids
        return set()

    def is_user_authorized(self, user_id: int | None) -> bool:
        """Check if given Telegram user ID is authorized."""
        if user_id is None:
            return False
        return user_id in self.allowed_telegram_user_ids


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
