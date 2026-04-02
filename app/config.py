"""Application configuration loaded from environment variables."""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Central configuration for the application."""

    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    APP_DEBUG: bool = os.getenv("APP_DEBUG", "true").lower() == "true"

    # Anthropic
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    AI_MODEL: str = os.getenv("AI_MODEL", "claude-sonnet-4-20250514")
    AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "4096"))

    @property
    def is_api_configured(self) -> bool:
        return bool(self.ANTHROPIC_API_KEY) and self.ANTHROPIC_API_KEY != "your-api-key-here"


settings = Settings()
