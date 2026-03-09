from __future__ import annotations

"""Runtime configuration models loaded from environment variables."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings validated at startup.

    Attributes:
        anthropic_api_key: API key used by BAML Anthropic provider.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    anthropic_api_key: str = Field(min_length=1)
