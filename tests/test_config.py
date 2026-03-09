import pytest
from pydantic import ValidationError

from privacyagent.config import Settings


def test_settings_raises_when_missing(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ValidationError, match="anthropic_api_key"):
        Settings(_env_file=None)


def test_settings_reads_required_keys(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "abc123")

    settings = Settings()

    assert settings.anthropic_api_key == "abc123"
