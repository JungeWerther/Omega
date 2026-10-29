"""Configuration logging must not print credentials."""

import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import config  # noqa: E402


def test_secret_like_keys_are_masked_in_logs(monkeypatch, caplog):
    monkeypatch.setattr(config, "_COMMAND_LINE", {
        "WS_TOKEN": "ws-secret", "SL_BOT_TOKEN": "xoxb-secret", "IRC_channel": "#public",
    })
    monkeypatch.setattr(config, "_CONFIG", {})
    monkeypatch.setattr(config, "_CONFIG_FILE", {})
    monkeypatch.setenv("OMEGA_OPENAI_API_KEY", "sk-secret")

    with caplog.at_level(logging.INFO, logger="config"):
        assert config.config_get_by_key("WS_TOKEN") == "ws-secret"
        assert config.config_get_by_key("SL_BOT_TOKEN") == "xoxb-secret"
        assert config.config_get_by_key("OPENAI_API_KEY") == "sk-secret"
        assert config.config_get_by_key("IRC_channel") == "#public"

    for secret in ("ws-secret", "xoxb-secret", "sk-secret"):
        assert secret not in caplog.text
    assert "WS_TOKEN=***" in caplog.text
    assert "IRC_channel=#public" in caplog.text
