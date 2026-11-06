"""Unit tests for logger and secret masking."""

import json
import logging
from agent.utils.logger import (
    JSONLogFormatter,
    SecretMaskingFilter,
    register_secret,
    sanitize_text,
    setup_logging,
)


def test_sanitize_text_registered_secret():
    secret_token = "my-ultra-secret-agent-key-99"
    register_secret(secret_token)
    msg = f"Connecting with token: {secret_token} to backend"
    sanitized = sanitize_text(msg)
    assert secret_token not in sanitized
    assert "[REDACTED]" in sanitized


def test_sanitize_text_patterns():
    test_cases = [
        "Authorization: Bearer my-secret-jwt-token-abcdef",
        "api_key: secret123456789",
        "password: supersecretpassword",
        "Connecting with token=supersecrettoken",
    ]
    for case in test_cases:
        sanitized = sanitize_text(case)
        assert "[REDACTED]" in sanitized
        assert "secret123456789" not in sanitized
        assert "supersecretpassword" not in sanitized


def test_secret_masking_filter():
    filt = SecretMaskingFilter()
    secret = "classified-api-key-xyz"
    register_secret(secret)

    record = logging.LogRecord(
        name="agent.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Using secret: %s",
        args=(secret,),
        exc_info=None,
    )
    filt.filter(record)
    assert secret not in record.args[0]
    assert "[REDACTED]" in record.args[0]


def test_json_formatter():
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="agent.firewall",
        level=logging.WARNING,
        pathname="firewall.py",
        lineno=42,
        msg="Firewall block attempted for 198.51.100.5",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    data = json.loads(formatted)
    assert data["level"] == "WARNING"
    assert data["logger"] == "agent.firewall"
    assert "198.51.100.5" in data["message"]
    assert "timestamp" in data

