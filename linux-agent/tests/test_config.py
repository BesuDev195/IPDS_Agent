"""Unit tests for configuration loading and validation."""

import os
import pytest
from pydantic import ValidationError

from agent.config import (
    AgentSettings,
    ProtectionMode,
    load_config_from_yaml_string,
    substitute_env_vars,
)


def test_substitute_env_vars():
    os.environ["TEST_SECRET_KEY"] = "super-secret-token"
    template = "api_key: ${TEST_SECRET_KEY}\ninterval: ${TEST_INTERVAL:-15}\nmissing: ${NOT_SET:-fallback}"
    result = substitute_env_vars(template)
    assert "super-secret-token" in result
    assert "15" in result
    assert "fallback" in result


def test_valid_config_loading():
    yaml_content = """
agent:
  id: "srv-999"
  name: "prod-web"
backend:
  url: "https://backend.example.com/api/v1"
  api_key: "agent-api-key-123"
monitoring:
  interval: 5
  ufw_logs: true
protection:
  mode: "monitor"
  automatic_blocking: false
"""
    cfg = load_config_from_yaml_string(yaml_content)
    assert cfg.agent.id == "srv-999"
    assert cfg.backend.url == "https://backend.example.com/api/v1"
    assert cfg.protection.mode == ProtectionMode.MONITOR
    assert cfg.protection.automatic_blocking is False
    assert cfg.monitoring.interval == 5


def test_automatic_blocking_safety_default():
    """Verify safety constraint: automatic blocking is NEVER enabled by default."""
    yaml_content = """
agent:
  id: "srv-001"
backend:
  url: "https://backend.example.com"
  api_key: "key"
protection:
  mode: "automatic"
  automatic_blocking: false
"""
    # If mode is automatic but automatic_blocking was not explicitly set to True,
    # the validator must downgrade to monitor mode to prevent unauthorized blocking.
    cfg = load_config_from_yaml_string(yaml_content)
    assert cfg.protection.mode == ProtectionMode.MONITOR


def test_invalid_url_rejected():
    yaml_content = """
agent:
  id: "srv-001"
backend:
  url: "ftp://invalid-url.com"
  api_key: "key"
"""
    with pytest.raises(ValidationError):
        load_config_from_yaml_string(yaml_content)


def test_api_key_masked_in_repr():
    yaml_content = """
agent:
  id: "srv-001"
backend:
  url: "https://backend.example.com"
  api_key: "my-sensitive-token-987"
"""
    cfg = load_config_from_yaml_string(yaml_content)
    repr_str = repr(cfg.backend)
    assert "my-sensitive-token-987" not in repr_str
    assert "***REDACTED***" in repr_str

