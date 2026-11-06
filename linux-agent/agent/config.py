"""Configuration module for Linux Security Agent.

Validates application settings using Pydantic and loads from YAML files
with support for environment variable substitution.
"""

from __future__ import annotations

import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class ProtectionMode(str, Enum):
    MONITOR = "monitor"
    MANUAL = "manual"
    AUTOMATIC = "automatic"


class AgentConfig(BaseModel):
    id: str = Field(..., description="Unique identifier for this agent", min_length=1)
    name: str = Field("linux-security-agent", description="Human-readable server name")


class BackendEndpoints(BaseModel):
    telemetry: str = "/api/v1/agent/telemetry"
    decisions: str = "/api/v1/agent/decisions"
    actions_report: str = "/api/v1/agent/actions/report"
    heartbeat: str = "/api/v1/agent/heartbeat"


class BackendConfig(BaseModel):
    url: str = Field(..., description="Base URL of central FastAPI backend")
    api_key: str = Field(..., description="Authentication token/key for the agent", min_length=1)
    endpoints: BackendEndpoints = Field(default_factory=BackendEndpoints)
    timeout_seconds: float = Field(10.0, ge=1.0, le=120.0)
    max_retries: int = Field(3, ge=0, le=10)
    backoff_factor: float = Field(1.5, ge=1.0, le=10.0)
    verify_ssl: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        clean_url = v.strip().rstrip("/")
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            raise ValueError("Backend URL must start with http:// or https://")
        return clean_url

    def __repr__(self) -> str:
        return f"BackendConfig(url='{self.url}', api_key='***REDACTED***', endpoints={self.endpoints})"


class MonitoringConfig(BaseModel):
    ufw_logs: bool = True
    network_monitoring: bool = True
    interval: int = Field(10, ge=1, le=3600, description="Collection interval in seconds")
    ufw_log_paths: List[str] = Field(
        default_factory=lambda: [
            "/var/log/ufw.log",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/kern.log",
        ]
    )
    use_journalctl: bool = True
    interfaces: List[str] = Field(
        default_factory=list,
        description="Specific interfaces to monitor. Empty list monitors all non-loopback interfaces",
    )


class ProtectionConfig(BaseModel):
    mode: ProtectionMode = Field(
        default=ProtectionMode.MONITOR,
        description="Protection mode: monitor, manual, or automatic",
    )
    automatic_blocking: bool = Field(
        default=False,
        description="Allow automatic firewall rule application (defaults to false for safety)",
    )
    block_duration: int = Field(
        600,
        ge=10,
        le=86400 * 30,
        description="Default duration of temporary block in seconds",
    )
    max_block_duration: int = Field(
        86400,
        ge=60,
        le=86400 * 365,
        description="Maximum permissible block duration",
    )
    min_confidence: float = Field(
        0.80,
        ge=0.0,
        le=1.0,
        description="Minimum AI confidence required to act on a decision",
    )
    trusted_ips: List[str] = Field(
        default_factory=lambda: [
            "127.0.0.1",
            "::1",
        ],
        description="IPs or subnets that must never be blocked",
    )
    management_ports: List[int] = Field(
        default_factory=lambda: [22],
        description="Management ports that must remain accessible",
    )
    allow_private_ip_blocking: bool = Field(
        default=False,
        description="Allow blocking RFC 1918 / private addresses (default false to prevent self-lockout)",
    )

    @model_validator(mode="after")
    def safety_checks(self) -> ProtectionConfig:
        # Enforce rule: never enable automatic blocking by default
        # If mode is automatic, automatic_blocking must be explicitly True
        if self.mode == ProtectionMode.AUTOMATIC and not self.automatic_blocking:
            # Fallback to monitor mode safely
            self.mode = ProtectionMode.MONITOR
        if self.block_duration > self.max_block_duration:
            self.block_duration = self.max_block_duration
        return self


class StorageConfig(BaseModel):
    database_path: str = "/var/lib/ai-ids-agent/agent.db"
    max_pending_telemetry: int = Field(10000, ge=100)
    max_audit_records: int = Field(50000, ge=100)


class LoggingConfig(BaseModel):
    level: str = Field("INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_file: Optional[str] = "/var/log/ai-ids-agent/agent.log"
    json_format: bool = False
    console_output: bool = True


class AgentSettings(BaseModel):
    agent: AgentConfig
    backend: BackendConfig
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    protection: ProtectionConfig = Field(default_factory=ProtectionConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-(.*?))?\}")


def substitute_env_vars(text: str) -> str:
    """Substitutes environment variables in a configuration string.

    Supports ${VAR_NAME} and ${VAR_NAME:-default_value}.
    """
    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        default_val = match.group(2)
        return os.environ.get(var_name, default_val if default_val is not None else "")

    return _ENV_PATTERN.sub(_replace, text)


def load_config_from_yaml_string(yaml_str: str) -> AgentSettings:
    """Loads and validates configuration from a YAML string with env substitution."""
    import yaml

    substituted = substitute_env_vars(yaml_str)
    raw_dict = yaml.safe_load(substituted)
    if not isinstance(raw_dict, dict):
        raise ValueError("Invalid YAML configuration: root must be a mapping")
    return AgentSettings.model_validate(raw_dict)


def load_config(config_path: str | Path | None = None) -> AgentSettings:
    """Loads configuration from file path or default search locations."""
    import yaml

    search_paths = []
    if config_path:
        search_paths.append(Path(config_path))
    else:
        env_path = os.environ.get("AGENT_CONFIG_FILE")
        if env_path:
            search_paths.append(Path(env_path))
        search_paths.extend([
            Path("config/config.yaml"),
            Path("linux-agent/config/config.yaml"),
            Path("/etc/ai-ids-agent/config.yaml"),
            Path("config/config.example.yaml"),
            Path("linux-agent/config/config.example.yaml"),
        ])

    for p in search_paths:
        if p.exists() and p.is_file():
            content = p.read_text(encoding="utf-8")
            return load_config_from_yaml_string(content)

    raise FileNotFoundError(
        f"No valid configuration file found. Checked: {[str(p) for p in search_paths]}"
    )

