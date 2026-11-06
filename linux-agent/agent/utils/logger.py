"""Structured logging and secret masking for Linux Security Agent.

Provides categorized logging (collection, communication, AI detection,
firewall, authentication, lifecycle) and guarantees that passwords,
tokens, and API secrets are never exposed in log output.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Known secrets registered at runtime (e.g. backend api_key)
_REGISTERED_SECRETS: Set[str] = set()

# Sensitive parameter patterns (case-insensitive)
_SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|bearer|token|password|secret|authorization)\s*[:=]\s*['\"]?([^\s'\",&]+)['\"]?"),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{12,})"),
    re.compile(r"(?i)('api_key'|\"api_key\")\s*:\s*('|\")([^'\"]+)('|\")"),
]


def register_secret(secret: str | None) -> None:
    """Registers a sensitive string to be masked in all log outputs."""
    if secret and len(secret.strip()) >= 3:
        _REGISTERED_SECRETS.add(secret.strip())


def sanitize_text(message: str) -> str:
    """Masks secrets and sensitive keywords from a string."""
    if not isinstance(message, str):
        message = str(message)

    # 1. Mask explicitly registered secrets
    for s in _REGISTERED_SECRETS:
        if s and s in message:
            message = message.replace(s, "[REDACTED]")

    # 2. Mask pattern-based credentials
    for pattern in _SENSITIVE_PATTERNS:
        message = pattern.sub(r"\1: [REDACTED]", message)

    return message


class SecretMaskingFilter(logging.Filter):
    """Logging filter that ensures no secrets or tokens leak into log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_text(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(sanitize_text(a) if isinstance(a, str) else a for a in record.args)
        return True


class JSONLogFormatter(logging.Formatter):
    """Structured JSON formatter with ISO-8601 timestamps and sanitized messages."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize_text(record.getMessage()),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = sanitize_text(self.formatException(record.exc_info))
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)
        return json.dumps(log_entry)


class StandardLogFormatter(logging.Formatter):
    """Human-readable formatter with clean timestamp and category indicators."""

    def format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        return sanitize_text(s)


def get_logger(name: str) -> logging.Logger:
    """Returns a logger attached to the agent hierarchy."""
    return logging.getLogger(name)


# Specialized loggers for distinct operational records
collection_logger = get_logger("agent.collection")
communication_logger = get_logger("agent.communication")
ai_detection_logger = get_logger("agent.ai_detection")
firewall_logger = get_logger("agent.firewall")
auth_logger = get_logger("agent.auth")
lifecycle_logger = get_logger("agent.lifecycle")


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    console_output: bool = True,
    api_key_to_mask: Optional[str] = None,
) -> None:
    """Initializes logging infrastructure with filters and handlers."""
    if api_key_to_mask:
        register_secret(api_key_to_mask)

    root_logger = logging.getLogger("agent")
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers on re-configuration
    root_logger.handlers.clear()

    masking_filter = SecretMaskingFilter()

    formatter: logging.Formatter
    if json_format:
        formatter = JSONLogFormatter()
    else:
        fmt = "%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
        formatter = StandardLogFormatter(fmt=fmt, datefmt="%Y-%m-%d %H:%M:%S")

    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(masking_filter)
        root_logger.addHandler(console_handler)

    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.addFilter(masking_filter)
            root_logger.addHandler(file_handler)
        except (PermissionError, OSError) as e:
            # Degrade gracefully to console if log file directory is not writable
            root_logger.warning(
                f"Could not open log file '{log_file}': {e}. Logging will continue to console."
            )

