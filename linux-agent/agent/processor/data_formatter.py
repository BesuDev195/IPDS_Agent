"""Data Formatter Module.

Encapsulates telemetry payloads, action reports, and heartbeat packets
into structured, schema-validated JSON representations for API transmission.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


AGENT_VERSION = "1.0.0"


class TelemetryPayload(BaseModel):
    """Payload sent to POST /api/v1/agent/telemetry."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    features: Any = Field(..., description="Extracted ML model features (dict or list)")
    raw_metrics: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional detailed metrics breakdown (system, network, UFW)",
    )
    client_version: str = AGENT_VERSION


class ActionReportPayload(BaseModel):
    """Payload sent to POST /api/v1/agent/actions/report."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    decision_id: str
    action: str = Field(..., description="Action taken, e.g. block_ip, unblock_ip")
    source_ip: str
    status: str = Field(..., description="Execution outcome: success, failed, skipped")
    execution_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: Optional[str] = None
    duration: Optional[int] = None
    error_message: Optional[str] = None
    client_version: str = AGENT_VERSION


class HeartbeatPayload(BaseModel):
    """Payload sent to POST /api/v1/agent/heartbeat."""

    agent_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str
    os_name: str
    agent_version: str = AGENT_VERSION
    ufw_status: str = "active"
    monitoring_status: str = "active"
    protection_mode: str = "monitor"
    last_successful_telemetry: Optional[str] = None
    agent_health: str = "healthy"
    details: Optional[Dict[str, Any]] = None


def format_telemetry(
    agent_id: str,
    features: Any,
    raw_metrics: Optional[Dict[str, Any]] = None,
    event_id: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> TelemetryPayload:
    """Creates a validated TelemetryPayload ready for JSON serialization."""
    return TelemetryPayload(
        event_id=event_id or str(uuid.uuid4()),
        agent_id=agent_id,
        timestamp=timestamp or datetime.now(timezone.utc),
        features=features,
        raw_metrics=raw_metrics,
        client_version=AGENT_VERSION,
    )

