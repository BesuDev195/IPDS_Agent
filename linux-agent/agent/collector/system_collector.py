"""System Host Telemetry Collector.

Collects non-invasive host telemetry including CPU, memory, load average,
disk usage, uptime, and operating system platform metadata.
"""

from __future__ import annotations

import os
import platform
import time
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

import psutil
from agent.utils.logger import collection_logger


class MemoryStats(BaseModel):
    total_bytes: int
    available_bytes: int
    used_bytes: int
    percent: float


class DiskStats(BaseModel):
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent: float


class SystemTelemetry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hostname: str
    os_name: str
    os_version: str
    kernel_release: str
    cpu_count: int
    cpu_usage_percent: float
    load_avg: List[float] = Field(default_factory=list, description="1m, 5m, 15m load averages")
    memory: MemoryStats
    disk: DiskStats
    uptime_seconds: float


class SystemCollector:
    """Collects system host performance and platform information."""

    def __init__(self) -> None:
        self.hostname = platform.node()
        self.os_name = platform.system()
        self.os_version = platform.version()
        self.kernel_release = platform.release()
        self.cpu_count = psutil.cpu_count(logical=True) or 1

    def collect(self) -> SystemTelemetry:
        """Collects current snapshot of system resources."""
        # Non-blocking CPU reading (interval=None uses last sample)
        cpu_percent = psutil.cpu_percent(interval=None)

        # Load average
        try:
            load = list(os.getloadavg())
        except (AttributeError, OSError):
            load = [0.0, 0.0, 0.0]

        # Memory stats
        mem = psutil.virtual_memory()
        mem_stats = MemoryStats(
            total_bytes=mem.total,
            available_bytes=mem.available,
            used_bytes=mem.used,
            percent=mem.percent,
        )

        # Disk stats for root filesystem
        try:
            disk = psutil.disk_usage("/")
            disk_stats = DiskStats(
                total_bytes=disk.total,
                used_bytes=disk.used,
                free_bytes=disk.free,
                percent=disk.percent,
            )
        except Exception:
            disk_stats = DiskStats(total_bytes=0, used_bytes=0, free_bytes=0, percent=0.0)

        # Uptime
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time

        telemetry = SystemTelemetry(
            hostname=self.hostname,
            os_name=self.os_name,
            os_version=self.os_version,
            kernel_release=self.kernel_release,
            cpu_count=self.cpu_count,
            cpu_usage_percent=cpu_percent,
            load_avg=load,
            memory=mem_stats,
            disk=disk_stats,
            uptime_seconds=uptime,
        )

        return telemetry

