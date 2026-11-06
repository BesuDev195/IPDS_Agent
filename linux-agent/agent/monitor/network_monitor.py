"""Network Monitor Module.

Coordinates interface traffic rate statistics and TCP connection state tracking.
Ensures strictly passive monitoring without generating network probes or attack traffic.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

from agent.monitor.connection_monitor import ConnectionMonitor, ConnectionStats
from agent.monitor.traffic_statistics import TrafficSnapshot, TrafficStatisticsCalculator
from agent.utils.logger import collection_logger


class NetworkTelemetry(BaseModel):
    """Aggregated network interface traffic and connection telemetry."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    traffic: TrafficSnapshot
    connections: ConnectionStats
    active_interfaces: List[str] = Field(default_factory=list)


class NetworkMonitor:
    """Passively observes host network performance, bandwidth, and socket states."""

    def __init__(self, target_interfaces: Optional[List[str]] = None) -> None:
        self.traffic_calc = TrafficStatisticsCalculator(target_interfaces=target_interfaces)
        self.conn_monitor = ConnectionMonitor()

    def collect(self) -> NetworkTelemetry:
        """Synchronously captures interface traffic and socket connection snapshot."""
        traffic_snap = self.traffic_calc.collect()
        conn_stats = self.conn_monitor.collect()

        active_ifaces = list(traffic_snap.interfaces.keys())

        telemetry = NetworkTelemetry(
            traffic=traffic_snap,
            connections=conn_stats,
            active_interfaces=active_ifaces,
        )

        collection_logger.debug(
            f"Network Monitor: rx={traffic_snap.incoming_bytes_per_sec} B/s, "
            f"rx_pps={traffic_snap.incoming_packets_per_sec} pps, "
            f"active_conns={conn_stats.active_tcp_connections}, "
            f"syn_recv={conn_stats.syn_recv_count}"
        )

        return telemetry

    async def collect_async(self) -> NetworkTelemetry:
        """Asynchronously captures telemetry off the main event loop thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.collect)

