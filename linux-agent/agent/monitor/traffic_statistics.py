"""Traffic Statistics Calculator.

Reads interface-level counters from /proc/net/dev (or psutil) and computes
incoming/outgoing bytes per second and packets per second over measurement windows.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

import psutil
from agent.utils.logger import collection_logger


class InterfaceTraffic(BaseModel):
    name: str
    bytes_recv: int = 0
    bytes_sent: int = 0
    packets_recv: int = 0
    packets_sent: int = 0
    err_in: int = 0
    err_out: int = 0
    drop_in: int = 0
    drop_out: int = 0
    rx_bytes_per_sec: float = 0.0
    tx_bytes_per_sec: float = 0.0
    rx_packets_per_sec: float = 0.0
    tx_packets_per_sec: float = 0.0


class TrafficSnapshot(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    measurement_window_seconds: float = 0.0
    incoming_bytes_per_sec: float = 0.0
    outgoing_bytes_per_sec: float = 0.0
    incoming_packets_per_sec: float = 0.0
    outgoing_packets_per_sec: float = 0.0
    total_bytes_recv: int = 0
    total_bytes_sent: int = 0
    total_packets_recv: int = 0
    total_packets_sent: int = 0
    total_drop_in: int = 0
    interfaces: Dict[str, InterfaceTraffic] = Field(default_factory=dict)


class TrafficStatisticsCalculator:
    """Calculates network rate statistics by comparing consecutive counter snapshots."""

    def __init__(self, target_interfaces: Optional[List[str]] = None) -> None:
        self.target_interfaces = set(target_interfaces) if target_interfaces else set()
        self._last_sample_time: Optional[float] = None
        self._last_counters: Dict[str, Dict[str, int]] = {}

    def _read_proc_net_dev(self) -> Dict[str, Dict[str, int]]:
        """Directly parses /proc/net/dev for optimal speed and reliability on Linux."""
        proc_file = Path("/proc/net/dev")
        if not proc_file.exists():
            return self._read_psutil_counters()

        counters: Dict[str, Dict[str, int]] = {}
        try:
            content = proc_file.read_text(encoding="utf-8")
            lines = content.splitlines()
            for line in lines[2:]:  # Skip the two header lines
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface_name = iface.strip()
                tokens = data.split()
                if len(tokens) >= 16:
                    counters[iface_name] = {
                        "bytes_recv": int(tokens[0]),
                        "packets_recv": int(tokens[1]),
                        "err_in": int(tokens[2]),
                        "drop_in": int(tokens[3]),
                        "bytes_sent": int(tokens[8]),
                        "packets_sent": int(tokens[9]),
                        "err_out": int(tokens[10]),
                        "drop_out": int(tokens[11]),
                    }
            return counters
        except Exception as e:
            collection_logger.debug(f"Failed parsing /proc/net/dev: {e}. Falling back to psutil.")
            return self._read_psutil_counters()

    def _read_psutil_counters(self) -> Dict[str, Dict[str, int]]:
        """Fallback counter reader using psutil.net_io_counters."""
        counters: Dict[str, Dict[str, int]] = {}
        try:
            io_dict = psutil.net_io_counters(pernic=True)
            for iface, stat in io_dict.items():
                counters[iface] = {
                    "bytes_recv": stat.bytes_recv,
                    "packets_recv": stat.packets_recv,
                    "err_in": stat.errin,
                    "drop_in": stat.dropin,
                    "bytes_sent": stat.bytes_sent,
                    "packets_sent": stat.packets_sent,
                    "err_out": stat.errout,
                    "drop_out": stat.dropout,
                }
        except Exception as e:
            collection_logger.warning(f"Error reading network counters: {e}")
        return counters

    def collect(self) -> TrafficSnapshot:
        """Computes rate snapshot comparing current state to previous sample."""
        now = time.time()
        current_counters = self._read_proc_net_dev()

        time_delta = 0.0
        if self._last_sample_time is not None:
            time_delta = max(0.001, now - self._last_sample_time)

        interfaces_dict: Dict[str, InterfaceTraffic] = {}

        total_rx_bytes = 0
        total_tx_bytes = 0
        total_rx_packets = 0
        total_tx_packets = 0
        total_drop_in = 0

        rx_bytes_sec_agg = 0.0
        tx_bytes_sec_agg = 0.0
        rx_pkts_sec_agg = 0.0
        tx_pkts_sec_agg = 0.0

        for iface_name, curr in current_counters.items():
            # If target interfaces are configured, only monitor those
            if self.target_interfaces and iface_name not in self.target_interfaces:
                continue

            rx_b_sec = 0.0
            tx_b_sec = 0.0
            rx_p_sec = 0.0
            tx_p_sec = 0.0

            if time_delta > 0 and iface_name in self._last_counters:
                prev = self._last_counters[iface_name]
                # Safeguard against counter rollover or interface reset
                if curr["bytes_recv"] >= prev["bytes_recv"]:
                    rx_b_sec = (curr["bytes_recv"] - prev["bytes_recv"]) / time_delta
                if curr["bytes_sent"] >= prev["bytes_sent"]:
                    tx_b_sec = (curr["bytes_sent"] - prev["bytes_sent"]) / time_delta
                if curr["packets_recv"] >= prev["packets_recv"]:
                    rx_p_sec = (curr["packets_recv"] - prev["packets_recv"]) / time_delta
                if curr["packets_sent"] >= prev["packets_sent"]:
                    tx_p_sec = (curr["packets_sent"] - prev["packets_sent"]) / time_delta

            iface_traffic = InterfaceTraffic(
                name=iface_name,
                bytes_recv=curr["bytes_recv"],
                bytes_sent=curr["bytes_sent"],
                packets_recv=curr["packets_recv"],
                packets_sent=curr["packets_sent"],
                err_in=curr["err_in"],
                err_out=curr["err_out"],
                drop_in=curr["drop_in"],
                drop_out=curr["drop_out"],
                rx_bytes_per_sec=round(rx_b_sec, 2),
                tx_bytes_per_sec=round(tx_b_sec, 2),
                rx_packets_per_sec=round(rx_p_sec, 2),
                tx_packets_per_sec=round(tx_p_sec, 2),
            )
            interfaces_dict[iface_name] = iface_traffic

            # Aggregate physical/external traffic (exclude loopback 'lo' from aggregates)
            if iface_name != "lo":
                total_rx_bytes += curr["bytes_recv"]
                total_tx_bytes += curr["bytes_sent"]
                total_rx_packets += curr["packets_recv"]
                total_tx_packets += curr["packets_sent"]
                total_drop_in += curr["drop_in"]
                rx_bytes_sec_agg += rx_b_sec
                tx_bytes_sec_agg += tx_b_sec
                rx_pkts_sec_agg += rx_p_sec
                tx_pkts_sec_agg += tx_p_sec

        # Update cache for next iteration
        self._last_sample_time = now
        self._last_counters = current_counters

        return TrafficSnapshot(
            measurement_window_seconds=round(time_delta, 2),
            incoming_bytes_per_sec=round(rx_bytes_sec_agg, 2),
            outgoing_bytes_per_sec=round(tx_bytes_sec_agg, 2),
            incoming_packets_per_sec=round(rx_pkts_sec_agg, 2),
            outgoing_packets_per_sec=round(tx_pkts_sec_agg, 2),
            total_bytes_recv=total_rx_bytes,
            total_bytes_sent=total_tx_bytes,
            total_packets_recv=total_rx_packets,
            total_packets_sent=total_tx_packets,
            total_drop_in=total_drop_in,
            interfaces=interfaces_dict,
        )

