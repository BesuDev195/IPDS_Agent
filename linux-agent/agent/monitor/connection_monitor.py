"""Connection Monitor Module.

Inspects active TCP/UDP socket states, connection distributions, and SYN flood indicators
using Linux /proc/net/tcp and /proc/net/tcp6 with psutil fallback.
"""

from __future__ import annotations

import socket
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

import psutil
from agent.utils.logger import collection_logger

# Linux /proc/net/tcp state mapping
TCP_STATE_MAP = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _hex_to_ipv4(hex_addr: str) -> str:
    """Converts a little-endian hex string into standard IPv4 dotted notation."""
    try:
        ip_int = int(hex_addr, 16)
        return socket.inet_ntoa(struct.pack("<L", ip_int))
    except Exception:
        return "0.0.0.0"


def _hex_to_ipv6(hex_addr: str) -> str:
    """Converts a 32-character hex string into standard IPv6 notation."""
    try:
        # In Linux /proc/net/tcp6, four 32-bit words are stored in host byte order
        words = [int(hex_addr[i : i + 8], 16) for i in range(0, 32, 8)]
        packed = b"".join(struct.pack("<I", w) for w in words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "::"


class ConnectionStats(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_connections: int = 0
    active_tcp_connections: int = 0
    tcp_states: Dict[str, int] = Field(default_factory=dict)
    syn_recv_count: int = 0
    syn_sent_count: int = 0
    syn_ratio: float = Field(0.0, description="Ratio of SYN_RECV to ESTABLISHED connections")
    unique_remote_ips: int = 0
    top_remote_ips: Dict[str, int] = Field(default_factory=dict)
    top_local_ports: Dict[int, int] = Field(default_factory=dict)


class ConnectionMonitor:
    """Monitors TCP and UDP connection states."""

    def __init__(self) -> None:
        self.tcp_proc = Path("/proc/net/tcp")
        self.tcp6_proc = Path("/proc/net/tcp6")

    def _parse_proc_tcp(self, proc_file: Path, is_ipv6: bool = False) -> List[Tuple[str, int, str, int, str]]:
        """Parses /proc/net/tcp or tcp6 lines.

        Returns tuples of (local_ip, local_port, remote_ip, remote_port, state_name).
        """
        connections: List[Tuple[str, int, str, int, str]] = []
        if not proc_file.exists():
            return connections

        try:
            content = proc_file.read_text(encoding="utf-8")
            lines = content.splitlines()
            for line in lines[1:]:  # Skip header line
                tokens = line.strip().split()
                if len(tokens) < 4:
                    continue

                local_addr_token = tokens[1]
                remote_addr_token = tokens[2]
                state_hex = tokens[3].upper()

                state_name = TCP_STATE_MAP.get(state_hex, "UNKNOWN")

                # Parse local ip and port
                local_hex_ip, local_hex_port = local_addr_token.split(":")
                local_port = int(local_hex_port, 16)
                local_ip = _hex_to_ipv6(local_hex_ip) if is_ipv6 else _hex_to_ipv4(local_hex_ip)

                # Parse remote ip and port
                remote_hex_ip, remote_hex_port = remote_addr_token.split(":")
                remote_port = int(remote_hex_port, 16)
                remote_ip = _hex_to_ipv6(remote_hex_ip) if is_ipv6 else _hex_to_ipv4(remote_hex_ip)

                connections.append((local_ip, local_port, remote_ip, remote_port, state_name))
        except Exception as e:
            collection_logger.debug(f"Error reading {proc_file}: {e}")

        return connections

    def _collect_via_proc(self) -> ConnectionStats:
        """Collects connections directly from Linux /proc/net/tcp* files."""
        v4_conns = self._parse_proc_tcp(self.tcp_proc, is_ipv6=False)
        v6_conns = self._parse_proc_tcp(self.tcp6_proc, is_ipv6=True)
        all_conns = v4_conns + v6_conns

        state_counter: Counter[str] = Counter()
        remote_ip_counter: Counter[str] = Counter()
        local_port_counter: Counter[int] = Counter()

        for local_ip, local_port, remote_ip, remote_port, state in all_conns:
            state_counter[state] += 1

            # Only count non-zero remote IPs as active peers
            if remote_ip not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                remote_ip_counter[remote_ip] += 1
                local_port_counter[local_port] += 1

        syn_recv = state_counter.get("SYN_RECV", 0)
        syn_sent = state_counter.get("SYN_SENT", 0)
        established = state_counter.get("ESTABLISHED", 0)

        syn_ratio = round(syn_recv / max(1, established), 4)

        top_ips = dict(remote_ip_counter.most_common(10))
        top_ports = dict(local_port_counter.most_common(10))

        return ConnectionStats(
            total_connections=len(all_conns),
            active_tcp_connections=established + syn_recv + syn_sent,
            tcp_states=dict(state_counter),
            syn_recv_count=syn_recv,
            syn_sent_count=syn_sent,
            syn_ratio=syn_ratio,
            unique_remote_ips=len(remote_ip_counter),
            top_remote_ips=top_ips,
            top_local_ports=top_ports,
        )

    def _collect_via_psutil(self) -> ConnectionStats:
        """Fallback connection collector using psutil."""
        state_counter: Counter[str] = Counter()
        remote_ip_counter: Counter[str] = Counter()
        local_port_counter: Counter[int] = Counter()
        total = 0

        try:
            conns = psutil.net_connections(kind="tcp")
            total = len(conns)
            for c in conns:
                state_counter[c.status] += 1
                if c.raddr:
                    ip = c.raddr.ip
                    if ip not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                        remote_ip_counter[ip] += 1
                if c.laddr:
                    local_port_counter[c.laddr.port] += 1
        except (psutil.AccessDenied, PermissionError):
            collection_logger.debug("psutil.net_connections() access denied. Relying on /proc parser.")
        except Exception as e:
            collection_logger.debug(f"psutil connection lookup error: {e}")

        syn_recv = state_counter.get("SYN_RECV", 0)
        syn_sent = state_counter.get("SYN_SENT", 0)
        established = state_counter.get("ESTABLISHED", 0)
        syn_ratio = round(syn_recv / max(1, established), 4)

        return ConnectionStats(
            total_connections=total,
            active_tcp_connections=established + syn_recv + syn_sent,
            tcp_states=dict(state_counter),
            syn_recv_count=syn_recv,
            syn_sent_count=syn_sent,
            syn_ratio=syn_ratio,
            unique_remote_ips=len(remote_ip_counter),
            top_remote_ips=dict(remote_ip_counter.most_common(10)),
            top_local_ports=dict(local_port_counter.most_common(10)),
        )

    def collect(self) -> ConnectionStats:
        """Collects connection statistics using the best available Linux mechanism."""
        if self.tcp_proc.exists():
            return self._collect_via_proc()
        return self._collect_via_psutil()

