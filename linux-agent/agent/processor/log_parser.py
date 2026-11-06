"""UFW Firewall Log Parser.

Extracts structured telemetry from Linux UFW / netfilter log strings.
Supports IPv4, IPv6, varying timestamps, missing fields, and TCP flags.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


# Standard TCP flag tokens in netfilter logs
KNOWN_TCP_FLAGS = {"SYN", "ACK", "FIN", "RST", "URG", "PSH", "ECE", "CWR"}

# Regex for finding the UFW prefix and action
UFW_ACTION_PATTERN = re.compile(r"\[UFW\s+([A-Z_]+)\]", re.IGNORECASE)

# Key=Value pattern for iptables/netfilter log parameters
KV_PATTERN = re.compile(r"\b([A-Z0-9_]+)=([^\s]+)")


class UfwLogEntry(BaseModel):
    """Structured representation of a parsed UFW firewall log entry."""

    timestamp: Optional[datetime] = None
    raw_timestamp: Optional[str] = None
    action: str = Field("UNKNOWN", description="Action taken: BLOCK, ALLOW, AUDIT, etc.")
    src_ip: str = Field(..., description="Source IP address (IPv4 or IPv6)")
    dst_ip: str = Field(..., description="Destination IP address (IPv4 or IPv6)")
    protocol: str = Field("UNKNOWN", description="Network protocol: TCP, UDP, ICMP, etc.")
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    interface_in: Optional[str] = None
    interface_out: Optional[str] = None
    mac: Optional[str] = None
    packet_length: Optional[int] = None
    ttl: Optional[int] = None
    tcp_flags: List[str] = Field(default_factory=list)
    raw_log: str


def parse_timestamp(raw_str: str) -> Optional[datetime]:
    """Attempts to parse common Linux log timestamps (ISO or syslog format)."""
    # 1. ISO 8601 (e.g., 2026-11-06T20:15:30.123456+00:00 or 2026-11-06T20:15:30Z)
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", raw_str)
    if iso_match:
        try:
            iso_str = iso_match.group(1).replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass

    # 2. Syslog classic format (e.g. "Nov  6 20:15:30")
    syslog_match = re.search(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", raw_str)
    if syslog_match:
        try:
            current_year = datetime.now(timezone.utc).year
            dt_str = f"{current_year} {syslog_match.group(1)}"
            # Handle variable spaces in day number
            cleaned_dt = re.sub(r"\s+", " ", dt_str)
            dt = datetime.strptime(cleaned_dt, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return None


def parse_ufw_line(line: str) -> Optional[UfwLogEntry]:
    """Parses a single log line into a structured UfwLogEntry.

    Returns None if the line does not appear to be a UFW log message or lacks essential fields.
    """
    if not line or "[UFW " not in line:
        return None

    action_match = UFW_ACTION_PATTERN.search(line)
    action = action_match.group(1).upper() if action_match else "UNKNOWN"

    # Extract all key-value pairs
    kv_dict = dict(KV_PATTERN.findall(line))

    src_ip = kv_dict.get("SRC")
    dst_ip = kv_dict.get("DST")

    # Essential requirement: must have source and destination IPs
    if not src_ip or not dst_ip:
        return None

    # Protocol
    proto = kv_dict.get("PROTO", "UNKNOWN").upper()

    # Ports
    src_port = None
    if "SPT" in kv_dict and kv_dict["SPT"].isdigit():
        src_port = int(kv_dict["SPT"])

    dst_port = None
    if "DPT" in kv_dict and kv_dict["DPT"].isdigit():
        dst_port = int(kv_dict["DPT"])

    # Interfaces
    in_iface = kv_dict.get("IN") or None
    out_iface = kv_dict.get("OUT") or None
    mac = kv_dict.get("MAC") or None

    # Packet length & TTL
    packet_len = int(kv_dict["LEN"]) if "LEN" in kv_dict and kv_dict["LEN"].isdigit() else None
    ttl = int(kv_dict["TTL"]) if "TTL" in kv_dict and kv_dict["TTL"].isdigit() else None

    # Detect TCP flags which are standalone words in the log
    # Example: "... PROTO=TCP SPT=123 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0"
    tcp_flags: List[str] = []
    tokens = set(re.findall(r"\b[A-Z]{3,4}\b", line))
    for flag in KNOWN_TCP_FLAGS:
        if flag in tokens:
            tcp_flags.append(flag)

    timestamp = parse_timestamp(line)

    return UfwLogEntry(
        timestamp=timestamp,
        raw_timestamp=line[:32].strip(),
        action=action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        src_port=src_port,
        dst_port=dst_port,
        interface_in=in_iface,
        interface_out=out_iface,
        mac=mac,
        packet_length=packet_len,
        ttl=ttl,
        tcp_flags=sorted(tcp_flags),
        raw_log=line,
    )

