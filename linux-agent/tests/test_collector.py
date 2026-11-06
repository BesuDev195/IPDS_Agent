"""Unit tests for UFW log collector, log reader, and system collector."""

import os
import tempfile
from pathlib import Path
import pytest

from agent.collector.log_reader import StatefulLogReader
from agent.collector.system_collector import SystemCollector
from agent.collector.ufw_collector import UfwCollector
from agent.processor.log_parser import parse_timestamp, parse_ufw_line


SAMPLE_TCP_BLOCK = (
    "Nov  6 20:15:30 ubuntu-server kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= "
    "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=198.51.100.4 DST=192.0.2.1 "
    "LEN=40 TOS=0x00 PREC=0x00 TTL=243 ID=54321 PROTO=TCP SPT=44123 DPT=80 WINDOW=65535 "
    "RES=0x00 SYN URGP=0"
)

SAMPLE_UDP_ALLOW = (
    "2026-11-06T20:16:00.123456+00:00 srv kernel: [UFW ALLOW] IN=eth0 OUT= "
    "SRC=198.51.100.5 DST=192.0.2.1 LEN=75 PROTO=UDP SPT=5353 DPT=53"
)

SAMPLE_ICMP_BLOCK = (
    "Nov  6 20:17:00 ubuntu-server kernel: [UFW BLOCK] IN=eth1 OUT= "
    "SRC=203.0.113.10 DST=192.0.2.1 LEN=84 PROTO=ICMP TYPE=8 CODE=0"
)

SAMPLE_IPV6_BLOCK = (
    "Nov  6 20:18:00 ubuntu-server kernel: [UFW BLOCK] IN=eth0 OUT= "
    "SRC=2001:db8::100 DST=2001:db8::1 LEN=60 PROTO=TCP SPT=51234 DPT=443 SYN"
)


def test_parse_ufw_tcp_block():
    entry = parse_ufw_line(SAMPLE_TCP_BLOCK)
    assert entry is not None
    assert entry.action == "BLOCK"
    assert entry.src_ip == "198.51.100.4"
    assert entry.dst_ip == "192.0.2.1"
    assert entry.protocol == "TCP"
    assert entry.src_port == 44123
    assert entry.dst_port == 80
    assert entry.interface_in == "eth0"
    assert entry.ttl == 243
    assert entry.packet_length == 40
    assert "SYN" in entry.tcp_flags


def test_parse_ufw_udp_allow():
    entry = parse_ufw_line(SAMPLE_UDP_ALLOW)
    assert entry is not None
    assert entry.action == "ALLOW"
    assert entry.src_ip == "198.51.100.5"
    assert entry.protocol == "UDP"
    assert entry.src_port == 5353
    assert entry.dst_port == 53


def test_parse_ufw_icmp_no_ports():
    entry = parse_ufw_line(SAMPLE_ICMP_BLOCK)
    assert entry is not None
    assert entry.action == "BLOCK"
    assert entry.src_ip == "203.0.113.10"
    assert entry.protocol == "ICMP"
    assert entry.src_port is None
    assert entry.dst_port is None


def test_parse_ufw_ipv6():
    entry = parse_ufw_line(SAMPLE_IPV6_BLOCK)
    assert entry is not None
    assert entry.src_ip == "2001:db8::100"
    assert entry.dst_ip == "2001:db8::1"
    assert entry.dst_port == 443


def test_parse_invalid_or_non_ufw_line():
    assert parse_ufw_line("Nov 6 20:00:00 systemd[1]: Starting Service...") is None
    assert parse_ufw_line("") is None
    assert parse_ufw_line("[UFW BLOCK] IN=eth0 OUT=") is None  # Missing SRC / DST


def test_stateful_log_reader_incremental_and_rotation():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "ufw.log"

        # 1. Write initial lines
        log_file.write_text(f"{SAMPLE_TCP_BLOCK}\n{SAMPLE_UDP_ALLOW}\n", encoding="utf-8")

        reader = StatefulLogReader(target_paths=[str(log_file)])
        results = reader.read_new_lines_from_file(str(log_file))
        assert len(results) == 2

        # 2. Reading again without new data should return empty (no duplicate processing)
        results2 = reader.read_new_lines_from_file(str(log_file))
        assert len(results2) == 0

        # 3. Append another line
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{SAMPLE_ICMP_BLOCK}\n")

        results3 = reader.read_new_lines_from_file(str(log_file))
        assert len(results3) == 1
        assert "203.0.113.10" in results3[0]

        # 4. Simulate log rotation (file truncated / overwritten)
        log_file.write_text(f"{SAMPLE_IPV6_BLOCK}\n", encoding="utf-8")
        results4 = reader.read_new_lines_from_file(str(log_file))
        assert len(results4) == 1
        assert "2001:db8::100" in results4[0]


def test_stateful_log_reader_missing_file_graceful():
    reader = StatefulLogReader(target_paths=["/tmp/non_existent_ufw_log_12345.log"])
    results = reader.read_all_new_lines()
    assert results == []


def test_ufw_collector_aggregation():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test_ufw.log"
        content = (
            f"{SAMPLE_TCP_BLOCK}\n"
            f"{SAMPLE_TCP_BLOCK}\n"
            f"{SAMPLE_UDP_ALLOW}\n"
            f"{SAMPLE_ICMP_BLOCK}\n"
        )
        log_file.write_text(content, encoding="utf-8")

        collector = UfwCollector(log_paths=[str(log_file)], use_journalctl=False)
        summary = collector.collect()

        assert summary.total_entries_read == 4
        assert summary.total_blocked == 3
        assert summary.total_allowed == 1
        assert summary.unique_source_ips == 3
        assert summary.unique_blocked_ips == 2
        assert "198.51.100.4" in summary.top_blocked_ips
        assert summary.top_blocked_ips["198.51.100.4"] == 2
        assert summary.top_targeted_ports.get(80) == 2


def test_system_collector():
    collector = SystemCollector()
    telemetry = collector.collect()

    assert telemetry.hostname != ""
    assert telemetry.cpu_count >= 1
    assert telemetry.memory.total_bytes > 0
    assert 0.0 <= telemetry.memory.percent <= 100.0
    assert telemetry.uptime_seconds >= 0.0

