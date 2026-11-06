"""Unit tests for traffic statistics, connection monitoring, and network monitoring."""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from agent.monitor.connection_monitor import (
    ConnectionMonitor,
    _hex_to_ipv4,
    _hex_to_ipv6,
)
from agent.monitor.network_monitor import NetworkMonitor
from agent.monitor.traffic_statistics import (
    TrafficSnapshot,
    TrafficStatisticsCalculator,
)


def test_hex_to_ipv4():
    # 0100007F in little endian is 127.0.0.1
    ip = _hex_to_ipv4("0100007F")
    assert ip == "127.0.0.1"


def test_hex_to_ipv6():
    hex_v6 = "00000000000000000000000001000000"
    ip = _hex_to_ipv6(hex_v6)
    assert ip in ("::1", "0:0:0:0:0:0:0:1")


SAMPLE_PROC_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000000   10000    0    0    0     0          0         0  1000000   10000    0    0    0     0       0          0
  eth0: 5000000   20000    1    2    0     0          0         0  3000000   15000    0    0    0     0       0          0
"""

SAMPLE_PROC_DEV_AFTER = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000000   10000    0    0    0     0          0         0  1000000   10000    0    0    0     0       0          0
  eth0: 5050000   20100    1    2    0     0          0         0  3020000   15050    0    0    0     0       0          0
"""


def test_traffic_statistics_rates():
    calc = TrafficStatisticsCalculator()

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "read_text", return_value=SAMPLE_PROC_DEV):
            # First snapshot establishes baseline
            snap1 = calc.collect()
            assert snap1.incoming_bytes_per_sec == 0.0

        time.sleep(0.1)

        with patch.object(Path, "read_text", return_value=SAMPLE_PROC_DEV_AFTER):
            # Second snapshot calculates rates over delta
            snap2 = calc.collect()
            assert snap2.measurement_window_seconds > 0
            # 50,000 bytes delta / delta_t
            assert snap2.incoming_bytes_per_sec > 0
            assert snap2.incoming_packets_per_sec > 0
            assert "eth0" in snap2.interfaces
            assert snap2.interfaces["eth0"].rx_bytes_per_sec > 0


SAMPLE_PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 0200007F:A123 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 0A0002C6:B456 03 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0050 0B0002C6:B457 03 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
"""


def test_connection_monitor_parsing():
    conn_mon = ConnectionMonitor()

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "read_text", side_effect=[SAMPLE_PROC_TCP, ""]):
            stats = conn_mon.collect()

            assert stats.total_connections == 3
            assert stats.tcp_states.get("ESTABLISHED") == 1
            assert stats.tcp_states.get("SYN_RECV") == 2
            assert stats.syn_recv_count == 2
            # 2 SYN_RECV / 1 ESTABLISHED = 2.0
            assert stats.syn_ratio == 2.0
            assert stats.unique_remote_ips >= 1


def test_network_monitor_integration():
    net_mon = NetworkMonitor()
    telemetry = net_mon.collect()

    assert telemetry.traffic is not None
    assert telemetry.connections is not None
    assert isinstance(telemetry.active_interfaces, list)

