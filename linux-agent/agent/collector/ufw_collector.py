"""UFW Collector Module.

Monitors and ingests UFW firewall log entries from file sources or journalctl,
parses them into structured models, and tracks incremental offsets to prevent duplicate processing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from agent.collector.log_reader import JournalctlReader, StatefulLogReader
from agent.processor.log_parser import UfwLogEntry, parse_ufw_line
from agent.utils.logger import collection_logger


class UfwCollectionSummary(BaseModel):
    """Aggregated summary of UFW events collected during an interval."""

    collection_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_entries_read: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    total_audit: int = 0
    unique_source_ips: int = 0
    unique_blocked_ips: int = 0
    protocol_distribution: Dict[str, int] = Field(default_factory=dict)
    top_blocked_ips: Dict[str, int] = Field(default_factory=dict)
    top_targeted_ports: Dict[int, int] = Field(default_factory=dict)
    entries: List[UfwLogEntry] = Field(default_factory=list)


class UfwCollector:
    """Collects and aggregates UFW log entries asynchronously."""

    def __init__(
        self,
        log_paths: Optional[List[str]] = None,
        use_journalctl: bool = True,
    ) -> None:
        self.log_paths = log_paths or [
            "/var/log/ufw.log",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/kern.log",
        ]
        self.file_reader = StatefulLogReader(target_paths=self.log_paths)
        self.journal_reader = JournalctlReader() if use_journalctl else None
        self._journalctl_used = False

    def collect(self, max_entries: int = 5000) -> UfwCollectionSummary:
        """Reads and parses new UFW entries synchronously (safe for async run_in_executor)."""
        raw_lines: List[str] = []

        # 1. First, attempt to read from log files
        file_results = self.file_reader.read_all_new_lines()
        for _, line in file_results:
            raw_lines.append(line)

        # 2. If no log files were accessible/found, try journalctl if available
        if not file_results and self.journal_reader and self.journal_reader.is_available():
            journal_lines = self.journal_reader.read_new_lines(max_lines=max_entries)
            if journal_lines:
                if not self._journalctl_used:
                    collection_logger.info("Reading UFW events directly from journalctl.")
                    self._journalctl_used = True
                raw_lines.extend(journal_lines)

        parsed_entries: List[UfwLogEntry] = []
        blocked_ips: Dict[str, int] = {}
        all_src_ips: set[str] = set()
        ports: Dict[int, int] = {}
        protocols: Dict[str, int] = {}
        action_counts = {"BLOCK": 0, "ALLOW": 0, "AUDIT": 0}

        for line in raw_lines:
            entry = parse_ufw_line(line)
            if not entry:
                continue

            parsed_entries.append(entry)
            all_src_ips.add(entry.src_ip)

            # Update action counters
            act = entry.action
            if act in action_counts:
                action_counts[act] += 1
            elif "BLOCK" in act:
                action_counts["BLOCK"] += 1
            else:
                action_counts["AUDIT"] += 1

            # Update protocol distribution
            protocols[entry.protocol] = protocols.get(entry.protocol, 0) + 1

            # Track targeted ports
            if entry.dst_port is not None:
                ports[entry.dst_port] = ports.get(entry.dst_port, 0) + 1

            # Track blocked sources
            if "BLOCK" in act:
                blocked_ips[entry.src_ip] = blocked_ips.get(entry.src_ip, 0) + 1

            if len(parsed_entries) >= max_entries:
                break

        # Compute top blocked IPs (up to 10)
        sorted_blocked = dict(sorted(blocked_ips.items(), key=lambda item: item[1], reverse=True)[:10])
        sorted_ports = dict(sorted(ports.items(), key=lambda item: item[1], reverse=True)[:10])

        summary = UfwCollectionSummary(
            total_entries_read=len(parsed_entries),
            total_blocked=action_counts["BLOCK"],
            total_allowed=action_counts["ALLOW"],
            total_audit=action_counts["AUDIT"],
            unique_source_ips=len(all_src_ips),
            unique_blocked_ips=len(blocked_ips),
            protocol_distribution=protocols,
            top_blocked_ips=sorted_blocked,
            top_targeted_ports=sorted_ports,
            entries=parsed_entries,
        )

        if summary.total_entries_read > 0:
            collection_logger.info(
                f"UFW Collector: Ingested {summary.total_entries_read} entries "
                f"({summary.total_blocked} blocked, {summary.total_allowed} allowed, "
                f"{summary.unique_source_ips} unique IPs)."
            )

        return summary

    async def collect_async(self, max_entries: int = 5000) -> UfwCollectionSummary:
        """Asynchronously collects UFW entries without blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.collect, max_entries)

