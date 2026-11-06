"""Agent Application Coordinator.

Coordinates collectors, monitors, feature extraction, communication,
firewall management, and lifecycle events.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Optional

from agent.collector.system_collector import SystemCollector
from agent.collector.ufw_collector import UfwCollector
from agent.config import AgentSettings, load_config
from agent.monitor.network_monitor import NetworkMonitor
from agent.utils.logger import lifecycle_logger, setup_logging


class AgentApplication:
    """Core lifecycle coordinator for the Linux Security Agent."""

    def __init__(self, settings: Optional[AgentSettings] = None, config_path: Optional[str] = None) -> None:
        if settings is not None:
            self.settings = settings
        else:
            self.settings = load_config(config_path)

        # Configure structured logging and mask API keys
        setup_logging(
            level=self.settings.logging.level,
            log_file=self.settings.logging.log_file,
            json_format=self.settings.logging.json_format,
            console_output=self.settings.logging.console_output,
            api_key_to_mask=self.settings.backend.api_key,
        )

        lifecycle_logger.info(
            f"Initializing Linux Security Agent (Agent ID: {self.settings.agent.id}, "
            f"Protection Mode: {self.settings.protection.mode.value})"
        )

        # Initialize Phase 1 components
        self.ufw_collector = UfwCollector(
            log_paths=self.settings.monitoring.ufw_log_paths,
            use_journalctl=self.settings.monitoring.use_journalctl,
        )
        self.system_collector = SystemCollector()
        self.network_monitor = NetworkMonitor(
            target_interfaces=self.settings.monitoring.interfaces or None,
        )

        self._running = False
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Starts the agent background monitoring loops."""
        self._running = True
        lifecycle_logger.info(
            f"Agent started successfully. Ingesting telemetry every {self.settings.monitoring.interval}s."
        )

        try:
            while self._running and not self._shutdown_event.is_set():
                # Telemetry cycle
                ufw_summary = await self.ufw_collector.collect_async()
                net_telemetry = await self.network_monitor.collect_async()
                sys_telemetry = self.system_collector.collect()

                # In later phases: feature extraction, API telemetry submission, decision handling

                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.settings.monitoring.interval,
                    )
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            lifecycle_logger.info("Agent run task cancelled.")
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Performs graceful shutdown of agent background operations."""
        if not self._running:
            return
        self._running = False
        self._shutdown_event.set()
        lifecycle_logger.info("Agent shutting down gracefully.")

