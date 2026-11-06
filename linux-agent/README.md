# Independent Linux Security Agent for AI-Based IDS/IPS

An independent, modular, installable Linux Security Agent written in Python 3.11+.
This agent is part of an AI-based Intrusion Detection and Prevention System (IDS/IPS) focused primarily on detecting and mitigating DDoS attacks.

## Architectural Overview

The AI model runs centrally on the FastAPI backend. The agent:
1. Passively collects real-time host network telemetry and UFW firewall logs.
2. Extracts structured features compatible with backend ML models.
3. Transmits telemetry securely to the central FastAPI backend.
4. Receives AI-based DDoS detection decisions.
5. Safely enforces authorized firewall actions locally via UFW with strict safety guardrails, timeouts, and automatic rollback.

> **Security Guardrail**: Automatic blocking is **never enabled by default**. The agent operates in `monitor` mode until explicitly configured otherwise.

---

## Directory Structure

```
linux-agent/
├── agent/
│   ├── __init__.py
│   ├── main.py                     # CLI entrypoint (ai-ids-agent)
│   ├── config.py                   # Pydantic v2 configuration system & env vars
│   ├── application.py              # Lifecycle orchestrator
│   ├── collector/
│   │   ├── __init__.py
│   │   ├── ufw_collector.py        # UFW firewall log ingestion and aggregation
│   │   ├── system_collector.py     # CPU, memory, load, uptime metrics
│   │   └── log_reader.py           # Stateful incremental reader with rotation handling
│   ├── monitor/
│   │   ├── __init__.py
│   │   ├── network_monitor.py      # Passive network metrics coordinator
│   │   ├── connection_monitor.py   # TCP socket states & SYN flood monitoring
│   │   └── traffic_statistics.py   # Interface rates (PPS, BPS) calculation
│   ├── processor/                  # (Phase 2)
│   │   ├── __init__.py
│   │   ├── log_parser.py           # Robust netfilter/UFW log parser
│   │   ├── feature_extractor.py
│   │   └── data_formatter.py
│   ├── communication/              # (Phase 2)
│   │   ├── __init__.py
│   │   ├── api_client.py
│   │   ├── telemetry_sender.py
│   │   └── heartbeat.py
│   ├── response/                   # (Phase 3)
│   │   ├── __init__.py
│   │   ├── decision_validator.py
│   │   └── decision_handler.py
│   ├── firewall/                   # (Phase 3)
│   │   ├── __init__.py
│   │   ├── firewall_interface.py
│   │   ├── ufw_manager.py
│   │   ├── rule_manager.py
│   │   └── rollback.py
│   ├── security/                   # (Phase 3)
│   │   ├── __init__.py
│   │   ├── authentication.py
│   │   └── ip_validator.py
│   ├── storage/                    # (Phase 4)
│   │   ├── __init__.py
│   │   ├── database.py
│   │   ├── event_queue.py
│   │   └── audit_logger.py
│   └── utils/
│       ├── __init__.py
│       └── logger.py               # Structured logger with secret redaction
├── config/
│   └── config.example.yaml         # Fully documented example configuration
├── systemd/
│   └── ai-ids-agent.service
├── packaging/
│   └── debian/
├── scripts/
│   ├── install.sh
│   └── uninstall.sh
├── tests/
│   ├── test_collector.py
│   ├── test_config.py
│   ├── test_logger.py
│   └── test_monitor.py
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Phase 1 Implementation Summary

- **Project Structure**: Created all modular sub-packages matching specification.
- **Configuration Module (`agent/config.py`)**:
  - YAML configuration loading with environment variable interpolation (`${VAR:-default}`).
  - Pydantic v2 data models for type safety, validation, and serialization.
  - Strict security guardrail: automatic blocking is disabled by default; mode downgrades to `monitor` if unauthorized.
  - Sensitive token/credential masking in object representations.
- **Structured Logging (`agent/utils/logger.py`)**:
  - Structured standard and JSON log formatters.
  - Automatic masking of API tokens, Bearer tokens, passwords, and registered secrets.
  - Categorized loggers for collection, communication, AI detection, firewall actions, auth, and lifecycle.
- **UFW Collector (`agent/collector/` & `agent/processor/log_parser.py`)**:
  - `log_reader.py`: Stateful file follower tracking inode and offset across log rotations (`logrotate`), handling missing files and permission denials gracefully.
  - `journalctl` reader fallback for systemd environments without standalone log files.
  - `log_parser.py`: Multi-format parser supporting IPv4/IPv6, variable timestamps, TCP flags (`SYN`, `ACK`, `FIN`, `RST`, etc.), port mappings, and missing fields.
  - `ufw_collector.py`: Incremental ingestion avoiding duplicate processing, computing real-time event aggregation.
  - `system_collector.py`: Non-invasive host telemetry (CPU, memory, load avg, disk, uptime).
- **Network Monitor (`agent/monitor/`)**:
  - `traffic_statistics.py`: High-performance parsing of `/proc/net/dev` with `psutil` fallback; calculates PPS and BPS over measurement intervals.
  - `connection_monitor.py`: Directly inspects socket states (`/proc/net/tcp`, `/proc/net/tcp6`), computing active TCP state counts, SYN flood indicators (`syn_ratio`, `syn_recv_count`), and top peer IPs.
  - `network_monitor.py`: Coordinated passive network telemetry.

---

## Running Tests

```bash
# Run automated unit tests
pytest linux-agent/tests
```

