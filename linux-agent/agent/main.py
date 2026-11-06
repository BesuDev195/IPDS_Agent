"""Command-line entry point for Linux Security Agent (ai-ids-agent)."""

from __future__ import annotations

import argparse
import asyncio
import sys

from agent.application import AgentApplication
from agent.config import load_config


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ai-ids-agent",
        description="Independent Linux Security Agent for AI-Based IDS/IPS",
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        default=None,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration file syntax and safety settings, then exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
    )

    args = parser.parse_args()

    if args.check_config:
        try:
            cfg = load_config(args.config_path)
            print(f"Configuration is valid! Agent ID: {cfg.agent.id}, Mode: {cfg.protection.mode.value}")
            sys.exit(0)
        except Exception as e:
            print(f"Configuration Error: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        app = AgentApplication(config_path=args.config_path)
        asyncio.run(app.start())
    except KeyboardInterrupt:
        print("\nAgent stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error initializing agent: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

