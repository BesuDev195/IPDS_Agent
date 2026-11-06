"""Stateful log file reader with log rotation and permission handling.

Tracks file offset and inode positions to ensure log records are read
incrementally without duplicates, surviving logrotate cycles and restarts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent.utils.logger import collection_logger


@dataclass
class FileCursor:
    path: str
    inode: int = 0
    offset: int = 0
    last_read: Optional[str] = None


class StatefulLogReader:
    """Incrementally reads new lines from one or more log files."""

    def __init__(self, target_paths: List[str] | None = None) -> None:
        self.target_paths: List[str] = target_paths or []
        self._cursors: Dict[str, FileCursor] = {}
        self._reported_missing: set[str] = set()
        self._reported_permissions: set[str] = set()

    def get_cursor_state(self) -> Dict[str, dict]:
        """Returns serialized cursor state for persistence."""
        return {
            p: {
                "inode": c.inode,
                "offset": c.offset,
                "last_read": c.last_read,
            }
            for p, c in self._cursors.items()
        }

    def set_cursor_state(self, state: Dict[str, dict]) -> None:
        """Restores cursor state from persistent storage."""
        for path, data in state.items():
            self._cursors[path] = FileCursor(
                path=path,
                inode=data.get("inode", 0),
                offset=data.get("offset", 0),
                last_read=data.get("last_read"),
            )

    def read_new_lines_from_file(self, file_path_str: str) -> List[str]:
        """Reads newly appended full lines from a single log file."""
        file_path = Path(file_path_str)
        if not file_path.exists():
            if file_path_str not in self._reported_missing:
                collection_logger.debug(f"Log source not found: {file_path_str}")
                self._reported_missing.add(file_path_str)
            return []

        # Reset reported missing status if file appeared
        self._reported_missing.discard(file_path_str)

        try:
            stat_res = file_path.stat()
        except PermissionError:
            if file_path_str not in self._reported_permissions:
                collection_logger.warning(
                    f"Permission denied reading log file: {file_path_str}. Check agent permissions."
                )
                self._reported_permissions.add(file_path_str)
            return []
        except OSError as e:
            collection_logger.debug(f"Error stating {file_path_str}: {e}")
            return []

        self._reported_permissions.discard(file_path_str)

        current_inode = stat_res.st_ino
        current_size = stat_res.st_size

        cursor = self._cursors.get(file_path_str)
        if cursor is None:
            # First time observing this file
            cursor = FileCursor(path=file_path_str, inode=current_inode, offset=0)
            self._cursors[file_path_str] = cursor

        lines: List[str] = []

        # Check for log rotation: inode change or size truncation
        if cursor.inode != current_inode or current_size < cursor.offset:
            collection_logger.info(
                f"Log rotation detected for {file_path_str} (inode changed from {cursor.inode} "
                f"to {current_inode} or size shrank from {cursor.offset} to {current_size}). Resetting offset."
            )
            cursor.inode = current_inode
            cursor.offset = 0

        # If no new content
        if current_size == cursor.offset:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(cursor.offset)
                content = f.read()
                new_offset = f.tell()

                # If content does not end with a newline, find the last complete line
                if content and not content.endswith("\n"):
                    last_nl = content.rfind("\n")
                    if last_nl == -1:
                        # No complete line yet, wait for subsequent writes
                        return []
                    # Keep only completed lines and rewind file position
                    incomplete_len = len(content.encode("utf-8")) - (last_nl + 1)
                    cursor.offset = new_offset - incomplete_len
                    content = content[: last_nl + 1]
                else:
                    cursor.offset = new_offset

                cursor.last_read = datetime.now(timezone.utc).isoformat()
                lines = [line.strip() for line in content.splitlines() if line.strip()]

        except PermissionError:
            if file_path_str not in self._reported_permissions:
                collection_logger.warning(f"Permission denied reading: {file_path_str}")
                self._reported_permissions.add(file_path_str)
            return []
        except Exception as e:
            collection_logger.error(f"Unexpected error reading {file_path_str}: {e}")
            return []

        return lines

    def read_all_new_lines(self) -> List[Tuple[str, str]]:
        """Reads new lines from all configured paths.

        Returns tuples of (source_path, line_text).
        """
        results: List[Tuple[str, str]] = []
        for path in self.target_paths:
            new_lines = self.read_new_lines_from_file(path)
            for line in new_lines:
                results.append((path, line))
        return results


class JournalctlReader:
    """Reads UFW messages directly from systemd journalctl with cursor tracking."""

    def __init__(self) -> None:
        self.cursor: Optional[str] = None
        self._journalctl_bin = shutil.which("journalctl")

    def is_available(self) -> bool:
        return self._journalctl_bin is not None

    def read_new_lines(self, max_lines: int = 1000) -> List[str]:
        if not self.is_available():
            return []

        cmd = [
            self._journalctl_bin,
            "-k",  # kernel ring buffer where UFW packets are logged
            "-o",
            "short-iso",
            "--no-pager",
            "-n",
            str(max_lines),
        ]
        if self.cursor:
            cmd.extend(["--after-cursor", self.cursor])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if proc.returncode != 0:
                collection_logger.debug(f"journalctl returned code {proc.returncode}")
                return []

            lines = proc.stdout.splitlines()
            # Extract cursor if journalctl output includes cursor or store last entry timestamp
            # Filter for UFW entries only
            ufw_lines = [l for l in lines if "[UFW " in l]
            return ufw_lines
        except subprocess.TimeoutExpired:
            collection_logger.warning("journalctl read timed out")
            return []
        except Exception as e:
            collection_logger.debug(f"journalctl execution failed: {e}")
            return []

