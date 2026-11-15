"""Read-only collection of Windows Security logon events."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET


class WindowsEventCollectorError(RuntimeError):
    """Raised when Windows Security events cannot be collected."""


@dataclass
class WindowsEventCollector:
    """Poll Windows Security events 4624 and 4625 without changing the host."""

    bookmark_path: Path = Path("data/windows_security_bookmark.json")
    max_events: int = 100

    def poll(self) -> list[dict[str, Any]]:
        last_record_id = self._read_bookmark()
        command = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            (
                "$events = Get-WinEvent -LogName Security -MaxEvents "
                f"{self.max_events}; "
                "$events | Where-Object {$_.Id -in 4624,4625} | "
                "ForEach-Object { "
                "$xml = $_.ToXml(); "
                "[pscustomobject]@{"
                "record_id=$_.RecordId; event_id=$_.Id; "
                "time=$_.TimeCreated.ToUniversalTime().ToString('o'); "
                "computer=$_.MachineName; xml=$xml"
                "} | ConvertTo-Json -Compress "
                "}"
            ),
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except OSError as exc:
            raise WindowsEventCollectorError(
                "PowerShell is required to read the Windows Security log."
            ) from exc
        if completed.returncode != 0:
            message = completed.stderr.strip() or "unknown Windows Event Log error"
            raise WindowsEventCollectorError(
                "Could not read the Windows Security log. "
                "Run VS Code or PowerShell with permission to read Security logs. "
                f"Details: {message}"
            )

        collected: list[dict[str, Any]] = []
        newest_record_id = last_record_id
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                record_id = int(raw["record_id"])
                if record_id <= last_record_id:
                    continue
                event = parse_windows_event(
                    event_id=int(raw["event_id"]),
                    timestamp=raw["time"],
                    hostname=raw.get("computer", ""),
                    raw_xml=raw["xml"],
                    record_id=record_id,
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise WindowsEventCollectorError(
                    "Windows returned an event that could not be parsed."
                ) from exc
            collected.append(event)
            newest_record_id = max(newest_record_id, record_id)

        if newest_record_id > last_record_id:
            self._write_bookmark(newest_record_id)
        return sorted(collected, key=lambda event: event["timestamp"])

    def _read_bookmark(self) -> int:
        try:
            return int(json.loads(self.bookmark_path.read_text())["last_record_id"])
        except FileNotFoundError:
            return 0
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise WindowsEventCollectorError(
                f"Bookmark file '{self.bookmark_path}' is invalid or unreadable."
            ) from exc

    def _write_bookmark(self, record_id: int) -> None:
        try:
            self.bookmark_path.parent.mkdir(parents=True, exist_ok=True)
            self.bookmark_path.write_text(
                json.dumps({"last_record_id": record_id}, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            raise WindowsEventCollectorError(
                f"Could not save the event bookmark at '{self.bookmark_path}'."
            ) from exc


def parse_windows_event(
    *,
    event_id: int,
    timestamp: str,
    hostname: str,
    raw_xml: str,
    record_id: int,
) -> dict[str, Any]:
    """Convert one Windows event XML document to the shared event schema."""

    root = ET.fromstring(raw_xml)
    values = {
        data.attrib["Name"]: (data.text or "")
        for data in root.findall(".//{*}EventData/{*}Data")
        if "Name" in data.attrib
    }
    status = "success" if event_id == 4624 else "failed" if event_id == 4625 else "unknown"
    source_ip = values.get("IpAddress") or "Local/Unavailable"
    return {
        "timestamp": _normalise_timestamp(timestamp),
        "source_ip": source_ip,
        "username": values.get("TargetUserName") or "Unknown",
        "event_type": "login",
        "status": status,
        "location": "Windows host",
        "event_id": event_id,
        "logon_type": values.get("LogonType") or "Unknown",
        "hostname": hostname or "Unknown",
        "record_id": record_id,
        "raw_event": raw_xml,
    }


def _normalise_timestamp(value: str) -> str:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return value
