"""Download and normalize a public OpenSSH security-log dataset."""

from __future__ import annotations

import io
import re
import urllib.request
from pathlib import Path

import pandas as pd

PUBLIC_OPENSSH_URL = (
    "https://raw.githubusercontent.com/logpai/loghub-2.0/main/"
    "2k_dataset/OpenSSH/OpenSSH_2k.log_structured_corrected.csv"
)


def download_public_openssh_dataset(
    destination: Path = Path("data/public_openssh_logs.csv"),
) -> Path:
    """Download LogHub OpenSSH logs and convert authentication events."""

    request = urllib.request.Request(
        PUBLIC_OPENSSH_URL,
        headers={"User-Agent": "agentic-security-course-project"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            source = response.read()
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Could not download the public OpenSSH dataset. "
            "Check internet access and try again."
        ) from exc

    converted = normalize_public_openssh(pd.read_csv(io.BytesIO(source)))
    if converted.empty:
        raise RuntimeError("The public dataset contained no authentication events.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    converted.to_csv(destination, index=False)
    return destination


def normalize_public_openssh(source: pd.DataFrame) -> pd.DataFrame:
    """Keep authentication records and map them to the application schema."""

    rows = []
    for _, record in source.iterrows():
        content = str(record.get("Content", ""))
        failed = any(
            phrase in content.lower()
            for phrase in (
                "failed password",
                "authentication failure",
                "possible break-in attempt",
                "invalid user",
            )
        )
        successful = "accepted password" in content.lower()
        if not (failed or successful):
            continue
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
        user_match = re.search(
            r"(?:for (?:invalid user )?|user=)([A-Za-z0-9._-]+)",
            content,
            flags=re.IGNORECASE,
        )
        rows.append(
            {
                "timestamp": f"2024-{record['Date']}-{int(record['Day']):02d}T{record['Time']}",
                "source_ip": ip_match.group(0) if ip_match else "Unknown",
                "username": user_match.group(1) if user_match else "Unknown",
                "event_type": "ssh_login",
                "status": "success" if successful else "failed",
                "location": "Public OpenSSH benchmark",
                "event_id": str(record.get("EventId", "")),
                "hostname": str(record.get("Component", "")),
                "raw_event": content,
            }
        )
    return pd.DataFrame(rows)
