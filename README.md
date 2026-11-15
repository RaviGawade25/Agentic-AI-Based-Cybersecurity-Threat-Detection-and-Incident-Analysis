# Cybersecurity Multi-Agent Analysis System

A beginner-friendly defensive security-log analysis project built with Python, LangGraph, and Streamlit.

## Features
- Upload authentication logs as CSV.
- Enter one event manually.
- Read-only polling of real Windows Security events 4624 and 4625.
- Local event bookmark to prevent duplicate Windows event ingestion.
- Download and analyse a public OpenSSH security-log benchmark from LogHub.
- Validate and normalize input.
- LangGraph workflow with four specialist nodes:
  1. Log Analyst — calculates event statistics.
  2. Threat Detector — applies explainable heuristics.
  3. Investigator — provides validation steps and defensive recommendations.
  4. Incident Reporter — generates a downloadable report.
- Conditional workflow: investigation runs only when a detection rule triggers.
- Download incident report and normalized CSV.

## Requirements
- Python 3.10 or newer (tested design target: Python 3.11)
- Internet connection for the initial package installation
- Windows, macOS, or Linux

## Setup on Windows PowerShell

Open the terminal in this project folder.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The live collector uses PowerShell and requires permission to read the Windows
Security event log; run VS Code with an authorized Windows account if access is
denied.

If PowerShell blocks activation, run this once in the current terminal:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Run the application

```powershell
streamlit run app.py
```

Streamlit will display a local URL, usually `http://localhost:8501`. Open it in your browser.

## Test the project
Upload `data/sample_auth_logs.csv` in the CSV tab. The sample is synthetic and deliberately contains repeated failed logins to demonstrate the alert workflow.

To test real telemetry, open the **Live Windows monitoring** section and select
**Collect new Windows events**. The collector reads only events already present
on the authorized Windows machine. It does not create attacks, block accounts,
change audit policy, or modify the event log. Events are limited to:

- `4624`: successful logon
- `4625`: failed logon

The last processed Windows record ID is stored in
`data/windows_security_bookmark.json` so the same event is not analysed again.
This bookmark is local state and should not be committed to source control.

## Public internet dataset

The CSV tab includes **Download public OpenSSH threat dataset**. It downloads
the OpenSSH benchmark published by LogHub from GitHub, then keeps authentication
records such as failed passwords, invalid users, authentication failures, and
possible break-in attempts. This is public benchmark telemetry, not data
collected from your laptop and not a live attack feed.

Source:
https://github.com/logpai/loghub-2.0/tree/main/2k_dataset/OpenSSH

After downloading, upload `data/public_openssh_logs.csv` in the same tab.
The source records are retained in the `raw_event` column and the source
EventId is retained in `event_id`.

Expected demonstration:
- 12 events
- 9 failed logins
- 2 source IPs
- One HIGH possible brute-force alert (5 failures from one IP)
- One MEDIUM possible password-spraying alert (4 usernames targeted)

## CSV format

The file must contain these exact columns:

`timestamp,source_ip,username,event_type,status,location`

- `timestamp`: date/time, e.g. `2026-11-01T09:00:00`
- `source_ip`: source IP string
- `username`: account name
- `event_type`: currently `login`
- `status`: `success` or `failed`
- `location`: location label if available, otherwise `Unknown`

## Architecture

```text
CSV upload / Manual event
          |
     Input validation
          |
       LangGraph
          |
      Log Analyst
          |
     Threat Detector
          |
    Conditional routing
       /         \
  Investigator   (no alert)
       \         /
     Incident Reporter
          |
       Final report
```

## Important limitations
- Detection thresholds are illustrative heuristics, not a validated production detection engine.
- The system does not use an LLM in this initial version. The specialist agents are Python functions orchestrated by LangGraph.
- The live collector currently supports Windows Security logon events only; it
  does not claim to collect Linux, Sysmon, or SAE telemetry.
- It does not query live threat intelligence, block IPs, disable accounts, or execute response actions.
- Validate alerts against trusted organisational context before acting.
