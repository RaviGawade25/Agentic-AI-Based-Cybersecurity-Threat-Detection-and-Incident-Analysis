# Agentic AI Cybersecurity Threat Detection and Incident Analysis

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

An educational, defensive security analytics application that uses a
LangGraph workflow to normalize authentication events, identify explainable
brute-force and password-spraying patterns, and produce an incident report.

> **Important:** This is a research and learning prototype, not a production
> SIEM, incident-response platform, or autonomous containment system. Alerts
> require validation by an authorized security professional.

## What it does

- Accepts normalized authentication events from CSV upload or a manual form.
- Optionally reads Windows Security logon events `4624` and `4625` in
  read-only mode.
- Downloads and normalizes the public LogHub OpenSSH benchmark.
- Calculates event statistics and applies transparent, deterministic rules:
  - **HIGH:** five or more failed logins from one source IP.
  - **MEDIUM:** failed logins from one source IP targeting four or more users.
- Runs investigation guidance only when an alert is raised.
- Displays and downloads normalized events and a plain-text incident report.

The application does not block accounts, change audit policy, modify event logs,
execute response actions, or query live threat-intelligence services.

## Architecture

```text
CSV / manual event / Windows Security log / public benchmark
                              |
                       Input normalization
                              |
                         LangGraph workflow
                              |
       Log Analyst -> Threat Detector -> (Investigator) -> Reporter
                              |
                    Dashboard and downloadable report
```

## Requirements

- Python 3.10 or newer (the project is developed against Python 3.11).
- Windows, macOS, or Linux for the dashboard and CSV workflows.
- Windows Security monitoring additionally requires Windows and permission to
  read the Security event log.
- Internet access is required only to install dependencies or download the
  optional public OpenSSH benchmark.

## Quick start

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL shown by Streamlit, normally
`http://localhost:8501`.

If PowerShell prevents activation, use the following only for the current
terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Using the application

1. Select **Upload CSV** and upload `data/sample_auth_logs.csv`, or enter one
   event manually.
2. Click **Analyse uploaded logs**.
3. Review the event metrics, alert evidence, investigation guidance, and report.
4. Use the download controls to export the normalized events or report.

The required CSV columns are:

| Column | Description |
| --- | --- |
| `timestamp` | Parseable event date/time, such as `2026-11-01T09:00:00` |
| `source_ip` | Source IP or host identifier |
| `username` | Account involved in the event |
| `event_type` | Event type, currently `login` |
| `status` | `success` or `failed` |
| `location` | Location label, or `Unknown` |

`data/sample_auth_logs.csv` is synthetic demonstration data. It intentionally
contains repeated failures so that both configured alert patterns can be
observed.

### Optional Windows monitoring

The **Live Windows monitoring** section polls authorized Windows Security
events every 10 seconds when enabled. It reads only event IDs `4624`
(successful logon) and `4625` (failed logon). A local bookmark prevents the
same record from being analyzed twice; the bookmark is ignored by Git and
must not be committed.

### Optional public dataset

Use **Download public OpenSSH threat dataset** to retrieve the LogHub
benchmark, then upload `data/public_openssh_logs.csv`. The source records are
retained in `raw_event` and their source IDs in `event_id`.

Source: [LogHub OpenSSH dataset](https://github.com/logpai/loghub-2.0/tree/main/2k_dataset/OpenSSH)

## Development

Run the focused test suite from the repository root:

```powershell
pip install -r requirements-dev.txt
python -m pytest -q
```

The GitHub Actions workflow runs the same tests on supported Python versions.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Project layout

```text
app.py                       Streamlit application
agents/                      Analysis and reporting nodes
graph/                       LangGraph state and workflow
tools/                       Input parsing and data collectors
data/sample_auth_logs.csv    Synthetic demonstration events
tests/                       Focused regression tests
```

## Responsible use and limitations

- Thresholds are illustrative heuristics and are not calibrated for a
  production environment.
- An alert is not proof of compromise. Check maintenance windows, VPN logs,
  identity-provider records, and other trusted context.
- Do not upload personal, regulated, or confidential logs without authorization
  and appropriate data handling controls.
- Generated reports and local Windows bookmarks are runtime artifacts and are
  excluded from version control.
- Contributions must preserve the read-only and defensive nature of the
  project.

## License

This project is released under the [MIT License](LICENSE).
