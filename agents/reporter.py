from datetime import datetime, timezone
from pathlib import Path

def incident_reporter(state):
    s = state["summary"]
    generated_at = datetime.now(timezone.utc)
    lines = [
        "CYBERSECURITY EVENT ANALYSIS REPORT",
        "=" * 40,
        f"Generated (UTC): {generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "1. EXECUTIVE SUMMARY",
        f"Events analysed: {s.get('total_events', 0)}",
        f"Failed logins: {s.get('failed_logins', 0)}",
        f"Successful logins: {s.get('successful_logins', 0)}",
        f"Unique source IPs: {s.get('unique_source_ips', 0)}",
        f"Alerts generated: {len(state['alerts'])}",
        "",
        "2. DETECTION RESULTS",
    ]
    if state["alerts"]:
        for i, alert in enumerate(state["alerts"], 1):
            lines.extend([
                f"{i}. [{alert['severity']}] {alert['title']}",
                f"   Description: {alert['description']}",
                f"   Evidence: {alert['evidence']}",
            ])
    else:
        lines.append("No configured detection rule was triggered.")
    lines.extend(["", "3. INVESTIGATION NOTES"])
    if state["investigation"]:
        lines.extend(f"- {item}" for item in state["investigation"])
    else:
        lines.append("- No additional investigation was triggered.")
    lines.extend([
        "",
        "4. LIMITATIONS",
        "- This prototype uses fixed heuristic thresholds, not a trained threat model.",
        "- A detected pattern is an alert for review, not proof of an attack.",
        "- Results depend on the completeness and correctness of the input logs.",
        "- No automatic containment or system modification is performed.",
    ])
    report = "\n".join(lines)
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / (
        f"incident_report_{generated_at.strftime('%Y%m%d_%H%M%S_%f')}.txt"
    )
    report_path.write_text(report, encoding="utf-8")
    return {"report": report}
