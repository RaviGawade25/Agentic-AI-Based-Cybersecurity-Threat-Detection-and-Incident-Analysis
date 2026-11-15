from collections import Counter

def log_analyst(state):
    events = state["events"]
    failed = [e for e in events if e["status"].lower() == "failed"]
    successful = [e for e in events if e["status"].lower() == "success"]
    summary = {
        "total_events": len(events),
        "failed_logins": len(failed),
        "successful_logins": len(successful),
        "unique_source_ips": len({e["source_ip"] for e in events}),
        "failures_by_ip": dict(Counter(e["source_ip"] for e in failed)),
        "failures_by_user": dict(Counter(e["username"] for e in failed)),
    }
    return {"summary": summary}
