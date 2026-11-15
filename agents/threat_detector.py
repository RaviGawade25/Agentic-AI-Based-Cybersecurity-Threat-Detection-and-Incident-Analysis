def threat_detector(state):
    summary = state["summary"]
    alerts = []

    # Educational heuristic: 5 or more failed attempts from one IP.
    for ip, count in summary["failures_by_ip"].items():
        if count >= 5:
            supporting = [
                event for event in state["events"]
                if event["status"].lower() == "failed"
                and event["source_ip"] == ip
            ]
            alerts.append({
                "severity": "HIGH",
                "title": "Possible brute-force login activity",
                "description": f"{count} failed login attempts were recorded from one source IP.",
                "evidence": (
                    f"source_ip={ip}; failed_attempts={count}; "
                    f"timestamps={[event['timestamp'] for event in supporting]}; "
                    f"event_ids={[event.get('event_id', 'not supplied') for event in supporting]}"
                )
            })

    # Educational heuristic: 4 or more distinct usernames targeted by one IP.
    events = state["events"]
    failed_events = [e for e in events if e["status"].lower() == "failed"]
    users_by_ip = {}
    for event in failed_events:
        users_by_ip.setdefault(event["source_ip"], set()).add(event["username"])
    for ip, users in users_by_ip.items():
        if len(users) >= 4:
            supporting = [
                event for event in failed_events
                if event["source_ip"] == ip and event["username"] in users
            ]
            alerts.append({
                "severity": "MEDIUM",
                "title": "Possible password-spraying pattern",
                "description": f"Failed attempts from one IP targeted {len(users)} distinct usernames.",
                "evidence": (
                    f"source_ip={ip}; usernames={', '.join(sorted(users))}; "
                    f"timestamps={[event['timestamp'] for event in supporting]}; "
                    f"event_ids={[event.get('event_id', 'not supplied') for event in supporting]}"
                )
            })

    return {"alerts": alerts}
