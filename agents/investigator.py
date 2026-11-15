def investigator(state):
    findings = []
    for alert in state["alerts"]:
        findings.append(
            f"{alert['title']}: {alert['description']} Evidence: {alert['evidence']}"
        )
    findings.append(
        "Recommended validation: compare the timestamps with approved maintenance, "
        "VPN, and identity-provider records before treating the activity as confirmed malicious."
    )
    findings.append(
        "Suggested defensive actions: review the source IP, check affected accounts, "
        "enforce MFA, and apply rate limiting or temporary account protection under your organisation's policy."
    )
    return {"investigation": findings}
