import pandas as pd

from graph.workflow import build_security_graph
from tools.log_parser import normalize_dataframe


def test_workflow_reports_brute_force_and_password_spraying_alerts():
    source = pd.read_csv("data/sample_auth_logs.csv")
    clean, errors = normalize_dataframe(source)
    assert errors == []

    result = build_security_graph().invoke(
        {
            "events": clean.to_dict(orient="records"),
            "summary": {},
            "alerts": [],
            "investigation": [],
            "report": "",
        }
    )

    assert {alert["severity"] for alert in result["alerts"]} == {"HIGH", "MEDIUM"}
    assert len(result["investigation"]) == 4
    assert "CYBERSECURITY EVENT ANALYSIS REPORT" in result["report"]
