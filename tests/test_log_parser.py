import pandas as pd

from tools.log_parser import normalize_dataframe


def test_normalize_dataframe_accepts_valid_events():
    source = pd.DataFrame(
        [
            {
                "timestamp": "2026-11-01T09:00:00",
                "source_ip": "203.0.113.50",
                "username": "admin",
                "event_type": "LOGIN",
                "status": "FAILED",
                "location": "Unknown",
            }
        ]
    )

    clean, errors = normalize_dataframe(source)

    assert errors == []
    assert clean.loc[0, "status"] == "failed"
    assert clean.loc[0, "event_type"] == "login"


def test_normalize_dataframe_reports_missing_and_invalid_values():
    source = pd.DataFrame(
        [
            {
                "timestamp": "not-a-date",
                "source_ip": "",
                "username": "admin",
                "event_type": "login",
                "status": "blocked",
                "location": "Unknown",
            }
        ]
    )

    _, errors = normalize_dataframe(source)

    assert "Column 'source_ip' contains blank values." in errors
    assert any("Status must be 'success' or 'failed'." in error for error in errors)
    assert any("timestamps are invalid" in error for error in errors)
