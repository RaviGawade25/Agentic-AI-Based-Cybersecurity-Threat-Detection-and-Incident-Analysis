import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "source_ip", "username", "event_type", "status", "location"]

def normalize_dataframe(df: pd.DataFrame):
    errors = []
    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        return pd.DataFrame(), [f"Missing required column: {column}" for column in missing]
    optional_columns = [
        column for column in df.columns if column not in REQUIRED_COLUMNS
    ]
    clean = df[REQUIRED_COLUMNS + optional_columns].copy()
    if clean.empty:
        return clean, ["The CSV contains no event rows."]
    for column in REQUIRED_COLUMNS:
        clean[column] = clean[column].fillna("").astype(str).str.strip()
        if (clean[column] == "").any():
            errors.append(f"Column '{column}' contains blank values.")
    clean["status"] = clean["status"].str.lower()
    invalid_status = sorted(set(clean.loc[~clean["status"].isin(["success", "failed"]), "status"]))
    if invalid_status:
        errors.append("Status must be 'success' or 'failed'. Invalid values: " + ", ".join(invalid_status))
    parsed = pd.to_datetime(clean["timestamp"], errors="coerce")
    if parsed.isna().any():
        errors.append("One or more timestamps are invalid. Use a format such as 2026-11-01T09:00:00.")
    clean["timestamp"] = parsed.astype(str)
    clean["event_type"] = clean["event_type"].str.lower()
    return clean, errors
