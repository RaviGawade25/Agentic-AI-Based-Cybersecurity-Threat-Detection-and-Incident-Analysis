from typing import TypedDict, Any

class SecurityState(TypedDict):
    events: list[dict[str, Any]]
    summary: dict[str, Any]
    alerts: list[dict[str, str]]
    investigation: list[str]
    report: str
