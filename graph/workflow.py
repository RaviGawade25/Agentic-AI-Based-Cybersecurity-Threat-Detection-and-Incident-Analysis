from langgraph.graph import StateGraph, START, END
from graph.state import SecurityState
from agents.log_analyst import log_analyst
from agents.threat_detector import threat_detector
from agents.investigator import investigator
from agents.reporter import incident_reporter

def route_after_detection(state: SecurityState) -> str:
    return "investigate" if state["alerts"] else "report"

def build_security_graph():
    builder = StateGraph(SecurityState)
    builder.add_node("log_analyst", log_analyst)
    builder.add_node("threat_detector", threat_detector)
    builder.add_node("investigator", investigator)
    builder.add_node("incident_reporter", incident_reporter)

    builder.add_edge(START, "log_analyst")
    builder.add_edge("log_analyst", "threat_detector")
    builder.add_conditional_edges(
        "threat_detector",
        route_after_detection,
        {"investigate": "investigator", "report": "incident_reporter"}
    )
    builder.add_edge("investigator", "incident_reporter")
    builder.add_edge("incident_reporter", END)
    return builder.compile()
