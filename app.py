import pandas as pd
import streamlit as st
from graph.workflow import build_security_graph
from tools.log_parser import normalize_dataframe, REQUIRED_COLUMNS
from tools.windows_event_collector import (
    WindowsEventCollector,
    WindowsEventCollectorError,
)
from tools.public_dataset import download_public_openssh_dataset

st.set_page_config(page_title="Cybersecurity Multi-Agent SOC", page_icon="🛡️", layout="wide")
st.title("🛡️ Cybersecurity Multi-Agent Analysis System")
st.caption("LangGraph orchestration • CSV + manual event input • Explainable detection")

st.info(
    "This educational prototype analyses authentication logs using transparent detection rules. "
    "It does not block accounts, modify systems, or replace a production SIEM/SOC."
)

if "live_events" not in st.session_state:
    st.session_state["live_events"] = []
if "windows_collector" not in st.session_state:
    st.session_state["windows_collector"] = WindowsEventCollector()


def analyze(df):
    clean_df, errors = normalize_dataframe(df)
    if errors:
        st.error("Input validation failed:\n\n" + "\n".join(errors))
        return
    graph = build_security_graph()
    result = graph.invoke({
        "events": clean_df.to_dict(orient="records"),
        "summary": {},
        "alerts": [],
        "investigation": [],
        "report": ""
    })
    st.session_state["analysis_result"] = result
    st.session_state["clean_df"] = clean_df

def analyze_live_events(events):
    if not events:
        return
    clean_df, errors = normalize_dataframe(pd.DataFrame(events))
    if errors:
        st.error("Collected event validation failed:\n\n" + "\n".join(errors))
        return
    result = build_security_graph().invoke({
        "events": clean_df.to_dict(orient="records"),
        "summary": {},
        "alerts": [],
        "investigation": [],
        "report": "",
    })
    st.session_state["live_result"] = result
    st.session_state["live_clean_df"] = clean_df


def collect_live_events():
    try:
        new_events = st.session_state["windows_collector"].poll()
    except WindowsEventCollectorError as exc:
        st.error(str(exc))
        return
    known_ids = {
        event.get("record_id")
        for event in st.session_state["live_events"]
    }
    unique_events = [
        event for event in new_events if event.get("record_id") not in known_ids
    ]
    st.session_state["live_events"].extend(unique_events)
    if st.session_state["live_events"]:
        analyze_live_events(st.session_state["live_events"])
    st.session_state["last_collection_count"] = len(unique_events)


@st.fragment(run_every="10s")
def render_live_monitoring():
    with st.container(border=True):
        st.header("🔴 Live Windows monitoring")
        st.caption(
            "Reads actual Windows Security events 4624 (success) and 4625 (failure). "
            "This collector is read-only and requires permission to read the Security log."
        )
        auto_collect = st.checkbox(
            "Automatically poll every 10 seconds",
            value=False,
            help="The dashboard will read new authorized Windows events without creating any events.",
        )
        if auto_collect or st.button("Collect new Windows events", type="primary"):
            collect_live_events()
        if st.session_state.get("last_collection_count") is not None:
            st.write(
                f"New events in the last collection: "
                f"{st.session_state['last_collection_count']}"
            )
        live_result = st.session_state.get("live_result")
        if live_result:
            summary = live_result["summary"]
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Events collected", summary.get("total_events", 0))
            m2.metric("Successful logins", summary.get("successful_logins", 0))
            m3.metric("Failed logins", summary.get("failed_logins", 0))
            m4.metric("Alerts", len(live_result["alerts"]))
            if live_result["alerts"]:
                for alert in live_result["alerts"]:
                    st.warning(
                        f"{alert['severity']} — {alert['title']}: "
                        f"{alert['description']}"
                    )
            st.dataframe(
                st.session_state["live_clean_df"].tail(20),
                use_container_width=True,
            )
        else:
            st.info("No live events have been collected yet.")


render_live_monitoring()

tab1, tab2 = st.tabs(["📁 Upload CSV", "✍️ Enter an event"])

with tab1:
    st.subheader("Upload authentication log file")
    st.write("Required columns: " + ", ".join(REQUIRED_COLUMNS))
    if st.button("Download public OpenSSH threat dataset"):
        try:
            dataset_path = download_public_openssh_dataset()
            st.success(f"Downloaded public data to {dataset_path}. Upload it below.")
        except RuntimeError as exc:
            st.error(str(exc))
    uploaded = st.file_uploader("Choose a CSV file", type=["csv"])
    if uploaded is not None:
        try:
            input_df = pd.read_csv(uploaded)
            st.dataframe(input_df, use_container_width=True)
            if st.button("Analyse uploaded logs", type="primary"):
                analyze(input_df)
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")

with tab2:
    st.subheader("Add one security event")
    with st.form("manual_event"):
        c1, c2 = st.columns(2)
        timestamp = c1.text_input("Timestamp", "2026-11-01T10:00:00")
        source_ip = c2.text_input("Source IP", "192.168.1.100")
        username = c1.text_input("Username", "alice")
        event_type = c2.selectbox("Event type", ["login"])
        status = c1.selectbox("Status", ["failed", "success"])
        location = c2.text_input("Location", "Hubli")
        submitted = st.form_submit_button("Analyse event", type="primary")
    if submitted:
        analyze(pd.DataFrame([{
            "timestamp": timestamp, "source_ip": source_ip, "username": username,
            "event_type": event_type, "status": status, "location": location
        }]))

if "analysis_result" in st.session_state:
    result = st.session_state["analysis_result"]
    st.divider()
    st.header("Analysis results")
    summary = result["summary"]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Events analysed", summary.get("total_events", 0))
    m2.metric("Failed logins", summary.get("failed_logins", 0))
    m3.metric("Unique source IPs", summary.get("unique_source_ips", 0))
    m4.metric("Alerts", len(result["alerts"]))

    st.subheader("Detected alerts")
    if result["alerts"]:
        for alert in result["alerts"]:
            with st.container(border=True):
                st.markdown(f"**{alert['severity']} — {alert['title']}**")
                st.write(alert["description"])
                st.caption("Evidence: " + alert["evidence"])
        st.subheader("Investigation")
        for item in result["investigation"]:
            st.write(f"- {item}")
    else:
        st.success("No configured suspicious pattern was detected in the supplied events.")

    st.subheader("Normalized events")
    st.dataframe(st.session_state["clean_df"], use_container_width=True)

    st.subheader("Incident report")
    st.text_area("Generated report", result["report"], height=300)
    st.download_button(
        "Download incident report",
        data=result["report"],
        file_name="incident_report.txt",
        mime="text/plain"
    )
    st.download_button(
        "Download normalized events",
        data=st.session_state["clean_df"].to_csv(index=False),
        file_name="normalized_events.csv",
        mime="text/csv"
    )
