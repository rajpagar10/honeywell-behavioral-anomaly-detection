"""Honeywell Behavioral Security analyst dashboard."""

from typing import Any

import streamlit as st
from api_client import APIUnavailableError, SOCAPIClient
from components import (
    SEVERITY_ORDER,
    alert_detail,
    alert_queue,
    cold_drift_summary,
    entity_view,
    evaluation_view,
    health_view,
    live_operations,
    metric_row,
    overview_charts,
)

st.set_page_config(
    page_title="Honeywell Behavioral Security",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _style() -> None:
    """Apply a polished industrial SOC visual system."""

    st.markdown(
        """
        <style>
        :root { --hw-red:#e31b23; --panel:#151e2b; --line:#2a3748; }
        .stApp { background: radial-gradient(circle at 80% 0%, #1b2636 0%, #0b111a 38%); }
        [data-testid="stSidebar"] { background:#0d141e; border-right:1px solid var(--line); }
        [data-testid="stMetric"] {
          background:linear-gradient(145deg,#172231,#111924); border:1px solid var(--line);
          border-radius:10px; padding:15px; box-shadow:0 10px 25px rgba(0,0,0,.18);
        }
        [data-testid="stMetricValue"] { color:#f5f7fa; }
        .hw-kicker { color:var(--hw-red); letter-spacing:.16em; font-weight:700; font-size:.78rem; }
        .hw-title { font-size:2rem; font-weight:750; margin:.15rem 0; }
        .hw-subtitle { color:#94a3b8; margin-bottom:1rem; }
        .stButton>button[kind="primary"] { background:var(--hw-red); border-color:var(--hw-red); }
        hr { border-color:var(--line); }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _load(client: SOCAPIClient) -> dict[str, Any]:
    """Load one consistent dashboard snapshot."""

    try:
        replay = client.get("/api/v1/replay/status")
    except APIUnavailableError:
        replay = None
    return {
        "health": client.get("/health"),
        "ready": client.get("/ready"),
        "summary": client.get("/api/v1/dashboard/summary"),
        "events": client.get("/api/v1/events/recent?limit=100"),
        "alerts": client.get("/api/v1/alerts?limit=500"),
        "metrics": client.get("/api/v1/evaluation/metrics"),
        "replay": replay,
    }


def main() -> None:
    """Render the interactive analyst experience."""

    _style()
    st.markdown('<div class="hw-kicker">HONEYWELL CAMPUS CONNECT</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="hw-title">Behavioral Security Operations</div>', unsafe_allow_html=True
    )
    st.markdown(
        '<div class="hw-subtitle">Explainable anomaly detection for identities, '
        "industrial edge systems, and connected devices.</div>",
        unsafe_allow_html=True,
    )
    with st.sidebar:
        st.markdown("### Control center")
        api_url = st.text_input("API URL", "http://127.0.0.1:8000")
        st.button("Refresh data", use_container_width=True)
        st.caption("Use browser refresh or this control while replay is running.")
    client = SOCAPIClient(api_url)
    try:
        data = _load(client)
    except APIUnavailableError as error:
        st.error(str(error))
        st.code("badp serve\nstreamlit run dashboard/app.py", language="bash")
        st.stop()

    metric_row(data["summary"])
    cold_drift_summary(data["alerts"])
    tabs = st.tabs(
        [
            "Executive Overview",
            "Live Operations",
            "Alert Investigation",
            "Entity Behavior",
            "Model Evaluation",
            "System Health",
        ]
    )
    with tabs[0]:
        overview_charts(data["alerts"])
    with tabs[1]:
        live_operations(client, data["events"], data["replay"])
    with tabs[2]:
        severities = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER[:3])
        attack_types = sorted({alert["attack_type"] for alert in data["alerts"]})
        attacks = st.multiselect("Attack type", attack_types)
        entity = st.text_input("Entity contains")
        filtered = alert_queue(data["alerts"], severities, attacks, entity)
        if filtered:
            alert_id = st.selectbox(
                "Investigate alert",
                [alert["alert_id"] for alert in filtered],
                format_func=lambda value: next(
                    f"{item['risk_score']:.1f} · {item['attack_type']} · {item['entity_id']}"
                    for item in filtered
                    if item["alert_id"] == value
                ),
            )
            alert_detail(client.get(f"/api/v1/alerts/{alert_id}"))
    with tabs[3]:
        entity_view(client, data["alerts"])
    with tabs[4]:
        evaluation_view(data["metrics"])
    with tabs[5]:
        health_view(data["health"], data["ready"], data["replay"])


if __name__ == "__main__":
    main()
