"""Persistent evidence-grounded Investigation Copilot panel."""

from html import escape
from typing import Any
from urllib.parse import quote

import streamlit as st
from api_client import SOCAPIClient
from theme import labelize

QUESTIONS = {
    "Summarize this alert": "executive_summary",
    "Why was this alert generated?": "why_generated",
    "Which behaviors were abnormal?": "abnormal_behaviors",
    "Why is the risk score high?": "high_risk_score",
    "Could this be concept drift?": "concept_drift",
    "What should I investigate first?": "investigate_first",
}
FEEDBACK = {
    "Confirmed Threat": "confirmed_threat",
    "False Positive": "false_positive",
    "Benign": "benign",
    "Needs Investigation": "needs_investigation",
}


def render_global_copilot(
    client: SOCAPIClient,
    alerts: list[dict[str, Any]],
) -> None:
    """Render a persistent right-side copilot for the active alert."""

    st.markdown('<span class="copilot-marker"></span>', unsafe_allow_html=True)
    st.markdown(
        '<div class="copilot-heading">'
        '<span class="copilot-orb">✦</span>'
        "<div><strong>AI Investigation Copilot</strong>"
        "<small>Analyst verification required</small></div></div>",
        unsafe_allow_html=True,
    )
    if not alerts:
        st.info("The copilot will activate when the first alert is generated.")
        return

    alert_by_id = {str(alert["alert_id"]): alert for alert in alerts}
    default_id = str(alerts[0]["alert_id"])
    selected_id = str(st.session_state.get("copilot_alert_id", default_id))
    if selected_id not in alert_by_id:
        selected_id = default_id
        st.session_state["copilot_alert_id"] = selected_id
    selected_id = st.selectbox(
        "Alert context",
        list(alert_by_id),
        index=list(alert_by_id).index(selected_id),
        format_func=lambda value: _alert_label(alert_by_id[value]),
        key="copilot_alert_id",
    )
    selected = alert_by_id[selected_id]
    st.markdown(
        f'<div class="copilot-risk {escape(str(selected["severity"]))}">'
        f"<span>{escape(labelize(selected['severity']).upper())} RISK ALERT</span>"
        f"<strong>{float(selected['risk_score']):.0f}<small>/100</small></strong>"
        f"<p>{escape(labelize(selected['attack_type']))} · "
        f"{escape(str(selected['entity_id']))}</p></div>",
        unsafe_allow_html=True,
    )

    selected_question = st.selectbox(
        "Ask about this alert",
        list(QUESTIONS),
        key="copilot_question",
    )
    question = QUESTIONS[selected_question]
    investigation = _load_investigation(client.base_url, selected_id, question)

    with st.chat_message("assistant", avatar="🛡️"):
        st.markdown(f"**{investigation['summary']}**")
        st.write(investigation["answer"])
    st.caption(f"{labelize(investigation['provider'])} · {investigation['disclaimer']}")

    st.markdown("**Recommended actions**")
    for index, action in enumerate(investigation["recommendations"], start=1):
        st.checkbox(
            action,
            key=f"copilot_action_{selected_id}_{index}",
        )

    with st.expander("Evidence and deviations"):
        evidence = investigation["evidence"]
        _evidence_line("Source IP", evidence.get("source_ip"))
        _evidence_line("Current location", _location(evidence.get("geo_location")))
        _evidence_line("Previous location", _location(evidence.get("previous_location")))
        _evidence_line("Device", evidence.get("device_fingerprint"))
        _evidence_line("Resource", evidence.get("resource_accessed"))
        _evidence_line("Failed logins (7d)", evidence.get("failed_logins"))
        _evidence_line("Cold start", evidence.get("cold_start"))
        _evidence_line("Drift", evidence.get("drift_status"))
        st.markdown("**Behavioral deviations**")
        for value in investigation["behavioral_deviations"]:
            st.markdown(f"- {value}")

    with st.expander("Investigation timeline"):
        for index, event in enumerate(investigation["timeline"]):
            st.markdown(
                f"**{event['title']}**  \n<small>{event['timestamp']}</small>  \n{event['detail']}",
                unsafe_allow_html=True,
            )
            if index < len(investigation["timeline"]) - 1:
                st.markdown('<div class="copilot-arrow">↓</div>', unsafe_allow_html=True)

    st.markdown("**Analyst feedback**")
    rows = [st.columns(2), st.columns(2)]
    for index, (label, feedback) in enumerate(FEEDBACK.items()):
        column = rows[index // 2][index % 2]
        if column.button(
            label,
            key=f"copilot_{feedback}_{selected_id}",
            use_container_width=True,
        ):
            receipt = client.post(
                f"/api/v1/alerts/{selected_id}/investigation",
                {"feedback": feedback},
            )
            st.toast(
                f"{label} stored at {receipt['timestamp']}.",
                icon="✔️",
            )


@st.cache_data(ttl=30, show_spinner=False)
def _load_investigation(
    base_url: str,
    alert_id: str,
    question: str,
) -> dict[str, Any]:
    """Load and briefly cache one grounded copilot response."""

    client = SOCAPIClient(base_url)
    response: dict[str, Any] = client.get(
        f"/api/v1/alerts/{alert_id}/investigation?question={quote(question)}"
    )
    return response


def _alert_label(alert: dict[str, Any]) -> str:
    """Build a compact alert-context selector label."""

    return (
        f"{float(alert['risk_score']):.0f} · "
        f"{labelize(alert['attack_type'])} · {alert['entity_id']}"
    )


def _evidence_line(label: str, value: object) -> None:
    """Render one supplied evidence value without inference."""

    visible = "Insufficient evidence available." if value is None else str(value)
    st.markdown(f"**{label}:** {visible}")


def _location(value: dict[str, Any] | None) -> str | None:
    """Format a supplied location without inventing missing fields."""

    if not value:
        return None
    return f"{value.get('city')}, {value.get('country_code')}"
