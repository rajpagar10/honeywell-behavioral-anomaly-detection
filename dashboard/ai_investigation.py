"""AI-assisted, evidence-grounded alert investigation panel."""

from typing import Any
from urllib.parse import quote

import pandas as pd
import streamlit as st
from api_client import SOCAPIClient
from theme import labelize, section_header

QUESTIONS = {
    "Why was this alert generated?": "why_generated",
    "Which behaviors were abnormal?": "abnormal_behaviors",
    "Why is the risk score high?": "high_risk_score",
    "Could this be concept drift?": "concept_drift",
    "What should I investigate first?": "investigate_first",
}
FEEDBACK = {
    "✔ Confirmed Threat": "confirmed_threat",
    "✔ False Positive": "false_positive",
    "✔ Benign": "benign",
    "✔ Needs Investigation": "needs_investigation",
}


def render_ai_investigation(client: SOCAPIClient, alert_id: str) -> None:
    """Render the bounded Investigation Copilot and feedback controls."""

    st.divider()
    section_header(
        "AI Investigation",
        "Evidence-grounded assistance built on the existing detection result.",
    )
    st.markdown(
        '<div class="hw-callout"><strong>AI Assisted Investigation</strong><br>'
        "Analyst verification required.</div>",
        unsafe_allow_html=True,
    )
    selected_label = st.selectbox(
        "Predefined analyst question",
        list(QUESTIONS),
        key=f"ai_question_{alert_id}",
    )
    question = QUESTIONS[selected_label]
    investigation = client.get(
        f"/api/v1/alerts/{alert_id}/investigation?question={quote(question)}"
    )

    st.subheader("Executive Summary")
    st.write(investigation["summary"])
    provider = labelize(investigation["provider"])
    st.caption(f"Response mode: {provider} · {investigation['disclaimer']}")
    st.info(investigation["answer"])

    why, deviations = st.columns(2)
    with why:
        st.subheader("Why the alert was generated")
        _bullet_list(investigation["why_generated"])
    with deviations:
        st.subheader("Behavioral deviations")
        _bullet_list(investigation["behavioral_deviations"])

    evidence, actions = st.columns([1.4, 1])
    with evidence:
        st.subheader("Evidence")
        st.dataframe(
            _evidence_frame(investigation["evidence"]),
            use_container_width=True,
            hide_index=True,
        )
    with actions:
        st.subheader("Recommended actions")
        _bullet_list(investigation["recommendations"])

    st.subheader("Investigation timeline")
    for index, event in enumerate(investigation["timeline"]):
        st.markdown(f"**{event['title']}**  \n{event['timestamp']}  \n{event['detail']}")
        if index < len(investigation["timeline"]) - 1:
            st.markdown("↓")

    st.subheader("Analyst feedback")
    columns = st.columns(4)
    for column, (label, feedback) in zip(columns, FEEDBACK.items(), strict=True):
        if column.button(label, key=f"{feedback}_{alert_id}", use_container_width=True):
            receipt = client.post(
                f"/api/v1/alerts/{alert_id}/investigation",
                {"feedback": feedback},
            )
            st.success(f"{label.removeprefix('✔ ').strip()} stored at {receipt['timestamp']}.")


def _bullet_list(values: list[str]) -> None:
    """Render a compact list of grounded statements."""

    for value in values:
        st.markdown(f"- {value}")


def _evidence_frame(evidence: dict[str, Any]) -> pd.DataFrame:
    """Flatten the allowlisted evidence object for analyst review."""

    fields = [
        ("Entity", evidence.get("entity")),
        ("Attack type", labelize(evidence.get("attack_type", ""))),
        ("Anomaly score", evidence.get("anomaly_score")),
        ("Risk score", evidence.get("risk_score")),
        ("Confidence", evidence.get("confidence")),
        ("Timestamp", evidence.get("timestamp")),
        ("Source IP", evidence.get("source_ip")),
        ("Current location", _location(evidence.get("geo_location"))),
        ("Previous location", _location(evidence.get("previous_location"))),
        ("Device", evidence.get("device_fingerprint")),
        ("Known device", evidence.get("known_device")),
        ("Login hour (UTC)", evidence.get("login_hour")),
        ("Resource", evidence.get("resource_accessed")),
        ("Failed logins (7d)", evidence.get("failed_logins")),
        ("Resource sensitivity", evidence.get("resource_sensitivity")),
        ("Cold start", evidence.get("cold_start")),
        ("Concept drift", evidence.get("concept_drift")),
        ("Drift status", evidence.get("drift_status")),
    ]
    return pd.DataFrame([{"Evidence": label, "Observed value": value} for label, value in fields])


def _location(value: dict[str, Any] | None) -> str:
    """Format a supplied location without inferring missing fields."""

    if not value:
        return "Insufficient evidence available."
    return f"{value.get('city')}, {value.get('country_code')}"
