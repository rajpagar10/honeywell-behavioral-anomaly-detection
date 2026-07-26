"""Ranked alert queue and explainable analyst investigation workspace."""

from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st
from api_client import SOCAPIClient
from theme import HONEYWELL_RED, chart, labelize, section_header

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def render_alert_center(
    client: SOCAPIClient,
    alerts: list[dict[str, Any]],
) -> None:
    """Render a filterable risk-ranked alert queue and investigation detail."""

    section_header(
        "Ranked alert queue",
        "Prioritize by risk, severity, attack family, adaptive state, or entity.",
    )
    if not alerts:
        st.info("No alerts are available. Start a replay from Live Operations.")
        return

    frame = _alert_frame(alerts)
    row_one = st.columns([1.2, 1.5, 1.2, 1.2])
    severities = row_one[0].multiselect(
        "Severity",
        SEVERITIES,
        default=SEVERITIES,
        format_func=labelize,
    )
    attack_types = sorted(frame["attack_type"].unique().tolist())
    attacks = row_one[1].multiselect("Attack type", attack_types, format_func=labelize)
    entity_types = sorted(frame["entity_type"].unique().tolist())
    types = row_one[2].multiselect(
        "Entity type",
        entity_types,
        default=entity_types,
        format_func=labelize,
    )
    risk_range = row_one[3].slider("Risk range", 0, 100, (0, 100))

    row_two = st.columns([2, 1, 1, 1])
    query = row_two[0].text_input(
        "Search entity or correlation key",
        placeholder="Search the queue",
    )
    cold_only = row_two[1].toggle("Cold start only")
    drift_only = row_two[2].toggle("Drift active only")
    sort_order = row_two[3].selectbox("Sort", ["Highest risk", "Newest", "Confidence"])

    filtered = frame[
        frame["severity"].isin(severities)
        & frame["entity_type"].isin(types)
        & frame["risk_score"].between(*risk_range)
    ]
    if attacks:
        filtered = filtered[filtered["attack_type"].isin(attacks)]
    if query:
        searchable = filtered[["entity_id", "correlation_key"]].astype(str).agg(" ".join, axis=1)
        filtered = filtered[searchable.str.contains(query, case=False, regex=False)]
    if cold_only:
        filtered = filtered[filtered["cold_start"]]
    if drift_only:
        filtered = filtered[filtered["drift_status"] != "stable"]
    sort_columns = {
        "Highest risk": ("risk_score", False),
        "Newest": ("event_timestamp", False),
        "Confidence": ("classifier_confidence", False),
    }
    sort_column, ascending = sort_columns[sort_order]
    filtered = filtered.sort_values(sort_column, ascending=ascending)

    queue_metrics = st.columns(4)
    queue_metrics[0].metric("Matching alerts", f"{len(filtered):,}")
    queue_metrics[1].metric(
        "Average risk",
        f"{filtered['risk_score'].mean():.1f}" if not filtered.empty else "0.0",
    )
    queue_metrics[2].metric("Cold start", f"{int(filtered['cold_start'].sum()):,}")
    queue_metrics[3].metric(
        "Active drift",
        f"{int((filtered['drift_status'] != 'stable').sum()):,}",
    )

    if filtered.empty:
        st.info("No alerts match these filters.")
        return

    display = filtered.copy()
    display["attack"] = display["attack_type"].map(labelize)
    display["type"] = display["entity_type"].map(labelize)
    display["drift"] = display["drift_status"].map(labelize)
    queue_columns = [
        "risk_score",
        "severity",
        "attack",
        "entity_id",
        "type",
        "classifier_confidence",
        "cold_start",
        "drift",
        "event_timestamp",
    ]
    st.dataframe(
        display[queue_columns],
        use_container_width=True,
        hide_index=True,
        height=390,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk",
                min_value=0,
                max_value=100,
                format="%.1f",
            ),
            "classifier_confidence": st.column_config.ProgressColumn(
                "Confidence",
                min_value=0,
                max_value=1,
                format="%.2f",
            ),
            "event_timestamp": st.column_config.DatetimeColumn(
                "Detected", format="YYYY-MM-DD HH:mm"
            ),
        },
    )
    st.download_button(
        "Export filtered alerts",
        data=display.to_csv(index=False).encode("utf-8"),
        file_name="soc_alert_export.csv",
        mime="text/csv",
    )

    selected_id = st.selectbox(
        "Open investigation",
        filtered["alert_id"].tolist(),
        format_func=lambda alert_id: _alert_option(filtered, alert_id),
    )
    detail = client.get(f"/api/v1/alerts/{selected_id}")
    _render_alert_detail(detail, frame)


def _render_alert_detail(alert: dict[str, Any], all_alerts: pd.DataFrame) -> None:
    """Render one alert's evidence, explanation, and analyst workflow."""

    st.divider()
    section_header(
        f"{labelize(alert['attack_type'])} investigation",
        f"Alert {alert['alert_id']} · {alert['event_timestamp']}",
    )
    primary_metrics = st.columns(3)
    primary_metrics[0].metric("Risk score", f"{alert['risk_score']:.1f}")
    primary_metrics[1].metric("Severity", labelize(alert["severity"]))
    primary_metrics[2].metric("Confidence", f"{alert['classifier_confidence']:.0%}")
    context_metrics = st.columns(3)
    context_metrics[0].metric("Entity", alert["entity_id"])
    context_metrics[1].metric("Baseline", labelize(alert["explanation"]["baseline_level"]))
    context_metrics[2].metric("Drift", labelize(alert["drift_status"]))

    if alert.get("cold_start"):
        st.warning(
            "Cold-start safeguard active: peer baselines are in use and confidence is reduced."
        )
    st.markdown(
        f'<div class="hw-callout"><strong>Why this was flagged</strong><br>'
        f"{alert['human_explanation']}</div>",
        unsafe_allow_html=True,
    )

    evidence, response = st.columns([1.6, 1])
    with evidence:
        section_header("Risk decomposition", "Weighted contribution to the 0–100 risk score.")
        components = pd.DataFrame(alert["explanation"]["components"])
        components["factor_label"] = components["factor"].map(labelize)
        figure = px.bar(
            components.sort_values("contribution"),
            x="contribution",
            y="factor_label",
            orientation="h",
            title="Contributing risk factors",
            color="contribution",
            color_continuous_scale=["#fee4e2", HONEYWELL_RED],
        )
        chart(figure, height=390, key=f"risk_{alert['alert_id']}")
        for reason in alert["explanation"]["reasons"]:
            st.markdown(
                f"**{reason['summary'].capitalize()}**  \n"
                f"Observed `{reason['observed_value']}` · Expected `{reason['expected_value']}`"
            )
    with response:
        section_header("Recommended response", "Session checklist for the assigned analyst.")
        for index, action in enumerate(alert["recommended_actions"], start=1):
            st.checkbox(action, key=f"{alert['alert_id']}_{index}")
        st.selectbox(
            "Disposition",
            ["Unreviewed", "Investigating", "Escalated", "Benign", "Confirmed incident"],
            key=f"disposition_{alert['alert_id']}",
        )
        st.text_area(
            "Analyst notes",
            placeholder="Record evidence, validation steps, and handoff context.",
            key=f"notes_{alert['alert_id']}",
        )
        st.caption("Checklist and notes are session-local in the current hackathon build.")

    related = all_alerts[all_alerts["entity_id"] == alert["entity_id"]].copy()
    section_header(
        "Entity correlation timeline",
        f"{len(related)} alert(s) associated with {alert['entity_id']}.",
    )
    figure = px.scatter(
        related,
        x="event_timestamp",
        y="risk_score",
        color="attack_type",
        size="classifier_confidence",
        hover_data=["severity", "drift_status"],
        title="Related alert history",
    )
    chart(figure, height=300, key=f"correlation_{alert['alert_id']}")


def _alert_frame(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    """Normalize alerts for queue filtering and sorting."""

    frame = pd.DataFrame(alerts)
    frame["event_timestamp"] = pd.to_datetime(
        frame["event_timestamp"],
        utc=True,
        format="mixed",
    )
    return frame


def _alert_option(frame: pd.DataFrame, alert_id: str) -> str:
    """Build the analyst-facing label for an alert selector option."""

    row = frame.loc[frame["alert_id"] == alert_id].iloc[0]
    return f"{row['risk_score']:.1f} · {labelize(row['attack_type'])} · {row['entity_id']}"
