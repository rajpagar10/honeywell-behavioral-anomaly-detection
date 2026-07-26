"""Executive overview and portfolio-level threat visualizations."""

from collections import Counter
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st
from theme import HONEYWELL_RED, SEVERITY_COLORS, chart, labelize, section_header


def render_overview(
    summary: dict[str, Any],
    alerts: list[dict[str, Any]],
) -> None:
    """Render executive KPIs, trends, heatmaps, and the priority watchlist."""

    replay = summary.get("latest_replay") or {}
    critical = sum(alert["severity"] == "critical" for alert in alerts)
    high = sum(alert["severity"] == "high" for alert in alerts)
    cold = sum(bool(alert.get("cold_start")) for alert in alerts)
    metrics = st.columns(5)
    metrics[0].metric("Events", f"{summary.get('events', 0):,}")
    metrics[1].metric("Open alerts", f"{summary.get('alerts', 0):,}")
    metrics[2].metric("Entities", f"{summary.get('entities', 0):,}")
    metrics[3].metric("Average risk", f"{summary.get('average_risk', 0):.1f}")
    metrics[4].metric(
        "Cold start",
        f"{cold:,}",
        delta=f"{critical + high} critical/high",
        delta_color="off",
    )

    if not alerts:
        st.info("No alerts are available yet. Start a replay from Live Operations.")
        return

    frame = _alert_frame(alerts)
    section_header(
        "Threat posture",
        f"Latest replay: {labelize(replay.get('status', 'not started'))} · "
        f"{replay.get('processed_events', 0):,} events processed",
    )
    left, right = st.columns([1.7, 1])
    with left:
        timeline = (
            frame.set_index("event_timestamp")
            .resample("4h")
            .agg(alerts=("alert_id", "count"), average_risk=("risk_score", "mean"))
            .reset_index()
        )
        figure = px.area(
            timeline,
            x="event_timestamp",
            y="alerts",
            markers=True,
            title="Alert volume over time",
            color_discrete_sequence=[HONEYWELL_RED],
        )
        figure.update_traces(fillcolor="rgba(227,27,35,.12)")
        chart(figure, key="overview_timeline")
    with right:
        severity = (
            frame["severity"].value_counts().rename_axis("severity").reset_index(name="alerts")
        )
        figure = px.pie(
            severity,
            values="alerts",
            names="severity",
            hole=0.66,
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            title="Alert severity",
        )
        figure.update_traces(textposition="inside", textinfo="percent+label")
        chart(figure, key="overview_severity")

    left, right = st.columns(2)
    with left:
        attacks = (
            frame["attack_type"]
            .value_counts()
            .rename_axis("attack_type")
            .reset_index(name="alerts")
        )
        attacks["attack"] = attacks["attack_type"].map(labelize)
        figure = px.bar(
            attacks.sort_values("alerts"),
            x="alerts",
            y="attack",
            orientation="h",
            title="Attack-type distribution",
            color="alerts",
            color_continuous_scale=["#fee4e2", HONEYWELL_RED],
        )
        chart(figure, height=380, key="overview_attacks")
    with right:
        matrix = pd.crosstab(frame["entity_type"], frame["attack_type"])
        matrix.columns = [labelize(column) for column in matrix.columns]
        matrix.index = [labelize(index) for index in matrix.index]
        figure = px.imshow(
            matrix,
            text_auto=True,
            aspect="auto",
            color_continuous_scale=["#fff5f5", HONEYWELL_RED],
            title="Attack heatmap by entity type",
            labels={"x": "Attack type", "y": "Entity type", "color": "Alerts"},
        )
        chart(figure, height=380, key="overview_heatmap")

    section_header(
        "Priority watchlist",
        "Entities ranked by maximum risk and repeated alert activity.",
    )
    watchlist = (
        frame.groupby(["entity_id", "entity_type"], as_index=False)
        .agg(
            max_risk=("risk_score", "max"),
            average_risk=("risk_score", "mean"),
            alert_count=("alert_id", "count"),
            latest_alert=("event_timestamp", "max"),
        )
        .sort_values(["max_risk", "alert_count"], ascending=False)
        .head(12)
    )
    st.dataframe(
        watchlist,
        use_container_width=True,
        hide_index=True,
        column_config={
            "max_risk": st.column_config.ProgressColumn("Peak risk", min_value=0, max_value=100),
            "average_risk": st.column_config.NumberColumn("Average risk", format="%.1f"),
            "latest_alert": st.column_config.DatetimeColumn("Latest alert"),
        },
    )

    drift_counts = Counter(alert.get("drift_status", "unknown") for alert in alerts)
    st.caption(
        "Adaptive baseline states · "
        + " · ".join(f"{labelize(key)}: {value}" for key, value in drift_counts.items())
    )


def _alert_frame(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    """Normalize alert records for executive analytics."""

    frame = pd.DataFrame(alerts)
    frame["event_timestamp"] = pd.to_datetime(
        frame["event_timestamp"],
        utc=True,
        format="mixed",
    )
    return frame.sort_values("event_timestamp")
