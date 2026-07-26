"""Threat analytics and model-performance dashboard views."""

from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from theme import HONEYWELL_RED, chart, labelize, section_header


def render_threat_analytics(
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> None:
    """Render cross-dimensional threat, resource, geo, and sequence analytics."""

    section_header(
        "Threat analytics",
        "Explore attack concentration, risky resources, locations, and behavioral changes.",
    )
    if not alerts:
        st.info("Threat analytics become available after alerts are generated.")
        return
    alert_frame = pd.DataFrame(alerts)
    alert_frame["event_timestamp"] = pd.to_datetime(
        alert_frame["event_timestamp"],
        utc=True,
        format="mixed",
    )
    event_frame = pd.DataFrame(events)

    left, right = st.columns(2)
    with left:
        risk_matrix = pd.pivot_table(
            alert_frame,
            values="risk_score",
            index="entity_type",
            columns="attack_type",
            aggfunc="mean",
            fill_value=0,
        )
        risk_matrix.index = [labelize(value) for value in risk_matrix.index]
        risk_matrix.columns = [labelize(value) for value in risk_matrix.columns]
        figure = px.imshow(
            risk_matrix,
            text_auto=".1f",
            aspect="auto",
            color_continuous_scale=["#fff5f5", HONEYWELL_RED],
            title="Average risk heatmap",
            labels={"x": "Attack type", "y": "Entity type", "color": "Risk"},
        )
        chart(figure, height=390, key="analytics_risk_heatmap")
    with right:
        drift = (
            alert_frame.groupby(["drift_status", "attack_type"])
            .size()
            .rename("alerts")
            .reset_index()
        )
        drift["drift"] = drift["drift_status"].map(labelize)
        drift["attack"] = drift["attack_type"].map(labelize)
        figure = px.bar(
            drift,
            x="alerts",
            y="drift",
            color="attack",
            orientation="h",
            title="Attack mix by concept-drift state",
        )
        chart(figure, height=390, key="analytics_drift")

    if not event_frame.empty:
        left, middle, right = st.columns(3)
        _dimension_chart(
            left,
            event_frame,
            "resource_accessed",
            "Most active resources",
            "analytics_resources",
        )
        _dimension_chart(
            middle,
            event_frame,
            "source_ip",
            "Most active source IPs",
            "analytics_sources",
        )
        _dimension_chart(
            right,
            event_frame,
            "auth_method",
            "Authentication methods",
            "analytics_auth",
        )

    timeline = alert_frame.sort_values("event_timestamp")
    figure = px.scatter(
        timeline,
        x="event_timestamp",
        y="risk_score",
        color="attack_type",
        symbol="entity_type",
        size="classifier_confidence",
        hover_data=["entity_id", "severity", "cold_start", "drift_status"],
        title="Risk timeline and attack progression",
    )
    figure.add_hline(y=70, line_dash="dash", line_color=HONEYWELL_RED, annotation_text="High risk")
    chart(figure, height=430, key="analytics_timeline")


def render_model_performance(metrics: dict[str, Any]) -> None:
    """Render anomaly, top-budget, confusion-matrix, and per-attack metrics."""

    section_header(
        "Model performance",
        "Held-out detection and attack-classification evaluation.",
    )
    if metrics.get("status") == "unavailable":
        st.warning(metrics["detail"])
        return
    top = metrics["top_1_percent"]
    values = [
        ("Precision", metrics["precision"]),
        ("Recall", metrics["recall"]),
        ("F1 score", metrics["f1_score"]),
        ("PR-AUC", metrics["pr_auc"]),
        ("False-positive rate", metrics["false_positive_rate"]),
        ("Top-1% precision", top["precision"]),
        ("Top-1% recall", top["recall"]),
    ]
    columns = [*st.columns(4), *st.columns(3)]
    for column, (label, value) in zip(columns, values, strict=True):
        column.metric(label, f"{value:.2%}")

    left, right = st.columns([1.25, 1])
    labels = metrics["confusion_matrix"]["labels"]
    matrix = metrics["confusion_matrix"]["values"]
    with left:
        figure = go.Figure(
            data=go.Heatmap(
                z=matrix,
                x=[labelize(value) for value in labels],
                y=[labelize(value) for value in labels],
                colorscale=[[0, "#ffffff"], [1, HONEYWELL_RED]],
                text=matrix,
                texttemplate="%{text}",
                hovertemplate="Actual %{y}<br>Predicted %{x}<br>Events %{z}<extra></extra>",
            )
        )
        figure.update_layout(
            title="Attack-classification confusion matrix",
            xaxis_title="Predicted",
            yaxis_title="Actual",
        )
        chart(figure, height=530, key="model_confusion")
    with right:
        rows = []
        for attack, result in metrics["per_attack"].items():
            if isinstance(result, dict) and "f1-score" in result:
                rows.append(
                    {
                        "attack": labelize(attack),
                        "precision": result["precision"],
                        "recall": result["recall"],
                        "f1": result["f1-score"],
                        "support": int(result["support"]),
                    }
                )
        per_attack = pd.DataFrame(rows)
        figure = px.bar(
            per_attack.melt(
                id_vars=["attack"],
                value_vars=["precision", "recall", "f1"],
                var_name="metric",
                value_name="score",
            ),
            x="score",
            y="attack",
            color="metric",
            barmode="group",
            orientation="h",
            range_x=[0, 1],
            title="Per-attack classification quality",
        )
        chart(figure, height=430, key="model_per_attack")
        st.markdown(
            f'<div class="hw-callout"><strong>Top-1% analyst budget</strong><br>'
            f"Review {top['event_count']} highest-risk events to achieve "
            f"{top['precision']:.1%} precision and {top['recall']:.1%} recall.</div>",
            unsafe_allow_html=True,
        )


def _dimension_chart(
    container: Any,
    frame: pd.DataFrame,
    field: str,
    title: str,
    key: str,
) -> None:
    """Render a top-value activity chart for one event dimension."""

    with container:
        if field not in frame:
            st.info(f"{title}: data unavailable.")
            return
        counts = (
            frame[field].value_counts().head(10).rename_axis("value").reset_index(name="events")
        )
        figure = px.bar(
            counts.sort_values("events"),
            x="events",
            y="value",
            orientation="h",
            title=title,
            color="events",
            color_continuous_scale=["#fee4e2", HONEYWELL_RED],
        )
        chart(figure, height=330, key=key)
