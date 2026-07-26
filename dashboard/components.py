"""Reusable Streamlit SOC dashboard sections."""

from collections import Counter
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from api_client import SOCAPIClient

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#ff3347",
    "high": "#ff6b35",
    "medium": "#ffb000",
    "low": "#4aa8ff",
    "info": "#7f8fa6",
}


def metric_row(summary: dict[str, Any]) -> None:
    """Render executive operational metrics."""

    replay = summary.get("latest_replay") or {}
    replay_status = {
        "completed": "Complete",
        "running": "Live",
        "failed": "Failed",
    }.get(str(replay.get("status", "")), "Not started")
    columns = st.columns(5)
    columns[0].metric("Events processed", f"{summary.get('events', 0):,}")
    columns[1].metric("Active alerts", f"{summary.get('alerts', 0):,}")
    columns[2].metric("Entities observed", f"{summary.get('entities', 0):,}")
    columns[3].metric("Average risk", f"{summary.get('average_risk', 0):.1f}")
    columns[4].metric("Replay", replay_status)


def overview_charts(alerts: list[dict[str, Any]]) -> None:
    """Render risk, attack, and risky-entity distributions."""

    if not alerts:
        st.info("No alerts yet. Start the replay from Live Operations.")
        return
    frame = pd.DataFrame(alerts)
    left, middle, right = st.columns(3)
    with left:
        figure = px.histogram(
            frame,
            x="risk_score",
            nbins=12,
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            title="Risk-score distribution",
        )
        _chart(figure)
    with middle:
        attack_counts = (
            frame["attack_type"].value_counts().rename_axis("attack").reset_index(name="alerts")
        )
        attack_counts["attack"] = attack_counts["attack"].str.replace("_", " ").str.title()
        figure = px.bar(
            attack_counts,
            x="alerts",
            y="attack",
            orientation="h",
            color="alerts",
            color_continuous_scale=["#37141b", "#e31b23"],
            title="Attack-type distribution",
        )
        _chart(figure)
    with right:
        risky = (
            frame.groupby("entity_id", as_index=False)["risk_score"].max().nlargest(8, "risk_score")
        )
        figure = px.bar(
            risky,
            x="risk_score",
            y="entity_id",
            orientation="h",
            color="risk_score",
            color_continuous_scale=["#25344a", "#ff3347"],
            title="Top risky entities",
        )
        _chart(figure)


def live_operations(
    client: SOCAPIClient,
    events: list[dict[str, Any]],
    replay: dict[str, Any] | None,
) -> None:
    """Render replay controls and a live event stream."""

    left, right = st.columns([1, 3])
    with left:
        st.subheader("Replay control")
        interval = st.slider("Interval (ms)", 0, 2000, 100, 50)
        event_limit = st.select_slider("Events", options=[100, 400, 800, 2000], value=2000)
        if st.button("Start / resume replay", type="primary", use_container_width=True):
            client.post(
                "/api/v1/replay/start",
                {"interval_ms": interval, "max_events": event_limit},
            )
            st.success("Replay started.")
        if replay:
            total = max(1, int(replay.get("total_events", 1)))
            processed = int(replay.get("processed_events", 0))
            st.progress(min(1.0, processed / total), text=f"{processed:,} / {total:,} events")
            st.caption(
                f"{replay.get('status', 'unknown').upper()} · "
                f"{replay.get('alerts_generated', 0)} alerts"
            )
        else:
            st.info("Replay has not started.")
    with right:
        st.subheader("Live event stream")
        if not events:
            st.info("Events will appear here as replay progresses.")
        else:
            frame = pd.DataFrame(events)
            preferred = [
                "timestamp",
                "entity_id",
                "entity_type",
                "resource_accessed",
                "auth_outcome",
                "source_ip",
            ]
            st.dataframe(
                frame[[column for column in preferred if column in frame]],
                use_container_width=True,
                hide_index=True,
                height=430,
            )


def alert_queue(
    alerts: list[dict[str, Any]],
    severity_filter: list[str],
    attack_filter: list[str],
    entity_query: str,
) -> list[dict[str, Any]]:
    """Filter and render the analyst alert queue."""

    filtered = [
        alert
        for alert in alerts
        if (not severity_filter or alert["severity"] in severity_filter)
        and (not attack_filter or alert["attack_type"] in attack_filter)
        and (not entity_query or entity_query.lower() in alert["entity_id"].lower())
    ]
    if not filtered:
        st.info("No alerts match the selected filters.")
        return []
    frame = pd.DataFrame(filtered)
    columns = [
        "risk_score",
        "severity",
        "attack_type",
        "entity_id",
        "confidence",
        "cold_start",
        "drift_status",
        "event_timestamp",
    ]
    if "confidence" not in frame and "classifier_confidence" in frame:
        frame["confidence"] = frame["classifier_confidence"]
    st.dataframe(
        frame[[column for column in columns if column in frame]],
        use_container_width=True,
        hide_index=True,
        height=380,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk", min_value=0, max_value=100, format="%.1f"
            ),
            "confidence": st.column_config.ProgressColumn(
                "Confidence", min_value=0, max_value=1, format="%.2f"
            ),
        },
    )
    return filtered


def alert_detail(alert: dict[str, Any]) -> None:
    """Render complete alert explainability and response guidance."""

    st.subheader(f"{alert['attack_type'].replace('_', ' ').title()} · {alert['risk_score']:.1f}")
    columns = st.columns(4)
    columns[0].metric("Severity", alert["severity"].upper())
    columns[1].metric("Confidence", f"{alert['classifier_confidence']:.0%}")
    columns[2].metric("Baseline", alert["explanation"]["baseline_level"].title())
    columns[3].metric("Drift", alert["drift_status"].replace("_", " ").title())
    if alert.get("cold_start"):
        st.warning("Cold-start entity: confidence is reduced and a peer baseline is active.")
    st.info(alert["human_explanation"], icon="🔎")
    left, right = st.columns([3, 2])
    with left:
        st.markdown("#### Contributing factors")
        components = pd.DataFrame(alert["explanation"]["components"])
        figure = px.bar(
            components.sort_values("contribution"),
            x="contribution",
            y="factor",
            orientation="h",
            color="contribution",
            color_continuous_scale=["#26354a", "#ff3347"],
        )
        _chart(figure, height=330)
        for reason in alert["explanation"]["reasons"]:
            st.markdown(
                f"- **{reason['summary'].capitalize()}** — observed `{reason['observed_value']}`"
            )
    with right:
        st.markdown("#### Recommended analyst actions")
        for index, action in enumerate(alert["recommended_actions"], start=1):
            st.markdown(f"{index}. {action}")
        st.markdown("#### Correlation")
        st.code(alert.get("correlation_key") or "No correlation key")


def entity_view(client: SOCAPIClient, alerts: list[dict[str, Any]]) -> None:
    """Render entity baseline history and adaptive status."""

    entities = sorted({alert["entity_id"] for alert in alerts})
    if not entities:
        st.info("Entity profiles become available after replay.")
        return
    entity_id = st.selectbox("Entity", entities)
    history = client.get(f"/api/v1/entities/{entity_id}?limit=100")
    drift = history["drift"]
    columns = st.columns(4)
    columns[0].metric("Entity type", history["entity"]["entity_type"].replace("_", " ").title())
    columns[1].metric("Cold start", "Yes" if history["cold_start"] else "No")
    columns[2].metric("Drift status", drift["status"].replace("_", " ").title())
    columns[3].metric("Trusted updates", drift["trusted_updates"])
    st.caption(
        f"Adaptive window: {drift['window_strategy']} · decay {drift['decay']} · "
        f"EWM deviation {drift['ewm_deviation']}"
    )
    profile = history.get("profile")
    if profile:
        left, right = st.columns(2)
        with left:
            st.markdown("#### Typical login hours")
            hours = pd.DataFrame(
                [
                    {"hour": int(hour), "probability": probability}
                    for hour, probability in profile["login_hour_probabilities"].items()
                ]
            )
            _chart(px.bar(hours, x="hour", y="probability"), height=270)
        with right:
            st.markdown("#### Common resources")
            resources = pd.DataFrame(
                [
                    {"resource": resource, "probability": probability}
                    for resource, probability in profile["resource_probabilities"].items()
                ]
            ).nlargest(10, "probability")
            _chart(px.bar(resources, x="probability", y="resource", orientation="h"), height=270)
    st.markdown("#### Recent behavioral history")
    st.dataframe(pd.DataFrame(history["events"]), use_container_width=True, hide_index=True)


def evaluation_view(metrics: dict[str, Any]) -> None:
    """Render detection metrics, alert budget, confusion matrix, and per-attack results."""

    if metrics.get("status") == "unavailable":
        st.warning(metrics["detail"])
        return
    columns = st.columns(6)
    for column, key, label in zip(
        columns,
        ("precision", "recall", "f1_score", "pr_auc", "false_positive_rate"),
        ("Precision", "Recall", "F1", "PR-AUC", "False-positive rate"),
        strict=False,
    ):
        column.metric(label, f"{metrics[key]:.2%}")
    top = metrics["top_1_percent"]
    columns[5].metric("Top-1% precision", f"{top['precision']:.2%}")
    labels = metrics["confusion_matrix"]["labels"]
    values = metrics["confusion_matrix"]["values"]
    left, right = st.columns([3, 2])
    with left:
        figure = go.Figure(
            data=go.Heatmap(
                z=values,
                x=[value.replace("_", " ") for value in labels],
                y=[value.replace("_", " ") for value in labels],
                colorscale=[[0, "#101722"], [1, "#e31b23"]],
            )
        )
        figure.update_layout(
            title="Confusion matrix", xaxis_title="Predicted", yaxis_title="Actual"
        )
        _chart(figure, height=470)
    with right:
        per_attack = []
        for attack, result in metrics["per_attack"].items():
            if isinstance(result, dict) and "f1-score" in result:
                per_attack.append(
                    {
                        "attack": attack,
                        "precision": result["precision"],
                        "recall": result["recall"],
                        "f1": result["f1-score"],
                    }
                )
        st.markdown("#### Per-attack classification")
        st.dataframe(pd.DataFrame(per_attack), use_container_width=True, hide_index=True)
        st.markdown("#### Top-1% alert budget")
        st.metric("Events reviewed", top["event_count"])
        st.metric("Precision", f"{top['precision']:.2%}")
        st.metric("Recall", f"{top['recall']:.2%}")


def health_view(health: dict[str, Any], readiness: dict[str, Any], replay: Any) -> None:
    """Render API, database, and replay health."""

    columns = st.columns(3)
    columns[0].success(f"API: {health['status']}")
    components = readiness.get("components", {})
    columns[1].success("Databases: ready" if all(components.values()) else "Databases: degraded")
    columns[2].info(f"Replay: {(replay or {}).get('status', 'not started')}")
    st.json(
        {
            "service": health,
            "readiness": readiness,
            "replay": replay or {"status": "not_started"},
        }
    )


def cold_drift_summary(alerts: list[dict[str, Any]]) -> None:
    """Show cold-start and drift indicators for executive triage."""

    cold = sum(bool(alert.get("cold_start")) for alert in alerts)
    drift = Counter(alert.get("drift_status", "unknown") for alert in alerts)
    left, right = st.columns(2)
    left.metric("Cold-start alerts", cold)
    right.caption("Drift states")
    right.write(" · ".join(f"{key}: **{value}**" for key, value in drift.items()) or "None")


def _chart(figure: go.Figure, *, height: int = 320) -> None:
    """Apply the shared dark SOC chart style."""

    figure.update_layout(
        height=height,
        margin={"l": 15, "r": 15, "t": 55, "b": 15},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#dbe4ee", "family": "Inter, sans-serif"},
        coloraxis_showscale=False,
    )
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
