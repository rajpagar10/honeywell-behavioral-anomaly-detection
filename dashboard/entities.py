"""Entity and device behavioral intelligence views."""

from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st
from api_client import SOCAPIClient
from theme import HONEYWELL_RED, chart, labelize, section_header


def render_entity_intelligence(
    client: SOCAPIClient,
    alerts: list[dict[str, Any]],
) -> None:
    """Render an entity profile, adaptive baseline, devices, and behavior history."""

    section_header(
        "Entity intelligence",
        "Inspect learned behavior, trusted devices, locations, resources, and adaptive state.",
    )
    if not alerts:
        st.info("Entity profiles become available after replay.")
        return
    alert_frame = pd.DataFrame(alerts)
    types = sorted(alert_frame["entity_type"].unique().tolist())
    controls = st.columns([1, 2])
    selected_type = controls[0].selectbox("Entity type", ["all", *types], format_func=labelize)
    candidates = alert_frame
    if selected_type != "all":
        candidates = candidates[candidates["entity_type"] == selected_type]
    entities = sorted(candidates["entity_id"].unique().tolist())
    entity_id = controls[1].selectbox("Entity", entities)

    history = client.get(f"/api/v1/entities/{entity_id}?limit=200")
    drift = history["drift"]
    events = pd.DataFrame(history.get("events", []))
    metrics = st.columns(6)
    metrics[0].metric("Entity type", labelize(history["entity"]["entity_type"]))
    metrics[1].metric("Cold start", "Active" if history["cold_start"] else "Cleared")
    metrics[2].metric("Drift state", labelize(drift["status"]))
    metrics[3].metric("Trusted updates", f"{drift['trusted_updates']:,}")
    metrics[4].metric("Decay factor", f"{drift['decay']:.2f}")
    metrics[5].metric("EWM deviation", f"{drift['ewm_deviation']:.3f}")

    st.markdown(
        f'<div class="hw-callout"><strong>Adaptive baseline</strong><br>'
        f"Strategy: {labelize(drift['window_strategy'])} · "
        f"Status: {labelize(drift['status'])} · "
        f"Trusted events are gradually incorporated while anomalous events are excluded.</div>",
        unsafe_allow_html=True,
    )
    profile = history.get("profile")
    if profile:
        _render_profile(profile)
    if events.empty:
        st.info("No behavioral history is available for this entity.")
        return
    _render_observed_behavior(events)


def _render_profile(profile: dict[str, Any]) -> None:
    """Render learned temporal, resource, authentication, geo, and device baselines."""

    section_header("Learned behavioral profile", "Current trusted baseline for this entity.")
    left, right = st.columns(2)
    hours = pd.DataFrame(
        [
            {"hour": int(hour), "probability": probability}
            for hour, probability in profile.get("login_hour_probabilities", {}).items()
        ]
    )
    with left:
        if not hours.empty:
            figure = px.bar(
                hours,
                x="hour",
                y="probability",
                title="Typical activity by hour",
                color_discrete_sequence=[HONEYWELL_RED],
            )
            chart(figure, height=300, key="entity_hours")
        else:
            st.info("Login-hour baseline is still forming.")
    resources = pd.DataFrame(
        [
            {"resource": resource, "probability": probability}
            for resource, probability in profile.get("resource_probabilities", {}).items()
        ]
    )
    with right:
        if not resources.empty:
            figure = px.bar(
                resources.nlargest(12, "probability").sort_values("probability"),
                x="probability",
                y="resource",
                orientation="h",
                title="Frequently accessed resources",
                color="probability",
                color_continuous_scale=["#fee4e2", HONEYWELL_RED],
            )
            chart(figure, height=300, key="entity_resources")
        else:
            st.info("Resource baseline is still forming.")

    detail_columns = st.columns(3)
    dimensions = [
        ("authentication_probabilities", "Expected authentication"),
        ("geolocation_probabilities", "Normal locations"),
    ]
    for column, (field, title) in zip(detail_columns[:2], dimensions, strict=True):
        with column:
            values = profile.get(field, {})
            if values:
                frame = pd.DataFrame(
                    [
                        {"value": labelize(value), "probability": probability}
                        for value, probability in values.items()
                    ]
                )
                figure = px.bar(
                    frame.sort_values("probability"),
                    x="probability",
                    y="value",
                    orientation="h",
                    title=title,
                    color_discrete_sequence=[HONEYWELL_RED],
                )
                chart(figure, height=260, key=f"profile_{field}")
            else:
                st.info(f"{title} baseline is still forming.")
    with detail_columns[2]:
        st.markdown("#### Trusted devices")
        devices = profile.get("known_device_fingerprints", [])
        if devices:
            for device in devices:
                st.code(device)
        else:
            st.info("No trusted device has been established.")
        st.metric("Failed-login baseline", f"{profile.get('failed_login_rate', 0):.2%}")


def _render_observed_behavior(events: pd.DataFrame) -> None:
    """Render devices, authentication methods, locations, and recent history."""

    section_header(
        "Observed behavioral history",
        "Recent devices, authentication methods, locations, and resource activity.",
    )
    dimensions = [
        ("device_fingerprint", "Observed device fingerprints"),
        ("source_ip", "Recent source IPs"),
        ("resource_accessed", "Recent resources"),
    ]
    columns = st.columns(3)
    for column, (field, title) in zip(columns, dimensions, strict=True):
        with column:
            if field in events:
                counts = (
                    events[field]
                    .value_counts()
                    .head(8)
                    .rename_axis("value")
                    .reset_index(name="events")
                )
                figure = px.bar(
                    counts.sort_values("events"),
                    x="events",
                    y="value",
                    orientation="h",
                    title=title,
                    color_discrete_sequence=[HONEYWELL_RED],
                )
                chart(figure, height=300, key=f"entity_{field}")
            else:
                st.info(f"{title} are not available.")

    preferred = [
        "timestamp",
        "resource_accessed",
        "auth_method",
        "auth_outcome",
        "geo_location",
        "source_ip",
        "device_fingerprint",
    ]
    if "timestamp" in events:
        events["timestamp"] = pd.to_datetime(
            events["timestamp"],
            utc=True,
            format="mixed",
        )
        events = events.sort_values("timestamp", ascending=False)
    st.dataframe(
        events[[column for column in preferred if column in events]],
        use_container_width=True,
        hide_index=True,
        height=420,
    )
