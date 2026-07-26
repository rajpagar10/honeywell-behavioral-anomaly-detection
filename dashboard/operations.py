"""Live event replay, streaming telemetry, and operational controls."""

from datetime import UTC, datetime
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st
from api_client import SOCAPIClient
from theme import HONEYWELL_RED, chart, labelize, section_header


def render_live_operations(
    client: SOCAPIClient,
    events: list[dict[str, Any]],
    replay: dict[str, Any] | None,
) -> None:
    """Render replay controls and a continuously refreshing event console."""

    control, activity = st.columns([1, 2.4])
    with control:
        section_header("Replay control", "Run deterministic attack demonstrations.")
        preset = st.selectbox(
            "Demo speed",
            ["Presentation (25 ms)", "Fast (0 ms)", "Analyst walkthrough (250 ms)"],
        )
        interval_map = {
            "Presentation (25 ms)": 25,
            "Fast (0 ms)": 0,
            "Analyst walkthrough (250 ms)": 250,
        }
        event_limit = st.select_slider(
            "Replay size",
            options=[100, 400, 800, 2000],
            value=2000,
        )
        if st.button("Start event replay", type="primary", use_container_width=True):
            client.post(
                "/api/v1/replay/start",
                {"interval_ms": interval_map[preset], "max_events": event_limit},
            )
            st.toast("Replay started. Live polling will update this page.", icon="▶️")
        if replay:
            total = max(1, int(replay.get("total_events", 1)))
            processed = int(replay.get("processed_events", 0))
            st.progress(
                min(1.0, processed / total),
                text=f"{processed:,} of {total:,} events",
            )
            stats = st.columns(2)
            stats[0].metric("Status", labelize(replay.get("status", "unknown")))
            stats[1].metric("Alerts", f"{replay.get('alerts_generated', 0):,}")
            if replay.get("error_message"):
                st.error(str(replay["error_message"]))
        else:
            st.info("No replay has been started.")
        st.caption(f"Console refreshed {datetime.now(UTC).strftime('%H:%M:%S UTC')}")

    with activity:
        section_header(
            "Live event activity",
            "Replay-time throughput; original synthetic event time is retained separately.",
        )
        if not events:
            st.info("Events will appear here as replay progresses.")
            return
        frame = _event_frame(events)
        bucket = (
            frame.set_index("processed_at").resample("1s").size().rename("events").reset_index()
        )
        figure = px.bar(
            bucket,
            x="processed_at",
            y="events",
            title="Live ingestion throughput",
            color_discrete_sequence=[HONEYWELL_RED],
        )
        chart(figure, height=280, key="live_throughput")

    section_header("Event stream", "Filter the live feed without interrupting replay.")
    filter_columns = st.columns([1, 1, 2])
    entity_types = sorted(frame["entity_type"].dropna().unique().tolist())
    selected_types = filter_columns[0].multiselect(
        "Entity type",
        entity_types,
        default=entity_types,
        format_func=labelize,
    )
    outcomes = (
        sorted(frame["auth_outcome"].dropna().unique().tolist()) if "auth_outcome" in frame else []
    )
    selected_outcomes = filter_columns[1].multiselect(
        "Authentication outcome",
        outcomes,
        default=outcomes,
        format_func=labelize,
    )
    query = filter_columns[2].text_input(
        "Search entity, IP, resource, location, or device",
        placeholder="e.g. user-0042 or finance-db",
    )
    filtered = frame[frame["entity_type"].isin(selected_types)]
    if outcomes:
        filtered = filtered[filtered["auth_outcome"].isin(selected_outcomes)]
    if query:
        searchable = filtered.astype(str).agg(" ".join, axis=1)
        filtered = filtered[searchable.str.contains(query, case=False, regex=False)]

    preferred = [
        "processed_at",
        "timestamp",
        "entity_id",
        "entity_type",
        "auth_outcome",
        "resource_accessed",
        "geo_location",
        "source_ip",
        "auth_method",
        "device_fingerprint",
    ]
    st.dataframe(
        filtered[[column for column in preferred if column in filtered]],
        use_container_width=True,
        hide_index=True,
        height=480,
        column_config={
            "processed_at": st.column_config.DatetimeColumn(
                "Processed live",
                format="HH:mm:ss.SSS",
            ),
            "timestamp": st.column_config.DatetimeColumn(
                "Synthetic event time",
                format="YYYY-MM-DD HH:mm:ss",
            ),
            "entity_id": "Entity",
            "entity_type": "Type",
            "auth_outcome": "Outcome",
            "resource_accessed": "Resource",
            "geo_location": "Location",
            "source_ip": "Source IP",
        },
    )


def _event_frame(events: list[dict[str, Any]]) -> pd.DataFrame:
    """Normalize event records for filtering and timeline aggregation."""

    frame = pd.DataFrame(events)
    frame["processed_at"] = pd.to_datetime(
        frame["processed_at"],
        utc=True,
        format="mixed",
    )
    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"],
        utc=True,
        format="mixed",
    )
    return frame.sort_values("processed_at", ascending=False)
