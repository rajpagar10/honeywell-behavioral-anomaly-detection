"""Honeywell Behavioral Security multi-view analyst dashboard."""

from datetime import UTC, datetime
from typing import Any

import streamlit as st
from analytics import render_model_performance, render_threat_analytics
from api_client import APIUnavailableError, SOCAPIClient
from entities import render_entity_intelligence
from health import render_system_health
from investigation import render_alert_center
from operations import render_live_operations
from overview import render_overview
from theme import apply_theme, page_header

st.set_page_config(
    page_title="Honeywell Behavioral Security SOC",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAVIGATION = [
    "Executive Overview",
    "Live Operations",
    "Alert Center",
    "Threat Analytics",
    "Entity Intelligence",
    "Model Performance",
    "System Health",
]


def _load(client: SOCAPIClient) -> dict[str, Any]:
    """Load a consistent operational snapshot from the backend."""

    try:
        replay = client.get("/api/v1/replay/status")
    except APIUnavailableError:
        replay = None
    return {
        "health": client.get("/health"),
        "ready": client.get("/ready"),
        "summary": client.get("/api/v1/dashboard/summary"),
        "events": client.get("/api/v1/events/recent?limit=500"),
        "alerts": client.get("/api/v1/alerts?limit=500"),
        "metrics": client.get("/api/v1/evaluation/metrics"),
        "replay": replay,
    }


def _render_view(
    navigation: str,
    data: dict[str, Any],
    client: SOCAPIClient,
) -> None:
    """Dispatch one navigation destination to its view renderer."""

    if navigation == "Executive Overview":
        render_overview(data["summary"], data["alerts"])
    elif navigation == "Live Operations":
        render_live_operations(client, data["events"], data["replay"])
    elif navigation == "Alert Center":
        render_alert_center(client, data["alerts"])
    elif navigation == "Threat Analytics":
        render_threat_analytics(data["alerts"], data["events"])
    elif navigation == "Entity Intelligence":
        render_entity_intelligence(client, data["alerts"])
    elif navigation == "Model Performance":
        render_model_performance(data["metrics"])
    else:
        render_system_health(
            data["health"],
            data["ready"],
            data["replay"],
            data["summary"],
        )


def _sidebar() -> tuple[str, str, bool, int]:
    """Render navigation and live-data controls."""

    with st.sidebar:
        st.markdown("### HONEYWELL")
        st.caption("Behavioral Security Platform")
        st.divider()
        navigation = st.radio(
            "Workspace",
            NAVIGATION,
            label_visibility="collapsed",
        )
        st.divider()
        st.markdown("#### Live data")
        auto_refresh = st.toggle("Automatic refresh", value=True)
        refresh_seconds = st.select_slider(
            "Refresh interval",
            options=[2, 5, 10, 30],
            value=5,
            disabled=not auto_refresh,
            format_func=lambda value: f"{value} seconds",
        )
        if st.button("Refresh now", use_container_width=True):
            st.rerun()
        st.divider()
        with st.expander("Connection"):
            api_url = st.text_input("Backend API", "http://127.0.0.1:8000")
        st.caption("Near-real-time polling · Ground truth isolated")
    return navigation, api_url, auto_refresh, refresh_seconds


def main() -> None:
    """Render the complete analyst console with timed live updates."""

    apply_theme()
    navigation, api_url, auto_refresh, refresh_seconds = _sidebar()
    page_header()
    client = SOCAPIClient(api_url)
    interval: int | None = refresh_seconds if auto_refresh else None

    @st.fragment(run_every=interval)
    def live_workspace() -> None:
        """Refresh the active SOC workspace on the configured interval."""

        try:
            data = _load(client)
        except APIUnavailableError as error:
            st.error(str(error))
            st.code(
                "powershell -ExecutionPolicy Bypass -File scripts/run_demo.ps1",
                language="powershell",
            )
            return
        st.caption(
            f"{navigation} · "
            f"Updated {datetime.now(UTC).strftime('%H:%M:%S UTC')} · "
            f"{'Auto-refresh on' if auto_refresh else 'Manual refresh'}"
        )
        _render_view(navigation, data, client)

    live_workspace()


if __name__ == "__main__":
    main()
