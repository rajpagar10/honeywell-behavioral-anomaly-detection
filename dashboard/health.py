"""System health and operational readiness view."""

from typing import Any

import streamlit as st
from theme import labelize, section_header


def render_system_health(
    health: dict[str, Any],
    readiness: dict[str, Any],
    replay: dict[str, Any] | None,
    summary: dict[str, Any],
) -> None:
    """Render service, storage, model, replay, and data-pipeline readiness."""

    section_header(
        "System health",
        "Operational readiness for the API, data stores, model artifacts, and replay engine.",
    )
    components = readiness.get("components", {})
    component_ready = all(components.values()) if components else False
    cards = st.columns(5)
    cards[0].metric("API", labelize(health.get("status", "unknown")))
    cards[1].metric("Databases", "Ready" if component_ready else "Degraded")
    cards[2].metric("Replay", labelize((replay or {}).get("status", "not started")))
    cards[3].metric("Events stored", f"{summary.get('events', 0):,}")
    cards[4].metric("Alerts stored", f"{summary.get('alerts', 0):,}")

    left, right = st.columns(2)
    with left:
        section_header("Component readiness", "Live dependency checks from the backend.")
        if components:
            for component, ready in components.items():
                if ready:
                    st.success(f"{labelize(component)} · ready")
                else:
                    st.error(f"{labelize(component)} · unavailable")
        else:
            st.warning("No component readiness details were returned.")
    with right:
        section_header("Replay engine", "Current background processing state.")
        if replay:
            total = max(1, int(replay.get("total_events", 1)))
            processed = int(replay.get("processed_events", 0))
            st.progress(processed / total, text=f"{processed:,} / {total:,} events")
            st.json(
                {
                    "run_id": replay.get("run_id"),
                    "status": replay.get("status"),
                    "alerts_generated": replay.get("alerts_generated"),
                    "started_at": replay.get("started_at"),
                    "completed_at": replay.get("completed_at"),
                    "error_message": replay.get("error_message"),
                }
            )
        else:
            st.info("No replay run has been recorded.")

    with st.expander("Raw health payloads"):
        st.json({"health": health, "readiness": readiness})
