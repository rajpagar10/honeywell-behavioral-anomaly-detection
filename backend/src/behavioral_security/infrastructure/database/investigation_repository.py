"""Curated SQLite persistence for AI-assisted investigations."""

import json
from typing import Any

from behavioral_security.core.models.feedback import AnalystFeedback
from behavioral_security.infrastructure.database.connection import SQLiteConnectionFactory


class SQLiteInvestigationRepository:
    """Expose only allowlisted investigation evidence and feedback writes."""

    def __init__(self, factory: SQLiteConnectionFactory) -> None:
        """Store the operational connection factory."""

        self._factory = factory

    def investigation_context(self, alert_id: str) -> dict[str, Any] | None:
        """Return an allowlisted alert context without exposing raw storage."""

        with self._factory.connect() as connection:
            row = connection.execute(
                """
                SELECT a.explanation_json, e.event_id, e.entity_id, e.event_timestamp,
                       e.source_ip, e.geo_location_json, e.resource_accessed,
                       e.auth_method, e.auth_outcome, e.device_fingerprint,
                       e.resource_sensitivity
                FROM alerts a
                JOIN security_events e ON e.event_id = a.event_id
                WHERE a.alert_id = ?
                """,
                (alert_id,),
            ).fetchone()
            if row is None:
                return None
            previous = connection.execute(
                """
                SELECT e.event_timestamp AS timestamp, e.geo_location_json,
                       e.auth_outcome,
                       EXISTS(
                           SELECT 1 FROM alerts prior_alert
                           WHERE prior_alert.event_id = e.event_id
                       ) AS alerted
                FROM security_events e
                WHERE e.entity_id = ?
                  AND datetime(e.event_timestamp) < datetime(?)
                ORDER BY datetime(e.event_timestamp) DESC
                LIMIT 1
                """,
                (row["entity_id"], row["event_timestamp"]),
            ).fetchone()
            failure_row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM security_events
                WHERE entity_id = ?
                  AND auth_outcome = 'failure'
                  AND datetime(event_timestamp)
                      BETWEEN datetime(?, '-7 days') AND datetime(?)
                """,
                (row["entity_id"], row["event_timestamp"], row["event_timestamp"]),
            ).fetchone()
        event = {
            "event_id": row["event_id"],
            "entity_id": row["entity_id"],
            "timestamp": row["event_timestamp"],
            "source_ip": row["source_ip"],
            "geo_location": json.loads(row["geo_location_json"]),
            "resource_accessed": row["resource_accessed"],
            "auth_method": row["auth_method"],
            "auth_outcome": row["auth_outcome"],
            "device_fingerprint": row["device_fingerprint"],
            "resource_sensitivity": row["resource_sensitivity"],
        }
        previous_event = (
            {
                "timestamp": previous["timestamp"],
                "geo_location": json.loads(previous["geo_location_json"]),
                "auth_outcome": previous["auth_outcome"],
                "alerted": bool(previous["alerted"]),
            }
            if previous
            else None
        )
        return {
            "alert": json.loads(row["explanation_json"]),
            "event": event,
            "previous_event": previous_event,
            "failed_logins": int(failure_row["count"]) if failure_row else 0,
        }

    def persist_feedback(self, feedback: AnalystFeedback) -> None:
        """Persist append-only analyst feedback for an investigation."""

        with self._factory.connect() as connection:
            connection.execute(
                """
                INSERT INTO analyst_feedback(
                    feedback_id, alert_id, analyst_id, disposition,
                    corrected_attack_type, notes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(feedback.feedback_id),
                    str(feedback.alert_id),
                    feedback.analyst_id,
                    feedback.disposition.value,
                    (
                        feedback.corrected_attack_type.value
                        if feedback.corrected_attack_type
                        else None
                    ),
                    feedback.notes,
                    feedback.created_at.isoformat(),
                ),
            )
