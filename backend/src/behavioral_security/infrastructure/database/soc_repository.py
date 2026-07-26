"""SQLite persistence for replay events, risk assessments, and alerts."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from behavioral_security.core.models.alert import ClassifiedAlert
from behavioral_security.infrastructure.database.connection import SQLiteConnectionFactory


class SOCRepository:
    """Persist and query the operational SOC demo state."""

    def __init__(self, factory: SQLiteConnectionFactory) -> None:
        """Store the operational connection factory."""

        self._factory = factory

    def persist_event(self, row: Mapping[str, Any]) -> None:
        """Persist one operational event and its entity without labels."""

        now = datetime.now(UTC).isoformat()
        with self._factory.connect() as connection:
            connection.execute(
                """
                INSERT INTO entities(
                    entity_id, entity_type, department, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(entity_id) DO UPDATE SET updated_at=excluded.updated_at
                """,
                (
                    str(row["entity_id"]),
                    str(row["entity_type"]),
                    _optional_text(row.get("department")),
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO security_events(
                    event_id, entity_id, entity_type, event_timestamp, source_ip,
                    geo_location_json, resource_accessed, auth_method, auth_outcome,
                    session_duration, command_sequence_json, device_fingerprint,
                    department, resource_sensitivity, bytes_transferred, destination_ip,
                    schema_version, extensions_json, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    entity_id=excluded.entity_id,
                    entity_type=excluded.entity_type,
                    event_timestamp=excluded.event_timestamp,
                    source_ip=excluded.source_ip,
                    geo_location_json=excluded.geo_location_json,
                    resource_accessed=excluded.resource_accessed,
                    auth_method=excluded.auth_method,
                    auth_outcome=excluded.auth_outcome,
                    session_duration=excluded.session_duration,
                    command_sequence_json=excluded.command_sequence_json,
                    device_fingerprint=excluded.device_fingerprint,
                    department=excluded.department,
                    resource_sensitivity=excluded.resource_sensitivity,
                    bytes_transferred=excluded.bytes_transferred,
                    destination_ip=excluded.destination_ip,
                    schema_version=excluded.schema_version,
                    extensions_json=excluded.extensions_json,
                    ingested_at=excluded.ingested_at
                """,
                (
                    str(row["event_id"]),
                    str(row["entity_id"]),
                    str(row["entity_type"]),
                    str(row["timestamp"]),
                    str(row["source_ip"]),
                    json.dumps(row["geo_location"], sort_keys=True),
                    str(row["resource_accessed"]),
                    str(row["auth_method"]),
                    str(row["auth_outcome"]),
                    float(row["session_duration"]),
                    json.dumps(row["command_sequence"]),
                    str(row["device_fingerprint"]),
                    _optional_text(row.get("department")),
                    str(row["resource_sensitivity"]),
                    int(row["bytes_transferred"]),
                    _optional_text(row.get("destination_ip")),
                    str(row["schema_version"]),
                    json.dumps(row["extensions"], sort_keys=True),
                    now,
                ),
            )

    def persist_alert(self, alert: ClassifiedAlert) -> None:
        """Persist an enriched alert and its explainability evidence."""

        payload = alert.model_dump(mode="json")
        with self._factory.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO risk_assessments(
                    assessment_id, event_id, score, severity, confidence,
                    policy_version, component_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    str(alert.event_id),
                    alert.risk_score,
                    alert.severity.value,
                    alert.classifier_confidence,
                    alert.explanation.policy_version,
                    json.dumps(payload["explanation"]["components"], sort_keys=True),
                    alert.updated_at.isoformat(),
                ),
            )
            connection.execute(
                """
                INSERT INTO alerts(
                    alert_id, event_id, entity_id, attack_type, severity, status,
                    risk_score, classifier_confidence, classifier_version,
                    correlation_key, created_at, updated_at, event_timestamp,
                    explanation_json, recommended_actions_json, cold_start, drift_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    event_id=excluded.event_id,
                    entity_id=excluded.entity_id,
                    attack_type=excluded.attack_type,
                    severity=excluded.severity,
                    status=excluded.status,
                    risk_score=excluded.risk_score,
                    classifier_confidence=excluded.classifier_confidence,
                    classifier_version=excluded.classifier_version,
                    correlation_key=excluded.correlation_key,
                    updated_at=excluded.updated_at,
                    event_timestamp=excluded.event_timestamp,
                    explanation_json=excluded.explanation_json,
                    recommended_actions_json=excluded.recommended_actions_json,
                    cold_start=excluded.cold_start,
                    drift_status=excluded.drift_status
                """,
                (
                    str(alert.alert_id),
                    str(alert.event_id),
                    alert.entity_id,
                    alert.attack_type.value,
                    alert.severity.value,
                    alert.status.value,
                    alert.risk_score,
                    alert.classifier_confidence,
                    alert.classifier_version,
                    alert.correlation_key,
                    alert.created_at.isoformat(),
                    alert.updated_at.isoformat(),
                    alert.event_timestamp.isoformat() if alert.event_timestamp else None,
                    json.dumps(payload, sort_keys=True),
                    json.dumps(alert.recommended_actions),
                    int(alert.cold_start),
                    alert.drift_status,
                ),
            )
            connection.execute(
                "DELETE FROM alert_reasons WHERE alert_id = ?",
                (str(alert.alert_id),),
            )
            connection.executemany(
                """
                INSERT INTO alert_reasons(reason_id, alert_id, ordinal, reason_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    (
                        str(uuid4()),
                        str(alert.alert_id),
                        index,
                        json.dumps(reason, sort_keys=True),
                    )
                    for index, reason in enumerate(payload["explanation"]["reasons"])
                ),
            )

    def create_run(self, total_events: int, configuration: Mapping[str, Any]) -> str:
        """Create a running replay record and return its identifier."""

        run_id = str(uuid4())
        now = datetime.now(UTC).isoformat()
        with self._factory.connect() as connection:
            connection.execute(
                """
                INSERT INTO simulation_runs(
                    run_id, seed, configuration_json, status, replay_cursor,
                    started_at, total_events, processed_events, alerts_generated,
                    updated_at
                ) VALUES (?, ?, ?, 'running', '0', ?, ?, 0, 0, ?)
                """,
                (
                    run_id,
                    int(configuration.get("seed", 0)),
                    json.dumps(dict(configuration), sort_keys=True),
                    now,
                    total_events,
                    now,
                ),
            )
        return run_id

    def update_run(
        self,
        run_id: str,
        *,
        status: str,
        processed: int,
        alerts: int,
        error: str | None = None,
    ) -> None:
        """Update replay progress and terminal state."""

        now = datetime.now(UTC).isoformat()
        completed = now if status in {"completed", "failed"} else None
        with self._factory.connect() as connection:
            connection.execute(
                """
                UPDATE simulation_runs
                SET status=?, replay_cursor=?, processed_events=?, alerts_generated=?,
                    error_message=?, updated_at=?, completed_at=?
                WHERE run_id=?
                """,
                (status, str(processed), processed, alerts, error, now, completed, run_id),
            )

    def run_status(self, run_id: str | None = None) -> dict[str, Any] | None:
        """Return a requested or latest replay status."""

        query = (
            "SELECT * FROM simulation_runs WHERE run_id = ?"
            if run_id
            else "SELECT * FROM simulation_runs ORDER BY started_at DESC LIMIT 1"
        )
        parameters = (run_id,) if run_id else ()
        with self._factory.connect() as connection:
            row = connection.execute(query, parameters).fetchone()
        return dict(row) if row else None

    def recent_events(self, limit: int) -> list[dict[str, Any]]:
        """Return recent operational events without ground truth."""

        with self._factory.connect() as connection:
            rows = connection.execute(
                """
                SELECT event_id, entity_id, entity_type, event_timestamp AS timestamp,
                       source_ip, resource_accessed, auth_method, auth_outcome,
                       session_duration, device_fingerprint, resource_sensitivity,
                       bytes_transferred, ingested_at AS processed_at
                FROM security_events ORDER BY ingested_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def ranked_alerts(self, limit: int) -> list[dict[str, Any]]:
        """Return alerts ranked by risk and recency."""

        with self._factory.connect() as connection:
            rows = connection.execute(
                """
                SELECT explanation_json FROM alerts
                ORDER BY risk_score DESC, created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [json.loads(row["explanation_json"]) for row in rows]

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        """Return one complete alert document."""

        with self._factory.connect() as connection:
            row = connection.execute(
                "SELECT explanation_json FROM alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
        return json.loads(row["explanation_json"]) if row else None

    def entity_history(self, entity_id: str, limit: int) -> dict[str, Any] | None:
        """Return entity metadata and recent operational history."""

        with self._factory.connect() as connection:
            entity = connection.execute(
                "SELECT * FROM entities WHERE entity_id = ?",
                (entity_id,),
            ).fetchone()
            rows = connection.execute(
                """
                SELECT event_id, event_timestamp AS timestamp, source_ip,
                       resource_accessed, auth_outcome, device_fingerprint
                FROM security_events WHERE entity_id = ?
                ORDER BY event_timestamp DESC LIMIT ?
                """,
                (entity_id, limit),
            ).fetchall()
        if entity is None:
            return None
        return {"entity": dict(entity), "events": [dict(row) for row in rows]}

    def summary(self) -> dict[str, Any]:
        """Return compact dashboard counts and distributions."""

        with self._factory.connect() as connection:
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM security_events) AS events,
                    (SELECT COUNT(*) FROM alerts) AS alerts,
                    (SELECT COUNT(DISTINCT entity_id) FROM security_events) AS entities,
                    (SELECT COALESCE(AVG(risk_score), 0) FROM alerts) AS average_risk
                """
            ).fetchone()
            severities = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
            ).fetchall()
            attacks = connection.execute(
                "SELECT attack_type, COUNT(*) AS count FROM alerts GROUP BY attack_type"
            ).fetchall()
        return {
            **dict(counts),
            "severity_distribution": {row["severity"]: row["count"] for row in severities},
            "attack_distribution": {row["attack_type"]: row["count"] for row in attacks},
            "latest_replay": self.run_status(),
        }


def _optional_text(value: object) -> str | None:
    """Convert nullable pandas values to optional text."""

    if value is None or str(value) in {"nan", "NaN", "<NA>"}:
        return None
    return str(value)
