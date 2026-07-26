"""Versioned SQLite schema definitions."""

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Migration:
    """One atomic, ordered database schema migration."""

    version: int
    name: str
    statements: tuple[str, ...]


OPERATIONAL_MIGRATIONS: Final[tuple[Migration, ...]] = (
    Migration(
        version=1,
        name="initial_operational_schema",
        statements=(
            """
            CREATE TABLE entities (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                department TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE security_events (
                event_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                geo_location_json TEXT NOT NULL,
                resource_accessed TEXT NOT NULL,
                auth_method TEXT NOT NULL,
                auth_outcome TEXT NOT NULL,
                session_duration REAL NOT NULL CHECK (session_duration >= 0),
                command_sequence_json TEXT NOT NULL,
                device_fingerprint TEXT NOT NULL,
                department TEXT,
                resource_sensitivity TEXT NOT NULL,
                bytes_transferred INTEGER NOT NULL CHECK (bytes_transferred >= 0),
                destination_ip TEXT,
                schema_version TEXT NOT NULL,
                extensions_json TEXT NOT NULL DEFAULT '{}',
                ingested_at TEXT NOT NULL,
                FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
            )
            """,
            """
            CREATE TABLE behavioral_profiles (
                entity_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL UNIQUE,
                profile_version INTEGER NOT NULL CHECK (profile_version >= 1),
                maturity REAL NOT NULL CHECK (maturity BETWEEN 0 AND 1),
                effective_sample_size REAL NOT NULL CHECK (effective_sample_size >= 0),
                profile_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
            )
            """,
            """
            CREATE TABLE profile_versions (
                profile_id TEXT NOT NULL,
                profile_version INTEGER NOT NULL,
                entity_id TEXT NOT NULL,
                profile_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (profile_id, profile_version),
                FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
            )
            """,
            """
            CREATE TABLE model_predictions (
                prediction_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                model_name TEXT NOT NULL,
                model_version TEXT NOT NULL,
                model_family TEXT NOT NULL,
                raw_score REAL NOT NULL,
                calibrated_score REAL NOT NULL CHECK (calibrated_score BETWEEN 0 AND 1),
                predicted_attack TEXT,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES security_events(event_id)
            )
            """,
            """
            CREATE TABLE rule_findings (
                finding_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES security_events(event_id)
            )
            """,
            """
            CREATE TABLE risk_assessments (
                assessment_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                score REAL NOT NULL CHECK (score BETWEEN 0 AND 100),
                severity TEXT NOT NULL,
                confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                policy_version TEXT NOT NULL,
                component_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES security_events(event_id)
            )
            """,
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                entity_id TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                classifier_confidence REAL NOT NULL CHECK (classifier_confidence BETWEEN 0 AND 1),
                classifier_version TEXT NOT NULL,
                correlation_key TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES security_events(event_id),
                FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
            )
            """,
            """
            CREATE TABLE alert_reasons (
                reason_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                reason_json TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id),
                UNIQUE (alert_id, ordinal)
            )
            """,
            """
            CREATE TABLE analyst_feedback (
                feedback_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                analyst_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                corrected_attack_type TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
            )
            """,
            """
            CREATE TABLE model_registry (
                model_name TEXT NOT NULL,
                model_version TEXT NOT NULL,
                model_family TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                feature_schema_version TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                promoted_at TEXT,
                PRIMARY KEY (model_name, model_version)
            )
            """,
            """
            CREATE TABLE simulation_runs (
                run_id TEXT PRIMARY KEY,
                seed INTEGER NOT NULL CHECK (seed >= 0),
                configuration_json TEXT NOT NULL,
                status TEXT NOT NULL,
                replay_cursor TEXT,
                started_at TEXT,
                completed_at TEXT
            )
            """,
            """
            CREATE TABLE system_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                labels_json TEXT NOT NULL DEFAULT '{}',
                observed_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_events_entity_time ON security_events(entity_id, event_timestamp)",
            "CREATE INDEX idx_events_time ON security_events(event_timestamp)",
            "CREATE INDEX idx_events_device ON security_events(device_fingerprint)",
            "CREATE INDEX idx_predictions_event ON model_predictions(event_id)",
            "CREATE INDEX idx_findings_event ON rule_findings(event_id)",
            "CREATE INDEX idx_alerts_status_time ON alerts(status, created_at DESC)",
            "CREATE INDEX idx_alerts_entity_time ON alerts(entity_id, created_at DESC)",
            "CREATE INDEX idx_feedback_alert ON analyst_feedback(alert_id, created_at)",
            "CREATE INDEX idx_metrics_name_time ON system_metrics(metric_name, observed_at DESC)",
        ),
    ),
    Migration(
        version=2,
        name="realtime_risk_intelligence",
        statements=(
            "ALTER TABLE alerts ADD COLUMN event_timestamp TEXT",
            "ALTER TABLE alerts ADD COLUMN explanation_json TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE alerts ADD COLUMN recommended_actions_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE alerts ADD COLUMN cold_start INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE alerts ADD COLUMN drift_status TEXT NOT NULL DEFAULT 'stable'",
            "ALTER TABLE simulation_runs ADD COLUMN total_events INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE simulation_runs ADD COLUMN processed_events INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE simulation_runs ADD COLUMN alerts_generated INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE simulation_runs ADD COLUMN error_message TEXT",
            "ALTER TABLE simulation_runs ADD COLUMN updated_at TEXT",
        ),
    ),
)


EVALUATION_MIGRATIONS: Final[tuple[Migration, ...]] = (
    Migration(
        version=1,
        name="initial_evaluation_schema",
        statements=(
            """
            CREATE TABLE ground_truth (
                event_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                attack_campaign_id TEXT,
                generated_at TEXT NOT NULL,
                scenario_metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """,
            """
            CREATE TABLE evaluation_runs (
                evaluation_id TEXT PRIMARY KEY,
                dataset_version TEXT NOT NULL,
                configuration_json TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT
            )
            """,
            "CREATE INDEX idx_ground_truth_label ON ground_truth(label)",
        ),
    ),
)
