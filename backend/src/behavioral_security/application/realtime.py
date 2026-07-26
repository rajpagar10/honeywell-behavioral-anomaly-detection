"""Near-real-time model-backed event replay and SOC query service."""

import asyncio
import json
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

import joblib
import numpy as np
import pandas as pd

from behavioral_security.application.dataset import load_operational_events
from behavioral_security.classification import AttackClassifier
from behavioral_security.detection import (
    IsolationForestDetector,
    apply_sequence_rules,
    engineer_features,
)
from behavioral_security.infrastructure.config.settings import IntelligenceSettings
from behavioral_security.infrastructure.database.soc_repository import SOCRepository
from behavioral_security.profiling import AdaptiveProfileTracker, ProfileStore
from behavioral_security.risk import RiskPolicy


class RealtimeSOCService:
    """Replay events sequentially and maintain queryable SOC state."""

    def __init__(
        self,
        repository: SOCRepository,
        settings: IntelligenceSettings,
        *,
        project_root: Path,
    ) -> None:
        """Initialize replay dependencies and adaptive state."""

        self._repository = repository
        self._settings = settings
        self._project_root = project_root
        self._risk_policy = RiskPolicy()
        self._adaptive = AdaptiveProfileTracker()
        self._task: asyncio.Task[None] | None = None
        self._profiles: ProfileStore | None = None

    async def start_replay(
        self,
        *,
        interval_ms: int | None = None,
        max_events: int | None = None,
    ) -> dict[str, Any]:
        """Prepare scored events and start sequential background replay."""

        if self._task is not None and not self._task.done():
            status = self._repository.run_status()
            if status is None:
                raise RuntimeError("replay is running without persisted status")
            return status
        frame, threshold = self._prepare_frame(max_events)
        interval = self._settings.replay_interval_ms if interval_ms is None else interval_ms
        run_id = self._repository.create_run(
            len(frame),
            {
                "seed": 1729,
                "interval_ms": interval,
                "model_threshold": threshold,
                "events_path": str(self._resolve(self._settings.events_path)),
            },
        )
        self._task = asyncio.create_task(
            self._replay(run_id, frame, threshold, interval),
            name=f"event-replay-{run_id}",
        )
        status = self._repository.run_status(run_id)
        if status is None:
            raise RuntimeError("failed to create replay status")
        return status

    def replay_status(self, run_id: str | None = None) -> dict[str, Any] | None:
        """Return replay progress."""

        return self._repository.run_status(run_id)

    def dashboard_summary(self) -> dict[str, Any]:
        """Return dashboard counts and model evaluation headline metrics."""

        summary = self._repository.summary()
        metrics = self.evaluation_metrics()
        summary["model_metrics"] = {
            key: metrics.get(key)
            for key in ("precision", "recall", "f1_score", "pr_auc", "false_positive_rate")
        }
        return summary

    def recent_events(self, limit: int) -> list[dict[str, Any]]:
        """Return recent replayed events."""

        return self._repository.recent_events(limit)

    def ranked_alerts(self, limit: int) -> list[dict[str, Any]]:
        """Return alerts ranked by risk score."""

        return self._repository.ranked_alerts(limit)

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        """Return one alert with full explanation."""

        return self._repository.alert(alert_id)

    def entity_history(self, entity_id: str, limit: int) -> dict[str, Any] | None:
        """Return entity events, baseline profile, and adaptive drift state."""

        history = self._repository.entity_history(entity_id, limit)
        if history is None:
            return None
        profile = self._profiles.entities.get(entity_id) if self._profiles else None
        history["profile"] = profile.model_dump(mode="json") if profile else None
        history["cold_start"] = profile is None or profile.maturity < 0.35
        history["drift"] = self._adaptive.snapshot(entity_id)
        return history

    def evaluation_metrics(self) -> dict[str, Any]:
        """Return persisted model evaluation metrics when available."""

        path = self._resolve(self._settings.metrics_path)
        if not path.is_file():
            return {"status": "unavailable", "detail": "train the model to produce metrics"}
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("evaluation metrics must be a JSON object")
        return payload

    async def shutdown(self) -> None:
        """Cancel an active replay during API shutdown."""

        if self._task is not None and not self._task.done():
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    def _prepare_frame(self, max_events: int | None) -> tuple[pd.DataFrame, float]:
        """Load a trusted artifact and precompute sequential model outputs."""

        model_path = self._resolve(self._settings.model_path)
        if not model_path.is_file():
            raise FileNotFoundError(f"model artifact not found: {model_path}")
        artifact = joblib.load(model_path)
        if not isinstance(artifact, dict):
            raise ValueError("model artifact must contain a mapping")
        profiles = _typed(artifact, "profiles", ProfileStore)
        detector = _typed(artifact, "detector", IsolationForestDetector)
        classifier = _typed(artifact, "classifier", AttackClassifier)
        threshold = float(artifact["threshold"])
        events = load_operational_events(self._resolve(self._settings.events_path))
        if max_events is not None:
            events = events.iloc[:max_events].copy()
        features = engineer_features(events, profiles)
        features = pd.concat([features, apply_sequence_rules(features)], axis=1)
        anomaly_scores = detector.score(features)
        predictions = classifier.predict(features)
        confidences = classifier.confidence(features)
        rule_types = features["rule_attack_type"].astype(str).to_numpy()
        rule_scores = features["rule_score"].astype(float).to_numpy()
        features["anomaly_score"] = anomaly_scores
        features["predicted_attack"] = np.where(rule_types != "normal", rule_types, predictions)
        features["classification_confidence"] = np.maximum(confidences, rule_scores)
        self._profiles = profiles
        return features, threshold

    async def _replay(
        self,
        run_id: str,
        frame: pd.DataFrame,
        threshold: float,
        interval_ms: int,
    ) -> None:
        """Persist scored events one at a time and update progress."""

        alerts = 0
        processed = 0
        try:
            for row in frame.to_dict(orient="records"):
                self._repository.persist_event(row)
                adjusted, _ = self._adaptive.adjust(row)
                trusted = float(row["rule_score"]) == 0.0 and float(row["anomaly_score"]) < min(
                    threshold, 0.9
                )
                drift_status = self._adaptive.observe(adjusted, trusted=trusted)
                alert = self._risk_policy.assess(
                    adjusted,
                    anomaly_score=float(row["anomaly_score"]),
                    predicted_attack=str(row["predicted_attack"]),
                    classifier_confidence=float(row["classification_confidence"]),
                    rule_score=float(row["rule_score"]),
                    drift_status=drift_status,
                )
                if alert.risk_score >= self._settings.alert_threshold:
                    self._repository.persist_alert(alert)
                    alerts += 1
                processed += 1
                if processed % 10 == 0 or processed == len(frame):
                    self._repository.update_run(
                        run_id,
                        status="running",
                        processed=processed,
                        alerts=alerts,
                    )
                if interval_ms:
                    await asyncio.sleep(interval_ms / 1000.0)
            self._repository.update_run(
                run_id,
                status="completed",
                processed=processed,
                alerts=alerts,
            )
        except Exception as error:
            self._repository.update_run(
                run_id,
                status="failed",
                processed=processed,
                alerts=alerts,
                error=str(error),
            )

    def _resolve(self, path: Path) -> Path:
        """Resolve a configured path against the project root."""

        return path if path.is_absolute() else self._project_root / path


def _typed(artifact: dict[str, Any], key: str, expected: type[Any]) -> Any:
    """Return a required typed artifact component."""

    value = artifact.get(key)
    if not isinstance(value, expected):
        raise ValueError(f"model artifact contains invalid {key}")
    return cast(Any, value)
