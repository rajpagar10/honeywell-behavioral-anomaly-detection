"""End-to-end profiling, training, evaluation, and inference pipeline."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from behavioral_security.application.dataset import (
    load_labeled_dataset,
    load_operational_events,
)
from behavioral_security.application.evaluation import (
    evaluate_predictions,
    tune_threshold,
)
from behavioral_security.application.training_config import TrainingConfig
from behavioral_security.classification import AttackClassifier
from behavioral_security.detection import (
    IsolationForestDetector,
    apply_sequence_rules,
    engineer_features,
)
from behavioral_security.profiling import ProfileStore, build_profile_store


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Paths and metrics produced by a completed training pipeline."""

    model_path: Path
    profiles_path: Path
    metrics_path: Path
    predictions_path: Path
    metrics: dict[str, Any]


def train_and_evaluate(
    dataset_directory: Path,
    output_directory: Path,
    config: TrainingConfig,
) -> PipelineResult:
    """Run the complete profile-to-evaluation workflow and persist artifacts."""

    events = load_labeled_dataset(dataset_directory)
    profiles = build_profile_store(events, config.profile_fraction)
    features = engineer_features(events, profiles)
    rules = apply_sequence_rules(features)
    features = pd.concat([features, rules], axis=1)
    train_indices, test_indices = _split_indices(features, config)
    detector = IsolationForestDetector(
        estimators=config.isolation_forest_estimators,
        contamination=config.isolation_forest_contamination,
        seed=config.seed,
    )
    normal_train = features.iloc[train_indices]
    normal_train = normal_train[normal_train["label"] == "normal"]
    detector.fit(normal_train)
    classifier = AttackClassifier(config.random_forest_estimators, config.seed)
    classifier_train = features.iloc[train_indices]
    classifier_train = classifier_train[classifier_train["label"] != "normal"]
    classifier.fit(classifier_train, classifier_train["label"])
    all_scores = _combined_scores(features, detector)
    threshold = tune_threshold(features.iloc[train_indices]["label"], all_scores[train_indices])
    test_features = features.iloc[test_indices]
    test_scores = all_scores[test_indices]
    attack_predictions = classifier.predict(test_features)
    metrics = evaluate_predictions(
        test_features["label"],
        test_scores,
        threshold,
        attack_predictions,
    )
    predictions = _prediction_frame(test_features, test_scores, threshold, attack_predictions)
    return _save_outputs(
        output_directory,
        config,
        profiles,
        detector,
        classifier,
        threshold,
        metrics,
        predictions,
    )


def run_inference(
    events_path: Path,
    model_path: Path,
    output_path: Path,
) -> Path:
    """Score operational events using a trusted trained artifact."""

    artifact = joblib.load(model_path)
    profiles = _require_type(artifact, "profiles", ProfileStore)
    detector = _require_type(artifact, "detector", IsolationForestDetector)
    classifier = _require_type(artifact, "classifier", AttackClassifier)
    threshold = float(artifact["threshold"])
    events = load_operational_events(events_path)
    features = engineer_features(events, profiles)
    rules = apply_sequence_rules(features)
    features = pd.concat([features, rules], axis=1)
    scores = _combined_scores(features, detector)
    predictions = _prediction_frame(
        features,
        scores,
        threshold,
        classifier.predict(features),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(output_path, index=False)
    return output_path


def evaluate_model(
    dataset_directory: Path,
    model_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Evaluate an existing trusted model artifact against separated labels."""

    artifact = joblib.load(model_path)
    profiles = _require_type(artifact, "profiles", ProfileStore)
    detector = _require_type(artifact, "detector", IsolationForestDetector)
    classifier = _require_type(artifact, "classifier", AttackClassifier)
    threshold = float(artifact["threshold"])
    features = engineer_features(load_labeled_dataset(dataset_directory), profiles)
    features = pd.concat([features, apply_sequence_rules(features)], axis=1)
    scores = _combined_scores(features, detector)
    metrics = evaluate_predictions(
        features["label"],
        scores,
        threshold,
        classifier.predict(features),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metrics


def _split_indices(
    features: pd.DataFrame,
    config: TrainingConfig,
) -> tuple[np.ndarray, np.ndarray]:
    """Create reproducible stratified train and test indices."""

    indices = np.arange(len(features))
    counts = features["label"].value_counts()
    stratify = features["label"] if int(counts.min()) >= 2 else None
    train, test = train_test_split(
        indices,
        test_size=config.test_fraction,
        random_state=config.seed,
        stratify=stratify,
    )
    return np.sort(train), np.sort(test)


def _combined_scores(
    features: pd.DataFrame,
    detector: IsolationForestDetector,
) -> np.ndarray:
    """Combine unknown-attack confidence with deterministic sequence evidence."""

    isolation_scores = detector.score(features)
    rule_scores = features["rule_score"].astype(float).to_numpy()
    return cast(np.ndarray, np.maximum(isolation_scores, rule_scores))


def _prediction_frame(
    features: pd.DataFrame,
    scores: np.ndarray,
    threshold: float,
    attack_predictions: np.ndarray,
) -> pd.DataFrame:
    """Build the operational inference output without ground-truth leakage."""

    detected = scores >= threshold
    result = pd.DataFrame(
        {
            "event_id": features["event_id"].astype(str).to_numpy(),
            "entity_id": features["entity_id"].astype(str).to_numpy(),
            "timestamp": features["timestamp"].astype(str).to_numpy(),
            "anomaly_score": np.round(scores, 6),
            "is_anomaly": detected,
            "attack_type": np.where(detected, attack_predictions, "normal"),
            "rule_attack_type": features["rule_attack_type"].astype(str).to_numpy(),
            "rule_score": features["rule_score"].astype(float).to_numpy(),
        }
    )
    return result


def _save_outputs(
    output_directory: Path,
    config: TrainingConfig,
    profiles: ProfileStore,
    detector: IsolationForestDetector,
    classifier: AttackClassifier,
    threshold: float,
    metrics: dict[str, Any],
    predictions: pd.DataFrame,
) -> PipelineResult:
    """Persist model, profiles, predictions, and evaluation metrics."""

    output_directory.mkdir(parents=True, exist_ok=True)
    model_path = output_directory / "model.joblib"
    profiles_path = output_directory / "profiles.json"
    metrics_path = output_directory / "metrics.json"
    predictions_path = output_directory / "predictions.csv"
    joblib.dump(
        {
            "artifact_version": 1,
            "config": config.model_dump(mode="json"),
            "profiles": profiles,
            "detector": detector,
            "classifier": classifier,
            "threshold": threshold,
        },
        model_path,
    )
    profile_payload = {
        entity_id: profile.model_dump(mode="json")
        for entity_id, profile in profiles.entities.items()
    }
    profiles_path.write_text(
        json.dumps(profile_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metrics_path.write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    predictions.to_csv(predictions_path, index=False)
    return PipelineResult(
        model_path,
        profiles_path,
        metrics_path,
        predictions_path,
        metrics,
    )


def _require_type(artifact: dict[str, Any], key: str, expected: type[Any]) -> Any:
    """Validate a required object loaded from a model artifact."""

    value = artifact.get(key)
    if not isinstance(value, expected):
        raise ValueError(f"model artifact contains invalid {key}")
    return value
