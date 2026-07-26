"""Smoke coverage for the complete behavioral-model pipeline."""

from pathlib import Path

import pandas as pd

from behavioral_security.application.pipeline import (
    evaluate_model,
    run_inference,
    train_and_evaluate,
)
from behavioral_security.application.training_config import load_training_config

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_training_evaluation_and_inference_pipeline(tmp_path: Path) -> None:
    """Train, evaluate, persist, reload, and score the demo dataset."""

    dataset = PROJECT_ROOT / "data" / "samples" / "honeywell_demo"
    config = load_training_config(PROJECT_ROOT / "config" / "training" / "fast.yaml")
    result = train_and_evaluate(dataset, tmp_path / "model", config)

    assert result.metrics["event_count"] == 600
    assert result.metrics["pr_auc"] >= 0.0
    assert result.model_path.is_file()
    assert result.profiles_path.is_file()
    assert result.predictions_path.is_file()

    evaluation = evaluate_model(
        dataset,
        result.model_path,
        tmp_path / "evaluation.json",
    )
    assert evaluation["event_count"] == 2000

    inference_path = run_inference(
        dataset / "events.csv",
        result.model_path,
        tmp_path / "inference.csv",
    )
    predictions = pd.read_csv(inference_path)
    assert len(predictions) == 2000
    assert {"anomaly_score", "is_anomaly", "attack_type"}.issubset(predictions.columns)
