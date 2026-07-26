"""Smoke coverage for the complete behavioral-model pipeline."""

from pathlib import Path
from time import monotonic, sleep

import pandas as pd
from fastapi.testclient import TestClient

from behavioral_security.api.app import create_app
from behavioral_security.application.pipeline import (
    evaluate_model,
    run_inference,
    train_and_evaluate,
)
from behavioral_security.application.training_config import load_training_config
from behavioral_security.infrastructure.config.settings import IntelligenceSettings, Settings

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_training_evaluation_and_inference_pipeline(
    tmp_path: Path,
    test_settings: Settings,
) -> None:
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

    api_settings = test_settings.model_copy(
        update={
            "intelligence": IntelligenceSettings(
                model_path=result.model_path,
                events_path=dataset / "events.csv",
                metrics_path=result.metrics_path,
                alert_threshold=55.0,
                replay_interval_ms=0,
            )
        }
    )
    with TestClient(create_app(api_settings)) as client:
        started = client.post(
            "/api/v1/replay/start",
            json={"interval_ms": 0, "max_events": 2000},
        )
        assert started.status_code == 202
        deadline = monotonic() + 20
        replay = client.get("/api/v1/replay/status").json()
        while replay["status"] == "running" and monotonic() < deadline:
            sleep(0.05)
            replay = client.get("/api/v1/replay/status").json()

        assert replay["status"] == "completed"
        assert replay["processed_events"] == 2000
        assert replay["alerts_generated"] > 0
        alerts = client.get("/api/v1/alerts").json()
        assert alerts
        detail = client.get(f"/api/v1/alerts/{alerts[0]['alert_id']}").json()
        assert 0 <= detail["risk_score"] <= 100
        assert detail["human_explanation"].startswith("Flagged because")
        assert detail["recommended_actions"]
        assert "cold_start" in detail
        assert "drift_status" in detail
        entity = client.get(f"/api/v1/entities/{detail['entity_id']}").json()
        assert "cold_start" in entity
        assert "drift" in entity
        assert client.get("/api/v1/dashboard/summary").status_code == 200
        assert client.get("/api/v1/evaluation/metrics").status_code == 200
