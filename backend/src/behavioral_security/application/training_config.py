"""Typed configuration for the behavioral-model pipeline."""

from pathlib import Path
from typing import Annotated

import yaml
from pydantic import Field

from behavioral_security.core.models.common import StrictModel


class TrainingConfig(StrictModel):
    """Validated model-training and evaluation parameters."""

    name: str
    seed: Annotated[int, Field(ge=0)]
    profile_fraction: Annotated[float, Field(gt=0.05, le=0.5)]
    test_fraction: Annotated[float, Field(ge=0.2, le=0.5)]
    isolation_forest_estimators: Annotated[int, Field(ge=50, le=2000)]
    isolation_forest_contamination: Annotated[float, Field(ge=0.005, le=0.03)]
    random_forest_estimators: Annotated[int, Field(ge=50, le=2000)]


def load_training_config(path: Path) -> TrainingConfig:
    """Load and validate a YAML training preset."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"training configuration must be a mapping: {path}")
    return TrainingConfig.model_validate(payload)
