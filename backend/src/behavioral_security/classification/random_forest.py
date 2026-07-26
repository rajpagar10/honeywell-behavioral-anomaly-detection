"""Class-weighted Random Forest attack classification."""

from dataclasses import dataclass
from typing import cast

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from behavioral_security.detection.features import MODEL_FEATURES


@dataclass(slots=True)
class AttackClassifier:
    """Predict known attack types from behavioral and sequence features."""

    estimators: int
    seed: int
    model: RandomForestClassifier | None = None

    def fit(self, features: pd.DataFrame, labels: pd.Series) -> None:
        """Fit a class-balanced attack classifier."""

        self.model = RandomForestClassifier(
            n_estimators=self.estimators,
            class_weight="balanced_subsample",
            min_samples_leaf=1,
            random_state=self.seed,
            n_jobs=-1,
        )
        self.model.fit(features.loc[:, MODEL_FEATURES].astype(float), labels.astype(str))

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        """Predict the most likely attack taxonomy label."""

        if self.model is None:
            raise RuntimeError("classifier must be fitted before prediction")
        return cast(
            np.ndarray,
            self.model.predict(features.loc[:, MODEL_FEATURES].astype(float)),
        )
