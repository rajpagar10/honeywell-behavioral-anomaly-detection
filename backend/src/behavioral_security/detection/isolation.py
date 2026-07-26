"""Isolation Forest anomaly detector with robust feature scaling."""

from dataclasses import dataclass
from typing import cast

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from behavioral_security.detection.features import MODEL_FEATURES


@dataclass(slots=True)
class IsolationForestDetector:
    """Fit and score multivariate behavioral deviations."""

    estimators: int
    contamination: float
    seed: int
    scaler: RobustScaler | None = None
    model: IsolationForest | None = None
    score_low: float = 0.0
    score_high: float = 1.0

    def fit(self, features: pd.DataFrame) -> None:
        """Fit a robust scaler and Isolation Forest on baseline events."""

        matrix = features.loc[:, MODEL_FEATURES].astype(float).to_numpy()
        self.scaler = RobustScaler()
        transformed = self.scaler.fit_transform(matrix)
        self.model = IsolationForest(
            n_estimators=self.estimators,
            contamination=self.contamination,
            random_state=self.seed,
            n_jobs=-1,
        )
        self.model.fit(transformed)
        raw = -self.model.decision_function(transformed)
        self.score_low = float(np.quantile(raw, 0.5))
        self.score_high = float(np.quantile(raw, 0.995))
        if self.score_high <= self.score_low:
            self.score_high = self.score_low + 1e-9

    def score(self, features: pd.DataFrame) -> np.ndarray:
        """Return normalized anomaly confidence between zero and one."""

        if self.scaler is None or self.model is None:
            raise RuntimeError("detector must be fitted before scoring")
        matrix = features.loc[:, MODEL_FEATURES].astype(float).to_numpy()
        raw = -self.model.decision_function(self.scaler.transform(matrix))
        normalized = (raw - self.score_low) / (self.score_high - self.score_low)
        return cast(
            np.ndarray,
            1.0 / (1.0 + np.exp(-np.clip(6.0 * (normalized - 0.5), -60.0, 60.0))),
        )
