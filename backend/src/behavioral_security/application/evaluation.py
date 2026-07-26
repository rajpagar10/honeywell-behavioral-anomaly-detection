"""Metrics for anomaly detection and attack classification."""

from math import ceil
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)


def tune_threshold(labels: pd.Series, scores: np.ndarray) -> float:
    """Select the score threshold that maximizes anomaly F1."""

    binary = (labels.astype(str) != "normal").astype(int).to_numpy()
    precision, recall, thresholds = precision_recall_curve(binary, scores)
    if thresholds.size == 0:
        return 0.5
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    return float(thresholds[int(np.argmax(f1))])


def evaluate_predictions(
    labels: pd.Series,
    anomaly_scores: np.ndarray,
    threshold: float,
    attack_predictions: np.ndarray,
) -> dict[str, Any]:
    """Calculate binary, ranking, and per-attack evaluation metrics."""

    truth = labels.astype(str).to_numpy()
    binary_truth = (truth != "normal").astype(int)
    binary_prediction = (anomaly_scores >= threshold).astype(int)
    predicted_labels = np.where(binary_prediction == 1, attack_predictions, "normal")
    false_positives = int(((binary_prediction == 1) & (binary_truth == 0)).sum())
    normal_count = int((binary_truth == 0).sum())
    top_count = max(1, ceil(len(truth) * 0.01))
    top_indices = np.argsort(anomaly_scores)[-top_count:]
    top_true_positives = int(binary_truth[top_indices].sum())
    labels_order = sorted(set(truth).union(map(str, predicted_labels)))
    return {
        "threshold": threshold,
        "event_count": len(truth),
        "anomaly_count": int(binary_truth.sum()),
        "precision": float(precision_score(binary_truth, binary_prediction, zero_division=0)),
        "recall": float(recall_score(binary_truth, binary_prediction, zero_division=0)),
        "f1_score": float(f1_score(binary_truth, binary_prediction, zero_division=0)),
        "pr_auc": float(average_precision_score(binary_truth, anomaly_scores)),
        "false_positive_rate": false_positives / max(1, normal_count),
        "top_1_percent": {
            "event_count": top_count,
            "precision": top_true_positives / top_count,
            "recall": top_true_positives / max(1, int(binary_truth.sum())),
        },
        "confusion_matrix": {
            "labels": labels_order,
            "values": confusion_matrix(truth, predicted_labels, labels=labels_order).tolist(),
        },
        "per_attack": classification_report(
            truth,
            predicted_labels,
            labels=labels_order,
            output_dict=True,
            zero_division=0,
        ),
    }
