"""Loading utilities for separated operational events and ground truth."""

import json
from pathlib import Path
from typing import Any

import pandas as pd


def load_labeled_dataset(dataset_directory: Path) -> pd.DataFrame:
    """Load events and labels by event identifier without leaking label columns."""

    events_path = dataset_directory / "events.csv"
    labels_path = dataset_directory / "labels.csv"
    if not events_path.is_file() or not labels_path.is_file():
        raise FileNotFoundError("dataset directory must contain events.csv and labels.csv")
    events = load_operational_events(events_path)
    labels = pd.read_csv(labels_path, usecols=["event_id", "label"])
    frame = events.merge(labels, on="event_id", how="inner", validate="one_to_one")
    if len(frame) != len(events):
        raise ValueError("every event must have exactly one ground-truth record")
    return frame.sort_values("timestamp", kind="stable").reset_index(drop=True)


def load_operational_events(events_path: Path) -> pd.DataFrame:
    """Load exported operational events without requiring ground truth."""

    if not events_path.is_file():
        raise FileNotFoundError(f"operational events file does not exist: {events_path}")
    frame = pd.read_csv(events_path)
    if "label" in frame.columns:
        raise ValueError("operational event data must not contain ground-truth labels")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="mixed")
    for column in ("geo_location", "command_sequence", "extensions"):
        frame[column] = frame[column].map(_parse_json)
    return frame.sort_values("timestamp", kind="stable").reset_index(drop=True)


def _parse_json(value: str) -> Any:
    """Decode a JSON field emitted by the dataset exporter."""

    return json.loads(value)
