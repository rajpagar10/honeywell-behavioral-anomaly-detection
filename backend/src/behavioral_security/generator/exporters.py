"""Atomic CSV and JSON dataset export."""

import csv
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from behavioral_security.core.models.access_event import AccessEvent, GroundTruthRecord
from behavioral_security.generator.config import GeneratorConfig
from behavioral_security.generator.models import (
    ExportedDataset,
    GeneratedDataset,
    GenerationSummary,
)

_EVENT_FIELDS = (
    "event_id",
    "entity_id",
    "entity_type",
    "timestamp",
    "source_ip",
    "geo_location",
    "resource_accessed",
    "auth_method",
    "session_duration",
    "command_sequence",
    "device_fingerprint",
    "auth_outcome",
    "department",
    "resource_sensitivity",
    "bytes_transferred",
    "destination_ip",
    "schema_version",
    "extensions",
)
_LABEL_FIELDS = (
    "event_id",
    "label",
    "attack_campaign_id",
    "generated_at",
    "scenario_metadata",
)


def export_dataset(
    dataset: GeneratedDataset,
    config: GeneratorConfig,
    summary: GenerationSummary,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> ExportedDataset:
    """Write operational events, labels, profiles, and manifest separately."""

    output_directory.mkdir(parents=True, exist_ok=True)
    paths = ExportedDataset(
        events_path=output_directory / "events.csv",
        labels_path=output_directory / "labels.csv",
        profiles_path=output_directory / "profiles.json",
        manifest_path=output_directory / "manifest.json",
    )
    targets = (
        paths.events_path,
        paths.labels_path,
        paths.profiles_path,
        paths.manifest_path,
    )
    existing = [path for path in targets if path.exists()]
    if existing and not overwrite:
        names = ", ".join(path.name for path in existing)
        raise FileExistsError(f"refusing to overwrite existing dataset files: {names}")

    _write_csv_atomic(
        paths.events_path,
        _EVENT_FIELDS,
        (_event_row(event) for event in dataset.events),
    )
    _write_csv_atomic(
        paths.labels_path,
        _LABEL_FIELDS,
        (_label_row(record) for record in dataset.labels),
    )
    _write_json_atomic(
        paths.profiles_path,
        [profile.model_dump(mode="json") for profile in dataset.profiles],
    )
    _write_json_atomic(
        paths.manifest_path,
        {
            "summary": summary.model_dump(mode="json"),
            "configuration": config.model_dump(mode="json"),
            "separation": {
                "operational_events": paths.events_path.name,
                "ground_truth_labels": paths.labels_path.name,
                "labels_present_in_event_file": False,
            },
        },
    )
    return paths


def _event_row(event: AccessEvent) -> dict[str, object]:
    """Serialize one operational event without adding its label."""

    payload = event.model_dump(mode="json")
    return {field: _csv_value(payload[field]) for field in _EVENT_FIELDS}


def _label_row(record: GroundTruthRecord) -> dict[str, object]:
    """Serialize one isolated ground-truth record."""

    payload = record.model_dump(mode="json")
    return {field: _csv_value(payload[field]) for field in _LABEL_FIELDS}


def _csv_value(value: Any) -> object:
    """Convert nested CSV values to deterministic compact JSON."""

    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return "" if value is None else value


def _write_csv_atomic(
    path: Path,
    fields: tuple[str, ...],
    rows: Iterable[dict[str, object]],
) -> None:
    """Write a CSV file through a sibling temporary path."""

    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="raise")
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json_atomic(path: Path, payload: object) -> None:
    """Write formatted JSON through a sibling temporary path."""

    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
