"""End-to-end synthetic generator and export tests."""

import csv
import json
from collections import defaultdict
from pathlib import Path

import pytest

from behavioral_security.core.enums import (
    AttackType,
    AuthenticationOutcome,
    EntityType,
)
from behavioral_security.generator.exporters import export_dataset
from behavioral_security.generator.stream import generate_dataset
from behavioral_security.generator.validation import validate_dataset

from ..factories import make_generator_config


def test_generation_is_reproducible_and_valid() -> None:
    config = make_generator_config(seed=777)

    first = generate_dataset(config)
    second = generate_dataset(config)
    summary = validate_dataset(first, config)

    assert first == second
    assert summary.event_count == config.event_count
    assert summary.anomaly_count == config.anomaly_event_count
    assert summary.anomaly_percentage == 3.0
    assert set(summary.entity_distribution) == {entity.value for entity in EntityType}
    assert summary.cold_start_entities > 0
    assert summary.drift_entities > 0


def test_normal_events_respect_stable_or_legitimate_drift_profiles() -> None:
    config = make_generator_config()
    dataset = generate_dataset(config)
    profiles = {profile.entity_id: profile for profile in dataset.profiles}

    for event, label in zip(dataset.events, dataset.labels, strict=True):
        if label.label is not AttackType.NORMAL:
            continue
        profile = profiles[event.entity_id]
        allowed_resources = set(profile.common_resources) | set(profile.drift_resources)
        allowed_devices = set(profile.known_devices)
        if profile.drift_device is not None:
            allowed_devices.add(profile.drift_device)
        assert event.resource_accessed in allowed_resources
        assert event.device_fingerprint in allowed_devices
        assert event.auth_method in profile.authentication_methods
        assert event.timestamp >= profile.active_after


def test_every_attack_has_distinct_observable_behavior() -> None:
    config = make_generator_config()
    dataset = generate_dataset(config)
    events_by_attack = defaultdict(list)
    for event, label in zip(dataset.events, dataset.labels, strict=True):
        events_by_attack[label.label].append(event)

    brute = events_by_attack[AttackType.BRUTE_FORCE]
    assert (
        sum(event.auth_outcome is AuthenticationOutcome.FAILURE for event in brute)
        >= len(brute) - 1
    )
    stuffing = events_by_attack[AttackType.CREDENTIAL_STUFFING]
    assert len({str(event.source_ip) for event in stuffing}) == 1
    assert len({event.entity_id for event in stuffing}) >= 2
    assert all(
        event.device_fingerprint.startswith("spoofed-device-")
        for event in events_by_attack[AttackType.DEVICE_SPOOFING]
    )
    assert all(
        event.destination_ip is not None for event in events_by_attack[AttackType.LATERAL_MOVEMENT]
    )
    assert all(
        event.bytes_transferred >= 300_000
        for event in events_by_attack[AttackType.LOW_AND_SLOW_EXFILTRATION]
    )
    assert all(
        "bulk_read" in event.command_sequence
        for event in events_by_attack[AttackType.INSIDER_DRIFT]
    )


def test_export_keeps_features_and_labels_separate(tmp_path: Path) -> None:
    config = make_generator_config()
    dataset = generate_dataset(config)
    summary = validate_dataset(dataset, config)
    output = tmp_path / "dataset"

    paths = export_dataset(dataset, config, summary, output)

    with paths.events_path.open(encoding="utf-8", newline="") as stream:
        event_reader = csv.DictReader(stream)
        event_rows = list(event_reader)
    with paths.labels_path.open(encoding="utf-8", newline="") as stream:
        label_reader = csv.DictReader(stream)
        label_rows = list(label_reader)
    manifest = json.loads(paths.manifest_path.read_text(encoding="utf-8"))
    profiles = json.loads(paths.profiles_path.read_text(encoding="utf-8"))

    assert "label" not in (event_reader.fieldnames or [])
    assert "label" in (label_reader.fieldnames or [])
    assert len(event_rows) == len(label_rows) == config.event_count
    assert {row["event_id"] for row in event_rows} == {row["event_id"] for row in label_rows}
    assert manifest["separation"]["labels_present_in_event_file"] is False
    assert len(profiles) == config.population.total
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        export_dataset(dataset, config, summary, output)
