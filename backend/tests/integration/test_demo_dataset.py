"""Committed demo dataset integrity tests."""

import csv
import json
from collections import Counter
from pathlib import Path

from behavioral_security.core.enums import AttackType

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEMO_ROOT = PROJECT_ROOT / "data" / "samples" / "honeywell_demo"


def test_committed_demo_distribution_matches_manifest() -> None:
    manifest = json.loads((DEMO_ROOT / "manifest.json").read_text(encoding="utf-8"))
    with (DEMO_ROOT / "events.csv").open(encoding="utf-8", newline="") as stream:
        event_reader = csv.DictReader(stream)
        event_rows = list(event_reader)
    with (DEMO_ROOT / "labels.csv").open(encoding="utf-8", newline="") as stream:
        label_reader = csv.DictReader(stream)
        labels = list(label_reader)

    distribution = Counter(row["label"] for row in labels)
    summary = manifest["summary"]
    assert len(event_rows) == len(labels) == summary["event_count"] == 2000
    assert summary["anomaly_percentage"] == 1.5
    assert distribution == Counter(summary["class_distribution"])
    assert "label" not in (event_reader.fieldnames or [])
    assert set(distribution) == {attack.value for attack in AttackType}
