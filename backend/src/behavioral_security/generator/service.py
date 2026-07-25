"""Application-facing synthetic dataset generation service."""

from pathlib import Path

from behavioral_security.generator.config import GeneratorConfig
from behavioral_security.generator.exporters import export_dataset
from behavioral_security.generator.models import ExportedDataset, GenerationSummary
from behavioral_security.generator.stream import generate_dataset
from behavioral_security.generator.validation import validate_dataset


def generate_and_export(
    config: GeneratorConfig,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> tuple[GenerationSummary, ExportedDataset]:
    """Generate, validate, and atomically export a synthetic dataset."""

    dataset = generate_dataset(config)
    summary = validate_dataset(dataset, config)
    exported = export_dataset(
        dataset,
        config,
        summary,
        output_directory,
        overwrite=overwrite,
    )
    return summary, exported
