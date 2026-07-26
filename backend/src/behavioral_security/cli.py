"""Operational command-line entry points."""

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from behavioral_security.core.randomness import set_global_seed
from behavioral_security.infrastructure.config.loader import find_project_root, load_settings
from behavioral_security.infrastructure.database.manager import DatabaseManager


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser and supported subcommands."""

    parser = argparse.ArgumentParser(
        prog="badp",
        description="SentinelAI operational CLI.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="YAML configuration path; defaults to BADP_CONFIG_FILE or config/base.yaml.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check-config", help="Validate and print effective configuration.")
    subparsers.add_parser("init-db", help="Initialize operational and evaluation databases.")
    generate_parser = subparsers.add_parser(
        "generate-data",
        help="Generate, validate, and export a synthetic security dataset.",
    )
    generate_parser.add_argument(
        "--generator-config",
        type=Path,
        required=True,
        help="Generator YAML configuration path.",
    )
    generate_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for separated events, labels, profiles, and manifest.",
    )
    generate_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing generated dataset in the selected output directory.",
    )
    train_parser = subparsers.add_parser(
        "train-model",
        help="Build profiles, train detectors, evaluate, and save model artifacts.",
    )
    train_parser.add_argument("--dataset", type=Path, required=True)
    train_parser.add_argument("--training-config", type=Path, required=True)
    train_parser.add_argument("--output", type=Path, required=True)
    evaluate_parser = subparsers.add_parser(
        "evaluate-model",
        help="Evaluate a saved model against a labeled synthetic dataset.",
    )
    evaluate_parser.add_argument("--dataset", type=Path, required=True)
    evaluate_parser.add_argument("--model", type=Path, required=True)
    evaluate_parser.add_argument("--output", type=Path, required=True)
    infer_parser = subparsers.add_parser(
        "infer",
        help="Run behavioral inference on an operational events CSV.",
    )
    infer_parser.add_argument("--events", type=Path, required=True)
    infer_parser.add_argument("--model", type=Path, required=True)
    infer_parser.add_argument("--output", type=Path, required=True)
    subparsers.add_parser("serve", help="Run the FastAPI service.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute a CLI command and return its process exit code."""

    arguments = build_parser().parse_args(argv)
    settings = load_settings(arguments.config)
    set_global_seed(
        settings.randomness.seed,
        deterministic_torch=settings.randomness.deterministic_torch,
    )

    if arguments.command == "check-config":
        print(json.dumps(settings.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if arguments.command == "init-db":
        manager = DatabaseManager.from_settings(
            settings.database,
            project_root=find_project_root(),
        )
        applied = manager.initialize()
        print(json.dumps({"status": "initialized", "migrations_applied": applied}, indent=2))
        return 0
    if arguments.command == "generate-data":
        from behavioral_security.generator.config import load_generator_config
        from behavioral_security.generator.service import generate_and_export

        root = find_project_root()
        generator_path = _resolve_cli_path(arguments.generator_config, root)
        output_path = _resolve_cli_path(arguments.output, root)
        generator_config = load_generator_config(generator_path)
        summary, exported = generate_and_export(
            generator_config,
            output_path,
            overwrite=arguments.overwrite,
        )
        print(
            json.dumps(
                {
                    "summary": summary.model_dump(mode="json"),
                    "files": {
                        "events": str(exported.events_path),
                        "labels": str(exported.labels_path),
                        "profiles": str(exported.profiles_path),
                        "manifest": str(exported.manifest_path),
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "train-model":
        from behavioral_security.application.pipeline import train_and_evaluate
        from behavioral_security.application.training_config import load_training_config

        root = find_project_root()
        result = train_and_evaluate(
            _resolve_cli_path(arguments.dataset, root),
            _resolve_cli_path(arguments.output, root),
            load_training_config(_resolve_cli_path(arguments.training_config, root)),
        )
        print(
            json.dumps(
                {
                    "model": str(result.model_path),
                    "profiles": str(result.profiles_path),
                    "metrics": result.metrics,
                    "predictions": str(result.predictions_path),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "evaluate-model":
        from behavioral_security.application.pipeline import evaluate_model

        root = find_project_root()
        metrics = evaluate_model(
            _resolve_cli_path(arguments.dataset, root),
            _resolve_cli_path(arguments.model, root),
            _resolve_cli_path(arguments.output, root),
        )
        print(json.dumps(metrics, indent=2, sort_keys=True))
        return 0
    if arguments.command == "infer":
        from behavioral_security.application.pipeline import run_inference

        root = find_project_root()
        output = run_inference(
            _resolve_cli_path(arguments.events, root),
            _resolve_cli_path(arguments.model, root),
            _resolve_cli_path(arguments.output, root),
        )
        print(json.dumps({"predictions": str(output)}, indent=2))
        return 0
    if arguments.command == "serve":
        from behavioral_security.api.app import create_app

        uvicorn.run(
            create_app(settings),
            host=settings.api.host,
            port=settings.api.port,
            log_config=None,
        )
        return 0
    raise AssertionError(f"unhandled command: {arguments.command}")


def _resolve_cli_path(path: Path, project_root: Path) -> Path:
    """Resolve a command path against the project root."""

    return path if path.is_absolute() else project_root / path
