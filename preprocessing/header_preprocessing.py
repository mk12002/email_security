"""Header-agent preprocessing."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .feature_pipeline import write_processed_dataset

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]


def _resolve_input_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    if path.exists():
        return path
    return WORKSPACE_ROOT / path


def _resolve_output_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return WORKSPACE_ROOT / path


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    base = _resolve_input_dir(base_dir)
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    email_content_dir = base / "email_content"
    extracted_source = email_content_dir / "header_training_extracted.csv"
    default_source = email_content_dir / "header_training.csv"

    source = extracted_source if extracted_source.exists() else default_source
    if not source.exists():
        return ""

    frame = pd.read_csv(source)
    return write_processed_dataset(frame, output / "header_training.csv")


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
