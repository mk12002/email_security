"""
Build processed training datasets from local raw corpora.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from preprocessing.feature_pipeline import (
    build_content_features,
    build_url_features,
    write_processed_dataset,
)


def _read_text_files(directory: Path, label: int) -> list[dict]:
    items: list[dict] = []
    if not directory.exists():
        return items
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            items.append({"content": text, "label": label})
        except Exception:
            continue
    return items


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> dict[str, str]:
    base = Path(base_dir)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    spam_rows = _read_text_files(base / "email_content" / "spam", label=1)
    ham_rows = _read_text_files(base / "email_content" / "legitimate", label=0)
    content_df = build_content_features(spam_rows + ham_rows)
    content_path = write_processed_dataset(content_df, output / "content_training.csv")

    malicious_urls = []
    benign_urls = []
    for file_path in (base / "url_dataset" / "malicious").rglob("*.csv"):
        try:
            frame = pd.read_csv(file_path)
            malicious_urls.extend(str(value) for value in frame.iloc[:, 0].dropna().tolist())
        except Exception:
            continue
    for file_path in (base / "url_dataset" / "benign").rglob("*.csv"):
        try:
            frame = pd.read_csv(file_path)
            benign_urls.extend(str(value) for value in frame.iloc[:, 0].dropna().tolist())
        except Exception:
            continue
    url_df = pd.concat(
        [
            build_url_features(malicious_urls, label=1),
            build_url_features(benign_urls, label=0),
        ],
        ignore_index=True,
    )
    url_path = write_processed_dataset(url_df, output / "url_training.csv")

    user_behavior_path = base / "user_behavior" / "user_email_behavior.csv"
    user_behavior_out = ""
    if user_behavior_path.exists():
        frame = pd.read_csv(user_behavior_path)
        user_behavior_out = write_processed_dataset(frame, output / "user_behavior_training.csv")

    report = {
        "content_training": content_path,
        "url_training": url_path,
        "user_behavior_training": user_behavior_out,
    }
    (output / "training_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    output = run()
    print(json.dumps(output, indent=2))
