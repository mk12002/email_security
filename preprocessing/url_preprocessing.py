"""URL-agent preprocessing."""

from __future__ import annotations

from pathlib import Path
import random

import pandas as pd

from .feature_pipeline import build_url_features, write_processed_dataset

RANDOM_SEED = 42
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


def _extract_urls_from_csv(file_path: Path) -> list[str]:
    urls: list[str] = []
    try:
        frame = pd.read_csv(file_path, comment="#", on_bad_lines="skip", low_memory=False)
    except Exception:
        try:
            frame = pd.read_csv(file_path, on_bad_lines="skip", low_memory=False)
        except Exception:
            return urls

    if frame.empty:
        return urls

    cols = {str(c).lower(): c for c in frame.columns}

    if "url" in cols:
        return frame[cols["url"]].dropna().astype(str).tolist()

    if "domain" in cols:
        domains = frame[cols["domain"]].dropna().astype(str).tolist()
        return [f"http://{d.strip()}" for d in domains if d.strip()]

    if len(frame.columns) == 2:
        values = frame.iloc[:, 1].dropna().astype(str).tolist()
        sample = values[:20]
        if sample and all("." in v and " " not in v for v in sample):
            return [f"http://{v.strip()}" for v in values if v.strip()]

    return frame.iloc[:, 0].dropna().astype(str).tolist()


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    base = _resolve_input_dir(base_dir)
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    malicious: list[str] = []
    benign: list[str] = []

    mal_dir = base / "url_dataset" / "malicious"
    if mal_dir.exists():
        for file_path in mal_dir.rglob("*.csv"):
            malicious.extend(_extract_urls_from_csv(file_path))

    ben_dir = base / "url_dataset" / "benign"
    if ben_dir.exists():
        for file_path in ben_dir.rglob("*.csv"):
            benign.extend(_extract_urls_from_csv(file_path))

    kaggle_csv = base / "url_dataset" / "malicious_phish.csv"
    if kaggle_csv.exists():
        try:
            frame = pd.read_csv(kaggle_csv, on_bad_lines="skip", low_memory=False)
            cols = {str(c).lower(): c for c in frame.columns}
            if "type" in cols and "url" in cols:
                benign.extend(
                    frame[frame[cols["type"]].astype(str).str.lower() == "benign"][cols["url"]]
                    .dropna()
                    .astype(str)
                    .tolist()
                )
                malicious.extend(
                    frame[frame[cols["type"]].astype(str).str.lower() != "benign"][cols["url"]]
                    .dropna()
                    .astype(str)
                    .tolist()
                )
            else:
                malicious.extend(_extract_urls_from_csv(kaggle_csv))
        except Exception:
            malicious.extend(_extract_urls_from_csv(kaggle_csv))

    malicious = sorted(set(malicious))
    benign = sorted(set(benign))

    if benign and malicious:
        random.seed(RANDOM_SEED)
        if len(benign) > len(malicious):
            benign = random.sample(benign, len(malicious))
        elif len(malicious) > len(benign):
            malicious = random.sample(malicious, len(benign))

    url_df = pd.concat(
        [
            build_url_features(malicious, label=1),
            build_url_features(benign, label=0),
        ],
        ignore_index=True,
    )
    return write_processed_dataset(url_df, output / "url_training.csv")


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
