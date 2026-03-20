"""
Build processed training datasets from local raw corpora.

Handles diverse CSV formats:
  - Majestic Million  (Domain column)
  - Alexa Top 1M      (rank, domain)
  - URLhaus            (comment lines starting with #, url in column 3)
  - PhishTank / OpenPhish (url column)
  - Nazario phishing   (CSV with email body text)
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
    """Read raw text/eml files from a directory and assign a label."""
    items: list[dict] = []
    if not directory.exists():
        return items
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        # Skip CSVs — they are handled separately
        if file_path.suffix.lower() == ".csv":
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            items.append({"content": text, "label": label})
        except Exception:
            continue
    return items


def _read_nazario_csv(csv_path: Path, label: int) -> list[dict]:
    """Read Nazario phishing CSV and extract email body text."""
    items: list[dict] = []
    if not csv_path.exists():
        return items
    try:
        df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip")
        # Nazario CSVs typically have a 'body' or 'content' column; fall back
        # to concatenating all string columns if neither is found
        text_col = None
        for candidate in ("body", "content", "text", "Body", "Content", "Text"):
            if candidate in df.columns:
                text_col = candidate
                break

        if text_col is None:
            # Use the widest string column as a proxy for email body
            str_cols = df.select_dtypes(include="object").columns.tolist()
            if str_cols:
                text_col = max(str_cols, key=lambda c: df[c].str.len().mean())

        if text_col:
            for row_text in df[text_col].dropna():
                text = str(row_text).strip()
                if len(text) > 10:
                    items.append({"content": text, "label": label})
    except Exception:
        pass
    return items


def _extract_urls_from_csv(file_path: Path) -> list[str]:
    """
    Intelligently extract URLs or domains from a CSV file.
    Handles: Majestic Million, Alexa Top 1M, URLhaus, PhishTank.
    """
    urls: list[str] = []
    try:
        # URLhaus uses # comment lines
        df = pd.read_csv(file_path, comment="#", on_bad_lines="skip")
    except Exception:
        try:
            df = pd.read_csv(file_path, on_bad_lines="skip")
        except Exception:
            return urls

    if df.empty:
        return urls

    col_lower = {c.lower(): c for c in df.columns}

    # Priority 1: Explicit 'url' column (PhishTank, URLhaus, OpenPhish)
    if "url" in col_lower:
        raw = df[col_lower["url"]].dropna().astype(str).tolist()
        urls.extend(raw)
        return urls

    # Priority 2: 'Domain' column (Majestic Million)
    if "domain" in col_lower:
        domains = df[col_lower["domain"]].dropna().astype(str).tolist()
        # Prepend http:// so the feature pipeline can extract the host
        urls.extend(f"http://{d.strip()}" for d in domains if d.strip())
        return urls

    # Priority 3: Two-column CSV with rank + domain (Alexa Top 1M style)
    if len(df.columns) == 2:
        second_col = df.columns[1]
        values = df[second_col].dropna().astype(str).tolist()
        # Check if values look like domains (contain dots, no spaces)
        sample = values[:20]
        if all("." in v and " " not in v for v in sample):
            urls.extend(f"http://{v.strip()}" for v in values if v.strip())
            return urls

    # Fallback: first column
    raw = df.iloc[:, 0].dropna().astype(str).tolist()
    urls.extend(raw)
    return urls


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> dict[str, str]:
    base = Path(base_dir)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # ── Content Training (spam + phishing = label 1, ham = label 0) ──
    spam_rows = _read_text_files(base / "email_content" / "spam", label=1)
    ham_rows = _read_text_files(base / "email_content" / "legitimate", label=0)

    # Include Nazario phishing CSVs as phishing (label=1)
    phishing_dir = base / "email_content" / "phishing"
    phishing_rows: list[dict] = []
    if phishing_dir.exists():
        # Read raw text/eml files
        phishing_rows.extend(_read_text_files(phishing_dir, label=1))
        # Read Nazario CSVs
        for csv_file in phishing_dir.rglob("*.csv"):
            phishing_rows.extend(_read_nazario_csv(csv_file, label=1))

    all_content_rows = spam_rows + phishing_rows + ham_rows
    content_df = build_content_features(all_content_rows)
    content_path = write_processed_dataset(content_df, output / "content_training.csv")

    # ── URL Training ──
    malicious_urls: list[str] = []
    benign_urls: list[str] = []

    mal_dir = base / "url_dataset" / "malicious"
    if mal_dir.exists():
        for file_path in mal_dir.rglob("*.csv"):
            malicious_urls.extend(_extract_urls_from_csv(file_path))

    ben_dir = base / "url_dataset" / "benign"
    if ben_dir.exists():
        for file_path in ben_dir.rglob("*.csv"):
            benign_urls.extend(_extract_urls_from_csv(file_path))

    url_df = pd.concat(
        [
            build_url_features(malicious_urls, label=1),
            build_url_features(benign_urls, label=0),
        ],
        ignore_index=True,
    )
    url_path = write_processed_dataset(url_df, output / "url_training.csv")

    # ── User Behavior Training ──
    user_behavior_path = base / "user_behavior" / "user_email_behavior.csv"
    user_behavior_out = ""
    if user_behavior_path.exists():
        frame = pd.read_csv(user_behavior_path)
        user_behavior_out = write_processed_dataset(frame, output / "user_behavior_training.csv")

    # ── Header Training (synthetic CSV if available) ──
    header_training_path = base / "email_content" / "header_training.csv"
    header_training_out = ""
    if header_training_path.exists():
        frame = pd.read_csv(header_training_path)
        header_training_out = write_processed_dataset(frame, output / "header_training.csv")

    # ── Attachment / EMBER Training (pass-through reference) ──
    ember_dir = base / "attachments" / "malware" / "ember_features"
    ember_training_out = ""
    ember_train_parquet = ember_dir / "train_ember_2018_v2_features.parquet"
    if ember_train_parquet.exists():
        ember_training_out = str(ember_train_parquet)

    report = {
        "content_training": content_path,
        "url_training": url_path,
        "user_behavior_training": user_behavior_out,
        "header_training": header_training_out,
        "attachment_training_ember": ember_training_out,
    }
    (output / "training_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    output = run(base_dir="../datasets", output_dir="../datasets_processed")
    print(json.dumps(output, indent=2))
