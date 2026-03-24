"""
Build processed training datasets from local raw corpora.

Handles diverse CSV formats:
  - Majestic Million  (Domain column)
  - Alexa Top 1M      (rank, domain)
  - URLhaus            (comment lines starting with #, url in column 3)
  - PhishTank / OpenPhish (url column)
  - Kaggle/Nazario   (CSV with email body text, message, Text, etc)
"""

from __future__ import annotations

import json
from pathlib import Path
import random

import pandas as pd
import numpy as np
import re

from .feature_pipeline import (
    build_content_features,
    build_url_features,
    write_processed_dataset,
)


def _clean_email_text(raw_text: str) -> str:
    """Strips RFC-822 and forwarded/quoted headers to reduce target leakage."""
    lines = str(raw_text).splitlines()
    cleaned: list[str] = []
    in_header = True
    header_like_line = re.compile(
        r'^(Message-ID|Date|From|To|Subject|Cc|Bcc|X-.*|Mime-Version|Content-Type|Content-Transfer-Encoding|Reply-To|Return-Path|Sent):',
        re.IGNORECASE,
    )
    forwarded_markers = re.compile(
        r'^(-----Original Message-----|Begin forwarded message:|Forwarded by\b|FW:|FWD:)',
        re.IGNORECASE,
    )
    for line in lines:
        if in_header:
            if header_like_line.match(line):
                continue
            if not line.strip():
                in_header = False
                continue

        # Remove forwarded/quoted headers that appear inside the body.
        if forwarded_markers.match(line.strip()):
            continue
        if header_like_line.match(line.strip()):
            continue

        # Only reached post-header or if lines aren't header artifacts.
        cleaned.append(line)
        in_header = False
        
    result = '\n'.join(cleaned).strip()
    return result if result else str(raw_text).strip()

def _read_text_files(directory: Path, label: int) -> list[dict]:
    """Reads all unstructured text files (.txt, .eml) in the given directory."""
    rows = []
    if not directory.exists():
        return rows
    
    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() == ".csv":
            continue
        
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            # Strip target leakage headers immediately
            cleaned_text = _clean_email_text(text)
            if cleaned_text.strip():
                rows.append({"content": cleaned_text, "label": label})
        except Exception:
            continue
    return rows


def _read_csv_corpus(csv_path: Path, label: int) -> list[dict]:
    """Read CSV corpus (Nazario, Enron, Kaggle) and extract email body text."""
    items: list[dict] = []
    if not csv_path.exists():
        return items
    try:
        df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip", low_memory=False)
        text_col = None
        # Enron uses 'message', Ling-Spam uses 'Text', Nigerian uses 'Text', Nazario uses 'body'
        for candidate in ("message", "Message", "body", "content", "text", "Body", "Content", "Text", "email"):
            if candidate in df.columns:
                text_col = candidate
                break

        if text_col is None:
            # Use the widest string column as a proxy for email body
            str_cols = df.select_dtypes(include="object").columns.tolist()
            if str_cols:
                text_col = max(str_cols, key=lambda c: df[c].dropna().astype(str).str.len().mean())

        if text_col:
            for row_text in df[text_col].dropna():
                cleaned_text = _clean_email_text(str(row_text))
                if len(cleaned_text) > 10:
                    items.append({"content": cleaned_text, "label": label})
    except Exception as e:
        print(f"Warning: Failed to read CSV {csv_path}: {e}")
    return items


def _extract_urls_from_csv(file_path: Path) -> list[str]:
    """
    Intelligently extract URLs or domains from a CSV file.
    Handles: Majestic Million, Alexa Top 1M, URLhaus, PhishTank, Kaggle Malicious URLs.
    """
    urls: list[str] = []
    try:
        # URLhaus uses # comment lines
        df = pd.read_csv(file_path, comment="#", on_bad_lines="skip", low_memory=False)
    except Exception:
        try:
            df = pd.read_csv(file_path, on_bad_lines="skip", low_memory=False)
        except Exception:
            return urls

    if df.empty:
        return urls

    col_lower = {str(c).lower(): c for c in df.columns}

    # Priority 1: Explicit 'url' column (PhishTank, URLhaus, OpenPhish, Kaggle)
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
    print("Extracting Content training data...")
    all_content_rows = []
    
    # Process legitimate (0)
    legit_dir = base / "email_content" / "legitimate"
    if legit_dir.exists():
        all_content_rows.extend(_read_text_files(legit_dir, label=0))
        for csv_file in legit_dir.rglob("*.csv"):
            all_content_rows.extend(_read_csv_corpus(csv_file, label=0))
            
    # Process spam (1)
    spam_dir = base / "email_content" / "spam"
    if spam_dir.exists():
        all_content_rows.extend(_read_text_files(spam_dir, label=1))
        for csv_file in spam_dir.rglob("*.csv"):
            all_content_rows.extend(_read_csv_corpus(csv_file, label=1))

    # Process phishing (2)
    phishing_dir = base / "email_content" / "phishing"
    if phishing_dir.exists():
        all_content_rows.extend(_read_text_files(phishing_dir, label=2))
        for csv_file in phishing_dir.rglob("*.csv"):
            all_content_rows.extend(_read_csv_corpus(csv_file, label=2))

    legit_rows = [r for r in all_content_rows if r["label"] == 0]
    spam_rows = [r for r in all_content_rows if r["label"] == 1]
    phish_rows = [r for r in all_content_rows if r["label"] == 2]
    
    # Ensure PERFECT 3-way Data Balancing for Content
    if len(legit_rows) > 0 and len(spam_rows) > 0 and len(phish_rows) > 0:
        min_len = min(len(legit_rows), len(spam_rows), len(phish_rows))
        print(f"Down-sampling all 3 classes (Legitimate, Spam, Phishing) to exactly {min_len} samples each to balance.")
        random.seed(42)
        legit_rows = random.sample(legit_rows, min_len)
        spam_rows = random.sample(spam_rows, min_len)
        phish_rows = random.sample(phish_rows, min_len)
        
    all_content_rows = legit_rows + spam_rows + phish_rows

    content_df = build_content_features(all_content_rows)
    content_path = write_processed_dataset(content_df, output / "content_training.csv")

    # ── URL Training ──
    print("Extracting URL training data...")
    malicious_urls: list[str] = []
    benign_urls: list[str] = []
    
    # Process Malicious (1)
    mal_dir = base / "url_dataset" / "malicious"
    if mal_dir.exists():
        for file_path in mal_dir.rglob("*.csv"):
            malicious_urls.extend(_extract_urls_from_csv(file_path))

    # Process Benign (0)
    ben_dir = base / "url_dataset" / "benign"
    if ben_dir.exists():
        for file_path in ben_dir.rglob("*.csv"):
            benign_urls.extend(_extract_urls_from_csv(file_path))

    # Add Kaggle Malicious URLs dataset specifically if it exists in base
    kaggle_url_csv = base / "url_dataset" / "malicious_phish.csv"
    if kaggle_url_csv.exists():
        urls_from_kaggle = _extract_urls_from_csv(kaggle_url_csv)
        # Kaggle dataset contains both benign and malicious depending on a 'type' column
        # Our _extract_urls_from_csv just pulls the 'url' column indiscriminately.
        # To handle the kaggle correctly, we need to partition it.
        try:
            df_k = pd.read_csv(kaggle_url_csv, on_bad_lines="skip")
            col_l = {c.lower(): c for c in df_k.columns}
            if "type" in col_l and "url" in col_l:
                df_benign = df_k[df_k[col_l['type']] == 'benign']
                df_mal = df_k[df_k[col_l['type']] != 'benign']
                benign_urls.extend(df_benign[col_l['url']].dropna().astype(str).tolist())
                malicious_urls.extend(df_mal[col_l['url']].dropna().astype(str).tolist())
        except Exception as e:
             print(f"Warning: Failed precise extraction of Kaggle URLs: {e}")

    # Remove duplicates
    malicious_urls = list(set(malicious_urls))
    benign_urls = list(set(benign_urls))
    
    # Ensure PERFECT Data Balancing
    if len(benign_urls) > len(malicious_urls) and len(malicious_urls) > 0:
        print(f"Down-sampling Benign URLs from {len(benign_urls)} to {len(malicious_urls)} to balance classes.")
        random.seed(42)
        benign_urls = random.sample(benign_urls, len(malicious_urls))
    elif len(malicious_urls) > len(benign_urls) and len(benign_urls) > 0:
        print(f"Down-sampling Malicious URLs from {len(malicious_urls)} to {len(benign_urls)} to balance classes.")
        random.seed(42)
        malicious_urls = random.sample(malicious_urls, len(benign_urls))

    url_df = pd.concat(
        [
            build_url_features(malicious_urls, label=1),
            build_url_features(benign_urls, label=0),
        ],
        ignore_index=True,
    )
    url_path = write_processed_dataset(url_df, output / "url_training.csv")

    # ── User Behavior Training ──
    print("Extracting User Behavior training data...")
    user_behavior_path = base / "user_behavior" / "user_email_behavior.csv"
    user_behavior_out = ""
    if user_behavior_path.exists():
        frame = pd.read_csv(user_behavior_path)
        user_behavior_out = write_processed_dataset(frame, output / "user_behavior_training.csv")

    # ── Header Training (synthetic CSV if available) ──
    print("Extracting Header training data...")
    header_training_path = base / "email_content" / "header_training.csv"
    header_training_out = ""
    if header_training_path.exists():
        frame = pd.read_csv(header_training_path)
        header_training_out = write_processed_dataset(frame, output / "header_training.csv")

    # ── Attachment / EMBER Training ──
    print("Checking Attachment/EMBER training data...")
    ember_dir = base / "attachments" / "malware" / "ember_features"
    ember_training_out = ""
    ember_train_parquet = ember_dir / "train_ember_2018_v2_features.parquet"
    
    if not ember_train_parquet.exists() and (ember_dir / "train_features_0.jsonl").exists():
        print("EMBER Parquet not found but JSONL exists. Converting JSONL to Parquet automatically...")
        try:
            from .convert_ember_jsonl import convert_ember_jsonl_to_parquet
            convert_ember_jsonl_to_parquet(ember_dir, ember_train_parquet)
        except Exception as e:
            print(f"Failed to convert EMBER JSONL: {e}")

    if ember_train_parquet.exists():
        ember_training_out = str(ember_train_parquet)
    else:
        print("Warning: EMBER Parquet is missing, Attachment Agent cannot be trained.")

    report = {
        "content_training": content_path,
        "url_training": url_path,
        "user_behavior_training": user_behavior_out,
        "header_training": header_training_out,
        "attachment_training_ember": ember_training_out,
    }
    (output / "training_manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nDataset Preprocessing Complete!")
    return report


if __name__ == "__main__":
    output = run(base_dir="datasets", output_dir="datasets_processed")
    print(json.dumps(output, indent=2))
