"""
Train Header Analysis Model.

Pipeline:  8-dim feature vector  →  RandomForestClassifier
Input:     datasets_processed/header_training.csv  (from synthetic or real data)
Output:    models/header_agent/model.joblib

Features:
    spf_pass, dkim_pass, dmarc_pass, sender_domain_len,
    display_name_mismatch, hop_count, reply_to_mismatch,
    sender_domain_entropy

Usage:
    cd /home/LabsKraft/new_work/email_security
    python scripts/train_header_model.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "header_agent"

FEATURE_COLS = [
    "spf_pass",
    "dkim_pass",
    "dmarc_pass",
    "sender_domain_len",
    "display_name_mismatch",
    "hop_count",
    "reply_to_mismatch",
    "sender_domain_entropy",
]


def main() -> None:
    csv_path = PROCESSED_DIR / "header_training.csv"
    if not csv_path.exists():
        print(f"ERROR: Training data not found at {csv_path}")
        print("Run:  python scripts/generate_synthetic_datasets.py")
        print("Then: python -m preprocessing.prepare_training_data")
        sys.exit(1)

    print(f"Loading training data from {csv_path} ...")
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=FEATURE_COLS + ["label"])

    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:\n{df['label'].value_counts().to_string()}\n")

    if len(df) < 20:
        print("ERROR: Too few samples for training.")
        sys.exit(1)

    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier ...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    print("\n── Test Set Evaluation ──")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": model,
        "kind": "sklearn_model",
    }
    out_path = MODEL_DIR / "model.joblib"
    joblib.dump(bundle, out_path)
    print(f"\n✅ Model saved to {out_path}")


if __name__ == "__main__":
    main()
