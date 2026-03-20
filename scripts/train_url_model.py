"""
Train URL Reputation Model.

Pipeline:  Feature matrix (url_length, subdomain_count, special_char_count,
           host_entropy)  →  RandomForestClassifier
Input:     datasets_processed/url_training.csv
Output:    models/url_agent/model.joblib

Usage:
    cd /home/LabsKraft/new_work/email_security
    python scripts/train_url_model.py
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
MODEL_DIR = REPO_ROOT.parent / "models" / "url_agent"

FEATURE_COLS = ["url_length", "subdomain_count", "special_char_count", "host_entropy"]


def main() -> None:
    csv_path = PROCESSED_DIR / "url_training.csv"
    if not csv_path.exists():
        print(f"ERROR: Training data not found at {csv_path}")
        print("Run:  python -m preprocessing.prepare_training_data")
        sys.exit(1)

    print(f"Loading training data from {csv_path} ...")
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=FEATURE_COLS + ["label"])

    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:\n{df['label'].value_counts().to_string()}\n")

    if len(df) < 20:
        print("ERROR: Too few samples for training. Need at least 20.")
        sys.exit(1)

    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier ...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
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
