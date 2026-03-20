"""
Train User Behavior Click-Risk Prediction Model.

Pipeline:  4-dim feature vector  →  LogisticRegression
Input:     datasets_processed/user_behavior_training.csv
Output:    models/user_behavior_agent/model.joblib

Features:
    sender_familiarity, subject_urgency, link_count, email_type (encoded)

Usage:
    cd /home/LabsKraft/new_work/email_security
    python scripts/train_user_behavior_model.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "user_behavior_agent"

NUMERIC_COLS = ["sender_familiarity", "subject_urgency", "link_count"]
LABEL_COL = "user_clicked"


def main() -> None:
    csv_path = PROCESSED_DIR / "user_behavior_training.csv"
    if not csv_path.exists():
        print(f"ERROR: Training data not found at {csv_path}")
        print("Run:  python scripts/generate_synthetic_datasets.py")
        print("Then: python -m preprocessing.prepare_training_data")
        sys.exit(1)

    print(f"Loading training data from {csv_path} ...")
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=NUMERIC_COLS + [LABEL_COL])

    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:\n{df[LABEL_COL].value_counts().to_string()}\n")

    if len(df) < 20:
        print("ERROR: Too few samples for training.")
        sys.exit(1)

    # Encode email_type if present
    feature_cols = list(NUMERIC_COLS)
    le = None
    if "email_type" in df.columns:
        le = LabelEncoder()
        df["email_type_encoded"] = le.fit_transform(df["email_type"].astype(str))
        feature_cols.append("email_type_encoded")

    X = df[feature_cols]
    y = df[LABEL_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training LogisticRegression ...")
    model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        class_weight="balanced",
        solver="lbfgs",
        random_state=42,
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
    if le is not None:
        bundle["label_encoder"] = le
    out_path = MODEL_DIR / "model.joblib"
    joblib.dump(bundle, out_path)
    print(f"\n✅ Model saved to {out_path}")


if __name__ == "__main__":
    main()
