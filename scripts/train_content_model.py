"""
Train Content Phishing Detection Model.

Pipeline:  TF-IDF vectorizer  →  LogisticRegression
Input:     datasets_processed/content_training.csv
Output:    models/content_agent/model.joblib  (bundled with vectorizer)

Usage:
    cd /home/LabsKraft/new_work/email_security
    python scripts/train_content_model.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "content_agent"


def main() -> None:
    csv_path = PROCESSED_DIR / "content_training.csv"
    if not csv_path.exists():
        print(f"ERROR: Training data not found at {csv_path}")
        print("Run:  python -m preprocessing.prepare_training_data")
        sys.exit(1)

    print(f"Loading training data from {csv_path} ...")
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str)

    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:\n{df['label'].value_counts().to_string()}\n")

    if len(df) < 20:
        print("ERROR: Too few samples for training. Need at least 20.")
        sys.exit(1)

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    print("Fitting TF-IDF vectorizer ...")
    vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        strip_accents="unicode",
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("Training LogisticRegression ...")
    model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        class_weight="balanced",
        solver="lbfgs",
        random_state=42,
    )
    model.fit(X_train_vec, y_train)

    print("\n── Test Set Evaluation ──")
    y_pred = model.predict(X_test_vec)
    print(classification_report(y_test, y_pred))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": model,
        "vectorizer": vectorizer,
        "kind": "sklearn_bundle",
    }
    out_path = MODEL_DIR / "model.joblib"
    joblib.dump(bundle, out_path)
    print(f"\n✅ Model saved to {out_path}")


if __name__ == "__main__":
    main()
