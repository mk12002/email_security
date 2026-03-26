"""Train a high-quality tabular URL classifier with detailed evaluation artifacts."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import warnings

# Keep CPU usage bounded for low-core machines.
os.environ["OMP_NUM_THREADS"] = "2"
os.environ["OPENBLAS_NUM_THREADS"] = "2"
os.environ["MKL_NUM_THREADS"] = "2"

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from tqdm.auto import tqdm

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from preprocessing.feature_pipeline import URL_FEATURE_COLUMNS


PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
MODEL_DIR = REPO_ROOT.parent / "models" / "url_agent"
CHECKPOINT_PATH = MODEL_DIR / "model.joblib"
RUN_LOG_DIR = MODEL_DIR / "run_logs"

RANDOM_SEED = 42
CSV_CHUNK_SIZE = int(os.getenv("URL_CSV_CHUNK_SIZE", "150000"))
MAX_TRAIN_ROWS = int(os.getenv("URL_MAX_TRAIN_ROWS", "900000"))
FORCE_RETRAIN = os.getenv("URL_FORCE_RETRAIN", "1") == "1"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _stratified_cap(df: pd.DataFrame, target_rows: int, seed: int) -> pd.DataFrame:
    if target_rows <= 0 or len(df) <= target_rows:
        return df

    class_counts = df["label"].value_counts()
    total = int(class_counts.sum())
    alloc = {
        int(label): max(1, int(round(target_rows * count / total)))
        for label, count in class_counts.items()
    }

    # Fix rounding drift to hit exact cap.
    while sum(alloc.values()) > target_rows:
        label = max(alloc, key=alloc.get)
        if alloc[label] > 1:
            alloc[label] -= 1
    while sum(alloc.values()) < target_rows:
        label = max(class_counts.index.tolist(), key=lambda value: class_counts[value])
        alloc[int(label)] += 1

    parts = []
    for label, n_rows in alloc.items():
        part = df[df["label"] == label]
        if len(part) <= n_rows:
            parts.append(part)
        else:
            parts.append(part.sample(n=n_rows, random_state=seed))
    capped = pd.concat(parts, ignore_index=True)
    return capped.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def _load_dataset(csv_path: Path) -> pd.DataFrame:
    chunks = []
    for chunk in tqdm(pd.read_csv(csv_path, low_memory=False, chunksize=CSV_CHUNK_SIZE), desc="Loading URL Features"):
        if chunk.empty:
            continue
        chunks.append(chunk)

    if not chunks:
        raise RuntimeError("No rows found in URL training CSV.")

    df = pd.concat(chunks, ignore_index=True)
    df = df.dropna(subset=["label"]).copy()

    missing = [col for col in URL_FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise RuntimeError(f"Missing required URL feature columns: {missing}")

    for col in URL_FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[URL_FEATURE_COLUMNS] = df[URL_FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(-1).astype(int)
    df = df[df["label"].isin([0, 1])].reset_index(drop=True)
    if len(df) < 1000:
        raise RuntimeError(f"URL dataset too small after cleanup: {len(df)} rows")

    df = _stratified_cap(df, target_rows=MAX_TRAIN_ROWS, seed=RANDOM_SEED)
    return df


def _fit_best_model(X_train: pd.DataFrame, y_train: pd.Series, X_val: pd.DataFrame, y_val: pd.Series):
    candidates = [
        {
            "name": "hgb_wide",
            "params": {
                "max_iter": 700,
                "learning_rate": 0.04,
                "max_leaf_nodes": 63,
                "min_samples_leaf": 30,
                "l2_regularization": 0.05,
            },
        },
        {
            "name": "hgb_fast",
            "params": {
                "max_iter": 500,
                "learning_rate": 0.05,
                "max_leaf_nodes": 31,
                "min_samples_leaf": 40,
                "l2_regularization": 0.10,
            },
        },
    ]

    best = None
    best_score = -1.0
    scores = []

    for candidate in candidates:
        print(f"3. Training candidate: {candidate['name']}")
        model = HistGradientBoostingClassifier(
            **candidate["params"],
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=25,
            random_state=RANDOM_SEED,
            verbose=0,
        )
        model.fit(X_train, y_train)
        val_proba = model.predict_proba(X_val)[:, 1]
        val_pred = (val_proba >= 0.5).astype(int)
        val_f1 = float(f1_score(y_val, val_pred))
        val_auc = float(roc_auc_score(y_val, val_proba))
        val_ap = float(average_precision_score(y_val, val_proba))
        composite = (0.50 * val_auc) + (0.30 * val_ap) + (0.20 * val_f1)

        result = {
            "name": candidate["name"],
            "params": candidate["params"],
            "val_f1": val_f1,
            "val_roc_auc": val_auc,
            "val_pr_auc": val_ap,
            "composite_score": composite,
        }
        scores.append(result)
        print(f"   -> val_f1={val_f1:.4f} val_roc_auc={val_auc:.4f} val_pr_auc={val_ap:.4f}")

        if composite > best_score:
            best = (candidate["name"], candidate["params"])
            best_score = composite

    if best is None:
        raise RuntimeError("No URL model candidate could be trained.")

    best_name, best_params = best
    print(f"4. Best candidate selected: {best_name}")
    final_model = HistGradientBoostingClassifier(
        **best_params,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=25,
        random_state=RANDOM_SEED,
        verbose=0,
    )
    final_model.fit(pd.concat([X_train, X_val]), pd.concat([y_train, y_val]))
    return final_model, scores, best_name


def main():
    csv_path = PROCESSED_DIR / "url_training.csv"
    if not csv_path.exists():
        print(f"ERROR: Training data not found at {csv_path}")
        sys.exit(1)

    print("1. Loading URL dataset...")
    df = _load_dataset(csv_path)
    print(f"   -> Total rows: {len(df)}")
    print(f"   -> Label distribution:\n{df['label'].value_counts().to_string()}")

    X = df[URL_FEATURE_COLUMNS].astype(float)
    y = df["label"].astype(int)

    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=y,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full,
        y_train_full,
        test_size=0.1,
        random_state=RANDOM_SEED,
        stratify=y_train_full,
    )

    if CHECKPOINT_PATH.exists() and not FORCE_RETRAIN:
        print("2. Existing model found and URL_FORCE_RETRAIN=0, loading checkpoint...")
        bundle = joblib.load(CHECKPOINT_PATH)
        model = bundle.get("model") if isinstance(bundle, dict) else bundle
        candidate_scores = [{"name": "loaded_checkpoint", "composite_score": None}]
        best_name = "loaded_checkpoint"
    else:
        model, candidate_scores, best_name = _fit_best_model(X_train, y_train, X_val, y_val)

    print("5. Evaluating on holdout test split...")
    y_score = model.predict_proba(X_test)[:, 1]
    y_pred = (y_score >= 0.5).astype(int)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_score))
    pr_auc = float(average_precision_score(y_test, y_score))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _stamp()

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Malicious"])
    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(cmap="Blues", ax=ax, colorbar=False)
    ax.set_title("URL Model Confusion Matrix")
    fig.tight_layout()
    fig.savefig(MODEL_DIR / "confusion_matrix.png")
    plt.close(fig)

    fpr, tpr, _ = roc_curve(y_test, y_score)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(fpr, tpr, label=f"ROC AUC = {roc_auc:.4f}")
    ax.plot([0, 1], [0, 1], "k--", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("URL Model ROC Curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(MODEL_DIR / "roc_curve.png")
    plt.close(fig)

    p_vals, r_vals, _ = precision_recall_curve(y_test, y_score)
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(r_vals, p_vals, label=f"PR AUC = {pr_auc:.4f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("URL Model Precision-Recall Curve")
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(MODEL_DIR / "precision_recall_curve.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.hist(y_score[y_test == 0], bins=50, alpha=0.6, label="Benign", color="#4CAF50")
    ax.hist(y_score[y_test == 1], bins=50, alpha=0.6, label="Malicious", color="#F44336")
    ax.set_xlabel("Predicted malicious probability")
    ax.set_ylabel("Count")
    ax.set_title("URL Model Score Distribution")
    ax.legend()
    fig.tight_layout()
    fig.savefig(MODEL_DIR / "score_histogram.png")
    plt.close(fig)

    report_text = classification_report(y_test, y_pred, target_names=["Benign", "Malicious"], digits=4, zero_division=0)
    metrics = {
        "timestamp_utc": stamp,
        "dataset_path": str(csv_path),
        "rows_used": int(len(df)),
        "label_distribution": {str(k): int(v) for k, v in y.value_counts().to_dict().items()},
        "model_type": "HistGradientBoostingClassifier",
        "selected_candidate": best_name,
        "candidate_scores": candidate_scores,
        "test_metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
        },
        "feature_columns": URL_FEATURE_COLUMNS,
    }

    report_lines = [
        "URL Model Training Report",
        "========================",
        "",
        f"Timestamp (UTC): {stamp}",
        f"Dataset: {csv_path}",
        f"Rows used: {len(df)}",
        f"Label distribution: {y.value_counts().to_dict()}",
        f"Selected candidate: {best_name}",
        "",
        "Test metrics",
        "------------",
        f"Accuracy:  {acc:.4f}",
        f"Precision: {prec:.4f}",
        f"Recall:    {rec:.4f}",
        f"F1:        {f1:.4f}",
        f"ROC AUC:   {roc_auc:.4f}",
        f"PR AUC:    {pr_auc:.4f}",
        "",
        "Classification report",
        "---------------------",
        report_text,
    ]
    (MODEL_DIR / "training_report.txt").write_text("\n".join(report_lines), encoding="utf-8")
    (RUN_LOG_DIR / f"metrics_{stamp}.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    bundle = {
        "model": model,
        "kind": "sklearn_model",
        "features": URL_FEATURE_COLUMNS,
        "metrics": metrics["test_metrics"],
    }
    joblib.dump(bundle, CHECKPOINT_PATH)

    print("6. Training complete")
    print(f"   -> Model: {CHECKPOINT_PATH}")
    print(f"   -> Report: {MODEL_DIR / 'training_report.txt'}")
    print(f"   -> Metrics JSON: {RUN_LOG_DIR / f'metrics_{stamp}.json'}")


if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    main()
