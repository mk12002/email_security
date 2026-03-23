"""
Optimized SLM (Small Language Model) Training for Phishing Content.

Optimized for AWS t3.large (2 vCPUs, 8GB RAM, NO GPU):
1. Model: `prajjwal1/bert-tiny` (Only 4.4M parameters). Runs incredibly fast on 2 CPU cores.
2. Memory: Uses the HuggingFace `datasets` Arrow-backed framework. It maps the 1.7GB CSV
   to disk instead of RAM, entirely preventing Out-Of-Memory (OOM) crashes.
3. Checkpointing: Integrates HuggingFace `Trainer` to save progress every 500 steps.
   If training stops, just re-run this script and it mathematically resumes where it crashed.
4. Batching: Uses `per_device_train_batch_size=8` and `gradient_accumulation_steps=4` 
   to simulate a batch of 32 without holding 32 text tensors in RAM simultaneously.
"""

import os
import sys
from pathlib import Path

# Important: Limit thread counts to prevent CPU context-switch thrashing on 2 cores
os.environ["OMP_NUM_THREADS"] = "2"
os.environ["OPENBLAS_NUM_THREADS"] = "2"
os.environ["MKL_NUM_THREADS"] = "2"

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from datasets import Dataset
from tqdm.auto import tqdm
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)
from transformers.trainer_utils import get_last_checkpoint

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PROCESSED_DIR = REPO_ROOT.parent / "datasets_processed"
OUTPUT_DIR = REPO_ROOT.parent / "models" / "content_agent_slm_checkpoints"
FINAL_MODEL_DIR = REPO_ROOT.parent / "models" / "content_agent"

def main():
    csv_path = PROCESSED_DIR / "content_training.csv"
    if not csv_path.exists():
        print(f"ERROR: Training data not found at {csv_path}")
        sys.exit(1)

    print("1. Loading TinyBERT tokenizer...")
    model_id = "prajjwal1/bert-tiny"
    tokenizer = AutoTokenizer.from_pretrained(model_id)

    print("2. Memory-Mapping large CSV using HuggingFace Datasets...")
    # Load via generator/pandas chunking to Arrow format with TQDM progress bar
    chunks = []
    # Using low_memory equivalent chunksize to gracefully parse 1.7GB natively
    for chunk in tqdm(pd.read_csv(csv_path, dtype={"text": str}, chunksize=50000), desc="Loading SLM Content"):
        chunks.append(chunk.dropna())
    df = pd.concat(chunks, ignore_index=True)
    dataset = Dataset.from_pandas(df)
    
    # 80/20 Train-Test Split natively in HF
    dataset = dataset.train_test_split(test_size=0.2, seed=42)

    def tokenize_function(examples):
        # Truncate to 128 tokens. Phishing tells are usually in the first 128 words.
        # This massively decreases CPU compute load compared to 512 length.
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=128)

    print("3. Tokenizing dataset (multi-processing limited to 2 cores)...")
    tokenized_datasets = dataset.map(tokenize_function, batched=True, num_proc=2)
    
    # Remove raw text to free up any stray RAM
    tokenized_datasets = tokenized_datasets.remove_columns(["text"])
    tokenized_datasets = tokenized_datasets.rename_column("label", "labels")
    tokenized_datasets.set_format("torch")

    print("4. Initializing BERT-Tiny Model for Sequence Classification...")
    model = AutoModelForSequenceClassification.from_pretrained(model_id, num_labels=2)

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, predictions, average="binary"
        )
        acc = accuracy_score(labels, predictions)
        return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


    # ── Checkpointing & Resumption Logic ──
    last_checkpoint = None
    if OUTPUT_DIR.exists() and len(os.listdir(OUTPUT_DIR)) > 0:
        last_checkpoint = get_last_checkpoint(str(OUTPUT_DIR))
        if last_checkpoint is not None:
            print(f"==================================================")
            print(f" RESUMING TRAINING from checkpoint: {last_checkpoint}")
            print(f"==================================================")

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        evaluation_strategy="epoch",      # Explicitly structured natively to Epochs
        save_strategy="epoch",
        logging_strategy="epoch",         # Logs loss and precision per epoch
        save_total_limit=2,               # Keeps only the 2 most recent checkpoints to save 8GB SSD space
        learning_rate=5e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        gradient_accumulation_steps=4, # Simulates batch size of 32
        num_train_epochs=10,
        weight_decay=0.01,
        fp16=False,               # Must be False on CPU!
        use_cpu=True,
        dataloader_num_workers=2, # Optimally utilizes the 2 vCPUs
        logging_steps=100,
        load_best_model_at_end=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        compute_metrics=compute_metrics,  # Inject mathematical logging evaluation
        tokenizer=tokenizer,
    )

    print("5. Starting Optimized Training...")
    trainer.train(resume_from_checkpoint=last_checkpoint)

    print("6. Generating Training Visualizations...")
    FINAL_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    # Plot history safely
    log_history = trainer.state.log_history
    train_loss = [x["loss"] for x in log_history if "loss" in x and "epoch" in x]
    eval_loss = [x["eval_loss"] for x in log_history if "eval_loss" in x and "epoch" in x]
    
    plt.figure(figsize=(10, 5))
    if train_loss:
        plt.plot(train_loss, label="Training Loss", marker="o")
    if eval_loss:
        plt.plot(eval_loss, label="Validation Loss", marker="s")
    plt.title("SLM Training Loss over Epochs")
    plt.xlabel("Epochs")
    plt.ylabel("Loss")
    plt.legend()
    plt.grid(True)
    loss_chart_path = FINAL_MODEL_DIR / "training_loss_curve.png"
    plt.savefig(loss_chart_path)
    plt.close()
    print(f"   -> Loss curve saved to {loss_chart_path}")

    print("7. Generating Confusion Matrix on Valid Data...")
    predictions = trainer.predict(tokenized_datasets["test"])
    preds = np.argmax(predictions.predictions, axis=-1)
    cm = confusion_matrix(predictions.label_ids, preds)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(cmap="Blues")
    plt.title("Validation Confusion Matrix")
    cm_path = FINAL_MODEL_DIR / "confusion_matrix.png"
    plt.savefig(cm_path)
    plt.close()
    print(f"   -> Confusion Matrix saved to {cm_path}")

    print("8. Saving Final Model...")
    trainer.save_model(str(FINAL_MODEL_DIR))
    print(f"Training Complete! SLM fully exported to {FINAL_MODEL_DIR}")

if __name__ == "__main__":
    main()
