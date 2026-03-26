"""
Smoke test for the Content SLM.

Applies the SAME _compact_text() preprocessing used during training
before sending text through the HuggingFace inference pipeline.
"""

import sys
from pathlib import Path
import warnings
warnings.filterwarnings("ignore")

from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "content_agent"

MAX_WORDS_PER_SAMPLE = 180

LABEL_NORMALIZATION = {
    "label_0": "Legitimate",
    "label_1": "Spam",
    "label_2": "Phishing",
}


def _compact_text(text: str) -> str:
    """Identical to the training preprocessor."""
    normalized = " ".join(str(text).split())
    words = normalized.split()
    if len(words) > MAX_WORDS_PER_SAMPLE:
        words = words[:MAX_WORDS_PER_SAMPLE]
    return " ".join(words)


def _normalize_label(label: str) -> str:
    return LABEL_NORMALIZATION.get(str(label).strip().lower(), str(label))


def main():
    if not MODEL_DIR.exists():
        print(f"Error: Model not found at {MODEL_DIR}")
        sys.exit(1)

    print(f"Loading finetuned SLM from {MODEL_DIR}...")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))

    classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)

    test_emails = [
        ("Legitimate Business Update",
         "Hi team, please find attached the Q3 financial reports. Let's discuss them in our meeting at 2PM today. Best, Sarah."),

        ("Blatant Spam",
         "BUY VIAGRA CHEAP NOW!!! FREE SHIPPING LIMITED TIME OFFER CLICK HERE TO GET 90% OFF ROLEX REPLICA"),

        ("Targeted Phishing",
         "Dear Customer, Your PayPal account has been suspended due to suspicious activity. "
         "You must verify your identity immediately by clicking this secure link: "
         "http://paypal-verify-secure123.com/login. Failure to do so will result in permanent closure."),

        ("Newsletter (Legitimate)",
         "Weekly digest: Here are the top stories from TechCrunch this week. "
         "Apple announced new MacBook models. Google released Android updates."),

        ("Nigerian Fraud (Phishing)",
         "I am Barrister Johnson from Lagos Nigeria. You have been selected to receive $4.5 million USD. "
         "Please send your bank details and a processing fee of $500 to claim your inheritance."),
    ]

    print("\n--- SMOKE TEST RESULTS ---")
    for category, text in test_emails:
        # Apply the SAME preprocessing as training
        processed = _compact_text(text)

        top_results = classifier(processed, truncation=True, max_length=96, top_k=3)
        result = top_results[0]
        raw_label = result["label"]
        label = _normalize_label(raw_label)
        score = result["score"]

        print(f"\n[Expected: {category}]")
        print(f"  Input: '{text[:80]}...'")
        print(f"  Predicted: {label} (raw: {raw_label}, Confidence: {score:.4f})")
        top_fmt = ", ".join(
            f"{_normalize_label(row['label'])}:{float(row['score']):.4f}" for row in top_results
        )
        print(f"  Top-3: {top_fmt}")

        # Simple pass/fail check
        expected_map = {
            "Legitimate Business Update": "Legitimate",
            "Blatant Spam": "Spam",
            "Targeted Phishing": "Phishing",
            "Newsletter (Legitimate)": "Legitimate",
            "Nigerian Fraud (Phishing)": "Phishing",
        }
        expected = expected_map.get(category, "")
        status = "✅ PASS" if expected.lower() in label.lower() else "⚠️  MISMATCH"
        print(f"  Status: {status}")


if __name__ == "__main__":
    main()
