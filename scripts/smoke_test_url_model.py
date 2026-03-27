#!/usr/bin/env python3
"""Smoke test for URL model quality and prediction robustness."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

ML_RUNTIME_PATH = REPO_ROOT / "agents" / "ml_runtime.py"
FEAT_EXTRACTOR_PATH = REPO_ROOT / "agents" / "url_agent" / "feature_extractor.py"


def _load_symbol(path: Path, symbol: str):
    spec = importlib.util.spec_from_file_location(path.stem + "_standalone", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, symbol)


load_model_bundle = _load_symbol(ML_RUNTIME_PATH, "load_model_bundle")
predict_with_model = _load_symbol(ML_RUNTIME_PATH, "predict_with_model")
extract_features = _load_symbol(FEAT_EXTRACTOR_PATH, "extract_features")

MODEL_DIR = REPO_ROOT.parent / "models" / "url_agent"


def _predict_risk(model_bundle, urls: list[str]) -> float:
    features = extract_features({"urls": urls})
    pred = predict_with_model(features, model_bundle, "smoke_url")
    return float(pred.get("risk_score", 0.0))


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * q))))
    return float(ordered[idx])


def _pairwise_win_rate(benign_scores: list[float], malicious_scores: list[float]) -> float:
    if not benign_scores or not malicious_scores:
        return 0.0
    total = len(benign_scores) * len(malicious_scores)
    wins = 0
    for m_score in malicious_scores:
        for b_score in benign_scores:
            if m_score > b_score:
                wins += 1
    return float(wins / total)


def run_smoke_test(
    model_dir: Path,
    min_mean_gap: float = 0.18,
    min_pairwise_win_rate: float = 0.70,
    min_malicious_above_rate: float = 0.50,
    min_benign_below_count: int = 1,
) -> dict[str, object]:
    model_bundle = load_model_bundle(model_dir)
    if not model_bundle:
        return {
            "timestamp_utc": _stamp(),
            "model_dir": str(model_dir),
            "passed": False,
            "error": f"No URL model found at {model_dir}",
            "conditions": {},
        }

    threshold = 0.5
    threshold_source = "default"
    if isinstance(model_bundle, dict) and "decision_threshold" in model_bundle:
        threshold = float(model_bundle["decision_threshold"])
        threshold_source = "model_bundle"

    benign_cases = [
        ["https://www.wikipedia.org/wiki/Cybersecurity"],
        ["https://docs.python.org/3/library/urllib.parse.html"],
        ["https://github.com/explore"],
        ["https://www.cloudflare.com/learning/security/what-is-phishing/"],
        ["https://www.microsoft.com/en-us/security/business/security-101/what-is-phishing"],
        ["https://www.cisa.gov/news-events/cybersecurity-advisories"],
        ["https://www.nist.gov/cyberframework"],
        ["https://www.mozilla.org/en-US/security/"],
    ]

    malicious_cases = [
        ["http://secure-login-update-account.example.biz/verify?token=abc123&continue=bank"],
        ["http://198.51.100.42/login.php?verify=1&session=expired"],
        ["http://xn--secure-paypa1-9k2d.com/auth/signin?confirm=invoice"],
        ["http://apple-id-verify-account.example.ru/security/update?password=reset"],
        ["http://confirm-wallet-secure.example.top/update?id=9981&next=signin"],
        ["http://support-verification.example.click/auth/session/check?user=mail"],
        ["http://203.0.113.71/account-security/verify-now?redirect=portal"],
        ["http://xn--microsft-support-9kb.example.cn/login/confirm"],
    ]

    benign_scores = [_predict_risk(model_bundle, urls) for urls in benign_cases]
    malicious_scores = [_predict_risk(model_bundle, urls) for urls in malicious_cases]

    benign_mean = sum(benign_scores) / max(1, len(benign_scores))
    malicious_mean = sum(malicious_scores) / max(1, len(malicious_scores))

    benign_below = sum(score < threshold for score in benign_scores)
    malicious_above = sum(score >= threshold for score in malicious_scores)
    benign_below_rate = float(benign_below / max(1, len(benign_scores)))
    malicious_above_rate = float(malicious_above / max(1, len(malicious_scores)))
    pairwise_win_rate = _pairwise_win_rate(benign_scores, malicious_scores)

    benign_p75 = _percentile(benign_scores, 0.75)
    malicious_p25 = _percentile(malicious_scores, 0.25)
    benign_median = _percentile(benign_scores, 0.50)
    malicious_median = _percentile(malicious_scores, 0.50)

    conditions = {
        "malicious_mean_gt_benign_mean": bool(malicious_mean > benign_mean),
        "mean_gap_at_least_required": bool((malicious_mean - benign_mean) >= min_mean_gap),
        "malicious_median_gt_benign_median": bool(malicious_median > benign_median),
        "malicious_p25_gt_benign_p75": bool(malicious_p25 > benign_p75),
        "pairwise_win_rate_at_least_required": bool(pairwise_win_rate >= min_pairwise_win_rate),
        "benign_below_threshold_at_least_required": bool(benign_below >= min_benign_below_count),
        "malicious_above_threshold_rate_at_least_required": bool(malicious_above_rate >= min_malicious_above_rate),
        "top_malicious_above_top_benign": bool(max(malicious_scores) > max(benign_scores)),
    }

    return {
        "timestamp_utc": _stamp(),
        "model_dir": str(model_dir),
        "criteria": {
            "min_mean_gap": float(min_mean_gap),
            "min_pairwise_win_rate": float(min_pairwise_win_rate),
            "min_malicious_above_rate": float(min_malicious_above_rate),
            "min_benign_below_count": int(min_benign_below_count),
        },
        "threshold": float(threshold),
        "threshold_source": threshold_source,
        "case_counts": {
            "benign": int(len(benign_scores)),
            "malicious": int(len(malicious_scores)),
        },
        "benign_scores": [float(value) for value in benign_scores],
        "malicious_scores": [float(value) for value in malicious_scores],
        "benign_mean": float(benign_mean),
        "malicious_mean": float(malicious_mean),
        "mean_gap": float(malicious_mean - benign_mean),
        "benign_below_threshold": int(benign_below),
        "malicious_above_threshold": int(malicious_above),
        "metrics": {
            "benign_below_threshold_rate": benign_below_rate,
            "malicious_above_threshold_rate": malicious_above_rate,
            "pairwise_win_rate": pairwise_win_rate,
            "benign_p75": benign_p75,
            "malicious_p25": malicious_p25,
            "benign_median": benign_median,
            "malicious_median": malicious_median,
        },
        "conditions": conditions,
        "passed": bool(all(conditions.values())),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smoke test for URL model quality")
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--min-mean-gap", type=float, default=0.18)
    parser.add_argument("--min-pairwise-win-rate", type=float, default=0.70)
    parser.add_argument("--min-malicious-above-rate", type=float, default=0.50)
    parser.add_argument("--min-benign-below-count", type=int, default=1)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    result = run_smoke_test(
        args.model_dir,
        min_mean_gap=args.min_mean_gap,
        min_pairwise_win_rate=args.min_pairwise_win_rate,
        min_malicious_above_rate=args.min_malicious_above_rate,
        min_benign_below_count=args.min_benign_below_count,
    )

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if "error" in result:
        print(f"ERROR: {result['error']}")
        return 1

    print("URL Model Smoke Test")
    print(f"  decision threshold={float(result['threshold']):.4f} ({result['threshold_source']})")
    print(
        "  cases="
        f"benign:{int(result['case_counts']['benign'])} "
        f"malicious:{int(result['case_counts']['malicious'])}"
    )
    for idx, score in enumerate(result["benign_scores"]):
        print(f"  benign_case_{idx} risk={score:.4f}")
    for idx, score in enumerate(result["malicious_scores"]):
        print(f"  malicious_case_{idx} risk={score:.4f}")
    print(
        f"  benign_mean={float(result['benign_mean']):.4f} "
        f"malicious_mean={float(result['malicious_mean']):.4f} "
        f"gap={float(result['mean_gap']):.4f}"
    )
    metrics = result.get("metrics", {})
    print(
        "  pairwise_win_rate="
        f"{float(metrics.get('pairwise_win_rate', 0.0)):.4f} "
        "malicious_above_rate="
        f"{float(metrics.get('malicious_above_threshold_rate', 0.0)):.4f} "
        "benign_below_rate="
        f"{float(metrics.get('benign_below_threshold_rate', 0.0)):.4f}"
    )

    if bool(result["passed"]):
        print("SMOKE TEST PASS")
        return 0

    print("SMOKE TEST FAIL")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
