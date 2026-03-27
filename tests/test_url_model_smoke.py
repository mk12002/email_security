from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

ML_RUNTIME_PATH = REPO_ROOT / "agents" / "ml_runtime.py"
SMOKE_SCRIPT_PATH = REPO_ROOT / "scripts" / "smoke_test_url_model.py"


def _load_symbol(path: Path, symbol: str):
    spec = importlib.util.spec_from_file_location(path.stem + "_standalone", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, symbol)


load_model_bundle = _load_symbol(ML_RUNTIME_PATH, "load_model_bundle")
run_smoke_test = _load_symbol(SMOKE_SCRIPT_PATH, "run_smoke_test")


@pytest.mark.smoke
def test_url_model_smoke_ordering_and_threshold() -> None:
    model_dir = REPO_ROOT.parent / "models" / "url_agent"
    model_bundle = load_model_bundle(model_dir)

    if not model_bundle:
        pytest.skip(f"No trained URL model found at {model_dir}")

    result = run_smoke_test(model_dir)
    assert bool(result.get("passed", False))

    metrics = result.get("metrics", {})
    assert float(metrics.get("pairwise_win_rate", 0.0)) >= 0.70
    assert float(metrics.get("malicious_above_threshold_rate", 0.0)) >= 0.50
    assert int(result.get("benign_below_threshold", 0)) >= 1
