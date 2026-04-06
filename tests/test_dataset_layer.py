import os
import json
import subprocess
import sys
from pathlib import Path
import pytest
import pandas as pd

# Ensure local workspace packages shadow similarly named third-party packages.
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from datasets.dataset_loader import DatasetLoader
from datasets.dataset_stats import DatasetStatisticsGenerator

@pytest.fixture(scope="module")
def setup_dummy_data(tmp_path_factory):
    original_cwd = Path.cwd()
    work_dir = tmp_path_factory.mktemp("dataset_layer")
    script_path = Path(__file__).resolve().parents[1] / "sandbox" / "create_dummy_datasets.py"

    subprocess.run(
        [sys.executable, str(script_path)],
        cwd=work_dir,
        check=True,
    )
    try:
        yield work_dir
    finally:
        os.chdir(original_cwd)

def test_dataset_integration(setup_dummy_data):
    os.chdir(setup_dummy_data)

    loader = DatasetLoader(base_dataset_dir="datasets")
    stats_gen = DatasetStatisticsGenerator()

    # 1. Emails
    res_emails = loader.load_email_dataset()
    assert res_emails["status"] == "success"
    assert len(res_emails["data"]) == 2
    stats_gen.generate_stats(res_emails["data"], "email_content", "file_collection")

    # 2. URLs
    res_urls = loader.load_url_dataset()
    assert res_urls["status"] == "success"
    assert isinstance(res_urls["data"], pd.DataFrame)
    assert len(res_urls["data"]) == 4  # 2 from phish + 2 from openphish
    stats_gen.generate_stats(res_urls["data"], "urls", "tabular")

    # 3. Attachments
    res_atts = loader.load_attachment_dataset()
    assert res_atts["status"] == "success"
    assert len(res_atts["data"]) == 2
    stats_gen.generate_stats(res_atts["data"], "attachments", "file_collection")

    # 4. Threat Intel
    res_ioc = loader.load_ioc_feeds()
    assert res_ioc["status"] == "success"
    assert isinstance(res_ioc["data"], pd.DataFrame)
    assert len(res_ioc["data"]) == 4 # 2 from csv, 2 from json lines
    stats_gen.generate_stats(res_ioc["data"], "threat_intel", "tabular")

    # Generate Report
    report_path = stats_gen.export_report("dataset_report.json")
    assert Path(report_path).exists()

    with open(report_path, "r") as f:
        report = json.load(f)

    assert "datasets" in report
    assert "urls" in report["datasets"]
    assert report["datasets"]["urls"]["samples"] == 4
    assert report["summary"]["total_datasets_loaded"] == 4
    
    print("Integration test passed, report generated as expected.")
