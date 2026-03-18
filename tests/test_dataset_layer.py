import os
import json
from pathlib import Path
import pytest
import pandas as pd

from datasets.dataset_loader import DatasetLoader
from datasets.dataset_stats import DatasetStatisticsGenerator

@pytest.fixture(scope="module")
def setup_dummy_data():
    # Attempt to use the script
    os.system("python sandbox/create_dummy_datasets.py")
    yield
    # Cleanup json report if needed, or leave it for inspection
    if Path("dataset_report.json").exists():
        pass

def test_dataset_integration(setup_dummy_data):
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
