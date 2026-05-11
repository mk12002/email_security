
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from src.action_layer.azure_search_client import get_azure_search_client, is_azure_search_available
from src.configs.settings import settings

def test_azure_search():
    print("=== Azure Search Test ===")
    print(f"Service: {settings.azure_search_service}")
    print(f"Index: {settings.azure_search_index_name}")
    print(f"Enabled: {settings.azure_search_enabled}")
    
    if not is_azure_search_available():
        print("Error: Azure Search is not available or not configured.")
        return

    client = get_azure_search_client()
    print("Client initialized.")

    # Test indicator upload (one dummy ioc)
    dummy_ioc = {
        "indicator": "test-malicious-domain.com",
        "indicator_type": "domain",
        "severity": "high",
        "source": "manual_test",
        "description": "Test indicator for system validation.",
        "confidence": 0.9,
        "tags": ["test", "malicious"]
    }

    print(f"Uploading dummy indicator: {dummy_ioc['indicator']}...")
    success, failed = client.upload_indicators([dummy_ioc])
    print(f"Upload result: {success} succeeded, {failed} failed.")

    if success > 0:
        print("\nPerforming semantic search...")
        # Note: Semantic search might take a few seconds for the index to update, 
        # but let's try.
        results = client.semantic_search("test malicious domain")
        print(f"Semantic search results: {len(results)}")
        for r in results:
            print(f" - {r['indicator']} (Score: {r['score']})")
    else:
        print("Skipping search test due to upload failure.")

if __name__ == "__main__":
    test_azure_search()
