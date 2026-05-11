
import os
import sys
import json
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.services.ocr_service import extract_text_from_file
from src.services.logging_service import setup_logging

def test_ocr():
    setup_logging()
    
    # Path to a sample image
    image_path = Path("docs/final arch.png")
    
    if not image_path.exists():
        print(f"Error: {image_path} not found.")
        return

    print(f"Testing OCR on {image_path}...")
    try:
        result = extract_text_from_file(image_path)
        
        print("\n--- OCR RESULTS ---")
        print(f"Success: {result.get('success')}")
        print(f"Text length: {len(result.get('extracted_text', ''))}")
        print(f"URLs found: {result.get('discovered_urls', [])}")
        print(f"Error: {result.get('error')}")
        print("\nSample Text (first 200 chars):")
        print(result.get('extracted_text', '')[:200])
        print("-------------------\n")
        
        if result.get('success') and (result.get('extracted_text') or result.get('discovered_urls')):
            print("SUCCESS: OCR service returned data.")
        else:
            print(f"WARNING: OCR service did not return expected data. Success={result.get('success')}")
            
    except Exception as e:
        print(f"FAILURE: OCR test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ocr()
