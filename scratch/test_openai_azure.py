
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from openai import AzureOpenAI
from src.configs.settings import settings

def test_openai():
    print("=== Azure OpenAI Test ===")
    print(f"Endpoint: {settings.azure_openai_endpoint}")
    print(f"Key: {settings.azure_openai_api_key[:5]}...{settings.azure_openai_api_key[-5:]}")
    print(f"Deployment: {settings.azure_openai_deployment}")
    
    if not settings.azure_openai_api_key:
        print("Error: Azure OpenAI API key not found.")
        return

    client = AzureOpenAI(
        api_key=settings.azure_openai_api_key,
        azure_endpoint=settings.azure_openai_endpoint,
        api_version=settings.azure_openai_api_version
    )

    try:
        print("Sending test prompt...")
        response = client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": "You are a helpful security assistant."},
                {"role": "user", "content": "Explain briefly why email security is important."}
            ],
            max_tokens=50
        )
        print("\nResponse:")
        print(response.choices[0].message.content)
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    test_openai()
