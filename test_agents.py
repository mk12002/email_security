import requests
import json
import time

BASE_URL = "http://localhost:8000"

# Fetch the examples payload that the UI uses
try:
    examples = requests.get(f"{BASE_URL}/agent-test/examples").json().get("examples", {})
except Exception as e:
    print("Failed to get examples:", str(e))
    exit(1)

agent_names = [
    "header_agent",
    "content_agent",
    "url_agent",
    "attachment_agent",
    "sandbox_agent",
    "threat_intel_agent",
    "user_behavior_agent"
]

results = {}

print(f"Testing {len(agent_names)} agents with predefined templates...")

for agent in agent_names:
    print(f"\n[{agent}] testing...")
    
    # 1. Positive (Malicious) from default example
    positive_payload = examples.get(agent, {})
    if "body" in positive_payload and isinstance(positive_payload["body"], str):
        positive_payload["body"] = {"plain": positive_payload["body"], "html": ""}
    try:
        start = time.time()
        res_pos = requests.post(f"{BASE_URL}/agent-test/{agent}", json={"payload": positive_payload}).json()
        print(f"  [Positive] Score: {res_pos.get('output', {}).get('risk_score', 'N/A')} | Time: {time.time()-start:.2f}s")
    except Exception as e:
        print(f"  [Positive] FAILED: {str(e)}")
        res_pos = {"error": str(e)}

    # 2. Negative (Benign)
    # We strip out malicious indicators to make it benign
    negative_payload = json.loads(json.dumps(positive_payload)) # deepcopy
    if "headers" in negative_payload:
        negative_payload["headers"]["sender"] = "trusted@company.com"
        negative_payload["headers"]["authentication_results"] = "spf=pass dkim=pass dmarc=pass"
        if "to" in negative_payload["headers"]:
            if negative_payload["headers"]["to"]:
                negative_payload["headers"]["to"] = ["bob@company.com"]
    if "urls" in negative_payload:
        negative_payload["urls"] = ["https://www.google.com", "https://github.com/login"]
    if "body" in negative_payload:
        negative_payload["body"] = {}
        negative_payload["body"]["plain"] = "Hey Bob, let's catch up for lunch today. Best, Alice."
        negative_payload["body"]["html"] = "<p>Hey Bob, let's catch up for lunch today. Best, Alice.</p>"
    if "attachments" in negative_payload:
        for att in negative_payload["attachments"]:
            att["filename"] = "meeting_notes.txt"
            att["size_bytes"] = 400
    if "iocs" in negative_payload:
        negative_payload["iocs"] = {"domains": ["google.com"], "ips": [], "hashes": []}

    try:
        start = time.time()
        res_neg = requests.post(f"{BASE_URL}/agent-test/{agent}", json={"payload": negative_payload}).json()
        print(f"  [Negative] Score: {res_neg.get('output', {}).get('risk_score', 'N/A')} | Time: {time.time()-start:.2f}s")
    except Exception as e:
        print(f"  [Negative] FAILED: {str(e)}")
        res_neg = {"error": str(e)}
        
    # 3. Edge Case (Empty / Malformed but acceptable)
    edge_payload = {
        "headers": {"sender": "", "to": [], "authentication_results": ""},
        "urls": [],
        "body": {"plain": "", "html": ""},
        "attachments": [],
        "iocs": {"domains": [], "ips": [], "hashes": []}
    }
    try:
        start = time.time()
        res_edge = requests.post(f"{BASE_URL}/agent-test/{agent}", json={"payload": edge_payload}).json()
        print(f"  [Edge Case] Score: {res_edge.get('output', {}).get('risk_score', 'N/A')} | Time: {time.time()-start:.2f}s")
    except Exception as e:
        print(f"  [Edge Case] FAILED: {str(e)}")
        res_edge = {"error": str(e)}
        
    results[agent] = {"positive": res_pos, "negative": res_neg, "edge": res_edge}

with open("test_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nDone. Details saved to test_results.json")
