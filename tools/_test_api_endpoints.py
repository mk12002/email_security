"""Test all API endpoints and dump results for analysis."""

import httpx
import json
import sys

BASE = "http://127.0.0.1:8000"

def test_agent(name, internal_payload):
    print(f"\n{'='*70}")
    print(f"TESTING: {name}")
    print(f"{'='*70}")
    try:
        r = httpx.post(
            f"{BASE}/agent-test/{name}",
            json={
                "payload": internal_payload,
                "inject_analysis_id": True,
                "print_output": False
            },
            timeout=60
        )
        print(f"Status: {r.status_code}")
        data = r.json()
        print(json.dumps(data, indent=2))
        return data
    except Exception as e:
        print(f"ERROR: {e}")
        return None

# 1. Header Agent
test_agent("header_agent", {
    "headers": {
        "sender": "alerts-security@paypa1.example",
        "reply_to": "hacker@evil.example",
        "subject": "URGENT: Your account has been compromised",
        "received": ["from unknown-smtp.example by victim-mx"],
        "message_id": "<phish-test-001@evil.example>",
        "authentication_results": "spf=fail; dkim=fail; dmarc=fail"
    }
})

# 2. Content Agent
test_agent("content_agent", {
    "headers": {"subject": "Invoice Payment Required"},
    "body": {
        "plain": "Urgent action required. Confirm your password now to avoid account lock. Click http://evil.example/login",
        "html": ""
    }
})

# 3. URL Agent
test_agent("url_agent", {
    "urls": [
        "http://secure-login-paypa1.example/verify?user=admin",
        "https://microsoft.com-security-login.example/reset",
        "http://bit.ly/3x7fake"
    ]
})

# 4. Attachment Agent
test_agent("attachment_agent", {
    "attachments": []
})

# 5. Threat Intel Agent
test_agent("threat_intel_agent", {
    "iocs": {
        "domains": ["evil.example", "known-phishing.com"],
        "ips": ["185.100.87.202", "203.0.113.42"],
        "hashes": ["44d88612fea8a8f36de82e1278abb02f"]
    },
    "urls": ["http://known-bad.example/malware"],
    "headers": {"sender": "attacker@evil.example"}
})

# 6. User Behavior Agent
test_agent("user_behavior_agent", {
    "headers": {
        "sender": "ceo-urgent@external-company.example",
        "subject": "Wire transfer needed immediately"
    },
    "body": {
        "plain": "I need you to wire $50,000 to this account urgently. Do not tell anyone.",
        "html": ""
    }
})

# 7. Full Pipeline Test - /analyze-email
print(f"\n{'='*70}")
print("TESTING: FULL PIPELINE /analyze-email")
print(f"{'='*70}")
try:
    r = httpx.post(f"{BASE}/analyze-email", json={
        "headers": {
            "sender": "phishing-attacker@paypa1.example",
            "reply_to": "attacker@evil.example",
            "subject": "URGENT: Verify your account NOW",
            "received": ["from malicious-smtp by victim-mx"],
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            "message_id": "<pipeline-test@evil.example>"
        },
        "body": "Your PayPal account has been compromised. Click http://secure-paypa1.example/verify to restore access immediately. Enter your password and SSN.",
        "urls": ["http://secure-paypa1.example/verify"],
        "attachments": []
    }, timeout=120)
    print(f"Status: {r.status_code}")
    data = r.json()
    print(json.dumps(data, indent=2))
except Exception as e:
    print(f"ERROR: {e}")

print(f"\n{'='*70}")
print("ALL TESTS COMPLETE")
print(f"{'='*70}")
