"""
Generate synthetic datasets for agents that lack sufficient training data.

Produces:
  1. User behavior       → datasets/user_behavior/user_email_behavior.csv   (5 000 rows)
  2. Threat intel IOC feeds  → datasets/threat_intelligence/{domains,ips,urls}/*.csv
  3. Sandbox behavior    → datasets/sandbox_behavior/sandbox_logs.csv        (500 rows)
  4. Header training     → datasets/email_content/header_training.csv        (3 000 rows)

Usage:
    cd /home/LabsKraft/new_work/email_security
    python scripts/generate_synthetic_datasets.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import string
from pathlib import Path


SEED = 42
random.seed(SEED)

BASE = Path(__file__).resolve().parents[1].parent / "datasets"


# ─────────────────────────────────────────────────────────────
#  1.  User Behavior Dataset  (5 000 rows)
# ─────────────────────────────────────────────────────────────

def _generate_user_behavior(n: int = 5000) -> None:
    """Generate realistic user email interaction data."""
    out = BASE / "user_behavior" / "user_email_behavior.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    email_types = ["phishing", "spam", "legitimate", "internal", "marketing", "newsletter"]
    weights_by_type = {
        "phishing":   {"click_base": 0.35, "urgency_range": (1, 3), "link_range": (1, 5)},
        "spam":       {"click_base": 0.15, "urgency_range": (0, 2), "link_range": (1, 8)},
        "legitimate": {"click_base": 0.60, "urgency_range": (0, 1), "link_range": (0, 3)},
        "internal":   {"click_base": 0.70, "urgency_range": (0, 1), "link_range": (0, 2)},
        "marketing":  {"click_base": 0.25, "urgency_range": (0, 1), "link_range": (2, 6)},
        "newsletter": {"click_base": 0.40, "urgency_range": (0, 0), "link_range": (1, 4)},
    }

    rows = []
    for _ in range(n):
        etype = random.choice(email_types)
        w = weights_by_type[etype]

        sender_fam = random.choice([0, 1])
        urgency = random.randint(*w["urgency_range"])
        links = random.randint(*w["link_range"])

        # Click probability influenced by familiarity, urgency, and type
        p = w["click_base"]
        p += 0.15 * (1 - sender_fam)   # unfamiliar senders increase risk
        p += 0.10 * min(urgency, 2)     # urgency increases risk
        p = max(0.0, min(1.0, p + random.gauss(0, 0.08)))
        clicked = 1 if random.random() < p else 0

        rows.append({
            "sender_familiarity": sender_fam,
            "subject_urgency": urgency,
            "link_count": links,
            "email_type": etype,
            "user_clicked": clicked,
        })

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["sender_familiarity", "subject_urgency", "link_count", "email_type", "user_clicked"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"  ✓ User behavior: {len(rows)} rows → {out}")


# ─────────────────────────────────────────────────────────────
#  2.  Threat Intelligence IOC Feeds
# ─────────────────────────────────────────────────────────────

def _random_domain(malicious: bool = True) -> str:
    tlds_malicious = [".xyz", ".top", ".buzz", ".club", ".info", ".cc", ".tk", ".ml", ".ga"]
    tlds_benign = [".com", ".org", ".net", ".edu"]
    if malicious:
        name_len = random.randint(6, 18)
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=name_len))
        tld = random.choice(tlds_malicious)
    else:
        name_len = random.randint(4, 10)
        name = "".join(random.choices(string.ascii_lowercase, k=name_len))
        tld = random.choice(tlds_benign)
    return name + tld


def _random_ip() -> str:
    # Avoid reserved ranges
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _generate_threat_intel() -> None:
    """Generate IOC feed CSVs in threat_intelligence subdirectories."""
    # Malicious domains
    dom_dir = BASE / "threat_intelligence" / "domains"
    dom_dir.mkdir(parents=True, exist_ok=True)
    domains = [_random_domain(malicious=True) for _ in range(500)]
    with open(dom_dir / "malicious_domains.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["domain", "source", "first_seen"])
        for d in domains:
            writer.writerow([d, random.choice(["phishtank", "openphish", "urlhaus", "otx"]),
                             f"2026-{random.randint(1,3):02d}-{random.randint(1,28):02d}"])
    print(f"  ✓ IOC domains: {len(domains)} entries → {dom_dir / 'malicious_domains.csv'}")

    # Malicious IPs
    ip_dir = BASE / "threat_intelligence" / "ips"
    ip_dir.mkdir(parents=True, exist_ok=True)
    ips = [_random_ip() for _ in range(300)]
    with open(ip_dir / "malicious_ips.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "source", "abuse_score"])
        for ip in ips:
            writer.writerow([ip, random.choice(["abuseipdb", "shodan", "otx"]),
                             random.randint(50, 100)])
    print(f"  ✓ IOC IPs: {len(ips)} entries → {ip_dir / 'malicious_ips.csv'}")

    # Malicious URLs
    url_dir = BASE / "threat_intelligence" / "urls"
    url_dir.mkdir(parents=True, exist_ok=True)
    urls = [f"http://{_random_domain(True)}/{'/'.join(random.choices(string.ascii_lowercase, k=random.randint(2,5)))}"
            for _ in range(400)]
    with open(url_dir / "malicious_urls.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "threat_type", "source"])
        for u in urls:
            writer.writerow([u, random.choice(["phishing", "malware_download", "c2", "scam"]),
                             random.choice(["urlhaus", "phishtank", "openphish"])])
    print(f"  ✓ IOC URLs: {len(urls)} entries → {url_dir / 'malicious_urls.csv'}")


# ─────────────────────────────────────────────────────────────
#  3.  Sandbox Behavior Logs  (500 rows)
# ─────────────────────────────────────────────────────────────

def _generate_sandbox_logs(n: int = 500) -> None:
    """Generate synthetic sandbox detonation results."""
    out = BASE / "sandbox_behavior" / "sandbox_logs.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for i in range(n):
        is_malicious = random.random() < 0.55  # slight malicious bias
        ext = random.choice([".exe", ".dll", ".js", ".ps1", ".py", ".pdf", ".docx", ".xlsx"])

        if is_malicious:
            executed = True
            return_code = random.choice([0, 1, -1, 137])
            timed_out = random.random() < 0.2
            spawned = random.randint(2, 12)
            suspicious_procs = random.randint(1, min(5, spawned))
            entropy = round(random.uniform(6.5, 7.99), 2)
        else:
            executed = random.random() < 0.7
            return_code = 0
            timed_out = random.random() < 0.03
            spawned = random.randint(0, 3)
            suspicious_procs = 0
            entropy = round(random.uniform(3.0, 6.5), 2)

        rows.append({
            "sample_id": f"sample_{i:04d}",
            "file_extension": ext,
            "executed": int(executed),
            "return_code": return_code,
            "timed_out": int(timed_out),
            "spawned_processes": spawned,
            "suspicious_process_count": suspicious_procs,
            "file_entropy": entropy,
            "label": 1 if is_malicious else 0,
        })

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"  ✓ Sandbox behavior: {len(rows)} rows → {out}")


# ─────────────────────────────────────────────────────────────
#  4.  Header Training Dataset  (3 000 rows)
# ─────────────────────────────────────────────────────────────

def _generate_header_training(n: int = 3000) -> None:
    """Generate synthetic header analysis training data."""
    out = BASE / "email_content" / "header_training.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for _ in range(n):
        is_phishing = random.random() < 0.45

        if is_phishing:
            spf = 1.0 if random.random() < 0.25 else 0.0       # mostly fails
            dkim = 1.0 if random.random() < 0.20 else 0.0
            dmarc = 1.0 if random.random() < 0.15 else 0.0
            domain_len = float(random.randint(8, 35))
            display_mismatch = 1.0 if random.random() < 0.55 else 0.0
            hops = float(random.randint(1, 3))
            reply_mismatch = 1.0 if random.random() < 0.45 else 0.0
            dom_entropy = round(random.uniform(3.2, 4.8), 4)
        else:
            spf = 1.0 if random.random() < 0.90 else 0.0       # mostly passes
            dkim = 1.0 if random.random() < 0.85 else 0.0
            dmarc = 1.0 if random.random() < 0.80 else 0.0
            domain_len = float(random.randint(5, 15))
            display_mismatch = 1.0 if random.random() < 0.05 else 0.0
            hops = float(random.randint(2, 8))
            reply_mismatch = 1.0 if random.random() < 0.05 else 0.0
            dom_entropy = round(random.uniform(2.0, 3.5), 4)

        # Add some noise
        dom_entropy += random.gauss(0, 0.15)
        dom_entropy = round(max(0, dom_entropy), 4)

        rows.append({
            "spf_pass": spf,
            "dkim_pass": dkim,
            "dmarc_pass": dmarc,
            "sender_domain_len": domain_len,
            "display_name_mismatch": display_mismatch,
            "hop_count": hops,
            "reply_to_mismatch": reply_mismatch,
            "sender_domain_entropy": dom_entropy,
            "label": 1 if is_phishing else 0,
        })

    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"  ✓ Header training: {len(rows)} rows → {out}")


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    print(f"Generating synthetic datasets into: {BASE}\n")
    _generate_user_behavior()
    _generate_threat_intel()
    _generate_sandbox_logs()
    _generate_header_training()
    print("\n✅ All synthetic datasets generated successfully.")


if __name__ == "__main__":
    main()
