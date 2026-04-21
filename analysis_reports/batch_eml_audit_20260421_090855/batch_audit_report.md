# Batch EML Audit Report

Generated: 2026-04-21 09:11:11 UTC
Target API: `http://127.0.0.1:8000`

## Summary
- Emails tested: `23`
- Completed reports: `23`
- Overall verdict reasonableness pass: `23/23`
- Agent-score appropriateness pass: `23/23`
- Counterfactual validity pass: `23/23`
- Storyline validity pass: `23/23`

## Repetitive Score Diagnostics
- Heuristic: low variability (`stddev < 0.05`) or very low unique rounded values may indicate repetitive scoring.
- `attachment_agent`: n=23, mean=0.0000, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `content_agent`: n=23, mean=0.4104, stddev=0.4227, unique_3dp=10, repetitive_flag=False
- `header_agent`: n=23, mean=0.3460, stddev=0.1758, unique_3dp=13, repetitive_flag=False
- `sandbox_agent`: n=23, mean=0.0000, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `threat_intel_agent`: n=23, mean=0.0004, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `url_agent`: n=23, mean=0.4255, stddev=0.4314, unique_3dp=12, repetitive_flag=False
- `user_behavior_agent`: n=23, mean=0.0838, stddev=0.1061, unique_3dp=4, repetitive_flag=False

## Per-Email Analysis
### 1. `/home/LabsKraft/new_work/email_security/email_drop/Dabur & Sony invite you to AINCAT'26.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `d987b163-6576-4111-9ec9-e1a7eeca8164`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.182`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.6984) | Avg Agent Score: `0.1343`
- Agent Scores: attachment_agent=0.000, content_agent=0.170, header_agent=0.023, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.698, user_behavior_agent=0.048
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 2. `/home/LabsKraft/new_work/email_security/email_drop/IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `095433cc-279c-4cdd-b619-5e901aea6892`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.3645`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.62) | Avg Agent Score: `0.3049`
- Agent Scores: attachment_agent=0.000, content_agent=0.620, header_agent=0.486, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.448, user_behavior_agent=0.580
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 3. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00317.22fe43af6f4c707c4f1bdc56af959a8e.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `012e76f5-1202-4422-bbcf-aa7a89b2a8f9`
- Expected Label (heuristic): `malicious`
- Verdict: `suspicious` | Risk: `0.42`
- Recommended Actions: `['manual_review', 'soc_alert']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.6327) | Avg Agent Score: `0.1627`
- Agent Scores: attachment_agent=0.000, content_agent=0.633, header_agent=0.446, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.4 new_score=0.1573 agents_altered=['content_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 4. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00318.7ce7e3cbbf4fa9c30a67b7ecdda2342e.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `e1f125c7-139d-463b-8781-0cff14d35e3b`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.9488) | Avg Agent Score: `0.3827`
- Agent Scores: attachment_agent=0.000, content_agent=0.949, header_agent=0.743, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.927, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.77 agents_altered=['content_agent', 'url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 5. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00319.a99dff9c010e00ec182ed5701556d330.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `b0e88f5f-c35a-49e4-a801-abd9b4c741e3`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `0.9785`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.9485) | Avg Agent Score: `0.2009`
- Agent Scores: attachment_agent=0.000, content_agent=0.949, header_agent=0.397, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.2236 agents_altered=['content_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 6. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00320.20dcbb5b047b8e2f212ee78267ee27ad.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `753ab18e-68b5-4b35-94bc-50e236554099`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.9485) | Avg Agent Score: `0.3292`
- Agent Scores: attachment_agent=0.000, content_agent=0.949, header_agent=0.390, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.906, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.3742 agents_altered=['content_agent', 'url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 7. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00321.22ec127de780c31da00ae5e1c1aa32e4.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `86681c76-7dbd-43f4-9505-78658e50156b`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `0.9979`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.9979) | Avg Agent Score: `0.1726`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.998, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.1516 agents_altered=['url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 8. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00322.7d39d31fb7aad32c15dff84c14019b8c.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `1a2745cd-b711-4bc2-b7a5-4ed8405dae67`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `0.9989`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.9989) | Avg Agent Score: `0.1799`
- Agent Scores: attachment_agent=0.000, content_agent=0.050, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.999, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.1617 agents_altered=['url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 9. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00323.9e36bf05304c99f2133a4c03c49533a9.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `68ee430b-5424-4e3f-b5b5-cf9c7bf89bba`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.9485) | Avg Agent Score: `0.3492`
- Agent Scores: attachment_agent=0.000, content_agent=0.949, header_agent=0.530, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.906, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.3952 agents_altered=['content_agent', 'url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 10. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00337.813498483bc80a24c002e6e7e8e0f2cb.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `4168a068-909d-4893-b1e6-b7640f6fb6c5`
- Expected Label (heuristic): `malicious`
- Verdict: `high_risk` | Risk: `0.7`
- Recommended Actions: `['quarantine', 'soc_alert', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.7) | Avg Agent Score: `0.1301`
- Agent Scores: attachment_agent=0.000, content_agent=0.700, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.6 new_score=0.123 agents_altered=['content_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 11. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01416.dd0b9717ec7e25f4adb5a5aefa204ba1.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `6b3f0aab-7f01-4165-bf5c-2e8cbc5c5aa0`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.1615`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.5534) | Avg Agent Score: `0.1394`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.553, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.362, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 12. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01417.ce7b07a2114218dbac682b599785820d.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `e27b4ee8-af42-4e80-800b-ea53c2e6a843`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0544`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.3221) | Avg Agent Score: `0.0546`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.322, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 13. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01418.de6a5fe900081a0492fb84f6bfae46a1.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `493048c2-e6d2-4bf2-a5d6-7d7d1f2ccd01`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0544`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.3221) | Avg Agent Score: `0.0546`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.322, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 14. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01419.97da4f8a986b55cbe1f81bb22836ac58.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `fee80e5a-1e00-4bf1-a42b-4a8d333fed2c`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0704`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4288) | Avg Agent Score: `0.0699`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.429, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 15. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01420.4ee4b7db2ca10b3f5ec512d26bf8b3f9.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `e9d362a7-87a5-4ef6-83eb-3b8a724a1eab`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0774`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4757) | Avg Agent Score: `0.0766`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.476, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 16. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01421.e01ad8fa7bcb36e969c838578051d684.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `edfcb9c9-635e-43f0-b729-14e71582be2e`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0704`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4288) | Avg Agent Score: `0.0699`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.429, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 17. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01636.07c82f37d072bce96820af0bbef80eff.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `aa9d4159-256b-4ebb-9850-3611087933fd`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.1271`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4097) | Avg Agent Score: `0.1097`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.410, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.298, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 18. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01701.a28b76746a64d3d352375a462f4f8404.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `98fc81ab-1147-4305-9e9c-67004accc57b`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0774`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4757) | Avg Agent Score: `0.0766`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.476, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 19. `/home/LabsKraft/new_work/email_security/email_drop/live_check_sample.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `5ab0e8ed-b745-41de-bd5d-8200c1e1ac45`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.995) | Avg Agent Score: `0.2649`
- Agent Scores: attachment_agent=0.000, content_agent=0.649, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.995, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.3323 agents_altered=['url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 20. `/home/LabsKraft/new_work/email_security/email_drop/test_bec_wire_transfer.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `3e99e3af-56bd-4a6a-8d20-8fec8e7bb2cc`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.9966) | Avg Agent Score: `0.3079`
- Agent Scores: attachment_agent=0.000, content_agent=0.948, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.997, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.3193 agents_altered=['url_agent', 'content_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 21. `/home/LabsKraft/new_work/email_security/email_drop/test_legit_github.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `07a38a78-9ec6-47bf-a8a1-07c676030c1b`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0774`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4757) | Avg Agent Score: `0.0766`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.476, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 22. `/home/LabsKraft/new_work/email_security/email_drop/test_malspam_invoice.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `a42d3ca1-bd39-44bc-85a4-b5ff50e19765`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `0.9489`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.9489) | Avg Agent Score: `0.2078`
- Agent Scores: attachment_agent=0.000, content_agent=0.949, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.256, user_behavior_agent=0.099
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.2117 agents_altered=['content_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 23. `/home/LabsKraft/new_work/email_security/email_drop/test_spearphishing_creds.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `2bc4c3fc-7779-4946-ae5f-1697dee78817`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.9967) | Avg Agent Score: `0.3046`
- Agent Scores: attachment_agent=0.000, content_agent=0.925, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.997, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.3148 agents_altered=['url_agent', 'content_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`
