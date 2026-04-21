# Batch EML Audit Report

Generated: 2026-04-21 09:01:14 UTC
Target API: `http://127.0.0.1:8000`

## Summary
- Emails tested: `13`
- Completed reports: `13`
- Overall verdict reasonableness pass: `13/13`
- Agent-score appropriateness pass: `13/13`
- Counterfactual validity pass: `13/13`
- Storyline validity pass: `13/13`

## Repetitive Score Diagnostics
- Heuristic: low variability (`stddev < 0.05`) or very low unique rounded values may indicate repetitive scoring.
- `attachment_agent`: n=13, mean=0.0000, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `content_agent`: n=13, mean=0.5033, stddev=0.3910, unique_3dp=9, repetitive_flag=False
- `header_agent`: n=13, mean=0.3132, stddev=0.1754, unique_3dp=7, repetitive_flag=False
- `sandbox_agent`: n=13, mean=0.0000, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `threat_intel_agent`: n=13, mean=0.0004, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `url_agent`: n=13, mean=0.4303, stddev=0.4144, unique_3dp=8, repetitive_flag=False
- `user_behavior_agent`: n=13, mean=0.1021, stddev=0.1384, unique_3dp=4, repetitive_flag=False

## Per-Email Analysis
### 1. `/home/LabsKraft/new_work/email_security/email_drop/Dabur & Sony invite you to AINCAT'26.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `22a0dfca-975c-4ef7-b753-1fbfcf611493`
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
- Analysis ID: `61c361d1-cbdc-4f22-b580-dd0376d72d1c`
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
- Analysis ID: `8a33a6e8-8321-4ed1-96d4-0a7e9feeb097`
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

### 4. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00323.9e36bf05304c99f2133a4c03c49533a9.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `a2363a4b-7611-4fbb-aff9-93b25506cfe0`
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

### 5. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00337.813498483bc80a24c002e6e7e8e0f2cb.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `53e829a5-bfad-4988-a9d8-88118fa70f03`
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

### 6. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01420.4ee4b7db2ca10b3f5ec512d26bf8b3f9.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `ff6f9901-7ba3-4499-84e5-ff4fd06e4b5f`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0774`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4757) | Avg Agent Score: `0.0766`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.476, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 7. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01636.07c82f37d072bce96820af0bbef80eff.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `2673fd00-c9fc-4edd-ac1a-4969de0c7e1a`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.1271`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4097) | Avg Agent Score: `0.1097`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.410, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.298, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 8. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01701.a28b76746a64d3d352375a462f4f8404.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `b4d26478-ccc6-4520-8fb9-6e4085d4c314`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0774`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4757) | Avg Agent Score: `0.0766`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.476, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 9. `/home/LabsKraft/new_work/email_security/email_drop/live_check_sample.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `082bb116-bedc-4871-b29c-d5b1695f338c`
- Expected Label (heuristic): `malicious`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `True` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `url_agent` (0.995) | Avg Agent Score: `0.2649`
- Agent Scores: attachment_agent=0.000, content_agent=0.649, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.995, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.321 agents_altered=['url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 10. `/home/LabsKraft/new_work/email_security/email_drop/test_bec_wire_transfer.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `1dfc34b8-4576-4e60-bcfb-de4ef83fd72b`
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

### 11. `/home/LabsKraft/new_work/email_security/email_drop/test_legit_github.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `96fc4347-e1d1-421e-857f-4160ac04a739`
- Expected Label (heuristic): `benign`
- Verdict: `likely_safe` | Risk: `0.0774`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `True` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `True` | Top Agent: `header_agent` (0.4757) | Avg Agent Score: `0.0766`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.476, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 12. `/home/LabsKraft/new_work/email_security/email_drop/test_malspam_invoice.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `7e79dedb-a2e0-4de9-9677-c112f5034a7c`
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

### 13. `/home/LabsKraft/new_work/email_security/email_drop/test_spearphishing_creds.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `698be5e1-c472-41da-ab5d-21d0d0ed0f7f`
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
