# Batch EML Audit Report

Generated: 2026-04-21 08:34:55 UTC
Target API: `http://127.0.0.1:8000`

## Summary
- Emails tested: `13`
- Completed reports: `13`
- Overall verdict reasonableness pass: `9/13`
- Agent-score appropriateness pass: `11/13`
- Counterfactual validity pass: `13/13`
- Storyline validity pass: `13/13`

## Repetitive Score Diagnostics
- Heuristic: low variability (`stddev < 0.05`) or very low unique rounded values may indicate repetitive scoring.
- `attachment_agent`: n=13, mean=0.0000, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `content_agent`: n=13, mean=0.4494, stddev=0.4080, unique_3dp=8, repetitive_flag=False
- `header_agent`: n=13, mean=0.3132, stddev=0.1754, unique_3dp=7, repetitive_flag=False
- `sandbox_agent`: n=13, mean=0.0000, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `threat_intel_agent`: n=13, mean=0.0004, stddev=0.0000, unique_3dp=1, repetitive_flag=True
- `url_agent`: n=13, mean=0.4303, stddev=0.4144, unique_3dp=8, repetitive_flag=False
- `user_behavior_agent`: n=13, mean=0.1021, stddev=0.1384, unique_3dp=4, repetitive_flag=False

## Per-Email Analysis
### 1. `/home/LabsKraft/new_work/email_security/email_drop/Dabur & Sony invite you to AINCAT'26.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `30a5f003-123b-42de-bd0b-d81963bc9969`
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
- Analysis ID: `e41ab7aa-662a-403b-970b-95fea6cc7aca`
- Expected Label (heuristic): `malicious`
- Verdict: `likely_safe` | Risk: `0.3645`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `False` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.62) | Avg Agent Score: `0.3049`
- Agent Scores: attachment_agent=0.000, content_agent=0.620, header_agent=0.486, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.448, user_behavior_agent=0.580
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 3. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00317.22fe43af6f4c707c4f1bdc56af959a8e.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `233be710-26d6-423c-bc19-717eb46204fc`
- Expected Label (heuristic): `malicious`
- Verdict: `likely_safe` | Risk: `0.1995`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `False` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `True` | Top Agent: `content_agent` (0.6327) | Avg Agent Score: `0.1627`
- Agent Scores: attachment_agent=0.000, content_agent=0.633, header_agent=0.446, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 4. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/00323.9e36bf05304c99f2133a4c03c49533a9.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `1d1b137e-d96d-4d8a-a1c9-39de56b22c56`
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
- Analysis ID: `a0b70c4d-7713-49df-9507-877f69dc5536`
- Expected Label (heuristic): `malicious`
- Verdict: `likely_safe` | Risk: `0.0285`
- Recommended Actions: `['deliver_with_banner']`
- Overall Correctness: `False` (Malicious expected -> should not be likely_safe and should exceed suspicious boundary)
- Agent Correctness: `False` | Top Agent: `header_agent` (0.15) | Avg Agent Score: `0.0301`
- Agent Scores: attachment_agent=0.000, content_agent=0.000, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.000, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (No blocking boundary expected for likely_safe)
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 6. `/home/LabsKraft/new_work/email_security/email_drop/dataset_samples/01420.4ee4b7db2ca10b3f5ec512d26bf8b3f9.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `38f84da5-9120-4ac0-8f8e-a4a2892fa3ea`
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
- Analysis ID: `ab940804-1d52-4aca-9361-e4317ffdf4ae`
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
- Analysis ID: `0813a000-2600-4ab1-bf10-727494036cf1`
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
- Analysis ID: `c9290185-0c89-49d4-bf17-ececaa703788`
- Expected Label (heuristic): `benign`
- Verdict: `malicious` | Risk: `1.0`
- Recommended Actions: `['quarantine', 'block_sender', 'trigger_garuda']`
- Overall Correctness: `False` (Benign expected -> prefer likely_safe or low-end suspicious with modest score)
- Agent Correctness: `False` | Top Agent: `url_agent` (0.995) | Avg Agent Score: `0.2649`
- Agent Scores: attachment_agent=0.000, content_agent=0.649, header_agent=0.150, sandbox_agent=0.000, threat_intel_agent=0.000, url_agent=0.995, user_behavior_agent=0.060
- Counterfactual Correctness: `True` (Counterfactual flip should reduce score below boundary)
- Counterfactual Details: threshold=0.8 new_score=0.3323 agents_altered=['url_agent']
- Storyline Correctness: `True` (Expected at least two storyline entries including Containment)
- Storyline Phases: `['Delivery', 'Lure', 'Weaponization', 'Containment']`

### 10. `/home/LabsKraft/new_work/email_security/email_drop/test_bec_wire_transfer.eml`
- Status: `ok`
- Message: analysis_completed
- Analysis ID: `f52db416-e777-4e5c-85c3-816155cc37af`
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
- Analysis ID: `822be170-b105-4507-9689-378684fabe45`
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
- Analysis ID: `12ddf055-a0c8-423e-96f7-77fb1726f42d`
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
- Analysis ID: `95622079-733d-4d47-b9b5-d8c57167522d`
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
