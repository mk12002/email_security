# Expanded 10-Mail Audit Analysis

## Scope Added
Added 10 new `.eml` samples to `email_security/email_drop/dataset_samples`:

- Malicious-labeled spamassassin set:
  - `00318.7ce7e3cbbf4fa9c30a67b7ecdda2342e.eml`
  - `00319.a99dff9c010e00ec182ed5701556d330.eml`
  - `00320.20dcbb5b047b8e2f212ee78267ee27ad.eml`
  - `00321.22ec127de780c31da00ae5e1c1aa32e4.eml`
  - `00322.7d39d31fb7aad32c15dff84c14019b8c.eml`
- Benign-labeled ham set:
  - `01416.dd0b9717ec7e25f4adb5a5aefa204ba1.eml`
  - `01417.ce7b07a2114218dbac682b599785820d.eml`
  - `01418.de6a5fe900081a0492fb84f6bfae46a1.eml`
  - `01419.97da4f8a986b55cbe1f81bb22836ac58.eml`
  - `01421.e01ad8fa7bcb36e969c838578051d684.eml`

## Run Outcome
- Run folder: `batch_eml_audit_20260421_090855`
- Total emails tested: `23`
- Completed reports: `23/23`
- Overall verdict reasonableness: `23/23`
- Agent-score appropriateness: `23/23`
- Counterfactual validity: `23/23`
- Threat storyline validity: `23/23`

## Relevant Behavioral Analysis

### 1) Decision quality on new malicious samples
- All 5 new `00318`-`00322` samples were classified at blocking levels:
  - `malicious`: `00318`, `00319`, `00320`, `00321`, `00322`
- Risk range for those 5: `0.9785` to `1.0`.
- Recommended actions consistently included containment (`quarantine` / `block_sender` / `trigger_garuda`).

### 2) Decision quality on new benign samples
- All 5 new `01416`-`01421` samples were classified `likely_safe`.
- Risk range for those 5: `0.0544` to `0.1615`.
- Actions consistently remained non-blocking (`deliver_with_banner`).

### 3) Explainability integrity (counterfactual + storyline)
- Counterfactual outputs remained structured and valid for all 23 emails.
- For blocking verdicts, counterfactual scores dropped below the corresponding threshold.
- Storyline outputs remained structured and phase-complete for all 23 emails.
- Phase sequence continued to include: `Delivery`, `Lure`, `Weaponization`, `Containment`.

### 4) Repetitive-score diagnostics (important caveat)
- Still flagged repetitive:
  - `attachment_agent` (mean `0.0`, stddev `0.0`)
  - `sandbox_agent` (mean `0.0`, stddev `0.0`)
  - `threat_intel_agent` (mean `0.0004`, stddev `0.0`)
- Interpretation for this corpus remains unchanged:
  - Most emails are no-attachment cases.
  - IOC enrichment did not produce decisive hits in this set.
- Non-repetitive/high-variance agents:
  - `content_agent`, `header_agent`, `url_agent`, `user_behavior_agent`.

### 5) Verdict distribution sanity check
- `likely_safe`: `11`
- `suspicious`: `1`
- `high_risk`: `1`
- `malicious`: `10`

This distribution is consistent with a mixed corpus containing benign ham plus explicit spam/phishing fixtures.

## Conclusion
The additional 10 emails did not introduce regressions. The expanded 23-mail campaign preserved full pass rates across correctness, agent appropriateness, and structured explainability checks.