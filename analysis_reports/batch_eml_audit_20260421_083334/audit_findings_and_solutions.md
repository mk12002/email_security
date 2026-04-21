# Audit Findings and Solutions

## Scope
- Corpus tested: 13 `.eml` files from `email_security/email_drop` (including 6 copied dataset samples: 3 spam + 3 ham).
- Pipeline used: full live system (API + frontend routes + orchestrator + all 7 agents + sandbox executor).
- Detailed per-email output: `batch_audit_report.md` and `batch_audit_results.json`.

## Overall Correctness Findings
- Completed reports: 13/13.
- Overall verdict reasonableness pass: 9/13.
- Agent-level appropriateness pass: 11/13.
- Counterfactual validity: 13/13.
- Threat storyline validity: 13/13.

## Emails Flagged as Potentially Incorrect or Needing Calibration
- `IEEE ICNPCV 2026 - PAYMENT REMINDER.eml`
  - Expected heuristic: malicious.
  - Actual: `likely_safe` with risk `0.3645`.
  - Observation: strong content and user-behavior risk signals were present, but score stayed below suspicious boundary after weighting/correlation.

- `dataset_samples/00317...eml` (spamassassin spam)
  - Expected heuristic: malicious.
  - Actual: `likely_safe` with risk `0.1995`.
  - Observation: content risk present, URL risk near zero for this sample; aggregate remained low.

- `dataset_samples/00337...eml` (spamassassin spam)
  - Expected heuristic: malicious.
  - Actual: `likely_safe` with risk `0.0285`.
  - Observation: weak detected indicators across agents for this particular sample.

- `live_check_sample.eml`
  - Expected heuristic: benign.
  - Actual: `malicious` with risk `1.0`.
  - Observation: URL + content agents produced very high scores; likely true positive or needs manual label review for this sample.

## Repetitive Score Findings (Your Main Concern)
- Repetitive diagnostics flagged:
  - `attachment_agent`: mean `0.0000`, stddev `0.0000`, unique_3dp `1`.
  - `sandbox_agent`: mean `0.0000`, stddev `0.0000`, unique_3dp `1`.
  - `threat_intel_agent`: mean `0.0004`, stddev `0.0000`, unique_3dp `1`.

### Interpretation
- For this corpus, repetition is mostly expected:
  - Most emails had no real attachments -> attachment/sandbox remain near zero.
  - IOC enrichment had no decisive matches -> threat-intel baseline remained constant.
- Not all agents were repetitive:
  - `content_agent`, `header_agent`, and `url_agent` showed meaningful variance.

## System Issue Discovered and Resolved During Audit
- Issue: `threat_intel_agent` and `user_behavior_agent` crashed with `sqlite3.OperationalError: database is locked` when loading IOC store.
- Operational fix used for this run:
  - Started those workers with explicit `IOC_DB_PATH=/home/LabsKraft/new_work/email_security/data/ioc_store_batchtest.db`.
- Impact:
  - Without this fix, orchestrator finalization was delayed/incomplete for many analyses.
  - With this fix, end-to-end completion became 13/13.

## Counterfactual and Storyline Quality
- Counterfactual output is structured and valid in all completed reports.
- For blocking verdicts, `new_normalized_score` correctly falls below relevant threshold.
- Storyline output is structured in all reports and includes required `Containment` phase.
- Phase sequence consistently appears as:
  - `Delivery`, `Lure`, `Weaponization`, `Containment`.

## Solutions and Recommended Next Actions
1. Threat-intel SQLite lock hardening (high priority)
- Move IOC store to a service-owned DB path with robust locking strategy.
- Consider WAL mode and retry/backoff for schema initialization.
- Avoid import-time write/DDL contention across workers.

2. Calibration for false-negative spam samples (high priority)
- Revisit weighted fusion for cases where content spam signal is high but URL is low.
- Add rule to raise floor for known spam lexical patterns if confidence is high.
- Re-evaluate suspicious boundary (0.4) versus business tolerance.

3. Repetitive score diagnosis improvements (medium priority)
- Add per-agent `analysis_mode` metadata in reports (for example: `no_attachments`, `no_ioc_hits`) so repetitive low scores are explicitly explainable.
- Add corpus-level stratification in future tests:
  - attachment-heavy malware emails
  - IOC-hit-positive phishing emails
  - benign newsletters with many URLs

4. Test harness reliability (medium priority)
- Keep batch method as ingest-all then poll-all (already implemented here) to avoid per-email timeout bias.
- Increase timeout window for large model warmups or queue backlogs.

5. Label quality review (medium priority)
- Confirm ground truth for `live_check_sample.eml` and `IEEE...PAYMENT REMINDER.eml` with manual SOC adjudication.
- Maintain a small gold set with reviewed labels for regression tracking.

## Deliverables Generated
- Detailed audit report: `batch_audit_report.md`
- Full JSON evidence: `batch_audit_results.json`
- This summary with findings + solutions: `audit_findings_and_solutions.md`
