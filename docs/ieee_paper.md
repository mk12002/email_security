# Agentic AI for Enterprise Email Threat Detection: A Multi-Agent, Explainable, and SOC-Operational Architecture

**Author:** [Your Name]  
**Affiliation:** ITC Infotech (Internship Project)  
**Date:** April 2026

## Abstract
Email remains the dominant initial-access vector for credential theft, malware delivery, and social engineering. Traditional monolithic filters frequently underperform against composite campaigns in which each signal appears weak in isolation but malicious in aggregate. This paper presents a production-oriented agentic cybersecurity architecture that decomposes email analysis into seven specialized agents and fuses their outputs via a deterministic state-graph orchestrator. The system supports structured and raw email ingestion, asynchronous queue-based fanout, resilience-aware orchestration, explainable decisioning, and SOC-facing response operations.

The proposed design integrates weighted multi-agent scoring, cross-agent correlation, counterfactual boundary analysis, and narrative reasoning for analyst triage. Evaluation artifacts indicate strong predictive behavior across header, content, URL, sandbox behavior, threat-intelligence, and user-behavior domains, alongside integration and smoke-test evidence validating end-to-end pipeline stability. The architecture provides a practical bridge between machine-learning detection quality and operational trust in Security Operations Center (SOC) workflows.

## Index Terms
Agentic AI, phishing detection, email security, multi-agent systems, cybersecurity orchestration, explainable AI, SOC automation, threat intelligence, sandbox analysis, risk scoring.

## I. Introduction
Enterprise email security is increasingly challenged by adaptive adversaries using domain impersonation, social-engineering language, evasive URL patterns, polymorphic payloads, and user-context targeting. Conventional approaches typically rely on static rules or single-model classification layers. Although effective for high-volume commodity spam, these approaches can under-detect blended attacks that distribute malicious intent across multiple weak indicators.

The key observation motivating this work is that phishing attacks are inherently multi-dimensional. A single suspicious signal is often insufficient for confident action, but cross-domain evidence can produce a decisive risk profile. This project therefore adopts a specialized multi-agent design where each agent analyzes one evidence domain and returns standardized risk semantics for orchestration.

The system was built as a production-oriented internship implementation with explicit goals:

1. Improve detection fidelity for multi-signal attacks.
2. Preserve deterministic and auditable decision pathways.
3. Provide explainable outputs suitable for analyst workflows.
4. Maintain operational resilience under partial system availability.
5. Enable policy-driven response automation and escalation.

## II. Problem Framing and Positioning
This work is positioned at the intersection of three streams:

1. Multi-signal phishing detection.
2. Agentic decomposition of cybersecurity tasks.
3. Explainable SOC decision support.

Unlike single-pass filters, the proposed architecture explicitly separates domain-specialist evidence generation from orchestration-time policy decisions. This decoupling improves transparency, enables per-agent scaling, and allows controlled degradation under partial outages.

## III. System Overview
The architecture follows a layered pipeline:

1. Ingestion and canonicalization.
2. Asynchronous parallel agent analysis.
3. Stateful orchestration and verdict generation.
4. Persistence, response actions, and SOC observability.

### A. High-Level Dataflow
Input emails are parsed into normalized artifacts: header fields, body text, URLs, attachment descriptors, and IOC bundles (domains/IPs/hashes). Events are published to a message bus and consumed by independent agent workers. Agent outputs are aggregated in orchestrator state, scored and correlated, then finalized into policy verdicts with recommendations.

**Figure 1 Placeholder: End-to-End System Architecture**  
[Insert full architecture figure here]

### B. Operational Characteristics
The architecture is designed for practical SOC deployment:

1. Parallelized processing for bounded latency.
2. Durable messaging and dead-letter paths for reliability.
3. Partial-finalization policy for resilience under delayed/missing agents.
4. Real-time telemetry for queue health, intermediate updates, and final outcomes.

## IV. Ingestion, Parsing, and IOC Construction
The ingestion plane supports both structured API payloads and raw email submission. Parsing normalizes multiple formats and extracts evidence needed for downstream analytics.

### A. Canonical Parsing Steps

1. Header extraction: sender identity, routing chain, authentication results.
2. Body extraction: plain and HTML content.
3. URL extraction: direct text links and HTML anchor-derived links.
4. Attachment persistence: metadata plus cryptographic hashing.
5. OCR enrichment: optional URL extraction from image/PDF surfaces.
6. IOC materialization: domains, IPs, and file hashes.

### B. Event Normalization and Traceability
Each email is assigned a unique analysis identifier and transformed into a canonical event schema so that all agents evaluate equivalent context. This enables deterministic joins at orchestration time and consistent report reconstruction.

## V. Agent Layer Design
Seven independent agents analyze domain-specific threat signals. Each emits standardized outputs: `risk_score` (0 to 1), `confidence` (0 to 1), and indicator evidence.

### A. Header Analysis Agent
This agent focuses on identity and transport integrity:

1. SPF, DKIM, DMARC anomaly scoring.
2. Sender-domain lookalike checks.
3. Reply-To vs sender-domain mismatch checks.
4. SMTP trace quality and missing-data semantics.
5. ML-plus-heuristic fusion with anti-dilution safeguards.

**Figure 2 Placeholder: Header Agent Internal Flow**  
[Insert header-agent architecture figure here]

### B. Content Analysis Agent
This agent detects semantic phishing patterns:

1. Urgency/credential/financial linguistic signal families.
2. Click-through and coercive language heuristics.
3. Transformer/SLM inference for semantic class prediction.
4. Fusion policy preserving high-confidence model evidence.

**Figure 3 Placeholder: Content Agent Internal Flow**  
[Insert content-agent architecture figure here]

### C. URL Analysis Agent
This agent combines structural heuristics, optional external enrichment, and ML:

1. URL-length, subdomain, entropy, protocol, and bait-token checks.
2. Brand-impersonation pattern detection.
3. Benign-prior and conflict-aware confidence adjustments.
4. Per-URL inference with calibration before final scoring.

**Figure 4 Placeholder: URL Agent Internal Flow**  
[Insert URL-agent architecture figure here]

### D. Attachment Analysis Agent
This agent performs static malware-oriented screening:

1. Suspicious extension and double-extension detection.
2. Binary entropy checks and suspicious-import signatures.
3. Macro-enabled office artifact detection.
4. Ensemble fusion with heuristic floors.

**Figure 5 Placeholder: Attachment Agent Internal Flow**  
[Insert attachment-agent architecture figure here]

### E. Sandbox Behavior Agent
This agent contributes dynamic behavioral evidence:

1. Local or remote detonation execution path.
2. Hardened runtime constraints.
3. Process, network, filesystem behavior extraction.
4. Critical-chain risk logic.
5. Fallback static behavior when detonation unavailable.

**Figure 6 Placeholder: Sandbox Agent Internal Flow**  
[Insert sandbox-agent architecture figure here]

### F. Threat Intelligence Agent
This agent enriches IOC evidence via local and optional external intelligence:

1. Local IOC store matching with freshness policy checks.
2. Candidate matching across domain/IP/hash channels.
3. Optional external provider enrichment.
4. Multi-source fusion into final intel risk score.

**Figure 7 Placeholder: Threat Intelligence Agent Internal Flow**  
[Insert threat-intel-agent architecture figure here]

### G. User Behavior Agent
This agent estimates susceptibility and user-context risk:

1. Sender familiarity and urgency priors.
2. Role/context feature mapping.
3. ML-dominant click-risk inference.

**Figure 8 Placeholder: User Behavior Agent Internal Flow**  
[Insert user-behavior-agent architecture figure here]

## VI. Orchestration, Decision Policy, and Explainability
A deterministic state-graph orchestrator transforms independent agent outputs into final policy actions.

### A. State-Graph Pipeline
Core stages:

1. Weighted score aggregation.
2. Cross-agent correlation.
3. Verdict and action mapping.
4. Explainability generation.
5. Conditional endpoint investigation trigger.
6. Persistence and dispatch.

**Figure 9 Placeholder: Decision-Orchestration Graph**  
[Insert LangGraph orchestrator figure here]

### B. Scoring Policy
The system applies fixed agent-family weights and deterministic risk bands. Correlation contributes an additive normalization term for cross-signal reinforcement. Verdict classes are policy mapped to:

1. `malicious`
2. `high_risk`
3. `suspicious`
4. `likely_safe`

### C. Partial Finalization
To preserve availability, the orchestrator supports timeout-aware finalization with minimum-evidence constraints when full agent coverage is not available. Reports explicitly encode missing evidence and finalization reason.

### D. Explainability Stack
Explainability has three components:

1. Counterfactual boundary analysis (minimum perturbation to cross below block threshold).
2. LLM-generated or deterministic fallback rationale.
3. Chronological storyline synthesis (delivery to containment).

## VII. Experimental Setup and Evaluation Methodology
Evaluation combines model metrics, runtime snapshots, and integration evidence.

### A. Evaluation Dimensions

1. Predictive quality metrics: accuracy, precision, recall, F1, ROC AUC, PR AUC, calibration (where available).
2. Runtime evidence: direct agent API outputs and scenario-based execution traces.
3. Pipeline stability: integration and smoke tests for orchestrator and agent compatibility.

### B. Reporting Conventions

1. All risk and confidence values are normalized to [0, 1].
2. Missing metrics in artifacts are denoted as `-` in summary tables.
3. Multi-run models are reported with explicit run separation.

## VIII. Results

### A. Model Performance Summary

| Model | Dataset Size | Accuracy | Balanced Accuracy | Precision | Recall | F1 | ROC AUC | PR AUC | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Header | 10,000 rows | 0.9590 | 0.9124 | 0.9574 | 0.8342 | 0.8915 | 0.9770 | 0.9534 | Threshold 0.7450 |
| Content (SLM) | 31,142 samples | 0.9809 | - | 0.9811 | 0.9829 | 0.9819 | - | - | Tri-class macro metrics |
| URL (Run A) | 596,576 rows | 0.9555 | 0.9555 | 0.9505 | 0.9611 | 0.9558 | 0.9924 | 0.9928 | Threshold 0.5100 |
| URL (Run B) | 150,000 rows | 0.9492 | 0.9492 | 0.9390 | 0.9608 | 0.9498 | 0.9903 | 0.9907 | Threshold 0.4650 |
| Sandbox | 83,821 rows | 0.9837 | 0.8742 | 0.9947 | 0.9886 | 0.9917 | 0.9847 | 0.9997 (malicious class) | PR AUC benign class: 0.7387 |
| Threat Intelligence | 7,500 test samples | - | - | - | - | - | 0.9987 | - | Brier score: 0.0125 |
| User Behavior (Run A) | 7,500 test samples | 0.9855 | - | 0.9321 | 1.0000 | 0.9649 | 0.9971 | 0.9846 | Brier score: 0.0508 |
| User Behavior (Run B) | 50,000 rows | 0.9859 | - | - | - | 0.9785 (macro) | 0.9970 | - | Holdout-focused summary |

### B. Runtime and Pipeline Evidence

| Evaluation Surface | Observation |
|---|---|
| Direct API runtime snapshot | URL agent risk/confidence: `0.9989/0.9989`; threat-intel risk/confidence: `0.8421/0.65` |
| Scenario matrix | 7 agent families across positive/negative/neutral patterns; 21 case executions completed |
| Integration tests | 13 tests passed in orchestrator/component smoke paths |
| Sandbox behavior tests | 6 tests passed |
| URL smoke profile | Benign mean risk `0.0012`; malicious mean risk `0.9974` |

### C. Disclosure on Attachment Metrics
Attachment runtime and smoke evidence are included. A full attachment training summary artifact in the same format as all other model families was not available in the collected report set at manuscript preparation time.

## IX. Discussion
The results indicate that the architecture is strong in two practical dimensions:

1. Detection quality across multiple domains.
2. Operational usability through deterministic and explainable workflows.

The combination of independent specialization and orchestration-level fusion is particularly effective for blended campaigns, where no single evidence source is sufficient in isolation.

## X. Limitations and Threats to Validity

1. Some model families are reported across multiple runs with different dataset scales; cross-run comparison should be interpreted cautiously.
2. Attachment reporting artifacts are less uniform than other agents.
3. Sandbox hardening remains a deployment-sensitive boundary and requires strong production isolation practices.
4. Performance in one environment may shift with different threat distributions and SOC policy thresholds.

## XI. Threat Model, Deployment, and Governance Considerations

### A. Threat Model and Assumptions
Operational assumptions for this architecture are:

1. Attackers can craft message content, metadata, links, and attachments.
2. External intel providers may become unavailable or throttled.
3. Orchestration state and control plane are trusted but must be hardened.
4. SOC thresholds are policy variables that require environment-specific tuning.

Current scope excludes protocol-inline MTA blocking guarantees and mailbox-remediation automation beyond response integration hooks.

### B. Deployment Considerations
A practical production topology includes:

1. API ingress and report services.
2. Durable messaging and dead-letter controls.
3. Horizontally scalable agent worker pools.
4. State and telemetry cache tier.
5. Persistent report and audit datastore.
6. Isolated sandbox execution path for dynamic behavior analysis.

### C. SOC KPI Framework
To complement model metrics, operational success should track:

1. Alert precision and false-positive rate by verdict tier.
2. Mean time to triage and containment.
3. Queue backlog and dead-letter rate.
4. Partial-finalization ratio and provider-outage impact.
5. Analyst override and agreement rates.

### D. Governance and Privacy
Given sensitivity of email payloads, production deployments should enforce:

1. Data minimization and retention controls.
2. Encryption at rest and in transit.
3. Role-based access to analyst views and report APIs.
4. Auditability for action dispatch and high-risk verdicting.

## XII. Reproducibility Notes
This manuscript includes a reproducibility appendix listing implementation and evidence artifacts used to derive results. For formal publication, authors should archive:

1. Exact model artifact versions and thresholds.
2. Data-preprocessing manifests.
3. Runtime test commands and environment toggles.
4. Hashes or immutable identifiers for report artifacts.

## XIII. Future Experimental Plan
To strengthen comparability and publication rigor, future evaluation should include the following controlled protocols.

### A. End-to-End Latency and Stability Protocol
Measure full-path latency from ingestion to final report under controlled concurrency.

Experimental factors:

1. Concurrency levels: 1, 5, 10, 25, 50.
2. Feature modes: enrichment off/on, sandbox off/on.
3. Email classes: benign, phishing, attachment-enabled phishing, IOC-heavy campaigns.

Recommended outputs:

1. `p50`, `p95`, `p99` latency.
2. Partial-finalization ratio.
3. Queue backlog and dead-letter frequency.

Template table:

| Scenario | Concurrency | Mode | p50 (ms) | p95 (ms) | p99 (ms) | Partial Finalization (%) | DLQ Count |
|---|---:|---|---:|---:|---:|---:|---:|
| L1 |  |  |  |  |  |  |  |
| L2 |  |  |  |  |  |  |  |
| L3 |  |  |  |  |  |  |  |

### B. Throughput and Capacity Protocol
Evaluate sustainable throughput and identify bottleneck agents.

Procedure:

1. Ramp load in fixed RPS increments.
2. Record accepted/completed rate and queue growth.
3. Identify SLO breakpoints by latency and error thresholds.

Template table:

| Stage | Target RPS | Completed RPS | Avg Queue Depth | p95 Latency (ms) | Error Rate (%) | Bottleneck Agent |
|---|---:|---:|---:|---:|---:|---|
| C1 |  |  |  |  |  |  |
| C2 |  |  |  |  |  |  |
| C3 |  |  |  |  |  |  |

### C. Baseline and Ablation Protocol
Compare the proposed system against simpler alternatives and perform ablations.

Baselines:

1. Content-only classifier.
2. URL-only classifier.
3. Header + content classifier.

Ablations:

1. Remove threat-intel enrichment.
2. Remove sandbox behavior evidence.
3. Remove user-behavior context.

Template table:

| System Variant | Precision | Recall | F1 | ROC AUC | PR AUC | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline-1 |  |  |  |  |  |  |  |
| Baseline-2 |  |  |  |  |  |  |  |
| Ablation-1 |  |  |  |  |  |  |  |
| Proposed Full System |  |  |  |  |  |  |  |

### D. Cost and Resource Efficiency Protocol
Estimate operational cost and resource footprint by mode.

Track:

1. External API calls per email.
2. LLM token usage per email.
3. Sandbox invocation rate and runtime.
4. Compute utilization by service tier.

Template table:

| Mode | Avg External Calls | Avg LLM Tokens | Sandbox Rate (%) | Avg CPU-sec / Email | Estimated Cost / 1K Emails |
|---|---:|---:|---:|---:|---:|
| E1 |  |  |  |  |  |
| E2 |  |  |  |  |  |

### E. Analyst Utility Protocol
Quantify practical value of explainability in SOC workflows.

Design:

1. Analyst A/B study: with vs without explanatory outputs.
2. Measure triage time, decision agreement, and escalation correctness.

Template table:

| Condition | Avg Triage Time (min) | Correct Escalation (%) | Incorrect Escalation (%) | Analyst Confidence (1-5) |
|---|---:|---:|---:|---:|
| Without Explainability |  |  |  |  |
| With Explainability |  |  |  |  |

## XIV. Conclusion
This work demonstrates a detailed, practical, and technically defensible multi-agent architecture for enterprise email threat triage. It integrates heterogeneous evidence domains, deterministic policy decisioning, and explainability mechanisms needed for real SOC operations. The system is suitable as a white-paper contribution and forms a robust foundation for further production hardening and policy calibration.

## Acknowledgment
This work was developed as part of a cybersecurity internship project at ITC Infotech.

## References
[1] Internal architecture and implementation artifacts (orchestration, agents, API, and service-layer components).  
[2] Internal model training and evaluation artifacts across header, content, URL, sandbox, threat intelligence, and user behavior tracks.  
[3] Internal runtime and integration validation artifacts including direct API tests, smoke suites, and system audit outputs.

## Appendix A: Figure Insertion Checklist

1. Figure 1: End-to-End System Architecture.
2. Figure 2: Header Agent Internal Flow.
3. Figure 3: Content Agent Internal Flow.
4. Figure 4: URL Agent Internal Flow.
5. Figure 5: Attachment Agent Internal Flow.
6. Figure 6: Sandbox Agent Internal Flow.
7. Figure 7: Threat Intelligence Agent Internal Flow.
8. Figure 8: User Behavior Agent Internal Flow.
9. Figure 9: Decision-Orchestration Graph.

## Appendix B: Artifact Reference Map (for reproducibility, optional in submission)

### B.1 Core Runtime and Orchestration
1. `email_security/docs/architecture.md`
2. `email_security/api/main.py`
3. `email_security/orchestrator/langgraph_workflow.py`
4. `email_security/orchestrator/runner.py`

### B.2 Model and Training Evidence
1. `email_security/analysis_reports/header_model_train_20260331_095429/training_report.txt`
2. `email_security/analysis_reports/url_model_train_20260403_102155/training_report.txt`
3. `email_security/analysis_reports/sandbox_model_train_20260402_100408/training_summary.json`
4. `email_security/analysis_reports/threat_intel_train_20260403_125703/metrics.json`
5. `email_security/analysis_reports/user_behavior_train_20260403_184055/metrics.json`
6. `models/content_agent/training_report.txt`
7. `models/content_agent/run_logs/metrics_20260325_204808.json`
8. `models/url_agent/run_logs/metrics_20260401_061236.json`
9. `models/user_behavior_agent/model_metrics.json`

### B.3 Runtime and Validation Evidence
1. `api_test_results.txt`
2. `test_results.json`
3. `email_security/analysis_reports/full_system_audit_20260402_104938/audit_report.md`
