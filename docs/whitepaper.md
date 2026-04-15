# Agentic AI Email Security System

## A Production Multi-Agent Architecture for Phishing and Malware Email Triage

## Abstract
This paper presents a production-oriented agentic cybersecurity platform for phishing email analysis. The system decomposes email triage into seven specialized agents and orchestrates their outputs through a deterministic state graph. It supports both structured and raw-email ingestion, asynchronous analysis at scale, explainable decisioning, and SOC-facing operational outputs.

The design objective is to combine high detection quality with operational clarity. To achieve this, the platform integrates weighted multi-agent scoring, cross-agent correlation, counterfactual boundary analysis, and analyst-readable narrative reasoning. Runtime behavior is resilient under partial-agent conditions through timeout-aware finalization and explicit partial-decision metadata.

Empirical evaluation demonstrates strong model performance across header, content, URL, sandbox behavior, threat intelligence, and user behavior domains, with additional runtime and integration evidence from smoke and pipeline tests. This document details architecture, algorithms, metrics, and operational boundaries suitable for white-paper submission.

## 1. Problem Statement and Motivation
Email remains a dominant initial-access vector for credential theft, malware delivery, and social engineering. Modern campaigns typically combine multiple weak signals into a high-confidence attack chain:

1. Header-level sender and routing anomalies.
2. Social-engineering language in subject/body.
3. Malicious or deceptive URL structures.
4. Suspicious attachments with static or behavioral risk.
5. IOC overlap with known threat infrastructure.
6. User-targeting context that increases click likelihood.

Single-pass filtering systems often underperform on such composite attacks. This project addresses that gap through specialized agents and deterministic orchestration.

## 2. Scope and Objectives
The system is designed for enterprise/SOC usage with the following goals:

1. High-quality detection across heterogeneous email artifacts.
2. Parallelized analysis with predictable latency.
3. Explainable, analyst-actionable outcomes.
4. Fault-tolerant behavior under missing or delayed agent results.
5. Production deployment readiness with configurable integrations and controls.

## 3. End-to-End Architecture

### 3.1 Control and Data Planes
The runtime pipeline is organized as:

1. API ingress and normalization.
2. Event fan-out on message bus.
3. Independent agent execution in parallel.
4. Result aggregation and stateful orchestration.
5. Persistence and automated response dispatch.
6. Real-time SOC telemetry and dashboarding.

**Diagram Placeholder**
Insert diagram: Overall System Architecture

### 3.2 Ingestion and API Surfaces
The platform exposes endpoints for:

1. Structured email analysis requests.
2. Raw email ingestion and parsing.
3. Asynchronous report retrieval by `analysis_id`.
4. SOC dashboard and pipeline overview.
5. Isolated direct agent testing for validation/debugging.

### 3.3 Parsing, IOC Extraction, and Canonical Event Construction
Ingestion normalizes headers, body, attachments, and IOC bundles. The parser includes:

1. MIME-aware extraction for plain and HTML content.
2. URL extraction from text and HTML anchors.
3. Attachment persistence with cryptographic hash generation.
4. Optional OCR-based URL extraction from image/PDF content.
5. IOC materialization into domains, IPs, and hashes.

## 4. Agent Layer Design
Each agent returns a standardized payload with `risk_score`, `confidence`, and `indicators`, enabling consistent downstream fusion.

### 4.1 Header Agent
The header agent combines deterministic checks and ML:

1. SPF/DKIM/DMARC anomaly scoring.
2. Domain lookalike detection using edit distance.
3. Reply-To misalignment handling with authentication-aware guardrails.
4. SMTP trace quality checks and missing-data semantics.
5. Heuristic/ML fusion with anti-dilution safeguards.

**Diagram Placeholder**
Insert diagram: Header Agent Architecture

### 4.2 Content Agent
The content agent detects linguistic and semantic phishing cues:

1. Urgency, credential, and financial signal families.
2. Click-through and behavioral-lure heuristics.
3. Transformer/SLM inference with max-preserving fusion.
4. Tri-class semantic output mapped to security routing.

**Diagram Placeholder**
Insert diagram: Content Agent Architecture

### 4.3 URL Agent
The URL agent performs hybrid static + reputation + ML analysis:

1. URL-structure heuristics (length, subdomains, entropy, protocol, bait tokens).
2. Brand impersonation and benign-prior logic.
3. Optional provider enrichments (safe-browsing/reputation feeds).
4. Per-URL inference with conflict-aware confidence control.
5. Post-inference calibration step.

**Diagram Placeholder**
Insert diagram: URL Agent Architecture

### 4.4 Attachment Agent
The attachment agent applies static malware-like scoring:

1. Suspicious extension and double-extension evasion patterns.
2. Binary entropy and suspicious API/import signatures.
3. Macro-enabled office artifact detection.
4. Ensemble-style ML/heuristic fusion with heuristic floors.

**Diagram Placeholder**
Insert diagram: Attachment Agent Architecture

### 4.5 Sandbox Agent
The sandbox agent adds dynamic behavior evidence:

1. Local or remote detonation modes.
2. Hardened detonation runtime constraints.
3. Process/network/filesystem signal extraction.
4. Critical-chain detection and behavior scoring.
5. Runtime observation capture for iterative dataset enrichment.
6. Controlled fallback to static mode on backend unavailability.

**Diagram Placeholder**
Insert diagram: Sandbox Agent Architecture

### 4.6 Threat Intelligence Agent
The threat-intel agent combines local IOC matching and external enrichment:

1. Local IOC store refresh and health policy checks.
2. Candidate matching across domains, IPs, and hashes.
3. Optional external provider enrichment.
4. Risk fusion across ML, local-match, and external evidence channels.

**Diagram Placeholder**
Insert diagram: Threat Intelligence Agent Architecture

### 4.7 User Behavior Agent
The user-behavior agent estimates human click susceptibility:

1. Sender familiarity and urgency prior model.
2. Role/context feature mapping.
3. ML-dominant fusion for click-risk estimation.

**Diagram Placeholder**
Insert diagram: User Behavior Agent Architecture

## 5. Orchestration and Decisioning

### 5.1 State-Graph Workflow
The orchestration graph executes:

1. Score aggregation.
2. Cross-agent correlation.
3. Verdict/action decision.
4. Reason generation.
5. Conditional endpoint-hunt trigger.
6. Persistence.
7. Action dispatch.
8. Final envelope generation.

**Diagram Placeholder**
Insert diagram: Decision Layer (LangGraph Orchestrator)

### 5.2 Scoring Policy
Default weighted contributions are fixed per agent family and mapped to threat bands. Correlation contributes an additive normalized boost. Verdict mapping uses deterministic thresholds for `malicious`, `high_risk`, `suspicious`, and `likely_safe` outcomes.

### 5.3 Partial Finalization and Resilience
The orchestrator supports timeout-based partial finalization when full agent coverage is unavailable, provided minimum evidence criteria are met. Output explicitly records received vs missing agents and partial-finalization reason.

## 6. Explainability and Analyst Readability

### 6.1 Counterfactual Boundary Analysis
For blocking verdicts, the system computes the minimum perturbation required to cross below policy thresholds, producing explicit boundary explanations (`agents_altered`, `new_score`).

### 6.2 LLM Reasoning with Deterministic Fallback
When configured, an LLM generates concise SOC narratives. If unavailable, deterministic fallback reasoning is produced from top contributors and risk decomposition.

### 6.3 Threat Storyline Synthesis
The system constructs chronological storyline phases (delivery, lure, weaponization, containment) with phase severity, confidence, and indicator attribution.

## 7. Action Layer and Integrations

### 7.1 Response Actions
The response layer supports simulated or live action dispatch, including quarantine and alert routing.

### 7.2 Endpoint Investigation Trigger
High-risk outcomes can trigger endpoint hunt workflow integration. Delivery failures are pushed to retry/degraded handling paths.

### 7.3 Messaging Reliability
Message durability and dead-letter routing are used for failed processing containment and replay-oriented operations.

## 8. Data and Training Inputs
Training and evaluation rely on processed datasets for content, URL, header, sandbox behavior, user behavior, and threat-intelligence feature construction. Attachment training combines static malware-oriented feature extraction with ensemble evaluation.

## 9. Quantitative Results

### 9.1 Model Metrics Summary
The following values are normalized to standard reporting dimensions for submission readability.

| Model | Dataset Size | Accuracy | Balanced Accuracy | Precision | Recall | F1 | ROC AUC | PR AUC | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Header | 10,000 rows | 0.9590 | 0.9124 | 0.9574 | 0.8342 | 0.8915 | 0.9770 | 0.9534 | Threshold 0.7450 |
| Content (SLM) | 31,142 samples | 0.9809 | - | 0.9811 | 0.9829 | 0.9819 | - | - | Tri-class; macro values shown |
| URL (Run A) | 596,576 rows | 0.9555 | 0.9555 | 0.9505 | 0.9611 | 0.9558 | 0.9924 | 0.9928 | Threshold 0.5100 |
| URL (Run B) | 150,000 rows | 0.9492 | 0.9492 | 0.9390 | 0.9608 | 0.9498 | 0.9903 | 0.9907 | Threshold 0.4650 |
| Sandbox | 83,821 rows | 0.9837 | 0.8742 | 0.9947 | 0.9886 | 0.9917 | 0.9847 | 0.9997 (malicious) | PR AUC benign: 0.7387 |
| Threat Intelligence | 7,500 test | - | - | - | - | - | 0.9987 | - | Brier 0.0125 |
| User Behavior (Run A) | 7,500 test | 0.9855 | - | 0.9321 | 1.0000 | 0.9649 | 0.9971 | 0.9846 | Brier 0.0508 |
| User Behavior (Run B) | 50,000 rows | 0.9859 | - | - | - | 0.9785 (macro) | 0.9970 | - | Holdout-focused summary |

Legend:

1. `-` indicates metric not explicitly published in the referenced artifact.
2. Content metrics are macro-level tri-class values where applicable.

### 9.2 Runtime and Integration Evidence

| Evaluation Surface | Result Summary |
|---|---|
| Direct API runtime snapshot | URL agent risk/confidence: `0.9989/0.9989`; Threat-intel risk/confidence: `0.8421/0.65` |
| Isolated agent matrix | 7 agent families exercised across positive/negative/neutral patterns; 21 case executions completed |
| Pipeline/component tests | 13 tests passed in orchestrator and key model smoke paths |
| Sandbox behavior tests | 6 tests passed |
| URL smoke profile | Benign mean risk `0.0012`; malicious mean risk `0.9974` |

### 9.3 Attachment Metric Disclosure
A full attachment training summary artifact in the same format as other model families was not available at the time of writing. Runtime and smoke evidence are included, and this limitation is explicitly disclosed for review transparency.

## 10. Security Posture and Operational Risks

### 10.1 Strengths
1. Multi-layer evidence fusion reduces single-signal evasion.
2. Deterministic, auditable decision flow with explainability overlays.
3. Graceful degradation for external provider outages.
4. IOC lifecycle monitoring and refresh controls.
5. SOC-facing observability from queue health to final verdict stream.

### 10.2 Residual Risks
1. Sandbox isolation boundary requires stronger production segregation in hardened deployments.
2. Some authenticated-header edge profiles may require policy recalibration to optimize sensitivity/specificity.
3. Threat-intel modelization is partially mixed with heuristic/local-store pathways and should be further unified.

## 11. Threat Model and Assumptions
This system is designed primarily for enterprise inbound email triage. The following assumptions define current scope:

1. The attacker controls email content and metadata but does not directly compromise the orchestration control plane.
2. Email payloads may include polymorphic links, obfuscated text, malicious attachments, and impersonation artifacts.
3. External enrichment providers may be unavailable or rate-limited; the system must degrade gracefully.
4. SOC policy thresholds are environment-specific and may require calibration based on risk tolerance.
5. Endpoint investigation integrations are treated as best-effort asynchronous actions rather than blocking dependencies.

Out-of-scope assumptions for this version include mailbox takeover remediation workflows, fully inline MTA blocking at protocol time, and adversarial retraining loops against model extraction attempts.

## 12. Operational KPI Framework for SOC Adoption
While this manuscript reports model and pipeline metrics, production operations should also track SOC-level effectiveness indicators. Recommended KPI framework:

1. Detection quality KPIs:
`precision`, `recall`, `false_positive_rate`, `false_negative_rate` by verdict band.
2. Triage efficiency KPIs:
`mean_time_to_triage`, `mean_time_to-containment`, and analyst queue aging.
3. Explainability utility KPIs:
analyst override rate by verdict class and reason-consistency ratings.
4. Reliability KPIs:
queue backlog, dead-letter volume, provider unavailability rate, and partial-finalization frequency.
5. Business impact KPIs:
prevented malicious deliveries, quarantined high-risk emails, and escalation-to-incident conversion rate.

Recommended rollout methodology:

1. Shadow mode against existing email controls.
2. Weekly threshold tuning on disagreement cases.
3. Controlled policy expansion from alert-only to quarantine automation.
4. Post-deployment feedback loop with SOC and incident response teams.

## 13. Deployment Blueprint and Capacity Planning
A minimum production blueprint should include:

1. API service tier for ingestion and report retrieval.
2. Message broker cluster for durable fanout and dead-letter routing.
3. Agent worker pool with independent horizontal scaling by queue depth.
4. Redis tier for orchestration state and real-time publish/subscribe updates.
5. PostgreSQL tier for persistent reports and audit replay.
6. Optional isolated sandbox execution tier and endpoint hunt integration tier.

Capacity planning recommendations:

1. Scale URL/content agents first under high phishing burst conditions.
2. Isolate sandbox workloads due to heavier runtime and resource profiles.
3. Set explicit queue-depth SLOs and autoscale triggers per agent family.
4. Reserve separate budgets for external provider calls and fallback behavior.

## 14. Data Governance, Privacy, and Compliance Considerations
Because this platform processes sensitive communications, governance controls are essential:

1. Minimize retention of full email bodies where policy permits feature-only storage.
2. Encrypt data in transit and at rest across ingestion, cache, and persistence tiers.
3. Apply role-based access controls for SOC dashboards and report retrieval APIs.
4. Maintain immutable audit trails for high-risk verdicts and action dispatch events.
5. Define data deletion and redaction workflows for regulatory obligations.

Human-in-the-loop policy should be retained for irreversible actions in early deployment phases.

## 15. Submission-Quality Terminology and Conventions
To maintain consistency, this paper uses the following normalized terms:

1. `Agent`: independent analysis component producing risk evidence.
2. `Risk Score`: normalized score in `[0,1]`.
3. `Confidence`: model/system confidence in `[0,1]`.
4. `Verdict`: policy output class (`malicious`, `high_risk`, `suspicious`, `likely_safe`).
5. `Orchestration`: deterministic state-graph decision layer.
6. `External Enrichment`: optional provider-based reputation augmentation.

## 16. Diagram Placement Guide
Insert architecture figures at these locations:

1. Section 3: overall architecture.
2. Section 4.1 to 4.7: each agent architecture.
3. Section 5.1: decision-layer orchestration.

## 17. Future Experimental Plan (Fill-Ready)
This section provides concrete benchmarking protocols so the paper can be upgraded from strong engineering evidence to publication-grade comparative evaluation.

### 17.1 End-to-End Latency Benchmark Protocol
Goal: measure realistic pipeline latency under different load levels and feature-toggle profiles.

Test matrix:

1. Load levels: 1, 5, 10, 25, 50 concurrent analysis requests.
2. Modes:
`ML only (external lookups off)`, `ML + external enrichment`, `sandbox enabled`, `sandbox disabled`.
3. Payload classes:
`benign`, `phishing-no-attachment`, `phishing-with-attachment`, `mixed IOC-heavy`.

Record for each run:

1. `p50`, `p95`, `p99` end-to-end latency from API accept to final report.
2. Agent-level execution times.
3. Partial-finalization occurrence rate.
4. Queue backlog and dead-letter counts.

Fill-ready table:

| Scenario ID | Concurrency | Mode | p50 (ms) | p95 (ms) | p99 (ms) | Partial Finalization (%) | DLQ Events | Notes |
|---|---:|---|---:|---:|---:|---:|---:|---|
| S1 |  |  |  |  |  |  |  |  |
| S2 |  |  |  |  |  |  |  |  |
| S3 |  |  |  |  |  |  |  |  |

### 17.2 Throughput and Capacity Protocol
Goal: determine sustainable throughput before SLA degradation.

Procedure:

1. Increase request rate in fixed steps (for example +5 RPS every 5 minutes).
2. Track accepted RPS, completed RPS, and backlog growth.
3. Identify breakpoints where `p95` latency or queue depth exceeds policy SLO.

Fill-ready table:

| Stage | Target RPS | Completed RPS | Avg Queue Depth | p95 Latency (ms) | Error Rate (%) | Bottleneck Agent |
|---|---:|---:|---:|---:|---:|---|
| T1 |  |  |  |  |  |  |
| T2 |  |  |  |  |  |  |
| T3 |  |  |  |  |  |  |

### 17.3 Baseline Comparison Protocol
Goal: compare the multi-agent architecture against a simpler baseline for publication credibility.

Recommended baselines:

1. Header + content only classifier.
2. URL-only reputation/ML classifier.
3. Single-model aggregate classifier using merged feature set.

Comparison metrics:

1. `precision`, `recall`, `F1`, `ROC AUC`, `PR AUC`.
2. False-positive rate on benign business emails.
3. False-negative rate on attachment-enabled phishing.

Fill-ready table:

| System | Precision | Recall | F1 | ROC AUC | PR AUC | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline-1 |  |  |  |  |  |  |  |
| Baseline-2 |  |  |  |  |  |  |  |
| Proposed Multi-Agent |  |  |  |  |  |  |  |

### 17.4 Cost-per-Analysis Protocol
Goal: estimate operational cost envelope and trade-offs.

Capture:

1. External provider call counts per analysis.
2. Average LLM token usage per analysis.
3. Sandbox invocation rate and average runtime.
4. Compute utilization by agent family.

Fill-ready table:

| Mode | Avg External Calls | Avg LLM Tokens | Sandbox Invocation (%) | Avg Compute Time (s) | Estimated Cost / 1K Emails |
|---|---:|---:|---:|---:|---:|
| Cost-Profile A |  |  |  |  |  |
| Cost-Profile B |  |  |  |  |  |

### 17.5 Analyst-Utility Validation Protocol
Goal: quantify whether explainability actually improves SOC operations.

Suggested study:

1. A/B review setup: with explainability vs without explainability.
2. Measure analyst decision time, override accuracy, and confidence rating.
3. Stratify by verdict tier and attack type.

Fill-ready table:

| Cohort | Avg Triage Time (min) | Correct Overrides (%) | False Escalations (%) | Analyst Confidence (1-5) |
|---|---:|---:|---:|---:|
| Without Explainability |  |  |  |  |
| With Explainability |  |  |  |  |

## 18. Conclusion
The system demonstrates a technically credible and practically relevant multi-agent architecture for phishing defense. It combines robust domain specialization, deterministic orchestration, and explainable output generation, while retaining operational controls suitable for SOC workflows.

Based on observed metrics and integration evidence, the platform is mature enough for a strong internship white paper. Remaining work is concentrated in infrastructure hardening and calibration refinement rather than foundational architecture gaps.

## Appendix A: Artifact and Evidence References
This appendix lists implementation and evidence artifacts used to support the claims in this paper.

### A.1 Architecture and Core Runtime
1. `email_security/docs/architecture.md`
2. `email_security/api/main.py`
3. `email_security/services/email_parser.py`
4. `email_security/services/messaging_service.py`
5. `email_security/orchestrator/langgraph_workflow.py`
6. `email_security/orchestrator/runner.py`
7. `email_security/orchestrator/scoring_engine/scorer.py`
8. `email_security/orchestrator/threat_correlation/correlator.py`
9. `email_security/orchestrator/counterfactual_engine.py`
10. `email_security/orchestrator/storyline_engine.py`
11. `email_security/action_layer/response_engine.py`
12. `email_security/garuda_integration/bridge.py`

### A.2 Training and Model Metrics Artifacts
1. `email_security/analysis_reports/header_model_train_20260331_095429/training_report.txt`
2. `email_security/analysis_reports/url_model_train_20260403_102155/training_report.txt`
3. `email_security/analysis_reports/sandbox_model_train_20260402_100408/training_summary.json`
4. `email_security/analysis_reports/threat_intel_train_20260403_125703/metrics.json`
5. `email_security/analysis_reports/user_behavior_train_20260403_184055/metrics.json`
6. `models/content_agent/training_report.txt`
7. `models/content_agent/run_logs/metrics_20260325_204808.json`
8. `models/url_agent/run_logs/metrics_20260401_061236.json`
9. `models/user_behavior_agent/model_metrics.json`

### A.3 Runtime and Validation Artifacts
1. `api_test_results.txt`
2. `test_results.json`
3. `email_security/analysis_reports/full_system_audit_20260402_104938/audit_report.md`
