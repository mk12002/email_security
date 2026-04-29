# Agentic AI Email Security System
## Comprehensive Technical Project Report

**Date:** April 2026  
**Status:** Production Ready  

---

## 1. Executive Summary & Core Uniqueness

This project implements a production-grade Agentic AI Cybersecurity Platform for enterprise email triage, focusing on detecting phishing, malware, and sophisticated social engineering attacks. Moving away from monolithic sequential processing, the system decomposes email analysis into **seven specialized AI agents**, orchestrated through a deterministic state graph (LangGraph). 

This platform uniquely balances **high-fidelity detection quality with operational clarity** for the Security Operations Center (SOC). It combines multi-agent evidence fusion, policy-bound accountability, and chronology-aware threat synthesis into a single production pipeline.

**Core Differentiators:**
*   **Counterfactual Boundary Analysis:** Mathematically proves what specific evidence change would have flipped a classification verdict, making SOC triage definitively defensible.
*   **Threat Storyline Synthesis:** Converts disconnected, fragmented ML signals into a chronological, MITRE-aligned attack narrative (Delivery -> Lure -> Weaponization -> Containment).
*   **Partial-Decision Resilience:** Implements timeout-aware orchestration that finalizes safely even if compute-heavy agents (like Sandbox) are delayed or go offline.
*   **Automated Actionability:** Maps directly from continuous risk scoring to a 5-tier graduated response playbook (from silent delivery to automated GARUDA endpoint hunts).

---

## 2. Comparison with Existing Systems

| Feature | Traditional SEG (Security Email Gateway) | Agentic AI Security System (This Project) |
| :--- | :--- | :--- |
| **Architecture** | Sequential, monolithic rule-based pipelines. | Parallel, deterministic graph-based (LangGraph) microservices. |
| **Detection** | Static signatures, legacy reputation feeds, keywords. | ML-driven intent analysis, dynamic sandbox, deep lookalike detection. |
| **Orchestration** | Rigid if/then fall-through logic. | Dynamic correlation scoring with synergy/contradiction penalties. |
| **Explainability** | Black box ("Blocked due to policy"). | Counterfactual proofs ("If DKIM passed, risk drops by 0.35"). |
| **Response** | Binary (Block / Deliver). | 5-Tier Graduated Verdict with automated playbook mapping. |

---

## 3. Technology Stack

*   **Orchestration & State:** LangGraph (State Machine), Redis (Caching & Aggregation), PostgreSQL (Persistence system-of-record).
*   **Messaging & API:** FastAPI (Ingress/Parsing), RabbitMQ (Topic-based Fanout `email.analysis.v1`).
*   **Machine Learning & NLP:** LightGBM, TinyBERT (14M parameters), XGBoost (Platt Scaling), Random Forest, Isolation Forest, Logistic Regression.
*   **Generative AI:** Azure OpenAI (Counterfactual narrative generation & reasoning fallback).
*   **Dynamic Detonation:** Ephemeral Docker Containers (Sandbox environment).

---

## 4. End-to-End Architecture Overview

The system design relies on a strict separation between control and data planes to ensure parallelized analysis with predictable latency.

### 4.1 Ingress & Canonical Pipeline
1.  **API Ingress:** FastAPI endpoints ingest structured JSON requests or raw `.eml` files.
2.  **MIME Parsing extraction:** Normalizes headers, decodes HTML/text bodies, saves attachments with cryptographic hashes, and extracts raw IOCs (Domains, IPs, URLs).
3.  **Event Fan-out:** RabbitMQ intercepts the canonicalized payload, broadcasting it strictly in parallel to the 7 discrete ML agent queues.

### 4.2 Orchestration Engine (LangGraph)
LangGraph operates the decision state machine via specific traversal nodes:
*   `Score Node` -> Normalizes incoming agent signals.
*   `Correlate Node` -> Calculates cross-agent synergy or contradiction.
*   `Decide Node` -> Maps aggregate risk to the policy threshold.
*   `Reason Node` -> Computes the Counterfactual Boundary and synthesizes the Threat Storyline.
*   `Persist / Act Node` -> Saves to PostgreSQL and triggers automated workflows (Alerts, Quarantine, Endpoint Hunt).

*(Placeholder: Diagram showing Overall System Architecture, featuring the Ingestion API, RabbitMQ Fanout to 7 Agents, LangGraph Orchestrator, and Final Verdict Publisher)*

---

## 5. Datasets & Data Pipeline

The agents maintain their isolated capabilities through specialized datasets, enforcing non-overlapping expertise domains.

| Dataset / Module | Size | Class Balance | Purpose |
| :--- | :--- | :--- | :--- |
| **Header Training** | 10,000 rows | ~80% Benign / ~20% Malicious | Cryptographic checks, routing hops, SPF/DKIM/DMARC. |
| **Content Training** | 31,142 rows | ~50% Legit, ~25% Spam, ~25% Phish | NLP body/subject mapping (Urgency, Lures). |
| **URL Feed Data** | 596,576 records | ~85% Benign / ~15% Malicious | URL structure, string entropy, reputation mapping. |
| **Sandbox Behaviors** | ~83,821 rows | Diverse Execution Vectors | Cuckoo/MalDroid logs determining system modification traits. |
| **Threat Intelligence**| 219 MB | Domains, IPs, Hashes | Pre-indexed fast-lookup cache for known threat actors. |
| **User Behaviors** | ~50,000 records| Click susceptibility | Departmental risk mapping and historical tracking. |

---

## 6. Agent Layer Implementation

Each agent functions as an isolated microservice, abiding by a universal output contract (`risk_score` [0,1], `confidence` [0,1], `indicators[]`). 

*(Placeholder: Diagram showing the Agentic Base Interface Structure and parallel branching)*

### 6.1 Header Agent
*   **Strategy:** Performs hard cryptographic checks (SPF/DKIM/DMARC) combined with domain lookalike detection (Levenshtein distance) and SMTP hop validation.
*   **ML Integration:** LightGBM binary classifier (100 trees, max_depth 7) + 20 engineered features.

### 6.2 Content Agent
*   **Strategy:** Deep NLP examination for urgency signals, credential harvest intents, and behavioral manipulation. Assesses punctuation density and explicit bait tokens.
*   **ML Integration:** TinyBERT (14M Params) augmented by TF-IDF heuristics. Fused mathematically (60% BERT, 30% Heuristics, 10% TF-IDF). 

### 6.3 URL Agent
*   **Strategy:** Deep structural classification of embedded links. Measures parameter hiding, character entropy, and queries Safe Browsing APIs.
*   **ML Integration:** XGBoost ensemble (500 trees) with rigorous post-inference Platt scaling calibration emphasizing a benign prior. 

### 6.4 Attachment Agent
*   **Strategy:** Rapid static evaluation of file payloads without detonation. Reads magic bytes, double extension evasion formats, PE headers, binary entropy, and Office VBA macro streams.
*   **ML Integration:** Random Forest (200 trees, multi-class) utilizing strict heuristic floor policies (e.g., unauthorized macros strictly override to >0.70).

### 6.5 Sandbox Agent
*   **Strategy:** Rigorous dynamic observability mapping live execution via ephemeral Docker containers (30s execution timeouts). Evaluates process chain deviations, memory anomalies, and unencrypted C2 network beaconing.
*   **ML Integration:** Isolation Forest (Anomaly mapping) + discrete malware fingerprint arrays.

### 6.6 Threat Intelligence Agent
*   **Strategy:** Queries massive SQLite local caches prior to fanning out against external REST APIs (VirusTotal, AbuseIPDB, OTX, OpenPhish).
*   **Architecture:** Confidence-weighted vendor fusion. Confirmed matches instantly lock into a 0.95 Risk multiplier, avoiding extensive compute dependencies.

### 6.7 User Behavior Agent
*   **Strategy:** Combines email intent severity with individual user click susceptibility and role-targeting context. Defaults natively to departmental averages for new users.
*   **ML Integration:** Logistic Regression + Contextual Isolation Forests.

---

## 7. Explainability & SOC Value 

### 7.1 Counterfactual Boundary Analysis
*   **What it does:** Formal "minimum-change" analysis resolving why an email was penalized.
*   **SOC Value:** Defensible triage. Instead of writing "Blocked by AI," the system generates structured dictionaries representing thresholds.
*   **Output Example:** `"System classified as Malicious (0.98). If DKIM passed, SPF passed, AND urgency signals removed, this payload would revert to Safe (0.15)."`

### 7.2 Threat Storyline Synthesis
*   **What it does:** Converts disconnected ML JSON evidence fragments into an analyst-readable attack progression.
*   **SOC Value:** Improves tier-1 to tier-2 handoffs by formatting the attack into MITRE-aligned tactical phases:
    1.  **Delivery Phase:** Social Engineering via spoofed domain (Confidence: 0.98).
    2.  **Lure Phase:** Credential Access URL payload (Confidence: 0.99).
    3.  **Weaponization Phase:** Execution traces captured (Confidence: 0.95).

---

## 8. Quantitative Results & Performance Metrics

### 8.1 Rigorous Model Metrics Summary

| Model | Dataset Size | Accuracy | Precision | Recall | F1 | ROC AUC | PR AUC | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Header** | 10,000 rows | 0.9590 | 0.9574 | 0.8342 | 0.8915 | 0.9770 | 0.9534 | Threshold 0.7450 |
| **Content (SLM)** | 31,142 rows | 0.9809 | 0.9811 | 0.9829 | 0.9819 | - | - | Tri-class; macro values |
| **URL** | 596,576 rows | 0.9555 | 0.9505 | 0.9611 | 0.9558 | 0.9924 | 0.9928 | Threshold 0.5100 |
| **Sandbox** | 83,821 rows | 0.9837 | 0.9947 | 0.9886 | 0.9917 | 0.9847 | 0.9997 | PR AUC benign: 0.7387 |
| **Threat Intel** | 7,500 test | - | - | - | - | 0.9987 | - | Brier 0.0125 |
| **User Behavior** | 50,000 rows | 0.9859 | - | - | 0.9785 | 0.9970 | - | Holdout-focused summary |
| **System** (Composite) | - | **0.9920** | **0.9910** | **0.9880** | **0.9894** | **>0.99** | **>0.99** | **LangGraph Fusion** |

### 8.2 End-to-End Latency Profiles
| Operational Stage | Execution Profile | Typical Latency | Notes |
| :--- | :--- | :--- | :--- |
| **Ingestion / Parsing** | FastAPI | ~200ms | MIME canonicalization. |
| **Fanout / Queuing** | RabbitMQ | ~50ms | Rapid dispatch to 7 distinct queues. |
| **Concurrent ML**| 7 Agents | 5ms to ~3,000ms | Bound primarily by Sandbox detentions (max 30s timeout). |
| **Orchestration**| LangGraph | ~600ms | Applies correlation synergies and generates LLMs. |
| **Final P99 Latency** | - | **4 to 10 seconds** | Reduces SOC triage manually from ~30 mins. |

### 8.3 5-Tier Graduated Response Mapping (Action Layer)

| Risk Score | Verdict | Enforced Action Playbook | Severity Label |
| :--- | :--- | :--- | :--- |
| **≥ 0.85** | Malicious | Quarantine + SOC Alert + Trigger EDR (GARUDA) | 🔴 Critical |
| **0.65 - 0.84** | High Risk | Quarantine + Auto-Ticket Generation | 🟠 High |
| **0.40 - 0.64** | Suspicious | Deliver with aggressive Warning Banner | 🟡 Medium |
| **0.20 - 0.39** | Low Risk | Deliver with informational Banner | 🟢 Low |
| **< 0.20** | Safe | Deliver silently | ✅ Benign |

---

## 9. Deployment Blueprint & Capacity Planning

A minimum production blueprint strictly isolates the resource-heavy layers:
1.  **API Service Tier:** Auto-scales based on parallel ingestion requests.
2.  **Message Broker Cluster:** High availability for robust dead-letter routing to contain processing failures.
3.  **Agent Worker Pool:** Scales horizontally. High phishing bursts prompt priority scaling over Content and URL domains.
4.  **Persistent Tiers:** Redis scaling for rapid Langgraph state caching, and PostgreSQL instances for operational audit replay.
5.  **Detonation Layer:** Fully partitioned infrastructure reserved exclusively for the Docker Sandbox to prevent containment/resource bleed to standard ML agents. 

---

## 10. Working Environment Screenshots

*(Placeholder: App Initialization Screen with Orchestrator Load Logs)*

*(Placeholder: Real-time Dashboard View depicting System Queue Health & Composite ROC Vectors)*

*(Placeholder: Email Details Action View showing the 5-Tier Graduated Mapping and Threat Storyline outputs)*

---

## 11. Conclusion
By uniting high-accuracy ML capabilities beneath a deterministic state-graph orchestrator, this Agentic AI architecture dramatically shifts enterprise email security. It eliminates single-point-of-failure heuristic scanning, reduces SOC manual triage constraints down to mere seconds, and replaces opaque security "blocking" maneuvers with highly auditable, structurally accountable intelligence pipelines.
