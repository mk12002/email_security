# Upgradation Plan for the Email Security System on a 30 GB RAM Machine

## Purpose

This document describes how to upgrade the current email security platform now that the deployment machine has **30 GB RAM** instead of the earlier low-memory environment. The system was originally optimized for a constrained host, so several choices were made to reduce RAM usage at the cost of speed, model quality, and throughput.

The goal of this plan is to:

- improve detection quality,
- reduce latency,
- increase throughput,
- improve startup behavior,
- make better use of available memory,
- preserve reliability and fallback behavior,
- keep the system maintainable and measurable.

---

## Executive Summary

The current system is already well-structured for a multi-agent phishing analysis pipeline. The main opportunity is to move from **survival mode** to **performance mode**.

### Highest-value upgrades

1. **Use a stronger content model** for phishing classification.
2. **Increase batch sizes and sequence lengths** during training.
3. **Preload hot models at startup** instead of lazy-loading on first request.
4. **Expand in-memory caching** for threat intelligence, URL reputation, and LLM reasoning.
5. **Increase parallelism** in orchestration and preprocessing.
6. **Strengthen report generation** with richer structured outputs and better cache reuse.
7. **Revisit hard-coded low-RAM limits** in scripts and runtime settings.

### General principle

Anything that was added solely to avoid OOM crashes on a 7.2 GB system should be re-evaluated. With 30 GB RAM, the system should favor:

- more data retained in memory,
- fewer disk round-trips,
- fewer repeated computations,
- larger training batches,
- more concurrent work,
- better model capacity.

---

## Current System Observations

The repository already has several memory-conscious design choices:

- training scripts use chunked CSV ingestion,
- tokenization is bounded aggressively,
- some agent model loaders cache artifacts in memory,
- local benign bootstrap data exists for sandbox preprocessing,
- threat intelligence prefers local lookup before external API fan-out,
- the storyline engine optionally enriches ATT&CK mappings using Azure OpenAI,
- the orchestrator uses LangGraph for deterministic workflow control.

These are good foundations. The upgrade plan is therefore not a rewrite; it is a **resource-aware tuning pass**.

---

## Upgrade Categories

1. **Model training improvements**
2. **Runtime inference improvements**
3. **Orchestrator and worker improvements**
4. **Threat intelligence and caching improvements**
5. **Preprocessing and data pipeline improvements**
6. **LLM reasoning and report quality improvements**
7. **Infrastructure and deployment improvements**
8. **Monitoring, benchmarking, and validation**

---

## 1. Model Training Improvements

### 1.1 Upgrade the phishing content model

The most important quality improvement is in the content classification path.

Current training is centered around a very small model in:

- [email_security/scripts/train_content_model_slm.py](email_security/scripts/train_content_model_slm.py)

That script is explicitly tuned for low-RAM training, including:

- very small model choice,
- strict token limits,
- conservative batch sizes,
- limited multiprocessing,
- chunked data loading.

### Recommended changes

#### A. Move from tiny to stronger model families

Evaluate at least two larger model options:

- a stronger BERT-family small model,
- a distilled transformer with better capacity,
- a compact DeBERTa variant if CPU latency is still acceptable.

Suggested progression:

- Stage 1: `bert-tiny` baseline comparison
- Stage 2: `distilbert-base-uncased` or equivalent
- Stage 3: a carefully chosen mid-sized model if latency is acceptable

#### B. Increase sequence length

If the current max sequence length is very small, increase it carefully.

Recommended approach:

- test 96 → 128 → 192 → 256 tokens,
- choose the smallest value that preserves useful phishing context.

This helps when malicious phrasing is spread across a longer email body.

#### C. Increase batch size and accumulation strategy

With 30 GB RAM, you can usually raise:

- per-device batch size,
- number of training samples per optimization step,
- evaluation batch size.

This improves throughput and can stabilize training.

#### D. Raise per-class sample ceiling

If class imbalance and data quality permit, increase the maximum number of samples per class. More RAM makes it possible to keep larger datasets in the pipeline.

Suggested policy:

- preserve class balance,
- cap by practical training time rather than memory alone,
- prioritize more phishing and legitimate examples over repeated oversampling.

#### E. Use more workers in tokenization

The script currently limits tokenization parallelism. On a 30 GB machine, increase worker count gradually.

Suggested path:

- 2 workers for baseline,
- 4 workers if CPU and I/O permit,
- 6–8 only if profiling shows benefit.

Do not blindly increase if disk becomes the bottleneck.

#### F. Use a better evaluation split and metrics

Expand evaluation beyond macro F1.

Track:

- per-class precision and recall,
- confusion matrix stability,
- false positive rate on legitimate email,
- false negative rate on phishing,
- calibration quality,
- latency per sample.

### 1.2 Improve attachment model training

The attachment pipeline already uses sampled EMBER-derived data and feature selection.

Relevant areas:

- [email_security/scripts/train_attachment_model.py](email_security/scripts/train_attachment_model.py)
- [email_security/preprocessing/convert_ember_jsonl.py](email_security/preprocessing/convert_ember_jsonl.py)

#### Recommended changes

- increase max training sample count if memory allows,
- keep more derived feature matrices in memory during preprocessing,
- profile whether a larger sample cap improves robustness,
- consider feature enrichment where safe and reproducible,
- preserve the current numeric feature subset if it is stable and fast.

### 1.3 Improve URL reputation model training

The URL agent is likely lightweight compared to the content model, but it can still benefit from richer training data and additional calibration.

Potential improvements:

- train on a larger URL corpus,
- keep a stronger balance between benign and malicious examples,
- tune the decision threshold against validation data,
- keep the allowlist and brand-token heuristics as a safety layer.

### 1.4 Improve sandbox behavior model training

The sandbox preprocessing system already supports local benign bootstrap data.

Relevant areas:

- [email_security/preprocessing/sandbox_preprocessing.py](email_security/preprocessing/sandbox_preprocessing.py)
- [email_security/agents/sandbox_agent/model_loader.py](email_security/agents/sandbox_agent/model_loader.py)

#### Recommended changes

- increase the amount of benign bootstrap data kept in memory during preprocessing,
- retain more API sequence samples if they improve coverage,
- expand the sample size for behavioral clustering and sequence statistics,
- profile the effect of larger in-memory feature construction on training quality.

---

## 2. Runtime Inference Improvements

### 2.1 Preload models at startup

At present, several agent loaders lazily load models:

- [email_security/agents/header_agent/model_loader.py](email_security/agents/header_agent/model_loader.py)
- [email_security/agents/content_agent/model_loader.py](email_security/agents/content_agent/model_loader.py)
- [email_security/agents/url_agent/model_loader.py](email_security/agents/url_agent/model_loader.py)
- [email_security/agents/attachment_agent/model_loader.py](email_security/agents/attachment_agent/model_loader.py)
- [email_security/agents/sandbox_agent/model_loader.py](email_security/agents/sandbox_agent/model_loader.py)
- [email_security/agents/threat_intel_agent/model_loader.py](email_security/agents/threat_intel_agent/model_loader.py)
- [email_security/agents/user_behavior_agent/model_loader.py](email_security/agents/user_behavior_agent/model_loader.py)

#### Recommended change

Create a startup warmup phase that loads the most-used models into memory before the first request.

Benefits:

- lower first-request latency,
- fewer cold-start spikes,
- more predictable service behavior.

Suggested priority order:

1. header agent
2. content agent
3. URL agent
4. attachment agent
5. sandbox agent
6. threat-intel agent
7. user-behavior agent

### 2.2 Keep hot runtime artifacts in memory

Memory can now be used to cache:

- model bundles,
- vectorizers,
- tokenizers,
- feature schemas,
- threat-intel IOC sets,
- allowlists,
- common parse outputs,
- repetitive reasoning prompts.

### 2.3 Add request-level deduplication

For repeated analysis of the same or very similar email content, add deduplication keys based on:

- normalized headers,
- body hash,
- URL set hash,
- attachment fingerprints.

This avoids recomputing identical analyses.

### 2.4 Improve model output reuse

Cache agent outputs for repeated indicators where safe.

Example targets:

- same URL reputation result,
- same IOC lookup result,
- same attachment static analysis result,
- same spam/phishing textual features.

---

## 3. Orchestrator and Worker Improvements

The orchestrator uses LangGraph and structured state transitions. That is a good base for scaling.

Relevant areas:

- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)
- [email_security/orchestrator/runner.py](email_security/orchestrator/runner.py)
- [email_security/orchestrator/llm_reasoner.py](email_security/orchestrator/llm_reasoner.py)
- [email_security/orchestrator/storyline_engine.py](email_security/orchestrator/storyline_engine.py)

### 3.1 Increase concurrency

More RAM allows more concurrent worker activity, especially if CPU is also stronger.

Possible upgrades:

- increase number of orchestration workers,
- raise queue consumer concurrency,
- allow more simultaneous email analyses,
- increase async task limits where safe.

### 3.2 Use staged warmup

Start the most essential components first, then warm up secondary components.

Suggested warmup order:

1. settings and config loading
2. model loaders
3. threat-intel local store
4. URL reputation caches
5. content model tokenizer and model
6. sandbox behavior artifacts
7. LLM reasoning client

### 3.3 Improve backpressure handling

With more throughput, the system should also manage overload better.

Add or improve:

- queue length monitoring,
- timeout handling,
- retry discipline,
- bounded worker pools,
- graceful degradation to heuristic mode.

### 3.4 Improve structured outputs

The orchestrator should continue to produce:

- normalized score summaries,
- counterfactual reasoning,
- attack storyline output,
- action dispatch details,
- report persistence metadata.

Expand these outputs with:

- confidence intervals,
- dominant evidence paths,
- top contributing indicators,
- agent disagreement summaries,
- per-phase severity tags.

---

## 4. Threat Intelligence and Caching Improvements

Threat intelligence is often the biggest runtime cost after the main model inference pipeline.

### 4.1 Expand local IOC cache usage

The docs already indicate local SQLite cache preference for IOCs.

With more RAM:

- keep more IOC indexes warm,
- preload frequent hash and domain lookups,
- reduce unnecessary vendor API calls,
- retain more recent indicators in memory.

### 4.2 Add cache expiry policies

Use cache tiers:

- short-lived cache for repeated request burst,
- medium-lived cache for common domain verdicts,
- longer-lived cache for known-bad indicators,
- negative cache for verified clean lookups.

### 4.3 Normalize and deduplicate indicators before lookup

Precompute canonical forms of:

- domains,
- URLs,
- IPs,
- file hashes,
- sender addresses.

This reduces repeated work and improves cache hit rate.

### 4.4 Improve fail-open / fail-safe behavior

If external lookups fail:

- retain local verdicts,
- annotate the uncertainty explicitly,
- do not block the whole pipeline,
- log degraded-mode operation.

---

## 5. Preprocessing and Data Pipeline Improvements

### 5.1 Increase chunk sizes where safe

Several scripts read large files in chunks. With more RAM, chunk sizes can be raised to reduce overhead.

Targets:

- CSV loading,
- Arrow conversion,
- feature extraction,
- benign bootstrap generation,
- sandbox sequence loading.

### 5.2 Keep intermediate features longer

Instead of writing every intermediate result immediately to disk, hold more derived features in memory and flush in larger batches.

This is especially useful for:

- attachment feature matrices,
- content tokenized datasets,
- threat-intel enrichment tables,
- sandbox sequence features.

### 5.3 Precompute reusable datasets

Move expensive transformations to offline preprocessing:

- cleaned text corpus,
- tokenized datasets,
- URL feature tables,
- normalized attachment metadata,
- threat-intel join tables.

### 5.4 Improve data fingerprinting and reuse

Use fingerprints to decide when a dataset or feature table needs rebuilding.

This avoids unnecessary retraining and data conversion.

---

## 6. LLM Reasoning and Report Quality Improvements

### 6.1 Strengthen explanation generation

The reasoning layer in [email_security/orchestrator/llm_reasoner.py](email_security/orchestrator/llm_reasoner.py) currently uses Azure OpenAI when available and falls back to deterministic text when not.

With more resources, improve this layer by:

- caching repeated prompts,
- generating richer analyst summaries,
- adding structured rationale sections,
- standardizing the wording of verdict explanations.

### 6.2 Improve counterfactual explanations

The system already supports counterfactual reasoning.

Upgrade the output to include:

- what evidence was decisive,
- which agents dominated the score,
- how the verdict would change if one or more agents were neutralized,
- how close the email was to the decision boundary.

### 6.3 Expand storyline generation

The storyline engine already supports ATT&CK-like mappings and optional LLM-based enrichment.

Relevant area:

- [email_security/orchestrator/storyline_engine.py](email_security/orchestrator/storyline_engine.py)

#### Recommended changes

- keep deterministic mapping as default,
- increase the number of indicators considered per phase,
- cache storyline templates,
- enrich the final Markdown report with clearer sequence labels,
- include a compact summary and a detailed section.

### 6.4 Produce richer analyst-facing reports

Reports should include:

- final verdict,
- normalized score,
- confidence,
- top indicators,
- counterfactual explanation,
- story of attack progression,
- evidence from each agent,
- recommended response action.

---

## 7. Infrastructure and Deployment Improvements

### 7.1 Move from memory-constrained defaults to performance defaults

Review configuration values that were introduced only to keep the system alive on small RAM.

Examples of values to revisit:

- token limits,
- batch sizes,
- worker counts,
- queue depth,
- cache sizes,
- request timeouts,
- sample caps.

### 7.2 Separate runtime tiers

Use different runtime profiles:

- **Development profile**: smaller, faster iteration, lower memory usage,
- **Production profile**: higher concurrency, larger caches, larger batch sizes,
- **Training profile**: maximum practical throughput and sample retention.

### 7.3 Consider container memory limits explicitly

If running under Docker:

- ensure container memory limits do not negate the 30 GB host benefit,
- review compose resource constraints,
- align worker counts with container allocations.

### 7.4 Reassess sandbox isolation

The repo notes that sandbox detonation still depends on Docker socket mount, which remains a host-risk.

With more resources available, the better long-term direction is:

- move sandbox execution to a separate host or VM,
- minimize privileged access to the main application runtime,
- keep detonation isolation stronger than the orchestration plane.

This is a security improvement, not just a performance one.

---

## 8. Monitoring, Benchmarking, and Validation

A bigger machine only helps if gains are measured.

### 8.1 Add baseline benchmarks before and after changes

Measure:

- API latency,
- throughput,
- model warmup time,
- tokenization time,
- threat-intel lookup time,
- memory peak usage,
- CPU utilization,
- disk I/O pressure.

### 8.2 Track quality metrics

For each agent and the overall system, track:

- precision,
- recall,
- F1,
- false positive rate,
- false negative rate,
- calibration,
- verdict stability.

### 8.3 Use load testing

Introduce load tests that simulate:

- one-off email analysis,
- burst traffic,
- repeated identical emails,
- worst-case attachment-heavy emails,
- long email bodies,
- URL-heavy messages.

### 8.4 Add memory regression checks

Because the machine has more RAM, there is a risk of bloat.

Add checks for:

- startup memory footprint,
- per-request memory delta,
- cache growth over time,
- model count loaded into memory,
- stale cache eviction effectiveness.

---

## 9. Suggested File-Level Upgrade Targets

Below is a practical map of likely files to revisit.

### Training and preprocessing

- [email_security/scripts/train_content_model_slm.py](email_security/scripts/train_content_model_slm.py)
- [email_security/scripts/train_attachment_model.py](email_security/scripts/train_attachment_model.py)
- [email_security/preprocessing/convert_ember_jsonl.py](email_security/preprocessing/convert_ember_jsonl.py)
- [email_security/preprocessing/sandbox_preprocessing.py](email_security/preprocessing/sandbox_preprocessing.py)

### Runtime model loading

- [email_security/agents/header_agent/model_loader.py](email_security/agents/header_agent/model_loader.py)
- [email_security/agents/content_agent/model_loader.py](email_security/agents/content_agent/model_loader.py)
- [email_security/agents/url_agent/model_loader.py](email_security/agents/url_agent/model_loader.py)
- [email_security/agents/attachment_agent/model_loader.py](email_security/agents/attachment_agent/model_loader.py)
- [email_security/agents/sandbox_agent/model_loader.py](email_security/agents/sandbox_agent/model_loader.py)
- [email_security/agents/threat_intel_agent/model_loader.py](email_security/agents/threat_intel_agent/model_loader.py)
- [email_security/agents/user_behavior_agent/model_loader.py](email_security/agents/user_behavior_agent/model_loader.py)

### Orchestration and reasoning

- [email_security/orchestrator/llm_reasoner.py](email_security/orchestrator/llm_reasoner.py)
- [email_security/orchestrator/storyline_engine.py](email_security/orchestrator/storyline_engine.py)
- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)
- [email_security/orchestrator/runner.py](email_security/orchestrator/runner.py)

### Benchmarking and validation

- [email_security/scripts/run_system_benchmark.py](email_security/scripts/run_system_benchmark.py)
- [email_security/tests/](email_security/tests/)

---

## 10. Recommended Implementation Phases

### Phase 1: Quick wins

Duration: 1 to 2 days

- raise tokenization and batch limits carefully,
- preload the most-used models,
- increase cache sizes for hot lookups,
- add startup warmup timing logs,
- benchmark baseline performance.

### Phase 2: Model quality upgrades

Duration: 2 to 5 days

- train and compare stronger content models,
- tune URL thresholds,
- re-evaluate attachment and sandbox sample caps,
- compare false positive and false negative rates.

### Phase 3: Runtime scaling

Duration: 2 to 4 days

- increase concurrency,
- improve request deduplication,
- expand threat-intel local cache usage,
- refine backpressure and worker pool behavior.

### Phase 4: Report and reasoning improvements

Duration: 1 to 3 days

- improve explanation caching,
- enrich storyline reports,
- standardize counterfactual narratives,
- produce richer analyst-facing summaries.

### Phase 5: Hardening and observability

Duration: ongoing

- add memory regression tests,
- add throughput dashboards,
- monitor latency and cache hit rate,
- keep sandbox isolation under review.

---

## 11. Risk Management

### Risk: Overusing RAM and causing swap pressure

Mitigation:

- increase limits incrementally,
- profile peak usage,
- keep eviction policies for caches,
- do not preload unnecessary models.

### Risk: Larger models increase latency

Mitigation:

- benchmark before switching fully,
- keep a smaller fallback model,
- add latency thresholds,
- expose model choice via config.

### Risk: More concurrency causes contention

Mitigation:

- profile CPU and I/O,
- use bounded worker pools,
- avoid too many parallel tokenization jobs,
- keep queue backpressure active.

### Risk: More caching causes stale decisions

Mitigation:

- use TTL-based caches,
- invalidate on model updates,
- version cache keys,
- log cache hit/miss behavior.

---

## 12. Success Criteria

The upgrade is successful if the system achieves most of the following:

- lower first-request latency,
- lower average request latency,
- improved phishing detection quality,
- better analyst-readable explanations,
- fewer repeated external lookups,
- higher training throughput,
- no new memory regressions,
- stable behavior under burst load,
- better use of the 30 GB host without swapping.

---

## 13. Action Layer Upgradation Plan

The action layer is the point where analysis becomes remediation. It is the bridge between a high-confidence verdict and a concrete response such as quarantine, banner injection, alerting, or safe delivery.

At the moment, the action layer is still relatively thin and simulated. The upgrade goal is to turn it into a policy-driven remediation engine that can execute deterministic actions with auditability, role-aware controls, and clear fallback behavior.

### 13.1 Objectives

The upgraded action layer should:

- convert verdicts into the correct operational response,
- distinguish between simulated and live execution modes,
- resolve mail identity before attempting remediation,
- support Microsoft Graph-based message actions,
- preserve analyst audit logs and action traces,
- avoid acting on ambiguous or incomplete message identity,
- degrade safely when Graph access or permissions are missing.

### 13.2 Administrative unlock checklist

Before real remediation can work, the Azure application must be fully enabled.

#### A. Create and store the client secret

Create a new client secret for the app registration and store the secret value in the environment file on the VM.

Recommended `.env` entries:

```env
GRAPH_TENANT_ID=your-tenant-id
GRAPH_CLIENT_ID=your-client-id
GRAPH_CLIENT_SECRET=your-client-secret-value
GRAPH_AUTHORITY=https://login.microsoftonline.com/your-tenant-id
GRAPH_SCOPES=https://graph.microsoft.com/.default
```

Important rules:

- never store the secret ID in `.env`,
- only store the secret value,
- rotate secrets on a schedule,
- restrict file access on the host,
- keep the secret out of version control.

#### B. Request admin consent

The application needs tenant-level consent for the Graph permissions used by the action layer.

Recommended permission set for the first version:

- `Mail.ReadWrite`
- `User.Read.All` if mailbox resolution needs directory lookups
- `offline_access` only if the design later requires delegated refresh, otherwise avoid it for app-only flow

For a future Defender branch, additional security permissions may be required, but the first production path should use Graph mailbox operations because it is usually simpler to obtain and easier to validate.

#### C. Verify Graph access in a controlled test tenant

Confirm the app can:

- acquire a token,
- query message IDs,
- move a message,
- patch message body if bannering is enabled,
- log failures cleanly when denied.

### 13.3 Recommended remediation model

Use a tiered action policy rather than a single hard-coded action.

| Composite risk score | Verdict path | Recommended action | Graph method |
|---|---|---|---|
| $\ge 0.85$ | Critical malicious | Quarantine immediately | `quarantine_email()` |
| $0.40$ to $0.84$ | High / suspicious | Apply warning banner, optionally quarantine on admin policy | `apply_warning_banner()` |
| $< 0.20$ | Safe | Deliver normally | No action |

This policy can later be expanded to include:

- sender blocking,
- SOC alerting,
- user notification,
- conditional escalation for repeat offenders,
- optional Defender investigation integration where licensed.

### 13.4 File-by-file implementation plan

#### A. Orchestrator state extension

Path: [email_security/orchestrator/langgraph_state.py](email_security/orchestrator/langgraph_state.py)

Add mailbox and Graph identity fields to the shared state so the action layer can operate on a real message rather than only on analysis metadata.

Suggested fields:

- `user_principal_name`
- `internet_message_id`
- `graph_message_id`
- `mailbox_provider`
- `action_context`
- `graph_action_status`

Example state extension:

```python
class OrchestratorState(TypedDict, total=False):
	# Inputs
	analysis_id: str
	agent_results: list[dict[str, Any]]
	user_principal_name: str
	internet_message_id: str
	graph_message_id: str
	mailbox_provider: str
	action_context: dict[str, Any]

	# Existing derived and decision fields...
```

#### B. Message identity resolution in parsing

Path: [email_security/services/email_parser.py](email_security/services/email_parser.py)

The parser already extracts `message_id` from standard headers and MSG content. Extend the payload so the action layer gets the most useful identity fields up front.

Suggested parser output additions:

- raw `Message-ID`
- `X-MS-Exchange-Organization-Network-Message-Id` when present,
- any mailbox routing metadata if available,
- `user_principal_name` if the source system already knows the mailbox owner,
- `internet_message_id` normalized for Graph lookup.

Example payload enrichment:

```python
headers = {
	"from": sender_raw,
	"sender": sender_addr[0][1] if sender_addr else "",
	"reply_to": raw_headers.get("Reply-To"),
	"to": [entry[1] for entry in recipient_addrs if entry[1]],
	"subject": subject,
	"message_id": message_id or raw_headers.get("Message-ID"),
	"network_message_id": raw_headers.get("X-MS-Exchange-Organization-Network-Message-Id"),
	"received": received,
	"authentication_results": auth_results,
	"raw": raw_headers,
}
```

#### C. Add a dedicated Graph client

Path to add: [email_security/action_layer/graph_client.py](email_security/action_layer/graph_client.py)

This module should own authentication and Microsoft Graph calls. Keep it separate from the response engine so the action layer stays testable and the Graph logic remains reusable.

Recommended responsibilities:

- obtain an app-only access token,
- resolve `internetMessageId` to a Graph message resource ID,
- move a message to Junk for quarantine-style response,
- prepend or update a banner for medium-risk emails,
- optionally add metadata tags or audit annotations,
- return structured result objects instead of only booleans.

Suggested class design:

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import msal

from email_security.configs.settings import settings


@dataclass
class GraphActionResult:
	ok: bool
	action: str
	status_code: int | None = None
	graph_message_id: str | None = None
	detail: str | None = None


class GraphActionBot:
	def __init__(self) -> None:
		self.tenant_id = settings.graph_tenant_id
		self.client_id = settings.graph_client_id
		self.client_secret = settings.graph_client_secret
		self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
		self.scopes = ["https://graph.microsoft.com/.default"]
		self.app = msal.ConfidentialClientApplication(
			self.client_id,
			authority=self.authority,
			client_credential=self.client_secret,
		)

	def _get_token(self) -> str | None:
		result = self.app.acquire_token_for_client(scopes=self.scopes)
		return result.get("access_token")

	def resolve_message_id(self, user_principal_name: str, internet_message_id: str) -> str | None:
		...

	def quarantine_email(self, user_principal_name: str, graph_message_id: str) -> GraphActionResult:
		...

	def apply_warning_banner(self, user_principal_name: str, graph_message_id: str, severity: str = "Medium") -> GraphActionResult:
		...
```

#### D. Replace simulated dispatch with real action routing

Path: [email_security/action_layer/response_engine.py](email_security/action_layer/response_engine.py)

The response engine currently prints simulated actions and uses placeholder HTTP hooks. Replace that with a small policy router that delegates to `GraphActionBot`.

Recommended change pattern:

```python
from email_security.action_layer.graph_client import GraphActionBot


class ResponseEngine:
	def __init__(self):
		self.graph = GraphActionBot()
		self.simulated_mode = bool(settings.action_simulated_mode)

	def execute_actions(self, decision: dict[str, Any]) -> None:
		actions = decision.get("recommended_actions", [])
		upn = decision.get("user_principal_name")
		internet_message_id = decision.get("internet_message_id")
		graph_message_id = decision.get("graph_message_id")

		if not upn or not internet_message_id:
			logger.warning("Action layer skipped due to missing mailbox identity", analysis_id=decision.get("analysis_id"))
			return

		if not graph_message_id:
			graph_message_id = self.graph.resolve_message_id(upn, internet_message_id)

		if "quarantine" in actions and graph_message_id:
			self.graph.quarantine_email(upn, graph_message_id)
		elif "deliver_with_banner" in actions and graph_message_id:
			severity = "High" if decision.get("overall_risk_score", 0.0) >= 0.6 else "Medium"
			self.graph.apply_warning_banner(upn, graph_message_id, severity=severity)
```

#### E. Pass action fields through LangGraph

Path: [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)

The act node should consume a decision that includes mailbox identity and Graph IDs, not just score and verdict.

Recommended additions:

- preserve `user_principal_name` in the assembled decision,
- preserve `internet_message_id` in the assembled decision,
- preserve `graph_message_id` once resolved,
- add `action_status` to the state,
- log action outcomes separately from analysis outcomes.

Suggested decision assembly extension:

```python
decision = {
	"analysis_id": state.get("analysis_id"),
	"overall_risk_score": float(state.get("overall_risk_score", 0.0)),
	"verdict": state.get("verdict", "unknown"),
	"recommended_actions": state.get("recommended_actions", []),
	"user_principal_name": state.get("user_principal_name"),
	"internet_message_id": state.get("internet_message_id"),
	"graph_message_id": state.get("graph_message_id"),
	"action_context": state.get("action_context", {}),
}
```

#### F. Settings and environment wiring

Path: [email_security/configs/settings.py](email_security/configs/settings.py)

Add explicit configuration fields so the action layer does not rely on hard-coded values.

Recommended fields:

- `graph_tenant_id`
- `graph_client_id`
- `graph_client_secret`
- `graph_scopes`
- `action_simulated_mode`
- `action_banner_enabled`
- `action_quarantine_enabled`

Example `.env` policy:

```env
ACTION_SIMULATED_MODE=1
ACTION_BANNER_ENABLED=1
ACTION_QUARANTINE_ENABLED=1
GRAPH_TENANT_ID=...
GRAPH_CLIENT_ID=...
GRAPH_CLIENT_SECRET=...
```

### 13.5 Recommended runtime flow

The action flow should be explicit and auditable:

1. Parse the email and capture the mailbox identity.
2. Normalize `internet_message_id`.
3. Resolve the Graph resource ID.
4. Run the 7-agent analysis pipeline.
5. Generate the orchestrator decision.
6. Select the remediation policy.
7. Execute the action through `GraphActionBot`.
8. Save the final result with the action status.

This flow keeps the system post-delivery and surgical, rather than trying to block mail before it reaches the mailbox.

### 13.6 Practical action mapping

Use a simple policy table at first, then refine later.

| Verdict | Risk band | Action path | Rationale |
|---|---|---|---|
| malicious | very high | quarantine | strongest remediation, removes from inbox view |
| high_risk | high | quarantine or banner | depends on operator policy and confidence |
| suspicious | medium | banner + alert | warn user and SOC, preserve message for review |
| likely_safe | low | deliver with no action or banner | only warn if policy requires it |
| safe | very low | deliver | no remediation needed |

### 13.7 Suggested validation steps

Test the action layer in this order:

1. unit test token acquisition with mock MSAL,
2. unit test message resolution with mocked Graph responses,
3. unit test quarantine and banner methods,
4. run the orchestrator in simulated mode,
5. verify `action_status` in the final decision envelope,
6. validate real Graph calls in a test tenant,
7. confirm mailbox changes are auditable and reversible where possible.

### 13.8 Security and operational cautions

- prefer app-only auth with least privilege,
- do not reuse the same secret across unrelated projects,
- rotate client secrets regularly,
- keep a simulated mode switch for safe testing,
- keep all Graph failures non-fatal to the analysis path,
- never act without a resolved mailbox identity.

---

## 14. Optional High-Value and Interesting Upgrades

If you want the system to feel more advanced, more intelligent, and more impressive to users or reviewers, these are the most interesting upgrades to consider next.

### 14.1 Adaptive policy engine

Instead of using fixed thresholds only, add a policy engine that learns from operational outcomes.

What it can do:

- raise quarantine sensitivity for repeat malicious sender patterns,
- lower false-positive rates for trusted business workflows,
- apply different policies for executives, finance, HR, or general users,
- change response intensity based on message source, time, and confidence.

Why it is interesting:

- it makes the system feel context-aware,
- it shows real SOC-style decisioning,
- it is more realistic than a single static threshold table.

### 14.2 Analyst feedback loop

Add a mechanism for analysts to mark actions as correct, too aggressive, or too weak.

Use that feedback to:

- tune scoring weights,
- update remediation rules,
- improve counterfactual explanations,
- refine banner/quarantine thresholds,
- reduce recurring false positives.

This creates a closed-loop security system rather than a one-way classifier.

### 14.3 Visual incident timeline

Generate a compact visual timeline for each email.

Possible elements:

- delivery event,
- sender anomaly,
- URL suspicion,
- attachment suspicion,
- sandbox signal,
- threat-intel match,
- final action.

This can be shown in the UI or included in the report as a structured sequence diagram.

### 14.4 Better explanation UX

Make the final explanation easier for humans to read.

Possible upgrades:

- executive summary at the top,
- evidence bullets sorted by importance,
- short plain-English conclusion,
- expandable technical appendix,
- severity badges for each agent.

This is especially useful if non-technical users will read the report.

### 14.5 Trust and reputation memory

Maintain a local reputation layer for:

- known-safe senders,
- recurring business domains,
- repeated campaign infrastructure,
- previously blocked malicious identities,
- historical user interaction patterns.

This makes the system smarter over time and improves both speed and precision.

### 14.6 Threat campaign clustering

Cluster similar attacks into campaigns rather than treating every email as isolated.

Examples:

- same sender infrastructure,
- same URL templates,
- same attachment hashes,
- same lure wording,
- same delivery timing.

Benefits:

- better threat hunting,
- easier analyst triage,
- faster identification of campaign waves,
- improved storyline quality.

### 14.7 Richer action outcomes

Instead of only quarantine or banner, you can build additional action types.

Examples:

- tag message with a classification label,
- notify the recipient with a safe explanation,
- notify the SOC channel,
- create an incident ticket,
- block sender or domain locally,
- add the indicator to a watchlist,
- trigger follow-up monitoring for the mailbox.

This gives the system a more complete defense-in-depth feel.

### 14.8 Progressive risk scoring

Make the score evolve in stages as more evidence arrives.

For example:

1. headers contribute an initial risk,
2. content and URLs refine it,
3. attachments and sandbox behavior adjust it,
4. threat-intel lookups finalize it,
5. the action layer maps it to remediation.

This is interesting because it mirrors how a real SOC analyst reasons.

### 14.9 Interactive dashboard

Add a small dashboard for live review.

Useful panels:

- recent verdicts,
- top malicious senders,
- open alerts,
- agent confidence breakdown,
- quarantine actions taken,
- false positive review queue,
- performance graphs.

This makes the project feel like a real security product rather than a script collection.

### 14.10 Model comparison mode

Allow the system to compare two models side by side.

For example:

- current model vs upgraded model,
- heuristic mode vs ML mode,
- local fallback vs LLM-enhanced reasoning.

Show:

- score difference,
- prediction difference,
- explanation difference,
- latency difference.

This is excellent for benchmarking and presentations.

### 14.11 Human-in-the-loop review queue

For borderline cases, send the email to a review queue instead of acting immediately.

That queue can store:

- verdict,
- score,
- evidence summary,
- reason for review,
- analyst resolution.

This makes the system safer and more professional.

### 14.12 Multi-tenant and role-aware behavior

If you plan to expand the project, the system can support different policies per department or tenant.

Examples:

- finance gets stricter quarantine rules,
- executives get faster alert escalation,
- developers get more permissive banner-based handling,
- HR gets stronger privacy-aware reporting.

This makes the platform much more realistic for enterprise deployment.

### 14.13 Smarter sandbox stories

Make sandbox output more narrative and dynamic.

Instead of only showing raw process signals, summarize:

- what the attachment tried to do,
- what resources it touched,
- whether it attempted network activity,
- whether it showed evasive behavior,
- how it contributed to the final verdict.

This improves both detection quality and report readability.

### 14.14 Campaign replay mode

Add a replay function that re-runs past incidents through the latest system.

Use it to:

- compare old and new scoring logic,
- test new action policies,
- validate rule changes,
- measure improvements over time.

This is useful for regression testing and demos.

### 14.15 Synthetic attack generator

Generate controlled phishing samples for testing.

Possible use cases:

- training augmentation,
- benchmark generation,
- attack simulation,
- UI demonstrations,
- policy stress tests.

This can make the system much easier to evaluate without relying only on external data.

---

## 15. Comprehensive Ranked Roadmap for Everything

This section turns the full upgrade plan into an execution order. It groups all improvements into practical phases so the work can be done without destabilizing the system.

### 15.1 Phase A: Foundation and safety first

Priority: highest

Goal: make the system safer, measurable, and ready for live use before increasing complexity.

#### A1. Add action-layer configuration and identity fields

Files:

- [email_security/configs/settings.py](email_security/configs/settings.py)
- [email_security/orchestrator/langgraph_state.py](email_security/orchestrator/langgraph_state.py)
- [email_security/services/email_parser.py](email_security/services/email_parser.py)
- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)

Steps:

1. Add Graph-related settings.
2. Extend orchestrator state with mailbox identity fields.
3. Parse and retain message identity data.
4. Pass identity through the decision object.

Why first:

- nothing should act without a resolved message identity,
- action-layer work depends on these fields,
- this also improves auditability.

#### A2. Keep simulated mode as the default for action execution

Files:

- [email_security/action_layer/response_engine.py](email_security/action_layer/response_engine.py)
- [email_security/action_layer/graph_client.py](email_security/action_layer/graph_client.py)  

Steps:

1. Add a real Graph client module.
2. Keep simulated mode enabled by default.
3. Add logging for skipped or failed real actions.
4. Validate all paths in a test tenant before production.

Why first:

- prevents accidental mailbox changes,
- allows safe development,
- avoids permission-related surprises.

#### A3. Add benchmarking and baselines

Files:

- [email_security/scripts/run_system_benchmark.py](email_security/scripts/run_system_benchmark.py)
- [email_security/tests/](email_security/tests/)

Steps:

1. Capture current latency, memory, throughput, and cache-hit metrics.
2. Record current quality metrics for each agent.
3. Save baseline results before each major change.

Why first:

- without baselines, improvements are hard to prove,
- it prevents invisible regressions.

### 15.2 Phase B: High-return runtime improvements

Priority: very high

Goal: make the system faster and smoother without changing model behavior yet.

#### B1. Preload hot models at startup

Files:

- [email_security/agents/header_agent/model_loader.py](email_security/agents/header_agent/model_loader.py)
- [email_security/agents/content_agent/model_loader.py](email_security/agents/content_agent/model_loader.py)
- [email_security/agents/url_agent/model_loader.py](email_security/agents/url_agent/model_loader.py)
- [email_security/agents/attachment_agent/model_loader.py](email_security/agents/attachment_agent/model_loader.py)
- [email_security/agents/sandbox_agent/model_loader.py](email_security/agents/sandbox_agent/model_loader.py)
- [email_security/agents/threat_intel_agent/model_loader.py](email_security/agents/threat_intel_agent/model_loader.py)
- [email_security/agents/user_behavior_agent/model_loader.py](email_security/agents/user_behavior_agent/model_loader.py)

Steps:

1. Build a warmup routine.
2. Load models during startup.
3. Measure startup memory and latency.
4. Keep lazy-loading only as fallback.

Why now:

- big improvement in first-request latency,
- high benefit with low functional risk.

#### B2. Increase caching for repeated indicators and outputs

Files:

- [email_security/agents/url_agent/agent.py](email_security/agents/url_agent/agent.py)
- [email_security/agents/threat_intel_agent/model_loader.py](email_security/agents/threat_intel_agent/model_loader.py)
- [email_security/orchestrator/llm_reasoner.py](email_security/orchestrator/llm_reasoner.py)
- [email_security/orchestrator/storyline_engine.py](email_security/orchestrator/storyline_engine.py)

Steps:

1. Cache URL verdicts.
2. Cache IOC lookups.
3. Cache repeated explanation prompts.
4. Cache storyline templates and common ATT&CK mappings.

Why now:

- cheaper repeated analyses,
- lower API usage,
- better throughput.

#### B3. Increase safe concurrency

Files:

- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)
- [email_security/scripts/run_system_benchmark.py](email_security/scripts/run_system_benchmark.py)

Steps:

1. Raise worker counts gradually.
2. Measure CPU and I/O saturation.
3. Keep bounded queues.
4. Avoid over-parallelizing tokenization.

Why now:

- direct benefit from extra RAM and likely extra CPU headroom.

### 15.3 Phase C: Model quality upgrades

Priority: very high

Goal: improve accuracy, especially on content and behavioral signals.

#### C1. Upgrade the content model

Files:

- [email_security/scripts/train_content_model_slm.py](email_security/scripts/train_content_model_slm.py)

Steps:

1. Compare the current tiny model with a stronger baseline.
2. Increase sequence length carefully.
3. Raise batch size and class sample caps.
4. Re-run metrics on phishing, spam, and legitimate classes.

Why now:

- this is likely the single biggest detection-quality gain.

#### C2. Improve attachment and sandbox behavior training

Files:

- [email_security/scripts/train_attachment_model.py](email_security/scripts/train_attachment_model.py)
- [email_security/preprocessing/convert_ember_jsonl.py](email_security/preprocessing/convert_ember_jsonl.py)
- [email_security/preprocessing/sandbox_preprocessing.py](email_security/preprocessing/sandbox_preprocessing.py)

Steps:

1. Increase data caps where memory allows.
2. Keep more intermediate features in memory.
3. Expand benign bootstrap data.
4. Verify no increase in false positives.

Why now:

- these models feed the strongest technical signals.

#### C3. Retune URL reputation logic

Files:

- [email_security/agents/url_agent/agent.py](email_security/agents/url_agent/agent.py)
- [email_security/agents/url_agent/model_loader.py](email_security/agents/url_agent/model_loader.py)

Steps:

1. Re-evaluate thresholds.
2. Refresh brand-token and allowlist logic.
3. Compare benign false positives before and after.

Why now:

- URL checks are high-volume and easy to improve with calibration.

### 15.4 Phase D: Threat-intel and correlation upgrades

Priority: high

Goal: make the system smarter about known indicators and campaign-level patterns.

#### D1. Strengthen local threat-intel caching

Files:

- [email_security/agents/threat_intel_agent/model_loader.py](email_security/agents/threat_intel_agent/model_loader.py)
- [email_security/docs/TECHNICAL_PROJECT_REPORT.md](email_security/docs/TECHNICAL_PROJECT_REPORT.md)

Steps:

1. Keep more lookups local.
2. Add TTL and negative caching.
3. Normalize indicators before lookup.

Why now:

- reduces external API dependency and cost.

#### D2. Improve campaign clustering and storyline output

Files:

- [email_security/orchestrator/storyline_engine.py](email_security/orchestrator/storyline_engine.py)
- [email_security/orchestrator/threat_correlation.py](email_security/orchestrator/threat_correlation.py)

Steps:

1. Group related observables into campaigns.
2. Add clearer phase-based explanation.
3. Include ATT&CK-like tactic summaries.

Why now:

- makes reports more useful for analysts and leadership.

### 15.5 Phase E: Action layer rollout

Priority: high, but only after Phase A

Goal: turn analysis into actual remediation.

#### E1. Add Graph client and real action routing

Files:

- [email_security/action_layer/graph_client.py](email_security/action_layer/graph_client.py)
- [email_security/action_layer/response_engine.py](email_security/action_layer/response_engine.py)

Steps:

1. Implement token acquisition.
2. Implement message resolution.
3. Implement quarantine and banner actions.
4. Keep simulated mode available.

Why now:

- this is the core transition from passive analysis to active defense.

#### E2. Add response policy tiers

Files:

- [email_security/action_layer/response_engine.py](email_security/action_layer/response_engine.py)
- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)

Steps:

1. Map score bands to actions.
2. Keep alerting and deliver-with-banner paths.
3. Escalate only when confidence is high enough.

Why now:

- gives predictable and explainable remediation.

#### E3. Add mailbox audit status tracking

Files:

- [email_security/orchestrator/langgraph_state.py](email_security/orchestrator/langgraph_state.py)
- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)

Steps:

1. Track action status in state.
2. Persist action outcome in the final decision.
3. Include Graph IDs and mailbox IDs in reports.

Why now:

- crucial for support, troubleshooting, and compliance.

### 15.6 Phase F: Report and reasoning quality upgrades

Priority: medium-high

Goal: make the system easy to understand for humans.

#### F1. Improve LLM explanation caching and structure

Files:

- [email_security/orchestrator/llm_reasoner.py](email_security/orchestrator/llm_reasoner.py)

Steps:

1. Cache repeated prompts.
2. Standardize explanation output format.
3. Keep fallback text concise and deterministic.

Why now:

- better analyst experience and lower LLM spend.

#### F2. Improve counterfactual explanations and storyline reports

Files:

- [email_security/orchestrator/llm_reasoner.py](email_security/orchestrator/llm_reasoner.py)
- [email_security/orchestrator/storyline_engine.py](email_security/orchestrator/storyline_engine.py)

Steps:

1. Explain what changed the verdict.
2. Show what would have happened if key signals were removed.
3. Render the attack sequence clearly.

Why now:

- strong value for analysts and presentations.

### 15.7 Phase G: Interesting and differentiating upgrades

Priority: optional but valuable

Goal: make the platform stand out and feel more complete.

#### G1. Add adaptive policy and feedback loop

Files:

- [email_security/action_layer/response_engine.py](email_security/action_layer/response_engine.py)
- [email_security/orchestrator/langgraph_workflow.py](email_security/orchestrator/langgraph_workflow.py)

Steps:

1. Record analyst feedback.
2. Use feedback to refine thresholds.
3. Adjust response policy by user group or campaign.

#### G2. Add dashboard and visual timelines

Files:

- [email_security/api/](email_security/api/)
- [email_security/docs/](email_security/docs/)

Steps:

1. Show verdict history.
2. Show agent confidence breakdown.
3. Show action outcomes and campaign clusters.

#### G3. Add replay mode and synthetic test generation

Files:

- [email_security/scripts/](email_security/scripts/)
- [email_security/tests/](email_security/tests/)

Steps:

1. Re-run prior incidents against new models.
2. Generate controlled phishing examples.
3. Benchmark regression and quality changes.

### 15.8 Suggested implementation order summary

If you want the shortest path to the biggest improvement, use this order:

1. add identity fields and action configuration,
2. keep simulated action mode by default,
3. preload models,
4. increase caching,
5. improve content model,
6. improve attachment/sandbox training,
7. expand threat-intel caching,
8. add real Graph action routing,
9. enrich explanations and storyline output,
10. add dashboard, feedback loop, and replay mode.

---

## Final Recommendation

Do not treat the 30 GB machine as a reason to simply raise every limit. Use the extra RAM strategically:

- load better models,
- keep more artifacts hot,
- increase parallelism where it matters,
- cache expensive repeated work,
- preserve strong fallback behavior,
- measure every improvement.

The best version of this system is not just larger; it is **faster, more accurate, and more predictable**.
