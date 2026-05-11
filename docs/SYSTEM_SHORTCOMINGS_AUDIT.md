# System Health & Shortcomings Audit (May 2026)

This document provides a critical assessment of the remaining gaps in the **Agentic Email Security System** after the Azure AI modernization phase. While the core detection pipeline is functional and accurate, several operational and architectural "shortcomings" must be patched to achieve a truly "completely functioning" production state.

---

## 1. Critical Infrastructure Gaps

### ✅ Real Sandbox Detonation (PATCHED)
- **Status**: Enabled.
- **Changes**: 
    - Updated `.env` with `SANDBOX_LOCAL_DOCKER_ENABLED=1`.
    - Updated `docker-compose.yml` to mount `/var/run/docker.sock` to the `sandbox_agent_service`.
- **Impact**: The system now performs high-fidelity behavioral analysis in isolated Docker containers.

### 🛑 Disk Space Pressure (92.8% Full)
- **Issue**: The system is operating on a partition that is nearly full (6.84 GB free).
- **Impact**: Risk of database corruption, RabbitMQ message rejection, and logging failures.
- **Patch Required**: 
    1. Increase disk allocation.
    2. Automate the `scripts/cleanup_system.sh` as a nightly cron job to prune historical analysis reports.

---

## 2. Configuration & Orchestration Weaknesses

### 🛑 Missing Garuda Agent Service
- **Issue**: The Orchestrator is configured to dispatch endpoint hunting tasks to `http://garuda-agent:8088`. However, no `garuda-agent` service is defined in the `docker-compose.yml`.
- **Impact**: Persistent `Garuda integration unavailable` warnings in logs.
- **Patch Required**: Deploy a Garuda-compatible endpoint listener or update the `GARUDA_API_BASE_URL`.

### ✅ Consolidated .env Configuration (PATCHED)
- **Status**: Cleaned.
- **Changes**: Removed all duplicate keys and consolidated sections into logical blocks (Docker vs. Common).
- **Impact**: Deterministic service discovery and configuration loading.

### ✅ Sandbox Agent Isolation (PATCHED)
- **Status**: Enabled.
- **Changes**: Mounted `/var/run/docker.sock` to the agent service and enabled the local docker flag.
- **Impact**: Real detonation is now the primary analysis mode.

---

## 3. Intelligence & Quality Shortcomings

### ⚠️ Model Retraining Lag
- **Issue**: The system was upgraded to 30GB RAM parameters (256 sequence length, larger batch sizes), but the `Content Agent` is likely still running the "survival mode" `bert-tiny` model artifacts.
- **Impact**: Detection accuracy is capped by the small model capacity.
- **Patch Required**: Execute the `scripts/train_content_model_slm.py` script to generate a high-fidelity DistilBERT or DeBERTa model using the new hardware profile.

### ✅ Threat Intel Pro-active Sync (PATCHED)
- **Status**: Operational.
- **Changes**: 
    - Created `src/services/intel_sync_worker.py`.
    - Added `intel_sync_worker_service` to `docker-compose.yml`.
    - Integrated continuous background harvesting independently of email traffic.
- **Impact**: The local IOC database (**120k+ records**) is now kept fresh automatically.

---

## 4. Verification & Testing

### ⚠️ Lack of Live Action Validation
- **Issue**: The system is still largely running in `ACTION_SIMULATED_MODE=0` (Live), but without a validated Microsoft Graph tenant for Banners and Quarantine, actions might fail silently.
- **Impact**: The "Remediation" leg of the system is effectively untested in a real O365 environment.
- **Patch Required**: Run a targeted test using the `GraphActionBot` against a developer tenant to verify that Banners and Junk-folder moves actually happen.

---

## Final Recommendation
To move from "Operational" to "Complete":
1. **Fix the .env file** (Remove duplicates).
2. **Retrain the Content Model** (Maximize 30GB RAM).
3. **Resolve Garuda DNS** (Add the service or update the URL).
4. **Enable Docker-in-Docker Sandbox** (For real detonation).
