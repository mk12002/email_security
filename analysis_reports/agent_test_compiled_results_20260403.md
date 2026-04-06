# Agent Test Compiled Results

Date: 2026-04-03

## 1. Compile Validation
Command:
- `python -m compileall email_security/agents email_security/orchestrator email_security/api`

Result:
- Completed successfully for agents, orchestrator, and API packages.
- No syntax compilation failures.

## 2. Existing Agent Test Suite (Before adding new script)
Command:
- `pytest -q email_security/tests/test_agent_wiring_consistency.py email_security/tests/test_header_edge_calibration.py email_security/tests/test_url_model_smoke.py email_security/tests/test_attachment_ensemble_smoke.py email_security/tests/test_sandbox_agent_behavior.py email_security/tests/test_sandbox_model_inference.py email_security/tests/test_threat_intel_smoke.py email_security/tests/test_operational_flow_e2e.py email_security/tests/test_langgraph_orchestrator.py`

Result:
- `18 passed in 6.24s`

## 3. Realistic Smoke Execution (Ad-hoc runtime scenarios)
### User Behavior Agent
- benign_internal -> risk `0.225`, confidence `0.72`
- phishy_external -> risk `0.8203`, confidence `0.72`
- Ordering: malicious-like > benign-like (expected)

### Threat Intel Agent (IOC-backed)
- IOC DB detected at `email_security/data/ioc_store.db`
- Known bad domains and IPs loaded from DB
- benign_iocs -> risk `0.0004`, confidence `0.65`, indicators include `no_local_ioc_hits`
- malicious_iocs_from_db -> risk `0.9924`, confidence `0.95`, indicators include multiple `ioc_match:*`
- Ordering check: `True`

## 4. New Required Script Added
Added missing realistic user behavior smoke test script:
- `email_security/tests/test_user_behavior_smoke.py`

Why added:
- Threat intel had smoke coverage already.
- User behavior had wiring coverage but lacked dedicated realistic smoke behavior validation.

## 5. Final Agent Test Suite (After adding new script)
Command:
- `pytest -q email_security/tests/test_agent_wiring_consistency.py email_security/tests/test_header_edge_calibration.py email_security/tests/test_url_model_smoke.py email_security/tests/test_attachment_ensemble_smoke.py email_security/tests/test_sandbox_agent_behavior.py email_security/tests/test_sandbox_model_inference.py email_security/tests/test_user_behavior_smoke.py email_security/tests/test_threat_intel_smoke.py email_security/tests/test_operational_flow_e2e.py email_security/tests/test_langgraph_orchestrator.py`

Result:
- `19 passed in 6.41s`

## 6. Diagnostics
- IDE/static errors check: none.
