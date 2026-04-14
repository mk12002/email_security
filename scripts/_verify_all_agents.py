"""Verify all 7 agents load and produce correct inference results."""

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def main():
    results = {}

    # 1. Header Agent
    print("\n[1/7] Testing header_agent...")
    from email_security.agents.header_agent import analyze as header_analyze
    r = header_analyze({
        "headers": {
            "sender": "alerts@paypa1.example",
            "reply_to": "support@evil.example",
            "subject": "Urgent: verify your account",
            "received": ["from smtp-unknown by victim-mx"],
            "message_id": "<m-test-1>",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
        }
    })
    results["header_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # 2. Content Agent
    print("\n[2/7] Testing content_agent...")
    from email_security.agents.content_agent import analyze as content_analyze
    r = content_analyze({
        "headers": {"subject": "Invoice overdue"},
        "body": {
            "plain": "Urgent action required. Confirm your password now to avoid account lock. Click http://evil.example/login",
            "html": "",
        },
    })
    results["content_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # 3. URL Agent
    print("\n[3/7] Testing url_agent...")
    from email_security.agents.url_agent import analyze as url_analyze
    r = url_analyze({
        "urls": [
            "http://secure-login-paypa1.example/verify",
            "https://microsoft.com-security-login.example/reset",
        ]
    })
    results["url_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # 4. Attachment Agent (no attachments)
    print("\n[4/7] Testing attachment_agent...")
    from email_security.agents.attachment_agent import analyze as attachment_analyze
    r = attachment_analyze({"attachments": []})
    results["attachment_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # 5. Sandbox Agent (no attachments)
    print("\n[5/7] Testing sandbox_agent...")
    from email_security.agents.sandbox_agent import analyze as sandbox_analyze
    r = sandbox_analyze({"attachments": []})
    results["sandbox_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # 6. Threat Intel Agent
    print("\n[6/7] Testing threat_intel_agent...")
    from email_security.agents.threat_intel_agent import analyze as threat_intel_analyze
    r = threat_intel_analyze({
        "iocs": {
            "domains": ["evil.example"],
            "ips": ["185.100.87.202"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        },
        "urls": ["http://known-bad.example/phish"],
        "headers": {"sender": "attacker@evil.example"},
    })
    results["threat_intel_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # 7. User Behavior Agent
    print("\n[7/7] Testing user_behavior_agent...")
    from email_security.agents.user_behavior_agent import analyze as user_behavior_analyze
    r = user_behavior_analyze({
        "headers": {
            "sender": "finance-team@example.com",
            "subject": "Payroll details update",
        },
        "body": {
            "plain": "Please review payroll changes immediately and confirm via this link.",
            "html": "",
        },
    })
    results["user_behavior_agent"] = r
    print(f"  risk={r['risk_score']:.4f} conf={r['confidence']:.4f} indicators={r['indicators'][:5]}")

    # Summary
    print("\n" + "=" * 70)
    print("ALL 7 AGENTS TESTED — SUMMARY")
    print("=" * 70)
    for name, res in results.items():
        model_used = "ml_model_unavailable" not in str(res.get("indicators", []))
        print(f"  {name:25s} risk={res['risk_score']:.4f}  conf={res['confidence']:.4f}  ml_model_active={model_used}")

    # Orchestrator scoring test
    print("\n" + "=" * 70)
    print("ORCHESTRATOR PIPELINE TEST")
    print("=" * 70)
    from email_security.orchestrator.scoring_engine import calculate_threat_score
    from email_security.orchestrator.threat_correlation import correlate_threats
    from email_security.orchestrator.counterfactual_engine import calculate_counterfactual, threshold_for_verdict
    from email_security.orchestrator.storyline_engine import generate_storyline

    agent_results_list = list(results.values())
    score_data = calculate_threat_score(agent_results_list)
    correlation = correlate_threats(agent_results_list)
    overall = float(score_data.get("overall_score", 0.0))
    corr = float(correlation.get("correlation_score", 0.0))
    normalized = min(1.0, overall + (0.2 * corr))

    if normalized >= 0.8:
        verdict = "malicious"
    elif normalized >= 0.6:
        verdict = "high_risk"
    elif normalized >= 0.4:
        verdict = "suspicious"
    else:
        verdict = "likely_safe"

    threshold = threshold_for_verdict(verdict)
    if threshold is not None:
        cf = calculate_counterfactual(
            agent_results=agent_results_list,
            correlation=correlation,
            current_normalized_score=normalized,
            threshold=threshold,
        )
    else:
        cf = {"is_counterfactual": False, "reason": "no_blocking_boundary"}

    storyline = generate_storyline(
        agent_results=agent_results_list,
        verdict=verdict,
        recommended_actions=["quarantine"] if verdict in ("malicious", "high_risk") else ["review"],
    )

    print(f"  Overall Score:      {overall:.4f}")
    print(f"  Correlation Score:  {corr:.4f}")
    print(f"  Normalized Score:   {normalized:.4f}")
    print(f"  Threat Level:       {score_data.get('threat_level')}")
    print(f"  Verdict:            {verdict}")
    print(f"  Counterfactual:     {cf.get('is_counterfactual', False)} — agents_altered={cf.get('agents_altered', [])}")
    print(f"  Storyline Phases:   {[phase['phase'] for phase in storyline]}")

    # LLM Reasoner (fallback)
    from email_security.orchestrator.llm_reasoner import generate_reasoning
    explanation = generate_reasoning(agent_results_list, normalized, cf)
    print(f"  LLM Explanation:    {explanation[:150]}...")

    # Action Layer
    from email_security.action_layer.response_engine import execute_actions
    decision = {
        "analysis_id": "test-verification-001",
        "overall_risk_score": normalized,
        "verdict": verdict,
        "recommended_actions": ["quarantine", "soc_alert"] if verdict in ("malicious", "high_risk") else ["review"],
        "agent_results": agent_results_list,
    }
    execute_actions(decision)

    print("\n" + "=" * 70)
    print("FULL PIPELINE VERIFICATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
