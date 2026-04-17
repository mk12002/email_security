from __future__ import annotations

from email_security.agents.content_agent import agent as content_agent
from email_security.agents.url_agent import agent as url_agent
from email_security.agents.user_behavior_agent import agent as user_behavior_agent
from email_security.orchestrator.decision_engine.engine import make_decision


def _legit_payment_payload() -> dict:
    return {
        "headers": {
            "sender": "noreply@msr-cmt.org",
            "subject": "IEEE ICNPCV 2026 - PAYMENT REMINDER",
            "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
        },
        "body": {
            "plain": "This is a payment reminder for conference registration fee.",
            "html": "",
        },
        "urls": [
            "https://go.microsoft.com/fwlink/?LinkId=521839",
            "https://rzp.io/rzp/ICNPCV2026",
        ],
        "attachments": [],
    }


def test_content_agent_marks_transactional_legitimacy(monkeypatch) -> None:
    monkeypatch.setattr(content_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        content_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.95,
            "confidence": 0.99,
            "indicators": ["ml_slm_label:Phishing"],
        },
    )

    result = content_agent.analyze(_legit_payment_payload())

    assert result["risk_score"] <= 0.62
    assert any("transactional_legitimacy_profile:strong" in i for i in result["indicators"])


def test_url_agent_marks_transactional_legitimacy(monkeypatch) -> None:
    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        url_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.86,
            "confidence": 0.9,
            "indicators": ["ml_url_model_used"],
        },
    )

    result = url_agent.analyze(_legit_payment_payload())

    assert result["risk_score"] < 0.7
    assert any("transactional_legitimacy_profile:strong" in i for i in result["indicators"])


def test_user_behavior_agent_marks_transactional_legitimacy(monkeypatch) -> None:
    monkeypatch.setattr(user_behavior_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        user_behavior_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.9,
            "confidence": 0.9,
            "indicators": ["ml_user_behavior_anomaly_detected"],
        },
    )

    result = user_behavior_agent.analyze(_legit_payment_payload())

    assert result["risk_score"] <= 0.58
    assert any("transactional_legitimacy_profile:strong" in i for i in result["indicators"])


def test_decision_downgrades_transactional_false_positive() -> None:
    agent_results = [
        {"agent_name": "header_agent", "risk_score": 0.28, "confidence": 0.9, "indicators": ["ml_header_model_used"]},
        {
            "agent_name": "content_agent",
            "risk_score": 0.62,
            "confidence": 0.91,
            "indicators": ["transactional_legitimacy_profile:strong"],
        },
        {
            "agent_name": "url_agent",
            "risk_score": 0.63,
            "confidence": 0.86,
            "indicators": ["transactional_legitimacy_profile:strong"],
        },
        {"agent_name": "attachment_agent", "risk_score": 0.0, "confidence": 0.8, "indicators": ["no_attachments"]},
        {"agent_name": "sandbox_agent", "risk_score": 0.0, "confidence": 0.75, "indicators": ["no_attachments_for_sandbox"]},
        {"agent_name": "threat_intel_agent", "risk_score": 0.0, "confidence": 0.65, "indicators": ["no_local_ioc_hits"]},
        {
            "agent_name": "user_behavior_agent",
            "risk_score": 0.58,
            "confidence": 0.85,
            "indicators": ["transactional_legitimacy_profile:strong"],
        },
    ]

    decision = make_decision(agent_results)
    assert decision["verdict"] == "likely_safe"
    assert decision["recommended_actions"] == ["deliver_with_banner"]


def test_decision_does_not_downgrade_with_hard_malicious_signal() -> None:
    agent_results = [
        {"agent_name": "header_agent", "risk_score": 0.3, "confidence": 0.9, "indicators": ["ml_header_model_used"]},
        {
            "agent_name": "content_agent",
            "risk_score": 0.62,
            "confidence": 0.91,
            "indicators": ["transactional_legitimacy_profile:strong"],
        },
        {
            "agent_name": "url_agent",
            "risk_score": 0.63,
            "confidence": 0.86,
            "indicators": ["transactional_legitimacy_profile:strong"],
        },
        {
            "agent_name": "attachment_agent",
            "risk_score": 0.98,
            "confidence": 0.8,
            "indicators": ["suspicious_extension:invoice.pdf.exe"],
        },
        {"agent_name": "sandbox_agent", "risk_score": 0.0, "confidence": 0.75, "indicators": ["no_attachments_for_sandbox"]},
        {"agent_name": "threat_intel_agent", "risk_score": 0.0, "confidence": 0.65, "indicators": ["no_local_ioc_hits"]},
        {
            "agent_name": "user_behavior_agent",
            "risk_score": 0.58,
            "confidence": 0.85,
            "indicators": ["transactional_legitimacy_profile:strong"],
        },
    ]

    decision = make_decision(agent_results)
    assert decision["verdict"] == "suspicious"
