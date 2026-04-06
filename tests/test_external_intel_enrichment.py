from __future__ import annotations

import pytest

from email_security.agents.threat_intel_agent import agent as threat_intel_agent
from email_security.agents.url_agent import agent as url_agent


def test_url_agent_external_enrichment_fusion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_agent, "_heuristic_score", lambda _url: (0.2, ["heuristic_signal"]))
    monkeypatch.setattr(url_agent, "_external_score", lambda _url: (1.0, ["external_signal"]))
    monkeypatch.setattr(url_agent, "_any_external_lookup_enabled", lambda: True)
    monkeypatch.setattr(url_agent, "extract_features", lambda _payload: {"metrics": {}})
    monkeypatch.setattr(url_agent, "load_model", lambda: object())
    monkeypatch.setattr(
        url_agent,
        "predict",
        lambda _features, model=None: {
            "risk_score": 0.4,
            "confidence": 0.8,
            "indicators": ["ml_url_model_used"],
        },
    )

    result = url_agent.analyze({"urls": ["http://suspicious.example/login"]})

    # evidence_risk=max(max(0.2, 0.45*0.2 + 0.55*1.0), 0.65*0.2 + 0.35*1.0)=0.64
    # final_risk=0.6*0.4 + 0.4*0.64 = 0.496
    assert result["risk_score"] == pytest.approx(0.496, abs=1e-4)
    assert result["confidence"] == pytest.approx(0.8, abs=1e-4)
    assert any("external_risk=1.0" == item for item in result["indicators"])
    assert any("external_lookups_enabled" == item for item in result["indicators"])


def test_threat_intel_external_enrichment_fusion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(threat_intel_agent, "_refresh_ioc_store_if_needed", lambda: 42)
    monkeypatch.setattr(threat_intel_agent._STORE, "lookup", lambda _candidates: ["evil.example"])
    monkeypatch.setattr(threat_intel_agent, "load_model", lambda: object())
    monkeypatch.setattr(threat_intel_agent, "extract_features", lambda *_args, **_kwargs: {"f": 1.0})
    monkeypatch.setattr(
        threat_intel_agent,
        "predict",
        lambda _features, _model: {
            "risk_score": 0.5,
            "confidence": 0.7,
            "indicators": [],
        },
    )
    monkeypatch.setattr(
        threat_intel_agent,
        "_external_enrichment_score",
        lambda _iocs: (0.8, ["otx_hit:domain:evil.example"]),
    )
    monkeypatch.setattr(threat_intel_agent.settings, "enable_otx_lookup", True, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_abuseipdb_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_malwarebazaar_lookup", False, raising=False)
    monkeypatch.setattr(threat_intel_agent.settings, "enable_virustotal_hash_lookup", False, raising=False)

    result = threat_intel_agent.analyze(
        {
            "iocs": {
                "domains": ["evil.example", "safe.example"],
                "ips": [],
                "hashes": [],
            }
        }
    )

    # local_match_score=1/2=0.5
    # final_risk=0.55*0.5 + 0.3*0.5 + 0.15*0.8 = 0.545
    assert result["risk_score"] == pytest.approx(0.545, abs=1e-4)
    assert result["confidence"] == pytest.approx(0.85, abs=1e-4)
    assert any(str(item).startswith("ioc_match:") for item in result["indicators"])
    assert "external_threat_enrichment_enabled" in result["indicators"]
