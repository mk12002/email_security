"""
Action layer for quarantine and alert responses.
"""

from __future__ import annotations

from typing import Any

import httpx

from email_security.configs.settings import settings
from email_security.services.logging_service import get_service_logger

logger = get_service_logger("response_engine")


def _safe_call(url: str, payload: dict[str, Any]) -> None:
    try:
        with httpx.Client(timeout=5) as client:
            client.post(url, json=payload)
    except Exception as exc:
        logger.warning("Action endpoint unavailable", url=url, error=str(exc))


class ResponseEngine:
    """
    Final Action Layer responsible for taking automated responses based on
    orchestrator decisions. Currently in 'Simulated Mode' where actions and 
    reasons are printed instead of executing external API calls.
    """
    
    def __init__(self):
        # Placeholders for Azure OpenAI configuration
        self.azure_openai_endpoint = settings.azure_openai_endpoint
        self.azure_openai_api_key = settings.azure_openai_api_key
        self.azure_openai_deployment = settings.azure_openai_deployment
        self.azure_openai_api_version = settings.azure_openai_api_version
        
        # Simulated mode defaults to safe behavior unless explicitly disabled.
        self.simulated_mode = bool(settings.action_simulated_mode)

    @staticmethod
    def _iter_agent_risks(agent_results: Any) -> list[tuple[str, float]]:
        """Normalize heterogeneous agent_results payloads into (agent_name, risk_score)."""
        normalized: list[tuple[str, float]] = []

        if isinstance(agent_results, dict):
            for agent_name, result in agent_results.items():
                if not isinstance(result, dict):
                    continue
                try:
                    risk = float(result.get("risk_score", 0.0) or 0.0)
                except Exception:
                    risk = 0.0
                normalized.append((str(agent_name), risk))
            return normalized

        if isinstance(agent_results, list):
            for entry in agent_results:
                if not isinstance(entry, dict):
                    continue
                agent_name = str(entry.get("agent_name") or entry.get("agent") or "unknown_agent")
                try:
                    risk = float(entry.get("risk_score", 0.0) or 0.0)
                except Exception:
                    risk = 0.0
                normalized.append((agent_name, risk))

        return normalized

    def _generate_ai_response_summary(self, decision: dict[str, Any]) -> str:
        """
        Placeholder method: Use Azure OpenAI to generate a natural language summary
        of the actions taken and the incident report.
        """
        if not self.azure_openai_api_key:
            return "AI Summary Unavailable: Azure OpenAI API Key not configured."
        
        # Placeholder for actual LLM call
        return "AI Summary Placeholder: Detected threat, recommended actions prioritized."

    def execute_actions(self, decision: dict[str, Any]) -> None:
        actions = decision.get("recommended_actions", [])
        analysis_id = decision.get("analysis_id", "unknown-id")
        score = decision.get("overall_risk_score", 0.0)
        verdict = decision.get("verdict", "unknown")
        
        # Extract reasons. Sometimes they are in nested agent results or a top-level summary.
        # Fallback to a composite string if no explicit reasons list exists.
        reasons = decision.get("reasons", [])
        if not reasons:
            # Try to build reasons from the decision payload
            reasons = [f"Verdict is {verdict} with a risk score of {score:.2f}"]
            for agent_name, risk in self._iter_agent_risks(decision.get("agent_results", {})):
                if risk > 0.6:
                    reasons.append(f"{agent_name} reported high risk ({risk:.2f})")

        payload = {
            "analysis_id": analysis_id,
            "score": score,
            "verdict": verdict,
            "actions": actions,
        }

        print("\n" + "="*60)
        print(f"🔒 ACTION LAYER INVOKED FOR ANALYSIS: {analysis_id}")
        print(f"📊 Verdict: {verdict.upper()} | Risk Score: {score:.2f}")
        print("-" * 60)
        
        if reasons:
            print("🛑 REASONS FOR ACTIONS:")
            for r in reasons:
                print(f"   - {r}")
        print("-" * 60)

        if not actions:
            print("✅ No specific actions recommended.")
            print("="*60 + "\n")
            return

        print("⚡ EXECUTING ACTIONS (SIMULATED MODE):")

        if "quarantine" in actions:
            print("   -> [ACTION TAKEN] 📦 Email Moved to Quarantine")
            # External API logic kept but disabled conditionally if simulated_mode is active
            if not self.simulated_mode and settings.quarantine_api_url:
                _safe_call(settings.quarantine_api_url, payload)
                logger.info("Quarantine action emitted", analysis_id=analysis_id)

        if "soc_alert" in actions or "trigger_garuda" in actions:
            print("   -> [ACTION TAKEN] 🚨 Alert Sent to SOC Team / Garuda Agent")
            if not self.simulated_mode and settings.soc_alert_api_url:
                _safe_call(settings.soc_alert_api_url, payload)
                logger.info("SOC alert action emitted", analysis_id=analysis_id)
                
        if "block_sender" in actions:
            print("   -> [ACTION TAKEN] 🚫 Sender Email / Domain Blocked Locally")
            
        if "reset_credentials" in actions:
            print("   -> [ACTION TAKEN] 🔑 Forced Password Reset for Target User")

        # Generate and print the AI summary
        ai_summary = self._generate_ai_response_summary(decision)
        print("-" * 60)
        print(f"🤖 AI Response Summary: {ai_summary}")
        print("="*60 + "\n")


# Replace the old functional entrypoint with the class-based one
response_engine = ResponseEngine()
execute_actions = response_engine.execute_actions
