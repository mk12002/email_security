"""
Action layer for quarantine and alert responses.

Now supports both simulated mode and real Microsoft Graph-backed actions
for email remediation including quarantine and banner insertion.
"""

from __future__ import annotations

from typing import Any

import httpx

from email_security.src.action_layer.graph_client import get_graph_client, GraphActionResult
from email_security.src.configs.settings import settings
from email_security.src.services.logging_service import get_service_logger

logger = get_service_logger("response_engine")


def _safe_call(url: str, payload: dict[str, Any]) -> None:
    try:
        with httpx.Client(timeout=5) as client:
            client.post(url, json=payload)
    except Exception as exc:
        logger.warning("Action endpoint unavailable", url=url, error=str(exc))


class ResponseEngine:
    """
    Action Layer responsible for taking automated responses based on orchestrator decisions.
    
    Supports two modes:
    1. **Simulated Mode** (default): Actions are logged and printed for testing/audit
    2. **Live Mode**: Real Graph API calls for email quarantine and banner insertion
    
    With 30GB RAM optimizations, we can now afford real Graph actions with proper
    error handling and audit trails.
    """
    
    def __init__(self):
        # Azure OpenAI configuration
        self.azure_openai_endpoint = settings.azure_openai_endpoint
        self.azure_openai_api_key = settings.azure_openai_api_key
        self.azure_openai_deployment = settings.azure_openai_deployment
        self.azure_openai_api_version = settings.azure_openai_api_version
        
        # Action layer mode: simulate first, then go live
        self.simulated_mode = bool(settings.action_simulated_mode)
        self.banner_enabled = settings.action_banner_enabled
        self.quarantine_enabled = settings.action_quarantine_enabled
        
        # Graph client for real actions
        self.graph = get_graph_client()
        
        logger.info(
            "Action Layer Initialized",
            simulated_mode=self.simulated_mode,
            graph_configured=self.graph.is_configured(),
            banner_enabled=self.banner_enabled,
            quarantine_enabled=self.quarantine_enabled,
        )

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
        
        # Graph identity fields for real actions
        user_principal_name = decision.get("user_principal_name")
        internet_message_id = decision.get("internet_message_id")
        graph_message_id = decision.get("graph_message_id")
        
        # Extract reasons
        reasons = decision.get("reasons", [])
        if not reasons:
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

        print("\n" + "="*70)
        print(f"[ACTION LAYER] Analysis: {analysis_id}")
        print(f"[VERDICT] {verdict.upper()} | Risk Score: {score:.2f}")
        print("-" * 70)
        
        if reasons:
            print("[REASONS]:")
            for r in reasons:
                print(f"  • {r}")
        print("-" * 70)

        if not actions:
            print("[✓] No specific actions recommended.")
            print("="*70 + "\n")
            return

        # If in live mode and we have Graph identity, attempt real actions
        if not self.simulated_mode and self.graph.is_configured() and user_principal_name:
            self._execute_graph_actions(
                actions, analysis_id, verdict, score,
                user_principal_name, internet_message_id, graph_message_id
            )
        else:
            # Simulated mode: just print actions
            self._execute_simulated_actions(actions, analysis_id)

        # Generate and print the AI summary
        ai_summary = self._generate_ai_response_summary(decision)
        print("-" * 70)
        print(f"[AI SUMMARY] {ai_summary}")
        print("="*70 + "\n")

    def _execute_graph_actions(
        self,
        actions: list[str],
        analysis_id: str,
        verdict: str,
        score: float,
        upn: str,
        internet_message_id: str | None,
        graph_message_id: str | None,
    ) -> None:
        """Execute real Graph API actions for email remediation."""
        print("[LIVE MODE] Executing via Microsoft Graph...")
        
        # Resolve message ID if not provided
        if not graph_message_id and internet_message_id:
            resolved = self.graph.resolve_message_id(upn, internet_message_id)
            if resolved:
                graph_message_id = resolved
                logger.info("Resolved message ID via Graph", analysis_id=analysis_id, upn=upn)
            else:
                logger.warning("Failed to resolve message ID", analysis_id=analysis_id, upn=upn)
                return

        if not graph_message_id:
            logger.warning(
                "Cannot execute actions: no graph_message_id available",
                analysis_id=analysis_id,
            )
            return

        # Execute quarantine for high-risk emails
        if "quarantine" in actions and self.quarantine_enabled:
            result = self.graph.quarantine_email(upn, graph_message_id)
            status_icon = "✓" if result.ok else "✗"
            print(f"  {status_icon} Quarantine: {result.detail or 'success'}")
            logger.info("Quarantine action executed", analysis_id=analysis_id, ok=result.ok)

        # Apply warning banner for medium-risk emails
        if "deliver_with_banner" in actions and self.banner_enabled:
            severity = "Critical" if score >= 0.85 else "High" if score >= 0.60 else "Medium"
            result = self.graph.apply_warning_banner(upn, graph_message_id, severity=severity)
            status_icon = "✓" if result.ok else "✗"
            print(f"  {status_icon} Banner ({severity}): {result.detail or 'success'}")
            logger.info("Banner action executed", analysis_id=analysis_id, ok=result.ok, severity=severity)

        # Add categories for classification
        if "categorize" in actions:
            categories = ["PhishingLure"] if verdict == "phishing" else ["Suspicious"] if verdict == "suspicious" else []
            if categories:
                result = self.graph.add_categories(upn, graph_message_id, categories)
                status_icon = "✓" if result.ok else "✗"
                print(f"  {status_icon} Categorized: {result.detail or 'success'}")

    def _execute_simulated_actions(self, actions: list[str], analysis_id: str) -> None:
        """Execute simulated actions (logging only, no external calls)."""
        print("[SIMULATED MODE] Logging actions (no external calls)...")

        if "quarantine" in actions:
            print("  → [QUARANTINE] Would move email to Junk folder")
            if not self.quarantine_enabled:
                print("     (quarantine disabled in settings)")

        if "deliver_with_banner" in actions:
            print("  → [BANNER] Would insert security warning banner")
            if not self.banner_enabled:
                print("     (banner disabled in settings)")

        if "soc_alert" in actions or "trigger_garuda" in actions:
            print("  → [ALERT] Would notify SOC team / Garuda agent")

        if "block_sender" in actions:
            print("  → [BLOCK] Would add sender to local blocklist")
            
        if "reset_credentials" in actions:
            print("  → [CREDS] Would trigger forced password reset")

        if "deliver" in actions:
            print("  → [DELIVER] Email would be delivered normally")

        if "categorize" in actions:
            print("  → [CATEGORIZE] Would apply classification tags")


# Replace the old functional entrypoint with the class-based one
response_engine = ResponseEngine()
execute_actions = response_engine.execute_actions
