"""
Orchestrator worker.

Consumes results from all agents, aggregates per analysis_id, stores final reports,
and triggers Garuda/action layer for high-risk cases.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import psycopg2
import redis
from psycopg2.extras import Json

from email_security.action_layer.response_engine import execute_actions
from email_security.agents.model_warmup import warmup_models_at_startup
from email_security.configs.settings import settings
from email_security.orchestrator.langgraph_state import OrchestratorState
from email_security.orchestrator.langgraph_workflow import LangGraphOrchestrator
from email_security.services.logging_service import get_service_logger, setup_logging
from email_security.services.messaging_service import RabbitMQClient

logger = get_service_logger("orchestrator_runner")

EXPECTED_AGENTS = {
    "header_agent",
    "content_agent",
    "url_agent",
    "attachment_agent",
    "sandbox_agent",
    "threat_intel_agent",
    "user_behavior_agent",
}


class OrchestratorWorker:
    def __init__(self):
        self.messaging = RabbitMQClient()
        self.redis_client = redis.from_url(settings.redis_url, decode_responses=True)
        self.graph = LangGraphOrchestrator(
            save_report=self._save_report,
            execute_actions=execute_actions,
        )

    def _pg_conn(self):
        return psycopg2.connect(settings.database_url)

    def _ensure_schema(self) -> None:
        with self._pg_conn() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_reports (
                        id SERIAL PRIMARY KEY,
                        analysis_id TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        overall_risk_score DOUBLE PRECISION NOT NULL,
                        verdict TEXT NOT NULL,
                        llm_explanation TEXT,
                        report JSONB NOT NULL
                    );
                    """
                )
            conn.commit()

    def _save_report(self, analysis_id: str, decision: dict[str, Any]) -> None:
        with self._pg_conn() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO threat_reports (analysis_id, created_at, overall_risk_score, verdict, llm_explanation, report)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (analysis_id)
                    DO UPDATE SET
                      created_at = EXCLUDED.created_at,
                      overall_risk_score = EXCLUDED.overall_risk_score,
                      verdict = EXCLUDED.verdict,
                      llm_explanation = EXCLUDED.llm_explanation,
                      report = EXCLUDED.report;
                    """,
                    (
                        analysis_id,
                        datetime.now(timezone.utc),
                        float(decision.get("overall_risk_score", 0.0)),
                        decision.get("verdict", "unknown"),
                        decision.get("llm_explanation", ""),
                        Json(decision),
                    ),
                )
            conn.commit()

    def _cache_key(self, analysis_id: str) -> str:
        return f"analysis:{analysis_id}:agent_results"

    def _report_exists(self, analysis_id: str) -> bool:
        with self._pg_conn() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT 1
                    FROM threat_reports
                    WHERE analysis_id = %s
                    LIMIT 1
                    """,
                    (analysis_id,),
                )
                return cursor.fetchone() is not None

    def _merge_results(self, analysis_id: str, incoming: dict[str, Any]) -> tuple[list[dict[str, Any]], float]:
        key = self._cache_key(analysis_id)
        current = self.redis_client.get(key)

        first_seen_ts = datetime.now(timezone.utc).timestamp()
        items: list[dict[str, Any]] = []
        if current:
            decoded = json.loads(current)
            if isinstance(decoded, dict):
                first_seen_ts = float(decoded.get("first_seen_ts", first_seen_ts))
                items = decoded.get("results", []) or []
            elif isinstance(decoded, list):
                # Backward-compatible path for cache entries written before state wrapping.
                items = decoded

        filtered = [entry for entry in items if entry.get("agent_name") != incoming.get("agent_name")]
        filtered.append(incoming)

        state = {
            "first_seen_ts": first_seen_ts,
            "results": filtered,
        }
        self.redis_client.setex(key, settings.orchestrator_cache_ttl_seconds, json.dumps(state))
        return filtered, first_seen_ts

    def _is_complete(self, agent_results: list[dict[str, Any]]) -> bool:
        names = {entry.get("agent_name") for entry in agent_results}
        return EXPECTED_AGENTS.issubset(names)

    def _should_finalize(self, agent_results: list[dict[str, Any]], first_seen_ts: float) -> tuple[bool, str]:
        if self._is_complete(agent_results):
            return True, "complete"

        elapsed = datetime.now(timezone.utc).timestamp() - first_seen_ts
        if (
            elapsed >= settings.orchestrator_partial_timeout_seconds
            and len(agent_results) >= settings.orchestrator_min_agents_for_decision
        ):
            return True, "partial_timeout"

        return False, "waiting"

    def _handle_result(self, payload: dict[str, Any]) -> None:
        analysis_id = payload.get("analysis_id")
        if not analysis_id:
            logger.warning("Skipping result without analysis_id")
            return

        if self._report_exists(analysis_id):
            logger.info("Ignoring late result for finalized analysis", analysis_id=analysis_id)
            return

        merged, first_seen_ts = self._merge_results(analysis_id, payload)
        logger.info("Result received", analysis_id=analysis_id, count=len(merged))

        try:
            self.redis_client.publish(
                "pipeline_ui_events",
                json.dumps({
                    "analysis_id": analysis_id,
                    "event_type": "agent_update",
                    "agent_name": payload.get("agent_name"),
                    "risk_score": payload.get("risk_score"),
                    "confidence": payload.get("confidence")
                })
            )
        except Exception as e:
            logger.warning("Failed to publish UI event", error=str(e))

        finalize, reason = self._should_finalize(merged, first_seen_ts)
        if not finalize:
            return

        received_agents = sorted(
            {entry.get("agent_name") for entry in merged if entry.get("agent_name")}
        )

        # Extract Graph identity fields from the first agent that carries them
        user_principal_name = ""
        internet_message_id = ""
        for entry in merged:
            if not user_principal_name and entry.get("user_principal_name"):
                user_principal_name = entry["user_principal_name"]
            if not internet_message_id and entry.get("internet_message_id"):
                internet_message_id = entry["internet_message_id"]
            if user_principal_name and internet_message_id:
                break

        initial_state: OrchestratorState = {
            "analysis_id": analysis_id,
            "agent_results": merged,
            "finalization_reason": reason,
            "received_agents": received_agents,
            "missing_agents": sorted(EXPECTED_AGENTS - set(received_agents)),
            "is_partial": reason != "complete",
            "user_principal_name": user_principal_name,
            "internet_message_id": internet_message_id,
        }

        final_state = self.graph.run(initial_state)
        decision = final_state.get("decision", {})
        
        # Save to PostgreSQL
        self._save_report(analysis_id, decision)
        
        # Cache to Deduplication Store if enabled
        if settings.request_deduplication_enabled:
            try:
                fingerprint = self.redis_client.get(f"email_dedup_mapping:{analysis_id}")
                if fingerprint:
                    from email_security.orchestrator.deduplication import get_dedup_cache
                    # the decision needs an analysis_id and agent_results to be useful for caching
                    cache_payload = decision.copy()
                    cache_payload["analysis_id"] = analysis_id
                    cache_payload["agent_results"] = merged
                    
                    get_dedup_cache().cache_result(fingerprint, cache_payload)
                    # Clean up mapping
                    self.redis_client.delete(f"email_dedup_mapping:{analysis_id}")
            except Exception as e:
                logger.warning("Failed to cache deduplication result", error=str(e))

        self.redis_client.delete(self._cache_key(analysis_id))
        logger.info(
            "Final decision produced",
            analysis_id=analysis_id,
            verdict=decision.get("verdict"),
            score=decision.get("overall_risk_score"),
            reason=reason,
        )

        try:
            self.redis_client.publish(
                "pipeline_ui_events",
                json.dumps({
                    "analysis_id": analysis_id,
                    "event_type": "final_verdict",
                    "verdict": decision.get("verdict"),
                    "overall_risk_score": decision.get("overall_risk_score"),
                    "recommended_actions": decision.get("recommended_actions")
                })
            )
        except Exception as e:
            logger.warning("Failed to publish final UI verdict", error=str(e))

    def run(self) -> None:
        self._ensure_schema()
        self.messaging.connect()
        self.messaging.declare_results_queue(settings.results_queue)
        self.messaging.consume(settings.results_queue, self._handle_result)


def main() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    
    # 30GB RAM Optimization: Preload all models at startup
    logger.info("=" * 60)
    logger.info("Orchestrator Starting (30GB RAM Optimized)")
    logger.info("=" * 60)
    warmup_results = warmup_models_at_startup()
    logger.info(f"Model warmup complete: {len(warmup_results)} agents processed")
    logger.info(f"Orchestrator concurrency: {settings.orchestrator_max_concurrent_analyses} max parallel analyses")
    logger.info(f"Worker pool size: {settings.orchestrator_worker_pool_size}")
    logger.info("=" * 60)
    
    OrchestratorWorker().run()


if __name__ == "__main__":
    main()
