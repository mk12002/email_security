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

from action_layer.response_engine import execute_actions
from configs.settings import settings
from garuda_integration.bridge import trigger_garuda_investigation
from orchestrator.decision_engine import make_decision
from services.logging_service import get_service_logger, setup_logging
from services.messaging_service import RabbitMQClient

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

    def _merge_results(self, analysis_id: str, incoming: dict[str, Any]) -> list[dict[str, Any]]:
        key = self._cache_key(analysis_id)
        current = self.redis_client.get(key)
        items: list[dict[str, Any]] = json.loads(current) if current else []

        filtered = [entry for entry in items if entry.get("agent_name") != incoming.get("agent_name")]
        filtered.append(incoming)
        self.redis_client.setex(key, 900, json.dumps(filtered))
        return filtered

    def _is_complete(self, agent_results: list[dict[str, Any]]) -> bool:
        names = {entry.get("agent_name") for entry in agent_results}
        return EXPECTED_AGENTS.issubset(names)

    def _handle_result(self, payload: dict[str, Any]) -> None:
        analysis_id = payload.get("analysis_id")
        if not analysis_id:
            logger.warning("Skipping result without analysis_id")
            return

        merged = self._merge_results(analysis_id, payload)
        logger.info("Result received", analysis_id=analysis_id, count=len(merged))
        if not self._is_complete(merged):
            return

        decision = make_decision(merged)
        decision["analysis_id"] = analysis_id
        self._save_report(analysis_id, decision)

        if decision.get("overall_risk_score", 0.0) > 0.7:
            garuda_feedback = trigger_garuda_investigation(decision)
            decision["garuda_feedback"] = garuda_feedback

        execute_actions(decision)
        self.redis_client.delete(self._cache_key(analysis_id))
        logger.info(
            "Final decision produced",
            analysis_id=analysis_id,
            verdict=decision.get("verdict"),
            score=decision.get("overall_risk_score"),
        )

    def run(self) -> None:
        self._ensure_schema()
        self.messaging.connect()
        self.messaging.declare_results_queue(settings.results_queue)
        self.messaging.consume(settings.results_queue, self._handle_result)


def run() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    OrchestratorWorker().run()


if __name__ == "__main__":
    run()
