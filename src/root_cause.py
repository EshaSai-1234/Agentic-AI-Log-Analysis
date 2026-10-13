"""
LogSense AI - Root Cause Investigation Agent
Analyzes correlated event timelines to produce evidence-backed root cause hypotheses.
Maintains scientific rigor: never claims confirmed causation without direct proof,
and explicitly quantifies uncertainty when log telemetry is incomplete.
"""

from datetime import datetime
from typing import List, Dict, Any, Tuple
import re

from src.models import Incident, RootCauseHypothesis, AgentResult, LogEvent


class RootCauseInvestigationAgent:
    """Agent responsible for causal timeline reconstruction and hypothesis generation."""

    def __init__(self):
        self.name = "Root Cause Investigation Agent"

    def investigate(self, incidents: List[Incident]) -> Tuple[List[Incident], AgentResult]:
        """
        Analyzes each incident's correlated event stream and generates evidence-based root cause hypotheses.
        Returns the updated incidents and the AgentResult.
        """
        import time
        start_time = time.time()
        agent_result = AgentResult(agent_name=self.name)

        if not incidents:
            agent_result.status = "SUCCESS"
            agent_result.output_summary = "No incidents provided for root cause investigation."
            agent_result.execution_time_ms = 0.0
            return [], agent_result

        hypotheses_count = 0
        high_conf_count = 0
        uncertain_count = 0

        for inc in incidents:
            hypotheses = self._analyze_incident(inc)
            inc.possible_root_causes = hypotheses
            hypotheses_count += len(hypotheses)

            for h in hypotheses:
                if h.confidence == "High":
                    high_conf_count += 1
                elif h.confidence == "Low" or h.uncertainty_note:
                    uncertain_count += 1

        execution_time_ms = (time.time() - start_time) * 1000

        agent_result.status = "SUCCESS"
        agent_result.execution_time_ms = execution_time_ms
        agent_result.input_summary = f"Investigated causal telemetry for {len(incidents)} active incidents."
        agent_result.output_summary = (
            f"Formulated {hypotheses_count} evidence-backed root cause hypotheses across {len(incidents)} incidents "
            f"({high_conf_count} High confidence, {uncertain_count} flagged with diagnostic uncertainty)."
        )
        agent_result.findings = [
            f"Synthesized {hypotheses_count} possible root cause scenarios supported by extracted log evidence lines.",
            f"High confidence hypotheses: {high_conf_count} (corroborated by clear stack traces or DB connection logs).",
            f"Uncertain/Sparse evidence cases: {uncertain_count} (telemetry lacks upstream diagnostic context).",
            "Ethical Observability Standard: All conclusions remain strictly designated as 'Possible Causes' awaiting verification.",
        ]
        agent_result.details = {
            "incidents_investigated": len(incidents),
            "total_hypotheses": hypotheses_count,
            "high_confidence_hypotheses": high_conf_count,
            "uncertain_hypotheses": uncertain_count,
        }

        return incidents, agent_result

    def _analyze_incident(self, inc: Incident) -> List[RootCauseHypothesis]:
        """Examines the correlated event sequence of an incident to formulate hypotheses."""
        events = sorted(inc.correlated_events, key=lambda e: e.timestamp)
        if not events:
            return [
                RootCauseHypothesis(
                    hypothesis="No correlated event telemetry available to reconstruct timeline.",
                    confidence="Low",
                    confidence_score=0.15,
                    evidence=["No supporting log lines recorded."],
                    uncertainty_note="Evidence is completely absent. External monitoring data required.",
                )
            ]

        # Chronological initiation analysis
        first_error_event = next((e for e in events if e.level in ["WARN", "ERROR", "CRITICAL"]), events[0])
        category = inc.category

        hypotheses: List[RootCauseHypothesis] = []

        # 1. DATABASE FAILURE ANALYSIS
        if category == "DATABASE_FAILURE" or any("db" in e.service.lower() or "database" in e.message.lower() for e in events):
            hypotheses.extend(self._investigate_db_failure(events, first_error_event))

        # 2. UNHANDLED EXCEPTION / CRASH ANALYSIS
        elif category == "UNHANDLED_EXCEPTION":
            hypotheses.extend(self._investigate_exception(events, first_error_event))

        # 3. HTTP SERVER ERROR CASCADES
        elif category == "HTTP_SERVER_ERROR":
            hypotheses.extend(self._investigate_http_5xx(events, first_error_event))

        # 4. SLOW API / LATENCY DEGRADATION
        elif category == "SLOW_RESPONSE":
            hypotheses.extend(self._investigate_slow_response(events, first_error_event))

        # 5. SUSPICIOUS AUTHENTICATION PATTERN
        elif category == "SUSPICIOUS_AUTH":
            hypotheses.extend(self._investigate_auth_attack(events, first_error_event))

        # 6. SERVICE DEGRADATION / RESTART
        elif category == "SERVICE_DEGRADATION":
            hypotheses.extend(self._investigate_service_degradation(events, first_error_event))

        # Fallback / General Error Burst
        if not hypotheses:
            hypotheses.append(self._investigate_generic_failure(events, first_error_event))

        return hypotheses

    def _investigate_db_failure(self, events: List[LogEvent], first_err: LogEvent) -> List[RootCauseHypothesis]:
        """Root cause logic for database related incidents."""
        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] {e.message[:120]}"
            for e in events if e.level in ["ERROR", "CRITICAL"] or "timeout" in e.message.lower()
        ][:5]

        msg_lower = " ".join([e.message.lower() for e in events])

        if "pool exhausted" in msg_lower or "no free connections" in msg_lower:
            return [
                RootCauseHypothesis(
                    hypothesis=(
                        f"Database Connection Pool Exhaustion in '{first_err.service}'. "
                        "All available connection slots were saturated by concurrent transactions, causing subsequent queries to block and time out."
                    ),
                    confidence="High",
                    confidence_score=0.92,
                    evidence=evidence,
                    uncertainty_note="Log explicitly mentions pool exhaustion, but the exact query holding connections or connection leak requires database slow-query logs.",
                ),
                RootCauseHypothesis(
                    hypothesis=(
                        "Secondary Possibility: Database server reached max_connections setting or network packet drop to PostgreSQL/MySQL."
                    ),
                    confidence="Medium",
                    confidence_score=0.60,
                    evidence=evidence[:2],
                    uncertainty_note="Secondary hypothesis dependent on network infrastructure health metrics.",
                )
            ]
        elif "deadlock" in msg_lower:
            return [
                RootCauseHypothesis(
                    hypothesis=(
                        f"Concurrent Transaction Deadlock in '{first_err.service}'. "
                        "Two or more parallel transactions competed for conflicting database row/table locks, causing database rollback."
                    ),
                    confidence="High",
                    confidence_score=0.90,
                    evidence=evidence,
                    uncertainty_note="Application code needs lock ordering analysis; specific SQL statements are not logged in application output.",
                )
            ]
        else:
            return [
                RootCauseHypothesis(
                    hypothesis=(
                        f"Database Connectivity Timeout or Unreachable Backend on '{first_err.service}'. "
                        "Connection dropped or failed to respond within the designated socket timeout period."
                    ),
                    confidence="High",
                    confidence_score=0.85,
                    evidence=evidence,
                    uncertainty_note="Could be caused by database service restart, high server CPU load, or network firewall/VPC partition.",
                )
            ]

    def _investigate_exception(self, events: List[LogEvent], first_err: LogEvent) -> List[RootCauseHypothesis]:
        """Root cause logic for unhandled exceptions."""
        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] {e.message[:130]}"
            for e in events if e.level in ["ERROR", "CRITICAL"]
        ][:4]

        # Extract exception name
        exc_match = re.search(r"([A-Za-z0-9_]+(?:Exception|Error|Panic))", first_err.message)
        exc_name = exc_match.group(1) if exc_match else "Unhandled Exception"

        return [
            RootCauseHypothesis(
                hypothesis=(
                    f"Application Software Defect: Uncaught {exc_name} in '{first_err.service}'. "
                    f"Unexpected input or missing null check triggered fatal error during processing."
                ),
                confidence="High",
                confidence_score=0.88,
                evidence=evidence,
                uncertainty_note="Full stack trace analysis is required to determine if trigger was malformed user payload or internal state corruption.",
            ),
            RootCauseHypothesis(
                hypothesis=(
                    f"Possible Incompatible API Payload: Upstream service sent unexpected JSON schema causing {exc_name}."
                ),
                confidence="Medium",
                confidence_score=0.55,
                evidence=evidence[:2],
                uncertainty_note="Request body payload is not logged due to privacy/PII masking.",
            )
        ]

    def _investigate_http_5xx(self, events: List[LogEvent], first_err: LogEvent) -> List[RootCauseHypothesis]:
        """Root cause logic for HTTP 500 / 503 cascades."""
        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] Status: {e.status_code or 500} - {e.message[:110]}"
            for e in events if (e.status_code and e.status_code >= 500) or e.level in ["ERROR", "CRITICAL"]
        ][:5]

        # Check if upstream error preceded it
        upstream_err = next((e for e in events if "db" in e.service.lower() or "timeout" in e.message.lower()), None)
        if upstream_err:
            return [
                RootCauseHypothesis(
                    hypothesis=(
                        f"Cascading Failure: Downstream HTTP {first_err.status_code or 500} errors on '{first_err.endpoint or first_err.service}' "
                        f"were triggered by upstream failure in '{upstream_err.service}'."
                    ),
                    confidence="High",
                    confidence_score=0.87,
                    evidence=[
                        f"Upstream trigger: [{upstream_err.timestamp.strftime('%H:%M:%S')}] {upstream_err.message[:100]}",
                        *evidence[:3]
                    ],
                    uncertainty_note="Correlation is temporally consistent, but distributed trace spans are needed to verify the synchronous call graph.",
                )
            ]
        else:
            return [
                RootCauseHypothesis(
                    hypothesis=(
                        f"Server Internal Failure (HTTP {first_err.status_code or 500}) on endpoint '{first_err.endpoint or first_err.service}'. "
                        "Backend processing aborted unexpectedly without graceful error recovery."
                    ),
                    confidence="Medium",
                    confidence_score=0.72,
                    evidence=evidence,
                    uncertainty_note="Endpoint lacks granular internal trace logs; requires application debug logs to isolate exact line of failure.",
                )
            ]

    def _investigate_slow_response(self, events: List[LogEvent], first_err: LogEvent) -> List[RootCauseHypothesis]:
        """Root cause logic for high latency spikes."""
        slow_events = [e for e in events if e.response_time_ms is not None and e.response_time_ms > 1000]
        max_latency = max((e.response_time_ms for e in slow_events), default=1500.0)

        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] Latency: {e.response_time_ms:.1f}ms on {e.endpoint or 'API'} - {e.message[:80]}"
            for e in slow_events[:4]
        ]

        return [
            RootCauseHypothesis(
                hypothesis=(
                    f"Downstream Dependency Latency or Thread Contention in '{first_err.service}'. "
                    f"Peak latency reached {max_latency:.1f}ms on endpoint '{first_err.endpoint or 'API'}', exceeding SLA."
                ),
                confidence="Medium",
                confidence_score=0.78,
                evidence=evidence,
                uncertainty_note="High latency can stem from slow database queries, external payment gateway delay, or worker thread pool saturation. Log data alone cannot distinguish without APM trace spans.",
            ),
            RootCauseHypothesis(
                hypothesis=(
                    "Possible Sudden Traffic Spike: Influx of simultaneous requests leading to queue backlog."
                ),
                confidence="Low",
                confidence_score=0.45,
                evidence=evidence[:2],
                uncertainty_note="Request throughput metrics are required to confirm if request arrival rate exceeded capacity.",
            )
        ]

    def _investigate_auth_attack(self, events: List[LogEvent], first_err: LogEvent) -> List[RootCauseHypothesis]:
        """Root cause logic for suspicious login bursts."""
        ips = list(set(e.client_ip for e in events if e.client_ip))
        primary_ip = ips[0] if ips else "Unknown IP"

        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] IP={e.client_ip or 'N/A'} - {e.message[:110]}"
            for e in events if "login" in (e.endpoint or "").lower() or (e.status_code in [401, 403]) or "failed" in e.message.lower()
        ][:5]

        return [
            RootCauseHypothesis(
                hypothesis=(
                    f"Automated Credential Stuffing / Brute-Force Authentication Attempt against '{first_err.service}'. "
                    f"Rapid burst of failed login transactions originating from source IP '{primary_ip}'."
                ),
                confidence="High",
                confidence_score=0.91,
                evidence=evidence,
                uncertainty_note="Evidence strongly suggests automated attack, but could theoretically be a misconfigured client service with expired credentials.",
            )
        ]

    def _investigate_service_degradation(self, events: List[LogEvent], first_err: LogEvent) -> List[RootCauseHypothesis]:
        """Root cause logic for service crashes and restarts."""
        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] {e.message[:120]}"
            for e in events
        ][:4]

        return [
            RootCauseHypothesis(
                hypothesis=(
                    f"Service Pod/Container Restart or Crash in '{first_err.service}'. "
                    "Host process terminated, likely due to an unhandled SIGSEGV, Out-of-Memory (OOM) kill by orchestrator, or liveness probe timeout."
                ),
                confidence="Medium",
                confidence_score=0.75,
                evidence=evidence,
                uncertainty_note="Application container stdout does not include kernel dmesg or Kubernetes Pod termination reasons (e.g. OOMKilled vs Node Eviction).",
            )
        ]

    def _investigate_generic_failure(self, events: List[LogEvent], first_err: LogEvent) -> RootCauseHypothesis:
        """Fallback hypothesis for sparse or ambiguous incident events."""
        evidence = [
            f"[{e.timestamp.strftime('%H:%M:%S')}] [{e.service}] {e.message[:120]}"
            for e in events[:3]
        ]
        return RootCauseHypothesis(
            hypothesis=(
                f"Operational Anomaly detected in '{first_err.service}'. "
                "Multiple warning/error conditions recorded without distinct root failure signature."
            ),
            confidence="Low",
            confidence_score=0.40,
            evidence=evidence,
            uncertainty_note="Telemetry data is sparse or ambiguous. Additional log verbosity or infrastructure metrics required to formulate a high-confidence cause.",
        )
