"""
LogSense AI - Resolution Recommendation Agent
Synthesizes evidence-based, actionable remediation procedures, immediate containment steps,
diagnostic commands, and preventive architectural measures for operational incidents.
"""

from typing import List, Tuple
from src.models import Incident, ResolutionAction, AgentResult


class ResolutionRecommendationAgent:
    """Agent responsible for recommending tactical and strategic troubleshooting steps."""

    def __init__(self):
        self.name = "Resolution Recommendation Agent"

    def recommend(self, incidents: List[Incident]) -> Tuple[List[Incident], AgentResult]:
        """
        Populates actionable recommendations for each incident based on its category,
        severity, affected endpoints, and discovered root cause hypotheses.
        """
        import time
        start_time = time.time()
        agent_result = AgentResult(agent_name=self.name)

        if not incidents:
            agent_result.status = "SUCCESS"
            agent_result.output_summary = "No incidents provided for recommendation generation."
            agent_result.execution_time_ms = 0.0
            return [], agent_result

        total_actions = 0
        immediate_count = 0

        for inc in incidents:
            actions = self._generate_recommendations(inc)
            inc.recommended_actions = actions
            total_actions += len(actions)
            immediate_count += sum(1 for a in actions if a.urgency == "Immediate")

        execution_time_ms = (time.time() - start_time) * 1000

        agent_result.status = "SUCCESS"
        agent_result.execution_time_ms = execution_time_ms
        agent_result.input_summary = f"Generated troubleshooting runbooks for {len(incidents)} active incidents."
        agent_result.output_summary = (
            f"Prescribed {total_actions} actionable mitigation steps across {len(incidents)} incidents "
            f"({immediate_count} immediate containment actions, including shell/SQL diagnostic commands)."
        )
        agent_result.findings = [
            f"Formulated {total_actions} prioritized troubleshooting recommendations.",
            f"Immediate containment actions: {immediate_count} (focused on preventing service cascading failure).",
            "Included copy-ready shell, SQL, and CLI diagnostic commands for on-call engineers.",
            "Policy: Actions are recommended guidance; platform requires engineer verification before marking resolved.",
        ]
        agent_result.details = {
            "incidents_serviced": len(incidents),
            "total_actions": total_actions,
            "immediate_actions": immediate_count,
        }

        return incidents, agent_result

    def _generate_recommendations(self, inc: Incident) -> List[ResolutionAction]:
        """Maps incident context to prioritized engineering remediation actions."""
        cat = inc.category
        svc = inc.service
        ep = inc.endpoint or "/api/..."

        actions: List[ResolutionAction] = []

        if cat == "DATABASE_FAILURE":
            actions = [
                ResolutionAction(
                    action=f"Inspect active connection count and saturated sessions on '{svc}'.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command="SELECT count(*), state, wait_event_type FROM pg_stat_activity GROUP BY 2, 3 ORDER BY 1 DESC;",
                ),
                ResolutionAction(
                    action=f"Temporarily increase connection pool size or terminate orphaned idle connections in '{svc}'.",
                    urgency="Immediate",
                    category="Remediation",
                    diagnostic_command="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction' AND state_change < current_timestamp - INTERVAL '5 minutes';",
                ),
                ResolutionAction(
                    action="Validate database connection pool configuration (max_connections, pool_timeout, idle_timeout).",
                    urgency="Short-term",
                    category="Configuration",
                    diagnostic_command="SHOW max_connections;",
                ),
                ResolutionAction(
                    action="Implement client-side circuit breakers and connection retry backoff to avoid stampeding herd.",
                    urgency="Preventive",
                    category="Configuration",
                    diagnostic_command=None,
                ),
            ]

        elif cat == "HTTP_SERVER_ERROR":
            actions = [
                ResolutionAction(
                    action=f"Inspect recent error logs and stack traces on '{svc}' for endpoint '{ep}'.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"kubectl logs -l app={svc} --tail=200 | grep -E 'ERROR|Exception'",
                ),
                ResolutionAction(
                    action=f"Check upstream dependency health and network reachability from '{svc}'.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"curl -Iv https://{svc}.internal{ep} --max-time 5",
                ),
                ResolutionAction(
                    action="Verify if recent deployment or config push introduced regression; prepare fast rollback.",
                    urgency="Short-term",
                    category="Remediation",
                    diagnostic_command=f"kubectl rollout history deployment/{svc} && kubectl rollout undo deployment/{svc}",
                ),
                ResolutionAction(
                    action="Implement fallback error responses and ensure API routes fail gracefully with RFC 7807 Problem Details.",
                    urgency="Preventive",
                    category="Configuration",
                    diagnostic_command=None,
                ),
            ]

        elif cat == "SLOW_RESPONSE":
            actions = [
                ResolutionAction(
                    action=f"Profile endpoint latency and query execution times on '{ep}'.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"curl -w 'dns: %{{time_namelookup}} connect: %{{time_connect}} ttfb: %{{time_starttransfer}} total: %{{time_total}}\\n' -o /dev/null -s https://{svc}.internal{ep}",
                ),
                ResolutionAction(
                    action=f"Inspect CPU, memory, and worker thread utilization on '{svc}' pods.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"kubectl top pods -l app={svc}",
                ),
                ResolutionAction(
                    action="Enable database query indexing or check for missing indexes on slow queries.",
                    urgency="Short-term",
                    category="Remediation",
                    diagnostic_command="EXPLAIN ANALYZE <frequent_slow_query>;",
                ),
                ResolutionAction(
                    action="Add distributed caching (Redis/Memcached) for high-frequency read operations.",
                    urgency="Preventive",
                    category="Configuration",
                    diagnostic_command=None,
                ),
            ]

        elif cat == "UNHANDLED_EXCEPTION":
            actions = [
                ResolutionAction(
                    action=f"Locate exact stack trace and line number in '{svc}' deployment logs.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"grep -n -C 5 'Traceback' /var/log/{svc}/*.log || kubectl logs -l app={svc} --tail=100",
                ),
                ResolutionAction(
                    action="Inspect recent git commits on affected controller to identify breaking change.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command="git log -n 5 --stat --oneline",
                ),
                ResolutionAction(
                    action="Deploy hotfix with null safety checks and schema validation for incoming payloads.",
                    urgency="Short-term",
                    category="Remediation",
                    diagnostic_command=None,
                ),
                ResolutionAction(
                    action="Add unit and integration tests covering the edge-case inputs that triggered the exception.",
                    urgency="Preventive",
                    category="Configuration",
                    diagnostic_command="pytest tests/ -k 'test_error_handling'",
                ),
            ]

        elif cat == "SUSPICIOUS_AUTH":
            # Extract client IP if available
            ip = next((e.client_ip for e in inc.correlated_events if e.client_ip), "ATTACKER_IP")
            actions = [
                ResolutionAction(
                    action=f"Temporarily rate-limit or drop packets from offending source IP '{ip}'.",
                    urgency="Immediate",
                    category="Remediation",
                    diagnostic_command=f"iptables -I INPUT -s {ip} -j DROP # or via Cloudflare / AWS WAF IP Block list",
                ),
                ResolutionAction(
                    action=f"Verify if any login attempts succeeded from '{ip}' during the incident window.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"grep '{ip}' /var/log/auth/*.log | grep -E '200 OK|success|authenticated'",
                ),
                ResolutionAction(
                    action="Enforce account lockout policies and notify impacted accounts to reset credentials.",
                    urgency="Short-term",
                    category="Remediation",
                    diagnostic_command=None,
                ),
                ResolutionAction(
                    action="Deploy CAPTCHA challenge and IP reputation scoring on all public authentication routes.",
                    urgency="Preventive",
                    category="Configuration",
                    diagnostic_command=None,
                ),
            ]

        elif cat == "SERVICE_DEGRADATION":
            actions = [
                ResolutionAction(
                    action=f"Inspect container exit code and previous termination logs on '{svc}'.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"kubectl describe pod -l app={svc} | grep -A 10 'Last State:'",
                ),
                ResolutionAction(
                    action=f"Check if pod exceeded memory limits (OOMKilled) or failed liveness health probes.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"kubectl get events --sort-by='.metadata.creationTimestamp' | tail -n 20",
                ),
                ResolutionAction(
                    action=f"Adjust container memory limits and increase liveness probe initialDelaySeconds.",
                    urgency="Short-term",
                    category="Configuration",
                    diagnostic_command=f"kubectl edit deployment/{svc}",
                ),
                ResolutionAction(
                    action="Conduct memory heap dump analysis to detect memory leaks in background workers.",
                    urgency="Preventive",
                    category="Remediation",
                    diagnostic_command=None,
                ),
            ]

        else:  # General / Repeated Errors
            actions = [
                ResolutionAction(
                    action=f"Review correlated warning/error streams for service '{svc}'.",
                    urgency="Immediate",
                    category="Diagnostic",
                    diagnostic_command=f"grep -E 'ERROR|WARN' /var/log/{svc}.log | tail -n 50",
                ),
                ResolutionAction(
                    action="Verify dependency health and downstream service connectivity.",
                    urgency="Short-term",
                    category="Diagnostic",
                    diagnostic_command=None,
                ),
                ResolutionAction(
                    action="Configure enhanced metric alarms for early warning before error density spikes.",
                    urgency="Preventive",
                    category="Configuration",
                    diagnostic_command=None,
                ),
            ]

        return actions
