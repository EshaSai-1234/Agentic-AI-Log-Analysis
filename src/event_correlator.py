"""
LogSense AI - Event Correlation Agent
Correlates disparate log events into distinct operational incidents using temporal proximity,
shared trace identifiers, service boundaries, endpoint routes, and cascading failure patterns.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
import uuid

from src.models import LogEvent, Incident, AgentResult


class EventCorrelatorAgent:
    """Agent responsible for clustering related anomalies into consolidated Incident entities."""

    def __init__(self, time_window_minutes: int = 5):
        self.name = "Event Correlation Agent"
        self.time_window = timedelta(minutes=time_window_minutes)

    def correlate(
        self,
        candidate_detections: List[Dict[str, Any]],
        all_events: List[LogEvent]
    ) -> Tuple[List[Incident], AgentResult]:
        """
        Groups detected incident candidates and surrounding context events into coherent Incidents.
        Returns the list of consolidated Incidents and the AgentResult.
        """
        import time
        start_time = time.time()
        agent_result = AgentResult(agent_name=self.name)

        if not candidate_detections:
            agent_result.status = "SUCCESS"
            agent_result.output_summary = "No incident candidates to correlate."
            agent_result.execution_time_ms = 0.0
            return [], agent_result

        # Sort candidate detections by timestamp
        sorted_candidates = sorted(candidate_detections, key=lambda c: c["event"].timestamp)

        # Build index of all events for context lookups
        events_by_id = {e.id: e for e in all_events}

        # Cluster candidate events
        clusters: List[List[Dict[str, Any]]] = []

        for cand in sorted_candidates:
            matched_cluster = None
            ev = cand["event"]

            # Try to match with existing clusters
            for cluster in clusters:
                if self._should_correlate(cand, cluster):
                    matched_cluster = cluster
                    break

            if matched_cluster is not None:
                matched_cluster.append(cand)
            else:
                clusters.append([cand])

        # Convert clusters into Incident objects
        incidents: List[Incident] = []
        cascading_count = 0

        for i, cluster in enumerate(clusters, start=1):
            incident = self._build_incident(cluster, all_events, index=i)
            if len(set(e.service for e in incident.correlated_events)) > 1:
                cascading_count += 1
            incidents.append(incident)

        # Sort incidents by severity weight and time
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        incidents.sort(key=lambda inc: (severity_order.get(inc.severity, 4), inc.first_seen))

        execution_time_ms = (time.time() - start_time) * 1000

        # Construct findings
        critical_count = sum(1 for inc in incidents if inc.severity == "CRITICAL")
        high_count = sum(1 for inc in incidents if inc.severity == "HIGH")
        avg_cluster_size = sum(len(c) for c in clusters) / max(len(clusters), 1)

        agent_result.status = "SUCCESS"
        agent_result.execution_time_ms = execution_time_ms
        agent_result.input_summary = f"Correlated {len(candidate_detections)} candidate detections against {len(all_events)} total events."
        agent_result.output_summary = (
            f"Consolidated into {len(incidents)} distinct operational incidents ({critical_count} Critical, "
            f"{high_count} High). Found {cascading_count} cross-service cascading failure chains."
        )
        agent_result.findings = [
            f"Clustered {len(candidate_detections)} anomaly signals into {len(incidents)} actionable incidents.",
            f"Average correlated events per incident: {avg_cluster_size:.1f} events.",
            f"Detected {cascading_count} cross-service failure cascades (e.g. downstream API failing due to upstream DB).",
            f"Temporal window used for correlation: ±{self.time_window.total_seconds() / 60:.0f} minutes.",
        ]
        agent_result.details = {
            "total_incidents": len(incidents),
            "critical_count": critical_count,
            "high_count": high_count,
            "cascading_incidents": cascading_count,
            "cluster_sizes": [len(c) for c in clusters],
        }

        return incidents, agent_result

    def _should_correlate(self, cand: Dict[str, Any], cluster: List[Dict[str, Any]]) -> bool:
        """Determines if a candidate event belongs to an existing incident cluster."""
        ev = cand["event"]

        for member in cluster:
            m_ev = member["event"]

            # 1. Exact trace ID correlation (strongest link)
            if ev.trace_id and m_ev.trace_id and ev.trace_id == m_ev.trace_id:
                return True

            # Check temporal proximity (must be within time window)
            time_diff = abs((ev.timestamp - m_ev.timestamp).total_seconds())
            if time_diff > self.time_window.total_seconds():
                continue

            # 2. Same service and same incident category within time window
            if ev.service == m_ev.service and cand["category"] == member["category"]:
                return True

            # 3. Same endpoint failure within time window
            if ev.endpoint and m_ev.endpoint and ev.endpoint == m_ev.endpoint:
                return True

            # 4. Same client IP for auth issues
            if cand["category"] == "SUSPICIOUS_AUTH" and member["category"] == "SUSPICIOUS_AUTH":
                if ev.client_ip and m_ev.client_ip and ev.client_ip == m_ev.client_ip:
                    return True

            # 5. Cascading failure pattern:
            # Database failure preceding HTTP 500/503 errors within 3 minutes
            if member["category"] == "DATABASE_FAILURE" and cand["category"] in ["HTTP_SERVER_ERROR", "SLOW_RESPONSE"]:
                if (ev.timestamp >= m_ev.timestamp) and (time_diff <= 180):
                    return True

            # Unhandled Exception causing HTTP 500 error on same or related service
            if member["category"] == "UNHANDLED_EXCEPTION" and cand["category"] == "HTTP_SERVER_ERROR":
                if time_diff <= 120:
                    return True

        return False

    def _build_incident(self, cluster: List[Dict[str, Any]], all_events: List[LogEvent], index: int) -> Incident:
        """Synthesizes a cluster of candidate events into a full Incident model."""
        cluster_events = [c["event"] for c in cluster]
        cluster_events.sort(key=lambda e: e.timestamp)

        first_seen = cluster_events[0].timestamp
        last_seen = cluster_events[-1].timestamp

        # Determine dominant category
        category_counts = defaultdict(int)
        for c in cluster:
            category_counts[c["category"]] += 1
        dominant_category = max(category_counts.items(), key=lambda x: x[1])[0]

        # Prioritize root categories if present
        for priority_cat in ["DATABASE_FAILURE", "UNHANDLED_EXCEPTION", "SUSPICIOUS_AUTH", "SERVICE_DEGRADATION"]:
            if priority_cat in category_counts:
                dominant_category = priority_cat
                break

        # Calculate severity
        severities = [c["severity"] for c in cluster]
        if "CRITICAL" in severities or len(cluster) >= 8 or dominant_category == "DATABASE_FAILURE":
            overall_severity = "CRITICAL"
        elif "HIGH" in severities or len(cluster) >= 4:
            overall_severity = "HIGH"
        elif "MEDIUM" in severities:
            overall_severity = "MEDIUM"
        else:
            overall_severity = "LOW"

        # Identify primary service and endpoint
        services = [e.service for e in cluster_events]
        primary_service = max(set(services), key=services.count) if services else "system"

        endpoints = [e.endpoint for e in cluster_events if e.endpoint]
        primary_endpoint = max(set(endpoints), key=endpoints.count) if endpoints else None

        # Build informative Title
        title = self._generate_incident_title(dominant_category, primary_service, primary_endpoint, len(cluster))

        # Compile detection reasons
        reasons = list(set(c["detection_reason"] for c in cluster))
        detection_reason = "; ".join(reasons[:3])

        # Gather surrounding context events (e.g. ±30s before first incident and after last incident)
        context_events = self._gather_context_events(all_events, first_seen, last_seen, primary_service)
        all_correlated = sorted(list({e.id: e for e in (cluster_events + context_events)}.values()), key=lambda e: e.timestamp)

        # Average confidence
        conf_scores = [c.get("confidence_score", 0.8) for c in cluster]
        avg_conf = sum(conf_scores) / len(conf_scores) if conf_scores else 0.85

        incident_id = f"INC-{index:03d}-{dominant_category[:3]}"

        return Incident(
            id=incident_id,
            title=title,
            category=dominant_category,
            severity=overall_severity,
            status="OPEN",
            service=primary_service,
            endpoint=primary_endpoint,
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=len(cluster_events),
            event_ids=[e.id for e in cluster_events],
            correlated_events=all_correlated,
            detection_reason=detection_reason,
            detection_method="Rule Pattern + Scikit-Learn Feature Classifier",
            confidence_score=avg_conf,
            possible_root_causes=[],
            recommended_actions=[],
            is_reviewed=False,
            review_notes="",
        )

    def _gather_context_events(
        self,
        all_events: List[LogEvent],
        first_seen: datetime,
        last_seen: datetime,
        service: str
    ) -> List[LogEvent]:
        """Collects relevant informational logs around the incident window for causal reasoning."""
        window_start = first_seen - timedelta(seconds=45)
        window_end = last_seen + timedelta(seconds=45)
        context = []

        for e in all_events:
            if window_start <= e.timestamp <= window_end:
                if e.service == service or e.level in ["WARN", "ERROR", "CRITICAL"]:
                    context.append(e)

        return context[:25]  # Cap context to prevent overflow

    def _generate_incident_title(self, category: str, service: str, endpoint: Optional[str], count: int) -> str:
        """Constructs human-friendly operational title."""
        ep_str = f" on {endpoint}" if endpoint else ""
        if category == "DATABASE_FAILURE":
            return f"Database Connectivity Failure & Timeout in [{service}]"
        elif category == "HTTP_SERVER_ERROR":
            return f"Cluster of HTTP 5xx Server Errors in [{service}]{ep_str}"
        elif category == "SLOW_RESPONSE":
            return f"High Latency SLA Degradation in [{service}]{ep_str}"
        elif category == "UNHANDLED_EXCEPTION":
            return f"Unhandled Runtime Exception / Crash in [{service}]"
        elif category == "SUSPICIOUS_AUTH":
            return f"Suspicious Authentication Spike / Brute-Force Pattern in [{service}]"
        elif category == "SERVICE_DEGRADATION":
            return f"Service Instability & Container Restart in [{service}]"
        elif category == "REPEATED_ERRORS":
            return f"High-Density Error Burst ({count} events) in [{service}]"
        else:
            return f"Operational Incident ({category}) in [{service}]{ep_str}"
