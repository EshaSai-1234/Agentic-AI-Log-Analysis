"""
LogSense AI - Incident Report Agent
Generates comprehensive post-incident operational reports in Plain Text (.txt),
Tabular Data (.csv), and Markdown/JSON formats for engineering reviews and audit compliance.
"""

import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Tuple

from src.models import Incident, AnalysisSession, AgentResult


class IncidentReportAgent:
    """Agent responsible for compiling formal incident post-mortems and exportable audit artifacts."""

    def __init__(self):
        self.name = "Incident Report Agent"

    def generate_reports(self, session: AnalysisSession) -> Tuple[Dict[str, str], AgentResult]:
        """
        Compiles TXT, CSV, and Markdown/JSON reports from an analysis session.
        Returns a dict of reports {format: content_string} and the AgentResult.
        """
        import time
        start_time = time.time()
        agent_result = AgentResult(agent_name=self.name)

        txt_report = self.generate_txt_report(session)
        csv_report = self.generate_csv_report(session)
        json_report = self.generate_json_report(session)

        reports = {
            "txt": txt_report,
            "csv": csv_report,
            "json": json_report,
        }

        execution_time_ms = (time.time() - start_time) * 1000

        agent_result.status = "SUCCESS"
        agent_result.execution_time_ms = execution_time_ms
        agent_result.input_summary = f"Processed session '{session.session_id}' containing {len(session.incidents)} incidents."
        agent_result.output_summary = (
            f"Compiled audit-grade reports across 3 formats (TXT: {len(txt_report)} chars, "
            f"CSV: {len(csv_report.splitlines())} rows, JSON: {len(json_report)} chars)."
        )
        agent_result.findings = [
            f"Generated executive text summary with operational metrics and troubleshooting runbooks.",
            f"Produced structured CSV incident registry for ITIL/SIEM record ingestion.",
            f"Generated full JSON artifact containing complete agent findings, evidence, and ML evaluation stats.",
        ]
        agent_result.details = {
            "txt_size_bytes": len(txt_report.encode("utf-8")),
            "csv_rows": len(csv_report.splitlines()),
            "json_size_bytes": len(json_report.encode("utf-8")),
        }

        return reports, agent_result

    def generate_txt_report(self, session: AnalysisSession) -> str:
        """Generates a formatted human-readable ASCII / Plain Text post-mortem report."""
        lines = []
        divider = "=" * 80
        subdivider = "-" * 80

        lines.append(divider)
        lines.append("AGENTIC AI LOG ANALYSIS SYSTEM - POST-INCIDENT REPORT")
        lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Session ID: {session.session_id}")
        lines.append(f"Source Log File: {session.filename}")
        lines.append(divider)
        lines.append("")

        # Section 1: Executive KPI Summary
        lines.append("1. EXECUTIVE SUMMARY & KPIS")
        lines.append(subdivider)
        lines.append(f"Total Log Events Ingested:    {session.total_logs:,}")
        lines.append(f"Total Operational Incidents:  {len(session.incidents):,}")
        lines.append(f"  - CRITICAL Severity:        {session.critical_count}")
        lines.append(f"  - HIGH Severity:            {session.high_count}")
        lines.append(f"  - MEDIUM Severity:          {session.medium_count}")
        lines.append(f"  - LOW Severity:             {session.low_count}")
        reviewed_count = sum(1 for i in session.incidents if i.is_reviewed)
        lines.append(f"Reviewed by On-Call:          {reviewed_count} / {len(session.incidents)}")
        lines.append("")

        # Section 2: Agent Workflow Execution
        lines.append("2. MULTI-AGENT EXECUTION AUDIT")
        lines.append(subdivider)
        for agent_name, result in session.agent_results.items():
            lines.append(f"Agent: {agent_name} [{result.status}] ({result.execution_time_ms:.1f}ms)")
            lines.append(f"  Output: {result.output_summary}")
        lines.append("")

        # Section 3: Detailed Incident Manifest
        lines.append("3. DETAILED INCIDENT BREAKDOWN")
        lines.append(subdivider)
        if not session.incidents:
            lines.append("No operational incidents detected in this session.")
        else:
            for idx, inc in enumerate(session.incidents, start=1):
                lines.append(f"Incident #{idx}: [{inc.severity}] {inc.id} - {inc.title}")
                lines.append(f"  Category:        {inc.category}")
                lines.append(f"  Primary Service: {inc.service}")
                lines.append(f"  Endpoint:        {inc.endpoint or 'N/A'}")
                lines.append(f"  Time Window:     {inc.first_seen.strftime('%Y-%m-%d %H:%M:%S')} to {inc.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"  Events Clustered:{inc.event_count}")
                lines.append(f"  Confidence:      {inc.confidence_score * 100:.0f}% ({inc.detection_method})")
                lines.append(f"  Review Status:   {'REVIEWED' if inc.is_reviewed else 'OPEN (Pending Review)'}")
                if inc.review_notes:
                    lines.append(f"  Engineer Notes:  {inc.review_notes}")

                # Hypotheses
                lines.append("  Possible Root Causes:")
                if not inc.possible_root_causes:
                    lines.append("    (No causal hypotheses formulated)")
                else:
                    for h_idx, h in enumerate(inc.possible_root_causes, start=1):
                        lines.append(f"    [{h_idx}] {h.hypothesis} (Confidence: {h.confidence})")
                        if h.uncertainty_note:
                            lines.append(f"        * Uncertainty Note: {h.uncertainty_note}")
                        if h.evidence:
                            lines.append("        * Key Evidence Log Lines:")
                            for ev_line in h.evidence[:3]:
                                lines.append(f"          > {ev_line}")

                # Recommendations
                lines.append("  Recommended Troubleshooting Actions:")
                if not inc.recommended_actions:
                    lines.append("    (No specific recommendations generated)")
                else:
                    for a_idx, act in enumerate(inc.recommended_actions, start=1):
                        lines.append(f"    [{a_idx}] [{act.urgency.upper()}] ({act.category}) {act.action}")
                        if act.diagnostic_command:
                            lines.append(f"        Command: {act.diagnostic_command}")

                lines.append("-" * 60)

        lines.append("")
        lines.append(divider)
        lines.append("CONFIDENTIALITY & GOVERNANCE NOTICE:")
        lines.append("Root causes are generated hypotheses based on observable log evidence.")
        lines.append("Production engineers must inspect underlying system state prior to concluding root cause.")
        lines.append(divider)

        return "\n".join(lines)

    def generate_csv_report(self, session: AnalysisSession) -> str:
        """Generates tabular CSV data of all incidents."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            "Incident_ID",
            "Severity",
            "Category",
            "Title",
            "Service",
            "Endpoint",
            "Event_Count",
            "First_Seen_UTC",
            "Last_Seen_UTC",
            "Confidence_Score",
            "Detection_Reason",
            "Primary_Possible_Root_Cause",
            "Root_Cause_Confidence",
            "Uncertainty_Note",
            "Immediate_Action",
            "Review_Status",
            "Review_Notes",
        ])

        for inc in session.incidents:
            primary_hyp = inc.possible_root_causes[0] if inc.possible_root_causes else None
            primary_act = next((a for a in inc.recommended_actions if a.urgency == "Immediate"), None)
            if not primary_act and inc.recommended_actions:
                primary_act = inc.recommended_actions[0]

            writer.writerow([
                inc.id,
                inc.severity,
                inc.category,
                inc.title,
                inc.service,
                inc.endpoint or "N/A",
                inc.event_count,
                inc.first_seen.isoformat(),
                inc.last_seen.isoformat(),
                f"{inc.confidence_score:.2f}",
                inc.detection_reason,
                primary_hyp.hypothesis if primary_hyp else "N/A",
                primary_hyp.confidence if primary_hyp else "N/A",
                primary_hyp.uncertainty_note if primary_hyp else "N/A",
                primary_act.action if primary_act else "N/A",
                "REVIEWED" if inc.is_reviewed else "OPEN",
                inc.review_notes or "",
            ])

        return output.getvalue()

    def generate_json_report(self, session: AnalysisSession) -> str:
        """Generates comprehensive structured JSON report."""
        data = {
            "session_id": session.session_id,
            "filename": session.filename,
            "created_at": session.created_at.isoformat(),
            "metrics": {
                "total_logs": session.total_logs,
                "total_incidents": session.total_incidents,
                "critical_count": session.critical_count,
                "high_count": session.high_count,
                "medium_count": session.medium_count,
                "low_count": session.low_count,
                "reviewed_count": sum(1 for i in session.incidents if i.is_reviewed),
            },
            "ml_evaluation_metrics": session.ml_metrics,
            "agent_audit": {k: v.to_dict() for k, v in session.agent_results.items()},
            "incidents": [inc.to_dict() for inc in session.incidents],
        }
        return json.dumps(data, indent=2)
