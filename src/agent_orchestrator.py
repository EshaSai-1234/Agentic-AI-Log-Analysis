"""
LogSense AI - Central Agent Orchestrator
Coordinates the end-to-end execution of all 6 specialized agents, managing shared state,
tracking execution metrics, and ensuring inspectable transparency at every stage.
"""

import time
import logging
from typing import Optional, Callable
from src.models import AnalysisSession, AgentResult
from src.log_parser import LogParserAgent
from src.incident_detector import IncidentDetectorAgent
from src.event_correlator import EventCorrelatorAgent
from src.root_cause import RootCauseInvestigationAgent
from src.recommendations import ResolutionRecommendationAgent
from src.report_generator import IncidentReportAgent

logger = logging.getLogger("LogSenseOrchestrator")


class AgentOrchestrator:
    """Coordinates the multi-agent incident intelligence workflow."""

    def __init__(self, slow_request_threshold_ms: float = 1500.0, time_window_minutes: int = 5):
        self.parser_agent = LogParserAgent()
        self.detector_agent = IncidentDetectorAgent(slow_request_threshold_ms=slow_request_threshold_ms)
        self.correlator_agent = EventCorrelatorAgent(time_window_minutes=time_window_minutes)
        self.root_cause_agent = RootCauseInvestigationAgent()
        self.recommendations_agent = ResolutionRecommendationAgent()
        self.report_agent = IncidentReportAgent()

    def run_pipeline(
        self,
        log_content: str,
        filename: str = "logs.log",
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> AnalysisSession:
        """
        Executes the entire 6-agent incident intelligence pipeline.
        Calls optional progress_callback(stage_name, percent_0_to_1).
        """
        session = AnalysisSession(filename=filename)

        # -------------------------------------------------------------
        # STEP 1: Log Parser Agent
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("Agent 1/6: Log Parser Ingesting Logs...", 0.15)

        try:
            parsed_logs, parser_result = self.parser_agent.parse(log_content, filename=filename)
            session.parsed_logs = parsed_logs
            session.total_logs = len(parsed_logs)
            session.agent_results[self.parser_agent.name] = parser_result
        except Exception as e:
            session.agent_results[self.parser_agent.name] = AgentResult(
                agent_name=self.parser_agent.name,
                status="ERROR",
                output_summary=f"Parser execution failed: {str(e)}",
                findings=[f"Unhandled error during log ingestion: {str(e)}"]
            )
            return session

        if not parsed_logs:
            return session

        # -------------------------------------------------------------
        # STEP 2: Incident Detection Agent
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("Agent 2/6: Incident Detection & ML Evaluation...", 0.35)

        candidate_detections = []
        try:
            candidate_detections, detector_result = self.detector_agent.detect_incidents(parsed_logs)
            session.agent_results[self.detector_agent.name] = detector_result
            session.ml_metrics = self.detector_agent.ml_metrics
        except Exception as e:
            session.agent_results[self.detector_agent.name] = AgentResult(
                agent_name=self.detector_agent.name,
                status="ERROR",
                output_summary=f"Incident detection failed: {str(e)}",
                findings=[f"Error during incident detection: {str(e)}"]
            )

        # -------------------------------------------------------------
        # STEP 3: Event Correlation Agent
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("Agent 3/6: Event Correlation & Incident Clustering...", 0.55)

        incidents = []
        try:
            incidents, correlator_result = self.correlator_agent.correlate(candidate_detections, parsed_logs)
            session.incidents = incidents
            session.total_incidents = len(incidents)
            session.agent_results[self.correlator_agent.name] = correlator_result

            # Compute severity tallies
            session.critical_count = sum(1 for i in incidents if i.severity == "CRITICAL")
            session.high_count = sum(1 for i in incidents if i.severity == "HIGH")
            session.medium_count = sum(1 for i in incidents if i.severity == "MEDIUM")
            session.low_count = sum(1 for i in incidents if i.severity == "LOW")
        except Exception as e:
            session.agent_results[self.correlator_agent.name] = AgentResult(
                agent_name=self.correlator_agent.name,
                status="ERROR",
                output_summary=f"Correlation failed: {str(e)}",
                findings=[f"Error during event clustering: {str(e)}"]
            )

        # -------------------------------------------------------------
        # STEP 4: Root Cause Investigation Agent
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("Agent 4/6: Root Cause Investigation & Evidence Extraction...", 0.75)

        try:
            session.incidents, rca_result = self.root_cause_agent.investigate(session.incidents)
            session.agent_results[self.root_cause_agent.name] = rca_result
        except Exception as e:
            session.agent_results[self.root_cause_agent.name] = AgentResult(
                agent_name=self.root_cause_agent.name,
                status="ERROR",
                output_summary=f"Root cause investigation failed: {str(e)}",
                findings=[f"Error during causal analysis: {str(e)}"]
            )

        # -------------------------------------------------------------
        # STEP 5: Resolution Recommendation Agent
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("Agent 5/6: Resolution Recommendation Engine...", 0.90)

        try:
            session.incidents, rec_result = self.recommendations_agent.recommend(session.incidents)
            session.agent_results[self.recommendations_agent.name] = rec_result
        except Exception as e:
            session.agent_results[self.recommendations_agent.name] = AgentResult(
                agent_name=self.recommendations_agent.name,
                status="ERROR",
                output_summary=f"Recommendation engine failed: {str(e)}",
                findings=[f"Error generating remediation runbooks: {str(e)}"]
            )

        # -------------------------------------------------------------
        # STEP 6: Incident Report Agent
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("Agent 6/6: Compiling Incident Post-Mortem Reports...", 1.0)

        try:
            reports, report_result = self.report_agent.generate_reports(session)
            session.agent_results[self.report_agent.name] = report_result
            # Store compiled reports in details
            session.agent_results[self.report_agent.name].details["compiled_reports"] = reports
        except Exception as e:
            session.agent_results[self.report_agent.name] = AgentResult(
                agent_name=self.report_agent.name,
                status="ERROR",
                output_summary=f"Report compilation failed: {str(e)}",
                findings=[f"Error generating audit reports: {str(e)}"]
            )

        return session
