"""
Unit tests for IncidentReportAgent and DatabaseManager.
"""

import os
import pytest
import tempfile
from datetime import datetime
from src.report_generator import IncidentReportAgent
from src.database import DatabaseManager
from src.models import AnalysisSession, Incident, LogEvent, RootCauseHypothesis, ResolutionAction, AgentResult


def test_report_generation_formats():
    agent = IncidentReportAgent()
    session = AnalysisSession(
        session_id="SESS-TEST",
        filename="test.log",
        total_logs=100,
        total_incidents=1,
        critical_count=1,
    )
    inc = Incident(
        id="INC-101",
        title="Test Incident",
        category="DATABASE_FAILURE",
        severity="CRITICAL",
        service="user-db",
        possible_root_causes=[
            RootCauseHypothesis(
                hypothesis="Pool exhaustion",
                confidence="High",
                confidence_score=0.9,
                evidence=["Log line 1"],
                uncertainty_note="Needs query logs"
            )
        ],
        recommended_actions=[
            ResolutionAction(
                action="Increase pool",
                urgency="Immediate",
                category="Remediation",
                diagnostic_command="SHOW max_connections;"
            )
        ]
    )
    session.incidents = [inc]
    session.agent_results["Test Agent"] = AgentResult(agent_name="Test Agent", output_summary="OK")

    reports, result = agent.generate_reports(session)

    assert result.status == "SUCCESS"
    assert "txt" in reports
    assert "csv" in reports
    assert "json" in reports

    # TXT checks
    assert "AGENTIC AI LOG ANALYSIS SYSTEM" in reports["txt"]
    assert "INC-101" in reports["txt"]
    assert "Pool exhaustion" in reports["txt"]

    # CSV checks
    csv_lines = reports["csv"].strip().splitlines()
    assert len(csv_lines) == 2  # header + 1 row
    assert "INC-101" in csv_lines[1]


def test_database_persistence_and_retrieval():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    try:
        db = DatabaseManager(db_path=temp_db_path)
        session = AnalysisSession(
            session_id="SESS-DB-1",
            filename="db_test.log",
            total_logs=50,
            total_incidents=1,
            critical_count=1,
        )
        ev = LogEvent(id="ev1", timestamp=datetime.utcnow(), level="CRITICAL", service="auth-service", message="Fatal auth error")
        inc = Incident(
            id="INC-DB-1",
            title="Auth Crash",
            category="UNHANDLED_EXCEPTION",
            severity="CRITICAL",
            service="auth-service",
            correlated_events=[ev],
            possible_root_causes=[RootCauseHypothesis(hypothesis="Null ref", confidence="High", confidence_score=0.95, evidence=[])],
            recommended_actions=[ResolutionAction(action="Hotfix", urgency="Immediate", category="Remediation")]
        )
        session.incidents = [inc]

        # Save
        assert db.save_session(session) is True

        # Retrieve
        loaded = db.get_session("SESS-DB-1")
        assert loaded is not None
        assert loaded.session_id == "SESS-DB-1"
        assert len(loaded.incidents) == 1
        assert loaded.incidents[0].id == "INC-DB-1"
        assert loaded.incidents[0].possible_root_causes[0].hypothesis == "Null ref"

        # Update review
        assert db.update_incident_review("INC-DB-1", is_reviewed=True, review_notes="Verified by Ops team") is True

        # Re-check updated review
        reloaded = db.get_session("SESS-DB-1")
        assert reloaded.incidents[0].is_reviewed is True
        assert reloaded.incidents[0].review_notes == "Verified by Ops team"
        assert reloaded.incidents[0].status == "REVIEWED"

        # List sessions
        sessions = db.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "SESS-DB-1"

    finally:
        import gc
        del db
        gc.collect()
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
