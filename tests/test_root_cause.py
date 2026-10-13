"""
Unit tests for RootCauseInvestigationAgent.
"""

import pytest
from datetime import datetime
from src.root_cause import RootCauseInvestigationAgent
from src.models import Incident, LogEvent


def test_root_cause_database_pool_exhaustion():
    agent = RootCauseInvestigationAgent()
    now = datetime.utcnow()

    e1 = LogEvent(timestamp=now, level="CRITICAL", service="user-db", message="Database connection pool exhausted: 100/100 connections.")
    e2 = LogEvent(timestamp=now, level="ERROR", service="order-service", endpoint="/checkout", message="HTTP 500 error on checkout.")

    incident = Incident(
        id="INC-001",
        title="DB Failure",
        category="DATABASE_FAILURE",
        severity="CRITICAL",
        service="user-db",
        correlated_events=[e1, e2]
    )

    incidents, result = agent.investigate([incident])

    assert len(incidents[0].possible_root_causes) >= 1
    primary = incidents[0].possible_root_causes[0]
    assert "Pool Exhaustion" in primary.hypothesis or "connection" in primary.hypothesis.lower()
    assert len(primary.evidence) > 0
    assert primary.uncertainty_note is not None
    assert primary.confidence in ["High", "Medium", "Low"]
    # Verify strict non-confirmation wording
    assert "confirmed" not in primary.hypothesis.lower()


def test_root_cause_uncertainty_handling_for_sparse_logs():
    agent = RootCauseInvestigationAgent()
    incident = Incident(
        id="INC-002",
        title="Sparse Anomaly",
        category="GENERAL_ERROR",
        severity="LOW",
        service="unknown",
        correlated_events=[]
    )

    incidents, result = agent.investigate([incident])
    primary = incidents[0].possible_root_causes[0]

    assert primary.confidence == "Low"
    assert primary.uncertainty_note is not None
    assert "required" in primary.uncertainty_note.lower() or "monitoring" in primary.uncertainty_note.lower()
