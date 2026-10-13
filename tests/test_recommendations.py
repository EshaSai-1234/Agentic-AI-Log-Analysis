"""
Unit tests for ResolutionRecommendationAgent.
"""

import pytest
from datetime import datetime
from src.recommendations import ResolutionRecommendationAgent
from src.models import Incident, LogEvent


def test_recommendations_database_incident():
    agent = ResolutionRecommendationAgent()
    incident = Incident(
        id="INC-001",
        title="Database Failure",
        category="DATABASE_FAILURE",
        severity="CRITICAL",
        service="user-db",
    )

    incidents, result = agent.recommend([incident])

    assert len(incidents[0].recommended_actions) >= 3
    actions = incidents[0].recommended_actions

    # Check for immediate action with diagnostic command
    immediate = [a for a in actions if a.urgency == "Immediate"]
    assert len(immediate) >= 1
    assert any("pg_stat_activity" in (a.diagnostic_command or "") for a in immediate)


def test_recommendations_auth_attack():
    agent = ResolutionRecommendationAgent()
    e = LogEvent(timestamp=datetime.utcnow(), client_ip="198.51.100.44", message="Failed login")
    incident = Incident(
        id="INC-002",
        title="Brute Force",
        category="SUSPICIOUS_AUTH",
        severity="HIGH",
        service="auth-service",
        correlated_events=[e]
    )

    incidents, _ = agent.recommend([incident])
    actions = incidents[0].recommended_actions

    assert any("rate-limit" in a.action.lower() or "iptables" in (a.diagnostic_command or "").lower() for a in actions)
