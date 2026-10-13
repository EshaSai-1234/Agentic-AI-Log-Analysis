"""
Unit tests for EventCorrelatorAgent.
"""

import pytest
from datetime import datetime, timedelta
from src.event_correlator import EventCorrelatorAgent
from src.models import LogEvent


def test_correlate_by_trace_id():
    correlator = EventCorrelatorAgent()
    now = datetime.utcnow()

    e1 = LogEvent(id="e1", timestamp=now, level="ERROR", service="order-service", trace_id="trace-abc", message="Order failed")
    e2 = LogEvent(id="e2", timestamp=now + timedelta(seconds=2), level="ERROR", service="payment-gateway", trace_id="trace-abc", message="Payment timeout")

    detections = [
        {"event": e1, "category": "HTTP_SERVER_ERROR", "severity": "HIGH", "detection_reason": "500 error"},
        {"event": e2, "category": "HTTP_SERVER_ERROR", "severity": "HIGH", "detection_reason": "Timeout"},
    ]

    incidents, result = correlator.correlate(detections, [e1, e2])

    assert result.status == "SUCCESS"
    assert len(incidents) == 1
    assert incidents[0].event_count == 2
    assert "e1" in incidents[0].event_ids
    assert "e2" in incidents[0].event_ids


def test_correlate_cascading_database_failure():
    correlator = EventCorrelatorAgent(time_window_minutes=5)
    now = datetime.utcnow()

    e_db = LogEvent(id="db1", timestamp=now, level="CRITICAL", service="user-db", message="Database connection pool exhausted")
    e_api = LogEvent(id="api1", timestamp=now + timedelta(seconds=15), level="ERROR", service="order-service", endpoint="/api/v1/checkout", message="HTTP 500 internal server error")

    detections = [
        {"event": e_db, "category": "DATABASE_FAILURE", "severity": "CRITICAL", "detection_reason": "Pool exhausted"},
        {"event": e_api, "category": "HTTP_SERVER_ERROR", "severity": "HIGH", "detection_reason": "500 code"},
    ]

    incidents, result = correlator.correlate(detections, [e_db, e_api])

    # Should cluster into cascading failure incident
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].category == "DATABASE_FAILURE"
