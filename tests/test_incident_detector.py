"""
Unit tests for IncidentDetectorAgent.
"""

import pytest
from datetime import datetime, timedelta
from src.incident_detector import IncidentDetectorAgent
from src.models import LogEvent


def test_detect_database_failure():
    detector = IncidentDetectorAgent()
    event = LogEvent(
        timestamp=datetime.utcnow(),
        level="CRITICAL",
        service="user-db",
        message="Database connection pool exhausted: 100/100 connections in use. Timeout waiting for free slot.",
    )
    candidates, result = detector.detect_incidents([event])

    assert len(candidates) == 1
    assert candidates[0]["category"] == "DATABASE_FAILURE"
    assert candidates[0]["severity"] == "CRITICAL"
    assert candidates[0]["confidence_score"] >= 0.8


def test_detect_http_500():
    detector = IncidentDetectorAgent()
    event = LogEvent(
        timestamp=datetime.utcnow(),
        level="ERROR",
        service="order-service",
        endpoint="/api/v1/orders/checkout",
        status_code=500,
        message="HTTP 500 Internal Server Error in order checkout",
    )
    candidates, result = detector.detect_incidents([event])

    assert len(candidates) == 1
    assert candidates[0]["category"] == "HTTP_SERVER_ERROR"
    assert candidates[0]["severity"] in ["HIGH", "CRITICAL"]


def test_detect_slow_api_request():
    detector = IncidentDetectorAgent(slow_request_threshold_ms=1500.0)
    normal_event = LogEvent(
        timestamp=datetime.utcnow(),
        level="INFO",
        service="order-service",
        endpoint="/api/v1/products",
        response_time_ms=80.0,
        message="OK",
    )
    slow_event = LogEvent(
        timestamp=datetime.utcnow(),
        level="WARN",
        service="order-service",
        endpoint="/api/v1/reports",
        response_time_ms=4200.0,
        message="Slow query execution",
    )
    candidates, _ = detector.detect_incidents([normal_event, slow_event])

    assert len(candidates) == 1
    assert candidates[0]["category"] == "SLOW_RESPONSE"
    assert candidates[0]["event"].id == slow_event.id


def test_detect_unhandled_exception():
    detector = IncidentDetectorAgent()
    event = LogEvent(
        timestamp=datetime.utcnow(),
        level="ERROR",
        service="inventory-api",
        endpoint="/api/v1/stock",
        message="Unhandled NullPointerException: item reference is null at Service.java:44",
    )
    candidates, _ = detector.detect_incidents([event])

    assert len(candidates) == 1
    assert candidates[0]["category"] == "UNHANDLED_EXCEPTION"


def test_detect_suspicious_auth_burst():
    detector = IncidentDetectorAgent()
    now = datetime.utcnow()
    # 4 failed logins from same IP in short succession
    events = [
        LogEvent(
            timestamp=now + timedelta(seconds=i * 10),
            level="WARN",
            service="auth-service",
            endpoint="/api/v1/login",
            client_ip="198.51.100.99",
            status_code=401,
            message=f"Authentication failed: invalid password for attempt {i}",
        )
        for i in range(4)
    ]
    candidates, _ = detector.detect_incidents(events)

    assert len(candidates) >= 1
    assert any(c["category"] == "SUSPICIOUS_AUTH" for c in candidates)


def test_ml_model_evaluation_metrics():
    detector = IncidentDetectorAgent()
    metrics = detector.ml_metrics

    assert "accuracy" in metrics
    assert "f1_score" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert metrics["accuracy"] >= 0.0
