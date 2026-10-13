"""
Unit tests for LogParserAgent.
"""

import pytest
from datetime import datetime
from src.log_parser import LogParserAgent
from src.models import LogEvent


def test_parse_standard_text_log():
    agent = LogParserAgent()
    log_text = """
2026-10-12 14:15:30,123 [INFO] [order-service] endpoint=/api/v1/orders/checkout client_ip=192.168.1.50 status=200 latency=45.5ms - Order placed successfully.
2026-10-12 14:15:32,456 [ERROR] [payment-gateway] endpoint=/api/v1/payments/charge status=500 latency=1200ms - Payment timed out.
2026-10-12 14:15:35,789 [CRITICAL] [user-db] service=user-db - Database connection pool exhausted.
"""
    events, result = agent.parse(log_text, filename="app.log")

    assert result.status == "SUCCESS"
    assert len(events) == 3
    assert events[0].service == "order-service"
    assert events[0].level == "INFO"
    assert events[0].status_code == 200
    assert events[0].response_time_ms == 45.5
    assert events[0].endpoint == "/api/v1/orders/checkout"

    assert events[1].level == "ERROR"
    assert events[1].status_code == 500
    assert events[1].response_time_ms == 1200.0

    assert events[2].level == "CRITICAL"
    assert events[2].service == "user-db"


def test_parse_json_lines_log():
    agent = LogParserAgent()
    json_lines = """
{"timestamp": "2026-10-12T14:20:00Z", "level": "INFO", "service": "auth-service", "endpoint": "/api/v1/login", "status_code": 200, "response_time_ms": 35.0, "message": "User authenticated"}
{"timestamp": "2026-10-12T14:20:05Z", "level": "ERROR", "service": "auth-service", "endpoint": "/api/v1/login", "status_code": 401, "response_time_ms": 50.0, "message": "Bad password"}
"""
    events, result = agent.parse(json_lines, filename="app.jsonl")

    assert result.status == "SUCCESS"
    assert len(events) == 2
    assert events[0].level == "INFO"
    assert events[0].service == "auth-service"
    assert events[1].level == "ERROR"
    assert events[1].status_code == 401


def test_parse_csv_log():
    agent = LogParserAgent()
    csv_text = """timestamp,level,service,endpoint,status_code,response_time_ms,message
2026-10-12 14:00:00,INFO,frontend-proxy,/api/v1/items,200,42,Fetched items list
2026-10-12 14:00:02,ERROR,inventory-api,/api/v1/stock,500,150,Item count mismatch
"""
    events, result = agent.parse(csv_text, filename="access.csv")

    assert result.status == "SUCCESS"
    assert len(events) == 2
    assert events[0].service == "frontend-proxy"
    assert events[0].status_code == 200
    assert events[1].level == "ERROR"
    assert events[1].service == "inventory-api"
    assert events[1].status_code == 500


def test_parse_empty_content():
    agent = LogParserAgent()
    events, result = agent.parse("", filename="empty.log")

    assert result.status == "WARNING"
    assert len(events) == 0


def test_parse_malformed_lines_gracefully():
    agent = LogParserAgent()
    mixed = """
2026-10-12 14:00:00 [INFO] [app] OK message
gibberish line without structure
another random line
2026-10-12 14:00:05 [ERROR] [app] Real error
"""
    events, result = agent.parse(mixed, filename="mixed.log")

    assert len(events) >= 2
    assert any(e.level == "ERROR" for e in events)
