"""
LogSense AI - Incident Detection Agent
Combines deterministic heuristic rules with a lightweight Scikit-learn text/feature classifier
to identify operational incidents, assign severity levels, and explain detection reasoning.
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from src.models import LogEvent, AgentResult


# Seed training data for the lightweight operational risk classifier
SEED_TRAINING_CORPUS = [
    # Normal / Benign (0)
    ("User authenticated successfully via oauth token", 0),
    ("HTTP 200 GET /api/v1/products processed in 35ms", 0),
    ("Health check probe ping /healthz returned status 200 OK", 0),
    ("Cache hit for key user_profile_9281 in 2ms", 0),
    ("Order #9921 placed successfully. Inventory reserved.", 0),
    ("Rendered template index.html for client 192.168.1.5", 0),
    ("Job worker processed 45 background tasks without errors", 0),
    ("Database connection pool initialized with 20 connections", 0),
    ("User session expired normally, redirecting to login", 0),
    ("Payment completed for transaction tx_8892182 via Stripe", 0),
    ("Static assets served from CDN cache hit 200", 0),
    ("Periodic backup snapshot completed successfully", 0),
    ("Queue consumer acked message id 120489", 0),
    ("WebSocket client connected to notifications channel", 0),
    ("Metrics flushed to collector in 12ms", 0),

    # Incidents / Anomalies (1)
    ("Database connection pool exhausted. Timeout waiting for free connection after 30000ms", 1),
    ("HTTP 500 Internal Server Error in POST /api/v1/checkout - unhandled exception", 1),
    ("Failed to connect to database host at 10.0.1.4:5432: Connection refused", 1),
    ("OutOfMemoryError: Java heap space during batch processing", 1),
    ("Deadlock found when trying to get lock; try restarting transaction", 1),
    ("HTTP 503 Service Unavailable: downstream payment-gateway timed out after 5000ms", 1),
    ("Too many failed login attempts for user admin from IP 198.51.100.22 - potential brute force", 1),
    ("NullPointerException at com.app.orders.Service.processOrder line 142", 1),
    ("API latency threshold breached: GET /api/v1/reports took 6400ms (threshold: 1500ms)", 1),
    ("ConnectionResetError: [Errno 104] Connection reset by peer during RPC call", 1),
    ("FATAL: worker process 9912 killed by SIGSEGV (signal 11)", 1),
    ("Redis ConnectionError: Error 111 connecting to 127.0.0.1:6379. Connection refused.", 1),
    ("HTTP 502 Bad Gateway: Upstream server closed connection prematurely", 1),
    ("CRITICAL: Disk space usage on /data is at 99.4% - write operations suspended", 1),
    ("Multiple unauthorized access attempts detected on sensitive endpoint /admin/keys", 1),
]


class IncidentDetectorAgent:
    """Agent responsible for identifying incident candidate events and calculating severity."""

    # Heuristic Rule Patterns
    DB_FAIL_PATTERNS = [
        re.compile(r"connection (?:timeout|refused|reset|exhausted|closed)", re.I),
        re.compile(r"(?:database|db|postgres|mysql|redis|mongodb) .*?(?:fail|down|unavailable|deadlock|timeout)", re.I),
        re.compile(r"pool exhausted|no free connections|max clients reached", re.I),
    ]

    EXCEPTION_PATTERNS = [
        re.compile(r"(?:NullPointer|KeyError|IndexError|ValueError|TypeError|AttributeError|ZeroDivisionError)Exception", re.I),
        re.compile(r"(?:UnhandledException|Panic|Traceback \(most recent call last\)|SIGSEGV|Segmentation fault)", re.I),
        re.compile(r"OutOfMemory|OOMKilled|Java heap space|memory limit exceeded", re.I),
    ]

    AUTH_ATTACK_PATTERNS = [
        re.compile(r"(?:failed login|invalid credentials|unauthorized|bad password|authentication failed)", re.I),
        re.compile(r"(?:brute force|multiple failed attempts|account locked|credential stuffing)", re.I),
    ]

    DEGRADATION_PATTERNS = [
        re.compile(r"(?:service restarted|worker killed|pod crashed|crashloopbackoff|high memory usage|cpu throttle)", re.I),
        re.compile(r"(?:circuit breaker opened|fallback triggered|rate limit exceeded|throttling requests)", re.I),
    ]

    def __init__(self, slow_request_threshold_ms: float = 1500.0, error_burst_threshold: int = 3):
        self.name = "Incident Detection Agent"
        self.slow_request_threshold_ms = slow_request_threshold_ms
        self.error_burst_threshold = error_burst_threshold
        self.ml_model = None
        self.vectorizer = None
        self.ml_metrics: Dict[str, Any] = {}
        self._train_and_evaluate_ml()

    def _train_and_evaluate_ml(self):
        """Trains a lightweight Scikit-learn text classifier and records validation metrics."""
        texts = [item[0] for item in SEED_TRAINING_CORPUS]
        labels = [item[1] for item in SEED_TRAINING_CORPUS]

        # Train/test split with stratified labels
        X_train_text, X_test_text, y_train, y_test = train_test_split(
            texts, labels, test_size=0.33, random_state=42, stratify=labels
        )

        self.vectorizer = TfidfVectorizer(max_features=250, ngram_range=(1, 2), lowercase=True)
        X_train = self.vectorizer.fit_transform(X_train_text)
        X_test = self.vectorizer.transform(X_test_text)

        clf = LogisticRegression(C=1.0, max_iter=200, random_state=42)
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)

        self.ml_model = clf
        self.ml_metrics = {
            "model_type": "TF-IDF + LogisticRegression (Scikit-Learn)",
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "training_samples": len(X_train_text),
            "test_samples": len(X_test_text),
        }

    def predict_ml_incident_score(self, message: str) -> float:
        """Returns the ML probability that this message indicates an operational incident."""
        if not self.ml_model or not self.vectorizer:
            return 0.5
        try:
            vec = self.vectorizer.transform([message])
            probs = self.ml_model.predict_proba(vec)[0]
            # Class 1 is incident
            return float(probs[1])
        except Exception:
            return 0.5

    def detect_incidents(self, events: List[LogEvent]) -> Tuple[List[Dict[str, Any]], AgentResult]:
        """
        Scans all log events using rules + ML to detect incident events.
        Returns candidate incident detections and agent metadata.
        """
        import time
        start_time = time.time()
        agent_result = AgentResult(agent_name=self.name)

        if not events:
            agent_result.status = "WARNING"
            agent_result.output_summary = "No log events provided to analyze."
            agent_result.execution_time_ms = 0.0
            return [], agent_result

        detected_candidates: List[Dict[str, Any]] = []

        # 1. Check for temporal bursts of error logs (Sliding Window: 3 mins)
        burst_event_ids = self._detect_error_bursts(events, window_minutes=3, threshold=self.error_burst_threshold)

        # 2. Check for brute-force auth bursts (Sliding Window: 5 mins)
        auth_burst_event_ids = self._detect_auth_bursts(events, window_minutes=5, threshold=3)

        # 3. Analyze each event with multi-rule detection & ML verification
        for ev in events:
            is_incident = False
            reasons = []
            category = "GENERAL_ERROR"
            severity = "LOW"
            rule_matched = None

            # ML incident probability
            ml_score = self.predict_ml_incident_score(ev.message)

            # Heuristic Rule 1: Database Failure
            if any(p.search(ev.message) for p in self.DB_FAIL_PATTERNS):
                is_incident = True
                category = "DATABASE_FAILURE"
                severity = "CRITICAL" if ("pool exhausted" in ev.message.lower() or "deadlock" in ev.message.lower() or ev.level == "CRITICAL") else "HIGH"
                rule_matched = "Database connectivity failure or pool exhaustion detected"
                reasons.append(f"Matched Database Failure rule (Severity: {severity})")

            # Heuristic Rule 2: HTTP 5xx Server Errors
            elif (ev.status_code and 500 <= ev.status_code < 600) or ("500 internal server error" in ev.message.lower()) or ("503 service unavailable" in ev.message.lower()) or ("502 bad gateway" in ev.message.lower()):
                is_incident = True
                category = "HTTP_SERVER_ERROR"
                severity = "CRITICAL" if (ev.status_code == 503 or "503" in ev.message) else "HIGH"
                rule_matched = f"HTTP {ev.status_code or 500} Server Error on endpoint {ev.endpoint or 'service'}"
                reasons.append(f"Server response code indicates backend failure (HTTP {ev.status_code or 500})")

            # Heuristic Rule 3: Unhandled Exceptions / Fatal Panics
            elif any(p.search(ev.message) for p in self.EXCEPTION_PATTERNS) or ev.level in ["CRITICAL", "FATAL"]:
                is_incident = True
                category = "UNHANDLED_EXCEPTION"
                severity = "CRITICAL" if any(k in ev.message.lower() for k in ["outofmemory", "oom", "panic", "fatal", "sigsegv"]) else "HIGH"
                rule_matched = "Unhandled runtime exception / crash signature"
                reasons.append(f"StackTrace/Crash signature detected in log payload")

            # Heuristic Rule 4: Slow API Requests
            elif (ev.response_time_ms is not None and ev.response_time_ms >= self.slow_request_threshold_ms):
                is_incident = True
                category = "SLOW_RESPONSE"
                severity = "HIGH" if ev.response_time_ms >= (self.slow_request_threshold_ms * 2.5) else "MEDIUM"
                rule_matched = f"High latency breached SLA threshold ({ev.response_time_ms:.1f}ms >= {self.slow_request_threshold_ms:.1f}ms)"
                reasons.append(f"Response latency of {ev.response_time_ms:.1f}ms exceeds {self.slow_request_threshold_ms}ms threshold")

            # Heuristic Rule 5: Suspicious Authentication Pattern
            elif ev.id in auth_burst_event_ids or any(p.search(ev.message) for p in self.AUTH_ATTACK_PATTERNS):
                if ev.id in auth_burst_event_ids or ev.level in ["WARN", "ERROR"] or (ev.status_code and ev.status_code in [401, 403]):
                    is_incident = True
                    category = "SUSPICIOUS_AUTH"
                    severity = "HIGH" if ev.id in auth_burst_event_ids else "MEDIUM"
                    rule_matched = "Repeated authentication failures / potential credential attack"
                    reasons.append("Authentication failure pattern or brute-force threshold reached")

            # Heuristic Rule 6: Service Degradation
            elif any(p.search(ev.message) for p in self.DEGRADATION_PATTERNS):
                is_incident = True
                category = "SERVICE_DEGRADATION"
                severity = "HIGH" if "crashed" in ev.message.lower() or "restarted" in ev.message.lower() else "MEDIUM"
                rule_matched = "Service restart / container degradation indicator"
                reasons.append("Platform service health degradation detected")

            # Heuristic Rule 7: Error Burst Member
            elif ev.id in burst_event_ids and ev.level in ["ERROR", "CRITICAL"]:
                is_incident = True
                category = "REPEATED_ERRORS"
                severity = "HIGH"
                rule_matched = f"High error density: Part of rapid {self.error_burst_threshold}+ error burst"
                reasons.append("Clustered error frequency anomaly")

            # Rule 8: Generic ERROR log level fallback
            elif ev.level in ["ERROR", "CRITICAL"]:
                is_incident = True
                category = "GENERAL_ERROR"
                severity = "HIGH" if ev.level == "CRITICAL" else "MEDIUM"
                rule_matched = f"Explicit log severity flag: {ev.level}"
                reasons.append(f"Logged with explicit {ev.level} severity")

            # Rule 9: ML Anomaly Detector (high confidence ML classification without explicit rule)
            elif ml_score >= 0.75:
                is_incident = True
                category = "ANOMALY_ML"
                severity = "MEDIUM"
                rule_matched = f"ML Incident Classifier triggered (Risk Score: {ml_score:.2f})"
                reasons.append(f"NLP Feature classifier assigned {ml_score*100:.1f}% incident probability")

            if is_incident:
                # Calculate combined confidence score
                confidence = 0.70
                if rule_matched and ml_score > 0.60:
                    confidence = 0.95
                elif rule_matched:
                    confidence = 0.85
                elif ml_score > 0.75:
                    confidence = round(ml_score, 2)

                detected_candidates.append({
                    "event": ev,
                    "category": category,
                    "severity": severity,
                    "rule_matched": rule_matched or "Operational threshold trigger",
                    "detection_reason": "; ".join(reasons),
                    "confidence_score": confidence,
                    "ml_score": round(ml_score, 3),
                })

        execution_time_ms = (time.time() - start_time) * 1000

        # Summary findings
        cat_counts = defaultdict(int)
        sev_counts = defaultdict(int)
        for cand in detected_candidates:
            cat_counts[cand["category"]] += 1
            sev_counts[cand["severity"]] += 1

        agent_result.status = "SUCCESS" if detected_candidates else "WARNING"
        agent_result.execution_time_ms = execution_time_ms
        agent_result.input_summary = f"Scanned {len(events)} log events across rules and ML models."
        agent_result.output_summary = (
            f"Detected {len(detected_candidates)} anomalous/incident log events. "
            f"Breakdown by severity: {sev_counts.get('CRITICAL', 0)} Critical, {sev_counts.get('HIGH', 0)} High, "
            f"{sev_counts.get('MEDIUM', 0)} Medium, {sev_counts.get('LOW', 0)} Low."
        )
        agent_result.findings = [
            f"Flagged {len(detected_candidates)} incident candidate events using 7 heuristic rules and TF-IDF ML model.",
            f"Top incident categories: {', '.join([f'{k} ({v})' for k, v in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:4]])}.",
            f"ML Classifier Performance: Accuracy={self.ml_metrics.get('accuracy', 0):.2%}, F1={self.ml_metrics.get('f1_score', 0):.2%}, Precision={self.ml_metrics.get('precision', 0):.2%}.",
            f"Critical-tier events requiring immediate correlation: {sev_counts.get('CRITICAL', 0)}.",
        ]
        agent_result.details = {
            "total_candidates": len(detected_candidates),
            "severity_counts": dict(sev_counts),
            "category_counts": dict(cat_counts),
            "ml_model_metrics": self.ml_metrics,
        }

        return detected_candidates, agent_result

    def _detect_error_bursts(self, events: List[LogEvent], window_minutes: int = 3, threshold: int = 3) -> set:
        """Finds log events that occur inside a high-frequency burst of errors."""
        burst_ids = set()
        error_events = [e for e in events if e.level in ["ERROR", "CRITICAL"]]
        if len(error_events) < threshold:
            return burst_ids

        window = timedelta(minutes=window_minutes)
        for i, ev in enumerate(error_events):
            cluster = [ev]
            for j in range(i + 1, len(error_events)):
                diff = abs((error_events[j].timestamp - ev.timestamp).total_seconds())
                if diff <= window.total_seconds():
                    cluster.append(error_events[j])
                else:
                    break
            if len(cluster) >= threshold:
                for c in cluster:
                    burst_ids.add(c.id)

        return burst_ids

    def _detect_auth_bursts(self, events: List[LogEvent], window_minutes: int = 5, threshold: int = 3) -> set:
        """Detects bursts of authentication failures, grouped by client IP or service."""
        auth_burst_ids = set()
        auth_events = []
        for e in events:
            is_auth_fail = (
                (e.status_code in [401, 403]) or
                any(p.search(e.message) for p in self.AUTH_ATTACK_PATTERNS) or
                ("login" in (e.endpoint or "").lower() and e.level in ["WARN", "ERROR"])
            )
            if is_auth_fail:
                auth_events.append(e)

        if len(auth_events) < threshold:
            return auth_burst_ids

        # Group by IP (or 'global' if ip not present)
        by_ip = defaultdict(list)
        for e in auth_events:
            key = e.client_ip or e.service
            by_ip[key].append(e)

        window_sec = window_minutes * 60
        for key, ev_list in by_ip.items():
            if len(ev_list) < threshold:
                continue
            for i, ev in enumerate(ev_list):
                cluster = [ev]
                for j in range(i + 1, len(ev_list)):
                    if abs((ev_list[j].timestamp - ev.timestamp).total_seconds()) <= window_sec:
                        cluster.append(ev_list[j])
                if len(cluster) >= threshold:
                    for c in cluster:
                        auth_burst_ids.add(c.id)

        return auth_burst_ids
