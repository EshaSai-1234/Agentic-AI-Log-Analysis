"""
LogSense AI - Shared Data Models
Defines core data structures for log events, incidents, agent results, and analysis sessions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any
import uuid


@dataclass
class LogEvent:
    """Represents a single parsed log entry."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=datetime.utcnow)
    level: str = "INFO"  # DEBUG, INFO, WARN, ERROR, CRITICAL
    service: str = "unknown-service"
    endpoint: Optional[str] = None
    message: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    client_ip: Optional[str] = None
    trace_id: Optional[str] = None
    raw_line: str = ""
    line_number: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            "level": self.level,
            "service": self.service,
            "endpoint": self.endpoint or "N/A",
            "message": self.message,
            "status_code": self.status_code if self.status_code is not None else "",
            "response_time_ms": self.response_time_ms if self.response_time_ms is not None else "",
            "client_ip": self.client_ip or "",
            "trace_id": self.trace_id or "",
            "line_number": self.line_number,
        }


@dataclass
class RootCauseHypothesis:
    """Represents a candidate root cause derived from log evidence."""
    hypothesis: str
    confidence: str  # High, Medium, Low
    confidence_score: float  # 0.0 to 1.0
    evidence: List[str]  # Concrete log messages/evidence lines
    uncertainty_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "uncertainty_note": self.uncertainty_note or "",
        }


@dataclass
class ResolutionAction:
    """Represents an actionable troubleshooting step."""
    action: str
    urgency: str  # Immediate, Short-term, Preventive
    category: str  # Diagnostic, Remediation, Configuration
    diagnostic_command: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "urgency": self.urgency,
            "category": self.category,
            "diagnostic_command": self.diagnostic_command or "",
        }


@dataclass
class Incident:
    """Represents a detected and correlated operational incident."""
    id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    title: str = ""
    category: str = "GENERAL_ERROR"
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    status: str = "OPEN"  # OPEN, INVESTIGATING, REVIEWED
    service: str = "system"
    endpoint: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    event_count: int = 0
    event_ids: List[str] = field(default_factory=list)
    correlated_events: List[LogEvent] = field(default_factory=list)
    detection_reason: str = ""
    detection_method: str = "Rule-based & Pattern Matching"  # or "ML Classifier"
    confidence_score: float = 0.8
    possible_root_causes: List[RootCauseHypothesis] = field(default_factory=list)
    recommended_actions: List[ResolutionAction] = field(default_factory=list)
    is_reviewed: bool = False
    review_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "service": self.service,
            "endpoint": self.endpoint or "N/A",
            "first_seen": self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else str(self.first_seen),
            "last_seen": self.last_seen.isoformat() if isinstance(self.last_seen, datetime) else str(self.last_seen),
            "event_count": self.event_count,
            "event_ids": self.event_ids,
            "detection_reason": self.detection_reason,
            "detection_method": self.detection_method,
            "confidence_score": round(self.confidence_score, 2),
            "possible_root_causes": [c.to_dict() for c in self.possible_root_causes],
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "is_reviewed": self.is_reviewed,
            "review_notes": self.review_notes,
        }


@dataclass
class AgentResult:
    """Execution status and inspectable results from an agent."""
    agent_name: str
    status: str = "SUCCESS"  # SUCCESS, WARNING, ERROR, SKIPPED
    execution_time_ms: float = 0.0
    input_summary: str = ""
    output_summary: str = ""
    findings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "status": self.status,
            "execution_time_ms": round(self.execution_time_ms, 2),
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "findings": self.findings,
            "details": self.details,
        }


@dataclass
class AnalysisSession:
    """Complete container for an analysis execution."""
    session_id: str = field(default_factory=lambda: f"SESS-{uuid.uuid4().hex[:8].upper()}")
    filename: str = "unknown.log"
    created_at: datetime = field(default_factory=datetime.utcnow)
    total_logs: int = 0
    total_incidents: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    parsed_logs: List[LogEvent] = field(default_factory=list)
    incidents: List[Incident] = field(default_factory=list)
    agent_results: Dict[str, AgentResult] = field(default_factory=dict)
    ml_metrics: Dict[str, Any] = field(default_factory=dict)
