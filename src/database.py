"""
LogSense AI - SQLite Database & Persistence Layer
Stores analysis sessions, incidents, correlated log events, agent execution results,
and incident review workflows.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from src.models import AnalysisSession, Incident, LogEvent, AgentResult, RootCauseHypothesis, ResolutionAction

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "logsense.db")


class DatabaseManager:
    """Manages SQLite persistence for LogSense AI."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes SQLite schema tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Analysis Sessions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    session_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    total_logs INTEGER DEFAULT 0,
                    total_incidents INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    ml_metrics_json TEXT,
                    reports_json TEXT
                )
            """)

            # 2. Incidents Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    service TEXT NOT NULL,
                    endpoint TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    event_count INTEGER DEFAULT 0,
                    confidence_score REAL DEFAULT 0.0,
                    detection_reason TEXT,
                    detection_method TEXT,
                    possible_root_causes_json TEXT,
                    recommended_actions_json TEXT,
                    is_reviewed INTEGER DEFAULT 0,
                    review_notes TEXT,
                    FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id) ON DELETE CASCADE
                )
            """)

            # 3. Log Events Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS log_events (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    incident_id TEXT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    service TEXT NOT NULL,
                    endpoint TEXT,
                    message TEXT NOT NULL,
                    status_code INTEGER,
                    response_time_ms REAL,
                    client_ip TEXT,
                    trace_id TEXT,
                    line_number INTEGER,
                    FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id) ON DELETE CASCADE
                )
            """)

            # 4. Agent Executions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    execution_time_ms REAL,
                    input_summary TEXT,
                    output_summary TEXT,
                    findings_json TEXT,
                    details_json TEXT,
                    FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id) ON DELETE CASCADE
                )
            """)

            conn.commit()

    def save_session(self, session: AnalysisSession) -> bool:
        """Persists a complete AnalysisSession including incidents, logs, and agent audit trails."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Save session summary
            reports_dict = session.agent_results.get("Incident Report Agent", AgentResult("Incident Report Agent")).details.get("compiled_reports", {})
            cursor.execute("""
                INSERT OR REPLACE INTO analysis_sessions
                (session_id, filename, created_at, total_logs, total_incidents, critical_count, high_count, medium_count, low_count, ml_metrics_json, reports_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                session.filename,
                session.created_at.isoformat(),
                session.total_logs,
                session.total_incidents,
                session.critical_count,
                session.high_count,
                session.medium_count,
                session.low_count,
                json.dumps(session.ml_metrics),
                json.dumps(reports_dict),
            ))

            # Save Agent Results
            for agent_name, res in session.agent_results.items():
                cursor.execute("""
                    INSERT INTO agent_executions
                    (session_id, agent_name, status, execution_time_ms, input_summary, output_summary, findings_json, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session.session_id,
                    agent_name,
                    res.status,
                    res.execution_time_ms,
                    res.input_summary,
                    res.output_summary,
                    json.dumps(res.findings),
                    json.dumps(res.details, default=str),
                ))

            # Save Incidents
            for inc in session.incidents:
                cursor.execute("""
                    INSERT OR REPLACE INTO incidents
                    (id, session_id, title, category, severity, status, service, endpoint, first_seen, last_seen,
                     event_count, confidence_score, detection_reason, detection_method, possible_root_causes_json,
                     recommended_actions_json, is_reviewed, review_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inc.id,
                    session.session_id,
                    inc.title,
                    inc.category,
                    inc.severity,
                    inc.status,
                    inc.service,
                    inc.endpoint,
                    inc.first_seen.isoformat(),
                    inc.last_seen.isoformat(),
                    inc.event_count,
                    inc.confidence_score,
                    inc.detection_reason,
                    inc.detection_method,
                    json.dumps([h.to_dict() for h in inc.possible_root_causes]),
                    json.dumps([a.to_dict() for a in inc.recommended_actions]),
                    1 if inc.is_reviewed else 0,
                    inc.review_notes,
                ))

                # Save correlated log events for incident
                for ev in inc.correlated_events:
                    cursor.execute("""
                        INSERT OR REPLACE INTO log_events
                        (id, session_id, incident_id, timestamp, level, service, endpoint, message, status_code, response_time_ms, client_ip, trace_id, line_number)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ev.id,
                        session.session_id,
                        inc.id,
                        ev.timestamp.isoformat(),
                        ev.level,
                        ev.service,
                        ev.endpoint,
                        ev.message,
                        ev.status_code,
                        ev.response_time_ms,
                        ev.client_ip,
                        ev.trace_id,
                        ev.line_number,
                    ))

            conn.commit()
            return True

    def list_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent analysis sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT session_id, filename, created_at, total_logs, total_incidents, critical_count, high_count, medium_count, low_count
                FROM analysis_sessions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> Optional[AnalysisSession]:
        """Loads a full session from SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analysis_sessions WHERE session_id = ?", (session_id,))
            s_row = cursor.fetchone()
            if not s_row:
                return None

            session = AnalysisSession(
                session_id=s_row["session_id"],
                filename=s_row["filename"],
                created_at=datetime.fromisoformat(s_row["created_at"]),
                total_logs=s_row["total_logs"],
                total_incidents=s_row["total_incidents"],
                critical_count=s_row["critical_count"],
                high_count=s_row["high_count"],
                medium_count=s_row["medium_count"],
                low_count=s_row["low_count"],
            )

            if s_row["ml_metrics_json"]:
                session.ml_metrics = json.loads(s_row["ml_metrics_json"])

            # Load agent executions
            cursor.execute("SELECT * FROM agent_executions WHERE session_id = ?", (session_id,))
            for a_row in cursor.fetchall():
                session.agent_results[a_row["agent_name"]] = AgentResult(
                    agent_name=a_row["agent_name"],
                    status=a_row["status"],
                    execution_time_ms=a_row["execution_time_ms"],
                    input_summary=a_row["input_summary"] or "",
                    output_summary=a_row["output_summary"] or "",
                    findings=json.loads(a_row["findings_json"] or "[]"),
                    details=json.loads(a_row["details_json"] or "{}"),
                )

            # Load incidents
            cursor.execute("SELECT * FROM incidents WHERE session_id = ? ORDER BY first_seen ASC", (session_id,))
            inc_rows = cursor.fetchall()

            for i_row in inc_rows:
                # Load correlated logs
                cursor.execute("SELECT * FROM log_events WHERE incident_id = ? ORDER BY timestamp ASC", (i_row["id"],))
                events = []
                for ev_row in cursor.fetchall():
                    events.append(LogEvent(
                        id=ev_row["id"],
                        timestamp=datetime.fromisoformat(ev_row["timestamp"]),
                        level=ev_row["level"],
                        service=ev_row["service"],
                        endpoint=ev_row["endpoint"],
                        message=ev_row["message"],
                        status_code=ev_row["status_code"],
                        response_time_ms=ev_row["response_time_ms"],
                        client_ip=ev_row["client_ip"],
                        trace_id=ev_row["trace_id"],
                        line_number=ev_row["line_number"] or 0,
                    ))

                # Deserialize root causes
                raw_rc = json.loads(i_row["possible_root_causes_json"] or "[]")
                root_causes = [
                    RootCauseHypothesis(
                        hypothesis=rc["hypothesis"],
                        confidence=rc["confidence"],
                        confidence_score=rc.get("confidence_score", 0.7),
                        evidence=rc.get("evidence", []),
                        uncertainty_note=rc.get("uncertainty_note", ""),
                    )
                    for rc in raw_rc
                ]

                # Deserialize actions
                raw_act = json.loads(i_row["recommended_actions_json"] or "[]")
                actions = [
                    ResolutionAction(
                        action=a["action"],
                        urgency=a["urgency"],
                        category=a["category"],
                        diagnostic_command=a.get("diagnostic_command"),
                    )
                    for a in raw_act
                ]

                incident = Incident(
                    id=i_row["id"],
                    title=i_row["title"],
                    category=i_row["category"],
                    severity=i_row["severity"],
                    status=i_row["status"],
                    service=i_row["service"],
                    endpoint=i_row["endpoint"],
                    first_seen=datetime.fromisoformat(i_row["first_seen"]),
                    last_seen=datetime.fromisoformat(i_row["last_seen"]),
                    event_count=i_row["event_count"],
                    event_ids=[e.id for e in events],
                    correlated_events=events,
                    detection_reason=i_row["detection_reason"] or "",
                    detection_method=i_row["detection_method"] or "Rule-based & Pattern Matching",
                    confidence_score=i_row["confidence_score"] or 0.8,
                    possible_root_causes=root_causes,
                    recommended_actions=actions,
                    is_reviewed=bool(i_row["is_reviewed"]),
                    review_notes=i_row["review_notes"] or "",
                )
                session.incidents.append(incident)

            return session

    def update_incident_review(self, incident_id: str, is_reviewed: bool, review_notes: str) -> bool:
        """Updates the review status and engineer notes for an incident."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            status = "REVIEWED" if is_reviewed else "INVESTIGATING"
            cursor.execute("""
                UPDATE incidents
                SET is_reviewed = ?, review_notes = ?, status = ?
                WHERE id = ?
            """, (1 if is_reviewed else 0, review_notes, status, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns database storage and incident aggregate statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM analysis_sessions")
            sessions_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents")
            incidents_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM log_events")
            events_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE is_reviewed = 1")
            reviewed_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL'")
            critical_count = cursor.fetchone()[0]

            db_size_kb = os.path.getsize(self.db_path) / 1024 if os.path.exists(self.db_path) else 0

            return {
                "total_sessions": sessions_count,
                "total_incidents": incidents_count,
                "total_events": events_count,
                "reviewed_incidents": reviewed_count,
                "critical_incidents": critical_count,
                "database_size_kb": round(db_size_kb, 1),
            }

    def clear_all_data(self) -> bool:
        """Cleans out all stored sessions, incidents, and logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM log_events")
            cursor.execute("DELETE FROM agent_executions")
            cursor.execute("DELETE FROM incidents")
            cursor.execute("DELETE FROM analysis_sessions")
            conn.commit()
            return True
