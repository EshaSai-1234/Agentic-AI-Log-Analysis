"""
LogSense AI - Log Parser Agent
Parses unstructured .log, .txt, and structured .csv files into standardized LogEvent objects.
"""

import re
import io
import html
import json
import csv
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from src.models import LogEvent, AgentResult


class LogParserAgent:
    """Agent responsible for ingesting, validating, and parsing diverse log formats."""

    MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB safety threshold
    MAX_LINES_DEFAULT = 50000  # Cap processing for responsiveness

    # Common regex patterns for timestamp matching
    TIMESTAMP_PATTERNS = [
        # ISO8601: 2026-10-12T14:15:30.123Z or 2026-10-12 14:15:30,123
        (re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)"), "%Y-%m-%d %H:%M:%S"),
        # Bracketed: [2026-10-12 14:15:30]
        (re.compile(r"^\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\]"), "%Y-%m-%d %H:%M:%S"),
        # Nginx/Apache: 12/Oct/2026:14:15:30 +0000
        (re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]"), "%d/%b/%Y:%H:%M:%S %z"),
        # Syslog: Oct 12 14:15:30
        (re.compile(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    ]

    # Pattern for log level: [ERROR], ERROR:, Level=ERROR
    LEVEL_PATTERN = re.compile(
        r"(?:\[|\b)(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)(?:\]|\b|:)",
        re.IGNORECASE,
    )

    # Pattern for service/app name: [auth-service] or service=auth-service or app=auth-service
    SERVICE_PATTERN = re.compile(
        r"(?:\[([a-zA-Z0-9_-]+(?:-service|-api|-app|-db|-worker|-proxy|[a-zA-Z0-9_-]*))\]|service=([a-zA-Z0-9_-]+)|app=([a-zA-Z0-9_-]+))",
        re.IGNORECASE,
    )

    # Pattern for endpoint / HTTP path: GET /api/v1/orders or path=/api/v1/orders
    ENDPOINT_PATTERN = re.compile(
        r"(?:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([/\w\-._~%]+)|endpoint=([/\w\-._~%]+)|path=([/\w\-._~%]+)|([/][a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)+))"
    )

    # Pattern for HTTP status code: 200, 404, 500, etc.
    STATUS_CODE_PATTERN = re.compile(
        r"(?:status(?:_code)?=|\sHTTP/\d\.\d\"\s|\sstatus\s)(\d{3})\b"
    )

    # Pattern for response time / latency: 450ms, 1.25s, latency=450ms, response_time=120
    LATENCY_PATTERN = re.compile(
        r"(?:(?:latency|duration|response_time|took)[=: ]\s*(\d+(?:\.\d+)?)\s*(ms|s)?|(\d+(?:\.\d+)?)\s*(ms|s)\b)",
        re.IGNORECASE,
    )

    # Pattern for IP addresses
    IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    # Pattern for trace/request IDs: trace_id=xyz or req_id=abc or [trace-1234]
    TRACE_PATTERN = re.compile(
        r"(?:trace[-_]?id[=:]\s*([a-zA-Z0-9-]+)|req[-_]?id[=:]\s*([a-zA-Z0-9-]+)|\[trace:([a-zA-Z0-9-]+)\])",
        re.IGNORECASE,
    )

    def __init__(self):
        self.name = "Log Parser Agent"

    def parse(self, content: str, filename: str = "logs.log", max_lines: int = MAX_LINES_DEFAULT) -> Tuple[List[LogEvent], AgentResult]:
        """
        Main entry point to parse log text or csv content into LogEvent objects.
        Returns parsed log events and the agent execution result.
        """
        import time
        start_time = time.time()
        agent_result = AgentResult(agent_name=self.name)

        if not content or not content.strip():
            agent_result.status = "WARNING"
            agent_result.output_summary = "Empty log file provided."
            agent_result.findings.append("No log entries detected in the input.")
            agent_result.execution_time_ms = (time.time() - start_time) * 1000
            return [], agent_result

        # Check payload size
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > self.MAX_FILE_SIZE_BYTES:
            agent_result.status = "WARNING"
            agent_result.findings.append(f"File size ({content_bytes / (1024*1024):.2f} MB) exceeded 50MB limit; analyzing first 50MB.")
            content = content[:self.MAX_FILE_SIZE_BYTES]

        # Determine file type
        filename_lower = filename.lower()
        if filename_lower.endswith(".csv"):
            events, parse_stats = self._parse_csv(content, max_lines)
        else:
            events, parse_stats = self._parse_text(content, max_lines)

        execution_time_ms = (time.time() - start_time) * 1000

        # Calculate severity counts
        level_counts = {}
        for ev in events:
            level_counts[ev.level] = level_counts.get(ev.level, 0) + 1

        agent_result.status = "SUCCESS" if events else "WARNING"
        agent_result.execution_time_ms = execution_time_ms
        agent_result.input_summary = f"Processed file '{filename}' ({parse_stats['total_lines']} total lines, format: {parse_stats['format_detected']})"
        agent_result.output_summary = (
            f"Successfully parsed {len(events)} events ({parse_stats['failed_lines']} malformed/skipped lines). "
            f"Severity breakdown: {', '.join([f'{k}: {v}' for k, v in sorted(level_counts.items())])}"
        )
        agent_result.findings = [
            f"Parsed {len(events)} valid operational log entries from {filename}.",
            f"Identified {len(set(ev.service for ev in events))} unique applications/services.",
            f"Severity distribution: {level_counts.get('CRITICAL', 0)} Critical, {level_counts.get('ERROR', 0)} Error, {level_counts.get('WARN', 0)} Warn, {level_counts.get('INFO', 0)} Info.",
            f"Detected {len(set(ev.endpoint for ev in events if ev.endpoint))} unique API endpoints."
        ]
        agent_result.details = {
            "total_lines": parse_stats["total_lines"],
            "parsed_events": len(events),
            "failed_lines": parse_stats["failed_lines"],
            "format": parse_stats["format_detected"],
            "level_counts": level_counts,
            "services_found": list(set(ev.service for ev in events))[:15],
            "first_timestamp": events[0].timestamp.isoformat() if events else None,
            "last_timestamp": events[-1].timestamp.isoformat() if events else None,
        }

        return events, agent_result

    def _parse_text(self, content: str, max_lines: int) -> Tuple[List[LogEvent], Dict[str, Any]]:
        """Parses unstructured or line-based text logs (including JSON lines)."""
        lines = content.splitlines()
        total_lines = len(lines)
        parsed_events: List[LogEvent] = []
        failed_lines = 0
        format_detected = "Unstructured/Standard"

        # Check if first non-empty lines are JSON lines
        first_few = [l.strip() for l in lines[:10] if l.strip()]
        if first_few and all(l.startswith("{") and l.endswith("}") for l in first_few):
            format_detected = "JSON Lines"
            for i, line in enumerate(lines[:max_lines], start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    data = json.loads(clean_line)
                    event = self._parse_json_dict(data, clean_line, i)
                    parsed_events.append(event)
                except Exception:
                    failed_lines += 1
            return parsed_events, {"total_lines": total_lines, "failed_lines": failed_lines, "format_detected": format_detected}

        # Otherwise parse line-by-line using heuristics & regex
        for i, line in enumerate(lines[:max_lines], start=1):
            clean_line = line.strip()
            if not clean_line:
                continue

            event = self._parse_single_text_line(clean_line, i)
            if event:
                parsed_events.append(event)
            else:
                failed_lines += 1

        # Sort events by timestamp if possible
        try:
            parsed_events.sort(key=lambda e: e.timestamp)
        except Exception:
            pass

        return parsed_events, {"total_lines": total_lines, "failed_lines": failed_lines, "format_detected": format_detected}

    def _parse_single_text_line(self, line: str, line_number: int) -> Optional[LogEvent]:
        """Parses a single text log line using regex extraction."""
        # 1. Timestamp extraction
        ts = self._extract_timestamp(line)
        if not ts:
            ts = datetime.utcnow()

        # 2. Level extraction
        level = "INFO"
        level_match = self.LEVEL_PATTERN.search(line)
        if level_match:
            lvl = level_match.group(1).upper()
            if lvl == "WARNING":
                level = "WARN"
            elif lvl == "FATAL":
                level = "CRITICAL"
            else:
                level = lvl

        # 3. Service / Application extraction
        service = "application"
        known_levels = {"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"}
        explicit_svc = re.search(r"(?:service|app)=([a-zA-Z0-9_-]+)", line, re.I)
        if explicit_svc:
            service = explicit_svc.group(1)
        else:
            all_bracket_matches = re.findall(r"\[([a-zA-Z0-9_\-\.]+)\]", line)
            service_bracket = next(
                (b for b in all_bracket_matches 
                 if b.upper() not in known_levels 
                 and not re.match(r"^\d{4}", b) 
                 and not b.lower().startswith("trace:")),
                None
            )
            if service_bracket:
                service = service_bracket
            else:
                for kw in ["auth", "payment", "order", "inventory", "database", "gateway", "frontend", "worker", "user-db"]:
                    if kw in line.lower():
                        service = kw if "-" in kw else f"{kw}-service"
                        break

        # 4. Endpoint extraction
        endpoint = None
        ep_match = self.ENDPOINT_PATTERN.search(line)
        if ep_match:
            for g in ep_match.groups():
                if g and g.startswith("/"):
                    endpoint = g
                    break

        # 5. Status code extraction
        status_code = None
        sc_match = self.STATUS_CODE_PATTERN.search(line)
        if sc_match:
            try:
                status_code = int(sc_match.group(1))
            except ValueError:
                pass

        # 6. Latency extraction
        response_time_ms = None
        lat_match = self.LATENCY_PATTERN.search(line)
        if lat_match:
            val_str = lat_match.group(1) or lat_match.group(3)
            unit_str = (lat_match.group(2) or lat_match.group(4) or "ms").lower()
            try:
                val = float(val_str)
                response_time_ms = val * 1000 if unit_str == "s" else val
            except ValueError:
                pass

        # 7. Client IP extraction
        client_ip = None
        ip_match = self.IP_PATTERN.search(line)
        if ip_match:
            client_ip = ip_match.group(1)

        # 8. Trace ID extraction
        trace_id = None
        tr_match = self.TRACE_PATTERN.search(line)
        if tr_match:
            trace_id = next(g for g in tr_match.groups() if g is not None)

        # Sanitize message
        safe_line = html.escape(line)

        return LogEvent(
            timestamp=ts,
            level=level,
            service=service,
            endpoint=endpoint,
            message=safe_line,
            status_code=status_code,
            response_time_ms=response_time_ms,
            client_ip=client_ip,
            trace_id=trace_id,
            raw_line=safe_line,
            line_number=line_number,
        )

    def _parse_json_dict(self, data: Dict[str, Any], raw_line: str, line_number: int) -> LogEvent:
        """Parses a structured JSON dictionary into a LogEvent."""
        # Find timestamp
        ts = None
        for key in ["timestamp", "time", "@timestamp", "datetime", "date"]:
            if key in data:
                ts = self._parse_iso_or_custom(str(data[key]))
                break
        if not ts:
            ts = datetime.utcnow()

        # Level
        level = "INFO"
        for key in ["level", "severity", "log_level", "loglevel"]:
            if key in data:
                lvl = str(data[key]).upper()
                if lvl in ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"]:
                    level = "WARN" if lvl == "WARNING" else ("CRITICAL" if lvl == "FATAL" else lvl)
                    break

        # Service
        service = "application"
        for key in ["service", "app", "application", "service_name", "component"]:
            if key in data:
                service = str(data[key])
                break

        # Message
        message = ""
        for key in ["message", "msg", "log", "text"]:
            if key in data:
                message = str(data[key])
                break
        if not message:
            message = json.dumps(data)

        # Endpoint
        endpoint = data.get("endpoint") or data.get("path") or data.get("url") or data.get("uri")

        # Status code
        status_code = None
        for key in ["status_code", "status", "http_status", "code"]:
            if key in data and str(data[key]).isdigit():
                status_code = int(data[key])
                break

        # Response time
        response_time_ms = None
        for key in ["response_time_ms", "latency_ms", "duration_ms", "latency", "response_time"]:
            if key in data:
                try:
                    response_time_ms = float(data[key])
                except (ValueError, TypeError):
                    pass
                break

        client_ip = data.get("client_ip") or data.get("ip") or data.get("remote_addr")
        trace_id = data.get("trace_id") or data.get("request_id") or data.get("req_id")

        return LogEvent(
            timestamp=ts,
            level=level,
            service=service,
            endpoint=endpoint,
            message=html.escape(message),
            status_code=status_code,
            response_time_ms=response_time_ms,
            client_ip=client_ip,
            trace_id=trace_id,
            raw_line=html.escape(raw_line),
            line_number=line_number,
        )

    def _parse_csv(self, content: str, max_lines: int) -> Tuple[List[LogEvent], Dict[str, Any]]:
        """Parses CSV logs mapping common column names."""
        reader = csv.reader(io.StringIO(content))
        events: List[LogEvent] = []
        failed = 0
        total = 0

        try:
            headers = next(reader)
        except StopIteration:
            return [], {"total_lines": 0, "failed_lines": 0, "format_detected": "Empty CSV"}

        total += 1
        headers_lower = [h.strip().lower() for h in headers]

        # Map column positions
        col_map = {
            "timestamp": self._find_col(headers_lower, ["timestamp", "time", "@timestamp", "date", "datetime"]),
            "level": self._find_col(headers_lower, ["level", "severity", "loglevel", "log_level", "type"]),
            "service": self._find_col(headers_lower, ["service", "app", "application", "component"]),
            "message": self._find_col(headers_lower, ["message", "msg", "log", "text", "description", "event"]),
            "endpoint": self._find_col(headers_lower, ["endpoint", "path", "url", "route", "api"]),
            "status_code": self._find_col(headers_lower, ["status_code", "status", "http_status", "code"]),
            "response_time_ms": self._find_col(headers_lower, ["response_time_ms", "latency_ms", "latency", "response_time", "duration"]),
            "client_ip": self._find_col(headers_lower, ["client_ip", "ip", "remote_ip", "ip_address"]),
            "trace_id": self._find_col(headers_lower, ["trace_id", "request_id", "req_id", "correlation_id"]),
        }

        for row in reader:
            total += 1
            if len(events) >= max_lines:
                break
            if not row or all(not cell.strip() for cell in row):
                continue
            try:
                def get_val(key):
                    idx = col_map.get(key)
                    if idx is not None and idx < len(row):
                        return row[idx].strip()
                    return ""

                ts_str = get_val("timestamp")
                ts = self._parse_iso_or_custom(ts_str) if ts_str else datetime.utcnow()

                raw_lvl = get_val("level").upper() or "INFO"
                level = "WARN" if raw_lvl == "WARNING" else ("CRITICAL" if raw_lvl in ["FATAL", "PANIC"] else raw_lvl)
                if level not in ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]:
                    level = "INFO"

                svc = get_val("service") or "application"
                msg = get_val("message") or ",".join(row)
                ep = get_val("endpoint") or None
                sc_str = get_val("status_code")
                sc = int(sc_str) if sc_str.isdigit() else None
                rt_str = get_val("response_time_ms")
                try:
                    rt = float(rt_str) if rt_str else None
                except ValueError:
                    rt = None

                ip = get_val("client_ip") or None
                tr = get_val("trace_id") or None

                raw_row = ",".join(row)

                event = LogEvent(
                    timestamp=ts,
                    level=level,
                    service=svc,
                    endpoint=ep,
                    message=html.escape(msg),
                    status_code=sc,
                    response_time_ms=rt,
                    client_ip=ip,
                    trace_id=tr,
                    raw_line=html.escape(raw_row),
                    line_number=total,
                )
                events.append(event)
            except Exception:
                failed += 1

        try:
            events.sort(key=lambda e: e.timestamp)
        except Exception:
            pass

        return events, {"total_lines": total, "failed_lines": failed, "format_detected": "CSV Table"}

    def _find_col(self, headers: List[str], candidate_names: List[str]) -> Optional[int]:
        for cand in candidate_names:
            if cand in headers:
                return headers.index(cand)
        return None

    def _extract_timestamp(self, text: str) -> Optional[datetime]:
        """Tries to extract and parse timestamp from the beginning of a line."""
        for pattern, _ in self.TIMESTAMP_PATTERNS:
            match = pattern.search(text)
            if match:
                raw_ts = match.group(1)
                parsed = self._parse_iso_or_custom(raw_ts)
                if parsed:
                    return parsed
        return None

    def _parse_iso_or_custom(self, ts_str: str) -> Optional[datetime]:
        """Robust parser for diverse date/time representations."""
        ts_str = ts_str.strip().strip("[]").replace(",", ".")
        # Standard formats
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.year == 1900:  # e.g., syslog missing year
                    dt = dt.replace(year=datetime.utcnow().year)
                return dt
            except ValueError:
                continue

        # If has timezone like +00:00 or Z
        try:
            clean_ts = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(clean_ts)
        except (ValueError, TypeError):
            pass

        return None
