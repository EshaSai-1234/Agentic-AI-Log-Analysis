"""
LogSense AI - Synthetic Log Data Generator
Generates realistic multi-service application logs encompassing normal operational traffic
and complex incident failure scenarios (database pool exhaustion, HTTP 5xx cascades,
slow API latency spikes, unhandled exceptions, brute-force attacks, container restarts).
"""

import random
from datetime import datetime, timedelta
from typing import List, Optional
import os


SERVICES = [
    "auth-service",
    "order-service",
    "payment-gateway",
    "inventory-api",
    "user-db",
    "frontend-proxy",
    "notification-worker",
]

NORMAL_ENDPOINTS = [
    ("/api/v1/products", "GET", 200, 35, 95),
    ("/api/v1/users/profile", "GET", 200, 45, 120),
    ("/api/v1/search", "GET", 200, 60, 180),
    ("/api/v1/cart/items", "POST", 201, 75, 160),
    ("/api/v1/healthz", "GET", 200, 5, 25),
    ("/api/v1/metrics", "GET", 200, 10, 30),
]


def generate_synthetic_logs(num_logs: int = 5000, start_time: Optional[datetime] = None) -> str:
    """
    Generates a realistic sequence of ~num_logs log entries with specific injected operational incident sequences.
    Returns the logs as a newline-delimited string.
    """
    if start_time is None:
        start_time = datetime.utcnow() - timedelta(hours=3)

    logs: List[str] = []
    curr_time = start_time
    time_step_sec = (3 * 3600) / max(num_logs, 1)  # spread across 3 hours

    attacker_ip = "198.51.100.77"
    client_ips = ["192.168.1.10", "192.168.1.25", "10.0.4.12", "172.16.0.8", "192.168.2.100"]

    # Injected incident milestones:
    # 1. 10% - 15%: Brute-Force Auth Attack
    # 2. 30% - 37%: Database Pool Exhaustion & Cascading HTTP 500s
    # 3. 52% - 57%: Slow API SLA breach on reports
    # 4. 70% - 75%: Unhandled Exception in inventory-api
    # 5. 85% - 90%: Memory leak, SIGSEGV container crash & restart recovery

    for idx in range(num_logs):
        curr_time += timedelta(seconds=random.uniform(0.5, time_step_sec * 2.0))
        ts_str = curr_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        trace_id = f"tr-{random.randint(100000, 999999)}"
        pct = (idx / num_logs) * 100

        # Scenario 1: Brute-force auth attack (10% - 14%)
        if 10.0 <= pct <= 14.0 and random.random() < 0.65:
            username = random.choice(["admin", "root", "administrator", "devops", "superadmin"])
            logs.append(
                f"{ts_str} [WARN] [auth-service] endpoint=/api/v1/auth/login client_ip={attacker_ip} trace_id={trace_id} "
                f"status=401 latency=120ms - Authentication failed: invalid password credentials for user '{username}'."
            )
            if idx % 15 == 0:
                logs.append(
                    f"{ts_str} [ERROR] [auth-service] endpoint=/api/v1/auth/login client_ip={attacker_ip} trace_id={trace_id} "
                    f"status=429 latency=40ms - Too many failed login attempts: Rate limiter triggered, account temporarily locked."
                )

        # Scenario 2: Database Connection Pool Exhaustion & Cascading HTTP 500s (30% - 37%)
        elif 30.0 <= pct <= 37.0:
            sub = random.random()
            if sub < 0.35:
                logs.append(
                    f"{ts_str} [CRITICAL] [user-db] service=user-db trace_id={trace_id} "
                    f"- Database connection pool exhausted: 100/100 active connections in use. Timeout waiting for free slot after 30000ms."
                )
            elif sub < 0.70:
                logs.append(
                    f"{ts_str} [ERROR] [order-service] endpoint=/api/v1/orders/checkout client_ip={random.choice(client_ips)} trace_id={trace_id} "
                    f"status=500 latency=30120ms - HTTP 500 Internal Server Error: Failed to acquire DB transaction connection from user-db pool."
                )
            else:
                logs.append(
                    f"{ts_str} [ERROR] [payment-gateway] endpoint=/api/v1/payments/charge trace_id={trace_id} "
                    f"status=503 latency=5000ms - HTTP 503 Service Unavailable: Upstream order-service timed out during checkout transaction."
                )

        # Scenario 3: High Latency SLA degradation (52% - 56%)
        elif 52.0 <= pct <= 56.0 and random.random() < 0.55:
            lat = random.uniform(2600.0, 5800.0)
            logs.append(
                f"{ts_str} [WARN] [order-service] endpoint=/api/v1/reports/summary client_ip={random.choice(client_ips)} trace_id={trace_id} "
                f"status=200 latency={lat:.1f}ms - API SLA breach: query execution took {lat:.1f}ms (threshold: 1500ms) on unindexed table scan."
            )

        # Scenario 4: Unhandled Exception in inventory-api (70% - 74%)
        elif 70.0 <= pct <= 74.0 and random.random() < 0.50:
            logs.append(
                f"{ts_str} [ERROR] [inventory-api] endpoint=/api/v1/inventory/reserve client_ip={random.choice(client_ips)} trace_id={trace_id} "
                f"status=500 latency=210ms - Unhandled NullPointerException: item_id reference is null in InventoryAllocator.allocateStock (line 88)."
            )

        # Scenario 5: Memory Leak & Container Crash/Restart (86% - 90%)
        elif 86.0 <= pct <= 90.0:
            sub = random.random()
            if sub < 0.30:
                mem_mb = random.randint(1850, 2040)
                logs.append(
                    f"{ts_str} [WARN] [notification-worker] service=notification-worker trace_id={trace_id} "
                    f"- High memory pressure detected: Worker heap utilization at {mem_mb}MB / 2048MB (98.2%)."
                )
            elif sub < 0.60:
                logs.append(
                    f"{ts_str} [CRITICAL] [notification-worker] service=notification-worker trace_id={trace_id} "
                    f"- FATAL: OutOfMemoryError in worker thread pool. Process received SIGSEGV (signal 11) - process terminated."
                )
            else:
                logs.append(
                    f"{ts_str} [INFO] [notification-worker] service=notification-worker "
                    f"- Service restarted successfully by orchestrator (pod-restart #2). Liveness health check probe returned 200 OK."
                )

        # Occasional HTTP 404 or 400 client error (benign)
        elif random.random() < 0.04:
            sc = random.choice([400, 404])
            logs.append(
                f"{ts_str} [WARN] [frontend-proxy] endpoint=/static/v2/missing.png client_ip={random.choice(client_ips)} trace_id={trace_id} "
                f"status={sc} latency={random.uniform(15, 60):.1f}ms - Client HTTP {sc} Not Found for asset request."
            )

        # Default: Normal baseline traffic
        else:
            ep, method, status, min_lat, max_lat = random.choice(NORMAL_ENDPOINTS)
            svc = random.choice(["frontend-proxy", "order-service", "auth-service", "inventory-api"])
            lat = random.uniform(min_lat, max_lat)
            ip = random.choice(client_ips)
            logs.append(
                f"{ts_str} [INFO] [{svc}] endpoint={ep} client_ip={ip} trace_id={trace_id} "
                f"status={status} latency={lat:.1f}ms - Successfully processed {method} {ep} request."
            )

    return "\n".join(logs)


def write_sample_log_file(target_path: Optional[str] = None, num_logs: int = 5000) -> str:
    """Generates synthetic logs and saves them to data/sample_logs.log."""
    if target_path is None:
        target_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "sample_logs.log")

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    logs_content = generate_synthetic_logs(num_logs=num_logs)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(logs_content)

    return target_path


if __name__ == "__main__":
    path = write_sample_log_file()
    print(f"Generated sample log file at: {path}")
