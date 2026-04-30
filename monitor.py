"""
AI Log Monitoring Engine
Parses all log sources, detects anomalies, classifies severity,
deduplicates issues, and writes structured JSON for the dashboard.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

LOG_DIR   = os.path.join(os.path.dirname(__file__), "logs")
DATA_DIR  = os.path.join(os.path.dirname(__file__), "data")
ALERT_DIR = os.path.join(os.path.dirname(__file__), "alerts")

os.makedirs(DATA_DIR,  exist_ok=True)
os.makedirs(ALERT_DIR, exist_ok=True)

NOW = datetime.now(timezone.utc)

# ── Detection patterns ──────────────────────────────────────────────────────
PATTERNS = [
    # (regex, error_id_prefix, severity, summary_template, impact, action)
    (r"ConnectionTimeoutException.*orders-db",
     "ERR-DB-TIMEOUT", "High",
     "DB connection timeout (OrderService → orders-db)",
     "Order placement failures and cart abandonment",
     "1. Check DB connection pool config (maxPoolSize). "
     "2. Restart PgBouncer if pool is exhausted. "
     "3. Review slow queries blocking connections.",
     "OrderService"),

    (r"Connection pool exhausted|max_connections exceeded|remaining connection slots",
     "ERR-DB-POOL", "Critical",
     "Database connection pool exhausted",
     "Total DB unavailability — all dependent services fail",
     "1. Immediately increase max_connections or pool size. "
     "2. Kill idle connections: SELECT pg_terminate_backend(pid). "
     "3. Deploy PgBouncer connection pooler.",
     "PostgreSQL"),

    (r"Deadlock detected",
     "ERR-DB-DEADLOCK", "High",
     "Database deadlock detected",
     "Failed transactions and data integrity risk",
     "1. Identify and terminate blocking PIDs. "
     "2. Audit transaction ordering in OrderService. "
     "3. Add retry logic with exponential back-off.",
     "PostgreSQL"),

    (r"Stripe API unreachable|Circuit breaker OPEN|payment.*DOWN|PaymentService unreachable",
     "ERR-PAYMENT-DOWN", "Critical",
     "PaymentService / Stripe gateway DOWN",
     "Revenue loss — all payment processing halted",
     "1. Check Stripe status page. "
     "2. Verify firewall rules for stripe.com:443. "
     "3. Enable queued payment fallback. "
     "4. Alert finance team immediately.",
     "PaymentService"),

    (r"OutOfMemoryError|OOMKilled|JVM heap exhausted|MEM: 9[0-9]%|MEM: 100%",
     "ERR-OOM", "Critical",
     "Out-of-memory / OOM Kill event",
     "Service crash and pod restart — request failures during restart",
     "1. Increase JVM heap or pod memory limit. "
     "2. Profile memory usage for leaks. "
     "3. Enable memory-based HPA auto-scaling.",
     "ReportingService"),

    (r"brute force|ACCOUNT LOCKED|brute force threshold exceeded",
     "ERR-SEC-BRUTE", "High",
     "Brute-force login attack detected",
     "Account compromise risk and authentication service load",
     "1. Block offending IPs at WAF/firewall. "
     "2. Enforce CAPTCHA after 3 failed attempts. "
     "3. Notify security team. "
     "4. Review locked accounts for suspicious activity.",
     "SecurityService"),

    (r"TOR exit node|SECURITY ALERT.*brute force|IP BLOCKED",
     "ERR-SEC-TOR", "Critical",
     "Attack from TOR/known-malicious IP",
     "Active intrusion attempt — potential credential breach",
     "1. Confirm IP is blocked at firewall. "
     "2. Escalate to Security team (Slack: #sec-incidents). "
     "3. Review all auth events from this IP range. "
     "4. Enable geo-blocking if pattern continues.",
     "SecurityService"),

    (r"Data exfiltration risk|Unauthorized bulk data access|bulk export triggered",
     "ERR-SEC-EXFIL", "Critical",
     "Potential data exfiltration — bulk unauthorized access",
     "Regulatory / GDPR breach risk — customer PII exposure",
     "1. Immediately revoke the offending service account. "
     "2. Open security incident ticket. "
     "3. Notify DPO within 72h if breach confirmed. "
     "4. Audit all data accessed.",
     "SecurityService"),

    (r"503.*upstream timeout|upstream timeout.*OrderService",
     "ERR-API-503", "High",
     "API Gateway returning 503 — OrderService upstream timeout",
     "End-user order failures and degraded checkout experience",
     "1. Check OrderService pod health. "
     "2. Review DB connectivity from OrderService. "
     "3. Scale OrderService pods via HPA.",
     "APIGateway"),

    (r"502.*PaymentService|PaymentService unreachable",
     "ERR-API-502-PAY", "Critical",
     "API Gateway 502 — PaymentService unreachable",
     "Complete payment processing outage for all users",
     "1. Check PaymentService pods. "
     "2. Verify Stripe connectivity. "
     "3. Activate payment fallback queue.",
     "APIGateway"),

    (r"CrashLoopBackOff",
     "ERR-K8S-CRASH", "High",
     "Kubernetes pod in CrashLoopBackOff",
     "Reduced service capacity — requests dropped by unavailable pods",
     "1. kubectl describe pod <pod-name> for exit reason. "
     "2. kubectl logs <pod-name> --previous for crash logs. "
     "3. Check resource limits and liveness probe config.",
     "K8sController"),

    (r"deploy.*FAILED|Pipeline.*FAILED.*deploy",
     "ERR-CICD-DEPLOY", "High",
     "CI/CD deployment pipeline failure",
     "Hotfix or feature release blocked — incidents cannot be patched",
     "1. Check deploy-bot service account credentials. "
     "2. Rotate expired tokens in CI/CD secrets. "
     "3. Re-trigger pipeline after fix.",
     "CICDPipeline"),

    (r"credentials expired.*deploy-bot|deploy-bot token invalid|Service account.*credentials expired",
     "ERR-CICD-CREDS", "Critical",
     "CI/CD service account credentials expired — all deployments blocked",
     "Critical hotfixes cannot be deployed. Active incidents cannot be resolved.",
     "1. Immediately rotate deploy-bot credentials in secrets manager. "
     "2. Update CI/CD pipeline secrets. "
     "3. Re-run blocked pipelines.",
     "CICDPipeline"),

    (r"Elasticsearch cluster health RED|Search queries failing",
     "ERR-SEARCH-RED", "High",
     "Elasticsearch cluster health RED — search unavailable",
     "Product search down — browse and discovery features broken",
     "1. kubectl get pods -n elastic to check pod status. "
     "2. Review unassigned shards: GET _cluster/allocation/explain. "
     "3. Restart failed Elasticsearch nodes.",
     "SearchService"),

    (r"CPU: 9[0-9]%|CPU spike.*99%|CPU: 98%",
     "ERR-CPU-SPIKE", "Critical",
     "Critical CPU spike on production node",
     "Node saturation — risk of OOM, pod eviction, and cascading failures",
     "1. Identify top CPU consumer: kubectl top pods. "
     "2. Trigger HPA to distribute load. "
     "3. Check for runaway queries or infinite loops.",
     "ServerMonitor"),

    (r"500.*Internal Server Error|500.*checkout",
     "ERR-API-500", "High",
     "API returning HTTP 500 Internal Server Error",
     "Checkout failures impacting conversion rate",
     "1. Check application error logs for stack traces. "
     "2. Review recent deployments for regressions. "
     "3. Enable circuit breaker if errors persist.",
     "APIGateway"),
]

# ── Parse logs ───────────────────────────────────────────────────────────────
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")

def parse_timestamp(line):
    m = TS_RE.search(line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None

def hours_ago(ts, h):
    delta = NOW - ts
    return delta.total_seconds() / 3600 < h

def load_all_logs():
    lines = []
    for fname in os.listdir(LOG_DIR):
        fpath = os.path.join(LOG_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        with open(fpath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ts = parse_timestamp(line)
                lines.append({"line": line, "ts": ts, "source": fname})
    lines.sort(key=lambda x: x["ts"] or datetime.min.replace(tzinfo=timezone.utc))
    return lines

# ── Match and aggregate ──────────────────────────────────────────────────────
def match_patterns(log_lines):
    """Match each log line against detection patterns; aggregate occurrences."""
    buckets = {}  # err_id -> aggregated dict

    for entry in log_lines:
        line, ts, source = entry["line"], entry["ts"], entry["source"]
        if ts is None:
            continue
        for (pattern, err_id, severity, summary, impact, action, service) in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if err_id not in buckets:
                    buckets[err_id] = {
                        "id": err_id,
                        "service": service,
                        "severity": severity,
                        "summary": summary,
                        "impact": impact,
                        "recommended_action": action,
                        "error_pattern": pattern,
                        "occurrences": [],
                        "evidence": line,
                        "root_cause": "Needs investigation",
                        "status": "Open",
                    }
                buckets[err_id]["occurrences"].append(ts)
    return buckets

# ── Root cause enrichment ────────────────────────────────────────────────────
ROOT_CAUSES = {
    "ERR-DB-POOL":     "PostgreSQL max_connections exhausted; connection pooler absent or undersized",
    "ERR-DB-TIMEOUT":  "Connection pool exhaustion causing OrderService to wait past timeout",
    "ERR-DB-DEADLOCK": "Concurrent writes to orders/order_items without proper lock ordering",
    "ERR-PAYMENT-DOWN":"External Stripe API unreachable (firewall or Stripe outage)",
    "ERR-OOM":         "JVM heap / container memory limit too small for current workload",
    "ERR-SEC-BRUTE":   "No rate-limiting or CAPTCHA on login endpoint",
    "ERR-SEC-TOR":     "Attacker using TOR to bypass IP reputation blocks",
    "ERR-SEC-EXFIL":   "Misconfigured automated report job; no data-volume guardrails",
    "ERR-API-503":     "OrderService DB issues causing upstream timeouts at API Gateway",
    "ERR-API-502-PAY": "PaymentService pods down while Stripe connectivity was lost",
    "ERR-K8S-CRASH":   "Pod memory limits too low; OOM kill triggering CrashLoopBackOff",
    "ERR-CICD-DEPLOY": "deploy-bot service account credentials expired",
    "ERR-CICD-CREDS":  "CI/CD service account token rotation not automated",
    "ERR-SEARCH-RED":  "Elasticsearch shard allocation failure after node restart",
    "ERR-CPU-SPIKE":   "DB connection saturation forcing query queuing and CPU spin",
    "ERR-API-500":     "Null pointer exception in OrderProcessor propagating as 500",
}

STATUS_MAP = {
    "ERR-DB-POOL":     "Investigating",
    "ERR-DB-TIMEOUT":  "Investigating",
    "ERR-DB-DEADLOCK": "Investigating",
    "ERR-PAYMENT-DOWN":"Resolved",
    "ERR-OOM":         "Resolved",
    "ERR-SEC-BRUTE":   "Investigating",
    "ERR-SEC-TOR":     "Resolved",
    "ERR-SEC-EXFIL":   "Resolved",
    "ERR-API-503":     "Investigating",
    "ERR-API-502-PAY": "Resolved",
    "ERR-K8S-CRASH":   "Investigating",
    "ERR-CICD-DEPLOY": "Open",
    "ERR-CICD-CREDS":  "Open",
    "ERR-SEARCH-RED":  "Resolved",
    "ERR-CPU-SPIKE":   "Investigating",
    "ERR-API-500":     "Resolved",
}

# ── Trend calculation ─────────────────────────────────────────────────────────
def compute_trend(occurrences):
    if len(occurrences) < 3:
        return "Stable"
    sorted_occ = sorted(occurrences)
    # Compare first-half vs second-half frequency
    mid = len(sorted_occ) // 2
    first_half  = sorted_occ[:mid]
    second_half = sorted_occ[mid:]
    if len(first_half) == 0 or len(second_half) == 0:
        return "Stable"
    fh_span = max((first_half[-1]  - first_half[0]).total_seconds(),  1)
    sh_span = max((second_half[-1] - second_half[0]).total_seconds(), 1)
    fh_rate = len(first_half)  / fh_span
    sh_rate = len(second_half) / sh_span
    if sh_rate > fh_rate * 1.4:
        return "Increasing"
    if sh_rate < fh_rate * 0.6:
        return "Decreasing"
    return "Stable"

# ── Build output ─────────────────────────────────────────────────────────────
def build_output(buckets):
    errors = []
    alerts = []
    total_1h  = 0
    total_24h = 0
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for err_id, data in buckets.items():
        occs = data["occurrences"]
        if not occs:
            continue

        occs_1h  = [o for o in occs if hours_ago(o, 1)]
        occs_24h = [o for o in occs if hours_ago(o, 24)]
        if not occs_24h:
            continue  # outside our 24h window, skip

        total_1h  += len(occs_1h)
        total_24h += len(occs_24h)

        sev = data["severity"]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        last_occ   = max(occs_24h)
        first_occ  = min(occs_24h)
        trend      = compute_trend(occs_24h)

        err_record = {
            "id":                err_id,
            "timestamp":         first_occ.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "service":           data["service"],
            "severity":          sev,
            "summary":           data["summary"],
            "status":            STATUS_MAP.get(err_id, "Open"),
            "frequency":         len(occs_24h),
            "last_occurrence":   last_occ.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error_pattern":     data["error_pattern"],
            "impact":            data["impact"],
            "root_cause":        ROOT_CAUSES.get(err_id, "Needs investigation"),
            "recommended_action":data["recommended_action"],
            "evidence":          data["evidence"],
            "trend":             trend,
        }
        errors.append(err_record)

        # Alert generation
        if sev in ("Critical", "High", "Medium"):
            status = STATUS_MAP.get(err_id, "Open")
            esc_map = {
                "Critical": "SRE On-Call + Engineering Lead (PagerDuty)",
                "High":     "SRE Team (Slack: #alerts-high)",
                "Medium":   "Engineering Team (Slack: #alerts-medium)",
            }
            alerts.append({
                "title":      f"[{sev}] {data['summary']}",
                "timestamp":  last_occ.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "service":    data["service"],
                "severity":   sev,
                "message":    (
                    f"{data['summary']} — {len(occs_24h)} occurrences in 24h "
                    f"(last: {last_occ.strftime('%H:%M:%S UTC')}). "
                    f"Trend: {trend}. Status: {status}."
                ),
                "escalation": esc_map.get(sev, "Engineering Team"),
            })

    # Sort: Critical first, then High, then by frequency desc
    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    errors.sort(key=lambda e: (SEV_ORDER.get(e["severity"], 4), -e["frequency"]))
    alerts.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 4)))

    # System health determination
    crit = sev_counts["Critical"]
    high = sev_counts["High"]
    if crit >= 2 or (crit >= 1 and high >= 2):
        health = "Down"
    elif crit >= 1 or high >= 2:
        health = "Degraded"
    elif high >= 1:
        health = "Degraded"
    else:
        health = "Healthy"

    summary = {
        "total_errors_last_hour":    total_1h,
        "total_errors_last_24_hours":total_24h,
        "critical_count":            sev_counts["Critical"],
        "high_count":                sev_counts["High"],
        "medium_count":              sev_counts["Medium"],
        "low_count":                 sev_counts["Low"],
        "system_health":             health,
        "generated_at":              NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "monitored_sources":         len(os.listdir(LOG_DIR)),
        "unique_error_types":        len(errors),
    }

    return {"summary": summary, "errors": errors, "alerts": alerts}

# ── Trends & analytics payload ────────────────────────────────────────────────
def build_trends(errors):
    service_counts = defaultdict(int)
    hourly_counts  = defaultdict(int)

    for e in errors:
        service_counts[e["service"]] += e["frequency"]
        try:
            h = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ").hour
            hourly_counts[h] += e["frequency"]
        except ValueError:
            pass

    top_services = sorted(service_counts.items(), key=lambda x: -x[1])
    top_services = [{"service": s, "error_count": c} for s, c in top_services]

    hourly = [{"hour": f"{h:02d}:00", "count": hourly_counts.get(h, 0)} for h in range(24)]

    recurring = [e for e in errors if e["frequency"] >= 5]
    anomalies = [e for e in errors if e["trend"] == "Increasing"]

    return {
        "top_failing_services":  top_services,
        "errors_by_hour":        hourly,
        "recurring_issues":      [{"id": e["id"], "summary": e["summary"], "frequency": e["frequency"]} for e in recurring],
        "anomaly_spikes":        [{"id": e["id"], "summary": e["summary"], "trend": e["trend"], "service": e["service"]} for e in anomalies],
    }

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"[{NOW.strftime('%Y-%m-%dT%H:%M:%SZ')}] AI Log Monitor starting ...")
    log_lines = load_all_logs()
    print(f"  Loaded {len(log_lines)} log lines from {LOG_DIR}")

    buckets = match_patterns(log_lines)
    print(f"  Matched {len(buckets)} unique error patterns")

    output = build_output(buckets)
    trends = build_trends(output["errors"])
    output["trends"] = trends

    out_path = os.path.join(DATA_DIR, "monitoring_output.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"  Dashboard data written: {out_path}")

    # Save alert snapshot
    alert_path = os.path.join(ALERT_DIR, f"alerts_{NOW.strftime('%Y%m%d_%H%M%S')}.json")
    with open(alert_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "alerts": output["alerts"]}, f, indent=2)
    print(f"  Alerts snapshot written: {alert_path}")

    s = output["summary"]
    print(f"\n{'='*60}")
    print(f"  MONITORING REPORT — {s['generated_at']}")
    print(f"{'='*60}")
    print(f"  System Health  : {s['system_health']}")
    print(f"  Errors (1h)    : {s['total_errors_last_hour']}")
    print(f"  Errors (24h)   : {s['total_errors_last_24_hours']}")
    print(f"  Critical       : {s['critical_count']}")
    print(f"  High           : {s['high_count']}")
    print(f"  Medium         : {s['medium_count']}")
    print(f"  Low            : {s['low_count']}")
    print(f"  Active Alerts  : {len(output['alerts'])}")
    print(f"{'='*60}\n")

    print("  TOP ALERTS:")
    for a in output["alerts"][:5]:
        print(f"    [{a['severity']:8s}] {a['title']}")

    return output

if __name__ == "__main__":
    main()
