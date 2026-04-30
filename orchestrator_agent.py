"""
AI Log Monitoring — Orchestrator Agent
True multi-agent architecture with one orchestrator + 5 specialist sub-agents.

Architecture:
    Orchestrator (Gemini)  ← drives the workflow, synthesizes all findings
      ├── Security Agent    ← analyzes security.log     (own Gemini call)
      ├── Database Agent    ← analyzes db.log           (own Gemini call)
      ├── API Agent         ← analyzes api.log          (own Gemini call)
      ├── Application Agent ← analyzes app.log          (own Gemini call)
      └── Infra Agent       ← server.log, k8s.log, cicd.log (own Gemini call)
      → synthesizes all 5 findings → writes monitoring_output.json

Setup:
    pip install google-genai
    Add GOOGLE_API_KEY to .env

Run:
    python orchestrator_agent.py
"""
import os
import json
import re
import datetime
from pathlib import Path


# ── Load .env ──────────────────────────────────────────────────────────────────
def _load_env(filename: str = ".env") -> None:
    env_file = Path(__file__).parent / filename
    if not env_file.exists():
        return
    with open(env_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip("\"'"))

_load_env()


# ── SDK import guard ───────────────────────────────────────────────────────────
try:
    from google import genai
    from google.genai import types
    from google.genai import errors as _genai_errors
except ImportError:
    raise SystemExit("\nMissing dependency. Run:\n  pip install google-genai\n")


# ── Config ─────────────────────────────────────────────────────────────────────
BASE   = Path(__file__).parent
LOGS   = BASE / "logs"
DATA   = BASE / "data"
ALERTS = BASE / "alerts"
MODEL  = os.environ.get("MODEL", "gemini-2.5-flash")

_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
if not _API_KEY:
    raise SystemExit(
        "\nGOOGLE_API_KEY not set.\nAdd it to .env:\n  GOOGLE_API_KEY=your_key_here\n"
    )

_client = genai.Client(api_key=_API_KEY)

# ── Model fallback chain ───────────────────────────────────────────────────────
_FALLBACK_MODELS: list = []
_seen_models: set = set()
for _m in [MODEL, "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]:
    if _m not in _seen_models:
        _FALLBACK_MODELS.append(_m)
        _seen_models.add(_m)

_active_model: str = MODEL


def _generate_with_fallback(contents, config) -> object:
    """Call generate_content with automatic model fallback on 503 UNAVAILABLE."""
    global _active_model
    to_try = [_active_model] + [m for m in _FALLBACK_MODELS if m != _active_model]
    last_exc = None
    for model in to_try:
        try:
            result = _client.models.generate_content(
                model=model, contents=contents, config=config
            )
            if model != _active_model:
                print(f"  [fallback] Switched to: {model}")
                _active_model = model
            return result
        except _genai_errors.ServerError as exc:
            if getattr(exc, "status_code", 0) == 503 or "UNAVAILABLE" in str(exc):
                print(f"  [!] {model} unavailable (503) — trying next model ...")
                last_exc = exc
            else:
                raise
    raise last_exc


# ── Helpers ────────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_logs(filenames: list) -> str:
    parts = []
    for name in filenames:
        path = LOGS / name
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            parts.append(f"=== {name} ===\n{content}")
        else:
            parts.append(f"=== {name} === [NOT FOUND]")
    return "\n\n".join(parts)


def _extract_json(text: str) -> dict:
    """Parse JSON from an LLM response, handling markdown code blocks."""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass
    return {"parse_error": True, "raw_snippet": text[:300]}


# ── Sub-agent output schema (appended to every sub-agent system prompt) ────────
_SUB_SCHEMA = """
Return ONLY a valid JSON object — no markdown, no explanation, no code block:
{
  "domain": "<domain name>",
  "health": "Healthy|Degraded|Down",
  "critical_count": <int>,
  "high_count": <int>,
  "medium_count": <int>,
  "low_count": <int>,
  "total_errors_last_24h": <int>,
  "total_errors_last_hour": <int>,
  "errors_found": [
    {
      "id": "ERR-<SHORT-ID>",
      "severity": "Critical|High|Medium|Low",
      "summary": "<one-line description>",
      "service": "<service name>",
      "frequency": <int>,
      "first_seen": "<timestamp or 'unknown'>",
      "last_seen": "<timestamp or 'unknown'>",
      "impact": "<business or technical impact>",
      "root_cause": "<detailed root cause>",
      "recommended_actions": "<numbered action steps>",
      "log_evidence": "<2-3 raw log lines>",
      "detection_pattern": "<keywords or pattern matched>",
      "status": "Investigating|Mitigating|Resolved",
      "trend": "Rising|Stable|Falling"
    }
  ],
  "alerts": [
    {
      "title": "[<Severity>] <short title>",
      "severity": "Critical|High|Medium|Low",
      "service": "<service>",
      "message": "<alert detail>",
      "escalation": "<escalation path>",
      "trend": "Rising|Stable|Falling"
    }
  ],
  "key_findings": ["<finding 1>", "<finding 2>"]
}
"""


# ── Sub-agent runner ───────────────────────────────────────────────────────────
def _run_sub_agent(domain: str, system_prompt: str, log_content: str) -> dict:
    """Make a dedicated Gemini API call for one specialist sub-agent."""
    print(f"      {domain} Agent  → analyzing ...")
    response = _generate_with_fallback(
        contents=[types.Content(
            role="user",
            parts=[types.Part(text=f"Analyze these {domain} logs:\n\n{log_content}")]
        )],
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.0,
        ),
    )
    result = _extract_json(response.text)
    n = len(result.get("errors_found", []))
    h = result.get("health", "?")
    print(f"      {domain} Agent  ← {n} error(s) | health={h}")
    return result


# ── Sub-agent system prompts ───────────────────────────────────────────────────
_SECURITY_PROMPT = (
    "You are a Senior Security Analyst. "
    "Analyze these security logs for: TOR/known-malicious IPs (Critical), "
    "brute-force attacks (High), account lockouts (High), "
    "credential exposure or expiry (Critical), bulk unauthorized data access / "
    "exfiltration (Critical), and authentication anomalies. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_DATABASE_PROMPT = (
    "You are a Senior Database Reliability Engineer. "
    "Analyze these PostgreSQL logs for: connection pool exhaustion / "
    "max_connections exceeded (Critical), deadlocks (High), "
    "connection timeouts to orders-db (High), slow queries >5s (Medium), "
    "and replication lag. "
    "Pool exhaustion causes cascading API failures — always Critical. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_API_PROMPT = (
    "You are a Senior API Reliability Engineer. "
    "Analyze these API Gateway logs for: HTTP 502 — upstream service unreachable "
    "(Critical), HTTP 503 — upstream timeout (High), HTTP 500 internal errors (High), "
    "latency spikes >2s (Medium), circuit breaker open events, and retry storms. "
    "Correlate 502 errors with specific upstream services. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_APP_PROMPT = (
    "You are a Senior Application Reliability Engineer. "
    "Analyze these application logs for: OutOfMemoryError / OOMKilled / JVM heap "
    "exhaustion (Critical), payment gateway failures / Stripe unreachable (Critical), "
    "Elasticsearch cluster RED status (High), service crashes and FATAL errors (High), "
    "retry storms / connection refused patterns (High/Medium). "
    "Group by service: OrderService, PaymentService, InventoryService, "
    "NotificationService, SearchService, ReportingService. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_INFRA_PROMPT = (
    "You are a Senior Infrastructure and DevOps Engineer. "
    "Analyze these logs for: CPU >= 90% on production nodes (Critical), "
    "OOMKilled pods / memory pressure (Critical), disk >= 90% (High), "
    "Kubernetes CrashLoopBackOff (High), pod restart loops (High), "
    "CI/CD deploy stage failures (High), expired deploy-bot credentials (Critical), "
    "HPA scaling events. "
    "server.log has CPU/MEM/DISK metrics; k8s.log has Kubernetes events; "
    "cicd.log has pipeline run results. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA


# ── Orchestrator tool registry ─────────────────────────────────────────────────
_TOOLS: dict = {}

def _register(fn):
    _TOOLS[fn.__name__] = fn
    return fn


# ── Orchestrator's tools = sub-agents + report writer ─────────────────────────
@_register
def analyze_security_logs() -> dict:
    """
    Sub-agent: Security specialist.
    Analyzes security.log for threats, attacks, credential issues, and exfiltration.
    Returns structured findings JSON.
    """
    return _run_sub_agent("Security", _SECURITY_PROMPT, _read_logs(["security.log"]))


@_register
def analyze_database_logs() -> dict:
    """
    Sub-agent: Database specialist.
    Analyzes db.log for connection exhaustion, deadlocks, timeouts, and slow queries.
    Returns structured findings JSON.
    """
    return _run_sub_agent("Database", _DATABASE_PROMPT, _read_logs(["db.log"]))


@_register
def analyze_api_logs() -> dict:
    """
    Sub-agent: API reliability specialist.
    Analyzes api.log for HTTP errors, latency spikes, and circuit breaker events.
    Returns structured findings JSON.
    """
    return _run_sub_agent("API", _API_PROMPT, _read_logs(["api.log"]))


@_register
def analyze_application_logs() -> dict:
    """
    Sub-agent: Application specialist.
    Analyzes app.log for service errors, OOM events, payment failures, and crashes.
    Returns structured findings JSON.
    """
    return _run_sub_agent("Application", _APP_PROMPT, _read_logs(["app.log"]))


@_register
def analyze_infrastructure_logs() -> dict:
    """
    Sub-agent: Infrastructure specialist.
    Analyzes server.log, k8s.log, cicd.log for resource pressure, pod crashes,
    and CI/CD failures.
    Returns structured findings JSON.
    """
    return _run_sub_agent(
        "Infrastructure", _INFRA_PROMPT,
        _read_logs(["server.log", "k8s.log", "cicd.log"])
    )


@_register
def write_monitoring_report(report_json: str) -> dict:
    """
    Write the final synthesized monitoring report to disk.
    The web dashboard reads this file every 60 seconds.

    Args:
        report_json: JSON string matching the monitoring_output schema.
    """
    try:
        report = json.loads(report_json)
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}"}

    DATA.mkdir(exist_ok=True)
    out = DATA / "monitoring_output.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    ALERTS.mkdir(exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    snap = ALERTS / f"alerts_{ts}.json"
    snap.write_text(json.dumps(report.get("alerts", []), indent=2), encoding="utf-8")
    return {"status": "ok", "output": str(out), "alert_snapshot": str(snap)}


# ── Orchestrator system prompt ─────────────────────────────────────────────────
_ORCHESTRATOR_PROMPT = """
You are the Master Orchestrator of a multi-agent AI log monitoring system.

Your 5 specialist sub-agents are your tools. Each sub-agent makes its own
AI analysis of a specific log domain and returns structured findings.

Workflow — follow in order:
1. Call ALL 5 sub-agents (order does not matter):
   - analyze_security_logs()       → Security Agent
   - analyze_database_logs()       → Database Agent
   - analyze_api_logs()            → API Agent
   - analyze_application_logs()    → Application Agent
   - analyze_infrastructure_logs() → Infrastructure Agent

2. Receive and study all 5 findings carefully.

3. Synthesize into a single coherent report:
   - Correlate cross-domain events (example: DB pool exhaustion causes API 502s —
     list this as one root cause in both the DB and API error entries)
   - De-duplicate errors that appear across multiple domains
   - Sum counts correctly across all domains
   - Set system_health:
       "Down"     → if ANY Critical errors exist
       "Degraded" → if ANY High errors exist (and no Critical)
       "Healthy"  → only Medium/Low or no errors

4. Call write_monitoring_report(report_json) ONCE with a JSON string matching:
{
  "generated_at": "<ISO-8601 UTC>",
  "summary": {
    "total_errors_last_hour": <int>,
    "total_errors_last_24_hours": <int>,
    "critical_count": <int>,
    "high_count": <int>,
    "medium_count": <int>,
    "low_count": <int>,
    "system_health": "Healthy|Degraded|Down"
  },
  "errors": [
    {
      "id": "ERR-<ID>",
      "severity": "Critical|High|Medium|Low",
      "summary": "<one-line>",
      "service": "<service>",
      "frequency": <int>,
      "first_seen": "<timestamp>",
      "last_seen": "<timestamp>",
      "impact": "<impact>",
      "root_cause": "<root cause>",
      "recommended_actions": "<numbered steps>",
      "log_evidence": "<2-3 raw log lines>",
      "detection_pattern": "<pattern>",
      "status": "Investigating|Mitigating|Resolved",
      "trend": "Rising|Stable|Falling"
    }
  ],
  "alerts": [
    {
      "title": "[<Severity>] <title>",
      "severity": "Critical|High|Medium|Low",
      "service": "<service>",
      "message": "<message>",
      "escalation": "<escalation path>",
      "trend": "Rising|Stable|Falling"
    }
  ],
  "trends": {
    "top_failing_services": [["<service>", <count>], ...],
    "errors_by_hour": [[<hour 0-23>, <count>], ...],
    "recurring_issues": ["<description>", ...],
    "anomaly_spikes": ["<description>", ...]
  }
}

MANDATORY: Call all 5 sub-agents first. Then call write_monitoring_report() exactly once.
""".strip()


# ── Orchestrator agentic loop ──────────────────────────────────────────────────
def run_orchestrator() -> None:
    print(f"[{_now()}] AI Log Monitor Orchestrator starting ...")
    print(f"  Model      : {_active_model}  (fallbacks: {' → '.join(_FALLBACK_MODELS[1:])})")
    print(f"  Sub-agents : Security | Database | API | Application | Infrastructure")
    print(f"  Logs dir   : {LOGS}\n")

    contents = [
        types.Content(
            role="user",
            parts=[types.Part(text=(
                f"Current UTC time: {_now()}. "
                "Activate all 5 specialist sub-agents to analyze the logs. "
                "Call every sub-agent before writing the final synthesized report."
            ))],
        )
    ]

    config = types.GenerateContentConfig(
        system_instruction=_ORCHESTRATOR_PROMPT,
        tools=list(_TOOLS.values()),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    step = 0
    last_candidate = None

    while True:
        step += 1
        response = _generate_with_fallback(contents=contents, config=config)
        candidate = response.candidates[0]
        last_candidate = candidate
        contents.append(candidate.content)

        fn_calls = [
            p.function_call
            for p in candidate.content.parts
            if getattr(p, "function_call", None)
        ]

        if not fn_calls:
            break  # Orchestrator is done

        response_parts = []
        for fc in fn_calls:
            fn = _TOOLS.get(fc.name)
            kwargs = dict(fc.args) if fc.args else {}

            label = fc.name.replace("analyze_", "").replace("_logs", "").replace("_", " ").title()
            if fc.name == "write_monitoring_report":
                print(f"  [Orchestrator] → write_monitoring_report")
            else:
                print(f"  [Orchestrator] → {label} Agent")

            if fn is None:
                result = {"error": f"Unknown tool: {fc.name}"}
            else:
                try:
                    result = fn(**kwargs)
                except Exception as exc:
                    result = {"error": str(exc)}

            response_parts.append(
                types.Part(function_response=types.FunctionResponse(
                    name=fc.name, response=result
                ))
            )

        contents.append(types.Content(role="user", parts=response_parts))

    # Print any final text from the orchestrator
    if last_candidate:
        for p in last_candidate.content.parts:
            text = getattr(p, "text", "")
            if text and text.strip():
                print("\n" + text.strip())

    # Print report summary
    report_path = DATA / "monitoring_output.json"
    if not report_path.exists():
        print("\n[WARNING] No monitoring_output.json written — orchestrator may have failed.")
        return

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    s = report.get("summary", {})
    alerts = report.get("alerts", [])
    severity_order = ("Critical", "High", "Medium", "Low")

    print("\n" + "=" * 60)
    print(f"  ORCHESTRATOR REPORT — {report.get('generated_at', _now())}")
    print("=" * 60)
    print(f"  System Health  : {s.get('system_health', '?')}")
    print(f"  Errors (1h)    : {s.get('total_errors_last_hour', 0)}")
    print(f"  Errors (24h)   : {s.get('total_errors_last_24_hours', 0)}")
    print(f"  Critical       : {s.get('critical_count', 0)}")
    print(f"  High           : {s.get('high_count', 0)}")
    print(f"  Medium         : {s.get('medium_count', 0)}")
    print(f"  Low            : {s.get('low_count', 0)}")
    print(f"  Active Alerts  : {len(alerts)}")
    print("=" * 60)

    top = sorted(
        alerts,
        key=lambda a: severity_order.index(a.get("severity", "Low"))
    )[:5]
    if top:
        print("\n  TOP ALERTS:")
        for a in top:
            print(f"    [{a.get('severity','?')}] {a.get('title','')}")
    print()


if __name__ == "__main__":
    run_orchestrator()
