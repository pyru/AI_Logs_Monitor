"""
AI Log Monitoring Agent — Google Gemini Edition
True AI agent: Gemini reasons over logs via function calling.

Setup:
    pip install google-genai
    Add GOOGLE_API_KEY to .env

Run:
    python ai_agent.py
"""
import os
import json
import datetime
from pathlib import Path


# ── Load .env (no extra package needed) ───────────────────────────────────────
def _load_env(filename: str = ".env") -> None:
    env_file = Path(__file__).parent / filename
    if not env_file.exists():
        return
    with open(env_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip().strip("\"'"))

_load_env()


# ── SDK import guard ───────────────────────────────────────────────────────────
try:
    from google import genai
    from google.genai import types
except ImportError:
    raise SystemExit(
        "\nMissing dependency. Install with:\n"
        "  pip install google-genai\n"
    )


# ── Config ─────────────────────────────────────────────────────────────────────
BASE   = Path(__file__).parent
LOGS   = BASE / "logs"
DATA   = BASE / "data"
ALERTS = BASE / "alerts"
MODEL  = os.environ.get("MODEL", "gemini-3.1-flash-lite")


# ── Tool registry ──────────────────────────────────────────────────────────────
_TOOLS: dict = {}

def _register(fn):
    _TOOLS[fn.__name__] = fn
    return fn


# ── Tool implementations ───────────────────────────────────────────────────────
@_register
def get_current_time() -> dict:
    """Return the current UTC timestamp for timestamping reports."""
    return {"utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}


@_register
def list_log_files() -> dict:
    """List all .log files available for analysis."""
    files = sorted(p.name for p in LOGS.glob("*.log"))
    return {"log_files": files, "count": len(files)}


@_register
def read_log_file(filename: str) -> dict:
    """
    Read a log file and return its full contents.

    Args:
        filename: Name of the log file, e.g. 'app.log'.
    """
    path = LOGS / Path(filename).name  # strip directory traversal
    if not path.exists():
        return {"error": f"File not found: {filename}"}
    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    return {
        "filename": filename,
        "line_count": len(lines),
        "content": content,
    }


@_register
def write_monitoring_report(report_json: str) -> dict:
    """
    Write the final structured monitoring report to disk.
    The web dashboard reads this file automatically every 60 seconds.

    Args:
        report_json: JSON string conforming to the monitoring_output schema.
    """
    try:
        report = json.loads(report_json)
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON: {exc}"}

    DATA.mkdir(exist_ok=True)
    out = DATA / "monitoring_output.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    ALERTS.mkdir(exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    alert_snap = ALERTS / f"alerts_{ts}.json"
    alert_snap.write_text(
        json.dumps(report.get("alerts", []), indent=2), encoding="utf-8"
    )
    return {"status": "ok", "output": str(out), "alert_snapshot": str(alert_snap)}


# ── System prompt ──────────────────────────────────────────────────────────────
_SYSTEM = """
You are an expert Site Reliability Engineer (SRE) AI agent specialized in log analysis and incident detection.

Workflow — follow these steps in order:
1. Call get_current_time() to get the report timestamp.
2. Call list_log_files() to discover all log sources.
3. Call read_log_file(filename) for EVERY file returned — do not skip any.
4. Analyze ALL logs carefully:
   - Identify errors, anomalies, security events, resource exhaustion.
   - Correlate events across services (e.g., DB pool exhaustion causing API 502s).
   - Count occurrences per error type in the last 1h and last 24h.
   - Detect trends (Rising = more in last half of window; Falling = fewer).
5. Call write_monitoring_report(report_json) with a valid JSON string matching this EXACT schema:

{
  "generated_at": "<ISO-8601 UTC>",
  "summary": {
    "total_errors_last_hour": <int>,
    "total_errors_last_24_hours": <int>,
    "critical_count": <int>,
    "high_count": <int>,
    "medium_count": <int>,
    "low_count": <int>,
    "system_health": "Healthy" | "Degraded" | "Down"
  },
  "errors": [
    {
      "id": "ERR-<SHORT-ID>",
      "severity": "Critical" | "High" | "Medium" | "Low",
      "summary": "<one-line description>",
      "service": "<service name>",
      "frequency": <int>,
      "first_seen": "<timestamp>",
      "last_seen": "<timestamp>",
      "impact": "<business or technical impact>",
      "root_cause": "<detailed root cause analysis>",
      "recommended_actions": "<numbered steps>",
      "log_evidence": "<2-3 raw log lines>",
      "detection_pattern": "<pattern or keywords matched>",
      "status": "Investigating" | "Mitigating" | "Resolved",
      "trend": "Rising" | "Stable" | "Falling"
    }
  ],
  "alerts": [
    {
      "title": "[<Severity>] <short title>",
      "severity": "Critical" | "High" | "Medium" | "Low",
      "service": "<service>",
      "message": "<alert detail>",
      "escalation": "<escalation path>",
      "trend": "Rising" | "Stable" | "Falling"
    }
  ],
  "trends": {
    "top_failing_services": [["<service>", <count>], ...],
    "errors_by_hour": [[<hour 0-23>, <count>], ...],
    "recurring_issues": ["<description>", ...],
    "anomaly_spikes": ["<description>", ...]
  }
}

Severity classification:
- Critical : data loss, full outages, OOM kills, DB pool exhausted, security breaches
- High     : degraded performance, CrashLoopBackOff, API 5xx, deadlocks
- Medium   : warnings, slow queries, retry storms
- Low      : informational anomalies

Security rules — always classify as Critical:
- TOR/known-malicious IP, brute force, credential exposure, bulk unauthorized data access

Escalation paths:
- Critical → "SRE On-Call + Engineering Lead (PagerDuty)"
- High     → "SRE Team (Slack: #alerts-high)"
- Medium   → "Engineering Team (Slack: #alerts-medium)"

MANDATORY: Always call write_monitoring_report() as your final action. Never output raw JSON as plain text.
""".strip()


# ── Agentic loop ───────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def run_agent() -> None:
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if not api_key:
        raise SystemExit(
            "\nGOOGLE_API_KEY not set.\n"
            "Add it to .env:\n"
            "  GOOGLE_API_KEY=your_key_here\n"
            "Get a key at: https://aistudio.google.com/apikey\n"
        )

    client = genai.Client(api_key=api_key)

    print(f"[{_now()}] AI Log Monitor starting ...")
    print(f"  Model : {MODEL}")
    print(f"  Logs  : {LOGS}\n")

    contents = [
        types.Content(
            role="user",
            parts=[types.Part(text=(
                "Analyze all log files now and produce a complete monitoring report. "
                "Read every single log file before writing the final report."
            ))],
        )
    ]

    config = types.GenerateContentConfig(
        system_instruction=_SYSTEM,
        tools=list(_TOOLS.values()),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(
            disable=True  # we drive the loop manually for full control + logging
        ),
        temperature=0.0,
    )

    step = 0
    last_candidate = None

    while True:
        step += 1
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=config,
        )

        candidate = response.candidates[0]
        last_candidate = candidate
        contents.append(candidate.content)

        # Collect function calls from this response
        fn_calls = [
            part.function_call
            for part in candidate.content.parts
            if getattr(part, "function_call", None)
        ]

        if not fn_calls:
            break  # Gemini finished — no more tool calls

        # Execute each function call
        response_parts = []
        for fc in fn_calls:
            fn = _TOOLS.get(fc.name)
            kwargs = dict(fc.args) if fc.args else {}

            short_args = ", ".join(f"{k}={v!r}" for k, v in kwargs.items())
            print(f"  [step {step}] {fc.name}({short_args})")

            if fn is None:
                result = {"error": f"Unknown tool: {fc.name}"}
            else:
                try:
                    result = fn(**kwargs)
                except Exception as exc:
                    result = {"error": str(exc)}

            response_parts.append(
                types.Part(
                    function_response=types.FunctionResponse(
                        name=fc.name,
                        response=result,
                    )
                )
            )

        contents.append(types.Content(role="user", parts=response_parts))

    # Print any final text from the model
    if last_candidate:
        for part in last_candidate.content.parts:
            text = getattr(part, "text", "")
            if text and text.strip():
                print("\n" + text.strip())

    # Print summary from the written report
    report_path = DATA / "monitoring_output.json"
    if not report_path.exists():
        print("\n[WARNING] No monitoring_output.json written — agent may have failed.")
        return

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    s = report.get("summary", {})
    alerts = report.get("alerts", [])

    print("\n" + "=" * 60)
    print(f"  MONITORING REPORT — {report.get('generated_at', _now())}")
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

    top = sorted(alerts, key=lambda a: ("Critical", "High", "Medium", "Low").index(
        a.get("severity", "Low")
    ))[:5]
    if top:
        print("\n  TOP ALERTS:")
        for a in top:
            print(f"    [{a.get('severity','?')}] {a.get('title','')}")
    print()


if __name__ == "__main__":
    run_agent()
