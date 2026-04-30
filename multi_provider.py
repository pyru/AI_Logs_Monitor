"""
Multi-provider AI Orchestrator Engine
Supports: Google Gemini | Anthropic Claude | OpenAI GPT

Each provider uses the same 5-sub-agent + orchestrator pattern.
Tool definitions are converted to each provider's native format at runtime.
"""
import json
import re
import datetime
from pathlib import Path
from typing import Callable


# ── Provider registry ──────────────────────────────────────────────────────────
PROVIDERS = {
    "Google Gemini":    "gemini",
    "Anthropic Claude": "anthropic",
    "OpenAI":           "openai",
}

DEFAULT_MODELS = {
    "gemini":    "gemini-2.5-flash",
    "anthropic": "claude-opus-4-7",
    "openai":    "gpt-4o",
}

MODEL_SUGGESTIONS = {
    "gemini":    "gemini-2.5-flash, gemini-2.0-flash, gemini-1.5-flash",
    "anthropic": "claude-opus-4-7, claude-sonnet-4-6, claude-haiku-4-5",
    "openai":    "gpt-4o, gpt-4o-mini, gpt-4-turbo",
}

GEMINI_FALLBACKS = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]


# ── Shared helpers ─────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_json(text: str) -> dict:
    """Parse JSON from an LLM response, handling markdown code fences."""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}") + 1
        if s >= 0 and e > s:
            try:
                return json.loads(text[s:e])
            except json.JSONDecodeError:
                pass
    return {"parse_error": True, "raw_snippet": text[:400]}


def _read_logs(log_files_dict: dict, names: list[str]) -> str:
    """Match requested log file names against the uploaded files dict."""
    parts = []
    for name in names:
        stem = Path(name).stem.lower()
        match = None
        for fn, content in log_files_dict.items():
            fn_stem = Path(fn).stem.lower()
            if stem == fn_stem or stem in fn_stem or fn_stem in stem:
                match = (fn, content)
                break
        if match:
            parts.append(f"=== {match[0]} ===\n{match[1]}")
        else:
            # Fall back to ALL available files for this sub-agent
            parts.append(f"=== {name} === [NOT FOUND — showing all available logs]\n" +
                         "\n\n".join(f"=== {fn} ===\n{c}" for fn, c in log_files_dict.items()))
            break  # already gave everything
    return "\n\n".join(parts)


# ── Sub-agent output schema ────────────────────────────────────────────────────
_SUB_SCHEMA = """
Return ONLY a valid JSON object. No markdown, no code block, no explanation:
{
  "domain": "<domain>",
  "health": "Healthy|Degraded|Down",
  "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
  "total_errors_last_24h": 0, "total_errors_last_hour": 0,
  "errors_found": [
    {
      "id": "ERR-<ID>",
      "severity": "Critical|High|Medium|Low",
      "summary": "<one-line>",
      "service": "<service>",
      "frequency": 0,
      "first_seen": "<timestamp or unknown>",
      "last_seen": "<timestamp or unknown>",
      "impact": "<business/technical impact>",
      "root_cause": "<detailed root cause>",
      "recommended_actions": "<numbered steps>",
      "log_evidence": "<2-3 raw log lines>",
      "detection_pattern": "<keywords matched>",
      "status": "Investigating|Mitigating|Resolved",
      "trend": "Rising|Stable|Falling"
    }
  ],
  "alerts": [
    {
      "title": "[<Severity>] <title>",
      "severity": "Critical|High|Medium|Low",
      "service": "<service>",
      "message": "<detail>",
      "escalation": "<escalation path>",
      "trend": "Rising|Stable|Falling"
    }
  ],
  "key_findings": ["<finding 1>", "<finding 2>"]
}
"""

# ── Sub-agent system prompts ───────────────────────────────────────────────────
_SECURITY_PROMPT = (
    "You are a Senior Security Analyst. Analyze for: TOR/known-malicious IPs (Critical), "
    "brute-force attacks (High), account lockouts (High), credential exposure or expiry (Critical), "
    "bulk unauthorized data access / exfiltration (Critical), JWT anomalies, CVEs. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_DATABASE_PROMPT = (
    "You are a Senior Database Reliability Engineer. Analyze PostgreSQL logs for: "
    "connection pool exhaustion / max_connections exceeded (Critical), deadlocks (High), "
    "connection timeouts (High), lock timeouts (High), slow queries >5s (Medium), table bloat (Low). "
    "Pool exhaustion causing cascading API failures is always Critical. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_API_PROMPT = (
    "You are a Senior API Reliability Engineer. Analyze API Gateway logs for: "
    "HTTP 502 — upstream unreachable (Critical), HTTP 503 — upstream timeout (High), "
    "HTTP 500 internal errors (High), latency >2s (Medium), circuit breaker open events, retry storms. "
    "Correlate 502/503s with specific upstream services. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_APP_PROMPT = (
    "You are a Senior Application Reliability Engineer. Analyze application logs for: "
    "OutOfMemoryError / OOMKilled / JVM heap exhaustion (Critical), "
    "payment gateway failures / Stripe unreachable (Critical), "
    "Elasticsearch cluster RED (High), service crashes and FATAL errors (High), "
    "NullPointerException / ConcurrentModificationException (High), retry storms (Medium). "
    "Group by service: OrderService, PaymentService, InventoryService, NotificationService, etc. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

_INFRA_PROMPT = (
    "You are a Senior Infrastructure and DevOps Engineer. Analyze logs for: "
    "CPU >= 90% on production nodes (Critical), OOMKilled pods (Critical), disk >= 90% (High), "
    "Kubernetes CrashLoopBackOff (High), CI/CD deploy failures (High), "
    "expired deploy-bot credentials (Critical), HPA scaling events. "
    "server.log = CPU/MEM/DISK metrics; k8s.log = Kubernetes events; cicd.log = pipeline runs. "
    "Critical escalation: 'SRE On-Call + Engineering Lead (PagerDuty)'. "
    "High escalation: 'SRE Team (Slack: #alerts-high)'. "
) + _SUB_SCHEMA

# ── Orchestrator tool schema (provider-neutral JSON Schema) ────────────────────
ORCHESTRATOR_TOOLS = [
    {
        "name": "analyze_security_logs",
        "description": "Security specialist sub-agent. Analyzes security logs for threats, attacks, credential issues, and data exfiltration. Returns structured findings JSON.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_database_logs",
        "description": "Database specialist sub-agent. Analyzes database logs for connection pool exhaustion, deadlocks, timeouts, and slow queries. Returns structured findings JSON.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_api_logs",
        "description": "API reliability specialist sub-agent. Analyzes API Gateway logs for HTTP errors, latency spikes, and circuit breaker events. Returns structured findings JSON.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_application_logs",
        "description": "Application specialist sub-agent. Analyzes application logs for OOM errors, payment failures, service crashes, and race conditions. Returns structured findings JSON.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_infrastructure_logs",
        "description": "Infrastructure specialist sub-agent. Analyzes server, Kubernetes, and CI/CD logs for resource pressure, pod crashes, and deployment failures. Returns structured findings JSON.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "write_monitoring_report",
        "description": "Write the final synthesized monitoring report. Call this LAST, after all 5 sub-agents have completed their analysis.",
        "parameters": {
            "type": "object",
            "properties": {
                "report_json": {
                    "type": "string",
                    "description": "Complete monitoring report as a valid JSON string matching the monitoring_output schema.",
                }
            },
            "required": ["report_json"],
        },
    },
]

# ── Orchestrator system prompt ─────────────────────────────────────────────────
_ORCHESTRATOR_PROMPT = """
You are the Master Orchestrator of a multi-agent AI log monitoring system.

Your 5 specialist sub-agents are your tools. Each sub-agent performs its own AI analysis of a specific log domain.

Workflow — follow in order:
1. Call ALL 5 sub-agents (order does not matter):
   - analyze_security_logs()       → Security Agent
   - analyze_database_logs()       → Database Agent
   - analyze_api_logs()            → API Agent
   - analyze_application_logs()    → Application Agent
   - analyze_infrastructure_logs() → Infrastructure Agent

2. Study all 5 findings carefully.

3. Synthesize into a single coherent report:
   - Correlate cross-domain events (e.g., DB pool exhaustion → API 502 errors)
   - De-duplicate errors appearing in multiple domains
   - Sum counts across all domains
   - Set system_health:
       "Down"     → any Critical errors exist
       "Degraded" → any High errors exist (no Critical)
       "Healthy"  → only Medium/Low or none

4. Call write_monitoring_report(report_json) ONCE with JSON matching:
{
  "generated_at": "<ISO-8601 UTC>",
  "summary": {
    "total_errors_last_hour": <int>,
    "total_errors_last_24_hours": <int>,
    "critical_count": <int>, "high_count": <int>,
    "medium_count": <int>, "low_count": <int>,
    "system_health": "Healthy|Degraded|Down"
  },
  "errors": [
    {
      "id": "ERR-<ID>", "severity": "Critical|High|Medium|Low",
      "summary": "<one-line>", "service": "<service>",
      "frequency": <int>, "first_seen": "<ts>", "last_seen": "<ts>",
      "impact": "<impact>", "root_cause": "<root cause>",
      "recommended_actions": "<numbered steps>",
      "log_evidence": "<2-3 raw lines>", "detection_pattern": "<pattern>",
      "status": "Investigating|Mitigating|Resolved", "trend": "Rising|Stable|Falling"
    }
  ],
  "alerts": [
    {
      "title": "[<Severity>] <title>", "severity": "Critical|High|Medium|Low",
      "service": "<service>", "message": "<detail>",
      "escalation": "<escalation path>", "trend": "Rising|Stable|Falling"
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


# ── Provider: sub-agent text generation (no tools) ─────────────────────────────
def _call_sub_agent(provider: str, client, model: str, system_prompt: str, log_content: str) -> dict:
    """Run a specialist sub-agent — simple text generation, no tool use."""
    user_msg = f"Analyze these logs:\n\n{log_content}"

    if provider == "gemini":
        from google.genai import types
        resp = client.models.generate_content(
            model=model,
            contents=[types.Content(role="user", parts=[types.Part(text=user_msg)])],
            config=types.GenerateContentConfig(system_instruction=system_prompt, temperature=0.0),
        )
        return _extract_json(resp.text)

    elif provider == "anthropic":
        resp = client.messages.create(
            model=model, max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_msg}],
        )
        return _extract_json(resp.content[0].text)

    elif provider == "openai":
        resp = client.chat.completions.create(
            model=model, temperature=0,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_msg},
            ],
        )
        return _extract_json(resp.choices[0].message.content)

    return {"error": f"Unknown provider: {provider}"}


# ── Provider: Gemini orchestrator loop ─────────────────────────────────────────
def _run_gemini_loop(client, model: str, tool_executor: Callable, on_progress: Callable) -> None:
    from google.genai import types
    try:
        from google.genai import errors as _gerr
    except ImportError:
        _gerr = None

    # Build Gemini tool declarations
    def _to_gemini_schema(params: dict):
        props = {}
        for k, v in params.get("properties", {}).items():
            t = v.get("type", "string").upper()
            props[k] = types.Schema(
                type=getattr(types.Type, t, types.Type.STRING),
                description=v.get("description", ""),
            )
        return types.Schema(
            type=types.Type.OBJECT,
            properties=props,
            required=params.get("required", []),
        )

    declarations = [
        types.FunctionDeclaration(
            name=t["name"],
            description=t["description"],
            parameters=_to_gemini_schema(t["parameters"]),
        )
        for t in ORCHESTRATOR_TOOLS
    ]

    config = types.GenerateContentConfig(
        system_instruction=_ORCHESTRATOR_PROMPT,
        tools=[types.Tool(function_declarations=declarations)],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    contents = [types.Content(
        role="user",
        parts=[types.Part(text=f"Current UTC: {_now()}. Activate all 5 specialist sub-agents, then write the final report.")],
    )]

    fallbacks = [model] + [m for m in GEMINI_FALLBACKS if m != model]
    active = model
    agents_called: set = set()

    while True:
        if len(agents_called) >= 5:
            on_progress("  [Orchestrator] All agents done — synthesizing final report ...")

        response = None
        for m in fallbacks:
            try:
                response = client.models.generate_content(model=m, contents=contents, config=config)
                if m != active:
                    on_progress(f"  [fallback] Switched to: {m}")
                    active = m
                break
            except Exception as exc:
                if _gerr and isinstance(exc, _gerr.ServerError) and (
                    getattr(exc, "status_code", 0) == 503 or "UNAVAILABLE" in str(exc)
                ):
                    on_progress(f"  [!] {m} unavailable (503) — trying next ...")
                else:
                    raise
        if response is None:
            raise RuntimeError("All Gemini models unavailable")

        candidate = response.candidates[0]
        if candidate.content is None:
            on_progress("  [Orchestrator] Warning: empty response — stopping loop")
            break
        contents.append(candidate.content)

        fn_calls = [p.function_call for p in candidate.content.parts if getattr(p, "function_call", None)]
        if not fn_calls:
            break

        result_parts = []
        for fc in fn_calls:
            if fc.name.startswith("analyze_"):
                agents_called.add(fc.name)
            result = tool_executor(fc.name, dict(fc.args) if fc.args else {}, on_progress)
            result_parts.append(types.Part(
                function_response=types.FunctionResponse(name=fc.name, response=result)
            ))
        contents.append(types.Content(role="user", parts=result_parts))


# ── Provider: Anthropic orchestrator loop ──────────────────────────────────────
def _run_anthropic_loop(client, model: str, tool_executor: Callable, on_progress: Callable) -> None:
    tools = [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": {
                **t["parameters"],
                "additionalProperties": False,
            },
        }
        for t in ORCHESTRATOR_TOOLS
    ]

    messages = [{"role": "user", "content": (
        f"Current UTC: {_now()}. Activate all 5 specialist sub-agents to analyze the logs, "
        "then write the final synthesized report."
    )}]

    while True:
        response = client.messages.create(
            model=model,
            max_tokens=8192,
            system=_ORCHESTRATOR_PROMPT,
            tools=tools,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            break

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = tool_executor(block.name, block.input or {}, on_progress)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result),
                })
        messages.append({"role": "user", "content": tool_results})


# ── Provider: OpenAI orchestrator loop ────────────────────────────────────────
def _run_openai_loop(client, model: str, tool_executor: Callable, on_progress: Callable) -> None:
    tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in ORCHESTRATOR_TOOLS
    ]

    messages = [
        {"role": "system", "content": _ORCHESTRATOR_PROMPT},
        {"role": "user",   "content": (
            f"Current UTC: {_now()}. Activate all 5 specialist sub-agents to analyze the logs, "
            "then write the final synthesized report."
        )},
    ]

    while True:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            break

        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments or "{}")
            result = tool_executor(tc.function.name, args, on_progress)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result),
            })


# ── Programmatic report builder (fallback when LLM synthesis fails) ────────────
def _build_report(sub_results: dict, generated_at: str) -> dict:
    all_errors = []
    all_alerts = []
    for result in sub_results.values():
        all_errors.extend(result.get("errors_found", []))
        all_alerts.extend(result.get("alerts", []))

    critical = sum(1 for e in all_errors if e.get("severity") == "Critical")
    high     = sum(1 for e in all_errors if e.get("severity") == "High")
    medium   = sum(1 for e in all_errors if e.get("severity") == "Medium")
    low      = sum(1 for e in all_errors if e.get("severity") == "Low")

    health = "Down" if critical > 0 else ("Degraded" if high > 0 else "Healthy")

    errors_1h  = sum(r.get("total_errors_last_hour", 0)  for r in sub_results.values())
    errors_24h = sum(r.get("total_errors_last_24h",  0)  for r in sub_results.values())

    service_counts: dict = {}
    for e in all_errors:
        svc = e.get("service", "unknown")
        service_counts[svc] = service_counts.get(svc, 0) + 1
    top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "generated_at": generated_at,
        "summary": {
            "total_errors_last_hour":    errors_1h,
            "total_errors_last_24_hours": errors_24h,
            "critical_count": critical,
            "high_count":     high,
            "medium_count":   medium,
            "low_count":      low,
            "system_health":  health,
        },
        "errors": all_errors,
        "alerts": all_alerts,
        "trends": {
            "top_failing_services": [[svc, cnt] for svc, cnt in top_services],
            "errors_by_hour":       [],
            "recurring_issues":     [],
            "anomaly_spikes":       [],
        },
    }


# ── Main entry point ───────────────────────────────────────────────────────────
def run_orchestrator_multi(
    provider_key: str,
    api_key: str,
    model: str,
    log_files_dict: dict,
    on_progress: Callable,
) -> dict:
    """
    Run the full multi-agent orchestrator.

    Args:
        provider_key  : "gemini" | "anthropic" | "openai"
        api_key       : User's API key for the chosen provider
        model         : Model identifier string
        log_files_dict: {filename: file_content_str} mapping
        on_progress   : Callback(str) for streaming progress messages

    Returns:
        dict — the monitoring report (same schema as monitoring_output.json)
    """
    # ── Init client ────────────────────────────────────────────────────────────
    if provider_key == "gemini":
        from google import genai as _genai
        client = _genai.Client(api_key=api_key)

    elif provider_key == "anthropic":
        import anthropic as _anthropic
        client = _anthropic.Anthropic(api_key=api_key)

    elif provider_key == "openai":
        from openai import OpenAI as _OpenAI
        client = _OpenAI(api_key=api_key)

    else:
        raise ValueError(f"Unknown provider: {provider_key!r}")

    # ── Sub-agent runner ───────────────────────────────────────────────────────
    def _run_sub_agent(domain: str, system_prompt: str, log_names: list[str]) -> dict:
        content = _read_logs(log_files_dict, log_names)
        on_progress(f"      {domain} Agent  → analyzing ...")
        result = _call_sub_agent(provider_key, client, model, system_prompt, content)
        n = len(result.get("errors_found", []))
        h = result.get("health", "?")
        on_progress(f"      {domain} Agent  ← {n} error(s) | health={h}")
        return result

    # ── Report + sub-agent result holders ─────────────────────────────────────
    report_holder: dict = {}
    sub_results: dict = {}

    # ── Tool executor (shared by all provider loops) ───────────────────────────
    def tool_executor(name: str, args: dict, cb: Callable) -> dict:
        if name == "analyze_security_logs":
            r = _run_sub_agent("Security",       _SECURITY_PROMPT, ["security.log"])
            sub_results["security"] = r; return r
        if name == "analyze_database_logs":
            r = _run_sub_agent("Database",       _DATABASE_PROMPT, ["db.log"])
            sub_results["database"] = r; return r
        if name == "analyze_api_logs":
            r = _run_sub_agent("API",            _API_PROMPT,      ["api.log"])
            sub_results["api"] = r; return r
        if name == "analyze_application_logs":
            r = _run_sub_agent("Application",    _APP_PROMPT,      ["app.log"])
            sub_results["application"] = r; return r
        if name == "analyze_infrastructure_logs":
            r = _run_sub_agent("Infrastructure", _INFRA_PROMPT,    ["server.log", "k8s.log", "cicd.log"])
            sub_results["infrastructure"] = r; return r
        if name == "write_monitoring_report":
            try:
                report = json.loads(args.get("report_json", "{}"))
            except json.JSONDecodeError as exc:
                return {"error": f"Invalid JSON: {exc}"}
            report_holder["report"] = report
            on_progress("  [Orchestrator] ✓ Report written")
            return {"status": "ok"}
        return {"error": f"Unknown tool: {name}"}

    # ── Dispatch to provider-specific loop ─────────────────────────────────────
    if provider_key == "gemini":
        _run_gemini_loop(client, model, tool_executor, on_progress)
    elif provider_key == "anthropic":
        _run_anthropic_loop(client, model, tool_executor, on_progress)
    elif provider_key == "openai":
        _run_openai_loop(client, model, tool_executor, on_progress)

    # ── Fallback: build report programmatically if LLM synthesis failed ────────
    if not report_holder.get("report") and sub_results:
        on_progress("  [Orchestrator] LLM synthesis incomplete — building report from agent results ...")
        report_holder["report"] = _build_report(sub_results, _now())

    return report_holder.get("report", {})
