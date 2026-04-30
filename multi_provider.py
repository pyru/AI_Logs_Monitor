"""
Multi-provider AI Orchestrator Engine — Parallel Edition
Supports: Google Gemini | Anthropic Claude | OpenAI GPT

Architecture:
  Phase 1 — ThreadPoolExecutor: 5 specialist sub-agents run simultaneously (~30s)
  Phase 2 — Orchestrator LLM:   synthesizes all findings into one report (~15s)
  Total: ~45s  (vs ~3 min sequential)
"""
import json
import re
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
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
            parts.append(f"=== {name} === [NOT FOUND — showing all available logs]\n" +
                         "\n\n".join(f"=== {fn} ===\n{c}" for fn, c in log_files_dict.items()))
            break
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

# ── Tool definitions ───────────────────────────────────────────────────────────
ORCHESTRATOR_TOOLS = [
    {
        "name": "analyze_security_logs",
        "description": "Security specialist sub-agent.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_database_logs",
        "description": "Database specialist sub-agent.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_api_logs",
        "description": "API reliability specialist sub-agent.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_application_logs",
        "description": "Application specialist sub-agent.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "analyze_infrastructure_logs",
        "description": "Infrastructure specialist sub-agent.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "write_monitoring_report",
        "description": "Write the final synthesized monitoring report.",
        "parameters": {
            "type": "object",
            "properties": {
                "report_json": {
                    "type": "string",
                    "description": "Complete monitoring report as a valid JSON string.",
                }
            },
            "required": ["report_json"],
        },
    },
]

# Only the synthesis tool — used in Phase 2
_SYNTHESIS_TOOLS = [t for t in ORCHESTRATOR_TOOLS if t["name"] == "write_monitoring_report"]

# ── Synthesis prompt (Phase 2 — orchestrator sees all 5 results, writes report) ─
_SYNTHESIS_PROMPT = """
You are the Master Orchestrator of a multi-agent AI log monitoring system.
All 5 specialist sub-agents have already run in PARALLEL. Their findings are in the user message.

Synthesize all findings into one coherent report:
1. Correlate cross-domain events (e.g., DB pool exhaustion → API 502 errors → cascading failures).
2. De-duplicate errors that appear in multiple domains.
3. Sum all counts across domains.
4. Set system_health:
     "Down"     → any Critical errors exist
     "Degraded" → any High errors exist (no Critical)
     "Healthy"  → only Medium/Low or none

Call write_monitoring_report(report_json) ONCE with JSON matching exactly:
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
""".strip()


# ── Sub-agent: single LLM call, no tool use ────────────────────────────────────
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
            model=model, max_tokens=8192,
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


# ── Phase 1: Run all 5 agents simultaneously ───────────────────────────────────
def _run_agents_parallel(
    provider_key: str, client, model: str, log_files_dict: dict, on_progress: Callable
) -> dict:
    """
    Launch all 5 specialist sub-agents concurrently using ThreadPoolExecutor.
    Returns {domain_key: result_dict} — available as soon as all threads finish.
    on_progress is thread-safe (backed by queue.Queue in app.py).
    """
    configs = [
        ("Security",       _SECURITY_PROMPT, ["security.log"]),
        ("Database",       _DATABASE_PROMPT, ["db.log"]),
        ("API",            _API_PROMPT,      ["api.log"]),
        ("Application",    _APP_PROMPT,      ["app.log"]),
        ("Infrastructure", _INFRA_PROMPT,    ["server.log", "k8s.log", "cicd.log"]),
    ]

    def _run_one(domain: str, prompt: str, log_names: list[str]):
        content = _read_logs(log_files_dict, log_names)
        on_progress(f"  [{domain} Agent] → analyzing ...")
        result = _call_sub_agent(provider_key, client, model, prompt, content)
        n = len(result.get("errors_found", []))
        h = result.get("health", "?")
        on_progress(f"  [{domain} Agent] ← {n} error(s) | health={h}")
        return domain.lower(), result

    sub_results: dict = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_run_one, d, p, l): d for d, p, l in configs}
        for future in as_completed(futures):
            try:
                domain_key, result = future.result()
                sub_results[domain_key] = result
            except Exception as exc:
                domain = futures[future]
                on_progress(f"  [!] {domain} Agent error: {exc}")

    return sub_results


# ── Phase 2: Provider-specific synthesis (1 LLM call, write_monitoring_report tool) ──

def _synthesize_gemini(client, model: str, sub_results: dict, on_progress: Callable) -> dict:
    from google.genai import types

    def _to_schema(params: dict):
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

    tool = _SYNTHESIS_TOOLS[0]
    config = types.GenerateContentConfig(
        system_instruction=_SYNTHESIS_PROMPT,
        tools=[types.Tool(function_declarations=[
            types.FunctionDeclaration(
                name=tool["name"],
                description=tool["description"],
                parameters=_to_schema(tool["parameters"]),
            )
        ])],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    user_msg = f"Sub-agent findings (all 5 ran in parallel):\n\n{json.dumps(sub_results, indent=2)}"
    contents = [types.Content(role="user", parts=[types.Part(text=user_msg)])]

    fallbacks = [model] + [m for m in GEMINI_FALLBACKS if m != model]
    response = None
    for m in fallbacks:
        try:
            response = client.models.generate_content(model=m, contents=contents, config=config)
            if m != model:
                on_progress(f"  [synthesis] Switched to fallback: {m}")
            break
        except Exception as exc:
            on_progress(f"  [!] {m} unavailable — trying next ...")

    if response is None:
        return {}

    candidate = response.candidates[0]
    if candidate.content is None:
        return {}

    for part in candidate.content.parts:
        fc = getattr(part, "function_call", None)
        if fc and fc.name == "write_monitoring_report":
            try:
                return json.loads(fc.args.get("report_json", "{}"))
            except (json.JSONDecodeError, AttributeError):
                return {}

    # Fallback: parse free text if tool call wasn't used
    text = "".join(getattr(p, "text", "") for p in candidate.content.parts)
    return _extract_json(text) if text.strip() else {}


def _synthesize_anthropic(client, model: str, sub_results: dict, on_progress: Callable) -> dict:
    tool = _SYNTHESIS_TOOLS[0]
    tools = [{
        "name": tool["name"],
        "description": tool["description"],
        "input_schema": {**tool["parameters"], "additionalProperties": False},
    }]

    user_msg = f"Sub-agent findings (all 5 ran in parallel):\n\n{json.dumps(sub_results, indent=2)}"
    try:
        response = client.messages.create(
            model=model, max_tokens=8192,
            system=_SYNTHESIS_PROMPT,
            tools=tools,
            messages=[{"role": "user", "content": user_msg}],
        )
    except Exception as exc:
        on_progress(f"  [!] Anthropic synthesis error: {exc}")
        return {}

    for block in response.content:
        if getattr(block, "type", "") == "tool_use" and block.name == "write_monitoring_report":
            try:
                return json.loads((block.input or {}).get("report_json", "{}"))
            except json.JSONDecodeError as exc:
                on_progress(f"  [!] Anthropic report JSON parse error: {exc}")
                return {}

    # Fallback: text
    for block in response.content:
        if hasattr(block, "text"):
            return _extract_json(block.text)
    return {}


def _synthesize_openai(client, model: str, sub_results: dict, on_progress: Callable) -> dict:
    tool = _SYNTHESIS_TOOLS[0]
    tools = [{"type": "function", "function": {
        "name": tool["name"],
        "description": tool["description"],
        "parameters": tool["parameters"],
    }}]

    user_msg = f"Sub-agent findings (all 5 ran in parallel):\n\n{json.dumps(sub_results, indent=2)}"
    try:
        response = client.chat.completions.create(
            model=model, temperature=0,
            tools=tools, tool_choice="auto",
            messages=[
                {"role": "system", "content": _SYNTHESIS_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
        )
    except Exception as exc:
        on_progress(f"  [!] OpenAI synthesis error: {exc}")
        return {}

    msg = response.choices[0].message
    for tc in (msg.tool_calls or []):
        if tc.function.name == "write_monitoring_report":
            try:
                args = json.loads(tc.function.arguments or "{}")
                return json.loads(args.get("report_json", "{}"))
            except json.JSONDecodeError:
                return {}

    # Fallback: text
    return _extract_json(msg.content) if msg.content else {}


# ── Fallback: build report from sub-results if LLM synthesis fails ─────────────
def _build_report(sub_results: dict, generated_at: str) -> dict:
    all_errors: list = []
    all_alerts: list = []
    for result in sub_results.values():
        all_errors.extend(result.get("errors_found", []))
        all_alerts.extend(result.get("alerts", []))

    critical = sum(1 for e in all_errors if e.get("severity") == "Critical")
    high     = sum(1 for e in all_errors if e.get("severity") == "High")
    medium   = sum(1 for e in all_errors if e.get("severity") == "Medium")
    low      = sum(1 for e in all_errors if e.get("severity") == "Low")

    health = "Down" if critical > 0 else ("Degraded" if high > 0 else "Healthy")

    errors_1h  = sum(r.get("total_errors_last_hour", 0) for r in sub_results.values())
    errors_24h = sum(r.get("total_errors_last_24h",  0) for r in sub_results.values())

    service_counts: dict = {}
    for e in all_errors:
        svc = e.get("service", "unknown")
        service_counts[svc] = service_counts.get(svc, 0) + 1
    top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "generated_at": generated_at,
        "summary": {
            "total_errors_last_hour":     errors_1h,
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
    Run the full parallel multi-agent orchestrator.

    Phase 1: ThreadPoolExecutor runs all 5 sub-agents simultaneously.
    Phase 2: Orchestrator LLM synthesizes findings into one report.
    Phase 3: Programmatic fallback if LLM synthesis fails.
    """
    # ── Init provider client ───────────────────────────────────────────────────
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

    # ── Phase 1: Parallel sub-agents ──────────────────────────────────────────
    on_progress("  [Phase 1] Launching all 5 agents in parallel ...")
    sub_results = _run_agents_parallel(provider_key, client, model, log_files_dict, on_progress)

    if not sub_results:
        on_progress("  [!] No agent results returned. Check your API key and logs.")
        return {}

    completed = len(sub_results)
    on_progress(f"  [Phase 1] Done — {completed}/5 agents completed")

    # ── Phase 2: Synthesis ────────────────────────────────────────────────────
    on_progress("  [Phase 2] Orchestrator synthesizing final report ...")

    report: dict = {}
    try:
        if provider_key == "gemini":
            report = _synthesize_gemini(client, model, sub_results, on_progress)
        elif provider_key == "anthropic":
            report = _synthesize_anthropic(client, model, sub_results, on_progress)
        elif provider_key == "openai":
            report = _synthesize_openai(client, model, sub_results, on_progress)
    except Exception as exc:
        on_progress(f"  [!] Synthesis error: {exc}")

    if report and not report.get("parse_error"):
        on_progress("  [Phase 2] ✓ Report synthesized")
        return report

    # ── Phase 3: Programmatic fallback ────────────────────────────────────────
    on_progress("  [Phase 3] LLM synthesis incomplete — assembling report from agent results ...")
    return _build_report(sub_results, _now())
