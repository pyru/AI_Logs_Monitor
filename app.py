"""
AI Log Monitoring Dashboard — Gradio App
Deploy to Hugging Face Spaces or run locally with: python app.py

Users provide their own API key and model. Log files can be uploaded
or the bundled sample logs are used automatically.
"""
import json
import queue
import threading
import datetime
from pathlib import Path

import gradio as gr

from multi_provider import (
    PROVIDERS,
    DEFAULT_MODELS,
    MODEL_SUGGESTIONS,
    run_orchestrator_multi,
)

BASE = Path(__file__).parent
SAMPLE_LOGS_DIR = BASE / "logs"
DASHBOARD_HTML  = BASE / "dashboard" / "index.html"


# ── Helpers ────────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_sample_logs() -> dict[str, str]:
    logs = {}
    if SAMPLE_LOGS_DIR.exists():
        for p in sorted(SAMPLE_LOGS_DIR.glob("*.log")):
            logs[p.name] = p.read_text(encoding="utf-8", errors="replace")
    return logs


def _inject_dashboard_data(report: dict) -> str:
    """
    Read dashboard/index.html and replace the EMBEDDED_DATA constant
    with the live report JSON, then wrap in a full-height iframe.
    """
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    data_json = json.dumps(report, ensure_ascii=False)

    # Replace: const EMBEDDED_DATA = <old JSON>;
    marker = "const EMBEDDED_DATA = "
    start = html.find(marker)
    if start != -1:
        start += len(marker)
        end = html.find(";\n", start)
        if end == -1:
            end = html.find(";", start)
        if end != -1:
            html = html[:start] + data_json + html[end:]

    import base64
    encoded = base64.b64encode(html.encode("utf-8")).decode()
    return (
        f'<iframe src="data:text/html;base64,{encoded}" '
        f'style="width:100%;height:920px;border:none;border-radius:8px;" '
        f'title="AI Log Monitoring Dashboard"></iframe>'
    )


# ── Analysis generator (streams progress to Gradio) ───────────────────────────
def run_analysis(provider_name, api_key, model_name, log_files, use_sample):
    """
    Gradio generator function — yields (progress_text, dashboard_html) tuples.
    Runs the orchestrator in a background thread and streams its output.
    """
    # ── Validate ───────────────────────────────────────────────────────────────
    if not api_key or not api_key.strip():
        yield "❌  Please enter your API key in the left panel.", ""
        return

    provider_key = PROVIDERS.get(provider_name, "gemini")
    model = model_name.strip() or DEFAULT_MODELS[provider_key]

    # ── Build log files dict ───────────────────────────────────────────────────
    logs: dict[str, str] = {}

    if log_files:
        for f in log_files:
            path = Path(f.name if hasattr(f, "name") else f)
            try:
                logs[path.name] = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                yield f"⚠️  Could not read {path.name}: {exc}", ""
                return

    if not logs and use_sample:
        logs = _load_sample_logs()
        if not logs:
            yield "❌  No sample logs found in logs/ directory.", ""
            return

    if not logs:
        yield "❌  No log files provided. Upload files or enable 'Use sample logs'.", ""
        return

    file_list = ", ".join(logs.keys())

    # ── Progress queue + background worker ────────────────────────────────────
    q: queue.Queue = queue.Queue()
    result_holder: dict = {}

    def worker():
        try:
            report = run_orchestrator_multi(
                provider_key=provider_key,
                api_key=api_key.strip(),
                model=model,
                log_files_dict=logs,
                on_progress=q.put,
            )
            result_holder["report"] = report
        except Exception as exc:
            result_holder["error"] = str(exc)
        finally:
            q.put(None)  # sentinel

    threading.Thread(target=worker, daemon=True).start()

    # ── Stream progress ────────────────────────────────────────────────────────
    lines = [
        f"[{_now()}] Starting {provider_name} orchestrator",
        f"  Model      : {model}",
        f"  Sub-agents : Security | Database | API | Application | Infrastructure",
        f"  Log files  : {file_list}",
        "",
    ]
    yield "\n".join(lines), ""

    while True:
        try:
            msg = q.get(timeout=360)
        except queue.Empty:
            yield "\n".join(lines) + "\n\n❌  Timeout — no response from AI provider.", ""
            return

        if msg is None:
            break

        lines.append(msg)
        yield "\n".join(lines), ""

    # ── Handle result ──────────────────────────────────────────────────────────
    if "error" in result_holder:
        err = result_holder["error"]
        lines.append(f"\n❌  Error: {err}")
        yield "\n".join(lines), ""
        return

    report = result_holder.get("report", {})
    if not report:
        lines.append("\n⚠️  Orchestrator returned no report. Check progress log.")
        yield "\n".join(lines), ""
        return

    s = report.get("summary", {})
    alerts = report.get("alerts", [])
    lines += [
        "",
        "=" * 58,
        f"  REPORT — {report.get('generated_at', _now())}",
        "=" * 58,
        f"  System Health  : {s.get('system_health', '?')}",
        f"  Errors (1h)    : {s.get('total_errors_last_hour', 0)}",
        f"  Errors (24h)   : {s.get('total_errors_last_24_hours', 0)}",
        f"  Critical       : {s.get('critical_count', 0)}",
        f"  High           : {s.get('high_count', 0)}",
        f"  Medium         : {s.get('medium_count', 0)}",
        f"  Low            : {s.get('low_count', 0)}",
        f"  Active Alerts  : {len(alerts)}",
        "=" * 58,
        "",
        "✅  Analysis complete — switch to the Dashboard tab.",
    ]

    try:
        dashboard_iframe = _inject_dashboard_data(report)
    except Exception as exc:
        lines.append(f"⚠️  Dashboard render error: {exc}")
        dashboard_iframe = ""

    yield "\n".join(lines), dashboard_iframe


# ── Model default helper ───────────────────────────────────────────────────────
def on_provider_change(provider_name):
    key = PROVIDERS.get(provider_name, "gemini")
    return (
        gr.update(value=DEFAULT_MODELS[key]),
        gr.update(value=f"Suggestions: {MODEL_SUGGESTIONS[key]}"),
    )


# ── Gradio UI ─────────────────────────────────────────────────────────────────
CSS = """
#run-btn { background: #7c3aed !important; color: #fff !important; font-size: 16px !important; }
#run-btn:hover { background: #6d28d9 !important; }
.progress-box textarea { font-family: 'Consolas', 'Courier New', monospace !important; font-size: 12px !important; }
footer { display: none !important; }
"""

with gr.Blocks(title="AI Log Monitoring Dashboard") as demo:

    gr.Markdown("""
# AI Log Monitoring Dashboard
**Multi-agent AI orchestrator** — 5 specialist sub-agents analyze your logs and synthesize a full incident report.
Supports **Google Gemini**, **Anthropic Claude**, and **OpenAI GPT** models.
    """)

    with gr.Row(equal_height=False):

        # ── Left panel: configuration ──────────────────────────────────────────
        with gr.Column(scale=1, min_width=300):
            gr.Markdown("### Configuration")

            provider_dd = gr.Dropdown(
                choices=list(PROVIDERS.keys()),
                value="Google Gemini",
                label="AI Provider",
            )
            api_key_box = gr.Textbox(
                type="password",
                label="API Key",
                placeholder="Paste your API key here...",
            )
            model_box = gr.Textbox(
                label="Model",
                value=DEFAULT_MODELS["gemini"],
                placeholder="Model identifier...",
            )
            model_hint = gr.Markdown(
                f"Suggestions: {MODEL_SUGGESTIONS['gemini']}",
                visible=True,
            )

            gr.Markdown("### Log Files")
            log_upload = gr.File(
                label="Upload log files (.log, .txt)",
                file_count="multiple",
                file_types=[".log", ".txt"],
            )
            use_sample = gr.Checkbox(
                label="Use bundled sample logs (if no files uploaded)",
                value=True,
            )

            run_btn = gr.Button(
                "▶  Run Analysis",
                variant="primary",
                size="lg",
                elem_id="run-btn",
            )

            gr.Markdown("""
---
**How it works**
1. Provider → API Key → Model
2. Upload your logs (or use sample logs)
3. Click **Run Analysis**
4. Switch to the **Dashboard** tab

**Sub-agents**
- Security Agent
- Database Agent
- API Agent
- Application Agent
- Infrastructure Agent
            """)

        # ── Right panel: output ────────────────────────────────────────────────
        with gr.Column(scale=3):
            with gr.Tabs():
                with gr.Tab("Progress Log"):
                    progress_box = gr.Textbox(
                        label="Orchestrator Output",
                        lines=28,
                        max_lines=100,
                        interactive=False,
                        elem_classes=["progress-box"],
                        placeholder=(
                            "Analysis progress will appear here...\n\n"
                            "Configure the provider and API key on the left, "
                            "then click Run Analysis."
                        ),
                    )

                with gr.Tab("Dashboard"):
                    dashboard_out = gr.HTML(
                        value=(
                            "<div style='display:flex;align-items:center;justify-content:center;"
                            "height:400px;color:#8b949e;font-family:system-ui;font-size:15px;'>"
                            "Run the analysis to load the dashboard.</div>"
                        ),
                        sanitize_html=False,
                    )

    # ── Wire up events ─────────────────────────────────────────────────────────
    provider_dd.change(
        fn=on_provider_change,
        inputs=[provider_dd],
        outputs=[model_box, model_hint],
    )

    run_btn.click(
        fn=run_analysis,
        inputs=[provider_dd, api_key_box, model_box, log_upload, use_sample],
        outputs=[progress_box, dashboard_out],
    )


# ── Launch ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    demo.queue()
    demo.launch(
        theme=gr.themes.Soft(primary_hue="violet", neutral_hue="slate"),
        css=CSS,
    )
