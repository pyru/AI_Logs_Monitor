---
title: AI Log Monitoring Dashboard
emoji: 🔍
colorFrom: purple
colorTo: blue
sdk: gradio
sdk_version: 5.0.0
app_file: app.py
pinned: false
license: mit
---

# AI Log Monitoring Dashboard

A multi-agent AI log monitoring system. Five specialist AI sub-agents analyze every domain (security, database, API, application, infrastructure), an orchestrator synthesizes the findings, and a live web dashboard displays the results.

Supports **Google Gemini**, **Anthropic Claude**, and **OpenAI GPT** — bring your own API key.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Architecture](#architecture)
3. [Local Setup & Testing](#local-setup--testing)
   - [Step 1 — Clone & Install](#step-1--clone--install)
   - [Step 2 — Verify installation](#step-2--verify-installation)
   - [Step 3 — Test Mode 1: Rule-based (no API key)](#step-3--test-mode-1-rule-based-no-api-key)
   - [Step 4 — Test Mode 2: Gradio Web App](#step-4--test-mode-2-gradio-web-app)
   - [Step 5 — Test Mode 3: CLI Orchestrator (Gemini)](#step-5--test-mode-3-cli-orchestrator-gemini)
   - [Step 6 — View the dashboard](#step-6--view-the-dashboard)
   - [Step 7 — Confirm end-to-end with a new log entry](#step-7--confirm-end-to-end-with-a-new-log-entry)
4. [Execution Modes Compared](#execution-modes-compared)
5. [GitHub — Push & Manage](#github--push--manage)
6. [Hugging Face Spaces — Deploy](#hugging-face-spaces--deploy)
7. [API Keys](#api-keys)
8. [Sub-agent Specializations](#sub-agent-specializations)
9. [Dashboard Views](#dashboard-views)
10. [Limitations & Constraints](#limitations--constraints)
11. [Troubleshooting](#troubleshooting)
12. [Security Notes](#security-notes)

---

## Project Structure

```
Logs_monitoring/
│
├── app.py                  ← Gradio web app (HF Spaces entry point)
├── multi_provider.py       ← Multi-provider orchestrator engine (Gemini/Claude/OpenAI)
├── orchestrator_agent.py   ← CLI orchestrator (Gemini-only, uses .env)
├── ai_agent.py             ← CLI single agent (Gemini-only, uses .env)
├── monitor.py              ← Rule-based regex engine (no AI, no API key)
├── serve_dashboard.py      ← Local HTTP server for the dashboard
│
├── requirements.txt        ← pip dependencies (used by HF Spaces)
├── .env                    ← Local secrets — NEVER commit this
├── .gitignore
├── README.md
│
├── logs/                   ← Source log files
│   ├── app.log             ← Application logs
│   ├── api.log             ← API Gateway logs
│   ├── db.log              ← PostgreSQL logs
│   ├── security.log        ← Auth / security logs
│   ├── server.log          ← CPU / MEM / DISK metrics
│   ├── k8s.log             ← Kubernetes events
│   └── cicd.log            ← CI/CD pipeline logs
│
├── dashboard/
│   └── index.html          ← Web dashboard (4 tabs, auto-refreshes every 60s)
│
├── data/
│   └── monitoring_output.json   ← Generated report (read by dashboard)
│
└── alerts/
    └── alerts_YYYYMMDD_HHMMSS.json  ← Timestamped alert snapshots
```

---

## Architecture

```
User
 │
 ├── app.py (Gradio)          ← Web UI: provider / API key / file upload
 │    └── multi_provider.py   ← Works with any provider
 │
 └── orchestrator_agent.py   ← CLI: Gemini-only, reads .env
      │
      ▼
  Orchestrator LLM  ──────────────────────────────────────┐
      │                                                    │
      ├──▶ Security Agent     (own LLM call)  security.log │
      ├──▶ Database Agent     (own LLM call)  db.log       │
      ├──▶ API Agent          (own LLM call)  api.log      │
      ├──▶ Application Agent  (own LLM call)  app.log      │
      └──▶ Infrastructure Agent (own LLM call) server/k8s/cicd
                                                           │
      Orchestrator synthesizes all 5 findings ←───────────┘
                    │
                    ▼
      data/monitoring_output.json
                    │
                    ▼
      dashboard/index.html  (live dashboard)
```

**Total LLM calls per run: 6** (1 orchestrator + 5 sub-agents)

---

## Local Setup & Testing

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.9 or later | `python --version` |
| pip | any recent | comes with Python |
| API key | one of: Gemini / Claude / OpenAI | see [API Keys](#api-keys) |
| Browser | Chrome / Edge / Firefox | for the dashboard |

---

### Step 1 — Clone & Install

```bash
# Clone the repository
git clone https://github.com/your-username/Logs_monitoring.git
cd Logs_monitoring

# Install all dependencies
pip install -r requirements.txt
```

`requirements.txt` installs:

| Package | Used by |
|---|---|
| `gradio` | `app.py` web interface |
| `google-genai` | Gemini provider |
| `anthropic` | Claude provider |
| `openai` | OpenAI provider |

> **Tip:** Use a virtual environment to keep things clean:
> ```bash
> python -m venv venv
> venv\Scripts\activate      # Windows
> source venv/bin/activate   # macOS / Linux
> pip install -r requirements.txt
> ```

---

### Step 2 — Verify installation

```bash
python -c "import gradio; import google.genai; import anthropic; import openai; print('All packages OK')"
```

Expected output:
```
All packages OK
```

If a package is missing, run `pip install -r requirements.txt` again.

---

### Step 3 — Test Mode 1: Rule-based (no API key)

This confirms the project structure and sample logs are working **without any AI or API key**.

```bash
python monitor.py
```

Expected output:
```
[2026-04-29T16:03:36Z] AI Log Monitor starting ...
  Loaded 237 log lines from ...\logs
  Matched 16 unique error patterns
  Dashboard data written: ...\data\monitoring_output.json
  Alerts snapshot written: ...\alerts\alerts_20260429_160336.json

============================================================
  MONITORING REPORT — 2026-04-29T16:03:36Z
============================================================
  System Health  : Down
  Errors (1h)    : 0
  Errors (24h)   : 93
  Critical       : 8
  High           : 8
  Active Alerts  : 16
============================================================
```

**What this confirms:**
- Python is working
- All 7 sample log files in `logs/` are readable
- `data/monitoring_output.json` was created
- `alerts/` snapshot was written

Then open the dashboard to confirm the output renders:

```bash
python serve_dashboard.py
```

Browser opens automatically at **http://localhost:8000/dashboard/index.html**

You should see the Overview tab with health status, error counts, and charts.
Press `Ctrl+C` to stop the server.

---

### Step 4 — Test Mode 2: Gradio Web App

This is the main entry point for the multi-provider web UI.

```bash
python app.py
```

Expected output:
```
Running on local URL:  http://127.0.0.1:7860
```

Browser opens automatically. You will see:

```
┌─────────────────────────────────────────────────────────────┐
│  AI Log Monitoring Dashboard                                │
├──────────────────┬──────────────────────────────────────────┤
│ Configuration    │  [Progress Log]  [Dashboard]             │
│                  │                                          │
│ Provider: [▼]    │                                          │
│ API Key:  [***]  │                                          │
│ Model:    [    ] │                                          │
│                  │                                          │
│ Upload Logs:     │                                          │
│ [Drop files]     │                                          │
│                  │                                          │
│ □ Use sample logs│                                          │
│                  │                                          │
│ [▶ Run Analysis] │                                          │
└──────────────────┴──────────────────────────────────────────┘
```

**To test without an API key first** (confirm UI loads):
- Leave the API key blank
- Click **Run Analysis**
- You should see: `❌ Please enter your API key in the left panel.`

**To run a full analysis:**
1. Select your provider from the dropdown
2. Paste your API key
3. Leave "Use sample logs" checked (no upload needed)
4. Click **Run Analysis**
5. Watch the Progress Log — each sub-agent logs its status
6. When complete, click the **Dashboard** tab

Press `Ctrl+C` to stop.

---

### Step 5 — Test Mode 3: CLI Orchestrator (Gemini)

If you prefer the command line and have a Gemini key:

**5a. Create your `.env` file:**

```bash
# Windows
copy .env .env.backup   # optional backup of existing
```

Open `.env` and confirm it has:
```
GOOGLE_API_KEY=your_actual_gemini_api_key_here
MODEL=gemini-2.5-flash
```

**5b. Run the orchestrator:**

```bash
python orchestrator_agent.py
```

Expected output (takes 1–3 minutes while sub-agents run):
```
[2026-04-29T19:49:45Z] AI Log Monitor Orchestrator starting ...
  Model      : gemini-2.5-flash  (fallbacks: gemini-2.0-flash → gemini-1.5-flash → gemini-1.5-pro)
  Sub-agents : Security | Database | API | Application | Infrastructure
  Logs dir   : ...\logs

  [Orchestrator] → Security Agent
      Security Agent  → analyzing ...
      Security Agent  ← 4 error(s) | health=Down
  [Orchestrator] → Database Agent
      Database Agent  → analyzing ...
      Database Agent  ← 3 error(s) | health=Down
  [Orchestrator] → API Agent
      API Agent  → analyzing ...
      API Agent  ← 2 error(s) | health=Degraded
  [Orchestrator] → Application Agent
      Application Agent  → analyzing ...
      Application Agent  ← 3 error(s) | health=Down
  [Orchestrator] → Infrastructure Agent
      Infrastructure Agent  → analyzing ...
      Infrastructure Agent  ← 3 error(s) | health=Down
  [Orchestrator] → write_monitoring_report

============================================================
  ORCHESTRATOR REPORT — 2026-04-29T19:52:10Z
============================================================
  System Health  : Down
  Errors (1h)    : 23
  Errors (24h)   : 88
  Critical       : 8
  High           : 5
  Active Alerts  : 16
============================================================

  TOP ALERTS:
    [Critical] TOR Brute-Force Attack & Account Lockout
    [Critical] PostgreSQL Max Connections Exceeded
    ...
```

**What this confirms:**
- API key is valid
- Gemini API is reachable
- All 5 sub-agents ran successfully
- `data/monitoring_output.json` was updated with AI-generated content

---

### Step 6 — View the dashboard

After any analysis run (Step 3, 4, or 5), view the local dashboard:

```bash
python serve_dashboard.py
```

| Tab | What to check |
|---|---|
| **Overview** | Health badge shows `Down` / `Degraded` / `Healthy`, error counts match the report |
| **Error List** | Table has rows — click any row to open the detail modal |
| **Alerts** | All alerts visible with severity pills and escalation paths |
| **Trends & Analytics** | Charts render (requires internet for Chart.js CDN) |

> If the **Error List** is empty, check that `data/monitoring_output.json` exists and was written by the last run.

---

### Step 7 — Confirm end-to-end with a new log entry

This confirms the full refresh cycle works:

**7a.** While the dashboard is open in your browser (`python serve_dashboard.py` running), open a new terminal and append a test error to `logs/app.log`:

```bash
# Windows PowerShell
Add-Content logs\app.log "2026-04-29T12:00:00Z CRITICAL [PaymentService] FATAL: Stripe API unreachable - connection refused"
```

```bash
# macOS / Linux
echo "2026-04-29T12:00:00Z CRITICAL [PaymentService] FATAL: Stripe API unreachable - connection refused" >> logs/app.log
```

**7b.** Re-run the monitor:

```bash
# No API key needed:
python monitor.py

# Or with AI:
python orchestrator_agent.py
```

**7c.** The dashboard auto-reloads every 60 seconds. Press **F5** to refresh immediately.

**What to confirm:** The new PaymentService error appears in the Error List and Alerts tabs.

---

## Execution Modes Compared

| Mode | Entry point | API Key | Speed | Intelligence |
|---|---|---|---|---|
| Rule-based | `monitor.py` | None | < 1s | Regex matching only |
| Single AI agent | `ai_agent.py` | Gemini | 30–60s | One Gemini session, sequential |
| CLI Orchestrator | `orchestrator_agent.py` | Gemini | 1–3 min | 6 Gemini calls, Gemini-only |
| **Gradio Web App** | **`app.py`** | **Any** | **1–3 min** | **6 LLM calls, Gemini / Claude / OpenAI** |

### What makes this a true AI agent?

| | `monitor.py` | `ai_agent.py` | `app.py` / `orchestrator_agent.py` |
|---|---|---|---|
| Detection | `re.search()` regex | LLM inference | 5 specialist LLM sub-agents |
| Root cause | Hardcoded strings | Inferred | Inferred per domain |
| Cross-domain correlation | None | Basic | Yes — orchestrator synthesizes |
| Unknown log formats | Fails | Handled | Handled |
| Providers supported | — | Gemini only | Gemini, Claude, OpenAI |

---

## GitHub — Push & Manage

### Initial push

```bash
cd Logs_monitoring

# Initialize git (if not already done)
git init
git add .
git commit -m "Initial commit: AI Log Monitoring Dashboard"

# Create repo on GitHub, then:
git remote add origin https://github.com/your-username/Logs_monitoring.git
git branch -M main
git push -u origin main
```

### What gets committed vs ignored

| Included | Ignored |
|---|---|
| All source `.py` files | `.env` (API key) |
| `logs/*.log` sample files | `data/monitoring_output.json` |
| `dashboard/index.html` | `alerts/*.json` |
| `requirements.txt` | `__pycache__/`, `venv/` |
| `README.md`, `.gitignore` | `gradio_cached_examples/` |

### Subsequent pushes

```bash
git add .
git commit -m "your message"
git push
```

---

## Hugging Face Spaces — Deploy

### One-time setup

1. Go to **https://huggingface.co/new-space**
2. Fill in:
   - **Space name**: e.g., `ai-log-monitor`
   - **SDK**: `Gradio`
   - **Hardware**: `CPU Basic` (free tier)
   - **Visibility**: Public or Private
3. Click **Create Space**

### Push your code

```bash
# Add HF Space as a second remote
git remote add space https://huggingface.co/spaces/YOUR_HF_USERNAME/YOUR_SPACE_NAME

# Push (HF Spaces builds automatically from main branch)
git push space main
```

HF Spaces will:
1. Install `requirements.txt`
2. Run `python app.py`
3. Expose the Gradio UI at `https://huggingface.co/spaces/YOUR_HF_USERNAME/YOUR_SPACE_NAME`

### Update the Space

```bash
# After any local changes:
git add .
git commit -m "update"
git push space main    # triggers HF rebuild (~1 min)
```

### Keep GitHub and HF Space in sync

```bash
# Push to both at once:
git push origin main
git push space main
```

Or configure a GitHub Action to auto-sync on push (optional).

---

## API Keys

| Provider | Where to get a key | Default model |
|---|---|---|
| Google Gemini | https://aistudio.google.com/apikey | `gemini-2.5-flash` |
| Anthropic Claude | https://console.anthropic.com | `claude-opus-4-7` |
| OpenAI | https://platform.openai.com/api-keys | `gpt-4o` |

### For local CLI use (`.env` file)

```
GOOGLE_API_KEY=AIza...
MODEL=gemini-2.5-flash
```

The `.gitignore` excludes `.env` — your key is never committed.

### For the Gradio web app

Enter the key directly in the **API Key** field. It is used in-memory only and never stored or logged.

---

## Sub-agent Specializations

| Sub-agent | Log file(s) | What it detects |
|---|---|---|
| Security Agent | `security.log` | TOR IPs, brute force, credential theft, JWT anomalies, CVEs, data exfiltration |
| Database Agent | `db.log` | Connection pool exhaustion, deadlocks, lock timeouts, slow queries, table bloat |
| API Agent | `api.log` | HTTP 502/503/500, latency spikes >2s, circuit breaker events, retry storms |
| Application Agent | `app.log` | OOM errors, payment gateway failures, service crashes, NullPointerExceptions |
| Infrastructure Agent | `server.log`, `k8s.log`, `cicd.log` | CPU/MEM/DISK pressure, CrashLoopBackOff, CI/CD failures, expired credentials |

---

## Dashboard Views

| Tab | Contents |
|---|---|
| **Overview** | Health badge, error counts by severity, doughnut chart, top services bar chart, active incidents table |
| **Error List** | Searchable/filterable table — click any row to open a detail modal with root cause, actions, and log evidence |
| **Alerts** | All alerts with severity pills, escalation path, trend indicator |
| **Trends & Analytics** | Hourly error timeline, service distribution chart, recurring issues, anomaly spikes |

The dashboard auto-reloads `data/monitoring_output.json` every **60 seconds**.

---

## Limitations & Constraints

### Architecture

| Constraint | Detail |
|---|---|
| Sequential sub-agents | All 5 sub-agents run one after another, not in parallel. Total time = sum of all 6 LLM calls (typically 1–3 min). |
| One-shot analysis | There is no continuous monitoring loop. Each run is a full analysis of the current log snapshot. |
| No cross-file correlation in sub-agents | Each sub-agent reads only its assigned log files. Raw cross-file correlation (e.g., a timestamp in `api.log` matching one in `db.log`) is done only by the orchestrator during synthesis, not during sub-agent analysis. |
| LLM synthesis can fail on small models | After all 5 sub-agents return results, the combined context can exceed what smaller models (e.g., `gemini-2.5-flash-lite`) can synthesize reliably. When this happens, the system falls back to **programmatic report assembly** — the 5 sub-agent results are merged in code instead of by the LLM. Cross-domain correlations and narrative text will be absent in the fallback report. |
| Orchestrator fallback (Gemini only) | The model fallback chain (`gemini-2.5-flash → gemini-2.0-flash → …`) only applies to the Gemini provider. Claude and OpenAI loops use a single model with no automatic retry. |

---

### Model & API

| Constraint | Detail |
|---|---|
| Rate limits | Each run makes **6 LLM API calls** (1 orchestrator + 5 sub-agents). Heavy usage may hit per-minute or per-day rate limits on free-tier API keys. |
| API cost | All three providers charge per token. A full analysis run with 7 log files typically costs $0.01–$0.10 depending on the model and provider. |
| Response quality | LLM output is non-deterministic — identical logs may produce slightly different findings across runs. |
| No ground-truth validation | The system cannot verify whether a detected error is a true positive. False positives and missed errors are possible. |
| Context window | Log files are read in full into the model context. Very large log files (>100K lines) may be truncated or cause errors. The practical limit per sub-agent is ~100K tokens of log content. |
| Gemini `flash-lite` limitations | `gemini-2.5-flash-lite` is optimized for speed over reasoning depth. It may miss subtle patterns, produce incomplete JSON, or fail on large tool responses. Prefer `gemini-2.5-flash` or `gemini-2.0-flash` for more reliable output. |

---

### Log Ingestion

| Constraint | Detail |
|---|---|
| File formats | Accepts `.log` and `.txt` plain-text files only. Binary logs, compressed logs (`.gz`), structured JSON logs, and syslog are not natively supported. |
| No log streaming | Logs are read once per run as a full file. There is no tail/streaming of live log files. |
| No log rotation | If logs are rotated (e.g., `app.log.1`, `app.log.2`), only the file explicitly uploaded or matched by name is analyzed. |
| Entire file in memory | Each log file is read fully into Python memory. Very large files (>500MB) may cause OOM errors depending on the machine. |
| Sub-agent file assignment | Sub-agents are assigned log files by name pattern (e.g., `security`, `db`, `api`). Files with non-standard names may fall back to scanning all available logs. |

---

### Dashboard

| Constraint | Detail |
|---|---|
| Static snapshot | The dashboard displays the most recent report only. There is no historical comparison or trend across multiple runs. |
| 60-second auto-refresh | The dashboard polls `data/monitoring_output.json` every 60 seconds when served locally. The Gradio embedded version uses injected data and does not auto-refresh without re-running the analysis. |
| CDN dependency | Charts (Chart.js) are loaded from `cdn.jsdelivr.net`. The dashboard will render without charts in air-gapped or offline environments. |
| No real-time alerting | The dashboard is display-only. It does not send emails, Slack messages, PagerDuty pages, or webhooks. |
| Browser-only | The dashboard has no API or programmatic interface for downstream consumers. |

---

### Deployment (Hugging Face Spaces)

| Constraint | Detail |
|---|---|
| CPU Basic tier | Free-tier Spaces have 2 vCPUs and 16 GB RAM. Analysis runs may be slower than on a local machine with a fast internet connection. |
| No persistent storage | Files written during a session (e.g., `data/monitoring_output.json`, `alerts/*.json`) are ephemeral. They do not persist across Space restarts. |
| Session timeout | HF Spaces may pause after extended inactivity. The Gradio session and any in-progress analysis will be lost. |
| Public visibility | If the Space is set to Public, anyone can access the UI and run analyses using their own API key. Set to Private if that is not intended. |
| No Secrets in HF UI | Never paste API keys into the code or commit them. Use the HF Space **Secrets** settings panel to provide environment variables if needed for server-side defaults. |

---

### Operational

| Constraint | Detail |
|---|---|
| No scheduling | There is no built-in cron or scheduled analysis. You must manually trigger a run each time. |
| No alerting integration | Escalation paths in the report (PagerDuty, Slack) are text recommendations only — no actual integrations are wired. |
| No user authentication | The Gradio UI has no login. Anyone with access to the URL can run analyses. |
| Single-user | There is no multi-user isolation. Concurrent runs from different users will overwrite `data/monitoring_output.json` with the last writer's result. |

---



### "All packages OK" check fails

```bash
pip install --upgrade -r requirements.txt
```

### 503 UNAVAILABLE from Gemini

`orchestrator_agent.py` automatically falls back through:
`gemini-2.5-flash → gemini-2.0-flash → gemini-1.5-flash → gemini-1.5-pro`

If all fail, wait a few minutes and retry. Gemini has occasional demand spikes.

### Error List tab is empty after running monitor.py

Check that `data/monitoring_output.json` exists:
```bash
# Windows
dir data\monitoring_output.json

# macOS / Linux
ls -la data/monitoring_output.json
```

If missing, re-run `python monitor.py` and check for errors.

### Dashboard shows "LOADING..." after page open

The dashboard is fetching `data/monitoring_output.json`. If the file doesn't exist yet, the dashboard uses its embedded fallback data. Run any analysis mode first.

### Chart.js charts are blank (offline)

Download Chart.js locally:
```bash
curl -o dashboard/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js
```

Then edit `dashboard/index.html` — change:
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
```
to:
```html
<script src="chart.umd.min.js"></script>
```

### Gradio app port already in use

```bash
python app.py --server-port 7861
```

Or set in code: `demo.launch(server_port=7861)`

### HF Space build fails

Check the **Logs** tab of your Space. Common causes:
- Package version conflict → relax version pins in `requirements.txt`
- Missing `app.py` at repo root → confirm the file is committed
- Wrong SDK selected → must be **Gradio**, not Docker or Streamlit

---

## Security Notes

- **API keys** are never stored — entered in-memory via the Gradio UI or read from `.env` locally.
- **`.env` is gitignored** — it will never be committed.
- **Log files are read locally** — no log content is sent anywhere except to the AI provider API you choose.
- **Dashboard on localhost only** — do not expose port 8000 to the internet without adding authentication.
- **Mask sensitive values** before writing to log files — tokens, passwords, and PII should never appear in plain-text logs.
