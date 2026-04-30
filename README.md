# AI Log Monitoring Dashboard

A multi-agent AI system that analyzes your server logs and generates a full incident report. Five specialist sub-agents (Security, Database, API, Application, Infrastructure) each analyze their domain **simultaneously**, and an orchestrator synthesizes the findings into a live web dashboard.

Supports **Google Gemini**, **Anthropic Claude**, and **OpenAI GPT** — bring your own API key.

**Live demo:** https://huggingface.co/spaces/Rpyru/ai-log-monitor  
**GitHub:** https://github.com/pyru/AI_Logs_Monitor

---

## How it works

```
Your Logs
    │
    ▼
Phase 1 — ThreadPoolExecutor (all 5 run simultaneously, ~30s)
    ├──▶ Security Agent      → analyzes security.log
    ├──▶ Database Agent      → analyzes db.log
    ├──▶ API Agent           → analyzes api.log
    ├──▶ Application Agent   → analyzes app.log
    └──▶ Infrastructure Agent → analyzes server.log, k8s.log, cicd.log
    │
    ▼
Phase 2 — Orchestrator LLM synthesizes all 5 findings (~15s)
    │
    ▼
Synthesized Report → Live Dashboard
```

**6 LLM calls per run** — 5 parallel sub-agents + 1 synthesis. Takes ~45s (vs ~3 min sequential).

---

## Project Files

| File | Purpose |
|---|---|
| `app.py` | Gradio web UI — main entry point (works locally and on HF Spaces) |
| `multi_provider.py` | Orchestrator engine supporting Gemini, Claude, and OpenAI |
| `orchestrator_agent.py` | CLI version — Gemini only, reads from `.env` |
| `ai_agent.py` | Single-agent CLI — Gemini only |
| `monitor.py` | Rule-based engine — no AI, no API key required |
| `dashboard/index.html` | Live web dashboard (4 tabs) |
| `logs/` | 7 sample log files for testing |
| `requirements.txt` | Dependencies for HF Spaces (Gradio handled separately) |

---

## Run Locally

### 1. Clone and install

```bash
git clone https://github.com/pyru/AI_Logs_Monitor.git
cd AI_Logs_Monitor

pip install gradio google-genai anthropic openai pillow
```

> **Tip:** Use a virtual environment first:
> ```bash
> python -m venv venv
> venv\Scripts\activate        # Windows
> source venv/bin/activate     # macOS / Linux
> ```

---

### 2. Start the web app

```bash
python app.py
```

Open **http://127.0.0.1:7860** in your browser.

---

### 3. Run an analysis

1. Select a provider (Google Gemini / Anthropic Claude / OpenAI)
2. Paste your API key
3. Leave **"Use sample logs"** checked — no upload needed
4. Click **Run Analysis**
5. Watch the **Progress Log** tab as each agent reports in
6. When done, click the **Dashboard** tab to see the full report

---

## Run Without an API Key (Rule-based)

No API key needed — uses regex pattern matching:

```bash
python monitor.py
```

Then view the dashboard locally:

```bash
python serve_dashboard.py
```

Opens at **http://localhost:8000/dashboard/index.html**

---

## CLI Mode (Gemini only)

Create a `.env` file in the project root:

```
GOOGLE_API_KEY=your_gemini_api_key_here
MODEL=gemini-2.5-flash
```

Then run:

```bash
python orchestrator_agent.py
```

---

## API Keys

| Provider | Get a key | Default model |
|---|---|---|
| Google Gemini | https://aistudio.google.com/apikey | `gemini-2.5-flash` |
| Anthropic Claude | https://console.anthropic.com | `claude-opus-4-7` |
| OpenAI | https://platform.openai.com/api-keys | `gpt-4o` |

Keys entered in the web app are used in-memory only — never stored or logged.

---

## Deploy to Hugging Face Spaces

### Step 1 — Create a Space

1. Go to https://huggingface.co/new-space
2. Set **SDK** to `Gradio`, **Hardware** to `CPU Basic` (free)
3. Click **Create Space**

### Step 2 — Push your code

```bash
# Add HF Space as a remote (one time)
git remote add space https://huggingface.co/spaces/YOUR_HF_USERNAME/YOUR_SPACE_NAME

# Push (HF Spaces uses the main branch)
git push space master:main
```

> When prompted for a password, use your HF **Access Token** (not your account password).  
> Generate one at: https://huggingface.co/settings/tokens → **Write** permission.

HF Spaces will install dependencies and start automatically. View build progress in the **Logs** tab of your Space.

### Step 3 — Push updates

```bash
# After making changes:
git add .
git commit -m "your message"
git push origin master          # update GitHub
git push space master:main      # update HF Spaces
```

---

## Dashboard Tabs

| Tab | What you see |
|---|---|
| **Overview** | System health badge, error counts by severity, top failing services |
| **Error List** | Searchable table — click any row for root cause and recommended actions |
| **Alerts** | All alerts with severity, escalation path, and trend indicator |
| **Trends & Analytics** | Hourly error timeline, service distribution, recurring issues |

---

## Execution Modes

| Mode | Entry point | API Key | Time |
|---|---|---|---|
| Rule-based | `monitor.py` | None | < 1s |
| Single agent (CLI) | `ai_agent.py` | Gemini | 30–60s |
| Orchestrator (CLI) | `orchestrator_agent.py` | Gemini | 1–3 min |
| **Web app (recommended)** | **`app.py`** | **Any** | **~45s (parallel)** |

---

## Troubleshooting

**App won't start — missing packages**
```bash
pip install gradio google-genai anthropic openai pillow
```

**HF Spaces build error**
- Check the **Logs** tab in your Space
- Confirm `app.py` is at the repo root
- Confirm the Space SDK is set to `Gradio`

**Analysis times out**
- Switch from `gemini-2.5-flash-lite` to `gemini-2.5-flash` — the lite model can struggle with large contexts
- The system will fall back to a programmatic report if the LLM synthesis step fails

**Dashboard tab is blank after analysis**
- Wait for the progress log to show "Analysis complete" before switching tabs
- If the issue persists, refresh the page and re-run

**Error List is empty after `monitor.py`**
- Check that `data/monitoring_output.json` was created:
  ```bash
  # Windows
  dir data\monitoring_output.json
  ```
- Re-run `python monitor.py` if missing

**Gemini 503 / quota errors**
- `orchestrator_agent.py` auto-retries with: `gemini-2.5-flash → gemini-2.0-flash → gemini-1.5-flash`
- If all fail, wait a few minutes — Gemini has occasional demand spikes

---

## Security

- `.env` is git-ignored — your API key is never committed
- Keys entered in the web UI are in-memory only — not stored or logged
- Do not expose `serve_dashboard.py` (port 8000) to the internet without authentication
- On HF Spaces, use the **Settings → Variables and Secrets** panel for any server-side defaults
