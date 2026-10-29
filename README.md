# 🛡️ NemoSec & Socratic PR Auditor

A full-stack, dual-branch **DevSecOps & Socratic Code Review Agent** powered by **NVIDIA Nemotron on Nebius Token Factory**, **LangGraph**, **FastAPI SSE**, **Live Snyk Code AST Scanning**, and **GitHub PR Integration**.

---

## ✨ Hackathon Demo Highlights

When a developer submits a **GitHub Pull Request URL** (e.g., `https://github.com/Harinath0225/nemosec-pr-auditor/pull/1`) or selects a 1-click preset:

1. **Branch A — Socratic Intent Agent (`socratic_intent_node`):**
   - Analyzes the PR diff and source code using NVIDIA Nemotron (`nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` or `nvidia/nemotron-3-super-120b`).
   - Identifies architectural & security trade-offs.
   - Generates **3 probing Socratic questions** and **posts them directly to the GitHub Pull Request comments** (and syncs interactive author replies back to the PR thread).
   - Auto-drafts a structured **PR Intent & Changelog** document.

2. **Branch B — SecOps Auto-Remediation & Snyk Verification Agent (`snyk_scanner_node` → `sandbox_patcher_node`):**
   - Scans the PR target code with the **Live Snyk Code & AST Vulnerability Engine** (`SNYK-PYTHON-SQLITE3-612941` / `CVE-2024-8912` or `SNYK-PYTHON-SUBPROCESS-704821` / `CVE-2024-9401`).
   - Generates a remediated security patch and unified diff.
   - Spins up an **isolated temporary sandbox (`tempfile` + `subprocess`)** running `pytest -v` against both functional tests and security exploit payloads.
   - Creates the remediation branch (`fix/secops-<cve-id>`), pushes the fix to the PR, and **re-runs the Snyk scan on the remediated code** to verify that the issue count drops from **`1 Critical` → `0 Vulnerabilities Found (RESOLVED)`**.

---

## 📂 Project Structure

```text
nemosec-pr-auditor/
├── .env.example
├── README.md
├── demo-vulnerable-app/        # Isolated target microservice for live GitHub PR audits
│   ├── README.md
│   ├── payment_ledger.py       # PR #1 Target: SQL Injection (CWE-89 / CVE-2024-8912)
│   └── webhook_diagnostics.py  # PR #2 Target: Command Injection (CWE-78 / CVE-2024-9401)
├── backend/
│   ├── requirements.txt
│   ├── main.py                 # FastAPI app + SSE streaming & GitHub/Snyk endpoints
│   ├── config.py               # Env loader & Nebius Token Factory LLM client
│   ├── github_service.py       # GitHub REST/MCP PR fetcher, comment poster & branch pusher
│   ├── snyk_scanner.py         # Live Snyk Code & AST analyzer (verifies 1 -> 0 issues)
│   ├── fixtures/
│   │   └── sample_payloads.py  # 2 built-in vulnerable code + Snyk JSON presets
│   ├── sandbox/
│   │   └── runner.py           # Temp-dir pytest runner & git branch creator
│   └── agent/
│       ├── state.py            # LangGraph TypedDict state schema
│       ├── nodes.py            # Socratic node, Snyk scanner node, Sandbox patcher node
│       └── graph.py            # Compiled parallel StateGraph
└── frontend/
    ├── package.json
    ├── vite.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx             # Main split-screen dashboard + PR bar + Settings drawer
        └── components/
            ├── GraphVisualizer.jsx  # Live visual DAG showing active LangGraph nodes
            ├── SocraticPanel.jsx    # Left branch UI: Socratic questions, PR comments & changelog
            └── SecOpsPanel.jsx      # Right branch UI: Snyk CVE badge (1 -> 0 issues), Pytest logs, Diff
```

---

## 🚀 Quick Start

### 1. Backend Setup (FastAPI + LangGraph + Pytest)
```powershell
cd nemosec-pr-auditor
Copy-Item .env.example .env
# Edit .env or configure keys directly inside the Web UI Settings modal!

cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Setup (React + Vite + Tailwind CSS)
```powershell
cd nemosec-pr-auditor/frontend
npm install
npm run dev
```
Open **http://localhost:5173** in your browser.
