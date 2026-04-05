# WebSpidey v2 — Web Vulnerability Scanner

A third-year engineering project that scans web applications for common security vulnerabilities.
Built with Flask (backend API) and React (frontend UI).

---

## What it does

Scans a target URL for the following vulnerabilities:

| Scanner | Severity | Description |
|---|---|---|
| SQL Injection | Critical | Tests form inputs with SQL payloads, checks for error/response-diff |
| XSS | High | Injects script tags into forms and URL params, checks reflection |
| CSRF | Medium | Finds POST forms with no CSRF token field |
| Open Redirect | Medium | Injects external URL into redirect parameters |
| Directory Exposure | High | Probes 17 common sensitive paths (/admin, /.git, /.env, etc.) |
| SSRF | High | Detects URL-accepting params, probes internal addresses |
| Auth Weaknesses | Critical | Tests default creds, checks for rate limiting |
| Security Headers | Medium | Checks 6 required headers + cookie flags + server disclosure |

Additional features:
- **Explainable AI** — each finding explains *why* it's a vulnerability, *how* it was detected, and *how to fix it* (rule-based, no external APIs)
- **PDF report** — download a structured report with all findings and remediation steps
- **Chatbot** — ask questions about the scan results or any vulnerability type (rule-based, no APIs)
- **Live scan progress** — real-time progress bar with scan log

---

## Project structure

```
webspidey_v2/
├── backend/                  ← Flask API
│   ├── app.py                ← Main Flask app, scan job management
│   ├── crawler.py            ← Web crawler (same-domain BFS)
│   ├── requirements.txt
│   ├── scanners/
│   │   ├── sql_scanner.py
│   │   ├── xss_scanner.py
│   │   ├── header_scanner.py
│   │   ├── csrf_scanner.py
│   │   ├── redirect_scanner.py
│   │   ├── directory_scanner.py
│   │   ├── ssrf_scanner.py
│   │   └── auth_scanner.py
│   └── services/
│       ├── risk.py           ← OWASP-style risk scoring
│       ├── explainer.py      ← Rule-based XAI explanations
│       ├── chatbot.py        ← Rule-based chatbot
│       └── pdf_generator.py  ← ReportLab PDF export
├── frontend/                 ← React app
│   ├── public/index.html
│   ├── package.json
│   └── src/
│       ├── App.js / App.css
│       ├── index.js / index.css
│       └── components/
│           ├── ScanForm.js       ← URL input
│           ├── ScanProgress.js   ← Live progress with log
│           ├── ResultsDashboard.js ← Main results view
│           ├── VulnCard.js       ← Collapsible finding cards
│           └── Chatbot.js        ← Floating chat widget
└── demo_site/
    └── app.py                ← Intentionally vulnerable Flask app (port 9000)
```

---

## Setup & Run

### Requirements
- Python 3.8+
- Node.js 16+ and npm

### Step 1 — Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Backend runs on **http://localhost:5000**

### Step 2 — Frontend

```bash
cd frontend
npm install
npm start
```

Frontend runs on **http://localhost:3000**

Open your browser at **http://localhost:3000** to use the scanner.

### Step 3 (Optional) — Demo vulnerable site

Run the intentionally vulnerable test site to scan locally:

```bash
cd demo_site
python app.py
```

Demo site runs on **http://localhost:9000**

Then in the scanner, enter: `http://localhost:9000`

---

## Demo site vulnerabilities

The demo site (`demo_site/app.py`) is **intentionally vulnerable** for testing:

| Path | Vulnerability |
|---|---|
| `/login` | SQL Injection + default creds (admin/admin) + no rate limiting |
| `/search?q=` | Reflected XSS |
| `/contact` | CSRF (POST form, no token) |
| `/redirect?next=` | Open Redirect |
| `/fetch?url=` | SSRF |
| `/admin` | Exposed admin panel |
| `/api/data` | Sensitive data exposure (API keys, tokens) |

---

## How scanning works

1. User enters a URL and clicks "Start Scan"
2. Frontend sends POST to `/api/scan`, gets back a `job_id`
3. Backend starts the scan in a background thread
4. Frontend polls `/api/scan/<job_id>` every second for progress
5. Each scanner runs independently on the crawled URLs
6. Results are stored in memory under the job ID
7. Frontend renders the results dashboard when scan is complete

---

## Chatbot usage examples

| You ask | Bot responds |
|---|---|
| "show risk score" | Risk level and score from scan |
| "how many XSS issues" | XSS finding count and affected URLs |
| "what is SQL injection" | Definition and fix advice |
| "show summary" | Full breakdown of all findings |
| "what is SSRF" | SSRF explanation |
| "how to fix CSRF" | Specific remediation steps |

---

## Notes

- The scanner is designed for educational and authorized testing only
- Scan depth is limited to 15 URLs to keep it practical for a demo
- Some scanners use heuristics — results may include false positives
- The chatbot uses keyword matching — it's not a language model
- No data is stored permanently — all results are in-memory per session

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-CORS |
| HTTP requests | requests, BeautifulSoup4 |
| PDF export | ReportLab |
| Frontend | React 18 |
| Styling | Plain CSS (no frameworks) |
| State | React useState/useEffect |

---

*WebSpidey v2 — Third-year engineering project.*
