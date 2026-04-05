"""
WebSpidey v2 - Main Flask Backend
Handles scan requests, results, PDF export, and chatbot.
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import threading
import uuid
import time

from crawler import crawl
from scanners.sql_scanner import scan_sql_injection
from scanners.xss_scanner import scan_xss
from scanners.header_scanner import scan_headers
from scanners.csrf_scanner import scan_csrf
from scanners.redirect_scanner import scan_open_redirect
from scanners.directory_scanner import scan_directories
from scanners.ssrf_scanner import scan_ssrf
from scanners.auth_scanner import scan_auth_weaknesses

from services.risk import classify_risk
from services.explainer import explain_vulnerability
from services.pdf_generator import generate_pdf_bytes
from services.chatbot import chatbot_reply

app = Flask(__name__)
app.secret_key = "webspidey_v2_secret"
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

# In-memory store for scan jobs (simple approach, no Redis needed)
scan_jobs = {}


def run_scan(job_id, target_url):
    """Run all scanners and store results in scan_jobs dict."""
    job = scan_jobs[job_id]
    job["status"] = "running"
    job["progress"] = 0
    job["log"] = []

    def log(msg):
        job["log"].append(msg)

    try:
        # Step 1: Crawl
        log("Starting crawler...")
        job["progress"] = 5
        discovered_urls = crawl(target_url)
        job["progress"] = 15
        log(f"Crawler found {len(discovered_urls)} URLs")

        # Step 2: Run scanners
        results = {}

        log("Running SQL Injection scan...")
        results["sqli"] = scan_sql_injection(discovered_urls)
        job["progress"] = 25
        log(f"SQL Injection: {len(results['sqli'])} findings")

        log("Running XSS scan...")
        results["xss"] = scan_xss(discovered_urls)
        job["progress"] = 35
        log(f"XSS: {len(results['xss'])} findings")

        log("Running Header security scan...")
        results["headers"] = scan_headers(target_url)
        job["progress"] = 45
        log(f"Missing headers: {len(results['headers'])}")

        log("Running CSRF detection...")
        results["csrf"] = scan_csrf(discovered_urls)
        job["progress"] = 55
        log(f"CSRF issues: {len(results['csrf'])}")

        log("Running Open Redirect scan...")
        results["open_redirect"] = scan_open_redirect(discovered_urls)
        job["progress"] = 63

        log("Running Directory Traversal scan...")
        results["directories"] = scan_directories(target_url)
        job["progress"] = 72

        log("Running SSRF detection...")
        results["ssrf"] = scan_ssrf(discovered_urls)
        job["progress"] = 82

        log("Running Auth weakness scan...")
        results["auth"] = scan_auth_weaknesses(discovered_urls)
        job["progress"] = 90

        # Step 3: Risk score
        log("Calculating risk score...")
        results["risk"] = classify_risk(results)
        job["progress"] = 95

        # Step 4: Explanations
        log("Generating explanations...")
        results["explanations"] = explain_vulnerability(results)

        # Step 5: Done
        job["urls"] = discovered_urls
        job["target_url"] = target_url
        job["results"] = results
        job["progress"] = 100
        job["status"] = "done"
        log("Scan complete.")

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        log(f"Error: {e}")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "id": job_id,
        "status": "queued",
        "progress": 0,
        "log": [],
        "results": None,
        "urls": [],
        "target_url": target_url,
    }

    t = threading.Thread(target=run_scan, args=(job_id, target_url), daemon=True)
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/pdf/<job_id>", methods=["GET"])
def download_pdf(job_id):
    from flask import make_response
    job = scan_jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Scan not complete"}), 400

    pdf_bytes = generate_pdf_bytes(job["results"], job["urls"], job["target_url"])
    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=scan_report.pdf"
    return response


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "").strip()
    job_id = data.get("job_id", "")
    job = scan_jobs.get(job_id)
    results = job["results"] if job and job.get("results") else None

    reply = chatbot_reply(message, results)
    return jsonify({"reply": reply})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
