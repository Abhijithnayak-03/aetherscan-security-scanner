
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from scanner import Scanner

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "ui_reports"
REPORT_DIR.mkdir(exist_ok=True)

jobs = {}
jobs_lock = threading.Lock()
MAX_JOBS = 25


def valid_target(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def run_scan(job_id: str, target: str, max_pages: int, delay: float, timeout: float):
    def log(message: str):
        with jobs_lock:
            jobs[job_id]["logs"].append(message)

    try:
        with jobs_lock:
            jobs[job_id]["status"] = "crawling"
            jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()

        log(f"Target: {target}")
        log("Authorization gate accepted.")
        log("Safety: same-site crawl, read-only/benign checks, no exploitation.")
        log(f"Limits: max-pages={max_pages}, delay={delay}s, timeout={timeout}s")
        log("Crawling authorized target...")

        scanner = Scanner(
            target=target,
            max_pages=max_pages,
            delay=delay,
            timeout=timeout,
        )

        scanner.crawl()
        with jobs_lock:
            jobs[job_id]["status"] = "checking"
            jobs[job_id]["pages_crawled"] = len(scanner.pages)
            jobs[job_id]["urls_discovered"] = len(scanner.discovered)

        log(f"Crawled {len(scanner.pages)} page(s).")
        log("Running passive and benign active checks...")
        scanner.run_checks()

        report = scanner.report()
        report_path = REPORT_DIR / f"{job_id}.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        with jobs_lock:
            jobs[job_id]["status"] = "complete"
            jobs[job_id]["report"] = report
            jobs[job_id]["report_path"] = str(report_path)
            jobs[job_id]["pages_crawled"] = len(scanner.pages)
            jobs[job_id]["urls_discovered"] = len(scanner.discovered)
            jobs[job_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
            jobs[job_id]["request_errors"] = len(report.get("errors", []))

        log(f"Scan complete. Findings: {len(report.get('findings', []))}.")
    except Exception as exc:
        with jobs_lock:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = f"{type(exc).__name__}: {exc}"
        log(f"ERROR: {type(exc).__name__}: {exc}")


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def start_scan():
    data = request.get_json(silent=True) or request.form
    target = str(data.get("target", "")).strip()
    consent = data.get("permission") in {True, "true", "1", "on", "yes"}

    if not consent:
        return jsonify({"error": "You must confirm that you have permission to scan the target."}), 400
    if not valid_target(target):
        return jsonify({"error": "Enter a valid http:// or https:// URL."}), 400

    try:
        max_pages = max(1, min(int(data.get("max_pages", 50)), 250))
        delay = max(0.0, min(float(data.get("delay", 0.25)), 10.0))
        timeout = max(1.0, min(float(data.get("timeout", 8.0)), 60.0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid scan settings."}), 400

    job_id = uuid.uuid4().hex[:12]
    with jobs_lock:
        jobs[job_id] = {
            "id": job_id,
            "target": target,
            "status": "starting",
            "logs": [],
            "pages_crawled": 0,
            "urls_discovered": 0,
            "request_errors": 0,
            "report": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        # Keep the in-memory job store bounded.
        if len(jobs) > MAX_JOBS:
            oldest = sorted(jobs, key=lambda x: jobs[x].get("created_at", ""))[:-MAX_JOBS]
            for old_id in oldest:
                old_path = REPORT_DIR / f"{old_id}.json"
                old_path.unlink(missing_ok=True)
                jobs.pop(old_id, None)

    thread = threading.Thread(
        target=run_scan,
        args=(job_id, target, max_pages, delay, timeout),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id})


@app.get("/api/status/<job_id>")
def scan_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Scan not found."}), 404
        return jsonify(job)


@app.get("/report/<job_id>")
def report_page(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return "Scan not found.", 404
    return render_template("report.html", job=job)


@app.get("/download/<job_id>")
def download_report(job_id):
    path = REPORT_DIR / f"{job_id}.json"
    if not path.exists():
        return "Report not found.", 404
    return send_file(path, as_attachment=True, download_name=f"scan_{job_id}.json")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print("Secure local scanner UI: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
