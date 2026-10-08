# Lightweight Web Vulnerability Scanner

A Python 3 command-line scanner for **authorized local or intentionally vulnerable lab targets**.

Built to match the course assignment requirements:
- `requests` + `beautifulsoup4`
- CLI URL input
- mandatory `--i-have-permission` consent gate
- same-site crawler
- page limit, timeout and request delay
- clear User-Agent
- modular vulnerability checks
- JSON report + console summary
- duplicate finding suppression
- benign/read-only testing
- unit tests
- OWASP mapping

## Ethical scope

Only scan systems you own or explicitly have permission to test. Recommended targets are local labs such as OWASP Juice Shop, DVWA, WebGoat or bWAPP.

The scanner does not attempt to exploit a target, extract data or disrupt it. Active checks use harmless strings such as a single quote and a unique marker.

## Installation

```bash
python -m venv .venv
```

Windows PowerShell:
```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

The consent flag is mandatory:

```bash
python scanner.py http://localhost:3000 --i-have-permission -o report.json
```

Useful options:

```bash
python scanner.py http://localhost:3000 \
  --i-have-permission \
  --max-pages 50 \
  --delay 0.25 \
  --timeout 8 \
  -o report.json
```

PowerShell one-line equivalent:

```powershell
python scanner.py http://localhost:3000 --i-have-permission --max-pages 50 --delay 0.25 --timeout 8 -o report.json
```

## Checks

### A01 — Broken Access Control
- POST forms without an apparent CSRF token

### A02 — Cryptographic Failures
- HTTP instead of HTTPS
- Missing HSTS on HTTPS
- Cookie without Secure

### A03 — Injection
- Error-based SQL injection indicator using a single quote
- Reflected harmless-marker test
- The scanner does not execute arbitrary SQL or JavaScript

### A05 — Security Misconfiguration
- Missing CSP
- Missing anti-clickjacking protection
- Missing `X-Content-Type-Options`
- Exposed `.git`, `.env`, `phpinfo.php`, `server-status` indicators
- Verbose stack-trace/error signatures

### A06 — Vulnerable and Outdated Components
- Server version disclosure
- X-Powered-By disclosure

### A07 — Identification and Authentication Failures
- Cookie without HttpOnly
- Cookie without SameSite
- POST/login form submitted over HTTP

### A08 — Software and Data Integrity Failures
- External scripts without SRI

### A09/A10
The assignment specifies that A09 and A10 are not safely testable remotely. The report should explain this limitation rather than pretending to test them.

## Unit tests

```bash
pytest -q
```

The tests cover the consent gate, URL normalization/same-site behavior, and duplicate finding behavior.

## Sample targets

Run an authorized local lab first. For example, the assignment gives OWASP Juice Shop:

```bash
docker run -p 3000:3000 bkimminich/juice-shop
```

Then:

```bash
python scanner.py http://localhost:3000 --i-have-permission -o juice-shop-report.json
```

For a second authorized lab, use DVWA/WebGoat/bWAPP locally and produce a second JSON report.

## Limitations

This scanner is intentionally lightweight. It will not reliably discover:
- business-logic flaws
- blind injection
- SSRF
- authenticated access-control bugs behind login
- complex multi-step workflows
- vulnerabilities requiring deep JavaScript execution

Compare its results with an OWASP ZAP baseline and discuss differences in the report.


## Local Web UI

A polished local dashboard is included in `webapp.py`.

### Start the UI

```bash
pip install -r requirements.txt
python webapp.py
```

Open:

```text
http://127.0.0.1:5000
```

Enter the authorized lab URL, confirm the permission checkbox, choose the crawl limits, and start the scan. The dashboard shows live status, deduplicated severity counts, OWASP coverage, evidence, all affected URLs, remediation guidance, request errors, and a downloadable JSON report.

The permission gate is enforced server-side. The scanner remains non-destructive and uses same-site crawling plus passive/benign checks only.
