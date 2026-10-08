#!/usr/bin/env python3
"""
Lightweight Web Vulnerability Scanner
Safe, read-only scanner for authorized local/lab targets.

Usage:
    python scanner.py http://localhost:3000 --i-have-permission -o report.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Set
from urllib.parse import (
    parse_qsl, urlencode, urljoin, urlparse, urlunparse
)

import requests
from bs4 import BeautifulSoup


USER_AGENT = "LightweightWebVulnScanner/1.0 (authorized-security-lab)"
SQL_MARKER = "__LWVS_SQL_TEST__"
XSS_MARKER = "__LWVS_XSS_MARKER_9f31__"

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: str
    owasp: str
    url: str
    parameter: str
    evidence: str
    recommendation: str


class Scanner:
    def __init__(self, target: str, max_pages: int = 50, delay: float = 0.25,
                 timeout: float = 8.0, same_host: bool = True):
        self.target = self.normalize_url(target)
        self.max_pages = max_pages
        self.delay = max(0.0, delay)
        self.timeout = timeout
        self.same_host = same_host
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
        self.pages: Dict[str, requests.Response] = {}
        self.findings: List[Finding] = []
        self.errors: List[str] = []

    @staticmethod
    def normalize_url(url: str) -> str:
        if not re.match(r"^https?://", url, re.I):
            raise ValueError("Target must start with http:// or https://")
        p = urlparse(url)
        return urlunparse((p.scheme.lower(), p.netloc, p.path or "/", p.params, p.query, ""))

    def same_site(self, url: str) -> bool:
        a, b = urlparse(self.target), urlparse(url)
        return a.netloc.lower() == b.netloc.lower() if self.same_host else True

    def add_finding(self, **kwargs):
        finding = Finding(**kwargs)
        if finding not in self.findings:
            self.findings.append(finding)

    def request(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            return self.session.get(url, timeout=self.timeout, allow_redirects=True, **kwargs)
        except requests.RequestException as exc:
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            return None

    def crawl(self):
        queue = [self.target]
        self.discovered.add(self.target)

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited or not self.same_site(url):
                continue

            response = self.request(url)
            self.visited.add(url)
            if response is None:
                continue
            self.pages[url] = response

            if "text/html" not in response.headers.get("Content-Type", "").lower():
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            for tag in soup.find_all(["a", "form"]):
                raw = tag.get("href") if tag.name == "a" else tag.get("action")
                if not raw:
                    raw = response.url
                absolute = urljoin(response.url, raw)
                p = urlparse(absolute)
                if p.scheme not in ("http", "https"):
                    continue
                clean = urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))
                if self.same_site(clean):
                    self.discovered.add(clean)
                    if clean not in self.visited and clean not in queue:
                        queue.append(clean)

    # -------------------- passive checks --------------------

    def check_transport(self):
        for url, r in self.pages.items():
            p = urlparse(url)
            if p.scheme == "http":
                self.add_finding(
                    check_id="A02-HTTP", title="HTTP instead of HTTPS",
                    severity="Medium", owasp="A02 Cryptographic Failures",
                    url=url, parameter="-",
                    evidence=f"Target uses {p.scheme.upper()} at {url}",
                    recommendation="Serve the application over HTTPS and redirect HTTP to HTTPS."
                )
            if p.scheme == "https" and "Strict-Transport-Security" not in r.headers:
                self.add_finding(
                    check_id="A02-HSTS", title="Missing HSTS header",
                    severity="Low", owasp="A02 Cryptographic Failures",
                    url=url, parameter="-",
                    evidence="Strict-Transport-Security response header is absent.",
                    recommendation="Set an appropriate Strict-Transport-Security header after HTTPS is correctly deployed."
                )

    def check_cookies(self):
        for url, r in self.pages.items():
            for cookie in r.headers.get("Set-Cookie", "").splitlines():
                if not cookie.strip():
                    continue
                low = cookie.lower()
                name = cookie.split("=", 1)[0].strip()
                if "secure" not in low:
                    self.add_finding(
                        check_id="A07-SECURE-COOKIE", title="Cookie without Secure attribute",
                        severity="Medium", owasp="A07 Identification and Authentication Failures",
                        url=url, parameter=name,
                        evidence=f"Set-Cookie for {name} does not contain Secure.",
                        recommendation="Set Secure on session/security-sensitive cookies and use HTTPS."
                    )
                if "httponly" not in low:
                    self.add_finding(
                        check_id="A07-HTTPONLY", title="Cookie without HttpOnly attribute",
                        severity="Medium", owasp="A07 Identification and Authentication Failures",
                        url=url, parameter=name,
                        evidence=f"Set-Cookie for {name} does not contain HttpOnly.",
                        recommendation="Set HttpOnly on session/security-sensitive cookies."
                    )
                if "samesite" not in low:
                    self.add_finding(
                        check_id="A07-SAMESITE", title="Cookie without SameSite attribute",
                        severity="Low", owasp="A07 Identification and Authentication Failures",
                        url=url, parameter=name,
                        evidence=f"Set-Cookie for {name} does not contain SameSite.",
                        recommendation="Set an appropriate SameSite policy, commonly Lax or Strict where compatible."
                    )

    def check_headers(self):
        for url, r in self.pages.items():
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "content-security-policy" not in headers:
                self.add_finding(
                    check_id="A05-CSP", title="Content-Security-Policy header missing",
                    severity="Medium", owasp="A05 Security Misconfiguration",
                    url=url, parameter="-",
                    evidence="Content-Security-Policy response header is absent.",
                    recommendation="Define and deploy a restrictive Content-Security-Policy."
                )
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                self.add_finding(
                    check_id="A05-CLICKJACK", title="Anti-clickjacking protection missing",
                    severity="Medium", owasp="A05 Security Misconfiguration",
                    url=url, parameter="-",
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                    recommendation="Set X-Frame-Options or a CSP frame-ancestors directive."
                )
            if "x-content-type-options" not in headers:
                self.add_finding(
                    check_id="A05-NOSNIFF", title="X-Content-Type-Options header missing",
                    severity="Low", owasp="A05 Security Misconfiguration",
                    url=url, parameter="-",
                    evidence="X-Content-Type-Options response header is absent.",
                    recommendation="Set X-Content-Type-Options: nosniff."
                )
            server = headers.get("server")
            powered = headers.get("x-powered-by")
            if server and re.search(r"\d", server):
                self.add_finding(
                    check_id="A06-SERVER", title="Server technology/version disclosure",
                    severity="Low", owasp="A06 Vulnerable and Outdated Components",
                    url=url, parameter="Server",
                    evidence=f"Server header: {server}",
                    recommendation="Minimize version details in response headers."
                )
            if powered:
                self.add_finding(
                    check_id="A06-POWERED", title="X-Powered-By disclosure",
                    severity="Low", owasp="A06 Vulnerable and Outdated Components",
                    url=url, parameter="X-Powered-By",
                    evidence=f"X-Powered-By header: {powered}",
                    recommendation="Remove unnecessary technology/version disclosure headers."
                )

    def check_forms(self):
        for url, r in self.pages.items():
            if "text/html" not in r.headers.get("Content-Type", "").lower():
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").lower()
                action = urljoin(r.url, form.get("action") or r.url)
                inputs = form.find_all("input")
                if method == "post" and not any(
                    (i.get("name") or "").lower() in ("csrf", "csrf_token", "_csrf", "xsrf", "_token")
                    for i in inputs
                ):
                    self.add_finding(
                        check_id="A01-CSRF", title="POST form without apparent CSRF token",
                        severity="Medium", owasp="A01 Broken Access Control",
                        url=action, parameter="-",
                        evidence=f"POST form at {url} contains no common CSRF token field.",
                        recommendation="Use a server-validated CSRF token for state-changing requests."
                    )
                if method == "post" and urlparse(action).scheme == "http":
                    self.add_finding(
                        check_id="A07-LOGIN-HTTP", title="POST form submitted over HTTP",
                        severity="Medium", owasp="A07 Identification and Authentication Failures",
                        url=action, parameter="-",
                        evidence=f"Form action uses HTTP: {action}",
                        recommendation="Submit authentication and sensitive forms over HTTPS."
                    )
                for inp in inputs:
                    if inp.get("type") == "text" and inp.get("value"):
                        self.add_finding(
                            check_id="A03-HTML-INPUT", title="User-controllable HTML input value observed",
                            severity="Info", owasp="A03 Injection",
                            url=url, parameter=inp.get("name") or "-",
                            evidence="A text input contains a pre-populated value; scanner does not classify this as XSS by itself.",
                            recommendation="Validate and contextually encode user-controlled values."
                        )

    def check_external_sri(self):
        for url, r in self.pages.items():
            if "text/html" not in r.headers.get("Content-Type", "").lower():
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = urljoin(r.url, script["src"])
                if urlparse(src).netloc != urlparse(r.url).netloc and not script.get("integrity"):
                    self.add_finding(
                        check_id="A08-SRI", title="External script without Subresource Integrity",
                        severity="Low", owasp="A08 Software and Data Integrity Failures",
                        url=url, parameter="script[src]",
                        evidence=f"External script lacks integrity attribute: {src}",
                        recommendation="Use SRI integrity and crossorigin attributes for externally hosted scripts where supported."
                    )

    def check_exposed_paths(self):
        paths = ["/.git/HEAD", "/.env", "/phpinfo.php", "/server-status"]
        base = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
        for path in paths:
            url = base + path
            r = self.request(url)
            if r is None:
                continue
            body = r.text[:10000].lower()
            if r.status_code == 200:
                signature = None
                if path == "/.git/HEAD" and "ref:" in body:
                    signature = "Git HEAD reference"
                elif path == "/.env" and re.search(r"(?m)^\s*[a-z_][a-z0-9_]*\s*=", r.text, re.I):
                    signature = ".env-style key/value content"
                elif path == "/phpinfo.php" and "phpinfo" in body:
                    signature = "phpinfo marker"
                elif path == "/server-status" and "apache" in body:
                    signature = "server-status content"
                if signature:
                    self.add_finding(
                        check_id="A05-EXPOSED", title=f"Potentially exposed sensitive path: {path}",
                        severity="High", owasp="A05 Security Misconfiguration",
                        url=url, parameter="-",
                        evidence=f"HTTP 200 with signature: {signature}",
                        recommendation="Remove exposed files/endpoints and block sensitive paths at the server."
                    )

    def check_stack_traces(self):
        patterns = [
            r"traceback \(most recent call last\)",
            r"stack trace",
            r"sql syntax.*error",
            r"werkzeug debugger",
            r"exception in thread",
        ]
        rx = re.compile("|".join(patterns), re.I)
        for url, r in self.pages.items():
            if rx.search(r.text[:30000]):
                self.add_finding(
                    check_id="A05-STACK", title="Stack trace or verbose error signature exposed",
                    severity="Medium", owasp="A05 Security Misconfiguration",
                    url=url, parameter="-",
                    evidence="Response body matched a known verbose-error signature.",
                    recommendation="Return generic errors to users and keep detailed diagnostics in protected server logs."
                )

    # -------------------- benign active checks --------------------

    def mutate_query(self, url: str, name: str, value: str) -> str:
        p = urlparse(url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        changed = False
        out = []
        for k, v in pairs:
            if k == name and not changed:
                out.append((k, value))
                changed = True
            else:
                out.append((k, v))
        if not changed:
            out.append((name, value))
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, urlencode(out), ""))

    def check_sql_errors(self):
        sql_error_patterns = [
            "sql syntax", "sqlite error", "sqlite3.operationalerror",
            "mysql", "postgresql", "psql:", "ora-", "odbc sql",
            "unterminated quoted string", "you have an error in your sql syntax"
        ]
        rx = re.compile("|".join(re.escape(x) for x in sql_error_patterns), re.I)
        seen_params = set()
        for url, r in list(self.pages.items()):
            p = urlparse(url)
            for name, _ in parse_qsl(p.query, keep_blank_values=True):
                key = (urlunparse((p.scheme, p.netloc, p.path or "/", p.params, "", "")), name)
                if key in seen_params:
                    continue
                seen_params.add(key)
                probe = self.mutate_query(url, name, "'")
                response = self.request(probe)
                if response is None:
                    continue
                if response.status_code >= 500 and rx.search(response.text[:30000]):
                    self.add_finding(
                        check_id="A03-SQL", title="Potential error-based SQL injection",
                        severity="High", owasp="A03 Injection",
                        url=probe, parameter=name,
                        evidence=f"Quote probe returned HTTP {response.status_code} and matched a database error signature.",
                        recommendation="Use parameterized queries/prepared statements and avoid exposing database errors."
                    )

    def check_reflected_xss(self):
        for url, r in list(self.pages.items()):
            p = urlparse(url)
            params = parse_qsl(p.query, keep_blank_values=True)
            for name, _ in params:
                probe = self.mutate_query(url, name, XSS_MARKER)
                response = self.request(probe)
                if response is None:
                    continue
                if XSS_MARKER in response.text:
                    self.add_finding(
                        check_id="A03-XSS", title="Reflected input marker detected",
                        severity="Medium", owasp="A03 Injection",
                        url=probe, parameter=name,
                        evidence=f"Unique harmless marker was reflected in the response: {XSS_MARKER}",
                        recommendation="Contextually encode untrusted output and validate input. Use framework auto-escaping where available."
                    )

    def run_checks(self):
        self.check_transport()
        self.check_cookies()
        self.check_headers()
        self.check_forms()
        self.check_external_sri()
        self.check_exposed_paths()
        self.check_stack_traces()
        self.check_sql_errors()
        self.check_reflected_xss()

    def report(self) -> dict:
        # Group identical vulnerability types across pages while retaining every affected URL.
        grouped = {}
        for f in self.findings:
            key = (f.check_id, f.title, f.severity, f.owasp, f.parameter, f.recommendation, f.evidence)
            if key not in grouped:
                grouped[key] = {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity,
                    "owasp": f.owasp,
                    "parameter": f.parameter,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "affected_urls": [],
                }
            if f.url not in grouped[key]["affected_urls"]:
                grouped[key]["affected_urls"].append(f.url)

        findings = sorted(
            grouped.values(),
            key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9), x["check_id"], x["title"])
        )
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
        categories = sorted({f["owasp"] for f in findings})
        return {
            "scanner": {
                "name": "Lightweight Web Vulnerability Scanner",
                "version": "1.0",
                "user_agent": USER_AGENT
            },
            "target": self.target,
            "scan": {
                "pages_crawled": len(self.visited),
                "urls_discovered": len(self.discovered),
                "max_pages": self.max_pages,
                "delay_seconds": self.delay,
                "timeout_seconds": self.timeout,
                "safe_mode": True,
            },
            "summary": {
                "total_findings": len(findings),
                "severity_counts": counts,
                "owasp_categories": categories
            },
            "findings": findings,
            "errors": self.errors,
        }


def build_parser():
    parser = argparse.ArgumentParser(description="Lightweight, non-destructive web vulnerability scanner.")
    parser.add_argument("url", help="Authorized target URL, e.g. http://localhost:3000")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="Required consent gate. Scanner refuses to run without it.")
    parser.add_argument("--delay", type=float, default=0.25, help="Delay between requests in seconds (default: 0.25)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum same-site HTML pages to crawl (default: 50)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds (default: 8)")
    parser.add_argument("-o", "--output", default="report.json", help="JSON output file (default: report.json)")
    return parser


def print_summary(report: dict):
    print("\n=== Lightweight Web Vulnerability Scanner ===")
    print(f"Target:          {report['target']}")
    print(f"Pages crawled:   {report['scan']['pages_crawled']}")
    print(f"URLs discovered: {report['scan']['urls_discovered']}")
    print(f"Total findings:  {report['summary']['total_findings']}")
    print("\nSeverity:")
    for severity, count in report["summary"]["severity_counts"].items():
        print(f"  {severity:<8} {count}")

    print("\nFindings:")
    if not report["findings"]:
        print("  No findings detected by implemented checks.")
    for f in report["findings"]:
        print(f"  [{f['severity']}] {f['check_id']} | {f['title']} | {f['url']}")

    if report["errors"]:
        print(f"\nRequest errors: {len(report['errors'])}")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.i_have_permission:
        parser.error("Consent required. Re-run with --i-have-permission for an authorized target.")

    if args.max_pages < 1:
        parser.error("--max-pages must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.delay < 0:
        parser.error("--delay cannot be negative")

    try:
        scanner = Scanner(args.url, args.max_pages, args.delay, args.timeout)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"[*] Scanning authorized target: {scanner.target}")
    print(f"[*] Safety controls: same-site crawl, max-pages={args.max_pages}, delay={args.delay}s, timeout={args.timeout}s")
    print("[*] Crawling...")
    scanner.crawl()
    print(f"[*] Crawled {len(scanner.visited)} page(s). Running checks...")
    scanner.run_checks()

    report = scanner.report()
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_summary(report)
    print(f"\n[+] JSON report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
