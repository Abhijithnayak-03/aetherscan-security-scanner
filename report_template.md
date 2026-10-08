# Lightweight Web Vulnerability Scanner — Project Report

## 1. Introduction
Describe the problem and the goal of building a lightweight, non-destructive scanner.

## 2. Architecture

```text
                  ┌──────────────────────┐
                  │      CLI / User      │
                  │ URL + safety flags   │
                  └──────────┬───────────┘
                             │
                             v
                  ┌──────────────────────┐
                  │   Safety / Scope     │
                  │ consent + same-site │
                  │ delay + timeout     │
                  │ page limit          │
                  └──────────┬───────────┘
                             │
                             v
                  ┌──────────────────────┐
                  │       Crawler        │
                  │ links/forms/params  │
                  └──────────┬───────────┘
                             │
                             v
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
       v                     v                     v
  Passive checks       Benign probes          Response data
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             v
                  ┌──────────────────────┐
                  │ Finding de-duplication│
                  └──────────┬───────────┘
                             v
                  ┌──────────────────────┐
                  │ Console + JSON      │
                  │ report              │
                  └──────────────────────┘
```

## 3. Check-to-OWASP Mapping

| Check | OWASP category | Technique |
|---|---|---|
| HTTP | A02 | Passive |
| HSTS | A02 | Passive |
| Secure cookie | A02 | Passive |
| CSRF token indicator | A01 | Passive |
| CSP | A05 | Passive |
| Anti-clickjacking | A05 | Passive |
| nosniff | A05 | Passive |
| Exposed files | A05 | Safe path probe |
| Stack trace | A05 | Passive |
| Server disclosure | A06 | Passive |
| X-Powered-By | A06 | Passive |
| HttpOnly | A07 | Passive |
| SameSite | A07 | Passive |
| Login/form HTTP | A07 | Passive |
| SRI | A08 | Passive |
| SQL error probe | A03 | Active, benign |
| Reflected marker | A03 | Active, benign |

## 4. Target 1 Results
Paste the real generated JSON findings/summary here.

## 5. Target 2 Results
Paste the real generated JSON findings/summary here.

## 6. False Positive / False Negative Analysis

Discuss examples where:
- a header was absent but the application may have compensating controls;
- a marker was reflected safely and therefore does not prove exploitable XSS;
- a 500 response alone did not prove SQL injection;
- authenticated and business-logic vulnerabilities were outside the scanner's scope.

## 7. Limitations

A09 and A10 are not safely testable remotely according to the assignment. Also discuss business logic, blind injection, SSRF, and authenticated access-control limitations.

## 8. Remediation Advice

For each finding, explain the recommended defensive fix.

## 9. Conclusion

Summarize what the lightweight scanner detects and what a heavier scanner such as OWASP ZAP can add.
