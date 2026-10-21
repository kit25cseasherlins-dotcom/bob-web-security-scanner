# Automated Web Security Scanner — Plan

## Top-Level Overview

A single-file Python script (`scanner.py`) that passively audits one or more URLs
for common web security misconfigurations using only the `requests` library.
No attacks, no crawling, no external tools.

The project grows in stages; each stage builds on the previous one without
breaking what already works.

---

## Data Contract — `Finding`

Every check function returns a list of `Finding` objects (a plain dataclass).

| Field    | Type  | Description                              |
|----------|-------|------------------------------------------|
| `url`    | `str` | The URL that was scanned                 |
| `check`  | `str` | Short name of the check                  |
| `passed` | `bool`| True = no issue found                    |
| `threat` | `str` | What an attacker could do                |
| `risk`   | `str` | High / Medium / Low                      |
| `owasp`  | `str` | Relevant OWASP Top 10 category           |
| `fix`    | `str` | One-line remediation advice              |

---

## Sub-Tasks

---

### Sub-Task 1 — Scaffold `scanner.py` with URL fetch + 6 security header checks + console output

**Status:** `[ ] pending`

**Intent**
Build the first working version of the scanner. A user runs:

```
python scanner.py https://example.com
```

and sees a PASS/FAIL table in the terminal for every security header check.

**Expected Outcomes**
- `scanner.py` exists and is runnable from the command line.
- `requirements.txt` lists `requests`.
- Fetching a URL works (follows redirects, short timeout, user-agent set).
- Six header checks run and each prints PASS or FAIL with a fix tip.
- Code has comments a 2nd-year CSE student can follow.

**Headers to check**

| Header                    | Risk   | OWASP                              |
|---------------------------|--------|------------------------------------|
| Strict-Transport-Security | High   | A05:2021 Security Misconfiguration |
| Content-Security-Policy   | High   | A05:2021 Security Misconfiguration |
| X-Frame-Options           | Medium | A05:2021 Security Misconfiguration |
| X-Content-Type-Options    | Medium | A05:2021 Security Misconfiguration |
| Referrer-Policy           | Low    | A05:2021 Security Misconfiguration |
| Permissions-Policy        | Low    | A05:2021 Security Misconfiguration |

**Todo List**
1. Create `requirements.txt` with `requests`.
2. Create `scanner.py` with:
   - `Finding` dataclass
   - `fetch_url(url)` function
   - `check_security_headers(url, headers)` function returning a list of `Finding`
   - `print_results(findings)` function showing coloured PASS/FAIL lines
   - `main()` entry point accepting a URL as a CLI argument
3. Smoke-test manually against `https://example.com` and `https://google.com`.

**Relevant Context**
- Only `requests` is allowed — no `beautifulsoup4`, `lxml`, `nmap`, etc.
- Keep all logic in one file for this stage; no sub-packages yet.
- Use `response.headers` (a case-insensitive dict) for header lookups.
- `requests.get(..., allow_redirects=True, timeout=10)` for fetching.

---

### Sub-Task 2 — Add HTTPS & redirect check

**Status:** `[x] done`

**Intent**
Detect when a site serves content over plain HTTP or fails to redirect
`http://` → `https://`.

**Expected Outcomes**
- Two new findings appear: one for HTTPS usage, one for redirect behaviour.
- No change to existing header-check output.

**Todo List**
1. Add `check_https(url)` function.
2. Call it from `main()` and merge findings.

---

### Sub-Task 3 — Add CORS misconfiguration check

**Status:** `[x] done`

**Intent**
Detect wildcard `Access-Control-Allow-Origin: *`, reflected origins,
and dangerous `Access-Control-Allow-Credentials: true` combinations.

**Expected Outcomes**
- CORS findings appear alongside header findings.
- Probe sends an `Origin: https://evil.com` request header and inspects the response.

**Todo List**
1. Add `check_cors(url)` function.
2. Merge findings in `main()`.

---

### Sub-Task 4 — Add cookie flags + server disclosure check

**Status:** `[x] done`

**Intent**
Inspect `Set-Cookie` headers for missing `Secure`, `HttpOnly`, `SameSite` flags.
Also flag if the `Server` header discloses software version info.

**Expected Outcomes**
- Per-cookie findings for each missing flag.
- A finding when `Server` header leaks a version string (e.g. `Apache/2.4.51`).

**Todo List**
1. Add `check_cookies(url, response)` function.
2. Add `check_server_disclosure(headers)` function.
3. Merge findings in `main()`.

---

### Sub-Task 5 — Risk scoring, grading, and multi-URL support

**Status:** `[x] done`

**Intent**
Calculate a risk-weighted score (High=3, Medium=2, Low=1) and assign an A–F grade.
Accept multiple URLs from the CLI or from `urls.txt`.

**Grading scale**

| Score (% of max possible) | Grade |
|---------------------------|-------|
| 0 issues                  | A     |
| 1–25 %                    | B     |
| 26–50 %                   | C     |
| 51–75 %                   | D     |
| > 75 %                    | F     |

**Todo List**
1. Add `score_findings(findings)` → `(score, grade)`.
2. Update `main()` to accept multiple URLs and a `--file` flag for `urls.txt`.
3. Print per-URL summary with score and grade.

---

### Sub-Task 6 — HTML and CSV reports

**Status:** `[x] done`

**Intent**
Save machine-readable (CSV) and human-readable (HTML) reports after each run.

**Expected Outcomes**
- `report_YYYYMMDD_HHMMSS.html` contains a styled table of all findings.
- `report_YYYYMMDD_HHMMSS.csv` contains the same data as flat rows.

**Todo List**
1. Add `save_html_report(findings, score, grade, filename)`.
2. Add `save_csv_report(findings, filename)`.
3. Call both from `main()` after all URLs are scanned.

---

## Non-Goals
- No active exploitation or fuzzing.
- No JavaScript execution or browser automation.
- No DNS, port scanning, or subdomain enumeration.
- No third-party libraries beyond `requests`.
