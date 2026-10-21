# Automated Web Security Scanner

A passive, command-line web security scanner built in Python using only the
`requests` standard library — no external attack tools required.

Built for the **IBM SkillsBuild National Cybersecurity Bootcamp (October 2026)**,
organised by **BharatCares (CSRBOX Group)**, and developed with the assistance
of **IBM Bob**.

---

## Problem Statement

Most developers deploy websites without checking basic security hygiene:
missing HTTPS enforcement, absent security headers, misconfigured CORS policies,
insecure cookies, and server version disclosure. These gaps map directly to
entries in the **OWASP Top 10** and are routinely exploited in real attacks.

This tool performs a rapid, **read-only** audit of any URL and produces a
detailed report with the threat, risk level, OWASP category, and a concrete fix
for every issue found — making security feedback accessible to developers at
any experience level.

---

## Features

| # | Check | Risk |
|---|-------|------|
| 1 | HTTPS in use (scheme check) | High |
| 2 | HTTP → HTTPS redirect (follows full chain, 301/302/307/308) | High |
| 3 | `Strict-Transport-Security` header | High |
| 4 | `Content-Security-Policy` header | High |
| 5 | `X-Frame-Options` header | Medium |
| 6 | `X-Content-Type-Options` header | Medium |
| 7 | `Referrer-Policy` header | Low |
| 8 | `Permissions-Policy` header | Low |
| 9 | CORS – wildcard `Access-Control-Allow-Origin: *` | Medium |
| 10 | CORS – reflected origin | High |
| 11 | CORS – credentials with open origin | High |
| 12 | Cookie `Secure` flag (per cookie) | High |
| 13 | Cookie `HttpOnly` flag (per cookie) | High |
| 14 | Cookie `SameSite` flag (per cookie) | Medium |
| 15 | Server version disclosure via `Server` header | Low |

**Scoring & Grading**

Each failed check is weighted by risk:

| Risk | Points |
|------|--------|
| High | 3 |
| Medium | 2 |
| Low | 1 |

The total score as a percentage of the maximum possible gives a letter grade:

| Score | Grade |
|-------|-------|
| 0 (no issues) | **A** |
| 1 – 25 % | **B** |
| 26 – 50 % | **C** |
| 51 – 75 % | **D** |
| > 75 % | **F** |

**Output**

- Colour-coded PASS / FAIL table in the terminal (per URL)
- `report_YYYYMMDD_HHMMSS.html` — styled HTML report with grade badges
- `report_YYYYMMDD_HHMMSS.csv` — flat CSV for import into spreadsheets / SIEMs

---

## Project Structure

```
bob-web-security-scanner/
├── scanner.py          # Main scanner — all checks, scoring, and reports
├── requirements.txt    # Python dependencies (requests only)
├── urls.txt            # Sample input file — one URL per line
├── README.md           # This file
└── .gitignore
```

---

## Setup

**Requirements:** Python 3.10 or later.

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/bob-web-security-scanner.git
cd bob-web-security-scanner

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv

# On Windows
.venv\Scripts\activate

# On macOS / Linux
source .venv/bin/activate

# 3. Install the single dependency
pip install -r requirements.txt
```

---

## Usage

### Scan a single URL

```bash
python scanner.py https://example.com
```

### Scan multiple URLs in one run

```bash
python scanner.py https://example.com https://github.com
```

### Scan from a file

Add one URL per line to `urls.txt` (lines starting with `#` are comments):

```
# urls.txt
https://example.com
https://github.com
```

Then run:

```bash
python scanner.py --file urls.txt
```

### Sample terminal output

```
=================================================================
  Security Scan Results - https://example.com
=================================================================

  HTTPS in Use                              PASS  [High]
  HTTP -> HTTPS Redirect                    FAIL  [High]
    Threat: If http:// requests are not redirected, users will browse unencrypted.
    Fix:    Configure your web server to issue a 301 redirect to https://.
    OWASP:  A02:2021 - Cryptographic Failures
  ...

=================================================================
  Checks: 5/12 passed  |  Risk score: 15  |  Grade: D
=================================================================

[+] HTML report saved: report_20261021_130000.html
[+] CSV  report saved: report_20261021_130000.csv
```

---

## Ethical Use

> **Only scan websites you own or have explicit written permission to test.**

This tool performs **passive, read-only checks** — it sends normal HTTP GET
requests and inspects the response headers. It does not exploit, attack, crawl,
or modify anything on the target server.

Scanning a website without the owner's permission may violate:

- The Computer Fraud and Abuse Act (CFAA) in the United States
- The Computer Misuse Act (CMA) in the United Kingdom
- The Information Technology Act (IT Act) in India
- Equivalent laws in other jurisdictions

The author and IBM SkillsBuild / BharatCares (CSRBOX Group) accept **no
liability** for misuse of this tool.

---

## Tech Stack

| Component | Details |
|-----------|---------|
| Language | Python 3.10+ |
| HTTP library | `requests` 2.32.3 |
| Reports | Hand-built HTML + Python `csv` module |
| External tools | None |
| AI assistant | IBM Bob (IBM SkillsBuild) |

---

## Screenshots


---

## Built with IBM Bob

This project was built **entirely through prompt-based (vibe) coding** using
**IBM Bob IDE v2.0**, the AI coding assistant provided by IBM SkillsBuild.

The development workflow:

1. **Plan mode** — described the full feature set in plain English; Bob produced
   a structured `web-security-scanner-plan.md` with six numbered sub-tasks,
   data contracts, and a Mermaid architecture diagram.
2. **Code mode (Agent)** — implemented each sub-task stage by stage by
   prompting Bob to write, test, and fix the code. No code was written manually.

Stages delivered by Bob:

| Stage | What was built |
|-------|---------------|
| 1 | URL fetch + 6 security header checks + colour terminal output |
| 2 | HTTPS in-use check + HTTP → HTTPS redirect chain check |
| 3 | CORS misconfiguration checks (wildcard, reflected origin, credentials) |
| 4 | Cookie flag checks (Secure, HttpOnly, SameSite) + server version disclosure |
| 5 | Risk-weighted scoring (High=3 / Medium=2 / Low=1) + A–F grade + multi-URL input |
| 6 | HTML report with grade badges + CSV report |

> **IBM SkillsBuild National Cybersecurity Bootcamp — October 2026**
> Organised by **BharatCares (CSRBOX Group)**

---

## Author

**Sherlin S**
2nd Year, B.E. Computer Science and Engineering (CSE)

- GitHub: [kit25cseasherlins-dotcom](https://github.com/kit25cseasherlins-dotcom)

IBM SkillsBuild National Cybersecurity Bootcamp — October 2026
Organised by **BharatCares (CSRBOX Group)**
Powered by **IBM SkillsBuild** | Developed with **IBM Bob**

---

## License

This project is submitted as part of a bootcamp programme and is intended for
educational purposes. Feel free to fork and extend it.
