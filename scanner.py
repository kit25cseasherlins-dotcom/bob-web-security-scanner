"""
scanner.py — Automated Web Security Scanner (Stage 6 - Complete)
IBM SkillsBuild National Cybersecurity Bootcamp project

What this does:
  1. Accepts one or more URLs from the command line or a urls.txt file.
  2. Fetches each page using only the 'requests' library (no other tools).
  3. Checks whether the URL uses HTTPS and whether http:// redirects to https://.
  4. Checks 6 important security HTTP response headers.
  5. Checks for CORS misconfigurations (wildcard, reflected origin, credentials).
  6. Checks cookie flags (Secure, HttpOnly, SameSite) and server version disclosure.
  7. Calculates a risk-weighted score (High=3, Medium=2, Low=1) and assigns a grade A-F.
  8. Prints a colour-coded PASS/FAIL table to the terminal for each URL.
  9. Saves an HTML report and a CSV report to the current directory.

Usage:
    python scanner.py https://example.com
    python scanner.py https://example.com https://google.com
    python scanner.py --file urls.txt

Dependencies:
    pip install requests
"""

import sys
import csv
import os
import re
import requests
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Finding — one result from a single security check
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """
    Everything we want to report about one security check.

    Attributes:
        url    : The URL that was scanned.
        check  : Short name for the check, e.g. "HSTS Header".
        passed : True if the site passed (no problem found).
        threat : What an attacker could do if this is missing/misconfigured.
        risk   : "High", "Medium", or "Low".
        owasp  : The OWASP Top 10 2021 category this falls under.
        fix    : A one-line action the developer should take to fix it.
    """
    url: str
    check: str
    passed: bool
    threat: str
    risk: str
    owasp: str
    fix: str


# ===========================================================================
# SECTION 1 — HTTP FETCHING
# ===========================================================================

# A shared User-Agent string used by all requests in this scanner.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)


def fetch_url(url: str) -> requests.Response:
    """
    Sends an HTTP GET request to the given URL.

    - allow_redirects=True : follows any http->https redirects automatically.
    - timeout=10           : gives up after 10 seconds so we don't hang.
    - User-Agent           : looks like a real browser so we aren't blocked.

    Returns the Response object on success, or raises an exception on failure.
    """
    response = requests.get(
        url,
        headers={"User-Agent": _USER_AGENT},
        allow_redirects=True,
        timeout=10,
    )
    return response


# ===========================================================================
# SECTION 2 — HTTPS & REDIRECT CHECK  (Stage 2)
# ===========================================================================

def check_https(url: str) -> list:
    """
    Two passive checks for HTTPS:

    Check 1 — Is the URL served over HTTPS?
        Looks at whether the URL starts with 'https://'.

    Check 2 — Does http:// redirect to https://?
        Sends a plain HTTP request with allow_redirects=False so we can
        inspect the raw redirect response before following it.
        A redirect PASSES when:
          - Status code is one of 301, 302, 307, or 308.
          - The Location header scheme is https://.
          - The Location header host matches the original host
            (extra path / query parameters like ?gws_rd=ssl are allowed).
    """
    findings = []

    # ------------------------------------------------------------------
    # Check 1: Is the scheme https?
    # ------------------------------------------------------------------
    is_https = url.startswith("https://")

    findings.append(Finding(
        url=url,
        check="HTTPS in Use",
        passed=is_https,
        threat=(
            "Traffic over plain HTTP is unencrypted. An attacker on the same "
            "network can read passwords, cookies, and personal data "
            "(Man-in-the-Middle attack)."
        ),
        risk="High",
        owasp="A02:2021 - Cryptographic Failures",
        fix=(
            "Obtain a TLS certificate (free via Let's Encrypt) and serve "
            "your site exclusively over https://."
        ) if not is_https else "N/A - site is already using HTTPS.",
    ))

    # ------------------------------------------------------------------
    # Check 2: Does the http:// version redirect to https://?
    # We always build the http:// version of the URL so we can test it
    # regardless of whether the user typed http:// or https://.
    # ------------------------------------------------------------------
    http_url = "http://" + url.split("://", 1)[1]
    redirects_to_https = False

    # Extract the base domain from the original URL so we can verify every
    # redirect in the chain stays on the same site.
    # e.g. google.com  ->  http://www.google.com/  ->  https://www.google.com/
    # Both hops share the 'google.com' base, so the check should PASS.
    original_host = urlparse(http_url).hostname or ""

    try:
        # Walk the redirect chain manually (up to 10 hops) so we can inspect
        # every Location header.  We stop as soon as we reach an HTTPS URL on
        # the same base host, or exhaust the chain.
        current_url = http_url
        for _ in range(10):
            probe = requests.get(
                current_url,
                allow_redirects=False,
                timeout=10,
                headers={"User-Agent": _USER_AGENT},
            )

            # Not a redirect — the chain ended without reaching https://.
            if probe.status_code not in (301, 302, 307, 308):
                break

            location = probe.headers.get("Location", "")
            if not location:
                break

            parsed_loc = urlparse(location)
            redirect_host = parsed_loc.hostname or ""

            # Helper: two hosts are "same site" when one is the other's
            # subdomain or they are identical (ignores path and query).
            is_same_host = (
                redirect_host == original_host
                or redirect_host.endswith("." + original_host)
                or original_host.endswith("." + redirect_host)
            )

            if parsed_loc.scheme == "https" and is_same_host:
                # Found a valid HTTPS redirect — check passes.
                redirects_to_https = True
                break

            # The redirect is still HTTP; keep following the chain.
            # Handle relative Location URLs (no scheme/host) by resolving
            # them against the current URL.
            if not parsed_loc.scheme:
                from urllib.parse import urljoin
                location = urljoin(current_url, location)

            current_url = location

    except requests.exceptions.RequestException:
        # Can't reach the http:// version — leave redirects_to_https as False.
        pass

    findings.append(Finding(
        url=url,
        check="HTTP -> HTTPS Redirect",
        passed=redirects_to_https,
        threat=(
            "If http:// requests are not redirected, users who type the URL "
            "without 'https://' will browse the site unencrypted."
        ),
        risk="High",
        owasp="A02:2021 - Cryptographic Failures",
        fix=(
            "Configure your web server to issue a 301 redirect from "
            "http:// to https:// for all requests."
        ) if not redirects_to_https else "N/A - HTTP correctly redirects to HTTPS.",
    ))

    return findings


# ===========================================================================
# SECTION 3 — SECURITY HEADERS CHECK  (Stage 1)
# ===========================================================================

def check_security_headers(url: str, resp_headers: dict) -> list:
    """
    Checks whether 6 important HTTP security headers are present.

    Each header is a tuple: (name, risk, threat, fix).
    Returns a list of Finding objects — one per header.
    """
    headers_to_check = [
        (
            "Strict-Transport-Security",
            "High",
            (
                "Without HSTS, attackers can SSL-strip traffic, silently "
                "downgrading HTTPS to HTTP (MITM attack)."
            ),
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ),
        (
            "Content-Security-Policy",
            "High",
            (
                "Without CSP, attackers can inject malicious scripts (XSS) "
                "that steal user data or sessions."
            ),
            "Add: Content-Security-Policy: default-src 'self'",
        ),
        (
            "X-Frame-Options",
            "Medium",
            (
                "Without this header your page can be embedded in an invisible "
                "iframe on an attacker's site (Clickjacking)."
            ),
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
        ),
        (
            "X-Content-Type-Options",
            "Medium",
            (
                "Without this header, browsers may misinterpret response content "
                "types, enabling MIME-confusion attacks."
            ),
            "Add: X-Content-Type-Options: nosniff",
        ),
        (
            "Referrer-Policy",
            "Low",
            (
                "Without a Referrer-Policy, sensitive URL parameters may leak "
                "to third-party sites via the Referer header."
            ),
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
        ),
        (
            "Permissions-Policy",
            "Low",
            (
                "Without Permissions-Policy, third-party scripts can request "
                "camera, microphone, or geolocation access."
            ),
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ),
    ]

    findings = []
    for header_name, risk, threat, fix in headers_to_check:
        # requests headers dict is case-insensitive.
        present = header_name in resp_headers
        findings.append(Finding(
            url=url,
            check=f"{header_name} Header",
            passed=present,
            threat=threat,
            risk=risk,
            owasp="A05:2021 - Security Misconfiguration",
            fix=fix if not present else "N/A - header is present.",
        ))

    return findings


# ===========================================================================
# SECTION 4 — CORS CHECK  (Stage 3)
# ===========================================================================

def check_cors(url: str) -> list:
    """
    Checks for three common CORS misconfigurations.

    How it works:
      We send a request with a fake 'Origin: https://evil-attacker.com' header.
      A correctly configured server should NOT echo that origin back.

    Check 1 — Wildcard origin (Access-Control-Allow-Origin: *)
        Any website can read the response. Dangerous if cookies/auth are used.

    Check 2 — Reflected origin
        The server echoes back whatever Origin we sent. An attacker can set
        their own domain as the origin and read the response.

    Check 3 — Credentials with wildcard or reflected origin
        Access-Control-Allow-Credentials: true together with a permissive
        ACAO header lets attackers make authenticated cross-origin requests.
    """
    findings = []

    # We send a fake, obviously-evil origin so we can see if the server
    # reflects it back in the Access-Control-Allow-Origin response header.
    evil_origin = "https://evil-attacker.com"

    try:
        resp = requests.get(
            url,
            headers={
                "User-Agent": _USER_AGENT,
                "Origin": evil_origin,     # <-- the CORS probe header
            },
            allow_redirects=True,
            timeout=10,
        )
    except requests.exceptions.RequestException:
        # Can't reach the server — skip CORS checks for this URL.
        return findings

    acao  = resp.headers.get("Access-Control-Allow-Origin", "")
    acac  = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    # ------------------------------------------------------------------
    # Check 1: Wildcard origin
    # ------------------------------------------------------------------
    is_wildcard = acao.strip() == "*"

    findings.append(Finding(
        url=url,
        check="CORS - Wildcard Origin",
        passed=not is_wildcard,
        threat=(
            "Access-Control-Allow-Origin: * means any website can read "
            "this server's responses, potentially exposing sensitive data."
        ),
        risk="Medium",
        owasp="A05:2021 - Security Misconfiguration",
        fix=(
            "Replace * with an explicit allowlist of trusted origins, e.g.: "
            "Access-Control-Allow-Origin: https://yourdomain.com"
        ) if is_wildcard else "N/A - wildcard origin not set.",
    ))

    # ------------------------------------------------------------------
    # Check 2: Reflected origin
    # The server echoed back our evil origin exactly — that's dangerous.
    # ------------------------------------------------------------------
    is_reflected = acao.strip() == evil_origin

    findings.append(Finding(
        url=url,
        check="CORS - Reflected Origin",
        passed=not is_reflected,
        threat=(
            "The server reflects any Origin header back in its response. "
            "An attacker can set their domain as Origin and read the response."
        ),
        risk="High",
        owasp="A05:2021 - Security Misconfiguration",
        fix=(
            "Validate incoming Origin headers against a strict allowlist. "
            "Never echo the Origin header back without checking it first."
        ) if is_reflected else "N/A - origin is not reflected.",
    ))

    # ------------------------------------------------------------------
    # Check 3: Credentials + permissive origin
    # credentials=true with a wildcard or reflected origin is the worst
    # combination — attackers can make authenticated cross-origin requests.
    # ------------------------------------------------------------------
    credentials_leak = acac == "true" and (is_wildcard or is_reflected)

    findings.append(Finding(
        url=url,
        check="CORS - Credentials + Open Origin",
        passed=not credentials_leak,
        threat=(
            "Access-Control-Allow-Credentials: true combined with a permissive "
            "origin lets attackers make authenticated requests from their site, "
            "bypassing same-origin protections."
        ),
        risk="High",
        owasp="A01:2021 - Broken Access Control",
        fix=(
            "Never set Allow-Credentials: true alongside a wildcard or "
            "reflected origin. Use a strict origin allowlist instead."
        ) if credentials_leak else "N/A - credentials not exposed.",
    ))

    return findings


# ===========================================================================
# SECTION 5 — COOKIE FLAGS & SERVER DISCLOSURE  (Stage 4)
# ===========================================================================

def check_cookies(url: str, response: requests.Response) -> list:
    """
    Inspects every Set-Cookie header in the response for three missing flags:

    - Secure   : Cookie is only sent over HTTPS. Without it, the cookie can
                 be intercepted over plain HTTP.
    - HttpOnly : Prevents JavaScript from reading the cookie. Without it,
                 an XSS attack can steal the cookie.
    - SameSite : Controls whether the cookie is sent with cross-site requests.
                 Without it, CSRF attacks become easier.

    Also checks for server version disclosure (see check_server_disclosure).
    """
    findings = []

    # requests stores all Set-Cookie headers in response.cookies, but to
    # check the raw flag text (like 'Secure', 'HttpOnly') we need the raw
    # header string.  response.raw.headers.getlist() gives us each header
    # as a separate string even if there are multiple cookies.
    raw_cookie_headers = response.headers.getlist("Set-Cookie") \
        if hasattr(response.headers, "getlist") \
        else response.raw.headers.getlist("Set-Cookie")

    for raw_cookie in raw_cookie_headers:
        # Extract the cookie name (the part before the first '=').
        cookie_name = raw_cookie.split("=")[0].strip()

        # Convert to lowercase for easier flag searching.
        cookie_lower = raw_cookie.lower()

        # ---- Secure flag ----
        has_secure = "secure" in cookie_lower
        findings.append(Finding(
            url=url,
            check=f"Cookie '{cookie_name}' - Secure Flag",
            passed=has_secure,
            threat=(
                f"Cookie '{cookie_name}' is missing the Secure flag. "
                "It can be transmitted over plain HTTP and intercepted."
            ),
            risk="High",
            owasp="A05:2021 - Security Misconfiguration",
            fix=f"Set the Secure flag on cookie '{cookie_name}'.",
        ))

        # ---- HttpOnly flag ----
        has_httponly = "httponly" in cookie_lower
        findings.append(Finding(
            url=url,
            check=f"Cookie '{cookie_name}' - HttpOnly Flag",
            passed=has_httponly,
            threat=(
                f"Cookie '{cookie_name}' is missing HttpOnly. "
                "A successful XSS attack can steal it via document.cookie."
            ),
            risk="High",
            owasp="A05:2021 - Security Misconfiguration",
            fix=f"Set the HttpOnly flag on cookie '{cookie_name}'.",
        ))

        # ---- SameSite flag ----
        has_samesite = "samesite" in cookie_lower
        findings.append(Finding(
            url=url,
            check=f"Cookie '{cookie_name}' - SameSite Flag",
            passed=has_samesite,
            threat=(
                f"Cookie '{cookie_name}' is missing SameSite. "
                "Cross-Site Request Forgery (CSRF) attacks become easier."
            ),
            risk="Medium",
            owasp="A05:2021 - Security Misconfiguration",
            fix=f"Set SameSite=Strict (or Lax) on cookie '{cookie_name}'.",
        ))

    return findings


def check_server_disclosure(url: str, resp_headers: dict) -> list:
    """
    Checks whether the Server response header discloses software version info.

    Examples of bad values: 'Apache/2.4.51', 'nginx/1.18.0', 'IIS/10.0'
    Examples of good values: 'Apache', 'nginx', or no Server header at all.

    Version strings give attackers a head start when looking for known CVEs.
    """
    server = resp_headers.get("Server", "")

    # A version number typically looks like digits and dots: e.g. '2.4.51'
    # We use a simple regex to detect any digit/dot sequence in the value.
    has_version = bool(re.search(r"\d+\.\d+", server))

    return [Finding(
        url=url,
        check="Server Version Disclosure",
        # passed = True when there is NO version string (safe)
        passed=not has_version,
        threat=(
            f"Server header '{server}' discloses the software version. "
            "Attackers can use this to look up known CVEs for that version."
        ),
        risk="Low",
        owasp="A05:2021 - Security Misconfiguration",
        fix=(
            "Configure your web server to suppress version info from the "
            "Server header, e.g. 'ServerTokens Prod' in Apache."
        ) if has_version else "N/A - no version disclosed.",
    )]


# ===========================================================================
# SECTION 6 — RISK SCORING & GRADING  (Stage 5)
# ===========================================================================

# Points awarded per failed finding.
RISK_WEIGHTS = {"High": 3, "Medium": 2, "Low": 1}

def score_findings(findings: list) -> tuple:
    """
    Calculates a risk-weighted score for a list of findings.

    Only *failed* findings (passed=False) count against the score.

    Scoring:
        High   = 3 points per failed check
        Medium = 2 points per failed check
        Low    = 1 point  per failed check

    Grading (based on score as a percentage of the maximum possible score):
        A  =  0 points  (perfect)
        B  =  1 - 25%
        C  = 26 - 50%
        D  = 51 - 75%
        F  = over 75%

    Returns (score, grade) as a tuple, e.g. (7, "C").
    """
    # Maximum possible score = every finding fails at its risk weight.
    max_score = sum(RISK_WEIGHTS.get(f.risk, 0) for f in findings)

    # Actual score = only the failed ones.
    actual_score = sum(
        RISK_WEIGHTS.get(f.risk, 0) for f in findings if not f.passed
    )

    if max_score == 0:
        return (0, "A")

    # Express the actual score as a percentage of the worst-case maximum.
    pct = (actual_score / max_score) * 100

    if actual_score == 0:
        grade = "A"
    elif pct <= 25:
        grade = "B"
    elif pct <= 50:
        grade = "C"
    elif pct <= 75:
        grade = "D"
    else:
        grade = "F"

    return (actual_score, grade)


# ===========================================================================
# SECTION 7 — CONSOLE OUTPUT
# ===========================================================================

def print_results(url: str, findings: list, score: int, grade: str) -> None:
    """
    Prints a PASS/FAIL table plus score and grade to the terminal.

    ANSI colour codes (work on Linux/macOS and modern Windows terminals):
      Green  \033[92m = PASS
      Red    \033[91m = FAIL
      Yellow \033[93m = fix/threat details
      Bold   \033[1m
      Reset  \033[0m
    """
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    # Grade colour: A/B = green, C = yellow, D/F = red.
    grade_colour = GREEN if grade in ("A", "B") else (YELLOW if grade == "C" else RED)

    print(f"\n{BOLD}{'=' * 65}{RESET}")
    print(f"{BOLD}  Security Scan Results - {url}{RESET}")
    print(f"{BOLD}{'=' * 65}{RESET}\n")

    for f in findings:
        status = f"{GREEN}PASS{RESET}" if f.passed else f"{RED}FAIL{RESET}"
        print(f"  {f.check:<45} {status}  [{f.risk}]")

        if not f.passed:
            print(f"    {YELLOW}Threat:{RESET} {f.threat}")
            print(f"    {YELLOW}Fix:   {RESET} {f.fix}")
            print(f"    {YELLOW}OWASP: {RESET} {f.owasp}")
            print()

    failed = sum(1 for f in findings if not f.passed)
    total  = len(findings)

    print(f"{BOLD}{'=' * 65}{RESET}")
    print(
        f"  Checks: {total - failed}/{total} passed  |  "
        f"Risk score: {score}  |  "
        f"Grade: {grade_colour}{BOLD}{grade}{RESET}"
    )
    print(f"{BOLD}{'=' * 65}{RESET}\n")


# ===========================================================================
# SECTION 8 — HTML REPORT  (Stage 6)
# ===========================================================================

def save_html_report(all_findings: dict, filename: str) -> None:
    """
    Saves a styled HTML report to 'filename'.

    'all_findings' is a dict mapping each URL to:
        { "findings": [Finding, ...], "score": int, "grade": str }

    The HTML is built by hand (no template engine) using only Python's
    built-in string formatting — no extra libraries needed.
    """

    # Colour for the grade badge.
    def grade_colour(g):
        if g in ("A", "B"): return "#16a34a"   # green
        if g == "C":        return "#ca8a04"   # amber
        return "#dc2626"                        # red

    # Risk badge colours.
    risk_colour = {"High": "#dc2626", "Medium": "#ca8a04", "Low": "#2563eb"}

    # Build one HTML table per scanned URL.
    url_sections = ""
    for url, data in all_findings.items():
        findings = data["findings"]
        score    = data["score"]
        grade    = data["grade"]
        gc       = grade_colour(grade)

        rows = ""
        for f in findings:
            status_cell = (
                '<td style="color:#16a34a;font-weight:bold">PASS</td>'
                if f.passed else
                '<td style="color:#dc2626;font-weight:bold">FAIL</td>'
            )
            rc = risk_colour.get(f.risk, "#374151")
            risk_cell = (
                f'<td><span style="background:{rc};color:#fff;'
                f'padding:2px 8px;border-radius:4px;font-size:12px">'
                f'{f.risk}</span></td>'
            )
            # Show fix only on failure rows; keep table clean on pass.
            fix_text = f.fix if not f.passed else ""
            rows += (
                f"<tr>"
                f"<td>{f.check}</td>"
                f"{status_cell}"
                f"{risk_cell}"
                f"<td style='font-size:12px;color:#374151'>{f.owasp}</td>"
                f"<td style='font-size:12px'>{fix_text}</td>"
                f"</tr>\n"
            )

        url_sections += f"""
        <div class="url-block">
          <div class="url-header">
            <span class="url-text">{url}</span>
            <span class="grade-badge" style="background:{gc}">Grade {grade}</span>
            <span class="score-text">Risk score: {score}</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Check</th><th>Status</th><th>Risk</th>
                <th>OWASP Category</th><th>Fix</th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
        """

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_urls = len(all_findings)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Web Security Scan Report</title>
  <style>
    body {{
      font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
      font-size: 14px; line-height: 1.6;
      background: #f7f8fa; color: #1f2328; margin: 0; padding: 24px;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    h1 {{ font-size: 22px; margin-bottom: 4px; }}
    .meta {{ color: #57606a; font-size: 13px; margin-bottom: 24px; }}
    .url-block {{
      background: #fff; border: 1px solid #e5e7eb;
      border-radius: 8px; margin-bottom: 28px; overflow: hidden;
    }}
    .url-header {{
      background: #1f2937; color: #f9fafb;
      padding: 12px 16px; display: flex; align-items: center; gap: 14px;
    }}
    .url-text {{ font-size: 14px; font-weight: 600; flex: 1;
                 word-break: break-all; }}
    .grade-badge {{
      padding: 3px 14px; border-radius: 20px; color: #fff;
      font-weight: 700; font-size: 14px; white-space: nowrap;
    }}
    .score-text {{ font-size: 12px; color: #d1d5db; white-space: nowrap; }}
    table {{
      width: 100%; border-collapse: collapse; font-size: 13px;
    }}
    th {{
      background: #f3f4f6; text-align: left;
      padding: 8px 12px; border-bottom: 1px solid #e5e7eb;
      font-weight: 600; color: #374151;
    }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #f3f4f6;
         vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #fafafa; }}
    footer {{
      text-align: center; font-size: 12px; color: #9ca3af;
      border-top: 1px solid #e5e7eb; margin-top: 32px; padding-top: 16px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Web Security Scan Report</h1>
    <div class="meta">
      Generated: {generated} &nbsp;|&nbsp; URLs scanned: {total_urls}
    </div>
    {url_sections}
    <footer>IBM SkillsBuild National Cybersecurity Bootcamp &mdash;
    Automated Web Security Scanner</footer>
  </div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


# ===========================================================================
# SECTION 9 — CSV REPORT  (Stage 6)
# ===========================================================================

def save_csv_report(all_findings: dict, filename: str) -> None:
    """
    Saves a flat CSV file with one row per finding.

    'all_findings' is the same dict used by save_html_report.

    Columns:
        URL, Check, Status, Risk, OWASP, Threat, Fix, Score, Grade
    """
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        # Write column headers first.
        writer.writerow([
            "URL", "Check", "Status", "Risk",
            "OWASP", "Threat", "Fix", "Score", "Grade"
        ])

        # Write one row per finding.
        for url, data in all_findings.items():
            for f in data["findings"]:
                writer.writerow([
                    f.url,
                    f.check,
                    "PASS" if f.passed else "FAIL",
                    f.risk,
                    f.owasp,
                    f.threat,
                    f.fix,
                    data["score"],
                    data["grade"],
                ])


# ===========================================================================
# SECTION 10 — MAIN ENTRY POINT  (Stage 5 + 6)
# ===========================================================================

def get_urls_from_args() -> list:
    """
    Parses the command-line arguments and returns a list of URLs to scan.

    Supported usages:
        python scanner.py https://example.com
        python scanner.py https://example.com https://google.com
        python scanner.py --file urls.txt

    For --file, the file should have one URL per line.
    Blank lines and lines starting with '#' are ignored.
    """
    args = sys.argv[1:]

    if not args:
        print("Usage:")
        print("  python scanner.py https://example.com")
        print("  python scanner.py https://a.com https://b.com")
        print("  python scanner.py --file urls.txt")
        sys.exit(1)

    # --file mode: read URLs from a text file.
    if args[0] == "--file":
        if len(args) < 2:
            print("[ERROR] --file requires a filename, e.g. --file urls.txt")
            sys.exit(1)
        filepath = args[1]
        if not os.path.exists(filepath):
            print(f"[ERROR] File not found: {filepath}")
            sys.exit(1)
        with open(filepath, "r", encoding="utf-8") as fh:
            urls = [
                line.strip() for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
        if not urls:
            print(f"[ERROR] No URLs found in {filepath}")
            sys.exit(1)
        return urls

    # Direct URL mode: every argument on the command line is a URL.
    return args


def scan_url(url: str) -> tuple:
    """
    Runs all checks on a single URL and returns (findings, score, grade).

    Called once per URL so multi-URL mode just loops over this function.
    """
    # Validate scheme.
    if not url.startswith(("http://", "https://")):
        print(f"[SKIP] {url} - no http:// or https:// scheme, skipping.")
        return None, None, None

    print(f"\n[*] Scanning: {url}")
    print("[*] Fetching...")

    try:
        response = fetch_url(url)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to {url} - skipping.")
        return None, None, None
    except requests.exceptions.Timeout:
        print(f"[ERROR] {url} timed out - skipping.")
        return None, None, None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - {e} - skipping.")
        return None, None, None

    print(f"[*] Status: {response.status_code}  Final URL: {response.url}")

    # Collect findings from every check module.
    findings = []
    findings += check_https(url)
    findings += check_security_headers(url, response.headers)
    findings += check_cors(url)
    findings += check_cookies(url, response)
    findings += check_server_disclosure(url, response.headers)

    # Score and grade this URL.
    score, grade = score_findings(findings)

    return findings, score, grade


def main():
    """
    Entry point. Reads URLs, scans each one, prints results,
    then saves both an HTML report and a CSV report.
    """
    urls = get_urls_from_args()

    # all_findings maps each URL to its findings + score + grade.
    # Used by both report generators.
    all_findings = {}

    for url in urls:
        findings, score, grade = scan_url(url)

        if findings is None:
            continue  # URL was skipped due to an error.

        # Print results to the terminal.
        print_results(url, findings, score, grade)

        # Store for the reports.
        all_findings[url] = {"findings": findings, "score": score, "grade": grade}

    if not all_findings:
        print("\n[!] No URLs were successfully scanned. No reports generated.")
        sys.exit(1)

    # Generate timestamped report filenames.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_file = f"report_{timestamp}.html"
    csv_file  = f"report_{timestamp}.csv"

    save_html_report(all_findings, html_file)
    save_csv_report(all_findings, csv_file)

    print(f"[+] HTML report saved: {html_file}")
    print(f"[+] CSV  report saved: {csv_file}\n")


# ---------------------------------------------------------------------------
# Run main() only when this file is executed directly (not imported).
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
