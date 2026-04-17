# ============================================================
#  WebSentinel - Module 3: Web Vulnerability Scanner
#  File: vuln_scanner.py
# ============================================================
#  WHAT THIS MODULE DOES:
#  1. Crawls the target website to find all links & forms
#  2. Tests for SQL Injection (error-based)
#  3. Tests for Cross-Site Scripting (Reflected XSS)
#  4. Checks for missing HTTP Security Headers
#  5. Tests for CSRF (missing anti-CSRF tokens in forms)
#  6. Checks for sensitive exposed files/directories
#  7. Detects directory traversal patterns
#  8. Saves all findings to vuln_results.json
# ============================================================

import requests
import json
from bs4 import BeautifulSoup   # pip install beautifulsoup4
from urllib.parse import urljoin, urlparse, urlencode
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"1\"=\"1", "' OR 'x'='x",
    "1' ORDER BY 1--", "1' ORDER BY 2--",
    "' UNION SELECT NULL--", "admin'--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'><script>alert(1)</script>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "pg_query",
    "sqlite3",
    "ora-",
    "syntax error",
]

SECURITY_HEADERS = {
    "Content-Security-Policy":   "Prevents XSS and data injection attacks",
    "X-Frame-Options":           "Prevents clickjacking attacks",
    "X-Content-Type-Options":    "Prevents MIME-type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Referrer-Policy":           "Controls referrer information leakage",
    "Permissions-Policy":        "Controls browser feature access",
}

SENSITIVE_PATHS = [
    "/robots.txt", "/.env", "/admin", "/admin/",
    "/backup.zip", "/backup.sql", "/db.sql",
    "/config.php", "/wp-config.php", "/web.config",
    "/.git/config", "/phpinfo.php", "/info.php",
    "/test.php", "/login", "/admin/login",
    "/administrator", "/phpmyadmin", "/server-status",
    "/.htaccess", "/sitemap.xml", "/crossdomain.xml",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

HEADERS = {"User-Agent": "WebSentinel/1.0 Security Scanner"}


# ─────────────────────────────────────────────
# STEP 1 – Crawl website for links and forms
# ─────────────────────────────────────────────
def crawl(base_url, max_pages=15):
    """Crawl target to collect all internal URLs and forms."""
    print(f"\n[*] Crawling target: {base_url} (max {max_pages} pages)")
    visited = set()
    to_visit = [base_url]
    all_forms = []
    all_links = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8,
                                verify=False)
            visited.add(url)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Collect forms on this page
            forms = soup.find_all("form")
            for form in forms:
                all_forms.append({"page": url, "form": form})

            # Collect internal links
            for a in soup.find_all("a", href=True):
                link = urljoin(base_url, a["href"])
                if urlparse(link).netloc == urlparse(base_url).netloc:
                    if link not in visited:
                        to_visit.append(link)
                        all_links.append(link)

            print(f"  [+] Crawled: {url} | Forms: {len(forms)}")
        except Exception as e:
            print(f"  [-] Failed : {url} — {e}")

    print(f"\n  [✔] Crawl complete — Pages: {len(visited)} | "
          f"Forms: {len(all_forms)} | Links: {len(all_links)}")
    return visited, all_forms, all_links


# ─────────────────────────────────────────────
# STEP 2 – SQL Injection Test
# ─────────────────────────────────────────────
def test_sqli(base_url, forms, links):
    """Test all forms and URL parameters for SQL Injection."""
    print("\n[*] Testing for SQL Injection...")
    findings = []

    # Test forms
    for item in forms:
        page  = item["page"]
        form  = item["form"]
        action = urljoin(page, form.get("action") or page)
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        fields = {i.get("name", f"field{n}"): "test"
                  for n, i in enumerate(inputs) if i.get("name")}

        for payload in SQLI_PAYLOADS:
            test_data = {k: payload for k in fields}
            try:
                if method == "post":
                    resp = requests.post(action, data=test_data,
                                         headers=HEADERS, timeout=8, verify=False)
                else:
                    resp = requests.get(action, params=test_data,
                                        headers=HEADERS, timeout=8, verify=False)

                body = resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        finding = {
                            "type":     "SQL Injection",
                            "severity": "CRITICAL",
                            "cvss":     9.8,
                            "url":      action,
                            "method":   method.upper(),
                            "payload":  payload,
                            "evidence": err,
                            "impact":   "Attacker can read, modify or delete database data",
                            "fix":      "Use parameterized queries / prepared statements",
                        }
                        findings.append(finding)
                        print(f"  [!!!] SQLi FOUND at: {action}")
                        print(f"        Payload  : {payload}")
                        print(f"        Evidence : {err}")
                        break
            except Exception:
                pass

    # Test URL parameters
    for link in links:
        parsed = urlparse(link)
        if "=" not in parsed.query:
            continue
        for payload in SQLI_PAYLOADS[:3]:
            test_url = link.split("?")[0] + "?" + parsed.query.replace(
                parsed.query.split("=")[1], payload)
            try:
                resp = requests.get(test_url, headers=HEADERS,
                                    timeout=8, verify=False)
                body = resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        findings.append({
                            "type":     "SQL Injection",
                            "severity": "CRITICAL",
                            "cvss":     9.8,
                            "url":      test_url,
                            "method":   "GET",
                            "payload":  payload,
                            "evidence": err,
                            "impact":   "Attacker can read, modify or delete database data",
                            "fix":      "Use parameterized queries / prepared statements",
                        })
                        print(f"  [!!!] SQLi FOUND (URL param): {test_url}")
                        break
            except Exception:
                pass

    print(f"  [✔] SQLi scan done — {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────
# STEP 3 – XSS Test
# ─────────────────────────────────────────────
def test_xss(base_url, forms, links):
    """Test forms and URL params for Reflected XSS."""
    print("\n[*] Testing for Cross-Site Scripting (XSS)...")
    findings = []

    # Test forms
    for item in forms:
        page   = item["page"]
        form   = item["form"]
        action = urljoin(page, form.get("action") or page)
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        fields = {i.get("name", f"field{n}"): "test"
                  for n, i in enumerate(inputs) if i.get("name")}

        for payload in XSS_PAYLOADS:
            test_data = {k: payload for k in fields}
            try:
                if method == "post":
                    resp = requests.post(action, data=test_data,
                                         headers=HEADERS, timeout=8, verify=False)
                else:
                    resp = requests.get(action, params=test_data,
                                        headers=HEADERS, timeout=8, verify=False)

                if payload in resp.text:
                    finding = {
                        "type":     "Reflected XSS",
                        "severity": "HIGH",
                        "cvss":     7.4,
                        "url":      action,
                        "method":   method.upper(),
                        "payload":  payload,
                        "evidence": "Payload reflected in response body",
                        "impact":   "Session hijacking, credential theft, defacement",
                        "fix":      "Encode all user output; implement Content-Security-Policy header",
                    }
                    findings.append(finding)
                    print(f"  [!!!] XSS FOUND at : {action}")
                    print(f"        Payload : {payload}")
                    break
            except Exception:
                pass

    # Test URL parameters
    for link in links:
        if "=" not in link:
            continue
        for payload in XSS_PAYLOADS[:3]:
            test_url = link + payload
            try:
                resp = requests.get(test_url, headers=HEADERS,
                                    timeout=8, verify=False)
                if payload in resp.text:
                    findings.append({
                        "type":     "Reflected XSS",
                        "severity": "HIGH",
                        "cvss":     7.4,
                        "url":      test_url,
                        "method":   "GET",
                        "payload":  payload,
                        "evidence": "Payload reflected in response body",
                        "impact":   "Session hijacking, credential theft, defacement",
                        "fix":      "Encode all user output; implement Content-Security-Policy header",
                    })
                    print(f"  [!!!] XSS FOUND (URL): {test_url}")
                    break
            except Exception:
                pass

    print(f"  [✔] XSS scan done — {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────
# STEP 4 – Security Header Check
# ─────────────────────────────────────────────
def check_security_headers(base_url):
    """Check for missing HTTP security headers."""
    print("\n[*] Checking HTTP Security Headers...")
    findings = []
    try:
        resp = requests.get(base_url, headers=HEADERS,
                            timeout=8, verify=False)
        for header, reason in SECURITY_HEADERS.items():
            if header not in resp.headers:
                finding = {
                    "type":     "Missing Security Header",
                    "severity": "MEDIUM",
                    "cvss":     5.3,
                    "url":      base_url,
                    "header":   header,
                    "evidence": f"Header '{header}' not present in response",
                    "impact":   reason,
                    "fix":      f"Add '{header}' header to all HTTP responses",
                }
                findings.append(finding)
                print(f"  [-] MISSING : {header}")
            else:
                print(f"  [+] PRESENT : {header}")
    except Exception as e:
        print(f"  [-] Header check failed: {e}")

    print(f"  [✔] Header check done — {len(findings)} missing header(s)")
    return findings


# ─────────────────────────────────────────────
# STEP 5 – CSRF Check
# ─────────────────────────────────────────────
def check_csrf(forms):
    """Check if forms are missing anti-CSRF tokens."""
    print("\n[*] Checking for CSRF vulnerabilities...")
    findings = []
    csrf_names = ["csrf", "token", "_token", "csrf_token",
                  "authenticity_token", "__requestverificationtoken"]

    for item in forms:
        page = item["page"]
        form = item["form"]
        method = form.get("method", "get").lower()

        if method != "post":
            continue  # CSRF mainly affects POST forms

        inputs = form.find_all("input")
        input_names = [i.get("name", "").lower() for i in inputs]
        has_token = any(n for n in input_names if any(c in n for c in csrf_names))

        if not has_token:
            finding = {
                "type":     "CSRF — Missing Anti-CSRF Token",
                "severity": "MEDIUM",
                "cvss":     6.5,
                "url":      page,
                "evidence": "POST form has no CSRF token in input fields",
                "impact":   "Attacker can trick logged-in users into unintended actions",
                "fix":      "Add a unique, secret CSRF token to all state-changing forms",
            }
            findings.append(finding)
            print(f"  [!!!] CSRF risk at: {page}")

    print(f"  [✔] CSRF check done — {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────
# STEP 6 – Sensitive File/Directory Check
# ─────────────────────────────────────────────
def check_sensitive_files(base_url):
    """Check for exposed sensitive files and directories."""
    print("\n[*] Checking for sensitive exposed files...")
    findings = []

    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, headers=HEADERS,
                                timeout=6, verify=False,
                                allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                severity = "HIGH" if resp.status_code == 200 else "LOW"
                finding = {
                    "type":     "Sensitive File/Directory Exposed",
                    "severity": severity,
                    "cvss":     7.5 if severity == "HIGH" else 3.1,
                    "url":      url,
                    "status":   resp.status_code,
                    "evidence": f"HTTP {resp.status_code} returned for {path}",
                    "impact":   "May expose credentials, config, or source code",
                    "fix":      "Remove or restrict access to sensitive files",
                }
                findings.append(finding)
                print(f"  [!!!] FOUND ({resp.status_code}): {url}")
            else:
                print(f"  [ ]  {resp.status_code} — {path}")
        except Exception:
            pass

    print(f"  [✔] Sensitive file check done — {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────
# STEP 7 – Directory Traversal Check
# ─────────────────────────────────────────────
def check_traversal(base_url, links):
    """Test URL params for directory traversal vulnerabilities."""
    print("\n[*] Checking for Directory Traversal...")
    findings = []

    for link in links:
        if "=" not in link:
            continue
        for payload in TRAVERSAL_PAYLOADS:
            test_url = link.split("=")[0] + "=" + payload
            try:
                resp = requests.get(test_url, headers=HEADERS,
                                    timeout=6, verify=False)
                if "root:x" in resp.text or "[boot loader]" in resp.text:
                    finding = {
                        "type":     "Directory Traversal",
                        "severity": "CRITICAL",
                        "cvss":     9.1,
                        "url":      test_url,
                        "payload":  payload,
                        "evidence": "System file content detected in response",
                        "impact":   "Attacker can read sensitive system files",
                        "fix":      "Validate and sanitize all file path inputs",
                    }
                    findings.append(finding)
                    print(f"  [!!!] TRAVERSAL FOUND: {test_url}")
                    break
            except Exception:
                pass

    print(f"  [✔] Traversal check done — {len(findings)} finding(s)")
    return findings


# ─────────────────────────────────────────────
# STEP 8 – Summary + Save
# ─────────────────────────────────────────────
def print_summary(all_findings):
    print("\n" + "=" * 55)
    print("   VULNERABILITY SCAN SUMMARY")
    print("=" * 55)
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        s = f.get("severity", "LOW")
        sev[s] = sev.get(s, 0) + 1
    print(f"  Total Findings  : {len(all_findings)}")
    print(f"  Critical        : {sev['CRITICAL']}")
    print(f"  High            : {sev['HIGH']}")
    print(f"  Medium          : {sev['MEDIUM']}")
    print(f"  Low             : {sev['LOW']}")
    print("=" * 55)


def save_results(data, filename="vuln_results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[✔] Vulnerability results saved to: {filename}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def run_vuln_scan(target_url):
    print("=" * 55)
    print("   WebSentinel — Module 3: Vulnerability Scanner")
    print("=" * 55)
    print(f"[*] Target      : {target_url}")
    print(f"[*] Scan Start  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Crawl first
    pages, forms, links = crawl(target_url)

    # Run all checks
    all_findings = []
    all_findings += test_sqli(target_url, forms, links)
    all_findings += test_xss(target_url, forms, links)
    all_findings += check_security_headers(target_url)
    all_findings += check_csrf(forms)
    all_findings += check_sensitive_files(target_url)
    all_findings += check_traversal(target_url, links)

    print_summary(all_findings)

    results = {
        "target":    target_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pages_crawled": len(pages),
        "forms_found":   len(forms),
        "total_findings": len(all_findings),
        "findings":  all_findings,
    }

    save_results(results)
    print("\n[✔] Module 3 — Vulnerability Scan Complete!")
    print("=" * 55)
    return results


# ─────────────────────────────────────────────
# Run directly for testing
# ─────────────────────────────────────────────
if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://testphp.vulnweb.com): ").strip()
    run_vuln_scan(target)