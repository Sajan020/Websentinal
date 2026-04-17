# ============================================================
#  WebSentinel - Module 1: Target Reconnaissance
#  File: recon.py
# ============================================================
#  WHAT THIS MODULE DOES:
#  1. Validates and parses the target URL
#  2. Performs WHOIS lookup (domain registration info)
#  3. Performs DNS enumeration (A, MX, NS records)
#  4. Grabs HTTP response headers
#  5. Detects basic technology stack
#  6. Saves all results to recon_results.json
# ============================================================

import socket
import json
import requests
import whois          # pip install python-whois
import dns.resolver   # pip install dnspython
from urllib.parse import urlparse
from datetime import datetime


# ─────────────────────────────────────────────
# STEP 1 – Parse and validate target URL
# ─────────────────────────────────────────────
def parse_target(url):
    """Extract clean domain and base URL from user input."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    return url, domain


# ─────────────────────────────────────────────
# STEP 2 – WHOIS Lookup
# ─────────────────────────────────────────────
def whois_lookup(domain):
    """Fetch domain registration details via WHOIS."""
    print(f"[*] Running WHOIS lookup on: {domain}")
    try:
        w = whois.whois(domain)
        result = {
            "registrar":       str(w.registrar),
            "creation_date":   str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers":    str(w.name_servers),
            "org":             str(w.org),
            "country":         str(w.country),
        }
        print(f"  [+] Registrar     : {result['registrar']}")
        print(f"  [+] Created       : {result['creation_date']}")
        print(f"  [+] Expires       : {result['expiration_date']}")
        return result
    except Exception as e:
        print(f"  [-] WHOIS failed  : {e}")
        return {"error": str(e)}


# ─────────────────────────────────────────────
# STEP 3 – DNS Enumeration
# ─────────────────────────────────────────────
def dns_enum(domain):
    """Enumerate A, MX, NS, and TXT DNS records."""
    print(f"\n[*] Running DNS Enumeration on: {domain}")
    dns_results = {}
    record_types = ["A", "MX", "NS", "TXT"]

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            dns_results[record] = [str(r) for r in answers]
            print(f"  [+] {record:3} Records : {dns_results[record]}")
        except Exception:
            dns_results[record] = []
            print(f"  [-] {record:3} Records : Not found")

    # Resolve IP address
    try:
        ip = socket.gethostbyname(domain)
        dns_results["IP"] = ip
        print(f"  [+] IP Address    : {ip}")
    except Exception:
        dns_results["IP"] = "Could not resolve"

    return dns_results


# ─────────────────────────────────────────────
# STEP 4 – HTTP Header Grabbing
# ─────────────────────────────────────────────
def grab_headers(url):
    """Fetch HTTP response headers from the target."""
    print(f"\n[*] Grabbing HTTP Headers from: {url}")
    try:
        resp = requests.get(url, timeout=8, verify=False,
                            headers={"User-Agent": "WebSentinel/1.0"})
        headers = dict(resp.headers)
        print(f"  [+] Status Code   : {resp.status_code}")
        for k, v in headers.items():
            print(f"  [+] {k}: {v}")
        return {"status_code": resp.status_code, "headers": headers}
    except Exception as e:
        print(f"  [-] Header grab failed: {e}")
        return {"error": str(e)}


# ─────────────────────────────────────────────
# STEP 5 – Technology Detection
# ─────────────────────────────────────────────
def detect_technologies(header_data):
    """Detect technologies from HTTP headers."""
    print(f"\n[*] Detecting Technologies...")
    tech = []

    if "error" in header_data:
        return ["Could not detect — headers unavailable"]

    headers = header_data.get("headers", {})
    server  = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    cookie  = headers.get("Set-Cookie", "")

    # Server detection
    if server:
        tech.append(f"Server: {server}")
        print(f"  [+] Server        : {server}")

    # Backend language / framework
    if powered:
        tech.append(f"Powered-By: {powered}")
        print(f"  [+] X-Powered-By  : {powered}")

    # CMS detection from cookies
    if "wordpress" in cookie.lower():
        tech.append("CMS: WordPress")
        print("  [+] CMS           : WordPress (detected via cookie)")
    if "joomla" in cookie.lower():
        tech.append("CMS: Joomla")
        print("  [+] CMS           : Joomla (detected via cookie)")
    if "PHPSESSID" in cookie:
        tech.append("Language: PHP")
        print("  [+] Language      : PHP (PHPSESSID detected)")
    if "JSESSIONID" in cookie:
        tech.append("Language: Java/JSP")
        print("  [+] Language      : Java/JSP (JSESSIONID detected)")
    if "ASP.NET" in cookie:
        tech.append("Framework: ASP.NET")
        print("  [+] Framework     : ASP.NET detected")

    if not tech:
        tech.append("Could not detect specific technologies")
        print("  [-] No specific technologies detected")

    return tech


# ─────────────────────────────────────────────
# STEP 6 – Save Results to JSON
# ─────────────────────────────────────────────
def save_results(data, filename="recon_results.json"):
    """Save all recon output to a JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[✔] Recon results saved to: {filename}")


# ─────────────────────────────────────────────
# MAIN – Run all recon steps
# ─────────────────────────────────────────────
def run_recon(target_url):
    """Run full reconnaissance on the given target URL."""
    print("=" * 55)
    print("   WebSentinel — Module 1: Reconnaissance")
    print("=" * 55)

    url, domain = parse_target(target_url)
    print(f"[*] Target URL    : {url}")
    print(f"[*] Target Domain : {domain}")
    print(f"[*] Scan Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Run all steps
    whois_data  = whois_lookup(domain)
    dns_data    = dns_enum(domain)
    header_data = grab_headers(url)
    tech_data   = detect_technologies(header_data)

    # Bundle everything
    results = {
        "target_url":    url,
        "domain":        domain,
        "scan_time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "whois":         whois_data,
        "dns":           dns_data,
        "http_headers":  header_data,
        "technologies":  tech_data,
    }

    save_results(results)

    print("\n[✔] Module 1 — Reconnaissance Complete!")
    print("=" * 55)
    return results


# ─────────────────────────────────────────────
# Run directly for testing
# ─────────────────────────────────────────────
if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://testphp.vulnweb.com): ").strip()
    run_recon(target)