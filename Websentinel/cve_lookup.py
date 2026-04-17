# ============================================================
#  WebSentinel - Module 4: CVE Lookup Integration
#  File: cve_lookup.py
# ============================================================
#  WHAT THIS MODULE DOES:
#  1. Reads port_results.json from Module 2
#  2. Extracts all detected service names + versions
#  3. Queries the NVD (National Vulnerability Database)
#     public API to fetch real CVEs for each service
#  4. Enriches findings with CVE ID, CVSS score,
#     severity, description, and published date
#  5. Saves enriched data to cve_results.json
#
#  API USED: NVD API v2 (Free, No key needed for basic use)
#  Docs: https://nvd.nist.gov/developers/vulnerabilities
# ============================================================

import requests
import json
import time
from datetime import datetime


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS     = {"User-Agent": "WebSentinel/1.0"}


# ─────────────────────────────────────────────
# CVSS Score → Severity Label
# ─────────────────────────────────────────────
def cvss_to_severity(score):
    if score is None:
        return "UNKNOWN"
    score = float(score)
    if score == 0.0:              return "NONE"
    elif 0.1 <= score <= 3.9:    return "LOW"
    elif 4.0 <= score <= 6.9:    return "MEDIUM"
    elif 7.0 <= score <= 8.9:    return "HIGH"
    else:                         return "CRITICAL"


# ─────────────────────────────────────────────
# STEP 1 – Load port scan results
# ─────────────────────────────────────────────
def load_port_results(filepath="port_results.json"):
    """Load Module 2 output to get detected services."""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        ports = data.get("open_ports", [])
        print(f"[*] Loaded {len(ports)} open port(s) from port_results.json")
        return ports
    except FileNotFoundError:
        print("[-] port_results.json not found.")
        print("    Run Module 2 (port_scanner.py) first.")
        return []


# ─────────────────────────────────────────────
# STEP 2 – Extract unique services to look up
# ─────────────────────────────────────────────
def extract_services(ports):
    """Build a unique list of (service, product, version) tuples."""
    services = []
    seen     = set()

    for p in ports:
        product = p.get("product", "").strip()
        version = p.get("version", "").strip()
        service = p.get("service", "").strip()
        port_no = p.get("port")

        if not product and not service:
            continue

        # Build a search keyword: prefer product name over generic service
        keyword = product if product else service
        key     = f"{keyword}_{version}"

        if key not in seen:
            seen.add(key)
            services.append({
                "port":    port_no,
                "service": service,
                "product": product,
                "version": version,
                "keyword": keyword,
            })

    print(f"[*] Unique services to look up: {len(services)}")
    return services


# ─────────────────────────────────────────────
# STEP 3 – Query NVD API for a single service
# ─────────────────────────────────────────────
def query_nvd(keyword, version="", max_results=5):
    """
    Query NVD API v2 for CVEs matching the given keyword.
    Returns a list of enriched CVE dicts.
    """
    # Build search query — keyword + version if available
    search_term = keyword
    if version:
        search_term = f"{keyword} {version}"

    params = {
        "keywordSearch": search_term,
        "resultsPerPage": max_results,
    }

    try:
        resp = requests.get(NVD_API_URL, params=params,
                            headers=HEADERS, timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            return parse_nvd_response(vulns, keyword)

        elif resp.status_code == 429:
            print("  [!] NVD rate limit hit — waiting 10 seconds...")
            time.sleep(10)
            return query_nvd(keyword, version, max_results)

        else:
            print(f"  [-] NVD API returned: {resp.status_code}")
            return []

    except requests.exceptions.Timeout:
        print(f"  [-] NVD API timeout for: {keyword}")
        return []
    except Exception as e:
        print(f"  [-] NVD API error: {e}")
        return []


# ─────────────────────────────────────────────
# STEP 4 – Parse NVD API response
# ─────────────────────────────────────────────
def parse_nvd_response(vulns, keyword):
    """Extract useful fields from raw NVD API response."""
    results = []

    for item in vulns:
        try:
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "N/A")
            desc    = cve_obj.get("descriptions", [{}])[0].get("value", "No description")
            pub     = cve_obj.get("published", "N/A")[:10]  # date only

            # Extract CVSS v3 score (prefer v3.1, fallback v3.0, then v2)
            cvss_score = None
            severity   = "UNKNOWN"
            metrics    = cve_obj.get("metrics", {})

            if "cvssMetricV31" in metrics:
                m          = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity   = m.get("baseSeverity", cvss_to_severity(cvss_score))

            elif "cvssMetricV30" in metrics:
                m          = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity   = m.get("baseSeverity", cvss_to_severity(cvss_score))

            elif "cvssMetricV2" in metrics:
                m          = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity   = cvss_to_severity(cvss_score)

            results.append({
                "cve_id":       cve_id,
                "description":  desc,
                "cvss_score":   cvss_score,
                "severity":     severity,
                "published":    pub,
                "nvd_url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "service":      keyword,
            })

        except Exception:
            continue

    return results


# ─────────────────────────────────────────────
# STEP 5 – Run full CVE lookup for all services
# ─────────────────────────────────────────────
def run_cve_lookup_for_services(services):
    """Loop through all detected services and query NVD for each."""
    all_cve_results = []

    for svc in services:
        keyword = svc["keyword"]
        version = svc["version"]
        port    = svc["port"]

        print(f"\n[*] Querying NVD for: {keyword} {version} (Port {port})")

        cves = query_nvd(keyword, version, max_results=5)

        if cves:
            print(f"  [+] Found {len(cves)} CVE(s):")
            for c in cves:
                print(f"      {c['cve_id']:20} | CVSS: {str(c['cvss_score']):5} "
                      f"| {c['severity']:8} | {c['description'][:60]}...")
            all_cve_results.append({
                "port":    port,
                "service": svc["service"],
                "product": svc["product"],
                "version": version,
                "cves":    cves,
            })
        else:
            print(f"  [-] No CVEs found for {keyword} {version}")

        # NVD rate limit: max 5 requests per 30s without API key
        time.sleep(6)

    return all_cve_results


# ─────────────────────────────────────────────
# STEP 6 – Also allow manual keyword lookup
# ─────────────────────────────────────────────
def manual_cve_lookup(keyword, version=""):
    """
    Standalone CVE lookup for any keyword.
    Useful for looking up specific software during thesis demo.
    """
    print(f"\n[*] Manual CVE Lookup: '{keyword} {version}'")
    cves = query_nvd(keyword, version, max_results=10)

    if not cves:
        print("  [-] No CVEs found.")
        return []

    print(f"\n  {'CVE ID':<20} {'CVSS':>6}  {'Severity':<10}  {'Published':<12}  Description")
    print("  " + "-" * 90)
    for c in cves:
        score = str(c["cvss_score"]) if c["cvss_score"] else "N/A"
        desc  = c["description"][:55] + "..." if len(c["description"]) > 55 else c["description"]
        print(f"  {c['cve_id']:<20} {score:>6}  {c['severity']:<10}  {c['published']:<12}  {desc}")

    return cves


# ─────────────────────────────────────────────
# STEP 7 – Summary
# ─────────────────────────────────────────────
def print_cve_summary(all_results):
    """Print a severity breakdown of all CVEs found."""
    print("\n" + "=" * 55)
    print("   CVE LOOKUP SUMMARY")
    print("=" * 55)

    total_cves = sum(len(r["cves"]) for r in all_results)
    sev_count  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                  "LOW": 0, "UNKNOWN": 0}

    for r in all_results:
        for c in r["cves"]:
            s = c.get("severity", "UNKNOWN").upper()
            sev_count[s] = sev_count.get(s, 0) + 1

    print(f"  Services Scanned : {len(all_results)}")
    print(f"  Total CVEs Found : {total_cves}")
    print(f"  Critical         : {sev_count['CRITICAL']}")
    print(f"  High             : {sev_count['HIGH']}")
    print(f"  Medium           : {sev_count['MEDIUM']}")
    print(f"  Low              : {sev_count['LOW']}")
    print("=" * 55)


# ─────────────────────────────────────────────
# STEP 8 – Save results
# ─────────────────────────────────────────────
def save_results(data, filename="cve_results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[✔] CVE results saved to: {filename}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def run_cve_lookup():
    print("=" * 55)
    print("   WebSentinel — Module 4: CVE Lookup")
    print("=" * 55)
    print(f"[*] Scan Start : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Load services from Module 2
    ports    = load_port_results()

    if not ports:
        # Fallback — allow manual lookup if no port results
        print("\n[*] No port results found. Switching to manual lookup mode.")
        kw = input("Enter software name to look up (e.g. Apache): ").strip()
        vr = input("Enter version (optional, press Enter to skip): ").strip()
        cves = manual_cve_lookup(kw, vr)
        results = {"manual_lookup": {"keyword": kw, "cves": cves}}
    else:
        services    = extract_services(ports)
        all_results = run_cve_lookup_for_services(services)
        print_cve_summary(all_results)
        results = {
            "scan_time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "services_scanned": len(all_results),
            "cve_findings":    all_results,
        }

    save_results(results)
    print("\n[✔] Module 4 — CVE Lookup Complete!")
    print("=" * 55)
    return results


# ─────────────────────────────────────────────
# Run directly
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("Choose mode:")
    print("  1 — Auto (uses port_results.json from Module 2)")
    print("  2 — Manual keyword lookup")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "2":
        kw = input("Enter software name (e.g. OpenSSH): ").strip()
        vr = input("Enter version (e.g. 7.2) or press Enter to skip: ").strip()
        manual_cve_lookup(kw, vr)
    else:
        run_cve_lookup()