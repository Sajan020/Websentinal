# ============================================================
#  WebSentinel - Module 2: Port & Service Scanner
#  File: port_scanner.py
# ============================================================
#  WHAT THIS MODULE DOES:
#  1. Scans common ports on the target using python-nmap
#  2. Identifies running services and their versions
#  3. Flags ports that are commonly risky/dangerous
#  4. Checks detected service versions against a local
#     CVE reference list and flags vulnerable ones
#  5. Saves results to port_results.json
# ============================================================

import nmap           # pip install python-nmap
import json
import socket
import shutil
from datetime import datetime
from urllib.parse import urlparse


# ─────────────────────────────────────────────
# LOCAL CVE REFERENCE TABLE
# Common vulnerable service versions — used to
# flag risky services without needing internet
# ─────────────────────────────────────────────
VULNERABLE_VERSIONS = {
    "apache":    {"version": "2.4.49", "cve": "CVE-2021-41773", "cvss": 9.8, "desc": "Path Traversal & RCE"},
    "openssh":   {"version": "7.2",    "cve": "CVE-2016-6515",  "cvss": 7.8, "desc": "DoS via password auth"},
    "vsftpd":    {"version": "2.3.4",  "cve": "CVE-2011-2523",  "cvss": 9.8, "desc": "Backdoor command exec"},
    "mysql":     {"version": "5.5",    "cve": "CVE-2012-2122",  "cvss": 5.8, "desc": "Auth bypass vulnerability"},
    "php":       {"version": "5.",     "cve": "CVE-2019-11043",  "cvss": 9.8, "desc": "Remote Code Execution"},
    "iis":       {"version": "6.0",    "cve": "CVE-2017-7269",  "cvss": 9.8, "desc": "Buffer overflow / RCE"},
    "proftpd":   {"version": "1.3.3",  "cve": "CVE-2010-4221",  "cvss": 10.0,"desc": "Remote Code Execution"},
    "samba":     {"version": "3.",     "cve": "CVE-2017-7494",  "cvss": 9.8, "desc": "EternalRed / RCE"},
}

# Ports considered high-risk if found open
RISKY_PORTS = {
    21:   "FTP — credentials sent in plaintext",
    23:   "Telnet — unencrypted remote access",
    25:   "SMTP — mail relay abuse possible",
    445:  "SMB — EternalBlue / ransomware target",
    3389: "RDP — brute-force & BlueKeep risk",
    1433: "MSSQL — database exposed to network",
    3306: "MySQL — database exposed to network",
    5900: "VNC — remote desktop, often weak auth",
    6379: "Redis — often exposed without auth",
    27017:"MongoDB — often exposed without auth",
}


# ─────────────────────────────────────────────
# STEP 1 – Extract IP from URL/domain
# ─────────────────────────────────────────────
def get_ip(target):
    """Resolve domain to IP address."""
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0]  # remove port if present
    try:
        ip = socket.gethostbyname(domain)
        print(f"  [+] Resolved {domain} → {ip}")
        return ip, domain
    except Exception as e:
        print(f"  [-] Could not resolve domain: {e}")
        return domain, domain


# ─────────────────────────────────────────────
# STEP 2 – Run Nmap Port Scan
# ─────────────────────────────────────────────
def run_nmap_scan(ip):
    """Run nmap scan on common ports with service/version detection."""
    print(f"\n[*] Starting Nmap scan on: {ip}")
    print("[*] Scanning top 1000 ports with service detection...")
    print("[*] This may take 1–2 minutes...\n")

    if not shutil.which("nmap"):
        print("  [!] nmap binary not found in system PATH.")
        print("  [*] Falling back to basic TCP connect scan.")
        return None, ip

    nm = nmap.PortScanner()

    # -sV  = version detection
    # -T4  = faster timing
    # --open = only show open ports
    nm.scan(hosts=ip, arguments="-sV -T4 --open -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017")

    return nm, ip


def run_basic_socket_scan(ip):
    """Fallback scanner when nmap binary is unavailable."""
    target_ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,27017]
    findings = []
    service_map = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
        443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
        1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
        8888: "http-alt", 27017: "mongodb",
    }

    print("[*] Running fallback socket scan on curated ports...")
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((ip, port)) == 0:
                service = service_map.get(port, "unknown")
                product = ""
                version = ""
                full_ver = f"{product} {version}".strip()
                risk = check_risk(port, service, product, version)
                cve_hit = check_cve(service, product, version)
                findings.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "product": product,
                    "version": version,
                    "full_version": full_ver,
                    "risk": risk["level"],
                    "risk_reason": risk["reason"],
                    "cve": cve_hit,
                })
                print(f"  [PORT {port:5}/tcp]  OPEN  |  {service:12} {full_ver:25}  |  Risk: {risk['level']:8}")
        except Exception:
            pass
        finally:
            sock.close()

    return findings


# ─────────────────────────────────────────────
# STEP 3 – Parse Nmap Results
# ─────────────────────────────────────────────
def parse_scan_results(nm, ip):
    """Parse nmap output into structured findings."""
    if nm is None:
        return run_basic_socket_scan(ip)

    port_findings = []

    if ip not in nm.all_hosts():
        print("  [-] No hosts found. Target may be offline or blocking scans.")
        return port_findings

    for proto in nm[ip].all_protocols():
        ports = sorted(nm[ip][proto].keys())
        for port in ports:
            svc   = nm[ip][proto][port]
            state = svc["state"]

            if state != "open":
                continue

            service = svc.get("name", "unknown")
            product = svc.get("product", "")
            version = svc.get("version", "")
            full_ver = f"{product} {version}".strip()

            # Determine risk level
            risk    = check_risk(port, service, product, version)
            cve_hit = check_cve(service, product, version)

            finding = {
                "port":        port,
                "protocol":    proto,
                "state":       state,
                "service":     service,
                "product":     product,
                "version":     version,
                "full_version":full_ver,
                "risk":        risk["level"],
                "risk_reason": risk["reason"],
                "cve":         cve_hit,
            }

            port_findings.append(finding)

            # Print to terminal
            cve_tag = f"⚠ {cve_hit['cve']}" if cve_hit else ""
            print(f"  [PORT {port:5}/{proto}]  {state.upper():4}  |  "
                  f"{service:12} {full_ver:25}  |  "
                  f"Risk: {risk['level']:8}  {cve_tag}")

    return port_findings


# ─────────────────────────────────────────────
# STEP 4 – Risk Level Check
# ─────────────────────────────────────────────
def check_risk(port, service, product, version):
    """Assign risk level based on port and service."""
    if port in RISKY_PORTS:
        return {"level": "HIGH", "reason": RISKY_PORTS[port]}
    if service in ["ftp", "telnet", "smtp"]:
        return {"level": "MEDIUM", "reason": "Unencrypted protocol in use"}
    if port in [80] and "http" in service:
        return {"level": "LOW", "reason": "HTTP (unencrypted) — consider HTTPS"}
    if port in [443, 22]:
        return {"level": "INFO", "reason": "Standard encrypted service"}
    return {"level": "INFO", "reason": "Open port — review if needed"}


# ─────────────────────────────────────────────
# STEP 5 – CVE Version Check
# ─────────────────────────────────────────────
def check_cve(service, product, version):
    """Check if detected version matches known vulnerable versions."""
    combined = f"{service} {product} {version}".lower()
    for key, data in VULNERABLE_VERSIONS.items():
        if key in combined and data["version"] in combined:
            print(f"\n  [!!!] VULNERABLE VERSION DETECTED!")
            print(f"        Service : {product} {version}")
            print(f"        CVE     : {data['cve']}  (CVSS: {data['cvss']})")
            print(f"        Impact  : {data['desc']}\n")
            return data
    return None


# ─────────────────────────────────────────────
# STEP 6 – Summary
# ─────────────────────────────────────────────
def print_summary(findings):
    """Print a clean summary table of all findings."""
    print("\n" + "=" * 55)
    print("   PORT SCAN SUMMARY")
    print("=" * 55)

    high   = [f for f in findings if f["risk"] == "HIGH"]
    medium = [f for f in findings if f["risk"] == "MEDIUM"]
    cves   = [f for f in findings if f["cve"]]

    print(f"  Total Open Ports : {len(findings)}")
    print(f"  High Risk Ports  : {len(high)}")
    print(f"  Medium Risk      : {len(medium)}")
    print(f"  CVEs Detected    : {len(cves)}")

    if high:
        print("\n  [!] HIGH RISK PORTS:")
        for f in high:
            print(f"      Port {f['port']} ({f['service']}) — {f['risk_reason']}")

    if cves:
        print("\n  [!] VULNERABLE VERSIONS:")
        for f in cves:
            c = f["cve"]
            print(f"      Port {f['port']} — {f['full_version']}")
            print(f"      {c['cve']} | CVSS {c['cvss']} | {c['desc']}")


# ─────────────────────────────────────────────
# STEP 7 – Save Results
# ─────────────────────────────────────────────
def save_results(data, filename="port_results.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[✔] Port scan results saved to: {filename}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def run_port_scan(target_url):
    print("=" * 55)
    print("   WebSentinel — Module 2: Port & Service Scanner")
    print("=" * 55)
    print(f"[*] Scan Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    ip, domain = get_ip(target_url)
    nm, ip     = run_nmap_scan(ip)
    findings   = parse_scan_results(nm, ip)

    print_summary(findings)

    results = {
        "target":     target_url,
        "ip":         ip,
        "scan_time":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": findings,
        "summary": {
            "total_open":  len(findings),
            "high_risk":   len([f for f in findings if f["risk"] == "HIGH"]),
            "medium_risk": len([f for f in findings if f["risk"] == "MEDIUM"]),
            "cves_found":  len([f for f in findings if f["cve"]]),
        }
    }

    save_results(results)

    print("\n[✔] Module 2 — Port Scan Complete!")
    print("=" * 55)
    return results


# ─────────────────────────────────────────────
# Run directly for testing
# ─────────────────────────────────────────────
if __name__ == "__main__":
    target = input("Enter target URL or IP (e.g. http://testphp.vulnweb.com): ").strip()
    run_port_scan(target)