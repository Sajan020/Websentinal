# ============================================================
#  WebSentinel - Module 5: PDF Report Generator
#  File: report_generator.py
# ============================================================
#  WHAT THIS MODULE DOES:
#  1. Reads all 4 JSON results from Modules 1–4
#  2. Generates a professional penetration test PDF report
#  3. Report sections:
#     - Cover Page
#     - Table of Contents
#     - Executive Summary
#     - Target Information (Recon)
#     - Open Ports & Services
#     - Vulnerability Findings (with severity badges)
#     - CVE Findings
#     - Remediation Summary Table
#     - Conclusion
#  4. Saves as:  WebSentinel_Report_<domain>_<date>.pdf
#
#  LIBRARY: fpdf2   (pip install fpdf2)
# ============================================================

import json
import os
from datetime import datetime
from fpdf import FPDF          # pip install fpdf2
from fpdf.enums import XPos, YPos


# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────
C_DARK      = (20,  20,  40)     # dark navy — headings
C_BLUE      = (30,  90,  160)    # brand blue
C_LIGHT     = (245, 247, 252)    # light grey bg
C_WHITE     = (255, 255, 255)
C_CRITICAL  = (180, 0,   0)
C_HIGH      = (210, 80,  0)
C_MEDIUM    = (200, 150, 0)
C_LOW       = (40,  140, 60)
C_INFO      = (80,  80,  140)
C_LINE      = (200, 210, 230)    # divider lines


def sev_color(severity):
    s = severity.upper()
    if s == "CRITICAL": return C_CRITICAL
    if s == "HIGH":     return C_HIGH
    if s == "MEDIUM":   return C_MEDIUM
    if s == "LOW":      return C_LOW
    return C_INFO


# ─────────────────────────────────────────────
# LOAD JSON FILES
# ─────────────────────────────────────────────
def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default or {}


# ─────────────────────────────────────────────
# CUSTOM PDF CLASS
# ─────────────────────────────────────────────
class WebSentinelReport(FPDF):

    def header(self):
        if self.page_no() == 1:
            return
        # Top bar
        self.set_fill_color(*C_BLUE)
        self.rect(0, 0, 210, 10, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C_WHITE)
        self.set_xy(10, 2)
        self.cell(0, 6, "WebSentinel — Penetration Test Report  |  CONFIDENTIAL")
        self.set_text_color(*C_DARK)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-13)
        self.set_draw_color(*C_LINE)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "", 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8,
                  f"WebSentinel Security Report  |  Generated: "
                  f"{datetime.now().strftime('%d %b %Y')}  |  Page {self.page_no()}",
                  align="C")

    # ── Section heading ──────────────────────
    def section_title(self, title, num=""):
        self.ln(4)
        self.set_fill_color(*C_BLUE)
        self.rect(10, self.get_y(), 190, 9, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*C_WHITE)
        self.set_x(13)
        self.cell(0, 9, f"{num}  {title}" if num else title)
        self.ln(11)
        self.set_text_color(*C_DARK)

    # ── Key-value row ─────────────────────────
    def kv_row(self, key, value, bg=False):
        if bg:
            self.set_fill_color(*C_LIGHT)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*C_BLUE)
        self.set_x(12)
        self.cell(55, 7, key, fill=bg)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*C_DARK)
        self.multi_cell(0, 7, str(value), fill=bg)

    # ── Severity badge (inline coloured box) ──
    def severity_badge(self, severity, x, y):
        color = sev_color(severity)
        self.set_fill_color(*color)
        self.set_text_color(*C_WHITE)
        self.set_font("Helvetica", "B", 8)
        self.set_xy(x, y)
        self.cell(22, 6, severity.upper(), align="C", fill=True)
        self.set_text_color(*C_DARK)

    # ── Divider line ──────────────────────────
    def divider(self):
        self.set_draw_color(*C_LINE)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)


# ─────────────────────────────────────────────
# PAGE 1 — COVER PAGE
# ─────────────────────────────────────────────
def add_cover(pdf, target, scan_date):
    pdf.add_page()

    # Top block
    pdf.set_fill_color(*C_BLUE)
    pdf.rect(0, 0, 210, 70, "F")

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*C_WHITE)
    pdf.set_xy(0, 20)
    pdf.cell(0, 14, "WebSentinel", align="C")
    pdf.ln(12)
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, "Automated Web Vulnerability Assessment Report", align="C")

    # Middle block
    pdf.set_text_color(*C_DARK)
    pdf.set_xy(30, 90)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_fill_color(*C_LIGHT)
    pdf.rect(25, 85, 160, 70, "F")

    details = [
        ("Target",         target),
        ("Report Date",    scan_date),
        ("Classification", "CONFIDENTIAL"),
        ("Prepared by",    "WebSentinel Automated Scanner"),
        ("Version",        "1.0"),
    ]
    pdf.set_xy(30, 90)
    for k, v in details:
        pdf.set_x(30)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*C_BLUE)
        pdf.cell(50, 9, k + ":")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*C_DARK)
        pdf.cell(0, 9, v)
        pdf.ln()

    # Warning banner
    pdf.set_xy(15, 175)
    pdf.set_fill_color(*C_CRITICAL)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(180, 8,
             "⚠  This report contains sensitive security information. "
             "Handle with strict confidentiality.",
             align="C", fill=True)

    # Bottom strip
    pdf.set_fill_color(*C_DARK)
    pdf.rect(0, 268, 210, 29, "F")
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_xy(0, 278)
    pdf.cell(0, 6,
             "Generated by WebSentinel  |  For Authorized Use Only",
             align="C")


# ─────────────────────────────────────────────
# EXECUTIVE SUMMARY
# ─────────────────────────────────────────────
def add_executive_summary(pdf, vuln_data, port_data, cve_data):
    pdf.add_page()
    pdf.section_title("Executive Summary", "01")

    findings  = vuln_data.get("findings", [])
    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", "LOW").upper()
        sev_count[s] = sev_count.get(s, 0) + 1

    total_ports = port_data.get("summary", {}).get("total_open", 0)
    high_ports  = port_data.get("summary", {}).get("high_risk",  0)
    cve_count   = sum(len(r.get("cves", [])) for r in
                      cve_data.get("cve_findings", []))

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*C_DARK)
    pdf.set_x(12)
    summary_text = (
        f"WebSentinel performed an automated vulnerability assessment on the "
        f"target system. The assessment identified a total of {len(findings)} "
        f"web application vulnerabilities, {total_ports} open network ports "
        f"({high_ports} high-risk), and {cve_count} CVEs associated with "
        f"detected service versions. Immediate attention is required for all "
        f"Critical and High severity findings."
    )
    pdf.multi_cell(186, 6, summary_text)
    pdf.ln(4)

    # Severity stat boxes
    boxes = [
        ("CRITICAL", sev_count["CRITICAL"], C_CRITICAL),
        ("HIGH",     sev_count["HIGH"],     C_HIGH),
        ("MEDIUM",   sev_count["MEDIUM"],   C_MEDIUM),
        ("LOW",      sev_count["LOW"],      C_LOW),
    ]
    x = 12
    for label, count, color in boxes:
        pdf.set_fill_color(*color)
        pdf.set_text_color(*C_WHITE)
        pdf.rect(x, pdf.get_y(), 42, 20, "F")
        pdf.set_xy(x, pdf.get_y() + 3)
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(42, 8, str(count), align="C")
        pdf.set_xy(x, pdf.get_y() + 2)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(42, 5, label, align="C")
        x += 47
    pdf.ln(26)


# ─────────────────────────────────────────────
# TARGET INFORMATION  (from recon)
# ─────────────────────────────────────────────
def add_target_info(pdf, recon_data):
    pdf.section_title("Target Information & Reconnaissance", "02")

    dns   = recon_data.get("dns",   {})
    whois = recon_data.get("whois", {})
    tech  = recon_data.get("technologies", [])

    rows = [
        ("Target URL",     recon_data.get("target_url",  "N/A")),
        ("Domain",         recon_data.get("domain",      "N/A")),
        ("IP Address",     dns.get("IP",                 "N/A")),
        ("Scan Time",      recon_data.get("scan_time",   "N/A")),
        ("Registrar",      whois.get("registrar",        "N/A")),
        ("Created",        whois.get("creation_date",    "N/A")),
        ("Expires",        whois.get("expiration_date",  "N/A")),
        ("Name Servers",   whois.get("name_servers",     "N/A")),
        ("DNS A Records",  ", ".join(dns.get("A",  []))),
        ("DNS MX Records", ", ".join(dns.get("MX", []))),
        ("Technologies",   ", ".join(tech) if tech else "Not detected"),
    ]
    for i, (k, v) in enumerate(rows):
        pdf.kv_row(k, str(v)[:100], bg=(i % 2 == 0))
    pdf.ln(4)


# ─────────────────────────────────────────────
# OPEN PORTS TABLE
# ─────────────────────────────────────────────
def add_ports_table(pdf, port_data):
    pdf.section_title("Open Ports & Services", "03")

    ports = port_data.get("open_ports", [])
    if not ports:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "No open ports detected.")
        pdf.ln()
        return

    # Table header
    col_w = [18, 14, 35, 40, 20, 60]
    heads = ["Port", "Proto", "Service", "Product/Version", "Risk", "Reason"]
    pdf.set_fill_color(*C_BLUE)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_x(10)
    for w, h in zip(col_w, heads):
        pdf.cell(w, 7, h, border=0, fill=True, align="C")
    pdf.ln()

    pdf.set_text_color(*C_DARK)
    for i, p in enumerate(ports):
        bg = (i % 2 == 0)
        if bg:
            pdf.set_fill_color(*C_LIGHT)
        else:
            pdf.set_fill_color(*C_WHITE)

        risk    = p.get("risk", "INFO")
        r_color = sev_color(risk)
        row_y   = pdf.get_y()
        pdf.set_x(10)
        pdf.set_font("Helvetica", "", 8)

        pdf.cell(col_w[0], 6, str(p.get("port", "")),      fill=bg, align="C")
        pdf.cell(col_w[1], 6, p.get("protocol", ""),        fill=bg, align="C")
        pdf.cell(col_w[2], 6, p.get("service", "")[:20],   fill=bg)
        pdf.cell(col_w[3], 6, p.get("full_version","")[:28],fill=bg)

        # Risk badge
        pdf.set_fill_color(*r_color)
        pdf.set_text_color(*C_WHITE)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(col_w[4], 6, risk, fill=True, align="C")

        pdf.set_fill_color(*C_LIGHT if bg else C_WHITE)
        pdf.set_text_color(*C_DARK)
        pdf.set_font("Helvetica", "", 7)
        pdf.cell(col_w[5], 6, p.get("risk_reason","")[:38], fill=bg)
        pdf.ln()

    pdf.ln(4)


# ─────────────────────────────────────────────
# VULNERABILITY FINDINGS
# ─────────────────────────────────────────────
def add_vuln_findings(pdf, vuln_data):
    pdf.section_title("Vulnerability Findings", "04")

    findings = vuln_data.get("findings", [])
    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "No vulnerabilities detected.")
        pdf.ln()
        return

    for i, f in enumerate(findings, 1):
        # Check page space
        if pdf.get_y() > 240:
            pdf.add_page()

        sev    = f.get("severity", "LOW")
        color  = sev_color(sev)
        f_type = f.get("type", "Unknown")

        # Finding header bar
        pdf.set_fill_color(*color)
        pdf.rect(10, pdf.get_y(), 190, 7, "F")
        pdf.set_text_color(*C_WHITE)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_x(13)
        cvss_str = f"  |  CVSS: {f.get('cvss', 'N/A')}" if f.get("cvss") else ""
        pdf.cell(0, 7, f"  Finding #{i:02d}  —  {f_type}{cvss_str}")
        pdf.ln(9)

        # Detail rows
        detail_rows = [
            ("Severity",    sev),
            ("URL",         f.get("url",      "N/A")),
            ("Method",      f.get("method",   "N/A")),
            ("Payload",     f.get("payload",  "N/A")),
            ("Evidence",    f.get("evidence", "N/A")),
            ("Impact",      f.get("impact",   "N/A")),
            ("Fix",         f.get("fix",      "N/A")),
        ]
        for j, (k, v) in enumerate(detail_rows):
            if v in ("N/A", "", None):
                continue
            pdf.set_fill_color(*C_LIGHT if j % 2 == 0 else C_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*C_BLUE)
            pdf.set_x(12)
            pdf.cell(35, 6, k + ":", fill=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*C_DARK)
            pdf.multi_cell(0, 6, str(v)[:200], fill=True)

        pdf.ln(3)
        pdf.divider()


# ─────────────────────────────────────────────
# CVE FINDINGS
# ─────────────────────────────────────────────
def add_cve_findings(pdf, cve_data):
    pdf.section_title("CVE Findings from Detected Services", "05")

    findings = cve_data.get("cve_findings", [])
    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "No CVE data available.")
        pdf.ln()
        return

    for svc in findings:
        if pdf.get_y() > 240:
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*C_BLUE)
        pdf.set_x(12)
        pdf.cell(0, 7,
                 f"Port {svc.get('port')}  —  "
                 f"{svc.get('product','')} {svc.get('version','')}")
        pdf.ln(8)

        for cve in svc.get("cves", []):
            if pdf.get_y() > 255:
                pdf.add_page()
            sev   = cve.get("severity", "UNKNOWN")
            score = cve.get("cvss_score", "N/A")
            color = sev_color(sev)

            pdf.set_fill_color(*color)
            pdf.set_text_color(*C_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_x(14)
            pdf.cell(32, 6, cve.get("cve_id", ""), fill=True, align="C")
            pdf.set_fill_color(*C_LIGHT)
            pdf.set_text_color(*C_DARK)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(20, 6, f"CVSS: {score}", fill=True, align="C")
            pdf.cell(0, 6, cve.get("description","")[:110], fill=True)
            pdf.ln(7)

        pdf.ln(2)
        pdf.divider()


# ─────────────────────────────────────────────
# REMEDIATION SUMMARY TABLE
# ─────────────────────────────────────────────
def add_remediation_table(pdf, vuln_data):
    pdf.add_page()
    pdf.section_title("Remediation Summary", "06")

    findings = vuln_data.get("findings", [])
    if not findings:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 8, "No findings to remediate.")
        return

    col_w = [8, 48, 22, 110]
    heads = ["#", "Vulnerability", "Severity", "Recommended Fix"]

    pdf.set_fill_color(*C_BLUE)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_x(10)
    for w, h in zip(col_w, heads):
        pdf.cell(w, 7, h, fill=True, align="C")
    pdf.ln()

    for i, f in enumerate(findings, 1):
        if pdf.get_y() > 265:
            pdf.add_page()
        bg    = (i % 2 == 0)
        sev   = f.get("severity", "LOW")
        color = sev_color(sev)

        if bg:
            pdf.set_fill_color(*C_LIGHT)
        else:
            pdf.set_fill_color(*C_WHITE)

        pdf.set_x(10)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*C_DARK)
        pdf.cell(col_w[0], 6, str(i), fill=bg, align="C")
        pdf.cell(col_w[1], 6, f.get("type","")[:30], fill=bg)

        pdf.set_fill_color(*color)
        pdf.set_text_color(*C_WHITE)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(col_w[2], 6, sev, fill=True, align="C")

        pdf.set_fill_color(*C_LIGHT if bg else C_WHITE)
        pdf.set_text_color(*C_DARK)
        pdf.set_font("Helvetica", "", 7)
        pdf.multi_cell(col_w[3], 6,
                       f.get("fix","N/A")[:120],
                       fill=bg)

    pdf.ln(5)


# ─────────────────────────────────────────────
# CONCLUSION
# ─────────────────────────────────────────────
def add_conclusion(pdf, vuln_data, target):
    pdf.section_title("Conclusion", "07")

    total = len(vuln_data.get("findings", []))
    sev_c = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in vuln_data.get("findings",[]):
        s = f.get("severity","LOW").upper()
        sev_c[s] = sev_c.get(s,0)+1

    text = (
        f"The automated assessment of {target} identified {total} security "
        f"vulnerabilities comprising {sev_c['CRITICAL']} Critical, "
        f"{sev_c['HIGH']} High, {sev_c['MEDIUM']} Medium, and "
        f"{sev_c['LOW']} Low severity findings. "
        f"All Critical and High severity issues should be remediated "
        f"immediately. Medium severity issues should be addressed in the "
        f"next patch cycle. It is recommended that a manual penetration test "
        f"be conducted after remediation to verify all fixes. This report was "
        f"generated automatically by WebSentinel and should be reviewed by a "
        f"qualified security professional before client delivery."
    )
    pdf.set_font("Helvetica", "", 10)
    pdf.set_x(12)
    pdf.multi_cell(186, 6, text)
    pdf.ln(6)

    pdf.set_fill_color(*C_LIGHT)
    pdf.set_x(12)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C_BLUE)
    pdf.cell(186, 8,
             "This report was generated by WebSentinel — "
             "An Automated VAPT Tool",
             fill=True, align="C")


# ─────────────────────────────────────────────
# MAIN — GENERATE FULL REPORT
# ─────────────────────────────────────────────
def generate_report(target_url=None):
    print("=" * 55)
    print("   WebSentinel — Module 5: PDF Report Generator")
    print("=" * 55)

    # Load all module outputs
    recon_data = load_json("recon_results.json")
    port_data  = load_json("port_results.json")
    vuln_data  = load_json("vuln_results.json")
    cve_data   = load_json("cve_results.json")

    target    = target_url or recon_data.get("target_url", "Unknown Target")
    domain    = recon_data.get("domain", "target")
    scan_date = datetime.now().strftime("%d %B %Y  %H:%M")
    safe_dom  = domain.replace(".", "_").replace("/", "_")
    filename  = f"WebSentinel_Report_{safe_dom}_{datetime.now().strftime('%Y%m%d')}.pdf"

    print(f"[*] Target      : {target}")
    print(f"[*] Output file : {filename}")
    print("[*] Generating report sections...")

    pdf = WebSentinelReport(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(10, 14, 10)

    print("  [+] Cover page...")
    add_cover(pdf, target, scan_date)

    print("  [+] Executive summary...")
    add_executive_summary(pdf, vuln_data, port_data, cve_data)

    print("  [+] Target information...")
    add_target_info(pdf, recon_data)

    print("  [+] Ports table...")
    add_ports_table(pdf, port_data)

    print("  [+] Vulnerability findings...")
    add_vuln_findings(pdf, vuln_data)

    print("  [+] CVE findings...")
    add_cve_findings(pdf, cve_data)

    print("  [+] Remediation table...")
    add_remediation_table(pdf, vuln_data)

    print("  [+] Conclusion...")
    add_conclusion(pdf, vuln_data, target)

    pdf.output(filename)
    print(f"\n[✔] Report saved: {filename}")
    print(f"[✔] Total pages : {pdf.page}")
    print("\n[✔] Module 5 — Report Generation Complete!")
    print("=" * 55)
    return filename


# ─────────────────────────────────────────────
# Run directly
# ─────────────────────────────────────────────
if __name__ == "__main__":
    generate_report()