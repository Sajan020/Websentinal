# ============================================================
#  WebSentinel - Module 6: Streamlit Dashboard
#  File: streamlit_app.py
#  Replaces: app.py (Flask)
# ============================================================
#  INSTALL:  pip install streamlit plotly pandas
#  RUN:      streamlit run streamlit_app.py
#  OPENS:    http://localhost:8501
# ============================================================

import streamlit as st
import json
import os
import time
import threading
import importlib
import importlib.util
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Import all scan modules
try:
    from recon import run_recon
    from port_scanner import run_port_scan
    from vuln_scanner import run_vuln_scan
    from cve_lookup import run_cve_lookup
except ImportError:
    from Websentinel.recon import run_recon
    from Websentinel.port_scanner import run_port_scan
    from Websentinel.vuln_scanner import run_vuln_scan
    from Websentinel.cve_lookup import run_cve_lookup


BASE_DIR = Path(__file__).resolve().parent


def generate_report(target):
    # Try normal module imports first
    for mod_name in ("report", "report_generator", "modules.report_generator", "modules.report"):
        try:
            mod = importlib.import_module(mod_name)
            if hasattr(mod, "generate_report"):
                return mod.generate_report(target)
        except Exception:
            pass

    # Try loading by file path from common locations
    base_dir = Path(__file__).resolve().parent
    candidates = [
        base_dir / "report.py",
        base_dir / "report_generator.py",
        base_dir / "modules" / "report.py",
        base_dir / "modules" / "report_generator.py",
        base_dir.parent / "report.py",
        base_dir.parent / "report_generator.py",
    ]

    for module_path in candidates:
        if module_path.exists():
            spec = importlib.util.spec_from_file_location("report_loader", module_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "generate_report"):
                    return mod.generate_report(target)

    raise ImportError(
        "Could not resolve 'report_generator'. Ensure report_generator.py exists and "
        "exports generate_report(target)."
    )


# ─────────────────────────────────────────────
# PAGE CONFIG  (must be first Streamlit call)
# ─────────────────────────────────────────────
st.set_page_config(
    page_title = "WebSentinel – VAPT Dashboard",
    page_icon  = "🔐",
    layout     = "wide",
    initial_sidebar_state = "expanded",
)


# ─────────────────────────────────────────────
# CUSTOM CSS  – dark cybersecurity theme
# ─────────────────────────────────────────────
st.markdown("""
<style>
/* Dark background */
.stApp { background-color: #0d1117; color: #c9d1d9; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
}

/* Metric cards */
div[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 14px;
}

/* Buttons */
.stButton > button {
    background: #238636;
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    width: 100%;
    padding: 12px;
}
.stButton > button:hover { background: #2ea043; }

/* Severity badges */
.badge-critical { background:#da3633; color:white; padding:3px 10px;
                  border-radius:4px; font-size:12px; font-weight:700; }
.badge-high     { background:#9e2a2b; color:#ff7b72; padding:3px 10px;
                  border-radius:4px; font-size:12px; font-weight:700;
                  border:1px solid #f85149; }
.badge-medium   { background:#5a3e10; color:#e3b341; padding:3px 10px;
                  border-radius:4px; font-size:12px; font-weight:700;
                  border:1px solid #bb8009; }
.badge-low      { background:#1a3a24; color:#56d364; padding:3px 10px;
                  border-radius:4px; font-size:12px; font-weight:700;
                  border:1px solid #238636; }

/* Cards */
.finding-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
}

/* Headers */
h1,h2,h3 { color: #e6edf3 !important; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────────
for key, default in {
    "scan_done":    False,
    "scan_running": False,
    "recon":        {},
    "ports":        {},
    "vulns":        {},
    "cves":         {},
    "report_path":  "",
    "scan_log":     [],
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def badge(severity):
    s = severity.lower()
    return f'<span class="badge-{s}">{severity.upper()}</span>'


def sev_color(s):
    return {"CRITICAL":"#da3633","HIGH":"#ff7b72",
            "MEDIUM":"#e3b341","LOW":"#56d364"}.get(s.upper(),"#8b949e")


def load_json(path):
    path_obj = Path(path)
    candidates = []

    if path_obj.is_absolute():
        candidates.append(path_obj)
    else:
        candidates.extend([
            Path.cwd() / path_obj,
            BASE_DIR / path_obj,
        ])

    for candidate in candidates:
        try:
            with open(candidate) as f:
                return json.load(f)
        except Exception:
            continue
    return {}


def safe_str(value):
    if value is None:
        return ""
    return str(value)


# ─────────────────────────────────────────────
# SCAN RUNNER  (called in main thread with
#               Streamlit progress widgets)
# ─────────────────────────────────────────────
def run_full_scan(target, progress_bar, status_text):
    steps = [
        ("🔎  Module 1 — Reconnaissance...",        20,  lambda: run_recon(target)),
        ("🌐  Module 2 — Port Scanner...",           40,  lambda: run_port_scan(target)),
        ("🛡  Module 3 — Vulnerability Scanner...",  65,  lambda: run_vuln_scan(target)),
        ("⚠  Module 4 — CVE Lookup...",             80,  lambda: run_cve_lookup()),
        ("📄  Module 5 — Generating PDF Report...", 95,  lambda: generate_report(target)),
    ]

    results = {}
    for msg, pct, fn in steps:
        status_text.markdown(f"**{msg}**")
        progress_bar.progress(pct)
        try:
            results[msg] = fn()
            st.session_state.scan_log.append(f"✅ {msg.split('—')[1].strip()} complete")
        except Exception as e:
            st.session_state.scan_log.append(f"❌ Error: {e}")

    # Load results from JSON files
    st.session_state.recon       = load_json("recon_results.json")
    st.session_state.ports       = load_json("port_results.json")
    st.session_state.vulns       = load_json("vuln_results.json")
    st.session_state.cves        = load_json("cve_results.json")

    # Find generated report file
    report_candidates = []
    for root in [Path.cwd(), BASE_DIR]:
        if root.exists():
            report_candidates.extend(root.glob("WebSentinel_Report*.pdf"))

    if report_candidates:
        latest_report = max(report_candidates, key=lambda p: p.stat().st_mtime)
        st.session_state.report_path = str(latest_report)

    progress_bar.progress(100)
    status_text.markdown("**✅  Scan Complete!**")
    st.session_state.scan_done    = True
    st.session_state.scan_running = False


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 WebSentinel")
    st.markdown("*Automated VAPT Dashboard*")
    st.divider()

    st.markdown("### 🎯 New Scan")
    target_url = st.text_input(
        "Target URL",
        placeholder="http://testphp.vulnweb.com",
        label_visibility="collapsed",
    )

    scan_clicked = st.button("▶  Start Scan", disabled=st.session_state.scan_running)

    st.divider()
    st.markdown("### 📋 Navigation")
    page = st.radio(
        "Go to",
        ["📊 Dashboard", "🛡 Vulnerabilities", "🌐 Ports & Services",
         "⚠ CVE Findings", "🔎 Reconnaissance", "📄 Report"],
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("WebSentinel v1.0 | Python + Streamlit")
    st.caption(f"© {datetime.now().year} | For authorized use only")


# ─────────────────────────────────────────────
# TRIGGER SCAN
# ─────────────────────────────────────────────
if scan_clicked and target_url:
    st.session_state.scan_done    = False
    st.session_state.scan_running = True
    st.session_state.scan_log     = []

    st.markdown("---")
    st.markdown(f"### ⏳ Scanning: `{target_url}`")
    prog  = st.progress(0)
    stxt  = st.empty()
    run_full_scan(target_url, prog, stxt)
    st.rerun()

elif scan_clicked and not target_url:
    st.sidebar.error("Please enter a target URL.")


# ─────────────────────────────────────────────
# MAIN CONTENT AREA
# ─────────────────────────────────────────────

# ── HEADER ───────────────────────────────────
st.markdown("# 🔐 WebSentinel")
st.markdown("#### Automated Web Application Vulnerability Assessment Platform")
st.divider()

# ── NO SCAN YET ───────────────────────────────
if not st.session_state.scan_done:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info("**Step 1**\n\nEnter a target URL in the sidebar")
    with col2:
        st.info("**Step 2**\n\nClick ▶ Start Scan")
    with col3:
        st.info("**Step 3**\n\nView results & download PDF report")
    st.stop()


# ─────────────────────────────────────────────
# LOAD DATA FROM SESSION STATE
# ─────────────────────────────────────────────
vulns    = st.session_state.vulns
ports    = st.session_state.ports
cves     = st.session_state.cves
recon    = st.session_state.recon
findings = vulns.get("findings", [])

sev_count = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
for f in findings:
    s = f.get("severity","LOW").upper()
    sev_count[s] = sev_count.get(s,0) + 1

total_ports = ports.get("summary",{}).get("total_open", 0)
high_ports  = ports.get("summary",{}).get("high_risk",  0)
cve_count   = sum(len(r.get("cves",[])) for r in cves.get("cve_findings",[]))


# ════════════════════════════════════════════
# PAGE: DASHBOARD
# ════════════════════════════════════════════
if page == "📊 Dashboard":

    target_disp = recon.get("target_url", "Unknown")
    st.markdown(f"### 📊 Scan Results — `{target_disp}`")
    st.caption(f"Scanned on: {recon.get('scan_time','—')}")
    st.divider()

    # ── METRIC CARDS ──────────────────────────
    c1,c2,c3,c4,c5,c6 = st.columns(6)
    c1.metric("🔴 Critical",  sev_count["CRITICAL"])
    c2.metric("🟠 High",      sev_count["HIGH"])
    c3.metric("🟡 Medium",    sev_count["MEDIUM"])
    c4.metric("🟢 Low",       sev_count["LOW"])
    c5.metric("🌐 Open Ports", total_ports)
    c6.metric("⚠ CVEs",       cve_count)

    st.divider()

    # ── CHARTS ROW ────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### Vulnerability Severity Distribution")
        labels = list(sev_count.keys())
        values = list(sev_count.values())
        colors = ["#da3633","#ff7b72","#e3b341","#56d364"]
        fig_pie = go.Figure(go.Pie(
            labels=labels, values=values,
            marker=dict(colors=colors),
            hole=0.45,
            textinfo="label+value",
        ))
        fig_pie.update_layout(
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            font=dict(color="#c9d1d9"),
            showlegend=True,
            margin=dict(t=20,b=20,l=20,r=20),
            height=300,
        )
        st.plotly_chart(fig_pie, width="stretch")

    with col_right:
        st.markdown("#### Findings by Vulnerability Type")
        type_counts = {}
        for f in findings:
            t = f.get("type","Unknown")
            type_counts[t] = type_counts.get(t,0) + 1
        if type_counts:
            df_types = pd.DataFrame(
                list(type_counts.items()), columns=["Type","Count"]
            ).sort_values("Count", ascending=True)
            fig_bar = px.bar(
                df_types, x="Count", y="Type", orientation="h",
                color="Count",
                color_continuous_scale=["#1f6feb","#da3633"],
            )
            fig_bar.update_layout(
                paper_bgcolor="#161b22", plot_bgcolor="#0d1117",
                font=dict(color="#c9d1d9"),
                coloraxis_showscale=False,
                margin=dict(t=20,b=20,l=20,r=20),
                height=300,
            )
            st.plotly_chart(fig_bar, width="stretch")
        else:
            st.info("No findings to chart.")

    st.divider()

    # ── SCAN LOG ──────────────────────────────
    with st.expander("📋 Scan Log"):
        for log in st.session_state.scan_log:
            st.markdown(f"- {log}")


# ════════════════════════════════════════════
# PAGE: VULNERABILITIES
# ════════════════════════════════════════════
elif page == "🛡 Vulnerabilities":

    st.markdown("### 🛡 Vulnerability Findings")
    st.caption(f"Total: {len(findings)} findings")
    st.divider()

    if not findings:
        st.success("No vulnerabilities detected.")
        st.stop()

    # Filter controls
    col_f1, col_f2 = st.columns([1,2])
    with col_f1:
        sev_filter = st.selectbox(
            "Filter by Severity",
            ["All","CRITICAL","HIGH","MEDIUM","LOW"]
        )
    with col_f2:
        type_filter = st.selectbox(
            "Filter by Type",
            ["All"] + list({f.get("type","") for f in findings})
        )

    filtered = [
        f for f in findings
        if (sev_filter == "All" or f.get("severity","").upper() == sev_filter)
        and (type_filter == "All" or f.get("type","") == type_filter)
    ]

    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
    st.divider()

    for i, f in enumerate(filtered, 1):
        sev   = f.get("severity","LOW").upper()
        color = sev_color(sev)

        with st.expander(
            f"#{i:02d}  |  {f.get('type','Unknown')}  |  "
            f"CVSS: {f.get('cvss','N/A')}  |  [{sev}]",
            expanded=(sev in ["CRITICAL","HIGH"])
        ):
            c1, c2 = st.columns([1,3])
            with c1:
                st.markdown(f"**Severity**")
                st.markdown(
                    f'<span style="background:{color};color:white;'
                    f'padding:4px 12px;border-radius:4px;'
                    f'font-weight:700;">{sev}</span>',
                    unsafe_allow_html=True
                )
                if f.get("cvss"):
                    st.metric("CVSS Score", f.get("cvss"))
            with c2:
                if f.get("url"):
                    st.markdown(f"**URL:** `{f.get('url')}`")
                if f.get("method"):
                    st.markdown(f"**Method:** `{f.get('method')}`")
                if f.get("payload"):
                    st.code(f.get("payload"), language="html")

            if f.get("evidence"):
                st.info(f"**Evidence:** {f.get('evidence')}")
            if f.get("impact"):
                st.warning(f"**Impact:** {f.get('impact')}")
            if f.get("fix"):
                st.success(f"**Recommended Fix:** {f.get('fix')}")


# ════════════════════════════════════════════
# PAGE: PORTS & SERVICES
# ════════════════════════════════════════════
elif page == "🌐 Ports & Services":

    st.markdown("### 🌐 Open Ports & Services")
    st.divider()

    open_ports = ports.get("open_ports", [])
    summary    = ports.get("summary", {})

    # Summary metrics
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Total Open Ports", summary.get("total_open",0))
    c2.metric("High Risk Ports",  summary.get("high_risk",0))
    c3.metric("Medium Risk",      summary.get("medium_risk",0))
    c4.metric("CVEs Detected",    summary.get("cves_found",0))

    st.divider()

    if not open_ports:
        st.info("No open ports detected.")
        st.stop()

    # Ports table using DataFrame
    df = pd.DataFrame([{
        "Port":        p.get("port"),
        "Protocol":    p.get("protocol","").upper(),
        "Service":     p.get("service",""),
        "Version":     p.get("full_version","—"),
        "Risk":        p.get("risk","INFO"),
        "Reason":      p.get("risk_reason",""),
    } for p in open_ports])

    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Risk": st.column_config.TextColumn("Risk"),
        }
    )

    st.divider()
    st.markdown("#### Risk Distribution")
    risk_counts = df["Risk"].value_counts().reset_index()
    risk_counts.columns = ["Risk","Count"]
    risk_colors = {
        "HIGH":"#f85149","MEDIUM":"#e3b341",
        "LOW":"#56d364","INFO":"#58a6ff"
    }
    fig_risk = px.bar(
        risk_counts, x="Risk", y="Count",
        color="Risk",
        color_discrete_map=risk_colors,
    )
    fig_risk.update_layout(
        paper_bgcolor="#161b22", plot_bgcolor="#0d1117",
        font=dict(color="#c9d1d9"),
        showlegend=False,
        height=280,
    )
    st.plotly_chart(fig_risk, width="stretch")


# ════════════════════════════════════════════
# PAGE: CVE FINDINGS
# ════════════════════════════════════════════
elif page == "⚠ CVE Findings":

    st.markdown("### ⚠ CVE Findings from Detected Services")
    st.divider()

    cve_findings = cves.get("cve_findings", [])
    if not cve_findings:
        st.info("No CVE data available. Run port scan first.")
        st.stop()

    total_cves = sum(len(r.get("cves",[])) for r in cve_findings)
    st.metric("Total CVEs Found", total_cves)
    st.divider()

    for svc in cve_findings:
        st.markdown(
            f"**Port {svc.get('port')}  —  "
            f"{svc.get('product','')} {svc.get('version','')}**"
        )
        cve_list = svc.get("cves", [])
        if not cve_list:
            st.caption("No CVEs found for this service.")
            continue

        df_cve = pd.DataFrame([{
            "CVE ID":      c.get("cve_id"),
            "CVSS Score":  c.get("cvss_score","N/A"),
            "Severity":    c.get("severity","UNKNOWN"),
            "Published":   c.get("published",""),
            "Description": c.get("description","")[:120] + "...",
            "NVD Link":    c.get("nvd_url",""),
        } for c in cve_list])

        st.dataframe(
            df_cve,
            width="stretch",
            hide_index=True,
            column_config={
                "NVD Link": st.column_config.LinkColumn("NVD Link"),
            }
        )
        st.divider()


# ════════════════════════════════════════════
# PAGE: RECONNAISSANCE
# ════════════════════════════════════════════
elif page == "🔎 Reconnaissance":

    st.markdown("### 🔎 Reconnaissance Summary")
    st.divider()

    dns   = recon.get("dns",   {})
    whois = recon.get("whois", {})
    tech  = recon.get("technologies", [])
    hdrs  = recon.get("http_headers", {}).get("headers", {})

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🌍 Target Info")
        st.table(pd.DataFrame([
            {"Field":"Target URL",  "Value": safe_str(recon.get("target_url","—"))},
            {"Field":"Domain",      "Value": safe_str(recon.get("domain","—"))},
            {"Field":"IP Address",  "Value": safe_str(dns.get("IP","—"))},
            {"Field":"Scan Time",   "Value": safe_str(recon.get("scan_time","—"))},
            {"Field":"Status Code", "Value": safe_str(recon.get("http_headers",{}).get("status_code","—"))},
        ]))

        st.markdown("#### 🏷 Technologies Detected")
        if tech:
            for t in tech:
                st.markdown(f"- {t}")
        else:
            st.caption("No technologies detected.")

    with col2:
        st.markdown("#### 📋 WHOIS Information")
        st.table(pd.DataFrame([
            {"Field":"Registrar",   "Value": str(whois.get("registrar","—"))[:60]},
            {"Field":"Created",     "Value": str(whois.get("creation_date","—"))[:40]},
            {"Field":"Expires",     "Value": str(whois.get("expiration_date","—"))[:40]},
            {"Field":"Org",         "Value": str(whois.get("org","—"))[:60]},
            {"Field":"Country",     "Value": str(whois.get("country","—"))},
        ]))

        st.markdown("#### 🔡 DNS Records")
        st.table(pd.DataFrame([
            {"Type":"A",   "Records": ", ".join(dns.get("A",[])) or "—"},
            {"Type":"MX",  "Records": ", ".join(dns.get("MX",[])) or "—"},
            {"Type":"NS",  "Records": ", ".join(dns.get("NS",[])) or "—"},
        ]))

    st.divider()
    with st.expander("📡 Full HTTP Response Headers"):
        if hdrs:
            df_hdrs = pd.DataFrame(
                list(hdrs.items()), columns=["Header","Value"]
            )
            if "Value" in df_hdrs.columns:
                df_hdrs["Value"] = df_hdrs["Value"].astype(str)
            st.dataframe(df_hdrs, width="stretch", hide_index=True)
        else:
            st.caption("No headers available.")


# ════════════════════════════════════════════
# PAGE: REPORT
# ════════════════════════════════════════════
elif page == "📄 Report":

    st.markdown("### 📄 Download PDF Report")
    st.divider()

    rpath = st.session_state.report_path

    if rpath and os.path.exists(rpath):
        report_name = os.path.basename(rpath)
        st.success(f"Report ready: **{report_name}**")

        with open(rpath, "rb") as f:
            pdf_bytes = f.read()

        st.download_button(
            label     = "⬇  Download Full PDF Report",
            data      = pdf_bytes,
            file_name = report_name,
            mime      = "application/pdf",
            width="stretch",
        )

        st.divider()
        st.markdown("#### Report Contents")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            - ✅ Cover Page
            - ✅ Executive Summary
            - ✅ Target Information
            - ✅ Open Ports Table
            """)
        with col2:
            st.markdown("""
            - ✅ Vulnerability Findings (with PoC)
            - ✅ CVE Findings (with CVSS scores)
            - ✅ Remediation Summary
            - ✅ Conclusion
            """)
    else:
        st.warning("No report found. Run a scan first.")