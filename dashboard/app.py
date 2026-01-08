import sys
from pathlib import Path
import json
import requests
from datetime import datetime
import ipaddress

import pandas as pd
import streamlit as st


# =================================================
# PROJECT PATH SETUP
# =================================================
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


# =================================================
# INTERNAL IMPORTS
# =================================================
from dashboard import (
    home,
    threat_summary,
    vulnerability_insights,
    risk_analysis,
    nmap,
    ai_analyst,
    export_report,  # new tab
)
from dashboard.data_loader import load_scan_metadata, load


API = "http://localhost:8000"


# =================================================
# PAGE CONFIG
# =================================================
st.set_page_config(
    page_title="Cyber Risk Assessment Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =================================================
# BACKEND HEALTH CHECK
# =================================================
@st.cache_data(ttl=30)
def backend_health():
    try:
        return requests.get(f"{API}/scan/metadata", timeout=3).ok
    except Exception:
        return False


if not backend_health():
    st.sidebar.error("🚫 Backend API not reachable")


# =================================================
# SHODAN SEARCH UTILS (optional helper)
# =================================================
def search_shodan(data, ip=None, port=None, cidr=None, asn=None, org=None):
    results = data or []

    if ip:
        results = [r for r in results if r.get("ip") == ip]

    if port:
        try:
            p = int(port)
            results = [r for r in results if p in r.get("ports", [])]
        except ValueError:
            return []

    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            results = [
                r
                for r in results
                if "ip" in r and ipaddress.ip_address(r["ip"]) in net
            ]
        except ValueError:
            pass

    if asn:
        results = [
            r
            for r in results
            if asn.lower() in str(r.get("asn", "")).lower()
        ]

    if org:
        results = [
            r
            for r in results
            if org.lower() in str(r.get("org", "")).lower()
        ]

    return results


# =================================================
# THEME MANAGEMENT
# =================================================
with st.sidebar:
    st.markdown("## ⚙️ Display Settings")
    theme_mode = st.radio("Theme Mode", ["Dark", "Light"], index=0)

if theme_mode == "Dark":
    bg_color = "#000000"
    panel_bg = "#0f0f0f"
    card_bg = "#121212"
    text_color = "#e0e0e0"
    accent_color = "#00f2ff"
    chart_theme = "plotly_dark"
    secondary_text = "#a0a0a0"
else:
    bg_color = "#f0f2f6"
    panel_bg = "#fafafa"
    card_bg = "#ffffff"
    text_color = "#1f1f1f"
    accent_color = "#0068c9"
    chart_theme = "plotly_white"
    secondary_text = "#555555"

st.session_state.plotly_template = chart_theme

st.markdown(
    f"""
<style>
.stApp {{
    background-color: {bg_color};
    color: {text_color};
}}
section[data-testid="stSidebar"] {{
    background-color: {panel_bg};
    border-right: 1px solid {'#333' if 'Dark' in theme_mode else '#ddd'};
}}
div.stContainer {{
    background-color: {card_bg};
    border-radius: 12px;
    padding: 18px;
    border: 1px solid {'#333' if 'Dark' in theme_mode else '#ddd'};
}}
h1, h2, h3 {{
    color: {accent_color} !important;
}}
p, span, label {{
    color: {text_color};
}}
div[data-testid="stMetricValue"] {{
    color: {accent_color} !important;
    font-size: 32px !important;
    font-weight: 700 !important;
}}
div[data-testid="stMetricLabel"] {{
    color: {secondary_text} !important;
}}
button[data-baseweb="tab"] div p {{
    color: {secondary_text} !important;
    font-size: 16px;
    font-weight: 600;
}}
button[data-baseweb="tab"][aria-selected="true"] div p {{
    color: {accent_color} !important;
}}
button[data-baseweb="tab"][aria-selected="true"] {{
    border-bottom: 3px solid {accent_color} !important;
}}
div.stButton > button {{
    background-color: {card_bg};
    color: {accent_color};
    border: 1px solid {accent_color};
    border-radius: 8px;
    font-weight: bold;
}}
div.stButton > button:hover {{
    background-color: {accent_color};
    color: {'#000' if 'Dark' in theme_mode else '#fff'};
}}
</style>
""",
    unsafe_allow_html=True,
)


# =================================================
# SIDEBAR — SCAN INPUTS
# =================================================
st.sidebar.markdown("## 🧪 Scan Inputs")

if "scan_target" not in st.session_state:
    st.session_state.scan_target = ""
if "scan_ports" not in st.session_state:
    st.session_state.scan_ports = ""

st.session_state.scan_target = st.sidebar.text_input(
    "Target (IP / Host / CIDR)", st.session_state.scan_target
)
st.session_state.scan_ports = st.sidebar.text_input(
    "Ports (comma or range)", st.session_state.scan_ports
)

st.sidebar.file_uploader("Upload targets file (optional)")
st.sidebar.subheader("Advanced Filters")
cidr_query = st.sidebar.text_input("CIDR (e.g. 192.168.1.0/24)")
asn_query = st.sidebar.text_input("ASN (e.g. AS15169)")
org_query = st.sidebar.text_input("Organization (e.g. Google)")

st.sidebar.markdown("---")
st.sidebar.markdown("## 🎯 Scan Profile")

if "scan_filter" not in st.session_state:
    st.session_state.scan_filter = "Normal"

st.session_state.scan_filter = st.sidebar.selectbox(
    "Scan Profile", ["Quick", "Normal", "High"], index=1
)


# =================================================
# SCAN EXECUTION
# =================================================
if st.sidebar.button("🚀 Run Scan"):
    try:
        params = {
            "scan_type": st.session_state.scan_filter,
            "target": st.session_state.scan_target or "scanme.nmap.org",
        }
        r = requests.post(f"{API}/scan/run", params=params, timeout=120)
        if r.ok:
            st.sidebar.success("Scan completed successfully")
            # clear caches so next calls to load() hit the backend again
            load.clear()
            load_scan_metadata.clear()
        else:
            st.sidebar.error(f"Scan failed: {r.status_code}")
    except Exception as e:
        st.sidebar.error(f"Scan error: {e}")


# =================================================
# SCAN METADATA STATE
# =================================================
if "scan_type" not in st.session_state:
    meta = load_scan_metadata()
    st.session_state.scan_type = meta.get("scan_type", "Normal")


# =================================================
# HEADER
# =================================================
st.markdown("## 🛡 Cyber Risk Assessment Dashboard")
st.markdown(
    f"**Scan Profile:** `{st.session_state.scan_filter}` "
    f"🕒 {datetime.now().strftime('%H:%M:%S')}"
)


# =================================================
# MAIN TABS
# =================================================
tabs = [
    "Overview",
    "Nmap",
    "Vulnerabilities",
    "Threat Summary",
    "Vulnerability Insights",
    "Risk Analysis",
    "AI Analyst",
    "Export",
]

tab_objs = st.tabs(tabs)


# =================================================
# TAB CONTENTS
# =================================================
with tab_objs[0]:
    try:
        home.run({"scan_type": st.session_state.scan_filter})
    except Exception:
        # Fallback: show raw recent scan if needed
        df = load("/nmap/results", st.session_state.scan_filter)
        if df is not None and not df.empty:
            st.dataframe(df)
        else:
            st.info("No recent scans")

with tab_objs[1]:
    try:
        nmap.run({"scan_type": st.session_state.scan_filter})
    except Exception:
        df = load("/nmap/results", st.session_state.scan_filter)
        if df is not None and not df.empty:
            st.dataframe(df)
        else:
            st.info("No Nmap data")

with tab_objs[2]:
    df = load("/vulnerabilities", st.session_state.scan_filter)
    if df is not None and not df.empty:
        st.dataframe(df)
    else:
        st.info("No vulnerability data")

with tab_objs[3]:
    threat_summary.run({"scan_type": st.session_state.scan_filter})

with tab_objs[4]:
    vulnerability_insights.run({"scan_type": st.session_state.scan_filter})

with tab_objs[5]:
    risk_analysis.run({"scan_type": st.session_state.scan_filter})

with tab_objs[6]:
    try:
        ai_analyst.run({"scan_type": st.session_state.scan_filter})
    except Exception:
        st.info("AI Analyst unavailable")

with tab_objs[7]:
    export_report.run({"scan_type": st.session_state.scan_filter})
